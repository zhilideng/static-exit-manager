"""静态出口管理器独立后端：配置、订阅与事务；特权操作只交给专用服务。"""
import base64
import binascii
import copy
import concurrent.futures
import csv
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import unicodedata
import uuid

# 纯 Python PyYAML 随应用分发（应用包内 pylib/，源码目录 vendor/pylib/），不依赖本机 Ruby 或第三方包。
for _pylib in (Path(__file__).resolve().parent / 'pylib', Path(__file__).resolve().parent / 'vendor/pylib'):
    if _pylib.is_dir():
        sys.path.insert(0, str(_pylib))
        break
import yaml  # noqa: E402

LIBRARY =Path.home() / 'Library/Application Support/StaticExitManager'
DATA = LIBRARY / 'standalone'
VERGE = Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
CONTROLLER_PORT = 17897
MIXED_PORT = 17896
EXIT_NAME = '静态IP出口'
RELAY_NAME = '静态IP机场中转'
MAX_SUBSCRIPTION_BYTES = 16 * 1024 * 1024
# 一次测完整个订阅：最多 256 个节点、同时 16 个探测，单节点 5 秒超时（实测可用节点均在 3.5 秒内）。
NODE_DELAY_MAX_NAMES = 256
NODE_DELAY_CONCURRENCY = 16
NODE_DELAY_MAX_MS = 5000
NODE_DELAY_MEASUREMENT_VERSION = 3
NODE_DELAY_METHOD = 'clash-manual-http-cloudflare-unified-5000'
OFFLINE_DELAY_STARTUP_SECONDS = 3.0
VALIDATION_CACHE_VERSION = 1
VALIDATION_CACHE_LIMIT = 16
VALIDATION_CACHE_FILE = 'config-validation-cache.json'
EXIT_LOCATION_CACHE_FILE = 'exit-locations.json'
EXIT_LOCATION_TTL = 7 * 24 * 60 * 60
EXIT_LOCATION_MAX_AGE = 30 * 24 * 60 * 60
EXIT_LOCATION_RETRY_SECONDS = 5 * 60
EXIT_LOCATION_CACHE_LIMIT = 64
RULES = [
    'DOMAIN,localhost,DIRECT', 'DOMAIN-SUFFIX,local,DIRECT', 'DOMAIN-SUFFIX,lan,DIRECT',
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve', 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve', 'IP-CIDR6,::1/128,DIRECT,no-resolve',
    'IP-CIDR6,fc00::/7,DIRECT,no-resolve', 'IP-CIDR6,fe80::/10,DIRECT,no-resolve',
    'GEOSITE,cn,DIRECT', 'GEOIP,CN,DIRECT', 'IP-CIDR6,::/0,REJECT,no-resolve',
    'NETWORK,UDP,REJECT', 'MATCH,' + EXIT_NAME,
]
# 未选择静态 IP 时，国外 TCP 直接以中转节点为出口；其余规则（含拒绝国外 UDP）不变。
RELAY_ONLY_RULES = RULES[:-1] + ['MATCH,' + RELAY_NAME]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def put_json(path, value):
    write(path, json.dumps(value, ensure_ascii=False, indent=2))


def read_json(path, default):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else copy.deepcopy(default)


def public_location_ip(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('归属地查询需要有效的公网 IP 地址。')
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError('归属地查询需要有效的公网 IP 地址。') from None
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError('归属地查询仅支持公网 IP 地址。')
    return str(address)


def empty_exit_location(address):
    return {'ip': address, 'status': 'unavailable', 'country': '', 'country_code': '',
            'region': '', 'city': '', 'source': 'ipwho.is', 'fetched_at': ''}


def location_fields(value, address):
    if not isinstance(value, dict) or public_location_ip(value.get('ip')) != address:
        raise ValueError('归属地响应 IP 不匹配。')
    result = {}
    for name in ('country', 'country_code', 'region', 'city'):
        field = value.get(name, '')
        if (not isinstance(field, str) or len(field) > 100 or
                any(unicodedata.category(character).startswith('C') for character in field)):
            raise ValueError('归属地响应字段无效。')
        result[name] = field.strip()
    if result['country_code'] and not re.fullmatch('[A-Z]{2}', result['country_code']):
        raise ValueError('归属地国家代码无效。')
    if not any(result[name] for name in ('country', 'region', 'city')):
        raise ValueError('归属地响应没有地点。')
    return result


def fetch_exit_location(address):
    # 只发送已实测的公网 IP；固定 HTTPS 地址，不跟随跳转，不携带本机代理凭据。
    url = ('https://ipwho.is/' + urllib.parse.quote(address, safe='') +
           '?lang=zh-CN&fields=success,ip,country,country_code,region,city')
    response = subprocess.run(
        ['/usr/bin/curl', '-q', '--silent', '--show-error', '--fail',
         '--proxy', '', '--noproxy', '*', '--proto', '=https',
         '--connect-timeout', '5.5', '--max-time', '5.5', '--max-filesize', '16384', url],
        capture_output=True, timeout=6)
    if response.returncode or len(response.stdout) > 16384:
        raise ValueError('归属地查询暂不可用。')
    value = json.loads(response.stdout)
    if not isinstance(value, dict) or value.get('success') is not True:
        raise ValueError('归属地查询暂不可用。')
    fields = location_fields(value, address)
    return {**empty_exit_location(address), **fields, 'status': 'ok', 'fetched_at': now()}


def read_exit_locations():
    try:
        path = DATA / EXIT_LOCATION_CACHE_FILE
        if path.stat().st_size > 128 * 1024:
            return {}
        value = read_json(path, {})
        entries = value.get('entries', {})
        if value.get('version') != 1 or not isinstance(entries, dict) or len(entries) > EXIT_LOCATION_CACHE_LIMIT:
            return {}
        return entries
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def cached_exit_location(entry, address, timestamp):
    result = empty_exit_location(address)
    if not isinstance(entry, dict):
        return result
    try:
        location = entry['location']
        fields = location_fields(location, address)
        fetched = datetime.datetime.fromisoformat(location['fetched_at'])
        if fetched.tzinfo is None:
            return result
        age = timestamp - fetched.timestamp()
        if 0 <= age <= EXIT_LOCATION_MAX_AGE:
            result.update(fields)
            result.update(status='ok' if age <= EXIT_LOCATION_TTL else 'stale',
                          fetched_at=fetched.isoformat())
    except (KeyError, ValueError, TypeError, OverflowError):
        pass
    return result


def exit_location(value):
    address = public_location_ip(value)
    timestamp = time.time()
    entries = read_exit_locations()
    cached = cached_exit_location(entries.get(address), address, timestamp)
    # 地理查询不能占用连接操作锁；重复请求也不排队等待网络。
    try:
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(DATA / 'exit-location.lock', os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'location': cached}
            entries = read_exit_locations()
            entry = entries.get(address, {})
            cached = cached_exit_location(entry, address, timestamp)
            attempted = entry.get('attempted_at', 0) if isinstance(entry, dict) else 0
            recent_failure = (type(attempted) in (int, float) and
                              0 <= timestamp - attempted < EXIT_LOCATION_RETRY_SECONDS)
            if cached['status'] == 'ok' or recent_failure:
                return {'location': cached}
            try:
                cached = fetch_exit_location(address)
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                pass
            timestamp = time.time()
            entries[address] = {'location': cached, 'attempted_at': timestamp}
            # 仅保留可验证的地点字段；不复制缓存中的任意附加内容。
            cleaned = {}
            for key, record in entries.items():
                try:
                    if public_location_ip(key) != key or not isinstance(record, dict):
                        continue
                    attempted = record.get('attempted_at', 0)
                    if type(attempted) not in (int, float) or not 0 <= timestamp - attempted <= EXIT_LOCATION_MAX_AGE:
                        continue
                    cleaned[key] = {'location': cached_exit_location(record, key, timestamp),
                                    'attempted_at': attempted}
                except ValueError:
                    continue
            cleaned = dict(sorted(cleaned.items(), key=lambda item: item[1]['attempted_at'])[-EXIT_LOCATION_CACHE_LIMIT:])
            try:
                put_json(DATA / EXIT_LOCATION_CACHE_FILE, {'version': 1, 'entries': cleaned})
            except OSError:
                pass
            return {'location': cached}
    except OSError:
        return {'location': cached}


def executable():
    if len(sys.argv) < 2:
        raise RuntimeError('无法定位应用程序，请从静态出口管理器打开。')
    return sys.argv[1]


def resources():
    return Path(executable()).resolve().parent.parent / 'Resources'


def run(args, stdin=None, timeout=30):
    try:
        result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('操作超时，请检查网络或服务状态。') from None
    if result.returncode:
        # 外部错误可能携带订阅地址、账号或配置内容，不能原样回显。
        raise RuntimeError('本机组件执行失败（' + Path(args[0]).name + '，状态 ' + str(result.returncode) + '）。')
    return result.stdout


def node_delay_service_timeout(names):
    rounds = -(-len(names or []) // NODE_DELAY_CONCURRENCY)
    return 5 + max(1, rounds) * 6


def service(op, config=None, path=None, names=None):
    request = {'op': op}
    if config is not None:
        request['config'] = config
    if path is not None:
        request['path'] = path
    if names is not None:
        request['names'] = names
    timeout = 60 if op in ('start', 'apply', 'stop') else (node_delay_service_timeout(names) if op == 'node_delays' else 8)
    result = json.loads(run([executable(), '--service'], json.dumps(request, ensure_ascii=False), timeout=timeout))
    if not result.get('ok'):
        raise RuntimeError(result.get('error') or '独立代理服务不可用，请先在应用中安装并授权服务。')
    return result


def service_status():
    try:
        state = service('status')
        state.setdefault('state_known', True)
        if not state['state_known']:
            state['service_error'] = '无法确认已安装服务的运行状态，请重新连接或安装匹配的服务版本。'
        return state
    except (RuntimeError, OSError, ValueError):
        return {'running': False, 'tun': False, 'mixed_port': MIXED_PORT, 'state_known': False,
                'service_error': '独立代理服务尚不可用，请在应用中安装并授权；代理库仍可离线管理。'}


def known_service_status(allow_stopped_error=False):
    state = service_status()
    stopped_with_old_error = allow_stopped_error and state.get('running') is False
    if state.get('state_known') is False or (state.get('service_error') and not stopped_with_old_error):
        raise RuntimeError('暂时无法确认独立服务是否运行，请恢复服务连接后重试；未修改网络配置。')
    return state


def require_settled():
    if (DATA / 'pending.json').exists():
        raise RuntimeError('上次配置操作尚未完成，请先恢复上次配置或停止独立服务，再修改订阅选择。')


def settings(create=False):
    path = DATA / 'settings.json'
    value = read_json(path, {})
    value.setdefault('current_subscription_uid', '')
    value.setdefault('selected_profile_id', '')
    value.setdefault('relays', {})
    if create and not value.get('controller_secret'):
        value['controller_secret'] = secrets.token_urlsafe(36)
        put_json(path, value)
    return value


def subscriptions():
    return read_json(DATA / 'subscriptions.json', [])


def profiles():
    return read_json(LIBRARY / 'profiles.json', [])


def subscription(uid):
    item = next((item for item in subscriptions() if item['uid'] == uid), None)
    if not item:
        raise ValueError('订阅不存在，请刷新列表。')
    return item


def cached(item):
    # 缓存文件由本程序 UUID 命名，不信任导入内容提供的路径。
    return read_json(cache_path(item), {})


def cache_path(item):
    version = '-' + str(uuid.UUID(item['cache_id'])) if item.get('cache_id') else ''
    return DATA / 'subscriptions' / (str(uuid.UUID(item['uid'])) + version + '.json')


def api(path, method='GET', body=None, timeout=5):
    if method != 'GET' or body is not None or path not in ('/configs', '/proxies', '/rules', '/version'):
        raise ValueError('只允许读取独立内核的公开状态。')
    # root 内核只监听服务私有 Unix socket；用户进程不能借 API 加载任意 root 路径。
    return service('api', path=path).get('data', {})


def keychain(action, identifier, password=''):
    return json.loads(run([executable(), '--keychain'], json.dumps({'action': action, 'id': identifier, 'password': password})))


def validated(profile):
    host = str(profile.get('server', '')).strip()
    protocol = profile.get('protocol', 'socks5')
    try:
        port = int(profile['port'])
    except (KeyError, ValueError, TypeError):
        raise ValueError('端口必须是 1 到 65535 的整数。') from None
    if not host or any(ch in host for ch in '/@ \n\r\t') or not 1 <= port <= 65535 or protocol not in ('socks5', 'http', 'https'):
        raise ValueError('代理地址、端口或协议不合法。')
    expected = str(profile.get('expected', '')).strip()
    if expected:
        try:
            ipaddress.ip_address(expected)
        except ValueError:
            raise ValueError('预期出口必须是合法 IP 地址。') from None
    return {'id': profile.get('id') or str(uuid.uuid4()), 'name': str(profile.get('name') or host),
            'server': host, 'port': port, 'protocol': protocol,
            'username': str(profile.get('username', '')), 'expected': expected,
            'expired': str(profile.get('expired', ''))}


def save(profile):
    value = validated(profile)
    entries = profiles()
    if profile.get('id') and not any(item['id'] == value['id'] for item in entries):
        raise ValueError('这条静态 IP 已不存在，请刷新后重新添加。')
    preserve = profile.get('id') and not profile.get('password') and not profile.get('replace_password')
    secret = keychain('get' if preserve else 'set', value['id'], profile.get('password', ''))
    if not secret.get('ok'):
        raise RuntimeError('钥匙串不可用，静态 IP 未保存。')
    updated = [value if item['id'] == value['id'] else item for item in entries]
    if not any(item['id'] == value['id'] for item in entries):
        updated.append(value)
    put_json(LIBRARY / 'profiles.json', updated)
    return {'profiles': updated, 'message': '静态 IP 已保存。'}


def delete_profile(identifier):
    entries = profiles()
    if not any(item['id'] == identifier for item in entries):
        raise ValueError('这条静态 IP 已不存在。')
    result = keychain('delete', identifier)
    if not result.get('ok'):
        raise RuntimeError('无法删除钥匙串记录，静态 IP 库未改动。')
    updated = [item for item in entries if item['id'] != identifier]
    put_json(LIBRARY / 'profiles.json', updated)
    return {'profiles': updated, 'message': '已删除静态 IP 记录；已经建立的连接和运行配置不受影响。'}


def import_csv(path):
    with open(path, encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not {'ip:port', 'username', 'password'}.issubset(reader.fieldnames or []):
            raise ValueError('CSV 需要包含 ip:port、username、password 三列。')
        rows = list(reader)
    if not rows:
        raise ValueError('CSV 为空。')
    candidates = []
    for row in rows:
        try:
            host, port = row['ip:port'].rsplit(':', 1)
        except (ValueError, AttributeError):
            raise ValueError('CSV 中存在不完整的代理地址。') from None
        host = host.strip('[]')
        try:
            ipaddress.ip_address(host)
            expected = host
        except ValueError:
            expected = ''
        value = dict(name=row.get('remark') or host, server=host, port=port,
                     protocol='socks5', username=row.get('username', ''), password=row.get('password', ''),
                     expected=expected, expired=row.get('expired', ''), replace_password=True)
        validated(value)
        candidates.append(value)
    count = 0
    for value in candidates:
        old = next((item for item in profiles() if (item['server'], item['port'], item['username']) ==
                    (value['server'], int(value['port']), value['username'])), None)
        if old:
            value['id'] = old['id']
        save(value)
        count += 1
    return {'profiles': profiles(), 'message': f'已导入或更新 {count} 条静态 IP，协议按 SOCKS5 保存。'}


def parse_yaml(path):
    # safe_load 不实例化 YAML 标签指向的对象；经 JSON 往返只保留基本类型，日期、NaN 等值按格式错误处理。
    try:
        value = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
        return json.loads(json.dumps(value, allow_nan=False))
    except (OSError, UnicodeError, yaml.YAMLError, TypeError, ValueError, RecursionError):
        raise ValueError('无法读取订阅，请使用 Clash/Mihomo YAML 格式。') from None


# 支持本机订阅使用的协议及常见纯网络协议；不接受插件程序、私钥路径或证书文件。
PROXY_TYPES = {'anytls', 'vless', 'vmess', 'trojan', 'ss', 'socks5', 'http', 'hysteria2', 'hysteria', 'tuic'}
PROXY_KEYS = {'name', 'type', 'server', 'port', 'ports', 'mport', 'username', 'password', 'uuid',
              'udp', 'tls', 'sni', 'servername', 'skip-cert-verify', 'alpn', 'client-fingerprint',
              'fingerprint', 'network', 'flow', 'cipher', 'alterId', 'encryption', 'packet-encoding',
              'up', 'down', 'auth-str', 'auth', 'obfs', 'obfs-password', 'congestion-controller',
              'udp-relay-mode', 'disable-sni', 'reduce-rtt', 'heartbeat-interval', 'hop-interval',
              'reality-opts', 'ech-opts', 'ws-opts', 'grpc-opts', 'http-opts', 'h2-opts',
              'idle-session-check-interval', 'idle-session-timeout', 'min-idle-session'}
NESTED_PROXY_KEYS = {
    'reality-opts': {'public-key', 'short-id'},
    'ech-opts': {'enable', 'config', 'query-server-name'},
    'ws-opts': {'path', 'headers', 'max-early-data', 'early-data-header-name', 'v2ray-http-upgrade', 'v2ray-http-upgrade-fast-open'},
    'grpc-opts': {'grpc-service-name'},
    'http-opts': {'method', 'path', 'headers'},
    'h2-opts': {'host', 'path'},
}


def validate_proxy_fields(node):
    if node.get('type') not in PROXY_TYPES:
        raise ValueError('订阅包含此独立版本暂不支持的协议。')
    if set(node) - PROXY_KEYS:
        raise ValueError('订阅节点包含暂不支持的高级字段；未执行或载入外部插件。')
    for key, allowed in NESTED_PROXY_KEYS.items():
        if key in node and (not isinstance(node[key], dict) or set(node[key]) - allowed):
            raise ValueError('订阅节点的传输选项不受支持。')
    if not isinstance(node.get('server'), str) or not node['server'] or any(ch in node['server'] for ch in '/@ \r\n\t'):
        raise ValueError('订阅节点服务器地址不合法。')
    try:
        port = int(node['port'])
        if not 1 <= port <= 65535:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise ValueError('订阅节点端口不合法。') from None


def normalize_subscription(config):
    if not isinstance(config, dict) or not isinstance(config.get('proxies'), list):
        raise ValueError('订阅需要包含 proxies 节点列表；此版本暂不支持只有 proxy-providers 或 Base64 链接的订阅。')
    nodes = []
    names = set()
    for node in config['proxies']:
        if not isinstance(node, dict) or not isinstance(node.get('name'), str) or not node.get('type'):
            raise ValueError('订阅中存在格式不完整的节点。')
        name = node['name']
        if name in (EXIT_NAME, RELAY_NAME):
            continue
        if name in names:
            raise ValueError('订阅包含重复的节点名称，请修正后导入。')
        if node['type'] in ('direct', 'reject', 'compatible'):
            continue
        validate_proxy_fields(node)
        names.add(name)
        nodes.append(copy.deepcopy(node))
    if not nodes:
        raise ValueError('订阅没有可用代理节点。')
    return {'proxies': nodes}


def available_nodes(config):
    names = [item['name'] for item in config.get('proxies', [])]
    return [name for name in names if not any(word in name for word in ('剩余', '重置', '到期', '官网', '发布页', '全红', '流量', '套餐'))]


def node_digest(node):
    # 摘要包含完整节点字段，凭据或传输选项改变后不可复用旧延迟。
    encoded = json.dumps(node, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def read_node_delay_cache():
    try:
        value = read_json(DATA / 'node-delays.json', {})
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        # 延迟缓存不是连接配置；损坏时只丢弃延迟，不阻止状态页面打开。
        return {}


def valid_node_delay(result):
    if not isinstance(result, dict) or result.get('status') not in ('ok', 'timeout', 'error'):
        return False
    delay = result.get('delay_ms')
    if result['status'] == 'ok':
        return type(delay) is int and 1 <= delay <= NODE_DELAY_MAX_MS
    return 'delay_ms' not in result


def cached_node_delays(uid, config):
    records = read_node_delay_cache().get(uid, {})
    if not isinstance(records, dict):
        return {}
    result = {}
    nodes = {node['name']: node for node in config.get('proxies', [])}
    for name in available_nodes(config):
        entry = records.get(name)
        if (not valid_node_delay(entry) or entry.get('measurement_version') != NODE_DELAY_MEASUREMENT_VERSION or
                entry.get('method') != NODE_DELAY_METHOD or
                entry.get('digest') != node_digest(nodes[name])):
            continue
        try:
            datetime.datetime.fromisoformat(entry['tested_at'])
        except (KeyError, TypeError, ValueError):
            continue
        result[name] = {'status': entry['status'], 'tested_at': entry['tested_at']}
        if entry['status'] == 'ok':
            result[name]['delay_ms'] = entry['delay_ms']
    return result


def node_delay_context(uid, running=True):
    if settings().get('current_subscription_uid') != uid:
        raise ValueError('只能检测当前所选订阅的节点，请刷新订阅列表。')
    source = normalize_subscription(cached(subscription(uid)))
    source_nodes = {node['name']: node_digest(node) for node in source.get('proxies', [])}
    if not running:
        return source, source_nodes
    active = read_json(DATA / 'active.json', {})
    if not isinstance(active, dict):
        raise RuntimeError('缺少当前运行配置记录，请重新连接当前订阅后检测。')
    active_nodes = {node['name']: node_digest(node) for node in active.get('proxies', []) if node.get('name') != EXIT_NAME}
    if not source_nodes or source_nodes != active_nodes:
        raise RuntimeError('订阅节点与正在使用的配置不一致，请重新连接当前订阅后检测。')
    return source, source_nodes


def physical_default_interface():
    try:
        output = run(['/sbin/route', '-n', 'get', 'default'], timeout=1)
    except (RuntimeError, OSError):
        raise RuntimeError('无法确认物理网络接口，已停止离线测速；当前 VPN 保持不变。') from None
    interfaces = re.findall(r'^\s*interface:\s*(\S+)\s*$', output, re.MULTILINE)
    # macOS 的 Wi-Fi/以太网使用 enN；不接受隧道、回环或未知接口后回落默认路由。
    if len(interfaces) != 1 or not re.fullmatch(r'en[0-9]{1,3}', interfaces[0]):
        raise RuntimeError('默认路由未指向可确认的物理网络接口，无法安全进行离线测速。')
    return interfaces[0]


def offline_delay_config(nodes, interface, socket_path, secret):
    if not re.fullmatch(r'en[0-9]{1,3}', interface):
        raise ValueError('离线测速网络接口不合法。')
    normalized = normalize_subscription({'proxies': nodes})['proxies']
    if not 1 <= len(normalized) <= NODE_DELAY_MAX_NAMES or len(normalized) != len(nodes):
        raise ValueError('离线测速节点数量不正确。')
    resolver = ['https://223.5.5.5/dns-query#DIRECT']
    return {'mixed-port': 0, 'port': 0, 'socks-port': 0, 'redir-port': 0, 'tproxy-port': 0,
            'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule', 'ipv6': False,
            'log-level': 'silent', 'find-process-mode': 'off', 'interface-name': interface,
            'tcp-concurrent': True, 'unified-delay': True, 'geodata-mode': False, 'geo-auto-update': False,
            'external-controller-unix': str(socket_path), 'secret': secret,
            'profile': {'store-selected': False, 'store-fake-ip': False},
            'tun': {'enable': False},
            'dns': {'enable': True, 'listen': '127.0.0.1:0', 'ipv6': False,
                    'enhanced-mode': 'redir-host', 'respect-rules': True,
                    'default-nameserver': resolver[:], 'nameserver': resolver[:],
                    'proxy-server-nameserver': resolver[:], 'direct-nameserver': resolver[:]},
            'proxies': normalized, 'proxy-groups': [], 'rules': ['MATCH,DIRECT']}


def offline_probe_api(socket_path, secret, path, timeout):
    # curl 仅连接此临时目录中的 Unix socket；令牌通过 stdin 传递，不进入进程参数。
    args = ['/usr/bin/curl', '-q', '--silent', '--show-error', '--max-time', str(timeout),
            '--connect-timeout', str(min(0.5, timeout)), '--proxy', '', '--noproxy', '*',
            '--path-as-is', '--unix-socket', str(socket_path), '--header', '@-',
            '--max-filesize', '65536', '--write-out', '\n%{http_code}', 'http://localhost' + path]
    try:
        response = subprocess.run(args, input='Authorization: Bearer ' + secret + '\n',
                                  text=True, encoding='utf-8', errors='replace', capture_output=True, timeout=timeout,
                                  env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path(socket_path).parent), 'LANG': 'en_US.UTF-8'})
    except subprocess.TimeoutExpired:
        return 28, 0, {}
    except OSError:
        return -1, 0, {}
    body, separator, http_text = response.stdout.rpartition('\n')
    status = int(http_text) if separator and http_text.isdigit() else 0
    try:
        payload = json.loads(body) if len(body) <= 65536 else {}
    except ValueError:
        payload = {}
    return response.returncode, status, payload if isinstance(payload, dict) else {}


def offline_probe_node(name, socket_path, secret, deadline):
    budget = min(NODE_DELAY_MAX_MS / 1000 + 0.5, deadline - time.monotonic())
    if CANCEL_PROBES.is_set():
        return {'name': name, 'status': 'error'}
    if budget <= 0:
        return {'name': name, 'status': 'timeout'}
    encoded = urllib.parse.quote(name, safe='').replace('.', '%2E')
    path = '/proxies/' + encoded + '/delay?url=http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=' + str(NODE_DELAY_MAX_MS)
    code, status, payload = offline_probe_api(socket_path, secret, path, budget)
    if code == 28 or status == 504:
        return {'name': name, 'status': 'timeout'}
    result = {'name': name, 'status': 'ok', 'delay_ms': payload.get('delay')}
    return result if code == 0 and status == 200 and valid_node_delay(result) else {'name': name, 'status': 'error'}


def stop_offline_probe(process):
    if process is None or process.poll() is not None:
        return
    # start_new_session 保证只终止本次临时内核的进程组，不按进程名查杀其他 VPN。
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.4)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            raise RuntimeError('临时测速内核未能按期退出，请稍后重试；未修改系统网络配置。') from None


def offline_delay_total_seconds(count):
    """一个临时内核测完全部节点：启动预算 + 按并发分轮的探测预算 + 回收余量。"""
    rounds = -(-count // NODE_DELAY_CONCURRENCY)
    return OFFLINE_DELAY_STARTUP_SECONDS + 2.0 + rounds * (NODE_DELAY_MAX_MS / 1000 + 0.6) + 1.0


def offline_node_delays(nodes):
    deadline = time.monotonic() + offline_delay_total_seconds(len(nodes))
    work_deadline = deadline - 1.0  # 留出 TERM/KILL 与回收进程的时间。
    core = resources() / 'mihomo'
    if not core.is_file():
        raise RuntimeError('应用缺少测速内核，请重新安装完整版本。')
    interface = physical_default_interface()
    # Darwin Unix socket 路径上限较短；目录 0700 是主要隔离边界，不能只依赖令牌。
    with tempfile.TemporaryDirectory(prefix='se-delay-', dir='/tmp') as directory:
        root = Path(directory)
        os.chmod(root, 0o700)
        socket_path = root / 'c.sock'
        secret = secrets.token_urlsafe(32)
        config = offline_delay_config(nodes, interface, socket_path, secret)
        path = root / 'config.json'
        put_json(path, config)
        environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(root), 'LANG': 'en_US.UTF-8'}
        process = None
        try:
            checked = subprocess.run([str(core), '-t', '-d', str(root), '-f', str(path)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=min(2.0, max(0.01, work_deadline - time.monotonic())), env=environment)
            if checked.returncode:
                raise RuntimeError('离线测速配置未通过内核校验，未改动当前网络。')
            process = subprocess.Popen([str(core), '-d', str(root), '-f', str(path)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True, env=environment, cwd=root)
            startup_deadline = min(time.monotonic() + OFFLINE_DELAY_STARTUP_SECONDS, work_deadline)
            ready = False
            while time.monotonic() < startup_deadline:
                if process.poll() is not None:
                    break
                if socket_path.exists():
                    os.chmod(socket_path, 0o600)
                    budget = min(0.25, max(0.01, startup_deadline - time.monotonic()))
                    code, status, payload = offline_probe_api(socket_path, secret, '/version', budget)
                    if code == 0 and status == 200 and payload.get('version'):
                        ready = True
                        break
                time.sleep(min(0.03, max(0, startup_deadline - time.monotonic())))
            if not ready:
                raise RuntimeError('临时测速内核未能在 3 秒内就绪，当前 VPN 保持不变。')
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(NODE_DELAY_CONCURRENCY, len(nodes))) as pool:
                jobs = [pool.submit(offline_probe_node, node['name'], socket_path, secret, work_deadline) for node in nodes]
                return {'results': [job.result() for job in jobs]}
        except subprocess.TimeoutExpired:
            raise RuntimeError('离线测速准备超时，当前 VPN 保持不变。') from None
        except OSError:
            raise RuntimeError('无法启动或访问临时测速内核，当前 VPN 保持不变。') from None
        finally:
            stop_offline_probe(process)


def node_delays(uid, names):
    if (not isinstance(uid, str) or not uid or not isinstance(names, list) or
            not 1 <= len(names) <= NODE_DELAY_MAX_NAMES or
            any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names)):
        raise ValueError('延迟检测需要订阅编号和 1–' + str(NODE_DELAY_MAX_NAMES) + ' 个不重复的节点名称。')
    require_settled()
    running = bool(known_service_status(allow_stopped_error=True).get('running'))
    source, digests = node_delay_context(uid, running=running)
    allowed = set(available_nodes(source))
    if any(name not in allowed or name in (EXIT_NAME, RELAY_NAME) for name in names):
        raise ValueError('只能检测当前订阅中可用的机场节点。')
    by_name = {node['name']: node for node in source['proxies']}
    response = service('node_delays', names=names) if running else offline_node_delays([by_name[name] for name in names])
    results = response.get('results')
    if (not isinstance(results, list) or len(results) != len(names) or
            any(not valid_node_delay(item) or item.get('name') not in names for item in results) or
            len({item['name'] for item in results}) != len(names)):
        raise RuntimeError('节点延迟结果格式不正确，请刷新后重试。')
    # 测速期间开始了连接、切换或停止：结果可能测在正在切换的内核上，整轮丢弃。
    if CANCEL_PROBES.is_set():
        raise RuntimeError('节点测速已被新的网络操作中止。')
    # 其他进程可能在检测期间改动选择或缓存，不能把结果归到新配置上。
    _, latest_digests = node_delay_context(uid, running=running)
    if latest_digests != digests:
        raise RuntimeError('检测期间订阅节点发生变化，请重新检测。')
    tested_at = now()
    cache = read_node_delay_cache()
    previous = cache.get(uid, {})
    previous = previous if isinstance(previous, dict) else {}
    records = {name: entry for name, entry in previous.items()
               if isinstance(entry, dict) and entry.get('measurement_version') == NODE_DELAY_MEASUREMENT_VERSION and
               entry.get('method') == NODE_DELAY_METHOD and
               name in digests and entry.get('digest') == digests[name]}
    measured = {}
    for entry in results:
        name = entry['name']
        public = {'status': entry['status'], 'tested_at': tested_at}
        if entry['status'] == 'ok':
            public['delay_ms'] = entry['delay_ms']
        measured[name] = public
        records[name] = dict(public)
        records[name]['digest'] = digests[name]
        records[name]['measurement_version'] = NODE_DELAY_MEASUREMENT_VERSION
        records[name]['method'] = NODE_DELAY_METHOD
    cache[uid] = records
    put_json(DATA / 'node-delays.json', cache)
    return {'subscription_uid': uid, 'node_delays': measured}


def validation_cache_key(config, root):
    """只计算校验身份；凭据参与摘要，但配置、路径和凭据均不落入缓存。"""
    try:
        geodata = root / 'geodata'
        # 这两个文件随应用一起分发，缺失时绝不复用旧的成功结果。
        if not all((geodata / name).is_file() for name in ('geosite.dat', 'Country.mmdb')):
            return None
        paths = [root / 'mihomo']
        # Mihomo 在工作目录创建的运行缓存不属于规则资源；不能令它反复失效。
        ignored = {'cache.db', 'cache.db-wal', 'cache.db-shm', 'cache.db-journal', '.DS_Store'}
        paths.extend(sorted(path for path in geodata.rglob('*') if path.name not in ignored and path.is_file()))
        identities = []
        for path in paths:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
            identities.append({'path': str(resolved), 'device': info.st_dev, 'inode': info.st_ino,
                               'size': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns})
        encoded = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
        fingerprint = {'version': VALIDATION_CACHE_VERSION,
                       'config': hashlib.sha256(encoded.encode('utf-8')).hexdigest(), 'resources': identities}
        payload = json.dumps(fingerprint, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(payload).hexdigest()
    except (OSError, TypeError, ValueError):
        # 缓存只是性能优化，无法读取资源身份时继续正常校验。
        return None


def validation_cache_entries():
    try:
        value = read_json(DATA / VALIDATION_CACHE_FILE, {})
        if (not isinstance(value, dict) or set(value) != {'version', 'entries'} or
                type(value['version']) is not int or value['version'] != VALIDATION_CACHE_VERSION or
                not isinstance(value['entries'], list) or len(value['entries']) > VALIDATION_CACHE_LIMIT):
            return []
        for entry in value['entries']:
            if (not isinstance(entry, dict) or set(entry) != {'digest', 'validated_at'} or
                    not isinstance(entry['digest'], str) or not re.fullmatch(r'[0-9a-f]{64}', entry['digest']) or
                    not isinstance(entry['validated_at'], str)):
                return []
            timestamp = datetime.datetime.fromisoformat(entry['validated_at'])
            if timestamp.tzinfo is None:
                return []
        return value['entries']
    except (OSError, TypeError, ValueError, KeyError):
        return []


def remember_validation(digest):
    entries = [entry for entry in validation_cache_entries() if entry['digest'] != digest]
    entries.append({'digest': digest, 'validated_at': now()})
    try:
        put_json(DATA / VALIDATION_CACHE_FILE,
                 {'version': VALIDATION_CACHE_VERSION, 'entries': entries[-VALIDATION_CACHE_LIMIT:]})
    except (OSError, TypeError, ValueError):
        # 写入失败不能把真实校验成功变成失败。
        pass


def validate_core(config):
    root = resources()
    core = root / 'mihomo'
    if not core.is_file():
        raise RuntimeError('应用中缺少独立内核，请重新构建或安装完整版本。')
    digest = validation_cache_key(config, root)
    if digest is not None and any(entry['digest'] == digest for entry in validation_cache_entries()):
        return True
    with tempfile.TemporaryDirectory(prefix='static-exit-validate-') as directory:
        candidate = Path(directory) / 'config.json'
        put_json(candidate, config)
        try:
            run([str(core), '-t', '-d', str(root / 'geodata'), '-f', str(candidate)], timeout=25)
        except RuntimeError:
            raise ValueError('内核配置校验失败；请检查订阅节点是否受当前内核支持。原配置保持不变。') from None
    # 校验中资源被替换时不缓存；特权服务仍会独立执行策略检查与内核校验。
    if digest is not None and digest == validation_cache_key(config, root):
        remember_validation(digest)
    return False


def validate_subscription(config):
    validate_core({'proxies': copy.deepcopy(config['proxies']), 'proxy-groups': [],
                   'rules': ['MATCH,DIRECT'], 'mode': 'rule', 'tun': {'enable': False}, 'dns': {'enable': False}})


def static_proxy(profile):
    secret = keychain('get', profile['id'])
    if not secret.get('ok'):
        raise RuntimeError('无法读取所选静态 IP 的钥匙串密码。')
    proxy = {'name': EXIT_NAME, 'type': 'http' if profile['protocol'] == 'https' else profile['protocol'],
             'server': profile['server'], 'port': profile['port'], 'username': profile['username'],
             'password': secret.get('password', ''), 'udp': False, 'dialer-proxy': RELAY_NAME}
    if profile['protocol'] == 'https':
        proxy['tls'] = True
    return proxy


def generate_config(config, profile, relay, preferences):
    nodes = available_nodes(config)
    if relay not in nodes:
        raise ValueError('所选中转节点已不在订阅中，请刷新并重新选择。')
    token = preferences.get('controller_secret')
    if not token:
        raise RuntimeError('控制接口尚未初始化。')
    return {'mixed-port': MIXED_PORT, 'allow-lan': False, 'bind-address': '127.0.0.1',
            'secret': token,
            'mode': 'rule', 'ipv6': False, 'log-level': 'warning', 'find-process-mode': 'off',
            'tcp-concurrent': True, 'unified-delay': True,
            'geodata-mode': False, 'geo-auto-update': False,
            'profile': {'store-selected': False, 'store-fake-ip': False},
            'tun': {'enable': True, 'device': 'utun78', 'stack': 'mixed', 'auto-route': True,
                    'auto-detect-interface': True, 'strict-route': True,
                    'dns-mode': 'native', 'dns-hijack': ['any:53', 'tcp://any:53']},
            'dns': {'enable': True, 'listen': '127.0.0.1:17895', 'ipv6': False,
                    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                    'fake-ip-filter': ['*.lan', '*.local', 'localhost'], 'respect-rules': True,
                    'default-nameserver': ['223.5.5.5'],
                    'nameserver': ['https://1.1.1.1/dns-query'],
                    'proxy-server-nameserver': ['https://223.5.5.5/dns-query#DIRECT'],
                    'nameserver-policy': {'geosite:cn': ['https://223.5.5.5/dns-query#DIRECT']}},
            'proxies': copy.deepcopy(config['proxies']) + ([static_proxy(profile)] if profile else []),
            'proxy-groups': [{'name': RELAY_NAME, 'type': 'select', 'proxies': [relay]}],
            'rules': RULES[:] if profile else RELAY_ONLY_RULES[:]}


def chosen_profile(profile_id):
    """空 ID 表示不使用静态 IP（仅中转节点）；指定了但已不在库中时报错，避免静默改成直连节点。"""
    if not profile_id:
        return None
    profile = next((entry for entry in profiles() if entry['id'] == profile_id), None)
    if profile is None:
        raise ValueError('所选静态 IP 已不在库中，请重新选择，或取消选择以仅使用中转节点。')
    return profile


DIAGNOSTICS_MAX_BYTES = 128 * 1024
DIAGNOSTICS_LOCK = threading.Lock()
# 首波用 IP 直连的 Cloudflare trace（证书含 IP，仍严格校验 TLS）：规则匹配无需先经代理链路解析域名，
# 省去冷启动时一整轮 DoH 往返；第二波换用其他服务商，避免单一服务商不可用时检测失败。
VERIFY_ENDPOINTS = (('1.1.1.1', '/cdn-cgi/trace'), ('1.0.0.1', '/cdn-cgi/trace'),
                    ('api.ipify.org', ''), ('icanhazip.com', ''))
VERIFY_HOSTS = tuple(host for host, _ in VERIFY_ENDPOINTS)
VERIFY_WAVE_SIZE = 2
VERIFY_TOTAL_SECONDS = 40.0
VERIFY_ATTEMPT_SECONDS = 12.0
VERIFY_MAX_ATTEMPTS = 4
SYSTEM_VERIFY_TOTAL_SECONDS = 25.0
SYSTEM_VERIFY_ATTEMPT_SECONDS = 10.0
SYSTEM_VERIFY_MAX_ATTEMPTS = 4
SYSTEM_WEB_HOST = 'www.google.com'
SYSTEM_DNS_HOST = 'google.com'
SYSTEM_DNS_SECONDS = 3.0
FAKE_IP_NETWORK = ipaddress.ip_network('198.18.0.0/16')
# 经中转与静态出口的单次 HTTPS 常见 1.5–5.5 秒；超过此时限仍无结论时提前发起下一波，旧请求继续竞速。
VERIFY_HEDGE_SECONDS = 4.0


# 进程级取消：本进程的后台补充检测已被新的网络操作取代，在途 curl 立即回收且不再写诊断。
CANCEL_PROBES = threading.Event()
DEFERRED_LOCK_FILE = 'deferred-checks.lock'
DEFERRED_CANCEL_FILE = 'deferred-checks.cancel'
# 会重启内核、重载配置或停止 TUN 的操作；开始前必须先中止上一次连接的后台补充检测。
NETWORK_OPS = ('start', 'switch', 'stop', 'restore', 'select_subscription', 'update_subscription')
NODE_DELAY_LOCK_FILE = 'node-delays.lock'
NODE_DELAY_CANCEL_FILE = 'node-delays.cancel'
# 不占操作锁、可被网络操作中止的后台任务：(锁文件, 取消标记, 已在运行时的提示, 被中止时的提示)。
BACKGROUND_OPS = {
    'deferred_checks': (DEFERRED_LOCK_FILE, DEFERRED_CANCEL_FILE,
                        '上一次连接后检测仍在进行，已跳过本次。', '连接后检测已被新的网络操作取消。'),
    'node_delays': (NODE_DELAY_LOCK_FILE, NODE_DELAY_CANCEL_FILE,
                    '节点测速正在进行，请稍后。', '节点测速已被新的网络操作中止。'),
}


def record_verification(attempt, host, code, elapsed, result, category, http_status=0, phase='exit_verification'):
    # 被取代的检测看到的是正在切换的路由，结果不代表线路状态，不能留下误导性的记录。
    if CANCEL_PROBES.is_set():
        return
    # 三条实时检测并行完成；必须锁住整个读改写过程，不能只锁最后的替换。
    with DIAGNOSTICS_LOCK:
        _record_verification(attempt, host, code, elapsed, result, category, http_status, phase)


def _record_verification(attempt, host, code, elapsed, result, category, http_status=0, phase='exit_verification'):
    # 仅记录固定诊断字段，不接受 URL、异常原文、响应正文、IP 账号或配置。
    phases = ('exit_verification', 'system_exit_verification', 'system_web_verification', 'system_dns_verification')
    record = {'time': now(), 'phase': phase if phase in phases else 'unknown', 'attempt': int(attempt),
              'host': host if host in VERIFY_HOSTS + (SYSTEM_WEB_HOST, SYSTEM_DNS_HOST) else 'unknown', 'code': int(code),
              'elapsed': round(max(0.0, elapsed), 3), 'result': result,
              'category': category, 'http_status': int(http_status)}
    try:
        path = DATA / 'diagnostics.jsonl'
        previous = b''
        truncated = False
        if path.exists():
            with path.open('rb') as stream:
                length = stream.seek(0, 2)
                truncated = length > DIAGNOSTICS_MAX_BYTES
                stream.seek(max(0, length - DIAGNOSTICS_MAX_BYTES))
                previous = stream.read(DIAGNOSTICS_MAX_BYTES)
        encoded = json.dumps(record, ensure_ascii=False).encode('utf-8') + b'\n'
        lines = previous.splitlines(keepends=True)
        if truncated and lines:
            lines.pop(0)
        while lines and sum(map(len, lines)) + len(encoded) > DIAGNOSTICS_MAX_BYTES:
            lines.pop(0)
        write(path, (b''.join(lines) + encoded).decode('utf-8', errors='ignore'))
    except (OSError, ValueError):
        # 日志写入失败不能改变出口检测结果。
        pass


def verification_failure(code, http_status):
    if code == 7:
        return 'local_proxy', '本地代理端口无法连接，请确认独立网络服务仍在运行。', False
    if code in (60, 51, 58, 77, 83, 90, 91):
        return 'certificate', '查询服务的 TLS 证书校验失败，已停止检测且未跳过证书校验。', False
    if code == 28:
        return 'timeout', '连接超时，中转线路或查询服务尚未响应。', True
    if code in (35, 52, 55, 56):
        return 'tls_interrupted', '代理链路的 TLS 连接中断，可能是中转或静态代理连接被关闭。', True
    if code == 22 or http_status >= 300:
        return 'query_http', '公网 IP 查询服务返回 HTTP ' + str(http_status or '错误') + '。', http_status == 429 or http_status >= 500
    if code in (5, 6):
        return 'dns', '查询域名解析失败，请检查代理链路 DNS。', True
    if code == 63:
        return 'invalid_ip', '公网 IP 查询服务返回的数据超出预期。', True
    return 'connection', '无法完成公网出口检测（连接错误 ' + str(code) + '）。', False


class ProbeCancelled(Exception):
    """同轮另一个查询已完成；主动取消不代表线路故障。"""


def stop_probe_process(process):
    """只回收本次创建的 curl，不留下读取旧路由的在途进程。"""
    if process.poll() is None:
        process.terminate()
    try:
        return process.communicate(timeout=0.25)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate()


def run_probe(args, *, timeout, env=None, cancelled=None):
    """可单独 mock 的 curl 边界；IP 竞速支持取消，Google 保留普通有界调用。"""
    if cancelled is None:
        return subprocess.run(args, text=True, encoding='utf-8', errors='replace',
                              capture_output=True, timeout=timeout, env=env)
    if cancelled.is_set() or CANCEL_PROBES.is_set():
        raise ProbeCancelled()
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(args, text=True, encoding='utf-8', errors='replace',
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        while True:
            # 已完成的响应必须交给上层判定，不能被稍后的取消掩盖证书或出口错误。
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
            if cancelled.is_set() or CANCEL_PROBES.is_set():
                stdout, stderr = stop_probe_process(process)
                if process.returncode is not None and process.returncode >= 0:
                    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
                raise ProbeCancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_probe_process(process)
                raise subprocess.TimeoutExpired(args, timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(0.05, remaining))
                return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            stop_probe_process(process)


def response_ip(body):
    """纯文本站点直接返回 IP；Cloudflare trace 为 key=value 行，只取 ip 字段。结果仍需通过 IP 校验。"""
    fields = dict(line.partition('=')[::2] for line in body.splitlines() if '=' in line)
    return (fields['ip'] if 'ip' in fields else body).strip()


def query_ip_attempt(host, attempt, deadline, attempt_seconds, phase, port, expected, cancelled, path=''):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'retry': True, 'reason': '检测总时限已到。'}
    budget = min(attempt_seconds, remaining)
    system = phase == 'system_exit_verification'
    environment = ({key: value for key, value in os.environ.items()
                    if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
                   if system else None)
    # 两种路径均禁用 .curlrc 并严格校验 HTTPS，系统路径还移除所有环境代理。
    args = ['/usr/bin/curl', '-q', '--silent', '--show-error']
    if not system:
        args.append('--fail')
    args += ['--noproxy', '*' if system else '', '--proxy', '' if system else 'http://127.0.0.1:' + str(port),
             # 握手经过中转与静态出口，冷启动常超过 5 秒；连接阶段可使用整个单次预算，避免掐断后重来。
             '--proto', '=https', '--connect-timeout', str(budget),
             '--max-time', str(budget), '--max-filesize', '1024',
             '--write-out', '\n%{http_code}', 'https://' + host + path]
    started = time.monotonic()
    try:
        completed = run_probe(args, timeout=budget, env=environment, cancelled=cancelled)
        code = completed.returncode
        body, separator, http_text = completed.stdout.rpartition('\n')
        http_status = int(http_text) if separator and http_text.isdigit() else 0
    except ProbeCancelled:
        return {'cancelled': True}
    except subprocess.TimeoutExpired:
        code, http_status, body = 28, 0, ''
    except OSError:
        record_verification(attempt, host, -1, time.monotonic() - started, 'failure', 'local_component', phase=phase)
        raise RuntimeError(('系统路径' if system else '公网出口') + '验证失败：本机 curl 组件不可用。') from None
    elapsed = time.monotonic() - started
    if code == 0 and 200 <= http_status < 300:
        try:
            address = str(ipaddress.ip_address(response_ip(body)))
        except ValueError:
            category, reason, retry = 'invalid_ip', ('系统路径 IP' if system else '公网 IP') + ' 查询服务未返回合法 IP 地址。', True
        else:
            if expected and address != expected:
                record_verification(attempt, host, code, elapsed, 'failure', 'exit_mismatch', http_status, phase)
                return {'retry': False, 'reason': '系统 TUN 公网出口与预期静态 IP 不一致。'}
            record_verification(attempt, host, code, elapsed, 'success', 'ok', http_status, phase)
            return {'ip': address}
    else:
        category, reason, retry = (system_verification_failure if system else verification_failure)(code, http_status)
    record_verification(attempt, host, code, elapsed, 'failure', category, http_status, phase)
    return {'retry': retry, 'reason': reason}


def hedged_probes(probe, count, wave, deadline, decisive):
    """按波次发起检测：本波全部失败或超过对冲时限仍无结论时发起下一波，旧请求继续竞速。

    出现决定性结果后取消其余请求；返回全部已发起检测的结果（按发起顺序）。"""
    cancelled = threading.Event()
    futures = []
    # 退出上下文会等待全部线程与其 curl 清理完成，随后才能提交或回滚网络。
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        pending = set()
        # 对冲只决定何时多发请求，用真实流逝时间；检测截止仍以 monotonic 共享时限为准。
        hedge_at = 0.0
        try:
            while True:
                more = len(futures) < count and deadline - time.monotonic() > 0
                if more and (not pending or time.perf_counter() >= hedge_at):
                    batch = [executor.submit(probe, len(futures) + index + 1, cancelled)
                             for index in range(min(wave, count - len(futures)))]
                    futures += batch
                    pending.update(batch)
                    hedge_at = time.perf_counter() + VERIFY_HEDGE_SECONDS
                    more = len(futures) < count
                if not pending:
                    break
                timeout = max(0.0, hedge_at - time.perf_counter()) if more else None
                done, pending = concurrent.futures.wait(
                    pending, timeout=timeout, return_when=concurrent.futures.FIRST_COMPLETED)
                if any(decisive(future.result()) for future in done):
                    break
                remaining = deadline - time.monotonic()
                if done and not pending and len(futures) < count and remaining > 0:
                    time.sleep(min(0.15, remaining))
        finally:
            cancelled.set()
    return [future.result() for future in futures]


def verify_ip_race(deadline, attempt_seconds, max_attempts, phase, port=MIXED_PORT, expected=''):
    """每波两站同时查询并按波次对冲；成功后取消慢站，并检查所有已完成响应的致命错误。"""
    prefix = '系统路径验证失败：' if phase == 'system_exit_verification' else '公网出口验证失败：'

    def probe(attempt, cancelled):
        host, path = VERIFY_ENDPOINTS[(attempt - 1) % len(VERIFY_ENDPOINTS)]
        return query_ip_attempt(host, attempt, deadline, attempt_seconds, phase, port, expected, cancelled, path)

    results = hedged_probes(probe, max_attempts, VERIFY_WAVE_SIZE, deadline,
                            lambda result: bool(result.get('ip')) or result.get('retry') is False)
    # 不只看最快响应：取消时已经完成的证书失败、出口不符仍然必须判失败。
    fatal = next((result for result in results if result.get('retry') is False), None)
    if fatal:
        raise RuntimeError(prefix + fatal['reason'])
    addresses = {result['ip'] for result in results if result.get('ip')}
    if len(addresses) > 1:
        raise RuntimeError(prefix + '公网 IP 查询服务返回的出口不一致。')
    if addresses:
        return addresses.pop()
    failures = [result for result in results if result.get('reason')]
    raise RuntimeError(prefix + (failures[-1]['reason'] if failures else '检测总时限已到。')) from None


def verify_exit(port=MIXED_PORT):
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError('本地代理端口不合法。') from None
    return verify_ip_race(time.monotonic() + VERIFY_TOTAL_SECONDS, VERIFY_ATTEMPT_SECONDS,
                          VERIFY_MAX_ATTEMPTS, 'exit_verification', port=port)


def system_verification_failure(code, http_status):
    if code in (5, 6):
        return 'dns', '系统 DNS 无法解析检测域名，请检查 TUN 的 DNS 接管。', True
    if code == 7:
        return 'connection', '系统 TUN 路径无法连接检测网站。', True
    if code == 28:
        return 'timeout', '系统 TUN 路径连接超时，DNS 解析或后续连接尚未完成。', True
    if code in (35, 52, 55, 56):
        return 'tls_interrupted', '系统 TUN 路径的 TLS 连接中断，请检查 DNS 与路由。', True
    return verification_failure(code, http_status)


def query_web_attempt(attempt, deadline, phase, environment, cancelled):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'retry': True, 'reason': '系统路径检测总时限已到。'}
    budget = min(SYSTEM_VERIFY_ATTEMPT_SECONDS, remaining)
    host = SYSTEM_WEB_HOST
    url = 'https://' + host + '/generate_204'
    # 禁用 .curlrc、环境变量与显式代理，保留系统 DNS 解析和 TUN 路由。
    # 不使用 --fail：HTTP 拒绝/限流说明 TLS 已完成，不能误报为链路故障。
    args = ['/usr/bin/curl', '-q', '--silent', '--show-error',
            '--noproxy', '*', '--proxy', '', '--proto', '=https',
            '--connect-timeout', str(budget), '--max-time', str(budget),
            '--write-out', '\n%{http_code}']
    args += ['--output', os.devnull]
    args.append(url)
    started = time.monotonic()
    try:
        completed = run_probe(args, timeout=budget, env=environment, cancelled=cancelled)
        code = completed.returncode
        body, separator, http_text = completed.stdout.rpartition('\n')
        http_status = int(http_text) if separator and http_text.isdigit() else 0
    except ProbeCancelled:
        return {'cancelled': True}
    except subprocess.TimeoutExpired:
        code, http_status, body = 28, 0, ''
    except OSError:
        record_verification(attempt, host, -1, time.monotonic() - started,
                            'failure', 'local_component', phase=phase)
        raise RuntimeError('系统路径验证失败：本机 curl 组件不可用。') from None
    elapsed = time.monotonic() - started
    if code == 0 and 200 <= http_status <= 599:
        warning = '' if http_status in (200, 204) else (
            'Google 已完成 HTTPS 连接，但返回 HTTP ' + str(http_status) +
            '（网站限制或服务响应，不代表 DNS/TUN 链路中断）。')
        record_verification(attempt, host, code, elapsed, 'warning' if warning else 'success',
                            'site_http' if warning else 'ok', http_status, phase)
        return {'warning': warning, 'http_status': http_status}
    category, reason, retry = system_verification_failure(code, http_status)
    record_verification(attempt, host, code, elapsed, 'failure', category, http_status, phase)
    return {'retry': retry, 'reason': reason}


def verify_system_phase(phase, expected, deadline):
    """执行一个系统路径检测；两个阶段共享同一个绝对截止时间。"""
    if phase == 'system_exit_verification':
        return {'ip': verify_ip_race(deadline, SYSTEM_VERIFY_ATTEMPT_SECONDS, SYSTEM_VERIFY_MAX_ATTEMPTS,
                                     phase, expected=expected)}
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    results = hedged_probes(lambda attempt, cancelled: query_web_attempt(attempt, deadline, phase, environment, cancelled),
                            2, 1, deadline, lambda result: 'http_status' in result or result.get('retry') is False)
    # 与 IP 竞速一致：已完成的证书等致命错误不能被另一次成功掩盖。
    fatal = next((result for result in results if result.get('retry') is False), None)
    if fatal:
        raise RuntimeError('系统路径验证失败：' + fatal['reason']) from None
    success = next((result for result in results if 'http_status' in result), None)
    if success:
        return success
    failures = [result for result in results if result.get('reason')]
    raise RuntimeError('系统路径验证失败：' + (failures[-1]['reason'] if failures else '系统路径检测总时限已到。')) from None


def resolve_system_dns(name):
    """可单独 mock 的系统解析器边界；与浏览器一样经 macOS 解析配置查询。"""
    return {item[4][0] for item in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)}


def verify_system_dns(deadline):
    """查询一次性随机子域：TUN DNS 接管生效时立即得到本内核的 fake-ip，不需要经代理链路往返。

    随机名称不会命中系统缓存；接管失效时查询落到局域网 DNS，得不到 fake-ip 即判失败。"""
    phase = 'system_dns_verification'
    reason = '系统 DNS 无法解析检测域名，请检查 TUN 的 DNS 接管。'
    for attempt in range(1, 4):
        budget = min(SYSTEM_DNS_SECONDS, deadline - time.monotonic())
        if budget <= 0:
            break
        name = 'se-' + secrets.token_hex(8) + '.' + SYSTEM_DNS_HOST
        outcome = {}

        def resolve():
            try:
                outcome['addresses'] = resolve_system_dns(name)
            except (OSError, UnicodeError):
                outcome['addresses'] = None
        started = time.monotonic()
        # 守护线程：系统解析器卡住时不阻止短生命周期的后端进程退出。
        worker = threading.Thread(target=resolve, daemon=True)
        worker.start()
        worker.join(budget)
        elapsed = time.monotonic() - started
        addresses = outcome.get('addresses')
        if not addresses:
            code, category = (28, 'timeout') if worker.is_alive() else (6, 'dns')
            reason = '系统 DNS 无法解析检测域名，请检查 TUN 的 DNS 接管。'
        elif all(ipaddress.ip_address(address) in FAKE_IP_NETWORK for address in addresses):
            record_verification(attempt, SYSTEM_DNS_HOST, 0, elapsed, 'success', 'ok', phase=phase)
            return {}
        else:
            code, category = 0, 'dns_bypass'
            reason = '系统 DNS 未经过本应用的 TUN 解析，浏览器可能绕过静态出口。'
        record_verification(attempt, SYSTEM_DNS_HOST, code, elapsed, 'failure', category, phase=phase)
        # 内核注册临时解析器与路由就绪之间可能有极短间隔，短暂等待后用新名称重查。
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.2, remaining))
    raise RuntimeError('系统路径验证失败：' + reason) from None


def verify_system_network(expected, web=True):
    """并行验证系统 TUN 出口、DNS 接管与（可选）HTTPS 网页；全部检测结束后才返回或抛出异常。"""
    if expected:
        try:
            expected = str(ipaddress.ip_address(expected))
        except ValueError:
            raise ValueError('系统路径检测缺少合法的预期出口 IP。') from None
    deadline = time.monotonic() + SYSTEM_VERIFY_TOTAL_SECONDS
    # executor 的上下文退出会等待所有在途 curl 结束，避免回滚期间仍探测旧路由。
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        exit_check = executor.submit(verify_system_phase, 'system_exit_verification', expected, deadline)
        dns_check = executor.submit(verify_system_dns, deadline)
        web_check = executor.submit(verify_system_phase, 'system_web_verification', expected, deadline) if web else None
        exit_result = exit_check.result()
        dns_check.result()
        web_result = web_check.result() if web_check else {}
    return {**exit_result, **web_result}


def verify_connection(expected='', deferred=False):
    """并行完成连接所需实时检查；不缓存可用性或上一次出口结果。

    deferred=True 用于连接事务：关键路径只核实承载整机流量的 TUN 出口与 DNS 接管，
    代理端口与 Google 网页检测由界面在连接后执行 deferred_checks。"""
    if expected:
        try:
            expected = str(ipaddress.ip_address(expected))
        except ValueError:
            raise ValueError('系统路径检测缺少合法的预期出口 IP。') from None
    if deferred:
        system_result = verify_system_network(expected, web=False)
        actual = system_result.get('ip')
        if not actual or (expected and actual != expected):
            raise RuntimeError('系统路径验证失败：系统 TUN 公网出口与预期静态 IP 不一致。')
        return actual, system_result
    web = True
    # 显式代理与系统 TUN 路径互不依赖；未填写预期出口时也并行执行，事后要求两条路径一致。
    # 任一 future 失败时也必须等待其它检测退出，再允许调用方回滚网络。
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        exit_check = executor.submit(verify_exit)
        system_check = executor.submit(verify_system_network, expected, web=web)
        actual = exit_check.result()
        if expected and actual != expected:
            raise RuntimeError('实际公网出口与预期静态 IP 不一致。')
        system_result = system_check.result()
    if system_result.get('ip') != actual:
        raise RuntimeError('系统路径验证失败：系统 TUN 公网出口与预期静态 IP 不一致。')
    return actual, system_result


def await_core(config, timeout=15):
    deadline = time.monotonic() + timeout
    desired_relay = config['proxy-groups'][0]['proxies'][0]
    while time.monotonic() < deadline:
        try:
            live = api('/configs', timeout=2)
            nodes = api('/proxies', timeout=2).get('proxies', {})
            if (live.get('mode') == 'rule' and live.get('tun', {}).get('enable') and
                    (EXIT_NAME in nodes or config['rules'][-1] == 'MATCH,' + RELAY_NAME) and
                    nodes.get(RELAY_NAME, {}).get('now') == desired_relay):
                return
        except (RuntimeError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError('独立内核没有按期进入预期的 TUN 和中转状态。')


def transaction(config, next_settings, expected='', commit=None, rollback_commit=None, recovering=False):
    if (DATA / 'pending.json').exists() and not recovering:
        raise RuntimeError('上次配置操作尚未完成，请先恢复上次配置或停止独立服务。')
    validate_core(config)
    before = known_service_status()
    previous = read_json(DATA / 'active.json', None)
    if before.get('running') and previous is None:
        raise RuntimeError('服务运行状态与本地记录不一致，请先停止独立服务再启动。')
    backup = DATA / 'backups' / (datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    backup.mkdir(parents=True, mode=0o700)
    put_json(backup / 'settings.json', settings())
    put_json(backup / 'subscriptions.json', subscriptions())
    put_json(backup / 'info.json', {'running': bool(before.get('running')), 'created_at': now()})
    if previous is not None:
        put_json(backup / 'active.json', previous)
    put_json(DATA / 'pending.json', {'backup': str(backup), 'stage': 'applying', 'created_at': now()})
    try:
        service('apply' if before.get('running') else 'start', config)
        await_core(config)
        # 关键路径只等 TUN 出口与 DNS 接管；代理端口与网页连通性由界面在连接后检测并提示。
        actual, system_check = verify_connection(expected, deferred=True)
        if commit is not None:
            commit()
        next_settings = copy.deepcopy(next_settings)
        next_settings['last_verified_ip'] = actual
        next_settings['verified_at'] = now()
        put_json(DATA / 'active.json', config)
        put_json(DATA / 'settings.json', next_settings)
        write(DATA / 'last-backup', str(backup))
        (DATA / 'pending.json').unlink(missing_ok=True)
        return {'ip': actual, 'verified_at': next_settings['verified_at'],
                'deferred_checks_pending': True,
                'message': '配置已应用，' + ('静态出口' if config['rules'][-1] == 'MATCH,' + EXIT_NAME else '中转出口') + '、系统 TUN 与 DNS 接管已验证。' + system_check.get('warning', '')}
    except Exception as error:
        try:
            if rollback_commit is not None:
                rollback_commit()
            if before.get('running'):
                service('apply', previous)
                await_core(previous)
            elif known_service_status().get('running'):
                service('stop')
            put_json(DATA / 'settings.json', read_json(backup / 'settings.json', {}))
            if previous is not None:
                put_json(DATA / 'active.json', previous)
            else:
                (DATA / 'active.json').unlink(missing_ok=True)
            (DATA / 'pending.json').unlink(missing_ok=True)
        except Exception:
            raise RuntimeError('应用失败且自动恢复未完成，请先停止独立服务。恢复记录保存在本机。') from None
        # 只转交本程序产生的错误；不可回显未知异常中的凭据或完整配置。
        message = str(error) if isinstance(error, (RuntimeError, ValueError)) else '保存配置时发生错误。'
        raise RuntimeError('应用失败，已恢复原配置或停止新启动的服务。' + message) from None


def select_and_apply(uid=None, profile_id=None, relay=None, start=False):
    require_settled()
    preferences = settings(create=True)
    uid = uid or preferences.get('current_subscription_uid')
    item = subscription(uid)
    source = cached(item)
    # None 沿用上次选择；空字符串表示本次明确不使用静态 IP。
    profile_id = preferences.get('selected_profile_id', '') if profile_id is None else profile_id
    profile = chosen_profile(profile_id)
    names = available_nodes(source)
    if relay and relay not in names:
        raise ValueError('所选中转节点已不在订阅中，请刷新后重新选择。')
    relay = relay or preferences['relays'].get(uid)
    if relay not in names:
        relay = names[0] if names else ''
    preferences['current_subscription_uid'] = uid
    preferences['selected_profile_id'] = profile_id
    preferences['relays'][uid] = relay
    config = generate_config(source, profile, relay, preferences)
    if not start and not known_service_status().get('running'):
        validate_core(config)
        put_json(DATA / 'settings.json', preferences)
        return {**status(), 'message': ('已保存静态 IP 和中转选择' if profile else '已保存中转选择（不使用静态 IP）') + '；点击开始连接后生效。'}
    result = transaction(config, preferences, profile.get('expected', '') if profile else '')
    return {**status(), **result}


SERVICE_ROOT = Path('/Library/Application Support/StaticExitManagerService')


def warm_file_cache(paths):
    """顺序读取一遍文件，让系统页缓存在首次连接前就绪；只读、不保留内容，失败忽略。"""
    for path in paths:
        try:
            with open(path, 'rb') as stream:
                while stream.read(4 * 1024 * 1024):
                    pass
        except OSError:
            continue


def prewarm(profile_id=None, relay=None):
    """打开应用或改选出口时提前完成本次「开始连接」将用到的内核校验。

    生成与 select_and_apply 完全相同的配置，使连接时校验缓存命中；不写设置、不连接服务、不访问网络。"""
    preferences = settings()
    uid = preferences.get('current_subscription_uid')
    profile_id = preferences.get('selected_profile_id', '') if profile_id is None else profile_id
    # 尚未生成控制令牌时，开始连接会新建令牌，预先校验的配置必然不同，直接跳过。
    if not uid or not preferences.get('controller_secret'):
        return {'prewarmed': False}
    try:
        profile = chosen_profile(profile_id)
        source = cached(subscription(uid))
        names = available_nodes(source)
        relay = relay if relay in names else preferences['relays'].get(uid)
        if relay not in names:
            relay = names[0] if names else ''
        cache_hit = validate_core(generate_config(source, profile, relay, preferences))
    except (RuntimeError, ValueError, OSError, KeyError, TypeError):
        # 预热只是性能优化；任何问题留给真正的连接流程给出明确错误。
        return {'prewarmed': False}
    # 网络服务启动前也会用自己的内核副本校验并加载地理数据，提前读入页缓存可缩短首次启动。
    warm_file_cache([SERVICE_ROOT / 'mihomo', SERVICE_ROOT / 'geodata' / 'geosite.dat',
                     SERVICE_ROOT / 'geodata' / 'Country.mmdb'])
    return {'prewarmed': True, 'cache_hit': cache_hit}


def choose_subscription(uid):
    require_settled()
    item = subscription(uid)
    preferences = settings(create=True)
    if known_service_status().get('running'):
        return select_and_apply(uid=uid)
    # 离线时仅选择，真正接管网络必须由用户点击启动。
    preferences['current_subscription_uid'] = uid
    nodes = available_nodes(cached(item))
    if preferences['relays'].get(uid) not in nodes:
        preferences['relays'][uid] = nodes[0] if nodes else ''
    put_json(DATA / 'settings.json', preferences)
    return {**status(), 'message': '已选择订阅，独立服务尚未启动。'}


USAGE_MAX_BYTES = (1 << 63) - 1
USAGE_MIN_EXPIRY = 946684800  # 2000-01-01 UTC；0 表示未提供期限，不能推断永久有效。
USAGE_MAX_EXPIRY = 4102444800  # 2100-01-01 UTC
USAGE_FIELDS = {'upload': 'upload_bytes', 'download': 'download_bytes', 'total': 'total_bytes', 'expire': 'expires_at'}


def usage_integer(value, expiry=False):
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,19}', value.strip()):
        value = int(value.strip())
    if type(value) is not int or not 0 <= value <= USAGE_MAX_BYTES:
        return None
    if expiry and not USAGE_MIN_EXPIRY <= value <= USAGE_MAX_EXPIRY:
        return None
    return value


def usage_timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
        if parsed.tzinfo is None or not 2000 <= parsed.year <= 2100:
            return None
    except ValueError:
        return None
    return value


def empty_subscription_usage(reason='尚未获取订阅用量信息。', checked_at=None):
    return {**{field: None for field in USAGE_FIELDS.values()}, 'used_bytes': None, 'remaining_bytes': None,
            'status': 'unknown', 'source': None, 'fetched_at': None, 'checked_at': checked_at, 'reason': reason}


def public_subscription_usage(value):
    result = empty_subscription_usage()
    if not isinstance(value, dict):
        return result
    for field in USAGE_FIELDS.values():
        result[field] = usage_integer(value.get(field), expiry=field == 'expires_at')
    upload, download, total = (result[field] for field in ('upload_bytes', 'download_bytes', 'total_bytes'))
    if upload is not None and download is not None and upload + download <= USAGE_MAX_BYTES:
        result['used_bytes'] = upload + download
    if result['used_bytes'] is not None and total is not None:
        result['remaining_bytes'] = max(0, total - result['used_bytes'])
    has_data = any(result[field] is not None for field in USAGE_FIELDS.values())
    result['status'] = value.get('status') if has_data and value.get('status') in ('fresh', 'stale') else 'unknown'
    result['source'] = value.get('source') if value.get('source') in ('subscription-userinfo', 'clash-extra') else None
    for field in ('fetched_at', 'checked_at'):
        result[field] = usage_timestamp(value.get(field))
    # 错误文字来自程序固定集合，不输出订阅 URL、HTTP 正文或未知缓存字符串。
    reasons = {'尚未获取订阅用量信息。', '部分流量或到期字段未提供或格式不正确。',
               '订阅服务未返回用量信息。', '订阅用量信息格式不正确。', '订阅用量刷新失败，已保留上次数据。',
               '来自 Clash 本地缓存，尚未从订阅服务刷新。', '本地订阅文件未提供账号用量信息。', ''}
    if isinstance(value.get('reason'), str) and value['reason'] in reasons:
        result['reason'] = value['reason']
    return result


def parse_subscription_userinfo(header, checked_at=None):
    checked_at = checked_at or now()
    if header is None or header == '':
        return empty_subscription_usage('订阅服务未返回用量信息。', checked_at)
    if not isinstance(header, str) or len(header) > 8192:
        return empty_subscription_usage('订阅用量信息格式不正确。', checked_at)
    fields = {}
    for part in header.split(';'):
        key, separator, value = part.partition('=')
        key = key.strip().lower()
        if key not in USAGE_FIELDS:
            continue
        # 重复字段有歧义；单独将该字段置为未知，不能悄悄采用最后一个值。
        fields[key] = None if not separator or key in fields else value.strip()
    result = empty_subscription_usage(checked_at=checked_at)
    for key, target in USAGE_FIELDS.items():
        result[target] = usage_integer(fields.get(key), expiry=key == 'expire')
    has_data = any(result[field] is not None for field in USAGE_FIELDS.values())
    if not has_data:
        return empty_subscription_usage('订阅用量信息格式不正确。', checked_at)
    result.update(status='fresh', source='subscription-userinfo', fetched_at=checked_at,
                  reason='' if all(result[field] is not None for field in USAGE_FIELDS.values()) else '部分流量或到期字段未提供或格式不正确。')
    return public_subscription_usage(result)


def merge_subscription_usage(previous, incoming):
    incoming = public_subscription_usage(incoming)
    if incoming['status'] == 'fresh':
        # 同一次响应构成一个快照；缺字段不与上次值混合成看似完整的新数据。
        return incoming
    previous = public_subscription_usage(previous)
    if previous['status'] != 'unknown':
        return {**previous, 'status': 'stale', 'checked_at': incoming['checked_at'], 'reason': incoming['reason']}
    return incoming


def clash_subscription_usage(source):
    extra = source.get('extra')
    if not isinstance(extra, dict):
        return empty_subscription_usage()
    values = {target: usage_integer(extra.get(key), expiry=key == 'expire') for key, target in USAGE_FIELDS.items()}
    updated = usage_integer(source.get('updated'), expiry=True)
    fetched_at = datetime.datetime.fromtimestamp(updated, datetime.timezone.utc).isoformat() if updated else None
    return public_subscription_usage({**values, 'status': 'stale', 'source': 'clash-extra',
                                      'fetched_at': fetched_at, 'reason': '来自 Clash 本地缓存，尚未从订阅服务刷新。'})


SUBSCRIPTION_NAME_MAX_LENGTH = 80


def clean_subscription_name(value, strip_extension=True):
    if not isinstance(value, str) or len(value) > 4096:
        return ''
    value = unicodedata.normalize('NFC', value)
    value = ''.join(char for char in value if unicodedata.category(char) not in ('Cc', 'Cf', 'Cs'))
    value = ' '.join(value.split()).strip()
    if strip_extension:
        value = re.sub(r'\.(yaml|yml)$', '', value, flags=re.IGNORECASE).strip()
    return value[:SUBSCRIPTION_NAME_MAX_LENGTH].rstrip()


def profile_title_name(value):
    if not isinstance(value, str) or len(value) > 4096:
        return ''
    value = value.strip()
    if value.lower().startswith('base64:'):
        payload = value[7:].strip()
        try:
            value = base64.b64decode(payload + '=' * (-len(payload) % 4), validate=True).decode('utf-8')
        except (binascii.Error, UnicodeError, ValueError):
            return ''
    return clean_subscription_name(value)


def disposition_filename_name(value):
    if not isinstance(value, str) or len(value) > 4096:
        return ''
    # RFC 6266 / RFC 5987：filename* 优先于 filename，解析引号与 quoted-pair。
    pattern = r';\s*(filename\*?)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))'
    parameters = {}
    for match in re.finditer(pattern, value, flags=re.IGNORECASE):
        key = match.group(1).lower()
        raw = re.sub(r'\\(.)', r'\1', match.group(2)) if match.group(2) is not None else match.group(3).strip()
        parameters[key] = '' if key in parameters else raw
    for key in ('filename*', 'filename'):
        candidate = parameters.get(key, '')
        if not candidate:
            continue
        if key == 'filename*':
            parts = candidate.split("'", 2)
            if len(parts) != 3 or parts[0].lower() not in ('utf-8', 'iso-8859-1', 'us-ascii'):
                continue
            if re.search(r'%(?![0-9A-Fa-f]{2})', parts[2]):
                continue
            try:
                candidate = urllib.parse.unquote_to_bytes(parts[2]).decode(parts[0], errors='strict')
            except (UnicodeError, LookupError):
                continue
        # 仅采用服务商明确给出的文件名；丢弃其目录部分，不读取订阅 URL 路径。
        candidate = candidate.replace('\\', '/').rsplit('/', 1)[-1]
        name = clean_subscription_name(candidate)
        if name:
            return name
    return ''


def subscription_response_name(headers, url):
    title = profile_title_name(headers.get('profile-title') or headers.get('Profile-Title'))
    if title:
        return {'name': title, 'name_source': 'profile-title'}
    filename = disposition_filename_name(headers.get('content-disposition') or headers.get('Content-Disposition'))
    if filename:
        return {'name': filename, 'name_source': 'content-disposition'}
    # URL 的 userinfo、路径、query、fragment 可能含订阅凭据，绝不作为显示名。
    host = clean_subscription_name(urllib.parse.urlsplit(url).hostname or '', strip_extension=False)
    return {'name': host or '新订阅', 'name_source': 'url-host'}


def fetch_subscription(url, usage_out=None, headers_only=False, metadata_out=None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('订阅链接必须是 HTTP 或 HTTPS 地址。')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'clash.meta StaticExitManager/0.3'})
        with opener.open(request, timeout=25) as response:
            if urllib.parse.urlsplit(response.url).scheme not in ('http', 'https'):
                raise ValueError('订阅跳转到了不支持的地址。')
            header = response.headers.get('Subscription-Userinfo')
            if hasattr(response.headers, 'get_all'):
                values = response.headers.get_all('Subscription-Userinfo') or []
                header = ';'.join(values) if values else None
            usage = parse_subscription_userinfo(header)
            metadata = subscription_response_name(response.headers, url)
            content = b'' if headers_only else response.read(MAX_SUBSCRIPTION_BYTES + 1)
        if len(content) > MAX_SUBSCRIPTION_BYTES:
            raise ValueError('订阅文件超过大小限制。')
        decoded = content.decode('utf-8-sig')
        if usage_out is not None:
            usage_out.update(usage)
        if metadata_out is not None:
            metadata_out.update(metadata)
        return decoded
    except (OSError, UnicodeError):
        raise RuntimeError('订阅下载失败，原缓存保持不变。') from None


def parse_subscription_text(content):
    with tempfile.TemporaryDirectory(prefix='static-exit-subscription-') as directory:
        source = Path(directory) / 'subscription.yaml'
        write(source, content)
        return normalize_subscription(parse_yaml(source))


def save_subscription(item, config):
    require_settled()
    validate_subscription(config)
    entries = subscriptions()
    if not any(entry['uid'] == item['uid'] for entry in entries):
        entries.append(item)
    else:
        entries = [item if entry['uid'] == item['uid'] else entry for entry in entries]
    put_json(cache_path(item), config)
    put_json(DATA / 'subscriptions.json', entries)
    preferences = settings(create=True)
    if not preferences['current_subscription_uid']:
        preferences['current_subscription_uid'] = item['uid']
        names = available_nodes(config)
        preferences['relays'][item['uid']] = names[0] if names else ''
        put_json(DATA / 'settings.json', preferences)


def add_subscription(name, url):
    require_settled()
    usage, metadata = {}, {}
    config = parse_subscription_text(fetch_subscription(url, usage_out=usage, metadata_out=metadata))
    display_name = clean_subscription_name(name, strip_extension=False) or metadata.get('name') or subscription_response_name({}, url)['name']
    item = {'uid': str(uuid.uuid4()), 'name': display_name, 'kind': 'remote', 'url': url,
            'updated_at': now(), 'usage': public_subscription_usage(usage)}
    save_subscription(item, config)
    return {**status(), 'message': '订阅已导入并通过内核校验。'}


def import_subscription(path, name=''):
    require_settled()
    path = Path(path)
    if path.stat().st_size > MAX_SUBSCRIPTION_BYTES:
        raise ValueError('订阅文件超过大小限制。')
    config = normalize_subscription(parse_yaml(path))
    item = {'uid': str(uuid.uuid4()), 'name': name.strip() or path.stem, 'kind': 'local', 'updated_at': now(),
            'usage': empty_subscription_usage('本地订阅文件未提供账号用量信息。')}
    save_subscription(item, config)
    return {**status(), 'message': '本地订阅已导入。'}


def update_subscription(uid):
    require_settled()
    old = subscription(uid)
    if old.get('kind') != 'remote' or not old.get('url'):
        raise ValueError('本地订阅没有更新链接，请重新导入文件。')
    usage = {}
    config = parse_subscription_text(fetch_subscription(old['url'], usage_out=usage))
    validate_subscription(config)
    item = {**old, 'updated_at': now(), 'cache_id': str(uuid.uuid4()),
            'usage': merge_subscription_usage(old.get('usage'), usage)}
    preferences = settings(create=True)
    if preferences['current_subscription_uid'] == uid and known_service_status().get('running'):
        try:
            profile = chosen_profile(preferences['selected_profile_id'])
        except ValueError:
            raise ValueError('当前静态 IP 已从库中删除，请重新选择后更新。') from None
        relay = preferences['relays'].get(uid)
        if relay not in available_nodes(config):
            raise ValueError('新订阅已移除当前中转节点，已保留旧缓存；请先换中转或停止服务后再更新。')
        candidate = generate_config(config, profile, relay, preferences)
        original_entries = subscriptions()
        new_entries = [item if entry['uid'] == uid else entry for entry in original_entries]
        # 新缓存不可变；校验成功前不更改 subscriptions.json 指向的版本。
        put_json(cache_path(item), config)
        result = transaction(candidate, preferences, profile.get('expected', '') if profile else '',
                             commit=lambda: put_json(DATA / 'subscriptions.json', new_entries),
                             rollback_commit=lambda: put_json(DATA / 'subscriptions.json', original_entries))
        return {**status(), **result, 'message': '订阅已更新，' + ('静态出口' if profile else '中转出口') + '保持可用。'}
    save_subscription(item, config)
    return {**status(), 'message': '订阅已更新并通过内核校验。'}


def public_subscriptions(entries, current_uid):
    return [{'uid': item['uid'], 'name': item['name'], 'current': item['uid'] == current_uid,
             'kind': item.get('kind', 'local'), 'updated_at': item.get('updated_at', ''),
             'usage': public_subscription_usage(item.get('usage'))} for item in entries]


def refresh_subscription_usage(uid):
    require_settled()
    old = subscription(uid)
    previous = old.get('usage')
    # 升级前迁移过的订阅没有 usage，可按原 UID 读取本机缓存；不按同名猜账号。
    if previous is None and old.get('migrated_uid') and (VERGE / 'profiles.yaml').exists():
        try:
            meta = parse_yaml(VERGE / 'profiles.yaml')
            source = next((entry for entry in meta.get('items', []) if entry.get('uid') == old['migrated_uid']), {})
            previous = clash_subscription_usage(source)
        except (OSError, RuntimeError, ValueError):
            pass
    usage = {}
    if old.get('kind') != 'remote' or not old.get('url'):
        usage = empty_subscription_usage('本地订阅文件未提供账号用量信息。', now())
    else:
        try:
            fetch_subscription(old['url'], usage_out=usage, headers_only=True)
        except (OSError, RuntimeError, ValueError):
            usage = empty_subscription_usage('订阅用量刷新失败，已保留上次数据。', now())
    usage = merge_subscription_usage(previous, usage)
    entries = subscriptions()
    entries = [{**item, 'usage': usage} if item['uid'] == uid else item for item in entries]
    put_json(DATA / 'subscriptions.json', entries)
    current_uid = settings()['current_subscription_uid']
    selected = next((item for item in entries if item['uid'] == current_uid), {})
    message = ('订阅用量已刷新。' if usage['status'] == 'fresh' else '') + usage['reason']
    return {'subscriptions': public_subscriptions(entries, current_uid), 'subscription_uid': current_uid,
            'subscription_usage': public_subscription_usage(selected.get('usage')), 'message': message}


def delete_subscription(uid):
    require_settled()
    item = subscription(uid)
    preferences = settings(create=True)
    if preferences['current_subscription_uid'] == uid and known_service_status().get('running'):
        raise ValueError('请先停止独立服务或切换到其他订阅，再删除当前订阅。')
    entries = [entry for entry in subscriptions() if entry['uid'] != uid]
    put_json(DATA / 'subscriptions.json', entries)
    # 不删除版本缓存：历史备份仍可能引用它，恢复不能因此失效。
    preferences['relays'].pop(uid, None)
    if preferences['current_subscription_uid'] == uid:
        preferences['current_subscription_uid'] = entries[0]['uid'] if entries else ''
    put_json(DATA / 'settings.json', preferences)
    return {**status(), 'message': '订阅已从独立管理器删除。'}


def import_runtime_proxy(config):
    proxy = next((item for item in config.get('proxies', []) if item.get('name') == EXIT_NAME), None)
    if proxy is None or proxy.get('type') not in ('socks5', 'http'):
        return False
    summary = summary_proxy(config)
    try:
        ipaddress.ip_address(summary['server'])
        expected = summary['server']
    except ValueError:
        expected = ''
    old = next((item for item in profiles() if (item['server'], item['port'], item['username']) ==
                (proxy['server'], proxy['port'], proxy.get('username', ''))), None)
    value = {**summary, 'name': old['name'] if old else summary['server'],
             'username': proxy.get('username', ''), 'password': proxy.get('password', ''),
             'expected': old.get('expected', expected) if old else expected,
             'expired': old.get('expired', '') if old else '', 'replace_password': True}
    if old:
        value['id'] = old['id']
    result = save(value)
    return next(item['id'] for item in result['profiles'] if item['server'] == proxy['server'] and
                item['port'] == proxy['port'] and item['username'] == proxy.get('username', ''))


def migrate():
    require_settled()
    state = known_service_status()
    if state.get('running'):
        raise ValueError('请先停止独立服务再迁移，避免改变正在使用的订阅记录。')
    meta = parse_yaml(VERGE / 'profiles.yaml')
    original_entries = subscriptions()
    entries = copy.deepcopy(original_entries)
    original_preferences = settings(create=True)
    preferences = copy.deepcopy(original_preferences)
    staged = []
    skipped = 0
    runtime_path = VERGE / 'clash-verge.yaml'
    legacy_runtime = parse_yaml(runtime_path) if runtime_path.exists() else {}
    runtime_group = next((group for group in legacy_runtime.get('proxy-groups', []) if group.get('name') == RELAY_NAME), {})
    runtime_choices = runtime_group.get('proxies', [])
    runtime_relay = runtime_choices[0] if len(runtime_choices) == 1 else None
    legacy_relays = read_json(LIBRARY / 'subscription-relays.json', {})
    # 全部读取和内核校验通过后，才提交独立版订阅目录；任一订阅失败不会形成半迁移。
    for source in meta.get('items', []):
        if source.get('type') not in ('remote', 'local') or not source.get('file'):
            continue
        item = next((entry for entry in entries if entry.get('migrated_uid') == source.get('uid')), None)
        if item:
            skipped += 1
            config = cached(item)
            if not item.get('usage'):
                item['usage'] = clash_subscription_usage(source)
        else:
            filename = Path(source['file'])
            if filename.is_absolute() or '..' in filename.parts:
                raise ValueError('Clash 订阅文件路径异常，未迁移该订阅。')
            config = normalize_subscription(parse_yaml(VERGE / 'profiles' / filename))
            validate_subscription(config)
            item = {'uid': str(uuid.uuid4()), 'name': source.get('name') or '导入订阅',
                    'kind': source['type'], 'migrated_uid': source.get('uid'), 'updated_at': now(),
                    'usage': clash_subscription_usage(source)}
            if source['type'] == 'remote':
                item['url'] = source.get('url', '')
            staged.append((item, config))
            entries.append(item)
        choices = ([runtime_relay] if source.get('uid') == meta.get('current') else [])
        choices += [legacy_relays.get(source.get('uid'))]
        choices += [entry.get('now') for entry in source.get('selected', [])]
        names = available_nodes(config)
        preferences['relays'][item['uid']] = next((choice for choice in choices if choice in names), names[0] if names else '')
        if source.get('uid') == meta.get('current'):
            preferences['current_subscription_uid'] = item['uid']
    if not preferences['current_subscription_uid'] and entries:
        preferences['current_subscription_uid'] = entries[0]['uid']
    # 钥匙串授权可能被拒绝；它发生在订阅目录提交之前，用户可以直接重试迁移。
    imported_profile = import_runtime_proxy(legacy_runtime) if legacy_runtime else False
    if imported_profile:
        preferences['selected_profile_id'] = imported_profile
    elif not preferences['selected_profile_id'] and profiles():
        preferences['selected_profile_id'] = profiles()[0]['id']
    preferences['migrated_at'] = now()
    try:
        for item, config in staged:
            put_json(cache_path(item), config)
        put_json(DATA / 'subscriptions.json', entries)
        put_json(DATA / 'settings.json', preferences)
    except Exception:
        put_json(DATA / 'subscriptions.json', original_entries)
        put_json(DATA / 'settings.json', original_preferences)
        raise RuntimeError('迁移保存失败，原订阅目录已保留；可以重试。') from None
    return {**status(), 'message': f'已迁移 {len(staged)} 个订阅，跳过 {skipped} 个已迁移订阅。Clash 配置未改动，独立服务未启动。'}


def summary_proxy(config):
    proxy = next((entry for entry in (config or {}).get('proxies', []) if entry.get('name') == EXIT_NAME), None)
    if proxy is None:
        return None
    return {'server': proxy.get('server', ''), 'port': proxy.get('port', 0),
            'protocol': 'https' if proxy.get('type') == 'http' and proxy.get('tls') else proxy.get('type', '')}


def status():
    preferences = settings()
    entries = subscriptions()
    selected = next((item for item in entries if item['uid'] == preferences['current_subscription_uid']), None)
    config = cached(selected) if selected else {}
    state = service_status()
    active = read_json(DATA / 'active.json', None) if state.get('running') else None
    selected_profile = next((profile for profile in profiles() if profile['id'] == preferences['selected_profile_id']), None)
    configured = summary_proxy(active) if state.get('running') else ({key: selected_profile[key] for key in ('server', 'port', 'protocol')} if selected_profile else None)
    return {'subscription': selected['name'] if selected else '未选择订阅',
            'subscription_uid': selected['uid'] if selected else '',
            'subscriptions': public_subscriptions(entries, preferences['current_subscription_uid']),
            'subscription_usage': public_subscription_usage(selected.get('usage') if selected else None),
            'nodes': available_nodes(config), 'node_delays': cached_node_delays(selected['uid'], config) if selected else {},
            'relay': preferences['relays'].get(selected['uid'], '') if selected else '',
            'profiles': profiles(), 'selected_profile_id': preferences['selected_profile_id'], 'selected_id': preferences['selected_profile_id'],
            'migrated': bool(preferences.get('migrated_at')), 'service_status': state.get('service_status', 'unavailable'),
            'running': bool(state.get('running')), 'tun': bool(state.get('tun')),
            'mode': 'rule' if state.get('running') else 'stopped', 'mixed_port': state.get('mixed_port', MIXED_PORT),
            'configured_exit': configured, 'backup': (DATA / 'last-backup').exists(),
            'recovery_needed': (DATA / 'pending.json').exists(), 'state_known': state.get('state_known', True), 'service_error': state.get('service_error', '')}


def verify():
    live_state = service_status()
    if not live_state.get('running'):
        raise RuntimeError('独立服务尚未启动，请先启动后检测出口。')
    if not live_state.get('tun'):
        raise RuntimeError('内核运行中，但整机 TUN 路由未生效；请停止后检查其他 VPN。')
    preferences = settings(create=True)
    profile = next((entry for entry in profiles() if entry['id'] == preferences['selected_profile_id']), {})
    address, system_check = verify_connection(profile.get('expected', ''))
    preferences['last_verified_ip'] = address
    preferences['verified_at'] = now()
    put_json(DATA / 'settings.json', preferences)
    return {'ip': address, 'verified_at': preferences['verified_at'],
            'message': '静态出口与系统 TUN 路径验证完成。' + system_check.get('warning', '')}


def deferred_proxy_check(verified):
    try:
        actual = verify_exit()
    except (RuntimeError, ValueError) as error:
        return {'status': 'failure', 'message': '代理端口 127.0.0.1:' + str(MIXED_PORT) + ' 检测失败：' + str(error)}
    if actual != verified:
        return {'status': 'failure', 'message': '代理端口出口与已验证的静态 IP 不一致，请勿经 127.0.0.1:' +
                str(MIXED_PORT) + ' 使用，建议重新连接。'}
    return {'status': 'ok', 'message': ''}


def deferred_web_check():
    try:
        result = verify_system_phase('system_web_verification', '', time.monotonic() + SYSTEM_VERIFY_TOTAL_SECONDS)
    except RuntimeError as error:
        return {'status': 'failure', 'message': str(error)}
    return {'status': 'warning' if result['warning'] else 'ok', 'message': result['warning']}


def watch_deferred_cancel(started_ns):
    watch_cancel(DATA / DEFERRED_CANCEL_FILE, started_ns)


def watch_cancel(path, started_ns):
    """后台检测进程内的守护线程：发现晚于本进程开始的取消标记即中止全部检测。"""
    while not CANCEL_PROBES.is_set():
        try:
            if path.stat().st_mtime_ns >= started_ns:
                CANCEL_PROBES.set()
                return
        except OSError:
            pass
        time.sleep(0.05)


def cancel_deferred_checks(timeout=2.0):
    """新的网络操作开始前中止仍在运行的后台补充检测，并等待它退出后才改变路由。"""
    return cancel_background(DEFERRED_LOCK_FILE, DEFERRED_CANCEL_FILE, timeout)


def cancel_node_delays():
    """中止后台节点测速但不等待：它的结果会整轮丢弃，临时内核绑定物理网卡，不影响新连接。"""
    return cancel_background(NODE_DELAY_LOCK_FILE, NODE_DELAY_CANCEL_FILE, 0)


def cancel_background(lock_name, cancel_name, timeout):
    """用文件锁判断是否有在途检测、用取消标记通知；不按 PID 发信号，避免误伤无关进程。"""
    cancel = DATA / cancel_name
    with open(DATA / lock_name, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            pass
        cancel.touch()
        if timeout <= 0:
            # 不等待时保留标记供对方轮询；之后启动的检测晚于标记时间，不会被误伤。
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(0.02)
    cancel.unlink(missing_ok=True)
    return True


def deferred_checks():
    """连接提交后的补充检测：代理端口出口与 Google 网页并行执行。

    只读，不改配置；失败只提示、不回滚。出口以连接事务记录的实测 IP 为准，不接受界面传入。"""
    state = service_status()
    if not state.get('running') or not state.get('tun'):
        raise RuntimeError('独立服务未运行或 TUN 未生效，已跳过连接后的补充检测。')
    verified = settings().get('last_verified_ip', '')
    if not verified:
        raise RuntimeError('缺少本次连接的实测出口记录，已跳过连接后的补充检测。')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        proxy = executor.submit(deferred_proxy_check, verified)
        web = executor.submit(deferred_web_check)
        results = [proxy.result(), web.result()]
    problems = [result for result in results if result['status'] != 'ok']
    status = 'ok' if not problems else ('failure' if any(item['status'] == 'failure' for item in problems) else 'warning')
    return {'deferred_checks': {'status': status, 'ip': verified,
                                'message': ' '.join(item['message'] for item in problems if item['message'])}}


def restore():
    pointer = DATA / 'last-backup'
    pending = read_json(DATA / 'pending.json', {})
    if not pointer.exists() and not pending.get('backup'):
        raise ValueError('没有可恢复的配置。')
    backup = Path(pending.get('backup') or pointer.read_text().strip()).resolve()
    if (DATA / 'backups').resolve() not in backup.parents:
        raise ValueError('备份位置不合法。')
    config = read_json(backup / 'active.json', None)
    preferences = read_json(backup / 'settings.json', {})
    backup_subscriptions = read_json(backup / 'subscriptions.json', subscriptions())
    info = read_json(backup / 'info.json', {'running': config is not None})
    if not info.get('running') or config is None:
        if known_service_status().get('running'):
            service('stop')
        if config is None:
            (DATA / 'active.json').unlink(missing_ok=True)
        else:
            put_json(DATA / 'active.json', config)
        put_json(DATA / 'settings.json', preferences)
        put_json(DATA / 'subscriptions.json', backup_subscriptions)
        (DATA / 'pending.json').unlink(missing_ok=True)
        return {**status(), 'message': '已恢复到服务未启动的状态。'}
    # 控制令牌属于独立服务；当前版本与备份保持一致，避免恢复时失去连接。
    preferences['controller_secret'] = settings(create=True)['controller_secret']
    config['secret'] = preferences['controller_secret']
    current_subscriptions = subscriptions()
    result = transaction(config, preferences, preferences.get('last_verified_ip', ''),
                         commit=lambda: put_json(DATA / 'subscriptions.json', backup_subscriptions),
                         rollback_commit=lambda: put_json(DATA / 'subscriptions.json', current_subscriptions), recovering=True)
    return {**status(), **result, 'message': '已恢复上次配置并验证出口。'}


# 检查更新：读取 GitHub 最新 Release，下载 dmg 并按 Release 公布的 SHA-256 校验；替换应用由界面完成。
UPDATE_REPO = 'zhilideng/static-exit-manager'
UPDATE_API = f'https://api.github.com/repos/{UPDATE_REPO}/releases/latest'
UPDATE_HOSTS = ('github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com')
UPDATE_CHECK_SECONDS = 24 * 3600
UPDATE_MAX_BYTES = 300 * 1024 * 1024


def app_version():
    import plistlib
    try:
        with open(Path(__file__).resolve().parent.parent / 'Info.plist', 'rb') as stream:
            return str(plistlib.load(stream).get('CFBundleShortVersionString', ''))
    except (OSError, ValueError):
        return ''


def version_tuple(value):
    parts = re.findall(r'\d+', str(value))[:4]
    return tuple(int(part) for part in parts) if parts else (0,)


def check_update(force=False):
    current = app_version()
    state_path = DATA / 'update-check.json'
    state = read_json(state_path, {}) or {}
    if not force and time.time() - float(state.get('checked_at', 0)) < UPDATE_CHECK_SECONDS:
        return {'available': False, 'current': current, 'skipped': True}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(UPDATE_API, headers={'Accept': 'application/vnd.github+json',
                                                          'User-Agent': 'StaticExitManager/' + current})
    release = None
    for _ in range(2):  # 网络偶有抖动，失败时再试一次
        try:
            with opener.open(request, timeout=15) as response:
                release = json.loads(response.read(2 * 1024 * 1024))
            break
        except (OSError, ValueError):
            continue
    if release is None:
        raise RuntimeError('无法连接 GitHub 检查更新，请稍后重试。')
    put_json(state_path, {'checked_at': time.time()})
    latest = str(release.get('tag_name', '')).lstrip('vV')
    asset = next((item for item in release.get('assets', [])
                  if re.fullmatch(r'StaticExitManager-[\d.]+-arm64\.dmg', str(item.get('name', '')))), None)
    if not latest or version_tuple(latest) <= version_tuple(current) or asset is None:
        return {'available': False, 'current': current, 'latest': latest or current}
    digest = str(asset.get('digest') or '')
    sha = digest.split(':', 1)[1] if digest.startswith('sha256:') else ''
    if not re.fullmatch(r'[0-9a-f]{64}', sha):
        found = re.search(r'\b([0-9a-f]{64})\b', str(release.get('body', '')))
        sha = found.group(1) if found else ''
    if not sha:
        raise RuntimeError('新版本缺少 SHA-256 校验值，已停止更新。')
    return {'available': True, 'current': current, 'latest': latest, 'notes': str(release.get('body', ''))[:4000],
            'url': str(asset.get('browser_download_url', '')), 'sha256': sha, 'size': int(asset.get('size') or 0),
            'page': str(release.get('html_url', ''))}


def download_update(url, sha256, version):
    parsed = urllib.parse.urlsplit(str(url))
    if parsed.scheme != 'https' or parsed.hostname != 'github.com' or not re.fullmatch(r'[0-9a-f]{64}', str(sha256)):
        raise ValueError('更新地址或校验值无效。')
    target_dir = DATA / 'updates'
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for old in target_dir.glob('*.dmg'):
        old.unlink(missing_ok=True)
    target = target_dir / f'StaticExitManager-{re.sub(r"[^0-9.]", "", str(version))}-arm64.dmg'
    digest, size = hashlib.sha256(), 0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'StaticExitManager'}), timeout=60) as response:
            if urllib.parse.urlsplit(response.url).hostname not in UPDATE_HOSTS:
                raise ValueError('更新下载被重定向到未知地址。')
            with open(target, 'wb') as stream:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > UPDATE_MAX_BYTES:
                        raise ValueError('更新文件超出大小限制。')
                    digest.update(chunk)
                    stream.write(chunk)
    except (OSError, ValueError) as error:
        target.unlink(missing_ok=True)
        raise RuntimeError('下载更新失败：' + (str(error) if isinstance(error, ValueError) else '网络错误，请稍后重试。')) from None
    if digest.hexdigest() != sha256:
        target.unlink(missing_ok=True)
        raise RuntimeError('更新文件校验失败，已删除下载内容。')
    return {'path': str(target), 'message': '更新已下载并通过校验。'}


def dispatch(request):
    op = request['op']
    if op == 'exit_location': return exit_location(request.get('ip'))
    if op == 'deferred_checks': return deferred_checks()
    if op == 'prewarm': return prewarm(request.get('id'), request.get('relay'))
    if op == 'status': return status()
    if op == 'check_update': return check_update(bool(request.get('force')))
    if op == 'download_update': return download_update(request.get('url'), request.get('sha256'), request.get('version'))
    if op == 'node_delays': return node_delays(request.get('subscription_uid'), request.get('names'))
    if op == 'list': return {'profiles': profiles()}
    if op == 'save': return save(request['profile'])
    if op == 'delete': return delete_profile(request['id'])
    if op == 'import': return import_csv(request['path'])
    if op == 'import_current':
        imported = import_runtime_proxy(read_json(DATA / 'active.json', {}))
        if not imported:
            raise ValueError('独立服务尚未保存静态出口配置。')
        return {'profiles': profiles(), 'message': '当前静态 IP 已载入库。'}
    if op == 'verify': return verify()
    if op in ('start', 'switch'):
        return select_and_apply(request.get('uid'), request.get('id'), request.get('relay'), start=op == 'start')
    if op == 'select_subscription': return choose_subscription(request['uid'])
    if op == 'stop':
        service('stop')
        (DATA / 'pending.json').unlink(missing_ok=True)
        return {**status(), 'message': '独立代理服务已停止。'}
    if op == 'restore': return restore()
    if op == 'migrate': return migrate()
    if op == 'add_subscription': return add_subscription(request.get('name', ''), request['url'])
    if op == 'import_subscription': return import_subscription(request['path'], request.get('name', ''))
    if op == 'update_subscription': return update_subscription(request['uid'])
    if op == 'refresh_subscription_usage': return refresh_subscription_usage(request['uid'])
    if op == 'delete_subscription': return delete_subscription(request['uid'])
    raise ValueError('未知操作。')


def main():
    try:
        request = json.load(sys.stdin)
        DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        # 只读的补充检测不占用连接操作锁，避免后台检测期间阻塞用户的下一步操作。
        if request.get('op') in BACKGROUND_OPS:
            lock_name, cancel_name, busy, cancelled = BACKGROUND_OPS[request['op']]
            with open(DATA / lock_name, 'a') as background:
                try:
                    fcntl.flock(background, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError(busy) from None
                # 持锁后才记录开始时间：此前针对其它检测的取消标记不会误伤本次。
                threading.Thread(target=watch_cancel, args=(DATA / cancel_name, time.time_ns()), daemon=True).start()
                try:
                    result = {'ok': True, **dispatch(request)}
                except (RuntimeError, ValueError) as error:
                    result = {'ok': False, 'error': str(error)}
                if CANCEL_PROBES.is_set():
                    result = {'ok': False, 'error': cancelled}
            print(json.dumps(result, ensure_ascii=False))
            return
        if request.get('op') in ('exit_location', 'prewarm', 'check_update', 'download_update'):
            result = {'ok': True, **dispatch(request)}
            print(json.dumps(result, ensure_ascii=False))
            return
        with (LIBRARY / 'operation.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('另一个操作正在进行，请稍后重试。') from None
            if request.get('op') in NETWORK_OPS:
                cancel_node_delays()
                cancel_deferred_checks()
            result = {'ok': True, **dispatch(request)}
    except (RuntimeError, ValueError) as error:
        result = {'ok': False, 'error': str(error)}
    except Exception:
        result = {'ok': False, 'error': '本机数据或组件不可用，请检查安装并刷新。'}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
