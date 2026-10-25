import copy
import io
import email.message
import json
from pathlib import Path
import tempfile
import subprocess
import os
import unittest
from unittest.mock import MagicMock, Mock, patch

import backend as b


class BackendTests(unittest.TestCase):
    @staticmethod
    def no_network(*args, **kwargs):
        # 默认禁止真实 curl；需要检测行为的测试会自行 mock run_probe。
        raise AssertionError('后端测试不得访问网络。')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.library = self.root / 'library'
        self.data = self.library / 'standalone'
        self.verge = self.root / 'verge'
        self.library.mkdir()
        self.data.mkdir()
        self.verge.mkdir()
        self.paths = patch.multiple(b, LIBRARY=self.library, DATA=self.data, VERGE=self.verge,
                                    resolve_system_dns=lambda name: {'198.18.0.5'},
                                    run_probe=self.no_network)
        self.paths.start()
        self.profile = {'id': 'profile-one', 'name': '美国静态出口', 'server': '198.51.100.20',
                        'port': 443, 'protocol': 'socks5', 'username': 'test-user',
                        'expected': '198.51.100.20', 'expired': ''}
        b.put_json(self.library / 'profiles.json', [self.profile])
        self.item = {'uid': '78d72e69-47bd-4613-92c5-5b0a1d9c2a21', 'name': '测试订阅',
                     'kind': 'remote', 'url': 'https://provider.example/secret-token', 'updated_at': ''}
        self.source = {'proxies': [{'name': '日本一', 'type': 'socks5', 'server': 'relay.example', 'port': 443, 'password': 'airport-private'}]}
        b.put_json(self.data / 'subscriptions.json', [self.item])
        b.put_json(b.cache_path(self.item), self.source)
        self.preferences = {'controller_secret': 'controller-private', 'current_subscription_uid': self.item['uid'],
                            'selected_profile_id': self.profile['id'], 'relays': {self.item['uid']: '日本一'}}
        b.put_json(self.data / 'settings.json', self.preferences)
        self.keychain = patch.object(b, 'keychain', return_value={'ok': True, 'password': 'static-private'})
        self.keychain_mock = self.keychain.start()

    def tearDown(self):
        b.CANCEL_PROBES.clear()
        self.keychain.stop()
        self.paths.stop()
        self.temp.cleanup()

    def make_config(self):
        return b.generate_config(self.source, self.profile, '日本一', self.preferences)

    def test_offline_status_keeps_lists_and_hides_secrets(self):
        with patch.object(b, 'service_status', return_value={'running': False, 'tun': False, 'service_status': 'notRegistered'}):
            result = b.status()
        self.assertEqual(result['selected_id'], self.profile['id'])
        self.assertEqual(result['nodes'], ['日本一'])
        self.assertFalse(result['running'])
        self.assertEqual(len(result['subscriptions']), 1)
        for private in ('controller-private', 'secret-token', 'airport-private', 'static-private'):
            self.assertNotIn(private, json.dumps(result))

    def test_generated_configuration_owns_routing_and_dns(self):
        source = {**self.source, 'rules': ['MATCH,DIRECT'], 'dns': {'nameserver': ['evil.example']},
                  'external-controller': '0.0.0.0:9090', 'script': 'unsafe'}
        result = b.generate_config(source, self.profile, '日本一', self.preferences)
        self.assertNotIn('external-controller', result)
        self.assertNotIn('script', result)
        self.assertEqual(result['mixed-port'], 17896)
        self.assertEqual(result['tun']['device'], 'utun78')
        self.assertTrue(result['tun']['enable'])
        self.assertTrue(result['unified-delay'])
        self.assertEqual(result['tun']['dns-mode'], 'native')
        self.assertEqual(result['tun']['dns-hijack'], ['any:53', 'tcp://any:53'])
        self.assertLess(result['rules'].index('GEOIP,CN,DIRECT'), result['rules'].index('MATCH,静态IP出口'))
        self.assertEqual(result['proxies'][-1]['dialer-proxy'], b.RELAY_NAME)
        self.assertEqual(result['proxy-groups'][0]['proxies'], ['日本一'])
        self.assertNotIn('evil.example', json.dumps(result))

    def test_api_uses_only_privileged_read_bridge(self):
        with patch.object(b, 'service', return_value={'ok': True, 'data': {'running': True}}) as service:
            self.assertEqual(b.api('/configs'), {'running': True})
            service.assert_called_once_with('api', path='/configs')
            with self.assertRaises(ValueError): b.api('/configs', 'PUT', {'path': '/root/private'})
            with self.assertRaises(ValueError): b.api('/logs')

    def test_delay_batch_uses_service_bridge_and_preserves_existing_exit_and_selection(self):
        b.put_json(self.data / 'active.json', self.make_config())
        preferences = {**self.preferences, 'last_verified_ip': '198.51.100.20', 'verified_at': b.now()}
        b.put_json(self.data / 'settings.json', preferences)
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', return_value={'ok': True, 'results': [{'name': '日本一', 'status': 'ok', 'delay_ms': 123, 'secret': 'do-not-copy'}]}) as service, patch.object(b, 'status', side_effect=AssertionError('不可用全量状态覆盖 UI')):
            result = b.dispatch({'op': 'node_delays', 'subscription_uid': self.item['uid'], 'names': ['日本一']})
        service.assert_called_once_with('node_delays', names=['日本一'])
        self.assertEqual(set(result), {'subscription_uid', 'node_delays'})
        self.assertEqual(result['node_delays']['日本一']['delay_ms'], 123)
        self.assertNotIn('stale', result['node_delays']['日本一'])
        self.assertEqual(b.settings(), preferences)
        self.assertEqual(b.read_json(self.data / 'active.json', {}), self.make_config())
        raw = (self.data / 'node-delays.json').read_text()
        for secret in ('do-not-copy', 'airport-private', 'static-private', 'controller-private', '198.51.100.20'):
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, json.dumps(result))

    def test_delay_service_request_has_bounded_timeout(self):
        with patch.object(b, 'executable', return_value='/test/app'), patch.object(b, 'run', return_value='{"ok":true,"results":[]}') as run:
            b.service('node_delays', names=['日本一'])
        self.assertEqual(json.loads(run.call_args.args[1]), {'op': 'node_delays', 'names': ['日本一']})
        self.assertEqual(run.call_args.kwargs['timeout'], 11)
        with patch.object(b, 'executable', return_value='/test/app'), patch.object(b, 'run', return_value='{"ok":true,"results":[]}') as run:
            b.service('node_delays', names=['节点' + str(index) for index in range(68)])
        # 68 个节点按 16 并发分 5 轮，每轮至多 5.5 秒。
        self.assertEqual(run.call_args.kwargs['timeout'], 35)

    def test_delay_batches_reject_invalid_names_before_contacting_service(self):
        too_many = ['node' + str(index) for index in range(b.NODE_DELAY_MAX_NAMES + 1)]
        for names in ([], too_many, ['node', 'node'], 'node', [None], [[]]):
            with self.subTest(names=len(names) if names is too_many else names), patch.object(b, 'service') as service:
                with self.assertRaisesRegex(ValueError, '1–256'):
                    b.node_delays(self.item['uid'], names)
            service.assert_not_called()

    def test_delay_batch_uses_offline_probe_only_for_known_stopped_state(self):
        response = {'results': [{'name': '日本一', 'status': 'ok', 'delay_ms': 33}]}
        for state in ({'running': False}, {'running': False, 'state_known': True, 'service_status': 'notRegistered'},
                      {'running': False, 'state_known': True, 'service_error': '先前连接失败'}):
            with self.subTest(state=state), patch.object(b, 'service_status', return_value=state), patch.object(b, 'service') as service, patch.object(b, 'offline_node_delays', return_value=response) as offline:
                result = b.node_delays(self.item['uid'], ['日本一'])
            offline.assert_called_once_with(self.source['proxies'])
            service.assert_not_called()
            self.assertEqual(result['node_delays']['日本一']['delay_ms'], 33)
        for running in (False, True):
            with self.subTest(running=running), patch.object(b, 'service_status', return_value={'running': running, 'state_known': False}), patch.object(b, 'service') as service, patch.object(b, 'offline_node_delays') as offline:
                with self.assertRaisesRegex(RuntimeError, '无法确认'):
                    b.node_delays(self.item['uid'], ['日本一'])
            service.assert_not_called()
            offline.assert_not_called()

    def test_delay_test_superseded_by_network_operation_discards_results(self):
        b.put_json(self.data / 'active.json', self.make_config())
        def superseded(*args, **kwargs):
            b.CANCEL_PROBES.set()
            return {'ok': True, 'results': [{'name': '日本一', 'status': 'error'}]}
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', side_effect=superseded):
            with self.assertRaisesRegex(RuntimeError, '已被新的网络操作中止'):
                b.node_delays(self.item['uid'], ['日本一'])
        self.assertFalse((self.data / 'node-delays.json').exists())

    def test_delay_test_runs_without_operation_lock_and_is_exclusive(self):
        printed = []
        with open(self.library / 'operation.lock', 'a') as busy:
            b.fcntl.flock(busy, b.fcntl.LOCK_EX | b.fcntl.LOCK_NB)
            # 连接等操作持有操作锁时，后台测速仍可运行，不会提示另一个操作正在进行。
            with patch.object(b, 'dispatch', return_value={'node_delays': {}}), patch.object(b.sys, 'stdin', io.StringIO(json.dumps({'op': 'node_delays'}))), patch('builtins.print', side_effect=printed.append):
                b.main()
        self.assertEqual(json.loads(printed[-1]), {'ok': True, 'node_delays': {}})
        with open(self.data / b.NODE_DELAY_LOCK_FILE, 'a') as running:
            b.fcntl.flock(running, b.fcntl.LOCK_EX | b.fcntl.LOCK_NB)
            with patch.object(b, 'dispatch') as dispatch, patch.object(b.sys, 'stdin', io.StringIO(json.dumps({'op': 'node_delays'}))), patch('builtins.print', side_effect=printed.append):
                b.main()
            dispatch.assert_not_called()
        self.assertEqual(json.loads(printed[-1]), {'ok': False, 'error': '节点测速正在进行，请稍后。'})

    def test_network_operation_signals_node_delay_test_without_waiting(self):
        with open(self.data / b.NODE_DELAY_LOCK_FILE, 'a') as running:
            b.fcntl.flock(running, b.fcntl.LOCK_EX | b.fcntl.LOCK_NB)
            started = b.time.monotonic()
            self.assertTrue(b.cancel_node_delays())
            self.assertLess(b.time.monotonic() - started, 0.2)
        self.assertTrue((self.data / b.NODE_DELAY_CANCEL_FILE).exists())
        self.assertFalse(b.cancel_node_delays())

    def test_offline_delay_uses_one_core_for_whole_subscription_with_bounded_concurrency(self):
        nodes = [{**self.source['proxies'][0], 'name': '节点' + str(index)} for index in range(68)]
        config = b.offline_delay_config(nodes, 'en0', '/tmp/c.sock', 'secret')
        self.assertEqual(len(config['proxies']), 68)
        self.assertIn('timeout=5000', '/proxies/x/delay?url=http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204&timeout=' + str(b.NODE_DELAY_MAX_MS))
        # 68 个节点、16 并发分 5 轮：总预算含 3 秒启动与回收余量，不超过 40 秒。
        self.assertLessEqual(b.offline_delay_total_seconds(68), 40)
        self.assertGreaterEqual(b.offline_delay_total_seconds(68), 5 * 5.5)
        with self.assertRaises(ValueError):
            b.offline_delay_config(nodes * 4, 'en0', '/tmp/c.sock', 'secret')

    def test_delay_batch_rejects_other_subscription_and_non_nodes(self):
        b.put_json(self.data / 'active.json', self.make_config())
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service') as service:
            with self.assertRaisesRegex(ValueError, '当前所选订阅'):
                b.node_delays('other-subscription', ['日本一'])
            for name in (b.EXIT_NAME, b.RELAY_NAME, 'DIRECT', 'removed'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, '机场节点'):
                    b.node_delays(self.item['uid'], [name])
        service.assert_not_called()

    def test_delay_batch_checks_all_node_credentials_against_active_configuration(self):
        for field, value in (('password', 'different-secret'), ('server', 'different.example'), ('port', 444), ('type', 'http')):
            active = self.make_config()
            active['proxies'][0][field] = value
            b.put_json(self.data / 'active.json', active)
            with self.subTest(field=field), patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service') as service:
                with self.assertRaisesRegex(RuntimeError, '配置不一致'):
                    b.node_delays(self.item['uid'], ['日本一'])
            service.assert_not_called()
        self.assertFalse((self.data / 'node-delays.json').exists())

    def test_delay_response_rejects_invalid_status_names_and_delays_atomically(self):
        b.put_json(self.data / 'active.json', self.make_config())
        invalid_results = [[], [{'name': 'other', 'status': 'ok', 'delay_ms': 10}],
                           [{'name': '日本一', 'status': 'unknown'}],
                           [{'name': '日本一', 'status': 'ok'}],
                           [{'name': '日本一', 'status': 'timeout', 'delay_ms': 10}],
                           [{'name': '日本一', 'status': 'error', 'delay_ms': 0}],
                           [None]]
        invalid_results += [[{'name': '日本一', 'status': 'ok', 'delay_ms': delay}]
                            for delay in (True, 1.5, '20', -1, 0, 10001)]
        for results in invalid_results:
            with self.subTest(results=results), patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', return_value={'ok': True, 'results': results}):
                with self.assertRaisesRegex(RuntimeError, '结果格式'):
                    b.node_delays(self.item['uid'], ['日本一'])
            self.assertFalse((self.data / 'node-delays.json').exists())

    def test_delay_results_merge_batches_and_keep_individual_failures(self):
        source = {'proxies': [{**self.source['proxies'][0], 'name': name} for name in ('日本一', '美国二', '英国三', '德国四')]}
        b.put_json(b.cache_path(self.item), source)
        b.put_json(self.data / 'active.json', b.generate_config(source, self.profile, '日本一', self.preferences))
        results = [{'name': '日本一', 'status': 'ok', 'delay_ms': 25},
                   {'name': '美国二', 'status': 'timeout'}, {'name': '英国三', 'status': 'error'}]
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', side_effect=[{'ok': True, 'results': results}, {'ok': True, 'results': [{'name': '德国四', 'status': 'ok', 'delay_ms': 4000}]}]):
            b.node_delays(self.item['uid'], ['日本一', '美国二', '英国三'])
            second = b.node_delays(self.item['uid'], ['德国四'])
        self.assertEqual(set(second['node_delays']), {'德国四'})
        with patch.object(b, 'service_status', return_value={'running': False}):
            status = b.status()
        self.assertEqual(set(status['node_delays']), {'日本一', '美国二', '英国三', '德国四'})
        self.assertEqual(status['node_delays']['美国二']['status'], 'timeout')
        self.assertNotIn('delay_ms', status['node_delays']['英国三'])

    def test_delay_cache_isolated_by_subscription_and_complete_node_configuration(self):
        b.put_json(self.data / 'active.json', self.make_config())
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', return_value={'ok': True, 'results': [{'name': '日本一', 'status': 'ok', 'delay_ms': 30}]}):
            b.node_delays(self.item['uid'], ['日本一'])
        self.assertEqual(b.cached_node_delays('other-subscription', self.source), {})
        changed = copy.deepcopy(self.source)
        changed['proxies'][0]['password'] = 'changed-private'
        self.assertEqual(b.cached_node_delays(self.item['uid'], changed), {})
        changed = copy.deepcopy(self.source)
        changed['proxies'][0]['ws-opts'] = {'headers': {'Host': 'different.example'}}
        self.assertEqual(b.cached_node_delays(self.item['uid'], changed), {})
        reordered = {'proxies': [dict(reversed(list(self.source['proxies'][0].items())))]}
        self.assertEqual(b.cached_node_delays(self.item['uid'], reordered)['日本一']['delay_ms'], 30)

    def test_old_delay_results_stay_visible_without_expiry_marker(self):
        old = (b.datetime.datetime.now(b.datetime.timezone.utc) - b.datetime.timedelta(seconds=601)).isoformat()
        b.put_json(self.data / 'node-delays.json', {self.item['uid']: {'日本一': {
            'digest': b.node_digest(self.source['proxies'][0]), 'status': 'ok', 'delay_ms': 31, 'tested_at': old,
            'measurement_version': b.NODE_DELAY_MEASUREMENT_VERSION, 'method': b.NODE_DELAY_METHOD}}})
        with patch.object(b, 'service_status', return_value={'running': False}):
            status = b.status()
        # 后台每 10 分钟刷新；旧结果照常展示，不再标记过期。
        self.assertNotIn('stale', status['node_delays']['日本一'])
        self.assertEqual(status['node_delays']['日本一']['delay_ms'], 31)
        b.write(self.data / 'node-delays.json', 'broken json')
        self.assertEqual(b.cached_node_delays(self.item['uid'], self.source), {})

    def test_delay_batch_does_not_cache_result_after_configuration_changes(self):
        b.put_json(self.data / 'active.json', self.make_config())
        def changed_during_request(*args, **kwargs):
            changed = copy.deepcopy(self.source)
            changed['proxies'][0]['password'] = 'changed-private'
            b.put_json(b.cache_path(self.item), changed)
            return {'ok': True, 'results': [{'name': '日本一', 'status': 'ok', 'delay_ms': 20}]}
        with patch.object(b, 'known_service_status', return_value={'running': True}), patch.object(b, 'service', side_effect=changed_during_request):
            with self.assertRaisesRegex(RuntimeError, '配置不一致'):
                b.node_delays(self.item['uid'], ['日本一'])
        self.assertFalse((self.data / 'node-delays.json').exists())

    def test_offline_probe_config_is_isolated_and_rejects_unsafe_nodes(self):
        config = b.offline_delay_config(self.source['proxies'], 'en0', '/tmp/private/c.sock', 'private-token')
        self.assertEqual(config['tun'], {'enable': False})
        self.assertTrue(config['unified-delay'])
        self.assertEqual(config['interface-name'], 'en0')
        for key in ('mixed-port', 'port', 'socks-port', 'redir-port', 'tproxy-port'):
            self.assertEqual(config[key], 0)
        self.assertNotIn('external-controller', config)
        self.assertEqual(config['dns']['listen'], '127.0.0.1:0')
        for key in ('default-nameserver', 'nameserver', 'proxy-server-nameserver', 'direct-nameserver'):
            self.assertEqual(config['dns'][key], ['https://223.5.5.5/dns-query#DIRECT'])
        self.assertEqual(config['proxies'], self.source['proxies'])
        self.assertEqual(config['proxy-groups'], [])
        self.keychain_mock.assert_not_called()
        for extra in ({'plugin': '/bin/sh'}, {'certificate': '/tmp/secret'}, {'dialer-proxy': 'other'}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                b.offline_delay_config([{**self.source['proxies'][0], **extra}], 'en0', '/tmp/private/c.sock', 'secret')
        with self.assertRaises(ValueError):
            b.offline_delay_config(self.source['proxies'], 'utun4', '/tmp/private/c.sock', 'secret')

    def test_offline_probe_only_accepts_a_physical_default_interface(self):
        with patch.object(b, 'run', return_value='route to: default\n  interface: en12\n') as run:
            self.assertEqual(b.physical_default_interface(), 'en12')
        run.assert_called_once_with(['/sbin/route', '-n', 'get', 'default'], timeout=1)
        for output in ('interface: utun4\n', 'interface: lo0\n', 'interface: bridge0\n',
                       'interface: en0;whoami\n', 'interface: en0\ninterface: en1\n', ''):
            with self.subTest(output=output), patch.object(b, 'run', return_value=output):
                with self.assertRaisesRegex(RuntimeError, '物理网络接口'):
                    b.physical_default_interface()

    def test_offline_probe_curl_uses_private_socket_and_stdin_secret(self):
        result = subprocess.CompletedProcess([], 0, stdout='{"delay":23}\n200', stderr='sensitive-error')
        with patch.dict(os.environ, {'CLASH_TUN': 'true', 'MIHOMO_PORT': '8999', 'HTTPS_PROXY': 'http://private'}), patch.object(b.subprocess, 'run', return_value=result) as run:
            self.assertEqual(b.offline_probe_api('/tmp/private/c.sock', 'private-token', '/version', 0.5), (0, 200, {'delay': 23}))
        args = run.call_args.args[0]
        self.assertNotIn('private-token', ' '.join(args))
        self.assertEqual(run.call_args.kwargs['input'], 'Authorization: Bearer private-token\n')
        self.assertEqual(args[args.index('--unix-socket') + 1], '/tmp/private/c.sock')
        self.assertEqual(args[args.index('--proxy') + 1], '')
        self.assertEqual(args[args.index('--noproxy') + 1], '*')
        self.assertEqual(set(run.call_args.kwargs['env']), {'PATH', 'HOME', 'LANG'})
        self.assertEqual(run.call_args.kwargs['timeout'], 0.5)

    def test_offline_probe_success_cleans_process_and_private_files(self):
        core = self.root / 'mihomo'
        core.touch()
        process = Mock(pid=93215)
        process.poll.return_value = None
        process.wait.return_value = 0
        captured = {}
        def start(args, **kwargs):
            config_path = Path(args[args.index('-f') + 1])
            config = b.read_json(config_path, {})
            captured.update(root=config_path.parent, config=config, args=args, kwargs=kwargs)
            self.assertEqual(config_path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
            self.assertLess(len(config['external-controller-unix'].encode()), 104)
            Path(config['external-controller-unix']).touch()
            return process
        def api(socket_path, secret, path, timeout):
            self.assertEqual(Path(socket_path).stat().st_mode & 0o777, 0o600)
            self.assertEqual(secret, captured['config']['secret'])
            return (0, 200, {'version': 'test'}) if path == '/version' else (0, 200, {'delay': 41})
        before = {str(path): path.read_bytes() for path in self.data.rglob('*') if path.is_file()}
        with patch.object(b, 'resources', return_value=self.root), patch.object(b, 'physical_default_interface', return_value='en0'), patch.object(b.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), patch.object(b.subprocess, 'Popen', side_effect=start), patch.object(b, 'offline_probe_api', side_effect=api), patch.object(b.os, 'killpg') as killpg:
            result = b.offline_node_delays(self.source['proxies'])
        self.assertEqual(result['results'], [{'name': '日本一', 'status': 'ok', 'delay_ms': 41}])
        self.assertFalse(captured['root'].exists())
        self.assertTrue(captured['kwargs']['start_new_session'])
        self.assertEqual(set(captured['kwargs']['env']), {'PATH', 'HOME', 'LANG'})
        self.assertEqual(captured['kwargs']['env']['HOME'], str(captured['root']))
        self.assertNotIn(captured['config']['secret'], ' '.join(captured['args']))
        killpg.assert_called_once_with(process.pid, b.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=0.4)
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.data.rglob('*') if path.is_file()})

    def test_offline_probe_cleanup_escalates_only_its_own_process_group(self):
        process = Mock(pid=93216)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('probe', 0.4), 0]
        with patch.object(b.os, 'killpg') as killpg:
            b.stop_offline_probe(process)
        self.assertEqual([call.args for call in killpg.call_args_list], [(93216, b.signal.SIGTERM), (93216, b.signal.SIGKILL)])
        self.assertEqual([call.kwargs for call in process.wait.call_args_list], [{'timeout': 0.4}, {'timeout': 0.5}])

    def test_offline_probe_startup_timeout_still_cleans_up(self):
        (self.root / 'mihomo').touch()
        process = Mock(pid=93217)
        process.poll.return_value = None
        process.wait.return_value = 0
        clock, directories = [100.0], []
        def start(args, **kwargs):
            directories.append(Path(args[args.index('-d') + 1]))
            return process
        with patch.object(b, 'resources', return_value=self.root), patch.object(b, 'physical_default_interface', return_value='en0'), patch.object(b.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), patch.object(b.subprocess, 'Popen', side_effect=start), patch.object(b.os, 'killpg') as killpg, patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(b.time, 'sleep', side_effect=lambda duration: clock.__setitem__(0, clock[0] + duration)):
            with self.assertRaisesRegex(RuntimeError, '3 秒内就绪'):
                b.offline_node_delays(self.source['proxies'])
        self.assertAlmostEqual(clock[0] - 100, 3)
        killpg.assert_called_once_with(process.pid, b.signal.SIGTERM)
        self.assertFalse(directories[0].exists())

    def test_offline_probe_uses_remaining_deadline_and_encodes_entire_name(self):
        with patch.object(b.time, 'monotonic', return_value=100.0), patch.object(b, 'offline_probe_api', return_value=(28, 0, {})) as api:
            result = b.offline_probe_node('../name?x=1', '/tmp/private/c.sock', 'secret', 101.0)
        self.assertEqual(result['status'], 'timeout')
        self.assertEqual(api.call_args.args[3], 1)
        self.assertIn('/proxies/%2E%2E%2Fname%3Fx%3D1/delay?', api.call_args.args[2])
        self.assertTrue(api.call_args.args[2].endswith('timeout=5000'))
        self.assertIn('url=http%3A%2F%2Fcp.cloudflare.com%2Fgenerate_204', api.call_args.args[2])

    def test_old_latency_method_is_not_displayed_as_current_measurement(self):
        entry = {'digest': b.node_digest(self.source['proxies'][0]), 'status': 'ok', 'delay_ms': 31, 'tested_at': b.now()}
        for extra in ({}, {'measurement_version': 1}, {'measurement_version': 2, 'method': 'old-url'}):
            b.put_json(self.data / 'node-delays.json', {self.item['uid']: {'日本一': {**entry, **extra}}})
            self.assertEqual(b.cached_node_delays(self.item['uid'], self.source), {})

    def test_offline_probe_validates_core_before_spawning_and_hides_raw_error(self):
        (self.root / 'mihomo').touch()
        with patch.object(b, 'resources', return_value=self.root), patch.object(b, 'physical_default_interface', return_value='en0'), patch.object(b.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stderr='private-password')), patch.object(b.subprocess, 'Popen') as start:
            with self.assertRaisesRegex(RuntimeError, '内核校验') as error:
                b.offline_node_delays(self.source['proxies'])
        start.assert_not_called()
        self.assertNotIn('private-password', str(error.exception))

    def test_subscription_rejects_external_program_and_paths(self):
        for fields in ({'plugin': '/tmp/anything'}, {'certificate': '/etc/private'}, {'dialer-proxy': 'outside'}, {'ws-opts': {'certificate': '/tmp/private'}}):
            source = copy.deepcopy(self.source)
            source['proxies'][0].update(fields)
            with self.assertRaises(ValueError): b.normalize_subscription(source)
        with self.assertRaises(ValueError): b.normalize_subscription({'proxy-providers': {'only': {}}})

    def test_subscription_name_prefers_plain_or_base64_provider_title(self):
        for title in ('示例机场.yaml', 'base64:' + b.base64.b64encode('示例机场.yaml'.encode()).decode()):
            result = b.subscription_response_name({'profile-title': title, 'content-disposition': 'attachment; filename="other.yml"'}, self.item['url'])
            self.assertEqual(result, {'name': '示例机场', 'name_source': 'profile-title'})
        self.assertEqual(b.profile_title_name('AirportB'), 'AirportB')
        self.assertEqual(b.profile_title_name('base64:' + b.base64.b64encode('机场'.encode()).decode().rstrip('=')), '机场')

    def test_subscription_name_decodes_filename_star_before_plain_filename(self):
        header = 'attachment; filename="fallback.yaml"; filename*=UTF-8\'\'%E7%A4%BA%E4%BE%8B%E6%9C%BA%E5%9C%BA.yml'
        result = b.subscription_response_name({'content-disposition': header}, self.item['url'])
        self.assertEqual(result, {'name': '示例机场', 'name_source': 'content-disposition'})
        self.assertEqual(b.disposition_filename_name('attachment; filename="Airport ; Premium.YAML"'), 'Airport ; Premium')
        self.assertEqual(b.disposition_filename_name('attachment; filename="../folder/机场.yml"'), '机场')

    def test_subscription_name_invalid_encoding_falls_back_without_exposing_url_secrets(self):
        url = 'https://username:password@provider.example/path/private-token.yaml?token=secret#private-name'
        invalid_titles = ('base64:@@@@', 'base64:/w==', 'base64:', '\u202e\x00')
        for title in invalid_titles:
            result = b.subscription_response_name({'profile-title': title}, url)
            self.assertEqual(result, {'name': 'provider.example', 'name_source': 'url-host'})
        result = b.subscription_response_name({'profile-title': 'base64:@@@@', 'content-disposition': 'attachment; filename="Airport.yaml"'}, url)
        self.assertEqual(result['name'], 'Airport')
        for value in ("UTF-8''%ZZ.yaml", "UTF-8''%FF.yaml", "unknown''test.yaml"):
            self.assertEqual(b.disposition_filename_name('attachment; filename="fallback.yml"; filename*=' + value), 'fallback')

    def test_subscription_name_cleans_controls_bidi_and_limits_length(self):
        self.assertEqual(b.profile_title_name('\u202e机场\x00\u2066服务\u2069\x1f.yaml'), '机场服务')
        self.assertEqual(len(b.profile_title_name('名' * 1000)), b.SUBSCRIPTION_NAME_MAX_LENGTH)
        self.assertEqual(b.profile_title_name('名' * 4097), '')

    def test_fetch_exposes_only_limited_name_metadata_from_headers(self):
        headers = email.message.Message()
        headers['Profile-Title'] = 'base64:' + b.base64.b64encode('机场名称'.encode()).decode()
        headers['Private-Token'] = 'secret-credential'
        response = MagicMock(url='https://redirect.example/token', headers=headers)
        response.__enter__.return_value = response
        opener = Mock()
        opener.open.return_value = response
        metadata = {}
        with patch.object(b.urllib.request, 'build_opener', return_value=opener):
            b.fetch_subscription(self.item['url'], metadata_out=metadata, headers_only=True)
        self.assertEqual(metadata, {'name': '机场名称', 'name_source': 'profile-title'})
        response.read.assert_not_called()

    def test_add_subscription_auto_names_without_overriding_explicit_name(self):
        def fetch(url, usage_out=None, headers_only=False, metadata_out=None):
            metadata_out.update({'name': '服务商名称', 'name_source': 'profile-title'})
            return 'unused'
        with patch.object(b, 'fetch_subscription', side_effect=fetch), patch.object(b, 'parse_subscription_text', return_value=self.source), patch.object(b, 'save_subscription') as save, patch.object(b, 'status', return_value={}):
            b.dispatch({'op': 'add_subscription', 'url': self.item['url']})
            self.assertEqual(save.call_args.args[0]['name'], '服务商名称')
            b.add_subscription('我的名称.yaml', self.item['url'])
            self.assertEqual(save.call_args.args[0]['name'], '我的名称.yaml')

    def test_update_subscription_preserves_existing_name(self):
        def fetch(url, usage_out=None, headers_only=False, metadata_out=None):
            if metadata_out is not None:
                metadata_out.update({'name': '服务商新名称', 'name_source': 'profile-title'})
            return 'unused'
        with patch.object(b, 'fetch_subscription', side_effect=fetch), patch.object(b, 'parse_subscription_text', return_value=self.source), patch.object(b, 'validate_subscription'), patch.object(b, 'service_status', return_value={'running': False}):
            b.update_subscription(self.item['uid'])
        self.assertEqual(b.subscription(self.item['uid'])['name'], self.item['name'])

    def test_usage_header_parses_bytes_and_expiry_without_guessing_missing_values(self):
        result = b.parse_subscription_userinfo('upload=10; download=20; total=100; expire=1795391202')
        self.assertEqual(result['status'], 'fresh')
        self.assertEqual(result['used_bytes'], 30)
        self.assertEqual(result['remaining_bytes'], 70)
        self.assertEqual(result['expires_at'], 1795391202)
        self.assertEqual(result['source'], 'subscription-userinfo')
        partial = b.parse_subscription_userinfo('download=20; total=100; expire=0')
        self.assertIsNone(partial['upload_bytes'])
        self.assertIsNone(partial['used_bytes'])
        self.assertIsNone(partial['remaining_bytes'])
        self.assertIsNone(partial['expires_at'])
        self.assertEqual(partial['status'], 'fresh')
        zero = b.parse_subscription_userinfo('upload=0; download=0; total=0')
        self.assertEqual(zero['used_bytes'], 0)
        self.assertEqual(zero['total_bytes'], 0)

    def test_usage_header_rejects_malformed_negative_overflow_duplicate_and_bad_expiry(self):
        for value in ('-1', '1.5', 'nan', 'True', str(1 << 63), '9' * 100):
            with self.subTest(value=value):
                self.assertIsNone(b.parse_subscription_userinfo('upload=' + value)['upload_bytes'])
        for value in ('0', '123', '9999999999', '1795391202000'):
            with self.subTest(expiry=value):
                self.assertIsNone(b.parse_subscription_userinfo('expire=' + value)['expires_at'])
        self.assertIsNone(b.parse_subscription_userinfo('upload=1;upload=2;download=4')['upload_bytes'])
        self.assertEqual(b.parse_subscription_userinfo('x=' + '0' * 9000)['status'], 'unknown')
        overflow = b.parse_subscription_userinfo(f'upload={b.USAGE_MAX_BYTES}; download=1; total=20')
        self.assertIsNone(overflow['used_bytes'])
        unsafe = b.public_subscription_usage({'upload_bytes': True, 'download_bytes': 1.2, 'total_bytes': 1 << 64, 'expires_at': 'private-url', 'reason': ['secret']})
        self.assertTrue(all(unsafe[field] is None for field in b.USAGE_FIELDS.values()))

    def test_usage_missing_or_invalid_header_retains_old_snapshot_as_stale(self):
        old = b.parse_subscription_userinfo('upload=1;download=2;total=10;expire=1795391202', '2026-10-20T00:00:00+00:00')
        for header in (None, '', 'total=invalid', 'secret-token'):
            incoming = b.parse_subscription_userinfo(header, '2026-10-23T00:00:00+00:00')
            result = b.merge_subscription_usage(old, incoming)
            self.assertEqual(result['status'], 'stale')
            self.assertEqual(result['used_bytes'], 3)
            self.assertEqual(result['fetched_at'], old['fetched_at'])
            self.assertEqual(result['checked_at'], '2026-10-23T00:00:00+00:00')
        replaced = b.merge_subscription_usage(old, b.parse_subscription_userinfo('total=50'))
        self.assertEqual(replaced['total_bytes'], 50)
        self.assertIsNone(replaced['used_bytes'])
        self.assertIsNone(replaced['expires_at'])

    def test_usage_fetch_headers_only_never_reads_or_updates_subscription_body(self):
        headers = email.message.Message()
        headers['subscription-userinfo'] = 'upload=10;download=15;total=100;expire=1795391202'
        response = MagicMock(url='https://provider.example/private-token', headers=headers)
        response.__enter__.return_value = response
        opener = Mock()
        opener.open.return_value = response
        usage = {}
        with patch.object(b.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(b.fetch_subscription(self.item['url'], usage_out=usage, headers_only=True), '')
        response.read.assert_not_called()
        self.assertEqual(usage['used_bytes'], 25)
        self.assertNotIn('private-token', json.dumps(usage))

    def test_usage_refresh_preserves_selection_nodes_and_config_timestamp(self):
        before_settings = (self.data / 'settings.json').read_bytes()
        before_cache = b.cache_path(self.item).read_bytes()
        def fetch(url, usage_out=None, headers_only=False):
            self.assertTrue(headers_only)
            usage_out.update(b.parse_subscription_userinfo('upload=5;download=8;total=50;expire=1795391202'))
            return ''
        with patch.object(b, 'fetch_subscription', side_effect=fetch), patch.object(b, 'service', side_effect=AssertionError('不应操作服务')):
            result = b.dispatch({'op': 'refresh_subscription_usage', 'uid': self.item['uid']})
        self.assertEqual(result['subscription_usage']['used_bytes'], 13)
        self.assertEqual((self.data / 'settings.json').read_bytes(), before_settings)
        self.assertEqual(b.cache_path(self.item).read_bytes(), before_cache)
        self.assertEqual(b.subscription(self.item['uid'])['updated_at'], self.item['updated_at'])
        for field in ('ip', 'relay', 'running', 'nodes'):
            self.assertNotIn(field, result)
        self.assertNotIn('secret-token', json.dumps(result))

    def test_usage_refresh_failure_and_missing_header_return_safe_stale_results(self):
        old = b.parse_subscription_userinfo('upload=3;download=4;total=20', '2026-10-20T00:00:00+00:00')
        b.put_json(self.data / 'subscriptions.json', [{**self.item, 'usage': old}])
        with patch.object(b, 'fetch_subscription', side_effect=RuntimeError('https://private-token')):
            result = b.refresh_subscription_usage(self.item['uid'])
        self.assertEqual(result['subscription_usage']['status'], 'stale')
        self.assertEqual(result['subscription_usage']['used_bytes'], 7)
        self.assertEqual(result['subscription_usage']['fetched_at'], old['fetched_at'])
        self.assertNotIn('private-token', json.dumps(result))
        def missing(url, usage_out=None, headers_only=False):
            usage_out.update(b.parse_subscription_userinfo(None))
            return ''
        with patch.object(b, 'fetch_subscription', side_effect=missing):
            result = b.refresh_subscription_usage(self.item['uid'])
        self.assertEqual(result['subscription_usage']['status'], 'stale')
        self.assertEqual(result['subscription_usage']['reason'], '订阅服务未返回用量信息。')

    def test_usage_update_missing_header_marks_old_values_stale(self):
        old = b.parse_subscription_userinfo('upload=3;download=4;total=20', '2026-10-20T00:00:00+00:00')
        b.put_json(self.data / 'subscriptions.json', [{**self.item, 'usage': old}])
        def fetch(url, usage_out=None, headers_only=False):
            usage_out.update(b.parse_subscription_userinfo(None))
            return 'unused'
        with patch.object(b, 'fetch_subscription', side_effect=fetch), patch.object(b, 'parse_subscription_text', return_value=self.source), patch.object(b, 'validate_subscription'), patch.object(b, 'service_status', return_value={'running': False}):
            result = b.update_subscription(self.item['uid'])
        usage = result['subscriptions'][0]['usage']
        self.assertEqual(usage['status'], 'stale')
        self.assertEqual(usage['fetched_at'], old['fetched_at'])

    def test_clash_usage_is_marked_cached_and_expiry_zero_is_unknown(self):
        source = {'extra': {'upload': 2, 'download': 4, 'total': 10, 'expire': 0}, 'updated': 1792719231}
        usage = b.clash_subscription_usage(source)
        self.assertEqual(usage['status'], 'stale')
        self.assertEqual(usage['source'], 'clash-extra')
        self.assertEqual(usage['used_bytes'], 6)
        self.assertIsNone(usage['expires_at'])
        self.assertIsNone(usage['checked_at'])
        self.assertIsNotNone(usage['fetched_at'])

    def test_status_usage_always_has_valid_nullable_schema(self):
        with patch.object(b, 'service_status', return_value={'running': False}):
            result = b.status()
        self.assertEqual(result['subscription_usage']['status'], 'unknown')
        self.assertEqual(result['subscriptions'][0]['usage']['status'], 'unknown')
        self.assertIsNone(result['subscription_usage']['used_bytes'])

    def test_proxy_validation_and_missing_relay(self):
        for port in (0, 65536, 'bad'):
            with self.assertRaises(ValueError): b.validated({**self.profile, 'port': port})
        with self.assertRaises(ValueError): b.generate_config(self.source, self.profile, '不存在', self.preferences)

    def test_csv_import_updates_existing_identity_without_storing_password(self):
        source = self.root / 'input.csv'
        source.write_text('ip:port,username,password\n198.51.100.20:443,test-user,new-private\n', encoding='utf-8')
        result = b.import_csv(source)
        self.assertEqual(len(result['profiles']), 1)
        self.assertEqual(result['profiles'][0]['id'], 'profile-one')
        self.assertNotIn('new-private', (self.library / 'profiles.json').read_text())
        self.keychain_mock.assert_called_once_with('set', 'profile-one', 'new-private')

    def test_offline_switch_saves_selection_without_starting(self):
        with patch.object(b, 'service_status', return_value={'running': False}), patch.object(b, 'service') as service, patch.object(b, 'validate_core'):
            result = b.dispatch({'op': 'switch', 'id': 'profile-one', 'relay': '日本一'})
        service.assert_not_called()
        self.assertFalse(result['running'])
        self.assertFalse((self.data / 'active.json').exists())

    def test_explicit_missing_relay_never_silently_falls_back(self):
        with patch.object(b, 'service') as service:
            with self.assertRaises(ValueError): b.select_and_apply(relay='removed-node', start=True)
        service.assert_not_called()

    def assert_fresh_connection_reply(self, result, item, relay):
        self.assertTrue(result['running'])
        self.assertTrue(result['tun'])
        self.assertTrue(result['state_known'])
        self.assertEqual(result['service_status'], 'enabled')
        self.assertEqual(result['subscription_uid'], item['uid'])
        self.assertEqual(result['subscription'], item['name'])
        self.assertEqual(result['relay'], relay)
        self.assertIn(relay, result['nodes'])
        self.assertIn(item['uid'], [entry['uid'] for entry in result['subscriptions']])
        self.assertEqual(result['selected_id'], self.profile['id'])
        self.assertEqual(result['profiles'], [self.profile])
        self.assertEqual(result['configured_exit']['server'], self.profile['server'])
        self.assertEqual(result['ip'], self.profile['expected'])
        self.assertEqual(result['verified_at'], b.settings()['verified_at'])
        self.assertFalse(result['recovery_needed'])
        self.assertTrue(result['backup'])
        for private in ('controller-private', 'secret-token', 'airport-private', 'static-private'):
            self.assertNotIn(private, json.dumps(result))

    def test_start_reply_includes_fresh_verification_and_complete_state(self):
        state = {'running': False, 'tun': False, 'state_known': True,
                 'service_status': 'enabled', 'service_error': ''}
        calls = []

        def service(op, config=None):
            calls.append(op)
            state.update(running=True, tun=True)
            return {'ok': True, **state}

        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', side_effect=lambda: dict(state)), patch.object(b, 'service', side_effect=service), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value=self.profile['expected']) as exit_check, patch.object(b, 'verify_system_network', return_value={'ip': self.profile['expected'], 'warning': ''}) as system_check:
            result = b.dispatch({'op': 'start', 'id': self.profile['id'], 'relay': '日本一'})
        self.assertEqual(calls, ['start'])
        exit_check.assert_not_called()
        system_check.assert_called_once_with(self.profile['expected'], web=False)
        self.assert_fresh_connection_reply(result, self.item, '日本一')

    def test_running_subscription_switch_reply_includes_new_nodes_and_verified_exit(self):
        other = {**self.item, 'uid': 'a204ab86-248f-424c-9c57-05c46b5d3d17', 'name': '另一订阅'}
        source = {'proxies': [{**self.source['proxies'][0], 'name': '美国节点'}]}
        b.put_json(self.data / 'subscriptions.json', [self.item, other])
        b.put_json(b.cache_path(other), source)
        b.put_json(self.data / 'active.json', self.make_config())
        state = {'running': True, 'tun': True, 'state_known': True, 'service_status': 'enabled'}
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value=state), patch.object(b, 'service', return_value={'ok': True, **state}) as service, patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value=self.profile['expected']) as exit_check, patch.object(b, 'verify_system_network', return_value={'ip': self.profile['expected'], 'warning': ''}) as system_check:
            result = b.dispatch({'op': 'select_subscription', 'uid': other['uid']})
        self.assertEqual([entry.args[0] for entry in service.call_args_list], ['apply'])
        exit_check.assert_not_called()
        system_check.assert_called_once_with(self.profile['expected'], web=False)
        self.assert_fresh_connection_reply(result, other, '美国节点')
        self.assertEqual(result['nodes'], ['美国节点'])

    def test_running_restore_reply_includes_restored_metadata_and_new_verification(self):
        other = {**self.item, 'uid': 'a204ab86-248f-424c-9c57-05c46b5d3d17', 'name': '恢复的订阅'}
        source = {'proxies': [{**self.source['proxies'][0], 'name': '美国节点'}]}
        b.put_json(b.cache_path(other), source)
        previous = {**self.preferences, 'current_subscription_uid': other['uid'],
                    'relays': {other['uid']: '美国节点'}, 'last_verified_ip': self.profile['expected'],
                    'verified_at': '2000-01-01T00:00:00+00:00'}
        target = b.generate_config(source, self.profile, '美国节点', previous)
        backup = self.data / 'backups' / 'restore-running'
        b.put_json(backup / 'active.json', target)
        b.put_json(backup / 'settings.json', previous)
        b.put_json(backup / 'subscriptions.json', [other])
        b.put_json(backup / 'info.json', {'running': True})
        b.write(self.data / 'last-backup', str(backup))
        b.put_json(self.data / 'active.json', self.make_config())
        state = {'running': True, 'tun': True, 'state_known': True, 'service_status': 'enabled'}
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value=state), patch.object(b, 'service', return_value={'ok': True, **state}) as service, patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value=self.profile['expected']) as exit_check, patch.object(b, 'verify_system_network', return_value={'ip': self.profile['expected'], 'warning': ''}) as system_check:
            result = b.dispatch({'op': 'restore'})
        self.assertEqual([entry.args[0] for entry in service.call_args_list], ['apply'])
        exit_check.assert_not_called()
        system_check.assert_called_once_with(self.profile['expected'], web=False)
        self.assert_fresh_connection_reply(result, other, '美国节点')
        self.assertEqual([entry['uid'] for entry in result['subscriptions']], [other['uid']])
        self.assertNotEqual(result['verified_at'], previous['verified_at'])

    def test_prewarm_validates_exactly_the_config_start_will_use(self):
        validated, applied = [], []
        with patch.object(b, 'validate_core', side_effect=lambda config: validated.append(copy.deepcopy(config)) or False), patch.object(b, 'warm_file_cache') as warm:
            result = b.dispatch({'op': 'prewarm', 'id': self.profile['id'], 'relay': '日本一'})
        self.assertEqual(result, {'prewarmed': True, 'cache_hit': False})
        warm.assert_called_once()
        with patch.object(b, 'transaction', side_effect=lambda config, *args, **kwargs: applied.append(config) or {'ip': self.profile['expected']}), patch.object(b, 'service_status', return_value={'running': False}):
            b.select_and_apply(profile_id=self.profile['id'], relay='日本一', start=True)
        # 配置相同才能让连接时的校验缓存命中；预热不改设置。
        self.assertEqual(validated, applied)
        self.assertEqual(b.read_json(self.data / 'settings.json', {}).get('relays', {}).get(self.item['uid']), '日本一')

    def test_prewarm_makes_first_start_hit_validation_cache(self):
        resources = self.root / 'prewarm-resources'
        (resources / 'geodata').mkdir(parents=True)
        for path in (resources / 'mihomo', resources / 'geodata/geosite.dat', resources / 'geodata/Country.mmdb'):
            path.write_bytes(b'test-resource')
        with patch.object(b, 'resources', return_value=resources), patch.object(b, 'run', return_value='') as core_check, patch.object(b, 'warm_file_cache'):
            self.assertEqual(b.prewarm(self.profile['id'], '日本一'), {'prewarmed': True, 'cache_hit': False})
            self.assertEqual(b.prewarm(self.profile['id'], '日本一'), {'prewarmed': True, 'cache_hit': True})
        core_check.assert_called_once()

    def test_prewarm_never_writes_settings_or_creates_secret(self):
        preferences = {key: value for key, value in self.preferences.items() if key != 'controller_secret'}
        b.put_json(self.data / 'settings.json', preferences)
        before = (self.data / 'settings.json').read_bytes()
        with patch.object(b, 'validate_core') as validate:
            self.assertEqual(b.prewarm(self.profile['id'], '日本一'), {'prewarmed': False})
        validate.assert_not_called()
        self.assertEqual((self.data / 'settings.json').read_bytes(), before)
        with patch.object(b, 'validate_core', side_effect=ValueError('内核配置校验失败')):
            b.put_json(self.data / 'settings.json', self.preferences)
            self.assertEqual(b.prewarm(self.profile['id'], '日本一'), {'prewarmed': False})

    def test_validation_cache_hit_still_applies_and_verifies_every_transaction(self):
        resources = self.root / 'validation-resources'
        (resources / 'geodata').mkdir(parents=True)
        for path in (resources / 'mihomo', resources / 'geodata/geosite.dat', resources / 'geodata/Country.mmdb'):
            path.write_bytes(b'test-resource')
        config = self.make_config()
        with patch.object(b, 'resources', return_value=resources), patch.object(b, 'run', return_value='') as local_validation, patch.object(b, 'service_status', side_effect=[{'running': False}, {'running': True}]), patch.object(b, 'service', return_value={'ok': True}) as service, patch.object(b, 'await_core') as readiness, patch.object(b, 'verify_exit', return_value=self.profile['expected']) as exit_check, patch.object(b, 'verify_system_network', return_value={'ip': self.profile['expected'], 'warning': ''}) as system_check:
            first = b.transaction(config, self.preferences, self.profile['expected'])
            second = b.transaction(config, self.preferences, self.profile['expected'])
        local_validation.assert_called_once()
        self.assertEqual([entry.args[0] for entry in service.call_args_list], ['start', 'apply'])
        self.assertEqual(readiness.call_count, 2)
        self.assertEqual(exit_check.call_count, 0)
        self.assertEqual(system_check.call_count, 2)
        self.assertEqual(first['ip'], self.profile['expected'])
        self.assertEqual(second['ip'], self.profile['expected'])
        self.assertNotEqual(first['verified_at'], second['verified_at'])

    def test_transaction_start_verifies_before_commit(self):
        config = self.make_config()
        events = []
        with patch.object(b, 'validate_core', side_effect=lambda c: events.append('validate')), patch.object(b, 'service_status', return_value={'running': False}), patch.object(b, 'service', side_effect=lambda op, c=None: events.append(op) or {'ok': True, 'running': True}), patch.object(b, 'await_core', side_effect=lambda c: events.append('ready')), patch.object(b, 'verify_exit', side_effect=lambda: events.append('verify') or '198.51.100.20'), patch.object(b, 'verify_system_network', side_effect=lambda expected, web=True: events.append('system_verify') or {'ip': expected, 'warning': ''}) as system_verify:
            result = b.transaction(config, self.preferences, '198.51.100.20', commit=lambda: events.append('commit'))
        self.assertEqual(events[:3], ['validate', 'start', 'ready'])
        self.assertEqual(events[3:-1], ['system_verify'])
        self.assertEqual(events[-1], 'commit')
        system_verify.assert_called_once_with('198.51.100.20', web=False)
        self.assertEqual(result['ip'], '198.51.100.20')
        self.assertEqual(b.read_json(self.data / 'active.json', {}), config)
        self.assertFalse((self.data / 'pending.json').exists())
        self.assertTrue((self.data / 'last-backup').exists())

    def test_failed_start_stops_new_service_and_preserves_settings(self):
        config = self.make_config()
        calls = []
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', side_effect=[{'running': False}, {'running': True}]), patch.object(b, 'service', side_effect=lambda op, c=None: calls.append(op) or {'ok': True}), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', return_value={'ip': '198.51.100.99', 'warning': ''}):
            with self.assertRaisesRegex(RuntimeError, '已恢复'): b.transaction(config, {**self.preferences, 'selected_profile_id': 'new'}, '198.51.100.20')
        self.assertEqual(calls, ['start', 'stop'])
        self.assertEqual(b.settings(), self.preferences)
        self.assertFalse((self.data / 'active.json').exists())

    def test_failed_apply_reloads_original_configuration(self):
        old = self.make_config()
        b.put_json(self.data / 'active.json', old)
        new = copy.deepcopy(old)
        new['proxies'][-1]['server'] = '198.51.100.21'
        calls = []
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value={'running': True}), patch.object(b, 'service', side_effect=lambda op, c=None: calls.append((op, c)) or {'ok': True}), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', side_effect=RuntimeError('系统路径验证失败。')):
            with self.assertRaisesRegex(RuntimeError, '已恢复'): b.transaction(new, self.preferences)
        self.assertEqual([op for op, _ in calls], ['apply', 'apply'])
        self.assertEqual(calls[-1][1], old)
        self.assertEqual(b.read_json(self.data / 'active.json', {}), old)

    def test_rollback_failure_retains_recovery_record(self):
        old = self.make_config()
        b.put_json(self.data / 'active.json', old)
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value={'running': True}), patch.object(b, 'service', side_effect=[{'ok': True}, RuntimeError('失败')]), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', side_effect=RuntimeError('失败')):
            with self.assertRaisesRegex(RuntimeError, '恢复未完成'): b.transaction(old, self.preferences)
        self.assertTrue((self.data / 'pending.json').exists())

    def test_subscription_update_validation_failure_keeps_original_cache(self):
        original = b.cache_path(self.item).read_bytes()
        original_entries = (self.data / 'subscriptions.json').read_bytes()
        with patch.object(b, 'fetch_subscription', return_value='unused'), patch.object(b, 'parse_subscription_text', return_value=self.source), patch.object(b, 'validate_subscription', side_effect=ValueError('invalid')):
            with self.assertRaises(ValueError): b.update_subscription(self.item['uid'])
        self.assertEqual(b.cache_path(self.item).read_bytes(), original)
        self.assertEqual((self.data / 'subscriptions.json').read_bytes(), original_entries)

    def test_running_subscription_update_rolls_back_cache_pointer(self):
        old = self.make_config()
        b.put_json(self.data / 'active.json', old)
        changed = copy.deepcopy(self.source)
        changed['proxies'][0]['server'] = 'new-relay.example'
        with patch.object(b, 'fetch_subscription', return_value='unused'), patch.object(b, 'parse_subscription_text', return_value=changed), patch.object(b, 'validate_subscription'), patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value={'running': True}), patch.object(b, 'service', return_value={'ok': True}), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', return_value={'ip': '198.51.100.99', 'warning': ''}):
            with self.assertRaisesRegex(RuntimeError, '已恢复'): b.update_subscription(self.item['uid'])
        self.assertEqual(b.subscription(self.item['uid']), self.item)
        self.assertEqual(b.cached(self.item), self.source)
        self.assertEqual(b.read_json(self.data / 'active.json', {}), old)

    def test_migration_reads_clash_without_altering_it_or_starting_service(self):
        (self.verge / 'profiles').mkdir()
        meta = {'current': 'legacy-id', 'items': [{'uid': 'legacy-id', 'type': 'remote', 'name': '导入机场', 'file': 'legacy.yaml', 'url': 'https://example/hidden', 'selected': [{'now': '日本一'}]}]}
        (self.verge / 'profiles.yaml').write_text(json.dumps(meta))
        (self.verge / 'profiles/legacy.yaml').write_text(json.dumps(self.source))
        (self.verge / 'clash-verge.yaml').write_text(json.dumps(self.make_config()))
        before = {str(path): path.read_bytes() for path in self.verge.rglob('*') if path.is_file()}
        with patch.object(b, 'parse_yaml', side_effect=lambda path: json.loads(Path(path).read_text())), patch.object(b, 'validate_subscription'), patch.object(b, 'service_status', return_value={'running': False}), patch.object(b, 'service') as service:
            result = b.migrate()
            again = b.migrate()
        after = {str(path): path.read_bytes() for path in self.verge.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(result['migrated'])
        self.assertEqual(len(again['subscriptions']), 2)
        self.assertEqual(len(b.profiles()), 1)
        service.assert_not_called()
        self.assertNotIn('hidden', json.dumps(result))

    def test_service_install_error_does_not_claim_connection_success(self):
        config = self.make_config()
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', return_value={'running': False}), patch.object(b, 'service', side_effect=RuntimeError('请先安装网络服务。')):
            with self.assertRaisesRegex(RuntimeError, '请先安装网络服务'): b.transaction(config, self.preferences)
        self.assertFalse((self.data / 'active.json').exists())

    def test_yaml_parser_rejects_object_tags(self):
        path = self.root / 'unsafe.yaml'
        path.write_text('--- !ruby/object:Object {}\n')
        with self.assertRaises(ValueError): b.parse_yaml(path)

    def test_foreign_backup_cannot_be_restored(self):
        b.write(self.data / 'last-backup', '/tmp/unowned')
        with self.assertRaises(ValueError): b.restore()


    def test_unknown_service_state_blocks_metadata_changes(self):
        original = (self.data / 'subscriptions.json').read_bytes()
        with patch.object(b, 'service_status', return_value={'running': False, 'state_known': False}):
            for action in (lambda: b.choose_subscription(self.item['uid']), lambda: b.delete_subscription(self.item['uid']), b.migrate):
                with self.assertRaisesRegex(RuntimeError, '无法确认'): action()
        self.assertEqual((self.data / 'subscriptions.json').read_bytes(), original)

    def test_pending_transaction_blocks_offline_selection_changes(self):
        b.put_json(self.data / 'pending.json', {'stage': 'applying'})
        original = (self.data / 'settings.json').read_bytes()
        with patch.object(b, 'service_status', return_value={'running': False}):
            with self.assertRaisesRegex(RuntimeError, '上次配置操作'): b.choose_subscription(self.item['uid'])
            with self.assertRaisesRegex(RuntimeError, '上次配置操作'): b.select_and_apply(start=True)
        self.assertEqual((self.data / 'settings.json').read_bytes(), original)

    def test_restore_uses_original_stopped_state_even_with_old_active_file(self):
        backup = self.data / 'backups' / 'previous-stopped'
        b.put_json(backup / 'active.json', self.make_config())
        b.put_json(backup / 'settings.json', self.preferences)
        b.put_json(backup / 'subscriptions.json', [self.item])
        b.put_json(backup / 'info.json', {'running': False})
        b.write(self.data / 'last-backup', str(backup))
        with patch.object(b, 'service_status', return_value={'running': True}), patch.object(b, 'service', return_value={'ok': True, 'running': False}) as service:
            result = b.restore()
        service.assert_called_once_with('stop')
        self.assertIn('服务未启动', result['message'])

    def test_delete_subscription_keeps_cache_for_historical_restore(self):
        cache = b.cache_path(self.item)
        with patch.object(b, 'service_status', return_value={'running': False}):
            b.delete_subscription(self.item['uid'])
        self.assertTrue(cache.exists())
        self.assertEqual(b.subscriptions(), [])

    def test_delete_inactive_subscription_preserves_running_connection(self):
        other = {**self.item, 'uid': 'a204ab86-248f-424c-9c57-05c46b5d3d17', 'name': '待删除订阅'}
        b.put_json(self.data / 'subscriptions.json', [self.item, other])
        b.put_json(b.cache_path(other), self.source)
        preferences = {**self.preferences, 'relays': {**self.preferences['relays'], other['uid']: '日本一'}}
        b.put_json(self.data / 'settings.json', preferences)
        b.put_json(self.data / 'active.json', self.make_config())
        active = (self.data / 'active.json').read_bytes()
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True, 'state_known': True}), patch.object(b, 'service') as service:
            result = b.delete_subscription(other['uid'])
        service.assert_not_called()
        self.assertEqual(b.settings(), self.preferences)
        self.assertEqual((self.data / 'active.json').read_bytes(), active)
        self.assertEqual([item['uid'] for item in b.subscriptions()], [self.item['uid']])
        self.assertEqual(result['subscription_uid'], self.item['uid'])
        self.assertEqual(result['relay'], '日本一')
        self.assertTrue(result['running'])

    def test_delete_running_current_subscription_is_rejected_without_writes(self):
        before = {path: path.read_bytes() for path in self.data.rglob('*') if path.is_file()}
        with patch.object(b, 'service_status', return_value={'running': True, 'state_known': True}), patch.object(b, 'service') as service:
            with self.assertRaisesRegex(ValueError, '先停止'):
                b.delete_subscription(self.item['uid'])
        service.assert_not_called()
        self.assertEqual(before, {path: path.read_bytes() for path in self.data.rglob('*') if path.is_file()})

    def test_failed_migration_keychain_does_not_leave_partial_subscriptions(self):
        (self.verge / 'profiles').mkdir()
        meta = {'current': 'legacy-id', 'items': [{'uid': 'legacy-id', 'type': 'remote', 'name': '机场', 'file': 'legacy.yaml'}]}
        (self.verge / 'profiles.yaml').write_text(json.dumps(meta))
        (self.verge / 'profiles/legacy.yaml').write_text(json.dumps(self.source))
        (self.verge / 'clash-verge.yaml').write_text(json.dumps(self.make_config()))
        original = (self.data / 'subscriptions.json').read_bytes()
        with patch.object(b, 'parse_yaml', side_effect=lambda p: json.loads(Path(p).read_text())), patch.object(b, 'validate_subscription'), patch.object(b, 'service_status', return_value={'running': False}), patch.object(b, 'keychain', return_value={'ok': False}):
            with self.assertRaisesRegex(RuntimeError, '钥匙串'): b.migrate()
        self.assertEqual((self.data / 'subscriptions.json').read_bytes(), original)
        self.assertNotIn('migrated_at', b.settings())

    def test_migration_prefers_active_static_relay_and_retries_consistently(self):
        (self.verge / 'profiles').mkdir()
        source = {'proxies': self.source['proxies'] + [{'name': '美国二', 'type': 'socks5', 'server': 'us.example', 'port': 443}]}
        runtime = self.make_config()
        runtime['proxy-groups'][0]['proxies'] = ['美国二']
        meta = {'current': 'legacy-id', 'items': [{'uid': 'legacy-id', 'type': 'remote', 'name': '机场', 'file': 'legacy.yaml', 'selected': [{'now': '日本一'}]}]}
        (self.verge / 'profiles.yaml').write_text(json.dumps(meta))
        (self.verge / 'profiles/legacy.yaml').write_text(json.dumps(source))
        (self.verge / 'clash-verge.yaml').write_text(json.dumps(runtime))
        with patch.object(b, 'parse_yaml', side_effect=lambda p: json.loads(Path(p).read_text())), patch.object(b, 'validate_subscription'), patch.object(b, 'service_status', return_value={'running': False}):
            first = b.migrate()
            second = b.migrate()
        self.assertEqual(first['relay'], '美国二')
        self.assertEqual(second['relay'], '美国二')
        self.assertEqual(first['subscription_uid'], second['subscription_uid'])

    def curl_result(self, code=0, body='198.51.100.20', status=200, error=''):
        return subprocess.CompletedProcess([], code, stdout=body + '\n' + str(status), stderr=error)

    def test_verification_main_failure_uses_backup_and_records_redacted_diagnostics(self):
        secret = 'username:private-password@host.example/?token=private-token'
        responses = lambda args, **kwargs: self.curl_result(35, '', 0, secret) if args[-1] == 'https://1.1.1.1/cdn-cgi/trace' else self.curl_result()
        with patch.object(b, 'run_probe', side_effect=responses) as run, patch.object(b.time, 'sleep'):
            actual = b.verify_exit()
        self.assertEqual(actual, '198.51.100.20')
        self.assertEqual(run.call_count, 2)
        self.assertCountEqual([call.args[0][-1] for call in run.call_args_list], ['https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace'])
        content = (self.data / 'diagnostics.jsonl').read_text()
        records = [json.loads(line) for line in content.splitlines()]
        self.assertCountEqual([record['result'] for record in records], ['failure', 'success'])
        self.assertEqual(next(record for record in records if record['host'] == '1.1.1.1')['category'], 'tls_interrupted')
        for sensitive in (secret, 'private-password', 'private-token', 'controller-private', '198.51.100.20'):
            self.assertNotIn(sensitive, content)
        self.assertEqual(set(records[0]), {'time', 'phase', 'attempt', 'host', 'code', 'elapsed', 'result', 'category', 'http_status'})

    def test_verification_all_attempts_fail_without_claiming_success(self):
        with patch.object(b, 'run_probe', return_value=self.curl_result(35, '', 0)) as run, patch.object(b.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'TLS 连接中断'):
                b.verify_exit()
        self.assertEqual(run.call_count, 4)
        records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
        self.assertTrue(all(record['result'] == 'failure' for record in records))

    def test_verification_forces_proxy_even_with_no_proxy_wildcard(self):
        with patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}), patch.object(b, 'run_probe', return_value=self.curl_result()) as run:
            b.verify_exit()
        args = run.call_args.args[0]
        self.assertEqual(args[1], '-q')
        self.assertEqual(args[args.index('--noproxy') + 1], '')
        self.assertEqual(args[args.index('--proxy') + 1], 'http://127.0.0.1:17896')
        self.assertNotIn('--insecure', args)
        self.assertNotIn('-k', args)

    def test_verification_total_budget_is_at_most_forty_seconds(self):
        with patch.object(b.time, 'monotonic', return_value=100.0), patch.object(b, 'verify_ip_race', return_value='198.51.100.20') as race:
            b.verify_exit()
        race.assert_called_once_with(140.0, 12.0, 4, 'exit_verification', port=17896)

    def test_verification_certificate_error_is_not_bypassed_or_retried(self):
        with patch.object(b, 'run_probe', return_value=self.curl_result(60, '', 0, 'secret certificate path')) as run:
            with self.assertRaisesRegex(RuntimeError, '证书校验失败'):
                b.verify_exit()
        self.assertLessEqual(run.call_count, 2)
        self.assertNotIn('--insecure', run.call_args.args[0])
        self.assertNotIn('secret certificate path', (self.data / 'diagnostics.jsonl').read_text())

    def test_verification_invalid_body_and_http_service_failures_use_backup(self):
        for first, category in ((self.curl_result(22, '', 503), 'query_http'),
                                (self.curl_result(0, '<html>not-an-ip</html>', 200), 'invalid_ip')):
            responses = lambda args, **kwargs: first if args[-1] == 'https://1.1.1.1/cdn-cgi/trace' else self.curl_result()
            with patch.object(b, 'run_probe', side_effect=responses), patch.object(b.time, 'sleep'):
                self.assertEqual(b.verify_exit(), '198.51.100.20')
            records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
            self.assertEqual([record for record in records if record['host'] == '1.1.1.1'][-1]['category'], category)

    def test_verification_local_port_error_is_clear(self):
        with patch.object(b, 'run_probe', return_value=self.curl_result(7, '', 0)) as run:
            with self.assertRaisesRegex(RuntimeError, '本地代理端口无法连接'):
                b.verify_exit()
        self.assertLessEqual(run.call_count, 2)

    def system_responses(self, exit_results, web_results):
        # 查询站同时启动，按固定域名分流；Google 自己按尝试次数取值。
        web = iter(web_results)
        def call(args, **kwargs):
            if '--output' in args:
                return next(web)
            index = 0 if args[-1] == 'https://1.1.1.1/cdn-cgi/trace' else min(1, len(exit_results) - 1)
            return exit_results[index]
        return call

    def test_system_verification_disables_all_proxies_and_checks_both_phases(self):
        env = {'http_proxy': 'http://user:private@localhost:1', 'HTTPS_PROXY': 'http://localhost:2',
               'ALL_PROXY': 'socks5://localhost:3', 'NO_PROXY': 'example.com'}
        responses = self.system_responses([self.curl_result()], [self.curl_result(body='', status=204)])
        with patch.dict(os.environ, env), patch.object(b, 'run_probe', side_effect=responses) as run:
            result = b.verify_system_network('198.51.100.20')
        self.assertEqual(result, {'ip': '198.51.100.20', 'warning': '', 'http_status': 204})
        self.assertCountEqual([call.args[0][-1] for call in run.call_args_list],
                              ['https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace', 'https://www.google.com/generate_204'])
        for call in run.call_args_list:
            args = call.args[0]
            self.assertEqual(args[1], '-q')
            self.assertEqual(args[args.index('--proxy') + 1], '')
            self.assertEqual(args[args.index('--noproxy') + 1], '*')
            self.assertFalse({'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'} & {key.lower() for key in call.kwargs['env']})
            self.assertNotIn('--fail', args)
            self.assertNotIn('--insecure', args)
            self.assertNotIn('-k', args)
            self.assertNotIn('--resolve', args)

    def test_system_exit_fallback_and_web_transient_retry(self):
        responses = self.system_responses([self.curl_result(6, '', 0), self.curl_result()],
                                          [self.curl_result(35, '', 0), self.curl_result(body='', status=200)])
        with patch.object(b, 'run_probe', side_effect=responses) as run, patch.object(b.time, 'sleep'):
            result = b.verify_system_network('198.51.100.20')
        self.assertEqual(result['ip'], '198.51.100.20')
        self.assertEqual(run.call_count, 4)
        exit_calls = [call for call in run.call_args_list if '--output' not in call.args[0]]
        self.assertCountEqual([call.args[0][-1] for call in exit_calls], ['https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace'])
        records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
        self.assertCountEqual([record['phase'] for record in records], ['system_exit_verification'] * 2 + ['system_web_verification'] * 2 + ['system_dns_verification'])

    def test_system_exit_mismatch_fails_without_retry(self):
        responses = self.system_responses([self.curl_result(body='198.51.100.99')],
                                          [self.curl_result(body='', status=204)])
        with patch.object(b, 'run_probe', side_effect=responses) as run:
            with self.assertRaisesRegex(RuntimeError, '系统 TUN 公网出口与预期静态 IP 不一致'):
                b.verify_system_network('198.51.100.20')
        self.assertEqual(sum('--output' not in call.args[0] for call in run.call_args_list), 2)
        records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
        self.assertEqual(next(record for record in records if record['phase'] == 'system_exit_verification')['category'], 'exit_mismatch')

    def test_system_google_http_restriction_is_a_warning_not_a_network_failure(self):
        for status in (403, 429, 503):
            responses = self.system_responses([self.curl_result()], [self.curl_result(body='', status=status)])
            with self.subTest(status=status), patch.object(b, 'run_probe', side_effect=responses) as run:
                result = b.verify_system_network('198.51.100.20')
            self.assertEqual(result['http_status'], status)
            self.assertIn('HTTP ' + str(status), result['warning'])
            self.assertEqual(run.call_count, 3)

    def test_system_google_dns_or_tls_failure_is_not_hidden_by_correct_exit(self):
        for code, reason in ((6, '系统 DNS'), (35, 'TLS 连接中断'), (28, '系统 TUN 路径连接超时')):
            responses = self.system_responses([self.curl_result()], [self.curl_result(code, '', 0), self.curl_result(code, '', 0)])
            with self.subTest(code=code), patch.object(b, 'run_probe', side_effect=responses) as run, patch.object(b.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, reason):
                    b.verify_system_network('198.51.100.20')
            self.assertEqual(run.call_count, 4)

    def test_system_certificate_error_is_never_bypassed_or_retried(self):
        private = 'private-password@private.example/?token=secret-token'
        responses = self.system_responses([self.curl_result()], [self.curl_result(60, '', 0, private)])
        with patch.object(b, 'run_probe', side_effect=responses) as run:
            with self.assertRaisesRegex(RuntimeError, '证书校验失败'):
                b.verify_system_network('198.51.100.20')
        self.assertEqual(run.call_count, 3)
        raw = (self.data / 'diagnostics.jsonl').read_text()
        for secret in (private, 'private-password', 'secret-token', '198.51.100.20', 'controller-private'):
            self.assertNotIn(secret, raw)
        self.assertTrue(all('--insecure' not in call.args[0] for call in run.call_args_list))

    def test_system_phases_share_twenty_five_second_deadline(self):
        def phase_result(phase, expected, deadline):
            return {'ip': expected} if phase == 'system_exit_verification' else {'warning': '', 'http_status': 204}
        with patch.object(b.time, 'monotonic', return_value=100.0), patch.object(b, 'verify_system_phase', side_effect=phase_result) as phase:
            result = b.verify_system_network('198.51.100.20')
        self.assertEqual(result['ip'], '198.51.100.20')
        self.assertEqual(phase.call_count, 2)
        self.assertTrue(all(call.args[2] == 125.0 for call in phase.call_args_list))

    def test_system_phase_never_extends_shared_deadline(self):
        clock = [100.0]
        budgets = []
        def call(args, **kwargs):
            budget = kwargs['timeout']
            budgets.append(budget)
            self.assertLessEqual(budget, 10)
            self.assertAlmostEqual(float(args[args.index('--max-time') + 1]), budget)
            clock[0] += budget
            raise subprocess.TimeoutExpired(args, budget)
        with patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(b.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), patch.object(b, 'run_probe', side_effect=call):
            with self.assertRaisesRegex(RuntimeError, '系统路径验证失败'):
                b.verify_system_phase('system_web_verification', '198.51.100.20', 115.0)
        self.assertEqual(clock[0], 115.0)
        self.assertEqual(len(budgets), 2)
        self.assertLess(budgets[-1], 5)

    def test_system_failure_rolls_back_transaction_before_commit(self):
        calls, committed = [], []
        with patch.object(b, 'validate_core'), patch.object(b, 'service_status', side_effect=[{'running': False}, {'running': True}]), patch.object(b, 'service', side_effect=lambda op, c=None: calls.append(op) or {'ok': True}), patch.object(b, 'await_core'), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', side_effect=RuntimeError('系统 DNS 解析失败')):
            with self.assertRaisesRegex(RuntimeError, '已恢复.*系统 DNS'):
                b.transaction(self.make_config(), self.preferences, '198.51.100.20', commit=lambda: committed.append(True))
        self.assertEqual(calls, ['start', 'stop'])
        self.assertEqual(committed, [])
        self.assertEqual(b.settings(), self.preferences)
        self.assertFalse((self.data / 'active.json').exists())

    def test_verify_preserves_last_success_when_system_path_fails(self):
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', side_effect=RuntimeError('系统路径验证失败')) as system_verify:
            with self.assertRaisesRegex(RuntimeError, '系统路径验证失败'):
                b.verify()
        system_verify.assert_called_once_with('198.51.100.20', web=True)
        self.assertEqual(b.settings(), self.preferences)

    def test_verify_returns_website_warning_without_claiming_website_access(self):
        warning = 'Google 已完成 HTTPS 连接，但返回 HTTP 403。'
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', return_value='198.51.100.20'), patch.object(b, 'verify_system_network', return_value={'ip': '198.51.100.20', 'warning': warning}):
            result = b.verify()
        self.assertIn(warning, result['message'])
        self.assertEqual(result['ip'], '198.51.100.20')
        self.assertIn('verified_at', b.settings())

    def test_diagnostics_are_bounded_and_keep_valid_json_lines(self):
        record = json.dumps({'long_field': 'x' * 140}) + '\n'
        b.write(self.data / 'diagnostics.jsonl', record * 1000)
        b.record_verification(1, '1.1.1.1', 0, 1.2, 'success', 'ok', 200)
        raw = (self.data / 'diagnostics.jsonl').read_bytes()
        self.assertLessEqual(len(raw), b.DIAGNOSTICS_MAX_BYTES)
        for line in raw.splitlines(): json.loads(line)
        self.assertEqual(json.loads(raw.splitlines()[-1])['result'], 'success')

if __name__ == '__main__':
    unittest.main()
