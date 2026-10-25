"""完整连接计时工具：显式运行后会启动并停止本应用网络，不修改其他 VPN。"""
import argparse
import fcntl
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-live', action='store_true')
    args = parser.parse_args()
    if not args.run_live:
        parser.error('需显式添加 --run-live 才会实际连接。')
    app = Path.home() / 'Applications/静态出口管理器独立版.app'
    executable = app / 'Contents/MacOS/StaticExitManager'
    spec = importlib.util.spec_from_file_location('measured_backend', args.backend)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    sys.argv = [str(args.backend), str(executable)]
    initial = backend.known_service_status()
    if initial.get('running'):
        raise SystemExit('独立服务正在运行，请先停止，未修改网络。')
    route = subprocess.run(['/sbin/route', '-n', 'get', '1.1.1.1'], capture_output=True, text=True, check=True).stdout
    interface = next((line.split(':', 1)[1].strip() for line in route.splitlines() if 'interface:' in line), '')
    if not interface or interface.startswith('utun'):
        raise SystemExit('当前仍有其他 TUN 路由，未开始测试。')
    records, mutex = [], threading.Lock()
    started = time.perf_counter()

    def instrument(name):
        original = getattr(backend, name)

        def timed(*values, **options):
            begin = time.perf_counter()
            result, success = None, False
            try:
                result = original(*values, **options)
                success = True
                return result
            finally:
                record = {'stage': name, 'start_seconds': round(begin - started, 3),
                          'seconds': round(time.perf_counter() - begin, 3), 'ok': success}
                if name == 'service':
                    record['operation'] = values[0]
                if name == 'validate_core' and success:
                    record['cache_hit'] = result is True
                with mutex:
                    records.append(record)
        setattr(backend, name, timed)

    for name in ('validate_core', 'generate_config', 'keychain', 'service', 'await_core',
                 'verify_exit', 'verify_system_network', 'verify_connection'):
        if hasattr(backend, name):
            instrument(name)
    report = {'backend_sha256': hashlib.sha256(args.backend.read_bytes()).hexdigest(),
              'timing_scope': '后端完整连接；不含界面启动 Python 的耗时，不含结束后的停止清理。',
              'ok': False}
    with (backend.LIBRARY / 'operation.lock').open('a') as operation_lock:
        fcntl.flock(operation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if backend.known_service_status().get('running'):
            raise SystemExit('独立服务状态已改变，取消测试，保留当前连接。')
        backend.require_settled()
        try:
            result = backend.select_and_apply(start=True)
            report.update(ok=True, ip=result.get('ip'), running=result.get('running'), tun=result.get('tun'))
        except (RuntimeError, ValueError) as error:
            report['error'] = str(error)
        finally:
            report['total_seconds'] = round(time.perf_counter() - started, 3)
            try:
                backend.service('stop')
                report['stopped_after_test'] = not backend.known_service_status().get('running')
            except (RuntimeError, ValueError):
                report['stopped_after_test'] = False
            report['stages'] = records
            backend.put_json(args.output, report)
            print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
