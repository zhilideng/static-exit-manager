"""实时连接检测并发回归：不访问网络，不启动或改变用户的网络服务。"""
import concurrent.futures
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import backend as b


class ConnectionParallelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.library = self.root / 'library'
        self.data = self.library / 'standalone'
        self.data.mkdir(parents=True)
        self.paths = patch.multiple(b, LIBRARY=self.library, DATA=self.data,
                                    resolve_system_dns=lambda name: {'198.18.0.5'})
        self.paths.start()
        self.preferences = {'selected_profile_id': 'test-profile', 'relays': {}}
        b.put_json(self.data / 'settings.json', self.preferences)
        self.expected = '198.51.100.20'

    def tearDown(self):
        b.CANCEL_PROBES.clear()
        self.paths.stop()
        self.temp.cleanup()

    def curl_result(self, body=None, status=200, code=0):
        if body is None:
            body = self.expected
        return subprocess.CompletedProcess([], code, stdout=body + '\n' + str(status), stderr='')

    def test_three_live_probes_overlap_and_retain_tls_and_route_checks(self):
        barrier = threading.Barrier(5, timeout=3)
        seen = []
        lock = threading.Lock()

        def curl(args, **kwargs):
            phase = 'web' if '--output' in args else (
                'proxy' if args[args.index('--proxy') + 1] else 'system')
            with lock:
                seen.append(phase)
            barrier.wait()
            self.assertNotIn('--insecure', args)
            self.assertNotIn('-k', args)
            self.assertEqual(args[1], '-q')
            return self.curl_result(body='', status=204) if phase == 'web' else self.curl_result()

        with patch.object(b, 'run_probe', side_effect=curl):
            actual, system = b.verify_connection(self.expected)
        self.assertCountEqual(seen, ['proxy', 'proxy', 'system', 'system', 'web'])
        self.assertEqual(actual, self.expected)
        self.assertEqual(system, {'ip': self.expected, 'warning': '', 'http_status': 204})

    def test_failed_proxy_waits_for_system_probe_before_returning(self):
        # 手动重新检测仍同时等待代理端口与系统路径；任一失败也必须等其它检测退出。
        system_started = threading.Event()
        proxy_failed = threading.Event()
        release_system = threading.Event()
        system_finished = threading.Event()

        def proxy_probe():
            self.assertTrue(system_started.wait(3))
            proxy_failed.set()
            raise RuntimeError('公网出口验证失败：测试失败。')

        def system_probe(expected, web=True):
            system_started.set()
            self.assertTrue(release_system.wait(3))
            system_finished.set()
            return {'ip': expected, 'warning': ''}

        with patch.object(b, 'verify_exit', side_effect=proxy_probe), patch.object(b, 'verify_system_network', side_effect=system_probe):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(b.verify_connection, self.expected)
                try:
                    self.assertTrue(proxy_failed.wait(3))
                    self.assertFalse(result.done())
                finally:
                    release_system.set()
                with self.assertRaisesRegex(RuntimeError, '测试失败'):
                    result.result(timeout=3)
        self.assertTrue(system_finished.is_set())

    def test_system_failure_during_connect_rolls_back_without_proxy_probe(self):
        state = {'running': False}
        committed = []
        def service(op, config=None):
            state['running'] = op == 'start'
            return {'ok': True, **state}
        with patch.object(b, 'validate_core'), patch.object(b, 'await_core'), patch.object(b, 'service_status', side_effect=lambda: dict(state)), patch.object(b, 'service', side_effect=service), patch.object(b, 'verify_exit') as proxy, patch.object(b, 'verify_system_network', side_effect=RuntimeError('系统路径验证失败：测试失败。')):
            with self.assertRaisesRegex(RuntimeError, '已恢复.*测试失败'):
                b.transaction({}, self.preferences, self.expected, commit=lambda: committed.append(True))
        proxy.assert_not_called()
        self.assertFalse(state['running'])
        self.assertEqual(committed, [])
        self.assertFalse((self.data / 'active.json').exists())
        self.assertFalse((self.data / 'pending.json').exists())

    def test_system_exit_failure_waits_for_google_probe_before_returning(self):
        web_started = threading.Event()
        exit_failed = threading.Event()
        release_web = threading.Event()
        web_finished = threading.Event()

        def phase(phase, expected, deadline):
            if phase == 'system_web_verification':
                web_started.set()
                self.assertTrue(release_web.wait(3))
                web_finished.set()
                return {'warning': '', 'http_status': 204}
            self.assertTrue(web_started.wait(3))
            exit_failed.set()
            raise RuntimeError('系统路径验证失败：出口不一致。')

        with patch.object(b, 'verify_system_phase', side_effect=phase):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(b.verify_system_network, self.expected)
                try:
                    self.assertTrue(exit_failed.wait(3))
                    self.assertFalse(result.done())
                finally:
                    release_web.set()
                with self.assertRaisesRegex(RuntimeError, '出口不一致'):
                    result.result(timeout=3)
        self.assertTrue(web_finished.is_set())

    def test_proxy_mismatch_cannot_be_hidden_by_matching_system_exit(self):
        with patch.object(b, 'verify_exit', return_value='198.51.100.99'), patch.object(b, 'verify_system_network', return_value={'ip': self.expected, 'warning': ''}) as system:
            with self.assertRaisesRegex(RuntimeError, '实际公网出口与预期静态 IP 不一致'):
                b.verify_connection(self.expected)
        system.assert_called_once_with(self.expected, web=True)

    def test_system_mismatch_cannot_be_hidden_by_matching_proxy_exit(self):
        with patch.object(b, 'verify_exit', return_value=self.expected), patch.object(b, 'verify_system_network', return_value={'ip': '198.51.100.99', 'warning': ''}):
            with self.assertRaisesRegex(RuntimeError, '系统 TUN 公网出口与预期静态 IP 不一致'):
                b.verify_connection(self.expected)

    def test_missing_expected_runs_proxy_and_system_checks_in_parallel(self):
        # 未填写预期出口时不再串行等待代理结果；两条路径同时检测，事后要求一致。
        barrier = threading.Barrier(2, timeout=3)
        def proxy_probe():
            barrier.wait()
            return self.expected
        def system_probe(expected, web=True):
            self.assertEqual(expected, '')
            barrier.wait()
            return {'ip': self.expected, 'warning': ''}
        with patch.object(b, 'verify_exit', side_effect=proxy_probe), patch.object(b, 'verify_system_network', side_effect=system_probe):
            actual, system = b.verify_connection()
        self.assertEqual(actual, self.expected)
        self.assertEqual(system['ip'], self.expected)

    def test_missing_expected_still_requires_matching_system_exit(self):
        with patch.object(b, 'verify_exit', return_value=self.expected), patch.object(b, 'verify_system_network', return_value={'ip': '198.51.100.99', 'warning': ''}):
            with self.assertRaisesRegex(RuntimeError, '系统 TUN 公网出口与预期静态 IP 不一致'):
                b.verify_connection()

    def test_invalid_expected_never_starts_probes(self):
        with patch.object(b, 'verify_exit') as proxy, patch.object(b, 'verify_system_network') as system:
            with self.assertRaisesRegex(ValueError, '合法的预期出口 IP'):
                b.verify_connection('invalid expected')
        proxy.assert_not_called()
        system.assert_not_called()

    def test_certificate_failure_remains_fatal_when_other_phases_succeed(self):
        calls = []
        lock = threading.Lock()
        def curl(args, **kwargs):
            is_proxy = bool(args[args.index('--proxy') + 1])
            with lock:
                calls.append(is_proxy)
            return self.curl_result(body='', status=0, code=60) if is_proxy else (
                self.curl_result(body='', status=204) if '--output' in args else self.curl_result())
        with patch.object(b, 'run_probe', side_effect=curl):
            with self.assertRaisesRegex(RuntimeError, '证书校验失败'):
                b.verify_connection(self.expected)
        self.assertLessEqual(calls.count(True), 2)
        self.assertEqual(calls.count(False), 3)

    def test_concurrent_diagnostics_keep_every_record_and_remain_redacted(self):
        phases = ('exit_verification', 'system_exit_verification', 'system_web_verification')
        def record(number):
            b.record_verification(number, '1.1.1.1', 0, 0.1, 'success', 'ok', 200,
                                  phases[number % len(phases)])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(record, range(64)))
        raw = (self.data / 'diagnostics.jsonl').read_bytes()
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(records), 64)
        self.assertEqual({record['attempt'] for record in records}, set(range(64)))
        self.assertLessEqual(len(raw), b.DIAGNOSTICS_MAX_BYTES)
        self.assertNotIn(self.expected.encode(), raw)
        self.assertTrue(all(set(record) == {'time', 'phase', 'attempt', 'host', 'code', 'elapsed',
                                            'result', 'category', 'http_status'} for record in records))

    def test_fast_ip_site_cancels_slow_site_before_returning(self):
        started = threading.Barrier(2, timeout=3)
        slow_finished = threading.Event()
        def probe(args, *, cancelled, **kwargs):
            started.wait()
            if args[-1] == 'https://1.1.1.1/cdn-cgi/trace':
                self.assertTrue(cancelled.wait(3), '成功站返回后必须立即取消慢站')
                slow_finished.set()
                raise b.ProbeCancelled()
            return self.curl_result()
        with patch.object(b, 'run_probe', side_effect=probe) as runner:
            self.assertEqual(b.verify_exit(), self.expected)
        self.assertTrue(slow_finished.is_set())
        self.assertEqual(runner.call_count, 2)
        records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['host'], '1.0.0.1')
        self.assertEqual(records[0]['result'], 'success')

    def test_completed_certificate_error_is_not_hidden_by_successful_site(self):
        started = threading.Barrier(2, timeout=3)
        def probe(args, **kwargs):
            started.wait()
            return self.curl_result(code=60, status=0, body='') if args[-1] == 'https://1.1.1.1/cdn-cgi/trace' else self.curl_result()
        with patch.object(b, 'run_probe', side_effect=probe) as runner:
            with self.assertRaisesRegex(RuntimeError, '证书校验失败'):
                b.verify_exit()
        self.assertEqual(runner.call_count, 2)

    def test_completed_system_mismatch_is_not_hidden_by_successful_site(self):
        started = threading.Barrier(2, timeout=3)
        def probe(args, **kwargs):
            started.wait()
            return self.curl_result(body='198.51.100.99') if args[-1] == 'https://1.1.1.1/cdn-cgi/trace' else self.curl_result()
        with patch.object(b, 'run_probe', side_effect=probe):
            with self.assertRaisesRegex(RuntimeError, '系统 TUN 公网出口与预期静态 IP 不一致'):
                b.verify_system_phase('system_exit_verification', self.expected, b.time.monotonic() + 25)

    def test_invalid_fast_response_cannot_cancel_valid_backup(self):
        invalid_done = threading.Event()
        def probe(args, *, cancelled, **kwargs):
            if args[-1] == 'https://1.1.1.1/cdn-cgi/trace':
                invalid_done.set()
                return self.curl_result(body='<html>not an IP</html>')
            self.assertTrue(invalid_done.wait(3))
            self.assertFalse(cancelled.is_set())
            return self.curl_result()
        with patch.object(b, 'run_probe', side_effect=probe):
            self.assertEqual(b.verify_exit(), self.expected)

    def test_ip_race_shared_deadline_does_not_restart_after_first_round(self):
        clock = [100.0]
        started = threading.Barrier(2, timeout=3, action=lambda: clock.__setitem__(0, 105.0))
        budgets = []
        def probe(args, *, timeout, **kwargs):
            budgets.append(timeout)
            self.assertEqual(float(args[args.index('--max-time') + 1]), 5.0)
            started.wait()
            raise subprocess.TimeoutExpired(args, timeout)
        with patch.object(b.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(b, 'run_probe', side_effect=probe):
            with self.assertRaisesRegex(RuntimeError, '连接超时'):
                b.verify_ip_race(105.0, 12.0, 4, 'exit_verification')
        self.assertEqual(budgets, [5.0, 5.0])
        self.assertEqual(clock[0], 105.0)

    def test_slow_ip_wave_is_hedged_without_waiting_for_timeout(self):
        calls = []
        lock = threading.Lock()
        def probe(args, *, cancelled, timeout, **kwargs):
            self.assertEqual(args[args.index('--connect-timeout') + 1], args[args.index('--max-time') + 1])
            with lock:
                calls.append(args[-1])
                number = len(calls)
            if number <= 2:
                # 首波卡在冷启动握手：不能等它超时，对冲波次成功后必须取消并回收。
                self.assertTrue(cancelled.wait(3))
                raise b.ProbeCancelled()
            return self.curl_result()
        with patch.object(b, 'VERIFY_HEDGE_SECONDS', 0.05), patch.object(b, 'run_probe', side_effect=probe):
            self.assertEqual(b.verify_exit(), self.expected)
        self.assertGreaterEqual(len(calls), 3)
        self.assertLessEqual(len(calls), 4)

    def test_slow_google_attempt_is_hedged_and_cancelled(self):
        calls = []
        def probe(args, *, cancelled, **kwargs):
            self.assertEqual(args[args.index('--connect-timeout') + 1], args[args.index('--max-time') + 1])
            calls.append(args[-1])
            if len(calls) == 1:
                self.assertTrue(cancelled.wait(3))
                raise b.ProbeCancelled()
            return self.curl_result(body='', status=204)
        with patch.object(b, 'VERIFY_HEDGE_SECONDS', 0.05), patch.object(b, 'run_probe', side_effect=probe):
            result = b.verify_system_phase('system_web_verification', self.expected, b.time.monotonic() + 25)
        self.assertEqual(result, {'warning': '', 'http_status': 204})
        self.assertEqual(len(calls), 2)

    def test_cloudflare_trace_body_yields_exit_ip(self):
        trace = 'fl=1\nh=1.1.1.1\nip=' + self.expected + '\nts=1.0\nloc=US\n'
        with patch.object(b, 'run_probe', return_value=self.curl_result(body=trace)) as runner:
            self.assertEqual(b.verify_exit(), self.expected)
        self.assertIn(runner.call_args.args[0][-1], ('https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace'))

    def test_connection_path_checks_only_tun_exit_and_dns_takeover(self):
        resolved = []
        def probe(args, **kwargs):
            self.assertNotIn('--output', args, '连接关键路径不应等待 Google 网页检测')
            self.assertEqual(args[args.index('--proxy') + 1], '', '连接关键路径不应等待代理端口检测')
            return self.curl_result()
        with patch.object(b, 'run_probe', side_effect=probe), patch.object(b, 'resolve_system_dns', side_effect=lambda name: resolved.append(name) or {'198.18.3.4'}):
            actual, system = b.verify_connection(self.expected, deferred=True)
        self.assertEqual(actual, self.expected)
        self.assertEqual(system, {'ip': self.expected})
        self.assertEqual(len(resolved), 1)
        # 每次使用一次性随机子域，避免命中系统 DNS 缓存。
        self.assertRegex(resolved[0], r'^se-[0-9a-f]{16}\.google\.com$')

    def test_dns_answer_outside_fake_ip_range_fails_connection(self):
        with patch.object(b, 'run_probe', return_value=self.curl_result()), patch.object(b, 'resolve_system_dns', return_value={'142.250.1.1'}), patch.object(b.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, '未经过本应用的 TUN 解析'):
                b.verify_connection(self.expected, deferred=True)
        records = [json.loads(line) for line in (self.data / 'diagnostics.jsonl').read_text().splitlines()]
        dns = [record for record in records if record['phase'] == 'system_dns_verification']
        self.assertEqual({record['category'] for record in dns}, {'dns_bypass'})
        self.assertNotIn('142.250.1.1', (self.data / 'diagnostics.jsonl').read_text())

    def test_stuck_system_resolver_fails_within_budget(self):
        release = threading.Event()
        def stuck(name):
            release.wait(3)
            return {'198.18.0.9'}
        try:
            with patch.object(b, 'SYSTEM_DNS_SECONDS', 0.05), patch.object(b, 'resolve_system_dns', side_effect=stuck), patch.object(b.time, 'sleep'):
                started = b.time.perf_counter()
                with self.assertRaisesRegex(RuntimeError, '无法解析检测域名'):
                    b.verify_system_dns(b.time.monotonic() + 25)
                self.assertLess(b.time.perf_counter() - started, 1.0)
        finally:
            release.set()

    def test_dns_registration_lag_recovers_on_retry(self):
        answers = iter([None, {'198.18.0.7'}])
        def resolve(name):
            value = next(answers)
            if value is None:
                raise OSError('not yet')
            return value
        with patch.object(b, 'resolve_system_dns', side_effect=resolve), patch.object(b.time, 'sleep'):
            self.assertEqual(b.verify_system_dns(b.time.monotonic() + 25), {})

    def test_deferred_checks_run_proxy_and_google_in_parallel(self):
        b.put_json(self.data / 'settings.json', {**self.preferences, 'last_verified_ip': self.expected})
        barrier = threading.Barrier(2, timeout=3)
        def proxy():
            barrier.wait()
            return self.expected
        def web(phase, expected, deadline):
            self.assertEqual(phase, 'system_web_verification')
            barrier.wait()
            return {'warning': '', 'http_status': 204}
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', side_effect=proxy), patch.object(b, 'verify_system_phase', side_effect=web):
            result = b.deferred_checks()
        self.assertEqual(result, {'deferred_checks': {'status': 'ok', 'ip': self.expected, 'message': ''}})

    def test_deferred_proxy_mismatch_or_failure_is_reported_not_raised(self):
        b.put_json(self.data / 'settings.json', {**self.preferences, 'last_verified_ip': self.expected})
        web_ok = {'warning': '', 'http_status': 204}
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', return_value='198.51.100.99'), patch.object(b, 'verify_system_phase', return_value=web_ok):
            check = b.deferred_checks()['deferred_checks']
        self.assertEqual(check['status'], 'failure')
        self.assertIn('代理端口出口与已验证的静态 IP 不一致', check['message'])
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', side_effect=RuntimeError('公网出口验证失败：超时。')), patch.object(b, 'verify_system_phase', return_value={'warning': 'HTTP 429', 'http_status': 429}):
            check = b.deferred_checks()['deferred_checks']
        self.assertEqual(check['status'], 'failure')
        self.assertIn('代理端口 127.0.0.1:17896 检测失败', check['message'])
        self.assertIn('HTTP 429', check['message'])
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit', return_value=self.expected), patch.object(b, 'verify_system_phase', side_effect=RuntimeError('系统路径验证失败：超时。')):
            check = b.deferred_checks()['deferred_checks']
        self.assertEqual((check['status'], check['message']), ('failure', '系统路径验证失败：超时。'))

    def test_deferred_checks_skip_when_not_connected_or_unverified(self):
        with patch.object(b, 'service_status', return_value={'running': False, 'tun': False}), patch.object(b, 'verify_exit') as proxy:
            with self.assertRaisesRegex(RuntimeError, '未运行'):
                b.deferred_checks()
        with patch.object(b, 'service_status', return_value={'running': True, 'tun': True}), patch.object(b, 'verify_exit') as proxy:
            with self.assertRaisesRegex(RuntimeError, '缺少本次连接的实测出口'):
                b.deferred_checks()
        proxy.assert_not_called()

    def test_transaction_reply_requests_deferred_checks(self):
        state = {'running': False}
        def service(op, config=None):
            state['running'] = op == 'start'
            return {'ok': True, **state}
        with patch.object(b, 'validate_core'), patch.object(b, 'await_core'), patch.object(b, 'service_status', side_effect=lambda: dict(state)), patch.object(b, 'service', side_effect=service), patch.object(b, 'verify_connection', return_value=(self.expected, {'ip': self.expected})) as verify:
            result = b.transaction({}, self.preferences, self.expected)
        verify.assert_called_once_with(self.expected, deferred=True)
        self.assertIs(result['deferred_checks_pending'], True)
        self.assertEqual(result['ip'], self.expected)

    def test_cancel_without_running_deferred_check_returns_immediately(self):
        started = b.time.monotonic()
        self.assertFalse(b.cancel_deferred_checks())
        self.assertLess(b.time.monotonic() - started, 0.5)
        self.assertFalse((self.data / b.DEFERRED_CANCEL_FILE).exists())

    def test_network_operation_cancels_and_waits_for_running_deferred_check(self):
        # 模拟另一进程中的后台检测：持有检测锁，由取消标记通知后回收 curl 并释放锁。
        holding = threading.Event()
        released = threading.Event()
        def deferred_process():
            with open(self.data / b.DEFERRED_LOCK_FILE, 'a') as lock:
                b.fcntl.flock(lock, b.fcntl.LOCK_EX | b.fcntl.LOCK_NB)
                watcher = threading.Thread(target=b.watch_deferred_cancel, args=(b.time.time_ns(),), daemon=True)
                watcher.start()
                holding.set()
                self.assertTrue(b.CANCEL_PROBES.wait(3), '检测进程必须收到取消标记')
                watcher.join(1)
                released.set()
        holder = threading.Thread(target=deferred_process)
        holder.start()
        self.assertTrue(holding.wait(3))
        self.assertTrue(b.cancel_deferred_checks(timeout=3))
        # 只有旧检测退出、锁释放后才允许继续改变路由。
        self.assertTrue(released.is_set())
        holder.join(3)
        self.assertFalse((self.data / b.DEFERRED_CANCEL_FILE).exists())

    def test_stale_cancel_marker_does_not_cancel_new_check(self):
        (self.data / b.DEFERRED_CANCEL_FILE).touch()
        started = b.time.time_ns() + 1_000_000
        watcher = threading.Thread(target=b.watch_deferred_cancel, args=(started,), daemon=True)
        watcher.start()
        watcher.join(0.2)
        self.assertFalse(b.CANCEL_PROBES.is_set())
        b.CANCEL_PROBES.set()
        watcher.join(1)

    def test_superseded_probe_reaps_curl_and_writes_no_diagnostics(self):
        processes = []
        original_popen = b.subprocess.Popen
        def popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            b.CANCEL_PROBES.set()
            return process
        with patch.object(b.subprocess, 'Popen', side_effect=popen):
            with self.assertRaises(b.ProbeCancelled):
                b.run_probe([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=30, cancelled=threading.Event())
        self.assertIsNotNone(processes[0].returncode)
        b.record_verification(1, '1.1.1.1', 7, 0.01, 'failure', 'local_proxy')
        self.assertFalse((self.data / 'diagnostics.jsonl').exists())

    def test_main_cancels_deferred_checks_only_before_network_operations(self):
        for op, expected in (('start', 1), ('stop', 1), ('select_subscription', 1), ('status', 0), ('save', 0)):
            with self.subTest(op=op), patch.object(b, 'cancel_deferred_checks') as cancel, patch.object(b, 'dispatch', return_value={}), patch.object(b.sys, 'stdin', io.StringIO(json.dumps({'op': op}))), patch('builtins.print'):
                b.main()
            self.assertEqual(cancel.call_count, expected)

    def test_cancelled_deferred_process_reports_cancellation_not_failure(self):
        def dispatch(request):
            b.CANCEL_PROBES.set()
            return {'deferred_checks': {'status': 'failure', 'ip': self.expected, 'message': '旧路由失败'}}
        printed = []
        with patch.object(b, 'dispatch', side_effect=dispatch), patch.object(b.sys, 'stdin', io.StringIO(json.dumps({'op': 'deferred_checks'}))), patch('builtins.print', side_effect=printed.append):
            b.main()
        self.assertEqual(json.loads(printed[0]), {'ok': False, 'error': '连接后检测已被新的网络操作取消。'})

    def test_expired_ip_deadline_never_starts_requests(self):
        with patch.object(b.time, 'monotonic', return_value=100.0), patch.object(b, 'run_probe') as runner:
            with self.assertRaisesRegex(RuntimeError, '总时限'):
                b.verify_ip_race(100.0, 12.0, 4, 'exit_verification')
        runner.assert_not_called()

    def test_cancellable_probe_terminates_and_reaps_only_its_child(self):
        started = threading.Event()
        cancelled = threading.Event()
        processes = []
        original_popen = b.subprocess.Popen
        def popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            started.set()
            return process
        # 本地无网络子进程，验证真实 terminate/communicate 回收，而非只断言 mock 调用。
        with patch.object(b.subprocess, 'Popen', side_effect=popen):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(b.run_probe, [sys.executable, '-c', 'import time; time.sleep(30)'],
                                         timeout=30, cancelled=cancelled)
                try:
                    self.assertTrue(started.wait(3))
                finally:
                    cancelled.set()
                with self.assertRaises(b.ProbeCancelled):
                    result.result(timeout=3)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)

    def test_probe_timeout_also_reaps_its_child(self):
        processes = []
        original_popen = b.subprocess.Popen
        def popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(b.subprocess, 'Popen', side_effect=popen):
            with self.assertRaises(subprocess.TimeoutExpired):
                b.run_probe([sys.executable, '-c', 'import time; time.sleep(30)'],
                            timeout=0.05, cancelled=threading.Event())
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)

    def test_already_completed_probe_retains_certificate_result_during_cancel(self):
        cancelled = threading.Event()
        process = unittest.mock.Mock()
        process.poll.return_value = 60
        process.returncode = 60
        process.communicate.return_value = ('\n000', 'private certificate failure')
        def popen(*args, **kwargs):
            cancelled.set()
            return process
        with patch.object(b.subprocess, 'Popen', side_effect=popen):
            result = b.run_probe(['/usr/bin/curl', '-q'], timeout=1, cancelled=cancelled)
        self.assertEqual(result.returncode, 60)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
