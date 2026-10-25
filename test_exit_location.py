import contextlib
import datetime
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import backend as b


class ExitLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.library = Path(self.temp.name)
        self.data = self.library / 'standalone'
        self.data.mkdir()
        self.paths = patch.multiple(b, LIBRARY=self.library, DATA=self.data)
        self.paths.start()
        self.address = '9.9.9.9'

    def tearDown(self):
        self.paths.stop()
        self.temp.cleanup()

    def location(self, days=0):
        fetched = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        return {**b.empty_exit_location(self.address), 'status': 'ok', 'country': '美国',
                'country_code': 'US', 'region': '俄勒冈州', 'city': '波特兰',
                'fetched_at': fetched.isoformat()}

    def cache(self, days=0, attempted=None):
        b.put_json(self.data / b.EXIT_LOCATION_CACHE_FILE, {'version': 1, 'entries': {
            self.address: {'location': self.location(days),
                           'attempted_at': attempted if attempted is not None else time.time() - 3600}}})

    def test_success_is_cached_privately_and_does_not_requery(self):
        with patch.object(b, 'fetch_exit_location', side_effect=lambda _: self.location()) as fetch:
            first = b.dispatch({'op': 'exit_location', 'ip': self.address})
            second = b.dispatch({'op': 'exit_location', 'ip': self.address})
        fetch.assert_called_once_with(self.address)
        self.assertEqual(first, second)
        self.assertEqual(first['location']['city'], '波特兰')
        self.assertEqual(os.stat(self.data / b.EXIT_LOCATION_CACHE_FILE).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.data / 'exit-location.lock').st_mode & 0o777, 0o600)

    def test_global_ip_validation_precedes_network(self):
        with patch.object(b, 'fetch_exit_location') as fetch:
            for address in (None, [], '10.0.0.1', '127.0.0.1', '::1', 'fe80::1%en0',
                            '224.0.0.1', '192.0.2.1', 'https://evil.example/', '8.8.8.8/32'):
                with self.subTest(address=address), self.assertRaises(ValueError):
                    b.exit_location(address)
        fetch.assert_not_called()
        self.assertEqual(b.public_location_ip(' 2606:4700:4700:0:0:0:0:1111 '), '2606:4700:4700::1111')

    def test_failed_query_keeps_old_location_for_thirty_days_and_retries_later(self):
        self.cache(days=8)
        with patch.object(b, 'fetch_exit_location', side_effect=ValueError('raw response secret')) as fetch:
            first = b.exit_location(self.address)
            second = b.exit_location(self.address)
        fetch.assert_called_once()
        self.assertEqual(first['location']['status'], 'stale')
        self.assertEqual(first['location']['city'], '波特兰')
        self.assertEqual(first, second)
        self.assertNotIn('raw response', json.dumps(first))
        self.cache(days=31)
        with patch.object(b, 'fetch_exit_location', side_effect=ValueError):
            result = b.exit_location(self.address)['location']
        self.assertEqual(result, b.empty_exit_location(self.address))

    def test_failure_without_cache_is_throttled_and_has_full_contract(self):
        with patch.object(b, 'fetch_exit_location', side_effect=subprocess.TimeoutExpired('curl', 6)) as fetch:
            first = b.exit_location(self.address)
            second = b.exit_location(self.address)
        fetch.assert_called_once()
        self.assertEqual(first, {'location': b.empty_exit_location(self.address)})
        self.assertEqual(first, second)
        self.assertTrue(all(isinstance(value, str) for value in first['location'].values()))

    def test_old_cache_success_refreshes_and_invalid_cache_is_ignored(self):
        self.cache(days=8)
        with patch.object(b, 'fetch_exit_location', side_effect=lambda _: self.location()) as fetch:
            self.assertEqual(b.exit_location(self.address)['location']['status'], 'ok')
        fetch.assert_called_once()
        for malformed in ('null', '[]', '{bad json', '{"version":1,"entries":[]}'):
            (self.data / b.EXIT_LOCATION_CACHE_FILE).write_text(malformed)
            with patch.object(b, 'fetch_exit_location', side_effect=lambda _: self.location()):
                self.assertEqual(b.exit_location(self.address)['location']['status'], 'ok')

    def test_location_lock_is_nonblocking(self):
        with (self.data / 'exit-location.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(b, 'fetch_exit_location') as fetch:
                self.assertEqual(b.exit_location(self.address)['location']['status'], 'unavailable')
            fetch.assert_not_called()

    def test_main_location_request_bypasses_busy_connection_lock(self):
        with (self.library / 'operation.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stream = io.StringIO()
            with patch.object(b.sys, 'stdin', io.StringIO(json.dumps({'op': 'exit_location', 'ip': self.address}))), \
                    patch.object(b, 'fetch_exit_location', side_effect=lambda _: self.location()), \
                    contextlib.redirect_stdout(stream):
                b.main()
        self.assertTrue(json.loads(stream.getvalue())['ok'])
        self.assertEqual(json.loads(stream.getvalue())['location']['status'], 'ok')

    def test_busy_location_lock_does_not_block_connection_operation(self):
        with (self.data / 'exit-location.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stream = io.StringIO()
            with patch.object(b.sys, 'stdin', io.StringIO('{"op":"start"}')), \
                    patch.object(b, 'dispatch', return_value={'message': 'started'}) as dispatch, \
                    contextlib.redirect_stdout(stream):
                b.main()
        dispatch.assert_called_once_with({'op': 'start'})
        self.assertTrue(json.loads(stream.getvalue())['ok'])

    def test_fixed_https_request_is_bounded_and_has_no_proxy_credentials(self):
        response = {**self.location(), 'success': True}
        with patch.object(b.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b'')) as run:
            result = b.fetch_exit_location(self.address)
        command = run.call_args.args[0]
        self.assertEqual(command[-1], 'https://ipwho.is/9.9.9.9?lang=zh-CN&fields=success,ip,country,country_code,region,city')
        self.assertEqual(run.call_args.kwargs['timeout'], 6)
        self.assertEqual(command[command.index('--max-filesize') + 1], '16384')
        self.assertEqual(command[command.index('--proxy') + 1], '')
        self.assertIn('-q', command)
        self.assertNotIn('-k', command)
        self.assertNotIn('-L', command)
        self.assertEqual(result['city'], '波特兰')

    def test_response_validation_rejects_wrong_ip_controls_and_oversize(self):
        valid = {**self.location(), 'success': True}
        values = [{**valid, 'ip': '8.8.8.8'}, {**valid, 'success': False},
                  {**valid, 'city': 'Los\nAngeles'}, {**valid, 'country': 'a' * 101},
                  {**valid, 'country_code': 'USA'}, {**valid, 'city': []},
                  {**valid, 'country': '', 'region': '', 'city': ''}, []]
        for value in values:
            with self.subTest(value=value), patch.object(b.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b'')):
                with self.assertRaises(ValueError):
                    b.fetch_exit_location(self.address)
        with patch.object(b.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b' ' * 16385, b'')):
            with self.assertRaises(ValueError):
                b.fetch_exit_location(self.address)

    def test_mismatched_response_is_not_saved_as_verified_location(self):
        response = {**self.location(), 'success': True, 'ip': '8.8.8.8'}
        with patch.object(b.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 0, json.dumps(response).encode(), b'')):
            result = b.exit_location(self.address)
        self.assertEqual(result['location'], b.empty_exit_location(self.address))
        cached = b.read_exit_locations()[self.address]['location']
        self.assertEqual(cached, b.empty_exit_location(self.address))
        self.assertNotIn('8.8.8.8', (self.data / b.EXIT_LOCATION_CACHE_FILE).read_text())

    def test_cache_eviction_limits_count_and_only_keeps_contract_fields(self):
        entries = {}
        for index in range(64):
            address = '8.8.8.' + str(index + 1)
            location = {**self.location(), 'ip': address, 'extra': 'do not retain'}
            entries[address] = {'location': location, 'attempted_at': time.time() - 1000 + index,
                                'secret': 'do not retain'}
        b.put_json(self.data / b.EXIT_LOCATION_CACHE_FILE, {'version': 1, 'entries': entries})
        with patch.object(b, 'fetch_exit_location', side_effect=lambda _: self.location()):
            b.exit_location(self.address)
        raw = (self.data / b.EXIT_LOCATION_CACHE_FILE).read_text()
        records = json.loads(raw)['entries']
        self.assertEqual(len(records), 64)
        self.assertNotIn('8.8.8.1', records)
        self.assertIn(self.address, records)
        self.assertNotIn('do not retain', raw)


if __name__ == '__main__':
    unittest.main()
