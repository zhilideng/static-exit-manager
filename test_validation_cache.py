"""配置校验缓存的离线回归检查；不启动内核或改动系统网络。"""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import backend as b


class ValidationCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.resources = self.root / 'resources'
        self.geodata = self.resources / 'geodata'
        self.geodata.mkdir(parents=True)
        self.core = self.resources / 'mihomo'
        self.core.write_bytes(b'test-core')
        (self.geodata / 'geosite.dat').write_bytes(b'test-geosite')
        (self.geodata / 'Country.mmdb').write_bytes(b'test-country')
        self.data = self.root / 'data'
        self.cache = self.data / b.VALIDATION_CACHE_FILE
        self.config = {'mode': 'rule', 'secret': 'private-controller-token',
                       'proxies': [{'name': '测试节点', 'type': 'socks5', 'server': 'relay.example',
                                    'port': 443, 'username': 'private-username', 'password': 'private-password'}],
                       'rules': ['GEOIP,CN,DIRECT', 'MATCH,测试节点']}
        self.paths = patch.multiple(b, DATA=self.data)
        self.paths.start()
        self.resource_patch = patch.object(b, 'resources', return_value=self.resources)
        self.resource_patch.start()
        self.runner_patch = patch.object(b, 'run', return_value='')
        self.runner = self.runner_patch.start()

    def tearDown(self):
        self.runner_patch.stop()
        self.resource_patch.stop()
        self.paths.stop()
        self.temporary.cleanup()

    def validate(self, config=None):
        return b.validate_core(self.config if config is None else config)

    def test_unchanged_configuration_reuses_success_with_canonical_key(self):
        self.assertIs(self.validate(), False)
        reordered = dict(reversed(list(self.config.items())))
        reordered['proxies'] = [dict(reversed(list(self.config['proxies'][0].items())))]
        self.assertIs(self.validate(reordered), True)
        self.assertEqual(self.runner.call_count, 1)

    def test_credentials_and_rules_invalidate_cached_success(self):
        self.validate()
        changed = copy.deepcopy(self.config)
        changed['proxies'][0]['password'] = 'replacement-password'
        self.validate(changed)
        changed['rules'] = ['MATCH,DIRECT']
        self.validate(changed)
        changed['secret'] = 'replacement-controller-token'
        self.validate(changed)
        self.assertEqual(self.runner.call_count, 4)

    def test_core_and_each_geodata_asset_invalidate_cached_success(self):
        self.validate()
        for path in (self.core, self.geodata / 'geosite.dat', self.geodata / 'Country.mmdb'):
            path.write_bytes(path.read_bytes() + b'-updated')
            self.validate()
        self.assertEqual(self.runner.call_count, 4)

    def test_inode_replacement_invalidates_even_with_original_size_and_mtime(self):
        self.validate()
        original = self.core.stat()
        replacement = self.resources / 'replacement'
        replacement.write_bytes(self.core.read_bytes())
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(self.core)
        self.validate()
        self.assertEqual(self.runner.call_count, 2)

    def test_ctime_invalidates_when_contents_change_and_mtime_is_restored(self):
        self.validate()
        original = self.core.stat()
        self.core.write_bytes(b'next-core')
        os.utime(self.core, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertNotEqual(self.core.stat().st_ctime_ns, original.st_ctime_ns)
        self.validate()
        self.assertEqual(self.runner.call_count, 2)

    def test_additional_geodata_files_are_included_recursively(self):
        self.validate()
        extra = self.geodata / 'regional' / 'extra.dat'
        extra.parent.mkdir()
        extra.write_bytes(b'extra-rules')
        self.validate()
        extra.write_bytes(b'updated-extra-rules')
        self.validate()
        self.assertEqual(self.runner.call_count, 3)

    def test_runtime_database_and_finder_metadata_do_not_invalidate(self):
        self.validate()
        for name in ('cache.db', 'cache.db-wal', 'cache.db-shm', 'cache.db-journal', '.DS_Store'):
            (self.geodata / name).write_bytes(b'runtime-state')
        self.validate()
        (self.geodata / 'cache.db').write_bytes(b'updated-runtime-state')
        self.validate()
        self.assertEqual(self.runner.call_count, 1)

    def test_missing_geodata_never_hits_or_creates_success_cache(self):
        self.validate()
        before = self.cache.read_bytes()
        (self.geodata / 'geosite.dat').unlink()
        self.validate()
        self.validate()
        self.assertEqual(self.runner.call_count, 3)
        self.assertEqual(self.cache.read_bytes(), before)

    def test_missing_core_still_raises_instead_of_reusing_cache(self):
        self.validate()
        self.core.unlink()
        with self.assertRaisesRegex(RuntimeError, '缺少独立内核'):
            self.validate()
        self.assertEqual(self.runner.call_count, 1)

    def test_corrupt_or_unrecognized_cache_is_revalidated(self):
        self.validate()
        original = json.loads(self.cache.read_text())
        invalid = ['not-json', '[]', json.dumps({**original, 'version': 999}),
                   json.dumps({**original, 'entries': [{'digest': 'bad', 'validated_at': b.now()}]}),
                   json.dumps({**original, 'entries': [{'digest': original['entries'][0]['digest'], 'validated_at': 'invalid'}]})]
        for content in invalid:
            self.cache.write_text(content)
            self.validate()
        self.assertEqual(self.runner.call_count, 1 + len(invalid))

    def test_failed_validation_is_not_cached(self):
        self.runner.side_effect = RuntimeError('测试校验失败')
        with self.assertRaisesRegex(ValueError, '内核配置校验失败'):
            self.validate()
        self.assertFalse(self.cache.exists())
        self.runner.side_effect = None
        self.validate()
        self.validate()
        self.assertEqual(self.runner.call_count, 2)

    def test_cache_write_failure_does_not_change_success(self):
        original_put_json = b.put_json

        def write_with_cache_failure(path, value):
            if Path(path) == self.cache:
                raise OSError('测试不可写')
            original_put_json(path, value)

        with patch.object(b, 'put_json', side_effect=write_with_cache_failure):
            self.validate()
        self.assertEqual(self.runner.call_count, 1)
        self.assertFalse(self.cache.exists())

    def test_cache_contains_only_version_digests_timestamps_and_is_private(self):
        self.validate()
        text = self.cache.read_text()
        value = json.loads(text)
        self.assertEqual(set(value), {'version', 'entries'})
        self.assertEqual(set(value['entries'][0]), {'digest', 'validated_at'})
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o600)
        for private in ('private-controller-token', 'private-username', 'private-password',
                        'relay.example', str(self.resources), '测试节点', 'GEOIP'):
            self.assertNotIn(private, text)

    def test_cache_keeps_at_most_sixteen_successful_configurations(self):
        for index in range(b.VALIDATION_CACHE_LIMIT + 1):
            self.validate({**self.config, 'secret': 'token-' + str(index)})
        entries = json.loads(self.cache.read_text())['entries']
        self.assertEqual(len(entries), 16)
        self.validate({**self.config, 'secret': 'token-16'})
        self.assertEqual(self.runner.call_count, 17)
        self.validate({**self.config, 'secret': 'token-0'})
        self.assertEqual(self.runner.call_count, 18)

    def test_assets_changed_during_validation_do_not_get_cached(self):
        def mutate_resources(*args, **kwargs):
            self.core.write_bytes(self.core.read_bytes() + b'-changed')
            return ''

        self.runner.side_effect = mutate_resources
        self.validate()
        self.assertFalse(self.cache.exists())

    def test_cache_version_change_requires_validation(self):
        self.validate()
        with patch.object(b, 'VALIDATION_CACHE_VERSION', b.VALIDATION_CACHE_VERSION + 1):
            self.validate()
        self.assertEqual(self.runner.call_count, 2)


if __name__ == '__main__':
    unittest.main()
