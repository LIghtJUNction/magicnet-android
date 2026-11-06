#!/usr/bin/env python3
"""Port #205's archive and bootstrap protections to the canonical #204 packager."""
import importlib.util
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packager', ROOT / 'scripts/package-components.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class ArchiveSafetyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'dist'
        self.output.mkdir()
        self.archive = self.output / 'MagicNet.zip'
        self.helper = self.root / 'helper'
        self.helper.write_bytes(b'bootstrap fixture, not executed')
        self.entries = {name: packager.zip_entry(name, data, 0o755) for name, data in {
            'module.prop': b'id=MagicNet\nversion=v1.4.8\nversionCode=148\n',
            'customize.sh': b'#!/bin/sh\nimport rich\n',
            '.config/sing-box/config.json': b'{}',
            'bin/magicnet-cli': b'cli-fixture',
            'bin/sing-box': b'core-fixture',
        }.items()}

    def write(self):
        packager.write_zip(self.archive, self.entries)

    def split(self):
        return packager.split(self.archive, self.helper, self.output, 'LIghtJUNction/MagicNet', 'arm64')

    def reject_without_output(self):
        original = self.archive.read_bytes()
        with self.assertRaises(ValueError):
            self.split()
        self.assertEqual(self.archive.read_bytes(), original)
        self.assertEqual({p.name for p in self.output.iterdir()}, {'MagicNet.zip'})

    def test_internal_leaf_links_survive_packaging(self):
        for name, target in (('cli', b'bin/magicnet-cli'), ('system/bin/sing-box', b'../../bin/sing-box')):
            self.entries[name] = packager.zip_entry(name, target, 0o777, symlink=True)
        self.write()
        self.split()
        for filename in ('MagicNet-core.zip', 'MagicNet-full.zip'):
            with zipfile.ZipFile(self.output / filename) as archive:
                self.assertTrue(stat.S_ISLNK(archive.getinfo('cli').external_attr >> 16))
                self.assertEqual(archive.read('system/bin/sing-box'), b'../../bin/sing-box')

    def test_escaping_absolute_and_malformed_links_are_rejected(self):
        for target in (b'/system/bin/sh', b'../../outside', b'../outside', b'bin\\outside',
                       b'', b'bin/file\x00', b'bin/file\n', b'\xff'):
            with self.subTest(target=target):
                self.entries['cli'] = packager.zip_entry('cli', target, 0o777, symlink=True)
                self.write()
                self.reject_without_output()

    def test_archive_cannot_write_through_internal_directory_link(self):
        self.entries['webroot'] = packager.zip_entry('webroot', b'bin', symlink=True)
        self.entries['webroot/unexpected'] = packager.zip_entry('webroot/unexpected', b'payload')
        self.write()
        self.reject_without_output()

    def test_parent_relative_link_cannot_escape_from_nested_path(self):
        self.entries['system/bin/escape'] = packager.zip_entry('system/bin/escape', b'../../../outside', symlink=True)
        self.write()
        self.reject_without_output()

    def test_total_size_is_checked_before_any_payload_read(self):
        self.write()
        with zipfile.ZipFile(self.archive) as archive:
            total = sum(info.file_size for info in archive.infolist())
        with patch.object(packager, 'MAX_UNCOMPRESSED', total - 1), \
                patch.object(zipfile.ZipFile, 'read', side_effect=AssertionError('payload read before size check')):
            self.reject_without_output()

    def test_single_compressed_member_is_limited(self):
        self.entries['oversized'] = packager.zip_entry('oversized', b'x' * 65536)
        self.write()
        self.assertLess(self.archive.stat().st_size, 4096)
        with patch.object(packager, 'MAX_UNCOMPRESSED', 32768):
            self.reject_without_output()

    def test_removed_build_archive_links_never_reach_runtime(self):
        name = '.state/cache.archive'
        self.entries[name] = packager.zip_entry(name, b'/tmp/build-cache', symlink=True)
        self.write()
        self.split()
        with zipfile.ZipFile(self.output / 'MagicNet-full.zip') as archive:
            self.assertNotIn(name, archive.namelist())

    def test_unsanitized_development_directories_are_rejected(self):
        for name in ('tests/test_module.py', '.config/sing-box/tests/test_rules.py',
                     'lib/kamfw/test/', 'webroot/__tests__/panel.js',
                     'webroot/fixtures/input.json', 'webroot/__fixtures__/input.json',
                     'webroot/__snapshots__/panel.snap', 'lib/bench/run.sh',
                     'lib/benches/run.sh', 'lib/benchmark/run.sh',
                     'lib/benchmarks/run.sh', 'coverage/index.html',
                     'htmlcov/index.html', 'webroot/node_modules/pkg/index.js'):
            with self.subTest(path=name):
                self.write()
                with zipfile.ZipFile(self.archive, 'a') as archive:
                    archive.writestr(name, b'fixture')
                self.reject_without_output()

    def test_runtime_test_names_survive_every_final_archive(self):
        runtime = {'bin/test': b'runtime command',
                   '.config/sing-box/rules/test.srs': b'runtime rules',
                   'lib/kamfw/test-support.sh': b'runtime helper',
                   'webroot/contest.js': b'runtime web asset'}
        self.entries.update({name: packager.zip_entry(name, data) for name, data in runtime.items()})
        self.write()
        manifest = self.split()
        with zipfile.ZipFile(self.output / 'MagicNet-full.zip') as archive:
            for name, data in runtime.items():
                self.assertEqual(archive.read(name), data)
        files = {item['path'] for component in manifest['components'] for item in component['files']}
        self.assertTrue({'bin/test', '.config/sing-box/rules/test.srs', 'webroot/contest.js'} <= files)
        for path in self.output.glob('*.zip'):
            with self.subTest(archive=path.name), zipfile.ZipFile(path) as archive:
                self.assertIsNone(archive.testzip())
                self.assertFalse(any(packager.DEVELOPMENT_DIRECTORY.search(name) for name in archive.namelist()))

    def test_write_zip_does_not_mutate_source_central_directory(self):
        self.write()
        with zipfile.ZipFile(self.archive) as source:
            entries = {info.filename: (info, source.read(info)) for info in source.infolist()}
            # Change the first member's length so reused offsets would be wrong.
            first = next(iter(entries))
            entries[first] = (entries[first][0], b'different' * 100)
            offsets = {info.filename: info.header_offset for info in source.infolist()}
            packager.write_zip(self.root / 'copy.zip', entries)
            self.assertIsNone(source.testzip())
            self.assertEqual(offsets, {info.filename: info.header_offset for info in source.infolist()})

    def test_declared_member_size_must_match_streamed_bytes(self):
        # CRC alone does not detect an overstated size. Cover component writing,
        # small metadata reads and the CLI-alias digest-only comparison path.
        self.entries['cli'] = packager.zip_entry('cli', b'cli-fixture', 0o755)
        for names in (('bin/sing-box',), ('module.prop',), ('cli',)):
            with self.subTest(names=names):
                # Equal declared lengths are necessary to reach alias hashing.
                self.entries['cli'] = packager.zip_entry('cli', b'cli' if names == ('cli',) else b'cli-fixture', 0o755)
                self.write()
                raw = bytearray(self.archive.read_bytes())
                with zipfile.ZipFile(self.archive) as source:
                    expected = {name: source.read(name) for name in names}
                    sizes = {name: source.getinfo('bin/magicnet-cli').file_size if name == 'cli'
                             else source.getinfo(name).file_size + 100 for name in names}
                    for name in names:
                        info = source.getinfo(name)
                        struct.pack_into('<I', raw, info.header_offset + 22, sizes[name])
                    offset = source.start_dir
                while raw[offset:offset + 4] == b'PK\x01\x02':
                    name_size, extra_size, comment_size = struct.unpack_from('<HHH', raw, offset + 28)
                    name = raw[offset + 46:offset + 46 + name_size].decode()
                    if name in names:
                        struct.pack_into('<I', raw, offset + 24, sizes[name])
                    offset += 46 + name_size + extra_size + comment_size
                self.archive.write_bytes(raw)
                with zipfile.ZipFile(self.archive) as source:
                    self.assertEqual({name: source.read(name) for name in names}, expected)
                self.reject_without_output()

    def test_bootstrap_rejects_symlinks_before_extracting(self):
        module = self.root / 'module'
        module.mkdir()
        protected = self.root / 'keep'
        protected.write_bytes(b'keep')
        (module / 'components.json').symlink_to(protected)
        code = 'abort() { exit 77; }; unzip() { touch "$MODPATH/extracted"; };\n' + packager.BOOTSTRAP
        result = subprocess.run(['sh', '-c', code], env={'PATH': '/usr/bin:/bin', 'MODPATH': str(module), 'ZIPFILE': str(self.archive)})
        self.assertEqual(result.returncode, 77)
        self.assertEqual(protected.read_bytes(), b'keep')
        self.assertFalse((module / 'extracted').exists())

    def test_directory_file_collision_is_rejected(self):
        self.write()
        with zipfile.ZipFile(self.archive, 'a') as archive:
            archive.writestr('bin/sing-box/', b'')
        self.reject_without_output()


if __name__ == '__main__':
    unittest.main()
