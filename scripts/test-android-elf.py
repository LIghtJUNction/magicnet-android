#!/usr/bin/env python3
"""Regression coverage for executable ELF packaging checks."""

import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'scripts/android-elf.py'
SPEC = importlib.util.spec_from_file_location('android_elf', HELPER)
ELF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ELF)
PIE = (0x6FFFFFFB, 0x08000001)
END = (0, 0)


def fixture(kind=2, machine=183, entry=0x400180, interpreter=None, dynamic=None,
            load_flags=5):
    data = bytearray(1024)
    segments = [(1, load_flags, 0, 0x400000, 0, len(data), len(data), 4096)]
    if interpreter is not None:
        data[512:512 + len(interpreter)] = interpreter
        segments.append((3, 4, 512, 0x400200, 0, len(interpreter), len(interpreter), 1))
    if dynamic is not None:
        payload = b''.join(struct.pack('<qQ', *item) for item in dynamic)
        data[768:768 + len(payload)] = payload
        segments.append((2, 6, 768, 0x400300, 0, len(payload), len(payload), 8))
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, kind, machine, 1, entry, 64, 0, 0,
                     64, 56, len(segments), 0, 0, 0)
    for index, segment in enumerate(segments):
        struct.pack_into('<IIQQQQQQ', data, 64 + index * 56, *segment)
    return data


class AndroidElfTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'executable'

    def inspect(self, data):
        self.path.write_bytes(data)
        return ELF.elf_identity(self.path)

    def test_static_executable(self):
        self.assertEqual(self.inspect(fixture())['linkage'], 'static')

    def test_static_pie(self):
        self.assertEqual(self.inspect(fixture(kind=3, dynamic=[PIE, END]))['linkage'],
                         'static-pie')

    def test_android_linker64(self):
        data = fixture(kind=3, interpreter=b'/system/bin/linker64\x00',
                       dynamic=[(1, 1), END])
        self.assertEqual(self.inspect(data)['linkage'], 'android')

    def test_symlink_entry(self):
        self.path.write_bytes(fixture())
        link = self.path.with_name('cli')
        link.symlink_to(self.path.name)
        self.assertEqual(ELF.elf_identity(link)['linkage'], 'static')

    def test_wrong_abi_or_non_executable_type(self):
        for data in (fixture(machine=62), fixture(kind=1),
                     b'\x7fELF\x01' + bytes(100), b'not an ELF'):
            with self.subTest(header=data[:24]), self.assertRaises(ValueError):
                self.inspect(data)

    def test_shared_object_is_not_static_pie(self):
        for dynamic in (None, [END], [(0x6FFFFFFB, 1), END]):
            with self.subTest(dynamic=dynamic), self.assertRaisesRegex(ValueError, 'DF_1_PIE'):
                self.inspect(fixture(kind=3, dynamic=dynamic))

    def test_entry_must_point_to_executable_file_bytes(self):
        for data in (fixture(kind=3, entry=0, dynamic=[PIE, END]),
                     fixture(entry=0x500000), fixture(load_flags=4)):
            with self.subTest(header=data[:32]), self.assertRaisesRegex(ValueError, 'entry'):
                self.inspect(data)

    def test_non_android_dynamic_linker_is_rejected(self):
        for interpreter in (b'/lib/ld-linux-aarch64.so.1\x00', b'/system/bin/linker\x00',
                            b'/system/bin/linker64'):
            with self.subTest(interpreter=interpreter), self.assertRaisesRegex(ValueError, 'linker64'):
                self.inspect(fixture(kind=3, interpreter=interpreter, dynamic=[END]))

    def test_static_never_has_needed_dependencies(self):
        for kind in (2, 3):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'DT_NEEDED'):
                self.inspect(fixture(kind=kind, dynamic=[PIE, (1, 1), END]))

    def test_dynamic_table_must_terminate(self):
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            self.inspect(fixture(kind=3, dynamic=[PIE]))

    def test_dynamic_table_and_program_header_bounds(self):
        truncated = fixture(kind=3, dynamic=[PIE, END])[:790]
        bad_size = fixture(kind=3, dynamic=[PIE, END])
        struct.pack_into('<Q', bad_size, 64 + 56 + 32, 31)
        bad_headers = fixture()
        struct.pack_into('<Q', bad_headers, 32, 1000)
        for data in (truncated, bad_size, bad_headers):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.inspect(data)

    def test_duplicate_dynamic_segments_are_rejected(self):
        data = fixture(kind=3, dynamic=[PIE, END])
        data[176:232] = data[120:176]
        struct.pack_into('<H', data, 56, 3)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.inspect(data)

    def test_cli_reports_failure_without_running_input(self):
        self.path.write_bytes(fixture(kind=3, dynamic=[END]))
        result = subprocess.run([sys.executable, str(HELPER), str(self.path)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn('DF_1_PIE', result.stderr)
        self.path.write_bytes(fixture(kind=3, dynamic=[PIE, END]))
        result = subprocess.run([sys.executable, str(HELPER), str(self.path)],
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['linkage'], 'static-pie')


@unittest.skipUnless(os.environ.get('MAGICNET_TEST_ECAPTURE_ELF'),
                     'set MAGICNET_TEST_ECAPTURE_ELF to inspect the verified upstream binary')
class UpstreamEcaptureTests(unittest.TestCase):
    def test_verified_upstream_static_pie(self):
        identity = ELF.elf_identity(Path(os.environ['MAGICNET_TEST_ECAPTURE_ELF']))
        self.assertEqual(identity, {'machine': 'AArch64', 'linkage': 'static-pie',
                                    'interpreter': None})


if __name__ == '__main__':
    unittest.main()
