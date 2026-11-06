#!/usr/bin/env python3
"""Offline curl build/ZIP identity boundaries; synthetic ELF is never executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('curl_artifact', ROOT / 'scripts/android-curl-artifact.py')
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


def elf_fixture(abi='arm64-v8a', *, libraries=('libc.so', 'libm.so', 'libdl.so'), rpath=False):
    data = bytearray(1024)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 3, 183 if abi == 'arm64-v8a' else 62, 1)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 3)
    interpreter = b'/system/bin/linker64\x00'
    data[256:256 + len(interpreter)] = interpreter
    strings, offsets = b'\x00', []
    for library in libraries:
        offsets.append(len(strings))
        strings += library.encode() + b'\x00'
    data[320:320 + len(strings)] = strings
    tags = [(1, offset) for offset in offsets] + [(5, 320), (10, len(strings))]
    if rpath:
        tags += [(29, 1)]
    tags += [(0, 0)]
    for index, (tag, value) in enumerate(tags):
        struct.pack_into('<qQ', data, 512 + index * 16, tag, value)
    for index, (kind, offset, length) in enumerate(((1, 0, len(data)), (3, 256, len(interpreter)),
                                                   (2, 512, len(tags) * 16))):
        struct.pack_into('<IIQQQQQQ', data, 64 + index * 56, kind, 5, offset, offset, offset,
                         length, length, 8)
    return bytes(data)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'curl'
        self.binary.write_bytes(elf_fixture())
        self.binary.chmod(0o755)
        self.licenses = self.root / 'licenses'
        self.licenses.mkdir()
        for name in ARTIFACT.LICENSE_FILES:
            (self.licenses / name).write_text('Synthetic notice for parser regression only.\n')
        inputs = ARTIFACT.lock()
        self.metadata = {
            'schema': 1, 'scope': ARTIFACT.SCOPE, 'status': 'built',
            'target': {'os': 'android', 'abi': 'arm64-v8a', 'api': 21}, 'versions': inputs['versions'],
            'sources': {name: {key: value[key] for key in ('url', 'sha256')}
                        for name, value in inputs['sources'].items()},
            'ca': ARTIFACT.ca_identity(inputs),
            'builder_sha256': ARTIFACT.digest(ARTIFACT.BUILDER_PATH),
            'verifier_sha256': ARTIFACT.digest(Path(ARTIFACT.__file__)),
            'lock_sha256': ARTIFACT.digest(ARTIFACT.LOCK_PATH),
            'curl_sha256': ARTIFACT.digest(self.binary), 'curl_bytes': self.binary.stat().st_size,
            'elf': ARTIFACT.elf_identity(self.binary, 'arm64-v8a'),
            'toolchain': {'ndk_revision': '29.0.14206865',
                          'ndk_source_properties_sha256': 'a' * 64, 'compiler': 'fixture clang'},
            'licenses': {name: {'sha256': ARTIFACT.digest(self.licenses / name),
                                'bytes': (self.licenses / name).stat().st_size}
                         for name in ARTIFACT.LICENSE_FILES},
            'runtime_capability': 'not_tested',
        }

    def verify(self, metadata=None):
        return ARTIFACT.verify(self.binary, metadata or self.metadata, self.licenses, 'arm64-v8a')

    def archive(self, *, missing=None, bad_mode=None):
        path = self.root / 'module.zip'
        payloads = {'bin/curl': self.binary.read_bytes(),
                    ARTIFACT.PROVENANCE: json.dumps(self.metadata).encode(),
                    **{f'licenses/curl/{name}': (self.licenses / name).read_bytes()
                       for name in ARTIFACT.LICENSE_FILES}}
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in payloads.items():
                if name == missing:
                    continue
                info = zipfile.ZipInfo(name)
                mode = 0o755 if name == 'bin/curl' else 0o644
                info.external_attr = (stat.S_IFREG | (0o644 if name == bad_mode else mode)) << 16
                archive.writestr(info, content)
        return path

    def test_both_abi_program_headers_are_inspected_without_execution(self):
        self.verify()
        self.binary.write_bytes(elf_fixture('x86_64'))
        ARTIFACT.elf_identity(self.binary, 'x86_64')
        with self.assertRaisesRegex(ValueError, 'ABI/PIE'):
            ARTIFACT.elf_identity(self.binary, 'arm64-v8a')

    def test_unbundled_libraries_and_rpath_are_rejected(self):
        for options in ({'libraries': ('libc.so', 'libssl.so')}, {'rpath': True}):
            with self.subTest(options=options):
                self.binary.write_bytes(elf_fixture(**options))
                with self.assertRaises(ValueError):
                    ARTIFACT.elf_identity(self.binary, 'arm64-v8a')

    def test_truncated_headers_and_symlinks_are_rejected(self):
        self.binary.write_bytes(b'\x7fELF')
        with self.assertRaises(ValueError):
            self.verify()
        self.binary.unlink()
        self.binary.symlink_to('/bin/true')
        with self.assertRaises(ValueError):
            ARTIFACT.elf_identity(self.binary, 'arm64-v8a')

    def test_source_ca_builder_toolchain_and_runtime_claim_are_checked(self):
        mutations = (
            ('ca', 'sha256', 'b' * 64), ('ca', 'runtime_bundle', True),
            ('ca', 'runtime_bundle', 0), ('ca', 'cert_count', True),
            ('elf', 'rpath', 0), ('target', 'api', 21.0),
            ('target', 'api', 35), ('toolchain', 'ndk_source_properties_sha256', 'unknown'),
        )
        for group, key, value in mutations:
            changed = copy.deepcopy(self.metadata)
            changed[group][key] = value
            with self.subTest(group=group, key=key), self.assertRaises(ValueError):
                self.verify(changed)
        for key, value in (('schema', True), ('builder_sha256', 'b' * 64), ('lock_sha256', 'b' * 64),
                           ('runtime_capability', 'passed'), ('curl_sha256', 'b' * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(self.metadata | {key: value})

    def test_license_bytes_are_verified(self):
        (self.licenses / ARTIFACT.LICENSE_FILES[0]).write_text('Changed license notice.\n')
        with self.assertRaisesRegex(ValueError, 'license identity'):
            self.verify()

    def test_zip_payload_is_complete_and_executable(self):
        ARTIFACT.verify_zip(self.archive(), 'arm64-v8a')
        for name in ARTIFACT.PAYLOAD_FILES:
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, 'missing/duplicate'):
                ARTIFACT.verify_zip(self.archive(missing=name), 'arm64-v8a')
        with self.assertRaisesRegex(ValueError, 'permissions'):
            ARTIFACT.verify_zip(self.archive(bad_mode='bin/curl'), 'arm64-v8a')

    def test_kam_blanket_executable_modes_are_normalized_once(self):
        path = self.archive()
        with zipfile.ZipFile(path) as archive:
            entries = [(copy.copy(info), archive.read(info)) for info in archive.infolist()]
        with zipfile.ZipFile(path, 'w') as archive:
            for info, content in entries:
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, content)
            unrelated = zipfile.ZipInfo('lib/unrelated-file')
            unrelated.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(unrelated, b'unrelated payload bytes')
        with zipfile.ZipFile(path) as archive:
            before = {info.filename: (archive.read(info), info.CRC, info.external_attr, info.date_time,
                                      info.extra, info.comment) for info in archive.infolist()}
        with self.assertRaisesRegex(ValueError, 'permissions'):
            ARTIFACT.verify_zip(path, 'arm64-v8a')
        self.assertEqual(set(ARTIFACT.normalize_modes(path)), set(ARTIFACT.PAYLOAD_FILES) - {'bin/curl'})
        ARTIFACT.verify_zip(path, 'arm64-v8a')
        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            for info in archive.infolist():
                data, crc, mode, stamp, extra, comment = before[info.filename]
                self.assertEqual((archive.read(info), info.CRC, info.date_time, info.extra, info.comment),
                                 (data, crc, stamp, extra, comment))
                if info.filename not in ARTIFACT.PAYLOAD_FILES:
                    self.assertEqual(info.external_attr, mode)
        normalized = path.read_bytes()
        self.assertEqual(ARTIFACT.normalize_modes(path), [])
        self.assertEqual(path.read_bytes(), normalized)

    def test_normalization_never_turns_missing_duplicate_or_symlink_into_payload(self):
        for kind in ('missing', 'duplicate', 'symlink'):
            with self.subTest(kind=kind):
                path = self.archive(missing='bin/curl' if kind == 'missing' else None)
                if kind != 'missing':
                    with zipfile.ZipFile(path) as archive:
                        entries = [(copy.copy(info), archive.read(info)) for info in archive.infolist()]
                    with zipfile.ZipFile(path, 'w') as archive:
                        for info, content in entries:
                            if kind == 'symlink' and info.filename == 'bin/curl':
                                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                                content = b'/system/bin/curl'
                            archive.writestr(info, content)
                        if kind == 'duplicate':
                            import warnings
                            with warnings.catch_warnings():
                                warnings.simplefilter('ignore', UserWarning)
                                archive.writestr('bin/curl', b'duplicate')
                original = path.read_bytes()
                with self.assertRaises(ValueError):
                    ARTIFACT.normalize_modes(path)
                self.assertEqual(path.read_bytes(), original)

    def test_builder_rejects_unknown_abi_before_network_or_compilation(self):
        result = subprocess.run(['bash', str(ARTIFACT.BUILDER_PATH), 'riscv64', str(self.root / 'out')],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported Android curl ABI', result.stderr)
        self.assertFalse((self.root / 'out').exists())

    def test_host_install_extraction_replaces_target_elf_without_executing_it(self):
        archive = self.archive()
        destination = self.root / 'host-module'
        destination.mkdir()
        stub = ROOT / 'scripts/fixtures/host-install-curl.sh'
        subprocess.run(['sh', str(ROOT / 'scripts/host-install-unzip.sh'), '-oq', str(archive),
                        '-d', str(destination)], check=True, capture_output=True, timeout=5,
                       env=dict(os.environ, MAGICNET_TEST_HOST_UNZIP=shutil.which('unzip'),
                                MAGICNET_TEST_HOST_CP=shutil.which('cp'), MAGICNET_TEST_HOST_CURL=str(stub)))
        self.assertEqual((destination / 'bin/curl').read_bytes(), stub.read_bytes())
        result = subprocess.run([str(destination / 'bin/curl'), '--version'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 127)
        self.assertIn('offline host installer fixture', result.stderr)

    def test_corrupt_source_cache_stops_before_compiler_or_download(self):
        ndk = self.root / 'ndk'
        tools = ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin'
        tools.mkdir(parents=True)
        (ndk / 'source.properties').write_text('Pkg.Revision = 29.0.14206865\n')
        for name in ('aarch64-linux-android21-clang', 'llvm-ar', 'llvm-ranlib', 'llvm-nm', 'llvm-strip'):
            tool = tools / name
            tool.write_text('#!/bin/sh\nprintf compiler-must-not-run >&2\nexit 99\n')
            tool.chmod(0o755)
        cache = self.root / 'cache'
        cache.mkdir()
        (cache / ARTIFACT.lock()['sources']['curl']['file']).write_bytes(b'corrupt cached source')
        result = subprocess.run(['bash', str(ARTIFACT.BUILDER_PATH), 'arm64', str(self.root / 'out')],
                                env=dict(os.environ, ANDROID_NDK_HOME=str(ndk),
                                         MAGICNET_CURL_SOURCE_CACHE=str(cache), MAGICNET_CURL_NDK_SHA256=''),
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FAILED', result.stdout)
        self.assertNotIn('compiler-must-not-run', result.stderr)
        self.assertFalse((self.root / 'out/curl').exists())


if __name__ == '__main__':
    unittest.main()
