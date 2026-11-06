#!/usr/bin/env python3
"""Record and verify the production curl payload without executing target ELF."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / 'scripts/android-curl-lock.json'
BUILDER_PATH = ROOT / 'scripts/build-android-curl.sh'
SCOPE = 'production-android-curl'
LICENSE_FILES = ('curl-COPYING.txt', 'OpenSSL-LICENSE.txt', 'zlib-README.txt', 'Mozilla-CA-NOTICE.txt')
PROVENANCE = 'licenses/curl/build-provenance.json'
PAYLOAD_FILES = ('bin/curl', PROVENANCE, *(f'licenses/curl/{name}' for name in LICENSE_FILES))


def require(value, message):
    if not value:
        raise ValueError(message)


def exact_json(actual, expected):
    """JSON booleans are not integers (Python's ordinary equality conflates them)."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_json(actual[key], value)
                                                       for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact_json(a, b) for a, b in zip(actual, expected))
    return actual == expected


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def lock():
    value = json.loads(LOCK_PATH.read_text())
    require(exact_json(value.get('schema'), 1) and exact_json(value.get('api'), 21), 'unsupported curl lock')
    require(set(value['sources']) == {'curl', 'openssl', 'zlib', 'ca'}, 'incomplete curl sources')
    for source in value['sources'].values():
        require(re.fullmatch(r'[0-9a-f]{64}', source['sha256'])
                and source['url'].startswith('https://')
                and re.fullmatch(r'[A-Za-z0-9_.-]+', source['file']), 'invalid curl source lock')
    return value


def elf_identity(path, abi):
    """Parse ELF64 program headers/dynamic strings; never invoke the binary."""
    require(abi in ('arm64-v8a', 'x86_64'), 'unsupported curl ABI')
    require(stat.S_ISREG(path.lstat().st_mode) and os.access(path, os.X_OK)
            and 64 <= path.stat().st_size <= 32 * 1024 * 1024, 'invalid curl executable')
    data = path.read_bytes()
    machine = 183 if abi == 'arm64-v8a' else 62
    require(data[:7] == b'\x7fELF\x02\x01\x01'
            and struct.unpack_from('<HH', data, 16) == (3, machine), 'curl ELF ABI/PIE mismatch')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    require(size == 56 and 1 <= count <= 256 and offset >= 64
            and offset + size * count <= len(data), 'invalid curl program headers')
    loads, interpreters, dynamics = [], [], []
    for index in range(count):
        kind, _, start, address, _, length, memory, _ = struct.unpack_from(
            '<IIQQQQQQ', data, offset + index * size)
        require(start + length <= len(data) and length <= memory, 'invalid curl segment')
        if kind == 1:
            loads.append((address, start, length))
        elif kind == 3:
            require(1 <= length <= 128, 'invalid curl interpreter')
            interpreters.append(data[start:start + length])
        elif kind == 2:
            require(length % 16 == 0 and length <= 65536, 'invalid curl dynamic segment')
            dynamics.append(data[start:start + length])
    require(interpreters == [b'/system/bin/linker64\x00'] and len(dynamics) == 1,
            'curl must use Android linker64 and one dynamic segment')
    tags, terminated = {}, False
    for index in range(0, len(dynamics[0]), 16):
        tag, value = struct.unpack_from('<qQ', dynamics[0], index)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    require(terminated and 15 not in tags and 29 not in tags
            and len(tags.get(5, [])) == len(tags.get(10, [])) == 1,
            'invalid curl dynamic strings or RPATH')
    address, length = tags[5][0], tags[10][0]
    require(1 <= length <= 1024 * 1024, 'invalid curl string table')
    positions = [start + address - base for base, start, length_in_file in loads
                 if base <= address and address + length <= base + length_in_file]
    require(len(positions) == 1, 'unmapped curl string table')
    strings = data[positions[0]:positions[0] + length]
    needed = []
    for offset in tags.get(1, []):
        require(offset < len(strings), 'invalid curl dependency')
        end = strings.find(b'\x00', offset)
        require(end != -1 and end - offset <= 128, 'invalid curl dependency')
        needed.append(strings[offset:end].decode('ascii'))
    require('libc.so' in needed and len(needed) == len(set(needed))
            and set(needed) <= {'libc.so', 'libm.so', 'libdl.so'},
            'curl requires an unbundled TLS/compression or non-Bionic library')
    return {'interpreter': '/system/bin/linker64', 'needed': sorted(needed), 'rpath': False}


def ca_identity(inputs):
    return {'mode': 'embedded', 'version': inputs['ca']['version'],
            'sha256': inputs['sources']['ca']['sha256'],
            'bytes': inputs['ca']['bytes'], 'cert_count': inputs['ca']['cert_count'],
            'runtime_bundle': False, 'system_store': False}


def verify(binary, metadata, licenses, abi, expected_ndk=None):
    inputs = lock()
    require(isinstance(metadata, dict) and exact_json(metadata.get('schema'), 1)
            and metadata.get('scope') == SCOPE and metadata.get('status') == 'built'
            and exact_json(metadata.get('target'), {'os': 'android', 'abi': abi, 'api': inputs['api']})
            and exact_json(metadata.get('versions'), inputs['versions']), 'curl build identity mismatch')
    sources = {name: {key: source[key] for key in ('url', 'sha256')}
               for name, source in inputs['sources'].items()}
    require(exact_json(metadata.get('sources'), sources) and exact_json(metadata.get('ca'), ca_identity(inputs)),
            'curl source or embedded CA identity mismatch')
    require(metadata.get('builder_sha256') == digest(BUILDER_PATH)
            and metadata.get('verifier_sha256') == digest(Path(__file__))
            and metadata.get('lock_sha256') == digest(LOCK_PATH), 'curl build inputs changed')
    require(exact_json(metadata.get('curl_bytes'), binary.stat().st_size)
            and metadata.get('curl_sha256') == digest(binary)
            and exact_json(metadata.get('elf'), elf_identity(binary, abi)), 'curl payload identity mismatch')
    require(metadata.get('runtime_capability') == 'not_tested', 'build cannot attest Android runtime success')
    toolchain = metadata.get('toolchain', {})
    require(isinstance(toolchain, dict)
            and isinstance(toolchain.get('ndk_revision'), str)
            and re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', toolchain['ndk_revision'])
            and isinstance(toolchain.get('ndk_source_properties_sha256'), str)
            and re.fullmatch(r'[0-9a-f]{64}', toolchain['ndk_source_properties_sha256'])
            and isinstance(toolchain.get('compiler'), str) and 0 < len(toolchain['compiler']) <= 512,
            'curl toolchain identity missing')
    if expected_ndk is not None:
        require(toolchain['ndk_source_properties_sha256'] == expected_ndk, 'curl NDK identity mismatch')
    records = metadata.get('licenses', {})
    require(set(records) == set(LICENSE_FILES), 'curl licenses missing')
    for name in LICENSE_FILES:
        path = licenses / name
        require(stat.S_ISREG(path.lstat().st_mode) and 16 <= path.stat().st_size <= 256 * 1024
                and exact_json(records[name], {'sha256': digest(path), 'bytes': path.stat().st_size}),
                'curl license identity mismatch: ' + name)
    return metadata


def record(args):
    inputs = lock()
    folder, source, ndk, compiler = map(Path, (args.folder, args.source, args.ndk, args.compiler))
    binary, ca = folder / 'curl', folder / 'cacert.pem'
    require(digest(ca) == inputs['sources']['ca']['sha256']
            and ca.stat().st_size == inputs['ca']['bytes']
            and ca.read_bytes().count(b'-----BEGIN CERTIFICATE-----') == inputs['ca']['cert_count'],
            'embedded CA source mismatch')
    # Preserve upstream notices from the exact verified source archives.
    licenses = folder / 'licenses'
    licenses.mkdir()
    versions = inputs['versions']
    for name, original in {
        'curl-COPYING.txt': source / f"curl-{versions['curl']}/COPYING",
        'OpenSSL-LICENSE.txt': source / f"openssl-{versions['openssl']}/LICENSE.txt",
        'zlib-README.txt': source / f"zlib-{versions['zlib']}/README",
    }.items():
        (licenses / name).write_bytes(original.read_bytes())
    notice = ('Mozilla CA certificate data snapshot ' + inputs['ca']['version'] + '\n'
              'Licensed under Mozilla Public License 2.0: https://mozilla.org/MPL/2.0/\n'
              'Complete corresponding certificate data: ' + inputs['sources']['ca']['url'] + '\n'
              'SHA256: ' + inputs['sources']['ca']['sha256'] + '\n'
              'The unchanged bundle is embedded in curl; curl --dump-ca-embed reproduces it.\n\n')
    # Retain the original bundle's license and generation notices verbatim.
    notice += ca.read_text().split('-----BEGIN CERTIFICATE-----', 1)[0]
    (licenses / 'Mozilla-CA-NOTICE.txt').write_text(notice)
    revision = re.search(r'^Pkg.Revision\s*=\s*([^\r\n]+)', ndk.read_text(), re.M)
    require(revision, 'NDK revision missing')
    version = subprocess.run([str(compiler), '--version'], check=True, capture_output=True,
                             text=True, timeout=10).stdout.splitlines()[0]
    metadata = {'schema': 1, 'scope': SCOPE, 'status': 'built',
                'target': {'os': 'android', 'abi': args.abi, 'api': inputs['api']},
                'versions': versions,
                'sources': {name: {key: value[key] for key in ('url', 'sha256')}
                            for name, value in inputs['sources'].items()},
                'ca': ca_identity(inputs),
                'toolchain': {'ndk_revision': revision.group(1).strip(),
                              'ndk_source_properties_sha256': digest(ndk), 'compiler': version},
                'elf': elf_identity(binary, args.abi),
                'builder_sha256': digest(BUILDER_PATH), 'verifier_sha256': digest(Path(__file__)),
                'lock_sha256': digest(LOCK_PATH),
                'curl_sha256': digest(binary), 'curl_bytes': binary.stat().st_size,
                'licenses': {name: {'sha256': digest(licenses / name),
                                    'bytes': (licenses / name).stat().st_size} for name in LICENSE_FILES},
                'runtime_capability': 'not_tested'}
    verify(binary, metadata, licenses, args.abi)
    (folder / 'build-provenance.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')


def verify_zip(path, abi):
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory() as temporary:
        entries = archive.namelist()
        root = Path(temporary)
        for name in PAYLOAD_FILES:
            require(entries.count(name) == 1, 'missing/duplicate curl payload: ' + name)
            info = archive.getinfo(name)
            mode = info.external_attr >> 16
            require(stat.S_ISREG(mode) and info.file_size <= (32 * 1024 * 1024 if name == 'bin/curl' else 256 * 1024),
                    'invalid curl archive member: ' + name)
            expected_mode = 0o755 if name == 'bin/curl' else 0o644
            require(stat.S_IMODE(mode) == expected_mode, 'invalid curl payload permissions: ' + name)
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(info))
            destination.chmod(expected_mode)
        metadata = json.loads((root / PROVENANCE).read_text())
        verify(root / 'bin/curl', metadata, root / 'licenses/curl', abi)
        return metadata


def normalize_modes(path):
    """Fix KAM's blanket 0755 export only for the six owned curl files.

    Use zipfile's reader/writer rather than a second ZIP parser. A temporary
    archive keeps the original intact on CRC/read/write failure. Retained file
    bytes, timestamps, comments, extra fields and unrelated mode/type bits stay
    unchanged; compression may be regenerated once. A second pass is a no-op.
    """
    require(path.is_file() and not path.is_symlink(), 'curl normalization requires a regular ZIP')
    temporary = None
    try:
        with zipfile.ZipFile(path) as source:
            infos = source.infolist()
            require(len(infos) == len({item.filename for item in infos}), 'duplicate ZIP member')
            require(sum(item.file_size for item in infos) <= 1 << 30, 'module ZIP exceeds size budget')
            by_name = {item.filename: item for item in infos}
            changed = []
            for name in PAYLOAD_FILES:
                require(name in by_name, 'missing curl payload: ' + name)
                info = by_name[name]
                require(stat.S_ISREG(info.external_attr >> 16) and not info.flag_bits & 1,
                        'curl normalization refuses non-regular/encrypted payload: ' + name)
                expected = 0o755 if name == 'bin/curl' else 0o644
                if stat.S_IMODE(info.external_attr >> 16) != expected:
                    changed.append(name)
            if not changed:
                return []
            descriptor, name = tempfile.mkstemp(prefix=path.name + '.curl-modes.', dir=path.parent)
            os.close(descriptor)
            temporary = Path(name)
            with zipfile.ZipFile(temporary, 'w') as output:
                output.comment = source.comment
                for original in infos:
                    entry = copy.copy(original)
                    if entry.filename in changed:
                        mode = 0o755 if entry.filename == 'bin/curl' else 0o644
                        entry.external_attr = ((stat.S_IFREG | mode) << 16) | (entry.external_attr & 0xFFFF)
                    with source.open(original) as reader, output.open(entry, 'w') as writer:
                        copied = 0
                        while chunk := reader.read(1024 * 1024):
                            writer.write(chunk)
                            copied += len(chunk)
                        require(copied == original.file_size, 'ZIP member length differs: ' + original.filename)
            temporary.chmod(stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary, path)
        temporary = None
        return changed
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('lock-fields')
    create = commands.add_parser('record')
    for name in ('folder', 'source', 'ndk', 'compiler', 'abi'):
        create.add_argument('--' + name, required=True)
    check = commands.add_parser('verify')
    check.add_argument('folder', type=Path)
    check.add_argument('--abi', choices=('arm64-v8a', 'x86_64'), required=True)
    check.add_argument('--ndk-sha256')
    check_zip = commands.add_parser('verify-zip')
    check_zip.add_argument('archive', type=Path)
    check_zip.add_argument('--abi', choices=('arm64-v8a', 'x86_64'), required=True)
    normalize = commands.add_parser('normalize-modes')
    normalize.add_argument('archive', type=Path)
    args = parser.parse_args()
    if args.command == 'lock-fields':
        inputs = lock()
        fields = [str(inputs['api']), *(inputs['versions'][key] for key in ('curl', 'openssl', 'zlib'))]
        for key in ('curl', 'openssl', 'zlib', 'ca'):
            fields.extend(inputs['sources'][key][field] for field in ('file', 'url', 'sha256'))
        print('\n'.join(fields))
    elif args.command == 'record':
        record(args)
    elif args.command == 'verify':
        verify(args.folder / 'curl', json.loads((args.folder / 'build-provenance.json').read_text()),
               args.folder / 'licenses', args.abi, args.ndk_sha256)
        print('Verified production curl build identity; Android runtime capability remains untested.')
    elif args.command == 'verify-zip':
        verify_zip(args.archive, args.abi)
        print('Verified packaged curl ELF, source/CA identity, digest and license notices without executing it.')
    else:
        print(json.dumps({'normalized_curl_modes': normalize_modes(args.archive)}))


if __name__ == '__main__':
    main()
