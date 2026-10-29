#!/usr/bin/env python3
"""Record verifiable identities of the actual built artifacts, never credentials."""
import hashlib
import json
import pathlib
import struct
import subprocess
import zipfile
from product_metadata import product_metadata, controller_metadata, source_metadata, clean_git_environment, INPUT_SHA256

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = ROOT / '.tools/go/bin/go'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(*args, cwd=ROOT):
    return subprocess.check_output(list(map(str, args)), cwd=cwd, env=clean_git_environment(), text=True).strip()

def main():
    product = product_metadata()
    controller = controller_metadata()
    source_identity = source_metadata(require_archive_inventory=True)
    assert source_identity['revision'] == controller['commit'], 'Source provenance differs from controller receipt'
    binaries = []
    for target in ['linux-amd64', 'android-arm64']:
        for name in ['magicnet-cli', 'magicnet-installer', 'sing-box']:
            path = ROOT / 'assets/bin' / target / name
            data = path.read_bytes()
            assert data[:4] == b'\x7fELF'
            machine = struct.unpack_from('<H', data, 18)[0]
            assert machine == (62 if target == 'linux-amd64' else 183)
            metadata = command(GO, 'version', '-m', path)
            assert 'GOOS=' + target.split('-')[0] in metadata
            assert 'GOARCH=' + target.split('-')[1] in metadata
            if name == 'sing-box':
                assert 'vcs.revision=871b7a3440cd9c850f1b09ef3b4ada9babb4384b' in metadata and 'vcs.modified=false' in metadata and 'with_ebpf' in metadata
            else:
                if source_identity['source_mode'] == 'git':
                    assert 'vcs.revision=' + controller['commit'] in metadata, 'Control artifact source revision differs from the version receipt'
                    assert 'vcs.modified=false' in metadata, 'Freeze the implementation before writing final build metadata'
                else:
                    assert '\tvcs.' not in metadata and '\tvcs\t' not in metadata, 'An archive build inherited unrelated Git metadata'
            binaries.append({'path': str(path.relative_to(ROOT)), 'sha256': digest(path), 'bytes': len(data), 'elf_machine': machine, 'go_build_info': metadata})
    jar = ROOT / 'assets/bin/android-arm64/magicnet-bridge.jar'
    source = ROOT / 'module/java/MagicNetBridge.java'
    with zipfile.ZipFile(jar) as z:
        manifest = z.read('META-INF/MANIFEST.MF').decode().replace('\r\n ', '').replace('\r\n', '\n')
        assert 'MagicNet-Source-SHA256: ' + digest(source) in manifest, 'Java bridge artifact is stale'
        assert z.read('classes.dex').startswith(b'dex\n')
    rules = json.loads((ROOT / 'assets/rules/manifest.json').read_text())
    assert len(rules['files']) == 55 and len({f['tag'] for f in rules['files']}) == 55
    for item in rules['files']:
        path = ROOT / 'assets/rules' / item['path']
        assert path.stat().st_size == item['size'] and digest(path) == item['sha256']
    values = {
        'schema': 1,
        'product': product,
        'implementation_commit': controller['commit'],
        'source_mode': source_identity['source_mode'],
        'source_provenance': source_identity['provenance'],
        'project_input_sha256': INPUT_SHA256,
        'go_toolchain': command(GO, 'version'),
        'core_source_revision': command('git', '-C', 'third_party/sing-box', 'rev-parse', 'HEAD'),
        'core_source_clean': command('git', '-C', 'third_party/sing-box', 'status', '--porcelain', '--untracked-files=no') == '',
        'binaries': binaries,
        'android_bridge': {'path': str(jar.relative_to(ROOT)), 'sha256': digest(jar), 'source_sha256': digest(source), 'bytes': jar.stat().st_size, 'dex': True, 'min_api': 26, 'd8_version': '8.10.21'},
        'rules': {'revision': rules['revision'], 'release_tag': rules['release_tag'], 'asset_count': len(rules['files']), 'payload_bytes': sum(item['size'] for item in rules['files']), 'manifest_sha256': digest(ROOT / 'assets/rules/manifest.json')},
        'dependency_locks': {str(path.relative_to(ROOT)): digest(path) for path in [ROOT / 'go.mod', ROOT / 'go.sum', ROOT / 'third_party/sing-box/go.mod', ROOT / 'third_party/sing-box/go.sum', ROOT / 'third_party/sing-box/submodules/wireguard-go/go.mod', ROOT / 'third_party/sing-box/submodules/wireguard-go/go.sum']},
        'execution_boundary': 'Linux executables were run on the host. Android arm64 ELF and DEX artifacts were inspected, not executed on Android.',
    }
    (ROOT / 'assets/BUILD_INPUTS.json').write_text(json.dumps(values, indent=2) + '\n')
    print(json.dumps({'binaries': len(binaries), 'rules': len(rules['files']), 'java_source_matches': True}))

if __name__ == '__main__':
    main()
