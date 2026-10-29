#!/usr/bin/env python3
"""Extract only checksum-approved runtime files; no downloaded code is executed."""
import hashlib
import json
import pathlib
import tarfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'assets/vendor'

def checked(name, expected):
    path = VENDOR / name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name + ' checksum mismatch'
    return path

def main():
    panel = checked('zashboard.zip', '1d8c7aca69e6ddead5e4fe6e92ceda23a499105f675d053362f7c9b53a9730f9')
    capture = checked('ecapture.tar.gz', '3531f47f60a45c02662188fb151fa8bbf9c40e5c245ff293e5a50477b99df2d1')
    destination = VENDOR / 'zashboard'
    destination.mkdir(exist_ok=True)
    with zipfile.ZipFile(panel) as z:
        names = set()
        for info in z.infolist():
            pure = pathlib.PurePosixPath(info.filename)
            assert not pure.is_absolute() and '..' not in pure.parts
            assert pure.parts[0] == 'dist' and info.filename not in names
            names.add(info.filename)
            if info.is_dir():
                continue
            assert info.file_size < 16 * 1024 * 1024
            target = destination.joinpath(*pure.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))
    licenses = ROOT / 'assets/licenses'
    licenses.mkdir(exist_ok=True)
    found = False
    with tarfile.open(capture) as t:
        for item in t:
            if not item.isfile():
                continue
            if item.name == 'ecapture-v2.5.2-android-arm64/ecapture':
                data = t.extractfile(item).read()
                assert len(data) < 64 * 1024 * 1024 and data[:4] == b'\x7fELF' and data[18:20] == b'\xb7\x00'
                binary = ROOT / 'assets/bin/android-arm64/ecapture'
                binary.write_bytes(data)
                binary.chmod(0o755)
                found = True
            elif item.name == 'ecapture-v2.5.2-android-arm64/LICENSE':
                (licenses / 'ecapture-Apache-2.0.txt').write_bytes(t.extractfile(item).read())
    assert found
    (licenses / 'zashboard-MIT.txt').write_bytes(checked('zashboard-LICENSE', 'ffc390eec51f16b58506b1a42c99fe0cd9ffea1e3081aab443100fd8c20182d9').read_bytes())
    (licenses / 'sing-box-GPL-3.0.txt').write_bytes((ROOT / 'third_party/sing-box/LICENSE').read_bytes())
    (licenses / 'Go-BSD.txt').write_bytes((ROOT / '.tools/go/LICENSE').read_bytes())
    lock = {
        'schema': 1,
        'sing_box': {'repository': 'https://github.com/LIghtJUNction/sing-box', 'revision': '871b7a3440cd9c850f1b09ef3b4ada9babb4384b', 'license': 'GPL-3.0-or-later', 'notice': 'Upstream additionally restricts derivative naming or implied association; see licenses/sing-box-GPL-3.0.txt', 'source': 'third_party/sing-box, including tracked submodules/wireguard-go; reproduce with scripts/fetch-build-inputs.py'},
        'rules': {'repository': 'https://github.com/LIghtJUNction/MagicNetRules', 'revision': 'f3335f9420d07b8c50b26488df2a9492da6bbb44', 'tag': 'rules-20260918-1ade898a44cc7727', 'license': 'Per upstream; see rules/upstream-manifest.json'},
        'ecapture': {'repository': 'https://github.com/gojue/ecapture', 'tag': 'v2.5.2', 'sha256': hashlib.sha256(capture.read_bytes()).hexdigest(), 'license': 'Apache-2.0'},
        'zashboard': {'repository': 'https://github.com/Zephyruso/zashboard', 'tag': 'v3.16.0', 'sha256': hashlib.sha256(panel.read_bytes()).hexdigest(), 'license': 'MIT'},
        'parser_tools': {'jq': 'not required: native Go implementation', 'yq': 'not required: pinned gopkg.in/yaml.v3 implementation'}
    }
    dependency_index = licenses / 'dependencies/index.json'
    if dependency_index.exists():
        dependencies = json.loads(dependency_index.read_text())
        lock['go_dependencies'] = {
            'manifest': 'licenses/dependencies/index.json',
            'modules': len(dependencies['modules']),
            'notice_files': sum(len(item['files']) for item in dependencies['modules']),
            'linked_runtime_notices_complete': dependencies['linked_runtime_notices_complete'],
            'nonruntime_without_notice': dependencies['nonruntime_without_notice'],
            'control_direct': [item['identity'] for item in dependencies['modules'] if 'control' in item['owners'] and item['module'] in ['gopkg.in/yaml.v3', 'golang.org/x/net', 'github.com/cilium/ebpf', 'github.com/sagernet/netlink']],
        }
    (ROOT / 'assets/THIRD_PARTY.json').write_text(json.dumps(lock, indent=2) + '\n')

if __name__ == '__main__':
    main()
