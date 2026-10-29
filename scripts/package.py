#!/usr/bin/env python3
"""Produce deterministic, content-addressed MagicNet module/component archives."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import zipfile
from product_metadata import product_metadata, controller_metadata, source_metadata

ROOT = pathlib.Path(__file__).resolve().parents[1]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def zip_bytes(files, links=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path, (data, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
        for path, target in sorted((links or {}).items()):
            info = zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, target.encode())
    return output.getvalue()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default=str(ROOT / 'dist'))
    args = parser.parse_args()
    product = product_metadata()
    controller = controller_metadata()
    build = json.loads((ROOT / 'assets/BUILD_INPUTS.json').read_text())
    source = source_metadata(require_archive_inventory=True)
    if build.get('product') != product or build.get('implementation_commit') != controller['commit']:
        raise ValueError('Build metadata belongs to a different product or implementation')
    if build.get('source_mode') != source['source_mode'] or build.get('source_provenance', {}).get('functional_inventory_sha256') != source['provenance'].get('functional_inventory_sha256'):
        raise ValueError('Functional sources differ from the verified build provenance')
    for item in build['binaries']:
        if digest((ROOT / item['path']).read_bytes()) != item['sha256']:
            raise ValueError('Build metadata is stale: ' + item['path'])
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    previous = {}
    previous_manifest = out / 'components.json'
    if previous_manifest.is_file() and not previous_manifest.is_symlink():
        for item in json.loads(previous_manifest.read_text()).get('components', []):
            expected_name = f"MagicNet-component-{item['id']}-{item['identity']}.zip"
            if item['archive'] == expected_name and '/' not in expected_name and '\\' not in expected_name:
                previous[expected_name] = item['sha256']
    groups = {name: {} for name in ['control', 'engine', 'rules', 'webui', 'android-bridge', 'ecapture', 'panel']}
    def add(group, destination, source, mode=0o644):
        file = pathlib.Path(source)
        assert file.is_file() and not file.is_symlink(), str(file)
        groups[group][destination] = (file.read_bytes(), mode)
    def tree(group, destination, source):
        for file in sorted(pathlib.Path(source).rglob('*')):
            if file.is_file():
                add(group, destination + '/' + file.relative_to(source).as_posix(), file)
    for name in ['magicnet-cli', 'magicnet-installer']:
        add('control', 'bin/' + name, ROOT / 'assets/bin/android-arm64' / name, 0o755)
    for name in ['customize.sh', 'service.sh', 'boot-completed.sh', 'uninstall.sh', 'action.sh']:
        add('control', name, ROOT / 'module' / name, 0o755)
    add('control', 'migration.json', ROOT / 'module/migration.json')
    add('control', 'META-INF/com/google/android/update-binary', ROOT / 'module/META-INF/com/google/android/update-binary', 0o755)
    add('control', 'META-INF/com/google/android/updater-script', ROOT / 'module/META-INF/com/google/android/updater-script')
    tree('control', 'licenses', ROOT / 'assets/licenses')
    add('control', 'THIRD_PARTY.json', ROOT / 'assets/THIRD_PARTY.json')
    if (ROOT / 'LICENSE').exists():
        add('control', 'LICENSE', ROOT / 'LICENSE')
    add('engine', 'bin/sing-box', ROOT / 'assets/bin/android-arm64/sing-box', 0o755)
    add('android-bridge', 'bin/magicnet-bridge.jar', ROOT / 'assets/bin/android-arm64/magicnet-bridge.jar')
    add('ecapture', 'bin/ecapture', ROOT / 'assets/bin/android-arm64/ecapture', 0o755)
    tree('rules', '.config/sing-box/rules', ROOT / 'assets/rules')
    for name in ['index.html', 'app.js', 'bridge.js', 'model.js', 'i18n.js', 'styles.css', 'icon.svg']:
        add('webui', 'webroot/' + name, ROOT / 'webui' / name)
    tree('panel', 'ui', ROOT / 'assets/vendor/zashboard')
    prop = (ROOT / 'module/module.prop').read_bytes()
    components = []
    artifacts = {}
    full = {}
    for component_id, files in groups.items():
        inventory = [{'path': path, 'mode': mode, 'size': len(data), 'sha256': digest(data)} for path, (data, mode) in sorted(files.items())]
        canonical = ''.join(f"{f['path']}\0{f['mode']}\0{f['size']}\0{f['sha256']}\n" for f in inventory).encode()
        identity = digest(canonical)
        filename = f'MagicNet-component-{component_id}-{identity}.zip'
        data = zip_bytes(files)
        artifacts[filename] = data
        components.append({'id': component_id, 'identity': identity, 'archive': filename, 'sha256': digest(data), 'files': inventory})
        full.update(files)
    manifest = {'schema': 1, 'module_id': 'MagicNet', 'arch': 'android-arm64', **product, 'source_mode': build['source_mode'], 'source_provenance': build['source_provenance'], 'release_tag': product['version'], 'components': components}
    manifest_bytes = (json.dumps(manifest, indent=2) + '\n').encode()
    core = dict(groups['control'])
    for files in [core, full]:
        files['module.prop'] = (prop, 0o644)
        files['components.json'] = (manifest_bytes, 0o644)
    core_bytes = zip_bytes(core, {'cli': 'bin/magicnet-cli'})
    for filename in ['MagicNet-core.zip', 'MagicNet.zip', 'magicnet_installer.zip']:
        artifacts[filename] = core_bytes
    artifacts['MagicNet-full.zip'] = zip_bytes(full, {'cli': 'bin/magicnet-cli'})
    artifacts['components.json'] = manifest_bytes
    sizes = {'schema': 1, 'product': product, 'implementation_commit': controller['commit'], 'source_mode': build['source_mode'], 'source_provenance': build['source_provenance'], 'artifact_bytes': {name: len(data) for name, data in sorted(artifacts.items())}, 'installed_bytes': sum(len(data) for data, _ in full.values()), 'components': {c['id']: {'identity': c['identity'], 'uncompressed_bytes': sum(f['size'] for f in c['files'])} for c in components}}
    artifacts['package-sizes.json'] = (json.dumps(sizes, indent=2) + '\n').encode()
    artifacts['SHA256SUMS'] = ''.join(digest(data) + '  ' + name + '\n' for name, data in sorted(artifacts.items())).encode()
    for name, data in artifacts.items():
        (out / name).write_bytes(data)
    for name, expected_hash in previous.items():
        candidate = out / name
        if name not in artifacts and candidate.is_file() and not candidate.is_symlink() and digest(candidate.read_bytes()) == expected_hash:
            candidate.unlink()
    installer = ROOT / 'assets/bin/linux-amd64/magicnet-installer'
    for name in ['MagicNet-core.zip', 'MagicNet-full.zip']:
        subprocess.run([str(installer), 'verify', str(out / name)], check=True)
    assert len({digest(artifacts[n]) for n in ['MagicNet-core.zip', 'MagicNet.zip', 'magicnet_installer.zip']}) == 1
    forbidden = [n for n in full if n.startswith(('.state/', '.log/', '.env')) or any(part in ['.git', 'node_modules', '.tools'] for part in pathlib.PurePosixPath(n).parts)]
    assert not forbidden, forbidden
    print(json.dumps({'artifacts': len(artifacts), 'core_bytes': len(core_bytes), 'full_bytes': len(artifacts['MagicNet-full.zip']), 'component_count': len(components), 'core_alias_sha256': digest(core_bytes)}, indent=2))

if __name__ == '__main__':
    main()
