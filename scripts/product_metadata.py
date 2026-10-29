"""Keep product identity separate from its reconstruction recipe and channel."""
import json
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INPUT_SHA256 = '502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a'
GIT_VARIABLES = ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE')


def clean_git_environment():
    return {key: value for key, value in os.environ.items() if key not in GIT_VARIABLES}


def functional_path(name):
    parts = pathlib.PurePosixPath(name).parts
    if not parts or 'test-artifacts' in parts or '__pycache__' in parts:
        return False
    return name in ('go.mod', 'go.sum') or parts[0] in ('cmd', 'internal', 'module', 'scripts') or name in {
        'webui/index.html', 'webui/app.js', 'webui/bridge.js', 'webui/model.js',
        'webui/i18n.js', 'webui/styles.css', 'webui/icon.svg', 'webui/package.json'}


def functional_inventory():
    entries = []
    candidates = [ROOT / 'go.mod', ROOT / 'go.sum']
    for name in ('cmd', 'internal', 'module', 'scripts', 'webui'):
        candidates.extend((ROOT / name).rglob('*'))
    for path in sorted(set(candidates)):
        name = path.relative_to(ROOT).as_posix()
        if not functional_path(name) or path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError('Unsafe functional source: ' + name)
        data = path.read_bytes()
        entries.append({'path': name, 'mode': oct(stat.S_IMODE(path.stat().st_mode)),
                        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'type': 'file'})
    required = {'go.mod', 'go.sum', 'module/module.prop', 'scripts/build.sh', 'webui/app.js'}
    if not required.issubset({item['path'] for item in entries}):
        raise ValueError('Incomplete functional source tree')
    fingerprint = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return entries, fingerprint


def source_metadata(require_archive_inventory=False):
    """Observe this root only; an enclosing Git repository is never a source."""
    override = os.environ.get('MAGICNET_SOURCE_REVISION', '')
    provenance = {}
    git_dir = ''
    if (ROOT / '.git').exists():
        def git(*args):
            return subprocess.check_output(['git', '-C', str(ROOT), *args], env=clean_git_environment(), text=True).strip()
        if pathlib.Path(git('rev-parse', '--show-toplevel')).resolve() != ROOT:
            raise ValueError('The source root does not own its Git repository')
        mode = 'git'
        git_dir = git('rev-parse', '--absolute-git-dir')
        declared = git('rev-parse', 'HEAD')
        provenance['git_revision'] = declared
    else:
        mode = 'archive'
        info_path = ROOT / 'SOURCE_ARCHIVE_INFO.json'
        files_path = ROOT / 'SOURCE_FILES.json'
        declared = 'uncommitted'
        if info_path.exists():
            if info_path.is_symlink() or not info_path.is_file():
                raise ValueError('Unsafe source archive descriptor')
            info = json.loads(info_path.read_bytes())
            declared = info.get('functional_binary_source_commit', 'uncommitted')
            provenance.update(archive_info_sha256=hashlib.sha256(info_path.read_bytes()).hexdigest(),
                              archive_declared_commit=declared, delivery_commit=info.get('delivery_commit'))
        elif require_archive_inventory:
            raise ValueError('Final archive build metadata requires SOURCE_ARCHIVE_INFO.json')
        if info_path.exists() and files_path.exists():
            if files_path.is_symlink() or not files_path.is_file():
                raise ValueError('Unsafe source archive inventory')
            inventory = json.loads(files_path.read_bytes())
            if inventory.get('functional_binary_source_commit') != declared or inventory.get('recipe_sha256') != INPUT_SHA256:
                raise ValueError('Archive identity and frozen recipe differ')
            if info.get('recipe_sha256') != INPUT_SHA256 or info.get('product') != product_metadata() or inventory.get('product') != product_metadata():
                raise ValueError('Archive product metadata differs')
            expected = {}
            for item in inventory.get('files', []):
                name = item.get('path', '')
                pure = pathlib.PurePosixPath(name)
                if not name or pure.is_absolute() or '..' in pure.parts or pure.as_posix() != name or name in expected:
                    raise ValueError('Ambiguous source inventory path')
                expected[name] = item
            actual, fingerprint = functional_inventory()
            selected = {name: item for name, item in expected.items() if functional_path(name)}
            if set(selected) != {item['path'] for item in actual}:
                raise ValueError('Functional source file inventory differs from the archive')
            for item in actual:
                original = selected[item['path']]
                if any(original.get(key) != item[key] for key in ('type', 'bytes', 'sha256')) or int(original.get('mode', '0'), 8) != int(item['mode'], 8):
                    raise ValueError('Functional source differs from archive: ' + item['path'])
            descriptor = expected.get('SOURCE_ARCHIVE_INFO.json', {})
            if descriptor.get('sha256') != provenance['archive_info_sha256']:
                raise ValueError('Source archive descriptor is not bound to its inventory')
            provenance.update(source_inventory_sha256=hashlib.sha256(files_path.read_bytes()).hexdigest(),
                              verified_files=len(actual), functional_inventory_sha256=fingerprint)
        elif require_archive_inventory:
            raise ValueError('Final archive build metadata requires SOURCE_FILES.json')
    revision = override or declared
    if revision != 'uncommitted' and not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', revision):
        raise ValueError('Source revision must be a full lowercase Git object ID')
    if mode == 'git':
        actual, fingerprint = functional_inventory()
        provenance.update(verified_files=len(actual), functional_inventory_sha256=fingerprint)
    provenance['revision_origin'] = 'environment' if override else ('git' if mode == 'git' else 'archive_descriptor' if declared != 'uncommitted' else 'unavailable')
    return {'source_mode': mode, 'revision': revision, 'git_dir': git_dir, 'provenance': provenance}


def properties(data):
    result = {}
    for raw in data.decode('utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key in result:
            raise ValueError('Ambiguous module property')
        result[key] = value
    return result


def product_metadata():
    prop = properties((ROOT / 'module/module.prop').read_bytes())
    if prop.get('id') != 'MagicNet' or not re.fullmatch(r'v\d+\.\d+\.\d+', prop.get('version', '')):
        raise ValueError('Invalid product version')
    if not re.fullmatch(r'[1-9][0-9]*', prop.get('versionCode', '')):
        raise ValueError('Invalid product version code')
    if not re.fullmatch(r'\d+\.\d+\.\d+', prop.get('recipeVersion', '')) or prop.get('releaseChannel') not in ('candidate', 'stable'):
        raise ValueError('Recipe version and product channel must be explicit')
    product = {'version': prop['version'], 'version_code': int(prop['versionCode']),
               'recipe_version': prop['recipeVersion'], 'channel': prop['releaseChannel']}
    ui = json.loads((ROOT / 'webui/package.json').read_text())
    if ui.get('version') != product['version'][1:] or any(ui.get(key) != product[key] for key in ('recipe_version', 'channel')):
        raise ValueError('WebUI and module product identities differ')
    return product


def controller_metadata():
    binary = ROOT / 'assets/bin/linux-amd64/magicnet-cli'
    result = subprocess.run([str(binary), 'version'], capture_output=True, text=True, check=True, timeout=15)
    actual = json.loads(result.stdout)
    if actual.get('schema') == 1:
        if actual.get('ok') is not True or actual.get('command') != 'version':
            raise ValueError('Invalid controller version receipt')
        actual = actual['data']
    expected = product_metadata()
    if actual.get('version') != expected['version'][1:] or any(actual.get(key) != expected[key] for key in ('version_code', 'recipe_version', 'channel')):
        raise ValueError('Controller and module product identities differ')
    if actual.get('recipe') != 'magicnet@' + expected['recipe_version'] or actual.get('input_sha256') != INPUT_SHA256:
        raise ValueError('Controller reconstruction input differs')
    return actual


if __name__ == '__main__':
    if sys.argv[1:] == ['--build-identity']:
        source = source_metadata()
        print(source['source_mode'])
        print(source['revision'])
        print(source['git_dir'])
    else:
        print(json.dumps(product_metadata()))
