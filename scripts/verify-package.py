#!/usr/bin/env python3
"""Exercise real installer binaries with only isolated, synthetic module roots."""
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile
from product_metadata import product_metadata, controller_metadata, properties

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
REPORTS = ROOT / 'module/test-artifacts'
INSTALLER = ROOT / 'assets/bin/linux-amd64/magicnet-installer'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def put(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)

def run(*args, success=True):
    result = subprocess.run([str(INSTALLER), *map(str, args)], capture_output=True, text=True, timeout=180)
    if success:
        assert result.returncode == 0, (args[0], result.stdout, result.stderr)
        assert ' download' not in result.stdout, 'A supposedly complete offline install requested a download'
    else:
        assert result.returncode != 0, 'An invalid candidate was accepted'
    return {'exit_code': result.returncode, 'stdout': result.stdout.strip(), 'stderr': result.stderr.strip()}

def fingerprint(root, manifest):
    values = {}
    for component in manifest['components']:
        for item in component['files']:
            path = root / item['path']
            data = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            assert (len(data), sha(data), mode) == (item['size'], item['sha256'], item['mode']), item['path']
            values[item['path']] = [mode, len(data), sha(data)]
    assert (root / 'cli').is_symlink() and os.readlink(root / 'cli') == 'bin/magicnet-cli'
    return sha(json.dumps(values, sort_keys=True).encode())

def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    manifest = json.loads((DIST / 'components.json').read_text())
    product = product_metadata()
    controller = controller_metadata()
    assert all(manifest[key] == value for key, value in product.items())
    assert manifest['release_tag'] == product['version']
    build = json.loads((ROOT / 'assets/BUILD_INPUTS.json').read_text())
    assert build['product'] == product and build['implementation_commit'] == controller['commit']
    assert manifest['source_mode'] == build['source_mode'] and manifest['source_provenance'] == build['source_provenance']
    aliases = [DIST / name for name in ['MagicNet-core.zip', 'MagicNet.zip', 'magicnet_installer.zip']]
    assert len({sha(path.read_bytes()) for path in aliases}) == 1
    checks = [{'case': 'product version, version code, recipe, candidate channel and CLI build revision agree', 'passed': True, 'product': product, 'implementation_commit': controller['commit']}]
    for archive in [DIST / 'MagicNet-core.zip', DIST / 'MagicNet-full.zip']:
        checks.append({'case': archive.name + ':verify', **run('verify', archive)})
        with zipfile.ZipFile(archive) as z:
            packed = properties(z.read('module.prop'))
            assert packed['version'] == product['version'] and packed['versionCode'] == str(product['version_code'])
            assert packed['recipeVersion'] == product['recipe_version'] and packed['releaseChannel'] == product['channel']
            assert json.loads(z.read('components.json')) == manifest
            assert len(z.namelist()) == len(set(z.namelist()))
            assert not any(name.startswith(('.state/', '.log/', '.env', '.tools/')) for name in z.namelist())
            assert not any('/node_modules/' in name or '/.git/' in name for name in z.namelist())
    with tempfile.TemporaryDirectory(prefix='installer-', dir=REPORTS) as location:
        base = pathlib.Path(location)
        full, components, reused, migrated = [base / name for name in ['full', 'components', 'reused', 'migrated']]
        for path in [full, components, reused, migrated]:
            path.mkdir(mode=0o700)
        checks.append({'case': 'fresh full offline', **run('install', '--root', full, '--archive', DIST / 'MagicNet-full.zip')})
        checks.append({'case': 'fresh core plus read-only offline component cache', **run('install', '--root', components, '--archive', DIST / 'MagicNet-core.zip', '--cache-dir', DIST)})
        checks.append({'case': 'core with complete installed-component reuse', **run('install', '--root', reused, '--old', full, '--archive', DIST / 'MagicNet-core.zip')})
        fingerprints = [fingerprint(path, manifest) for path in [full, components, reused]]
        assert len(set(fingerprints)) == 1
        checks.append({'case': 'three installation paths converge on identical bytes and modes', 'passed': True, 'inventory_sha256': fingerprints[0]})

        # A synthetic old installation contains private state plus an old active
        # config. The current immutable rules must replace old data; the active
        # config is preserved only as an explicitly labelled migration backup.
        saved = {
            '.config/magicnet/settings.json': b'{"synthetic_setting":true}\n',
            '.config/warp/profile.json': b'{"synthetic_private_key":"CANARY_MIGRATION"}\n',
            '.state/private/override.json': b'{"revision":8,"synthetic":"CANARY_OVERRIDE"}\n',
            '.state/tailscale/preferences.json': b'{"synthetic_tailnet":true}\n',
        }
        for name, data in saved.items():
            put(full, name, data)
        active = b'{"outbounds":[{"type":"socks","tag":"synthetic","server":"127.0.0.1","server_port":1080}]}\n'
        put(full, '.config/sing-box/config.json', active)
        put(full, '.state/private/payload/tmp/not-migrated.data', b'CANARY_PAYLOAD')
        put(full, '.config/sing-box/rules/old-unowned.srs', b'old synthetic rule')
        checks.append({'case': 'single-manifest private-state migration', **run('install', '--root', migrated, '--old', full, '--archive', DIST / 'MagicNet-full.zip')})
        for name, data in saved.items():
            path = migrated / name
            assert path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == 0o600
        assert (migrated / '.migration-backup/.config/sing-box/config.json').read_bytes() == active
        assert not (migrated / '.config/sing-box/config.json').exists()
        assert not (migrated / '.state/private/payload/tmp/not-migrated.data').exists()
        assert not (migrated / '.config/sing-box/rules/old-unowned.srs').exists()
        assert fingerprint(migrated, manifest) == fingerprints[0]

        # Explicit boundary: an existing installation cannot be upgraded in its
        # own live root, because manager-level config rollback is not available.
        before_inplace = fingerprint(full, manifest)
        failure = run('install', '--root', full, '--old', full, '--archive', DIST / 'MagicNet-full.zip', success=False)
        assert 'install.in_place_upgrade_requires_staging' in failure['stderr']
        assert fingerprint(full, manifest) == before_inplace
        assert (full / '.config/sing-box/config.json').read_bytes() == active
        checks.append({'case': 'known limitation: in-place upgrade rejected before mutation; manager staging required', **failure})

        # A broken migration source fails before replacing any destination data.
        bad_old, destination = base / 'bad-old', base / 'unchanged'
        bad_old.mkdir(); destination.mkdir()
        put(destination, 'user-owned.txt', b'preserve destination')
        (bad_old / '.config').mkdir()
        (bad_old / '.config/unsafe').symlink_to('/tmp')
        failure = run('install', '--root', destination, '--old', bad_old, '--archive', DIST / 'MagicNet-full.zip', success=False)
        assert 'migration.link_rejected' in failure['stderr']
        assert (destination / 'user-owned.txt').read_bytes() == b'preserve destination'
        assert not (destination / 'bin').exists() and not (destination / '.components-install').exists()
        checks.append({'case': 'unsafe migration leaves destination unchanged and removes staging', **failure})

        # A missing engine must come from the fixed manifest's exact archive hash.
        cache, fresh = base / 'bad-cache', base / 'bad-component'
        cache.mkdir(); fresh.mkdir()
        engine = next(c for c in manifest['components'] if c['id'] == 'engine')
        data = bytearray((DIST / engine['archive']).read_bytes()); data[-1] ^= 1
        put(cache, engine['archive'], data)
        failure = run('install', '--root', fresh, '--archive', DIST / 'MagicNet-core.zip', '--cache-dir', cache, success=False)
        assert 'component.archive_hash_mismatch' in failure['stderr']
        assert not (fresh / 'bin').exists() and not (fresh / '.components-install').exists()
        checks.append({'case': 'bad component digest fails before publication', **failure})

        # All public release payloads must remain free of these synthetic private
        # markers; the packaging script reads only its explicit source inventory.
        for component in manifest['components']:
            with zipfile.ZipFile(DIST / component['archive']) as z:
                assert all(b'CANARY_MIGRATION' not in z.read(n) and b'CANARY_OVERRIDE' not in z.read(n) for n in z.namelist())
        checks.append({'case': 'private fixture canaries absent from every component', 'passed': True})
    report = {
        'passed': True,
        'environment': 'Linux amd64 real independent installer; Android arm64 package bytes; synthetic module roots; no Android root manager execution',
        'network': 'Executed in the network-restricted host executor; full, offline-cache and complete-reuse cases reported no download stage',
        'elapsed_seconds': round(time.monotonic() - started, 3),
        'core_alias_sha256': sha(aliases[0].read_bytes()),
        'product': product,
        'implementation_commit': controller['commit'],
        'component_count': len(manifest['components']),
        'checks': checks,
    }
    (REPORTS / 'package-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
