#!/usr/bin/env python3
"""Compile only the Linux CLI from a synthetic no-.git source archive fixture."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from product_metadata import ROOT, INPUT_SHA256, functional_inventory, product_metadata, source_metadata


def main():
    started = time.monotonic()
    fixture = ROOT / '.tools/archive-build-fixture'
    if fixture.exists():
        raise RuntimeError('Archive fixture already exists; inspect it before choosing another run')
    fixture.mkdir(parents=True)
    inventory, _ = functional_inventory()
    for item in inventory:
        destination = fixture / item['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / item['path'], destination)
    # This canary tests descriptor plumbing; it is not a claimed Git revision
    # of the copied, currently edited implementation.
    declared = '0123456789abcdef0123456789abcdef01234567'
    info = {'schema': 1, 'functional_binary_source_commit': declared,
            'delivery_commit': declared, 'product': product_metadata(),
            'recipe_sha256': INPUT_SHA256, 'synthetic_build_regression': True}
    descriptor = (json.dumps(info, indent=2) + '\n').encode()
    (fixture / 'SOURCE_ARCHIVE_INFO.json').write_bytes(descriptor)
    inventory.append({'path': 'SOURCE_ARCHIVE_INFO.json', 'mode': '0o644', 'type': 'file',
                      'bytes': len(descriptor), 'sha256': hashlib.sha256(descriptor).hexdigest()})
    (fixture / 'SOURCE_FILES.json').write_text(json.dumps({**info, 'files': inventory}, indent=2) + '\n')
    origin = source_metadata()
    env = dict(os.environ)
    env.pop('MAGICNET_SOURCE_REVISION', None)
    env.update(MAGICNET_GO=str(ROOT / '.tools/go/bin/go'), GOMODCACHE=str(ROOT / '.tools/gomodcache'),
               GOCACHE=str(ROOT / '.tools/gocache'), GIT_DIR=origin['git_dir'], GIT_WORK_TREE=str(ROOT))
    result = subprocess.run(['bash', 'scripts/build.sh', 'cli-linux'], cwd=fixture, env=env,
                            capture_output=True, text=True, timeout=240)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    binary = fixture / 'assets/bin/linux-amd64/magicnet-cli'
    receipt = json.loads(subprocess.check_output([str(binary), 'version'], text=True, cwd=fixture))
    assert receipt['commit'] == declared and receipt['version'] == '1.8.1' and receipt['channel'] == 'candidate'
    build_info = subprocess.check_output([str(ROOT / '.tools/go/bin/go'), 'version', '-m', str(binary)], text=True)
    assert '\tvcs.' not in build_info and '\tvcs\t' not in build_info
    assert 'GOOS=linux' in build_info and 'GOARCH=amd64' in build_info
    assert not (fixture / '.git').exists() and not (fixture / 'assets/bin/android-arm64').exists()
    assert not (fixture / 'assets/bin/linux-amd64/magicnet-installer').exists()
    probe = 'import json,sys;sys.path.insert(0,"scripts");from product_metadata import source_metadata;print(json.dumps(source_metadata(require_archive_inventory=True)))'
    observed = json.loads(subprocess.check_output([sys.executable, '-c', probe], cwd=fixture, env=env, text=True))
    assert observed['source_mode'] == 'archive' and observed['revision'] == declared
    override = {**env, 'MAGICNET_SOURCE_REVISION': 'fedcba9876543210fedcba9876543210fedcba98'}
    overridden = json.loads(subprocess.check_output([sys.executable, '-c', probe], cwd=fixture, env=override, text=True))
    assert overridden['revision'] == override['MAGICNET_SOURCE_REVISION'] and overridden['provenance']['revision_origin'] == 'environment'
    descriptor_path = fixture / 'SOURCE_ARCHIVE_INFO.json'
    descriptor_path.rename(fixture / 'SOURCE_ARCHIVE_INFO.saved')
    try:
        missing = subprocess.check_output([sys.executable, 'scripts/product_metadata.py', '--build-identity'], cwd=fixture, env=env, text=True).splitlines()
        assert missing[:2] == ['archive', 'uncommitted']
    finally:
        (fixture / 'SOURCE_ARCHIVE_INFO.saved').rename(descriptor_path)
    editable = fixture / 'webui/app.js'
    original = editable.read_bytes()
    editable.write_bytes(original + b'\n// synthetic unrecorded functional edit\n')
    try:
        changed = subprocess.run([sys.executable, '-c', probe], cwd=fixture, env=env, capture_output=True, text=True)
        assert changed.returncode != 0 and 'Functional source differs from archive' in changed.stderr
    finally:
        editable.write_bytes(original)
    report = {'passed': True, 'synthetic_fixture': True,
              'identity_boundary': 'The descriptor commit is a synthetic canary, not a claimed Git source revision.',
              'fixture': str(fixture.relative_to(ROOT)), 'compiled': 'Linux amd64 CLI only; no core, installer or Android rebuild',
              'controller': receipt, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'source_mode': observed['source_mode'], 'source_provenance': observed['provenance'],
              'checks': ['own .git absent inside an enclosing worktree', 'inherited GIT_DIR/GIT_WORK_TREE ignored',
                         'real Linux build succeeds with explicit buildvcs=false', 'CLI commit uses archive descriptor fallback',
                         'Go binary has no unrelated VCS metadata', 'functional inventory hashes and modes verified',
                         'explicit revision override has priority', 'missing descriptor uses uncommitted, not parent Git',
                         'unrecorded functional edit rejected'],
              'elapsed_seconds': round(time.monotonic() - started, 3)}
    reports = ROOT / 'module/test-artifacts'; reports.mkdir(exist_ok=True)
    (reports / 'archive-build-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
