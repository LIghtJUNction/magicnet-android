#!/usr/bin/env python3
"""Keep reusable source builds bound to their selected commits and quality gates."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stamp_fixture", ROOT / "scripts/test-stamp-release.py")
STAMP_FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAMP_FIXTURE)


class ReleaseGateTests(unittest.TestCase):
    def test_reusable_artifact_requires_successful_local_quality_gate(self):
        build = yaml.safe_load((ROOT / '.github/workflows/exec.yml').read_text())['jobs']['build']
        steps = build['steps']
        gate = next(s for s in steps if s.get('id') == 'release_quality')
        upload = next(s for s in steps if s.get('id') == 'artifact')
        self.assertLess(steps.index(gate), steps.index(upload))
        self.assertEqual(gate['if'], "${{ inputs.release_quality == true }}")
        self.assertNotIn('if', upload)  # Default success() must stop a failed gate.
        self.assertFalse(upload.get('continue-on-error', False))
        self.assertFalse(build.get('continue-on-error', False))
        self.assertFalse(gate.get('continue-on-error', False))
        self.assertEqual(gate.get('env', {}).get('CI_TEST_FORCE'), '1')
        self.assertGreater(gate['timeout-minutes'], 0)
        for command in ('set -euo pipefail', 'bash scripts/quality-gate.sh all',
                        'git submodule status --recursive', 'scripts/stamp-release.py', '--verify'):
            self.assertIn(command, gate['run'])
        for name in ('Prepare release quality dependencies', 'Compile release acceptance test APK'):
            dependency = next(s for s in steps if s.get('name') == name)
            self.assertEqual(dependency['if'], gate['if'])
            self.assertLess(steps.index(dependency), steps.index(gate))

    def test_reusable_build_and_android_accept_the_same_explicit_source(self):
        flow = yaml.safe_load((ROOT / '.github/workflows/exec.yml').read_text())
        android = yaml.safe_load((ROOT / '.github/workflows/android-kernelsu-acceptance.yml').read_text())
        self.assertEqual(flow['permissions'], {'contents': 'read'})
        self.assertEqual(set(flow['jobs']), {'build'})
        inputs = flow.get('on', flow.get(True))['workflow_call']['inputs']
        for name in ('source_sha', 'recipe_sha', 'release_version', 'release_version_code'):
            self.assertEqual(inputs[name]['type'], 'string')
            self.assertTrue(inputs[name]['required'])
        self.assertEqual(inputs['release_quality']['type'], 'boolean')
        android_inputs = android.get('on', android.get(True))['workflow_call']['inputs']
        for name in ('source_sha', 'release_version', 'release_version_code'):
            self.assertEqual(android_inputs[name]['type'], 'string')
        for job in ('harness', 'android-kernelsu'):
            checkout = android['jobs'][job]['steps'][0]
            self.assertEqual(checkout['with']['repository'],
                             "${{ inputs.source_sha && 'LIghtJUNction/magicnet-android' || github.repository }}")
            self.assertEqual(checkout['with']['ref'], '${{ inputs.source_sha || github.sha }}')
            verification = android['jobs'][job]['steps'][1]
            self.assertEqual(verification['env']['SOURCE_SHA'], '${{ inputs.source_sha || github.sha }}')
            self.assertIn('^[0-9a-f]{40}$', verification['run'])
            self.assertIn('git rev-parse HEAD', verification['run'])
        gate = android['jobs']['simulation-gate']
        self.assertEqual(set(gate['needs']), {'harness', 'android-kernelsu'})
        command = gate['steps'][0]['run']
        for harness, device in (('success', 'success'), ('failure', 'success'),
                                ('success', 'skipped'), ('cancelled', 'success')):
            result = subprocess.run(['bash', '-e', '-c', command],
                                    env=dict(os.environ, HARNESS_RESULT=harness, ANDROID_RESULT=device))
            self.assertEqual(result.returncode == 0, harness == device == 'success')
        checkout = flow['jobs']['build']['steps'][0]
        self.assertEqual(checkout['with']['repository'],
                         "${{ inputs.source_sha && 'LIghtJUNction/magicnet-android' || github.repository }}")
        self.assertEqual(checkout['with']['ref'], '${{ inputs.source_sha || github.sha }}')
        self.assertFalse(checkout['with']['persist-credentials'])

    def test_shared_suite_preserves_all_original_checks(self):
        script = (ROOT / 'scripts/quality-gate.sh').read_text()
        for command in ('cargo fmt', 'cargo clippy', 'cargo test',
                        'python3 scripts/test-lint-source.py', 'python3 scripts/lint-source.py',
                        'bash scripts/lint-shell.sh', 'bash scripts/test-host.sh',
                        'go vet', 'go test -race', 'npm run check', 'npm run test:ui'):
            self.assertIn(command, script)
        for lint in ('-D clippy::dbg_macro', '-D clippy::todo', '-D clippy::unimplemented'):
            self.assertIn(lint, script)
        self.assertIn('for group in rust shell components webui-check webui-browser', script)
        quality = yaml.safe_load((ROOT / '.github/workflows/quality.yml').read_text())
        commands = '\n'.join(s.get('run', '') for job in quality['jobs'].values()
                             for s in job.get('steps', []))
        for group in ('rust', 'shell', 'components', 'webui-check', 'webui-browser'):
            self.assertIn('bash scripts/quality-gate.sh ' + group, commands)

    def test_each_failed_check_stops_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for name in ('scripts', 'bin', 'webui', 'installer/components'):
                (work / name).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'scripts/quality-gate.sh', work / 'scripts/quality-gate.sh')
            # Exercise the actual shared shell; only external check commands are stubs.
            for name in ('cargo', 'go', 'npm', 'python3', 'gofmt'):
                stub = work / 'bin' / name
                stub.write_text('#!/bin/sh\n[ "${0##*/} $*" != "$FAIL_CHECK" ] || exit 27\nexit 0\n')
                stub.chmod(0o755)
            for name in ('lint-shell.sh', 'test-host.sh'):
                (work / 'scripts' / name).write_text('[ "${0##*/}" != "$FAIL_CHECK" ] || exit 27\n')
            checks = ('cargo fmt --all -- --check',
                      'cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -D clippy::dbg_macro -D clippy::todo -D clippy::unimplemented',
                      'cargo test --workspace --all-targets --all-features --locked',
                      'python3 scripts/test-lint-source.py', 'python3 scripts/lint-source.py',
                      'lint-shell.sh', 'test-host.sh',
                      'go vet ./installer/components', 'go test -race ./installer/components',
                      'python3 scripts/test-components.py', 'npm run check', 'npm run test:ui')
            for check in checks:
                with self.subTest(check=check):
                    sentinel = work / 'published'
                    sentinel.unlink(missing_ok=True)
                    env = dict(os.environ, PATH=str(work / 'bin') + ':' + os.environ['PATH'], FAIL_CHECK=check)
                    result = subprocess.run(['bash', '-e', '-c',
                                             'bash scripts/quality-gate.sh all\ntouch published'],
                                            cwd=work, env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 27, result.stdout + result.stderr)
                    self.assertFalse(sentinel.exists())


class BuildStepTests(unittest.TestCase):
    """Execute the workflow's actual metadata/provenance shell in an isolated repo."""

    git = STAMP_FIXTURE.StampTest.git

    def setUp(self):
        STAMP_FIXTURE.StampTest.setUp(self)
        self.sha = self.git('rev-parse', 'HEAD')
        for name in ('scripts', 'bin', 'hooks', 'runner'):
            (self.root / name).mkdir()
        for name in ('stamp-release.py', 'checksum-release-assets.sh'):
            shutil.copyfile(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        self.steps = yaml.safe_load((ROOT / '.github/workflows/exec.yml').read_text())['jobs']['build']['steps']
        self.environment = dict(os.environ, SOURCE_SHA=self.sha, RELEASE_COMMIT_SHA=self.sha,
                                GITHUB_SHA='c' * 40, RECIPE_SHA='b' * 40,
                                SELECTED_VERSION='v1.9.0', SELECTED_VERSION_CODE='10700',
                                RELEASE_VERSION='v1.9.0', RELEASE_VERSION_CODE='10700',
                                GITHUB_ENV=str(self.root / 'runner/environment'),
                                RUNNER_TEMP=str(self.root / 'runner'),
                                PATH=str(self.root / 'bin') + ':' + os.environ['PATH'])
        (self.root / 'runner/build-submodules.txt').write_text('')
        kam = self.root / 'bin/kam'
        kam.write_text('''#!/bin/sh
test "$1" = build || exit 1
mkdir -p dist
python3 - <<'PY'
import json
import os
from pathlib import Path
path = Path("update.json")
data = json.loads(path.read_text())
data["zipUrl"] = "https://example.invalid/kam-export.zip"
field = os.environ.get("KAM_BROKEN_FIELD")
if field:
    data[field] = {"version": "v9.9.9", "versionCode": 99999,
                   "changelog": "https://example.invalid/wrong-notes"}[field]
path.write_text(json.dumps(data))
PY
''')
        kam.chmod(0o755)

    def run_step(self, name, **environment):
        step = next(step for step in self.steps if step.get('name') == name)
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']], cwd=self.root,
                              env=self.environment | environment, capture_output=True, text=True)

    def stamp(self):
        result = self.run_step('Stamp selected build version')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_selected_source_and_inputs_are_checked_before_stamping(self):
        cases = (({}, True),
                 ({'RECIPE_SHA': '', 'SELECTED_VERSION': '', 'SELECTED_VERSION_CODE': ''}, True),
                 ({'SOURCE_SHA': 'a' * 40}, False), ({'SOURCE_SHA': 'main'}, False),
                 ({'RECIPE_SHA': 'main'}, False),
                 ({'SELECTED_VERSION': ''}, False),
                 ({'SELECTED_VERSION': 'v1.9.0\nINJECTED=true'}, False),
                 ({'SELECTED_VERSION_CODE': '0'}, False),
                 ({'SELECTED_VERSION_CODE': '10700\nINJECTED=true'}, False),
                 ({'SELECTED_VERSION': '', 'SELECTED_VERSION_CODE': ''}, False))
        for environment, passes in cases:
            with self.subTest(environment=environment):
                output = Path(self.environment['GITHUB_ENV'])
                output.unlink(missing_ok=True)
                result = self.run_step('Verify selected source and version', **environment)
                self.assertEqual(result.returncode == 0, passes, result.stdout + result.stderr)
                if passes:
                    values = dict(line.split('=', 1) for line in output.read_text().splitlines())
                    self.assertEqual(set(values), {'RELEASE_VERSION', 'RELEASE_VERSION_CODE'})
                    self.assertEqual(values['RELEASE_VERSION'], 'v1.9.0' if not environment else 'v1.8.5')
                else:
                    self.assertFalse(output.exists())
                self.assertEqual(self.git('rev-parse', 'HEAD'), self.sha)
                self.assertEqual((self.root / 'kam.toml').read_text(), self.original['kam.toml'])

    def test_kam_export_restores_only_selected_installer_url(self):
        self.stamp()
        result = self.run_step('Build module')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        selected = json.loads((self.root / 'runner/selected-update.json').read_text())
        self.assertEqual(json.loads((self.root / 'update.json').read_text()), selected)
        self.assertEqual(selected['version'], 'v1.9.0')
        self.assertEqual(selected['versionCode'], 10700)
        self.assertIn('/releases/download/v1.9.0/magicnet_installer.zip', selected['zipUrl'])
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.sha)

    def test_kam_metadata_drift_is_not_hidden_by_updater_restore(self):
        for field in ('version', 'versionCode', 'changelog'):
            with self.subTest(field=field):
                self.git('restore', '--', *STAMP_FIXTURE.STAMP.METADATA_FILES)
                self.stamp()
                result = self.run_step('Build module', KAM_BROKEN_FIELD=field)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                selected = json.loads((self.root / 'runner/selected-update.json').read_text())
                generated = json.loads((self.root / 'update.json').read_text())
                self.assertEqual(generated['zipUrl'], selected['zipUrl'])
                self.assertNotEqual(generated[field], selected[field])

    def test_final_assets_record_source_recipe_version_and_updater_before_checksums(self):
        self.stamp()
        for name in ('Build module', 'Record immutable build provenance', 'Generate release checksums'):
            result = self.run_step(name)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        provenance = json.loads((self.root / 'dist/build-source.json').read_text())
        self.assertEqual(provenance, {'schema': 1, 'repository': 'LIghtJUNction/MagicNet',
                         'source_repository': 'LIghtJUNction/magicnet-android',
                         'source_sha': self.sha, 'recipe_sha': 'b' * 40,
                         'version': 'v1.9.0', 'version_code': '10700'})
        self.assertEqual((self.root / 'dist/update.json').read_bytes(), (self.root / 'update.json').read_bytes())
        inventory = {line.split('  ', 1)[1] for line in (self.root / 'dist/SHA256SUMS').read_text().splitlines()}
        self.assertEqual(inventory, {'build-source.json', 'build-submodules.txt', 'update.json'})
        result = self.run_step('Record immutable build provenance', RECIPE_SHA='')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        standalone = json.loads((self.root / 'dist/build-source.json').read_text())
        self.assertEqual(standalone['repository'], 'LIghtJUNction/magicnet-android')
        self.assertNotIn('recipe_sha', standalone)


if __name__ == '__main__':
    unittest.main()
