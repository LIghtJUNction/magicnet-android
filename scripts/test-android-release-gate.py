#!/usr/bin/env python3
"""Publication must not reuse an old, PR-only, failed or incomplete Android run."""
import importlib.util
from pathlib import Path
import unittest

import yaml

SPEC = importlib.util.spec_from_file_location('android_release_gate',
                                            Path(__file__).with_name('require-android-acceptance.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
SHA = 'a' * 40
REPO = 'LIghtJUNction/MagicNet'
RUN = {'id': 10, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
       'head_repository': {'full_name': REPO}, 'status': 'completed', 'conclusion': 'success'}
JOBS = [{'name': name, 'status': 'completed', 'conclusion': 'success'}
        for name in ('Simulation harness contracts', 'Android 15 / KernelSU / x86_64',
                     'Android Simulation Gate')]


class AndroidReleaseGateTests(unittest.TestCase):
    def test_success_requires_matching_run_and_all_jobs(self):
        requests = []
        def query(path):
            requests.append(path)
            return {'jobs': JOBS} if '/jobs?' in path else {'workflow_runs': [RUN]}
        self.assertEqual(GATE.require_acceptance(REPO, SHA, query=query), 10)
        self.assertIn(f'head_sha={SHA}&branch=main&event=push', requests[0])
        self.assertIn('/actions/runs/10/jobs?', requests[1])

    def test_other_commits_branches_events_and_repositories_are_not_evidence(self):
        for key, value in (('head_sha', 'b'*40), ('head_branch', 'work'),
                           ('event', 'pull_request'), ('event', 'workflow_dispatch'), ('head_repository', {'full_name': 'other/fork'})):
            self.assertIsNone(GATE.inspect_runs([RUN | {key: value}], SHA, REPO))

    def test_latest_failure_cannot_reuse_earlier_success(self):
        for conclusion in ('failure', 'cancelled', 'skipped', 'timed_out', None):
            with self.subTest(conclusion=conclusion), self.assertRaises(RuntimeError):
                GATE.inspect_runs([RUN, RUN | {'id': 11, 'conclusion': conclusion}], SHA, REPO)
        self.assertIsNone(GATE.inspect_runs([RUN, RUN | {'id': 11, 'status': 'in_progress'}], SHA, REPO))

    def test_missing_or_unsuccessful_gate_never_publishes(self):
        for jobs in (JOBS[:-1], JOBS[:-1] + [JOBS[-1] | {'conclusion': 'skipped'}],
                     JOBS[:-1] + [JOBS[-1] | {'status': 'in_progress'}]):
            with self.assertRaises(RuntimeError):
                GATE.verify_jobs(jobs)

    def test_pending_run_has_bounded_wait_then_fails(self):
        times = iter([0, 0, 5, 6])
        sleeps = []
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            GATE.require_acceptance(REPO, SHA, timeout=6,
                                    query=lambda _: {'workflow_runs': []},
                                    clock=lambda: next(times), sleep=sleeps.append)
        self.assertEqual(sleeps, [1])


class AndroidReleaseMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/android-kernelsu-acceptance.yml'
        cls.workflow = yaml.safe_load(workflow.read_text())

    def test_reusable_inputs_keep_versions_optional_and_codes_as_strings(self):
        triggers = self.workflow.get('on', self.workflow.get(True))
        inputs = triggers['workflow_call']['inputs']
        for name in ('source_sha', 'release_version', 'release_version_code'):
            with self.subTest(name=name):
                self.assertEqual(inputs[name]['type'], 'string')
                self.assertEqual(inputs[name]['default'], '')
                self.assertFalse(inputs[name]['required'])
        for event in ('push', 'pull_request', 'merge_group', 'workflow_dispatch'):
            self.assertIn(event, triggers)

    def test_metadata_contracts_run_in_the_uncached_harness(self):
        harness = self.workflow['jobs']['harness']
        checks = next(step for step in harness['steps']
                      if step.get('name') == 'Test simulation safety and workflow wiring')
        self.assertIn('python3 scripts/test-android-release-gate.py', checks['run'].splitlines())
        self.assertNotIn('if', checks)
        self.assertNotIn('continue-on-error', checks)
        self.assertFalse(any('cache' in step.get('uses', '') for step in harness['steps']))

    def test_both_jobs_stamp_after_sha_verification_before_tool_installation(self):
        for job, first_tool_step in (('harness', 'Install workflow test dependency'),
                                     ('android-kernelsu', 'Locate Android SDK tools')):
            with self.subTest(job=job):
                steps = self.workflow['jobs'][job]['steps']
                names = [step['name'] for step in steps]
                self.assertLess(names.index('Checkout repository'), names.index('Verify implementation commit'))
                self.assertLess(names.index('Verify implementation commit'), names.index('Stamp release metadata'))
                self.assertLess(names.index('Stamp release metadata'), names.index(first_tool_step))
                checkout = steps[names.index('Checkout repository')]
                self.assertEqual(checkout['with']['ref'], '${{ inputs.source_sha || github.sha }}')
                self.assertFalse(checkout['with']['persist-credentials'])
                verify = steps[names.index('Verify implementation commit')]
                self.assertEqual(verify['env']['SOURCE_SHA'], '${{ inputs.source_sha || github.sha }}')
                self.assertIn('[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]', verify['run'])
                self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_SHA"', verify['run'])
                stamp = steps[names.index('Stamp release metadata')]
                self.assertEqual(stamp['if'], "${{ inputs.release_version != '' || inputs.release_version_code != '' }}")
                self.assertEqual(stamp['env'], {'RELEASE_VERSION': '${{ inputs.release_version }}',
                                               'RELEASE_VERSION_CODE': '${{ inputs.release_version_code }}'})
                self.assertEqual(stamp['run'], 'python3 scripts/stamp-release.py --version "$RELEASE_VERSION" --version-code "$RELEASE_VERSION_CODE"')
                self.assertNotIn('continue-on-error', stamp)
                self.assertNotIn('continue-on-error', self.workflow['jobs'][job])


if __name__ == '__main__':
    unittest.main()
