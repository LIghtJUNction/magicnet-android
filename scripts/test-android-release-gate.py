#!/usr/bin/env python3
"""Publication must not reuse an old, PR-only, failed or incomplete Android run."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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


def completed_report():
    phases = (
        'environment', 'kernelsu-bootstrap', 'install-before-first-boot', 'cold-boot',
        'app-uid-tun-controls', 'tun-route-recovery', 'invalid-config-rollback',
        'stop-cleanup', 'restart-idempotence', 'upgrade-preservation',
        'disable-reboot', 'enable-reboot', 'uninstall-reboot',
    )
    native = {'mode': 'pinned-kernel-native-init', 'kernel_interface': True,
              'domain_verified': True, 'selinux_enforcing': True, 'busybox_verified': True,
              'stages': {name: 'passed' for name in ('post-fs-data', 'services', 'boot-completed')}}
    reboot = {'status': 'passed', 'new_boot_observed': True, 'root_verified': True,
              'selinux_enforcing': True, 'kernelsu_reactivation': 'verified_native_init',
              'kernelsu_native_boot': native}
    owned = '9000: from all iif lo lookup 2022'
    unowned = '0: from all lookup local'
    before = {'core_pid': 400, 'core_start_ticks': 10000, 'tun_name': 'magicnet0',
              'tun_ifindex': 9, 'rules': [unowned, owned], 'fib': ['default dev magicnet0 scope link']}
    previous = {'status': 'present', 'recovery_limit': 3, 'recovery_attempts': 0}
    recovered = {'status': 'present', 'warning': False, 'recovery_status': 'ok',
                 'recovery_limit': 3, 'consecutive_failures': 0,
                 'recovery_attempts': 1, 'last_recovery_at': 100, 'checked_at': 101}
    recovery = {
        'schema': 1, 'status': 'verified', 'scope': 'disposable-android-app-uid-tun',
        'positive': True, 'reject': True, 'positive_after': True, 'restored': True, 'app_uid': 10123,
        'rpdb_loss': {
            'status': 'verified', 'removed_rule_count': 1, 'core_identity_unchanged': True,
            'tun_unchanged': True, 'fib_unchanged': True, 'unowned_rules_unchanged': True,
            'ready_after_fault': False, 'app_after_fault': False,
            'health_after_fault_rpdb_missing': True, 'recovery_entry': 'connectivity.tick',
            'recovery_tick_count': 2, 'ready_after_recovery': True, 'app_after_recovery': True,
            'fault_app': {'complete': True, 'ok': False, 'uid': 10123, 'accepted': 0,
                          'reason': 'connect', 'elapsed_ms': 12},
            'owned_rules': [owned], 'before': before,
            'fault': copy.deepcopy(before) | {'rules': [unowned]},
            'after': copy.deepcopy(before) | {'core_pid': 500, 'core_start_ticks': 15000, 'tun_ifindex': 10},
            'recovery_before': previous,
            'first_missing': previous | {'status': 'missing', 'consecutive_failures': 1},
            'first_missing_identity': {'core_pid': 400, 'core_start_ticks': 10000},
            'recovery_after': recovered,
        },
        'uplink_reconnect': {'status': 'verified', 'interface': 'wlan0', 'down_observed': True,
                             'up_observed': True, 'ready_after_recovery': True, 'app_after_recovery': True,
                             'control_transport_verified': True, 'control_channel_survived': True,
                             'restore_guard_finished': True,
                             'down_flags': 4098, 'up_flags': 4163,
                             'recovery_after': recovered | {'checked_at': 102}},
    }
    return {
        'schema': 1, 'status': 'passed',
        'scope': 'Android-15-KernelSU-v3.2.0-pinned-kernel-x86_64-standalone-TUN-fixture',
        'cases': [{'name': name, 'status': 'passed', 'seconds': 1.25} for name in phases],
        'provenance': {
            'schema': 1, 'scope': 'disposable-x86_64-avd-only', 'source_sha': SHA,
            'production_zip_sha256': 'b' * 64, 'fixture_zip_sha256': 'c' * 64,
            'payload_sha256': {name: 'd' * 64 for name in
                              ('bin/magicnet-cli', 'bin/sing-box', 'bin/jq', 'bin/yq', 'bin/curl')},
            'metadata_sha256': {'licenses/curl/build-provenance.json': 'e' * 64},
            'device': {'sdk': 35},
            'kernelsu': {'mode': 'pinned-kernel-userspace-late-load', 'kmi': 'android14-6.1',
                        'kernel_version': 'Kernel Version: 32317'},
            'reboot_checks': [copy.deepcopy(reboot) for _ in range(5)], 'route_recovery': recovery,
        },
    }


class AndroidReportGateTests(unittest.TestCase):
    def assert_rejected(self, report):
        with self.assertRaises((RuntimeError, ValueError)):
            GATE.validate_report(report, SHA)

    def test_complete_current_local_evidence_is_accepted(self):
        report = completed_report()
        self.assertIs(GATE.validate_report(report, SHA), report)

    def test_missing_duplicate_unrun_or_legacy_phase_never_passes(self):
        for change in ('missing', 'duplicate', 'legacy', 'failed', 'not_run', 'skipped', 'zero-proof'):
            with self.subTest(change=change):
                report = completed_report()
                cases = report['cases']
                if change == 'missing':
                    cases.pop()
                elif change == 'duplicate':
                    cases[-1] = cases[0].copy()
                elif change == 'legacy':
                    report['cases'] = [case for case in cases if case['name'] != 'tun-route-recovery']
                elif change == 'zero-proof':
                    cases[0].pop('seconds')
                else:
                    cases[0]['status'] = change
                self.assert_rejected(report)
        for cases in (None, {}, [True], [{'name': []}]):
            report = completed_report()
            report['cases'] = cases
            self.assert_rejected(report)
        for seconds in (True, None, '1', -1, float('nan'), float('inf'), 5401):
            report = completed_report()
            report['cases'][0]['seconds'] = seconds
            self.assert_rejected(report)

    def test_report_identity_requires_strict_versions_current_source_and_payloads(self):
        changes = (
            (('schema',), True), (('scope',), 'host-fixture'), (('status',), 'skipped'),
            (('provenance', 'schema'), True), (('provenance', 'source_sha'), 'b' * 40),
            (('provenance', 'scope'), 'mock'), (('provenance', 'production_zip_sha256'), None),
            (('provenance', 'fixture_zip_sha256'), 'local'),
            (('provenance', 'payload_sha256'), {'bin/sing-box': 'd' * 64}),
            (('provenance', 'payload_sha256', 'bin/sing-box'), ''),
            (('provenance', 'metadata_sha256'), {}), (('provenance', 'device', 'sdk'), '35'),
            (('provenance', 'kernelsu', 'mode'), 'stub'),
            (('provenance', 'kernelsu', 'kernel_version'), 'unknown'),
        )
        for path, value in changes:
            with self.subTest(path=path, value=value):
                report = completed_report()
                target = report
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(report)
        for sha in ('local', 'A' * 40, '', None, True):
            with self.subTest(sha=sha), self.assertRaises(RuntimeError):
                GATE.validate_report(completed_report(), sha)

    def test_all_reboots_need_actual_native_init_and_enforcement(self):
        for change in ('missing', 'short', 'root', 'domain', 'stage', 'replayed'):
            with self.subTest(change=change):
                report = completed_report()
                boots = report['provenance']['reboot_checks']
                if change == 'missing':
                    report['provenance'].pop('reboot_checks')
                elif change == 'short':
                    boots.pop()
                elif change == 'root':
                    boots[0]['root_verified'] = 'true'
                elif change == 'domain':
                    boots[-1]['kernelsu_native_boot']['domain_verified'] = 1
                elif change == 'stage':
                    boots[-1]['kernelsu_native_boot']['stages']['services'] = 'pending'
                else:
                    boots[-1]['kernelsu_reactivation'] = 'replayed_late_load'
                self.assert_rejected(report)

    def test_every_route_control_requires_boolean_evidence(self):
        template = completed_report()['provenance']['route_recovery']
        for section, fields in ((None, template), ('rpdb_loss', template['rpdb_loss']),
                                ('uplink_reconnect', template['uplink_reconnect'])):
            for key, expected in fields.items():
                if type(expected) is not bool:
                    continue
                for value in (not expected, str(expected).lower(), int(expected), None):
                    with self.subTest(section=section, key=key, value=value):
                        report = completed_report()
                        evidence = report['provenance']['route_recovery']
                        target = evidence if section is None else evidence[section]
                        target[key] = value
                        self.assert_rejected(report)

    def test_claimed_success_cannot_replace_actual_fault_snapshots(self):
        changes = (
            (('removed_rule_count',), 0), (('removed_rule_count',), True),
            (('removed_rule_count',), 2), (('owned_rules',), []),
            (('fault', 'rules'), completed_report()['provenance']['route_recovery']['rpdb_loss']['before']['rules']),
            (('fault', 'rules'), []), (('fault', 'rules'), ['0: from all lookup other']),
            (('fault', 'core_pid'), 401), (('fault', 'core_start_ticks'), 9999),
            (('fault', 'tun_ifindex'), 10), (('fault', 'fib'), ['default dev magicnet0 metric 10']),
            (('after', 'rules'), ['0: from all lookup local']),
            (('after', 'rules'), ['9000: from all iif lo lookup 2022']),
            (('after', 'rules'), ['0: from all lookup main', '9000: from all iif lo lookup 2022']),
            (('after', 'core_pid'), 400), (('after', 'core_start_ticks'), 10000),
            (('after', 'tun_name'), 'tun0'), (('before', 'core_pid'), True),
            (('before', 'fib'), []), (('before', 'rules'), '9000: from all lookup 2022'),
            (('fault',), None), (('after',), {}),
        )
        for path, value in changes:
            with self.subTest(path=path, value=value):
                report = completed_report()
                target = report['provenance']['route_recovery']['rpdb_loss']
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                # PID reuse alone is legitimate; changing both identity fields is not.
                if path == ('after', 'core_pid'):
                    target['core_start_ticks'] = 10000
                self.assert_rejected(report)

    def test_rule_snapshots_preserve_duplicate_foreign_rules(self):
        report = completed_report()
        loss = report['provenance']['route_recovery']['rpdb_loss']
        for name in ('before', 'fault', 'after'):
            loss[name]['rules'].append('0: from all lookup local')
        GATE.validate_report(report, SHA)
        loss['after']['rules'].remove('0: from all lookup local')
        self.assert_rejected(report)

    def test_manual_restart_stale_state_or_single_failure_is_not_recovery(self):
        changes = (
            (('recovery_entry',), 'service.restart'), (('recovery_tick_count',), 0),
            (('recovery_tick_count',), True), (('recovery_before', 'recovery_attempts'), True),
            (('recovery_after', 'recovery_attempts'), 0), (('recovery_after', 'recovery_attempts'), 4),
            (('recovery_after', 'status'), 'unknown'), (('recovery_after', 'recovery_status'), 'pending'),
            (('recovery_after', 'warning'), 0), (('recovery_after', 'recovery_limit'), 4),
            (('recovery_after', 'checked_at'), 0), (('recovery_after', 'last_recovery_at'), None),
            (('first_missing', 'consecutive_failures'), 0), (('first_missing', 'consecutive_failures'), True),
            (('first_missing', 'recovery_attempts'), 1), (('first_missing_identity', 'core_pid'), 500),
        )
        for path, value in changes:
            with self.subTest(path=path, value=value):
                report = completed_report()
                target = report['provenance']['route_recovery']['rpdb_loss']
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(report)

    def test_completed_app_timeout_is_evidence_but_unfinished_or_wrong_uid_is_not(self):
        report = completed_report()
        fault = report['provenance']['route_recovery']['rpdb_loss']['fault_app']
        fault.update(reason='timeout', elapsed_ms=5000)
        GATE.validate_report(report, SHA)
        for key, value in (('complete', False), ('complete', 'true'), ('ok', True), ('ok', 0),
                           ('uid', 0), ('uid', 10124), ('accepted', 1), ('accepted', False),
                           ('reason', 'adb_timeout'), ('elapsed_ms', None), ('elapsed_ms', True),
                           ('elapsed_ms', 0), ('elapsed_ms', 15001)):
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(report)
                bad['provenance']['route_recovery']['rpdb_loss']['fault_app'][key] = value
                self.assert_rejected(bad)

    def test_wall_clock_adjustment_does_not_erase_proven_monotonic_recovery(self):
        report = completed_report()
        report['provenance']['route_recovery']['rpdb_loss']['recovery_after']['checked_at'] = 50
        GATE.validate_report(report, SHA)

    def test_missing_skipped_or_root_uid_fault_evidence_never_passes(self):
        for key, value in (('schema', True), ('status', 'skipped'), ('scope', 'host'),
                           ('app_uid', 0), ('app_uid', True), ('rpdb_loss', None),
                           ('uplink_reconnect', {'status': 'skipped'})):
            with self.subTest(key=key, value=value):
                report = completed_report()
                report['provenance']['route_recovery'][key] = value
                self.assert_rejected(report)
        report = completed_report()
        report['provenance'].pop('route_recovery')
        self.assert_rejected(report)

    def test_uplink_requires_observed_kernel_link_flags(self):
        for key, value in (('down_flags', None), ('down_flags', False), ('down_flags', 1),
                           ('up_flags', None), ('up_flags', True), ('up_flags', 0),
                           ('down_flags', -2), ('up_flags', -1), ('interface', 'lo')):
            with self.subTest(key=key, value=value):
                report = completed_report()
                report['provenance']['route_recovery']['uplink_reconnect'][key] = value
                self.assert_rejected(report)

    def test_uplink_requires_present_production_observation_with_preserved_budget(self):
        report = completed_report()
        report['provenance']['route_recovery']['uplink_reconnect'].pop('recovery_after')
        self.assert_rejected(report)
        for key, value in (('status', 'missing'), ('status', 'unknown'), ('status', 'stale'),
                           ('warning', True), ('warning', 0), ('consecutive_failures', 1),
                           ('consecutive_failures', False), ('recovery_limit', 4),
                           ('recovery_attempts', 0), ('recovery_attempts', 4),
                           ('recovery_attempts', True), ('recovery_attempts', '1'),
                           ('checked_at', None), ('checked_at', 0), ('checked_at', True)):
            with self.subTest(key=key, value=value):
                report = completed_report()
                report['provenance']['route_recovery']['uplink_reconnect']['recovery_after'][key] = value
                self.assert_rejected(report)

    def test_uplink_can_recover_without_another_restart_or_use_remaining_budget(self):
        for attempts in (1, 2, 3):
            with self.subTest(attempts=attempts):
                report = completed_report()
                observed = report['provenance']['route_recovery']['uplink_reconnect']['recovery_after']
                observed.update(recovery_attempts=attempts, checked_at=50)
                GATE.validate_report(report, SHA)

    def test_report_reader_is_bounded_and_rejects_ambiguous_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'simulation.json'
            path.write_text(json.dumps(completed_report()))
            self.assertEqual(GATE.require_report(path, SHA)['status'], 'passed')
            for payload in ('', '{"schema":1,"schema":1}', '{"value":NaN}', '{"value":1e9999}',
                            '[' * 10000, ' ' * (GATE.MAX_REPORT_BYTES + 1)):
                with self.subTest(payload=payload[:80]):
                    path.write_text(payload)
                    with self.assertRaises((ValueError, RuntimeError, RecursionError)):
                        GATE.require_report(path, SHA)
            link = Path(directory) / 'linked.json'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                GATE.require_report(link, SHA)
            fifo = Path(directory) / 'pipe.json'
            os.mkfifo(fifo)
            with self.assertRaises(RuntimeError):
                GATE.require_report(fifo, SHA)

    def test_cli_report_mode_requires_both_arguments_and_exits_nonzero_on_missing_evidence(self):
        script = str(Path(__file__).with_name('require-android-acceptance.py'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'simulation.json'
            path.write_text(json.dumps(completed_report()))
            valid = [sys.executable, script, '--report', str(path), '--source-sha', SHA]
            accepted = subprocess.run(valid, capture_output=True, text=True, timeout=5)
            self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
            self.assertIn(SHA, accepted.stdout)
            path.unlink()
            for args in (valid, valid[:-2], [sys.executable, script, '--source-sha', SHA]):
                rejected = subprocess.run(args, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)


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
