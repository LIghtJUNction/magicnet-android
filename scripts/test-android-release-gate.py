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
RESTRICTED_RULES = {
    'NETWORK': '16000: from all fwmark 0x50064/0x5ffff iif lo lookup eth0',
    'SYSTEM': '16000: from all fwmark 0xd0064/0xdffff iif lo lookup eth0',
}


def helper(table):
    return {'rule': f'1: from all lookup {table}', 'table': table,
            'fib': ['local 127.0.0.1 dev eth0 scope host',
                    'local 127.0.0.1 dev wlan0 scope host']}


def udp_result(ok):
    return {'complete': True, 'ok': ok, 'uid': 10123, 'accepted': int(ok),
            'reason': 'sentinel' if ok else 'connect', 'elapsed_ms': 12,
            'transport': 'udp', 'receiver_bound': True, 'receiver_closed': True,
            'request_attempted': True}


def uplink_observation(state):
    return {'state': state.copy(),
            'routes': ['default via 10.0.2.2 dev eth0 table eth0',
                       'default via 192.168.1.1 dev wlan0 table wlan0'],
            'selected_default': True, 'ready': True,
            'tcp': {'called': True, 'result': {
                'complete': True, 'ok': True, 'uid': 10123,
                'reason': 'sentinel', 'accepted': 1, 'elapsed_ms': 12}}}


def eth0_rules(net_id):
    return [f'16000: from all fwmark {0x10000 | net_id:#x}/0x1ffff iif lo lookup eth0',
            f'23000: from all fwmark {net_id:#x}/0x1ffff iif lo lookup eth0']


def eth0_uid_rules(net_id, priority, ranges):
    return [f'{base + priority}: from all fwmark {mark:#x}/0x1ffff '
            f'iif lo uidrange {start}-{end} lookup eth0'
            for start, end in ranges
            for base, mark in ((15000, 0x10000 | net_id), (22000, net_id))]


def netd_state():
    return {'networks': [
                {'net_id': 99, 'type': 'LOCAL', 'interfaces': [],
                 'details': ['Allowed UID ranges: unrestricted']},
                {'net_id': 100, 'type': 'PHYSICAL', 'interfaces': ['eth0'],
                 'details': ['Allowed UID ranges: unrestricted', 'Required permission: NONE']},
                {'net_id': 101, 'type': 'PHYSICAL', 'interfaces': ['wlan0'],
                 'details': ['Allowed UID ranges: unrestricted', 'Required permission: NONE']}],
            'eth0_ifindex': 2,
            'eth0_fib': ['10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15',
                         'default via 10.0.2.2 dev eth0']}


def renumber_eth0(snapshot, net_id):
    network = next(item for item in snapshot['netd']['networks'] if item['interfaces'] == ['eth0'])
    for prefix in (0x10000, 0x50000, 0xd0000, 0):
        old, new = f'fwmark {prefix | network["net_id"]:#x}/', f'fwmark {prefix | net_id:#x}/'
        snapshot['rules'] = [row.replace(old, new) if row.endswith(' lookup eth0') else row
                             for row in snapshot['rules']]
    network['net_id'] = net_id
    snapshot['netd']['networks'].sort(key=lambda item: item['net_id'])


def eth0_uid_metadata(snapshot, allowed, per_app=None):
    details = ['Allowed UID ranges: ' + allowed, 'Required permission: NONE']
    if per_app is not None:
        details.append('Per-app UID ranges: ' + per_app)
    network = next(item for item in snapshot['netd']['networks'] if item['interfaces'] == ['eth0'])
    network['details'] = sorted(details)


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
    unowned = ['0: from all lookup local', *eth0_rules(100)]
    before = {'core_pid': 400, 'core_start_ticks': 10000, 'tun_name': 'magicnet0',
              'tun_ifindex': 9, 'rules': [*unowned, helper(76501405)['rule'], owned],
              'fib': ['default dev magicnet0 scope link'], 'helper': helper(76501405),
              'netd': netd_state()}
    prior = copy.deepcopy(before) | {'core_pid': 300, 'core_start_ticks': 5000, 'tun_ifindex': 8,
                                    'rules': [*unowned, helper(91719807)['rule'], owned],
                                    'helper': helper(91719807)}
    after = copy.deepcopy(before) | {'core_pid': 500, 'core_start_ticks': 15000, 'tun_ifindex': 10,
                                    'rules': [*unowned, helper(259533620)['rule'], owned],
                                    'helper': helper(259533620), 'previous_helper_fib': []}
    previous = {'status': 'present', 'recovery_limit': 3, 'recovery_attempts': 0}
    recovered = {'status': 'present', 'warning': False, 'recovery_status': 'ok',
                 'recovery_limit': 3, 'consecutive_failures': 0,
                 'recovery_attempts': 1, 'last_recovery_at': 100, 'checked_at': 101,
                 'next_check_at': 161, 'retry_in_seconds': 200}
    recovery = {
        'schema': 1, 'status': 'verified', 'scope': 'disposable-android-app-uid-tun',
        'positive': True, 'reject': True, 'positive_after': True, 'restored': True, 'app_uid': 10123,
        'rpdb_loss': {
            'status': 'verified', 'removed_rule_count': 1, 'core_identity_unchanged': True,
            'tun_unchanged': True, 'fib_unchanged': True, 'unowned_rules_unchanged': True,
            'ready_after_fault': False, 'app_after_fault': False,
            'health_after_fault_rpdb_missing': True, 'recovery_entry': 'connectivity.tick',
            'recovery_tick_count': 2, 'ready_after_recovery': True, 'app_after_recovery': True,
            'baseline_app': udp_result(True), 'fault_app': udp_result(False),
            'recovered_app': udp_result(True),
            'owned_rules': [owned], 'before': before,
            'fault': copy.deepcopy(before) | {'rules': [*unowned, before['helper']['rule']]},
            'after': after,
            'helper_lifecycle': {'before_stop': prior,
                                 'stopped': {'core_state': 'stopped', 'rules': unowned.copy(),
                                             'helper_table': prior['helper']['table'], 'helper_fib': []},
                                 'after_start': copy.deepcopy(before)},
            'recovery_before': previous,
            'first_missing': previous | {'status': 'missing', 'consecutive_failures': 1},
            'first_missing_identity': {'core_pid': 400, 'core_start_ticks': 10000},
            'recovery_after': recovered,
        },
        'uplink_reconnect': {'status': 'verified', 'interface': 'wlan0', 'down_observed': True,
                             'up_observed': True, 'ready_after_recovery': True, 'app_after_recovery': True,
                             'control_transport_verified': True, 'control_channel_survived': True,
                             'restore_guard_finished': True, 'restore_method': 'android_wifi_toggle',
                             'down_flags': 4098, 'up_flags': 4163,
                             'baseline': uplink_observation(recovered),
                             'last_observation': uplink_observation(recovered | {'checked_at': 102}),
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


def per_app_report():
    report = completed_report()
    loss = report['provenance']['route_recovery']['rpdb_loss']
    # Netd metadata and per-app selectors observed in Android run 43253655173.
    # The other report fields remain the synthetic complete-gate fixture.
    uid_rules = [
        '15040: from all fwmark 0x10064/0x1ffff iif lo uidrange 10137-10137 lookup eth0',
        '22040: from all fwmark 0x64/0x1ffff iif lo uidrange 10137-10137 lookup eth0',
        '25000: from all fwmark 0x0/0x10000 iif lo uidrange 10137-10137 lookup eth0_local',
        '29040: from all fwmark 0x0/0xffff iif lo uidrange 10137-10137 lookup eth0',
    ]
    for snapshot in (loss['before'], loss['fault'], loss['after'],
                     loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
        eth0_uid_metadata(snapshot, 'uids{ 0-99999 }', 'prio 40 uids{ 10137 }')
        snapshot['netd']['networks'] = [network for network in snapshot['netd']['networks']
                                       if network['interfaces'] != ['wlan0']]
        snapshot['rules'] += uid_rules
    loss['helper_lifecycle']['stopped']['rules'] += uid_rules
    return report


def restricted_report(permission):
    report = per_app_report()
    loss = report['provenance']['route_recovery']['rpdb_loss']
    for snapshot in (loss['before'], loss['fault'], loss['after'],
                     loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
        network = next(item for item in snapshot['netd']['networks'] if item['interfaces'] == ['eth0'])
        network['details'][-1] = 'Required permission: ' + permission
        snapshot['rules'] = [row for row in snapshot['rules'] if row not in eth0_rules(100)]
        snapshot['rules'].append(RESTRICTED_RULES[permission])
    stopped = loss['helper_lifecycle']['stopped']
    stopped['rules'] = [row for row in stopped['rules'] if row not in eth0_rules(100)]
    stopped['rules'].append(RESTRICTED_RULES[permission])
    return report


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

    def test_observed_eth0_netid_change_preserves_other_rules_in_both_lifecycles(self):
        report = completed_report()
        loss = report['provenance']['route_recovery']['rpdb_loss']
        renumber_eth0(loss['helper_lifecycle']['before_stop'], 103)
        renumber_eth0(loss['after'], 102)
        GATE.validate_report(report, SHA)

    def test_observed_per_app_uid_rules_follow_the_proven_netid_change(self):
        report = per_app_report()
        loss = report['provenance']['route_recovery']['rpdb_loss']
        renumber_eth0(loss['helper_lifecycle']['before_stop'], 103)
        renumber_eth0(loss['after'], 101)
        self.assertEqual(dict(GATE.netd_selectors(loss['after'])), {
            '16000: from all fwmark 0x10065/0x1ffff iif lo lookup eth0': 1,
            '23000: from all fwmark 0x65/0x1ffff iif lo lookup eth0': 1,
            '15040: from all fwmark 0x10065/0x1ffff iif lo uidrange 10137-10137 lookup eth0': 1,
            '22040: from all fwmark 0x65/0x1ffff iif lo uidrange 10137-10137 lookup eth0': 1,
        })
        GATE.validate_report(report, SHA)

    def test_known_restricted_permissions_use_exact_explicit_rules_without_global_implicit(self):
        for permission, explicit in RESTRICTED_RULES.items():
            for renumber in (False, True):
                report = restricted_report(permission)
                loss = report['provenance']['route_recovery']['rpdb_loss']
                with self.subTest(permission=permission, renumber=renumber):
                    self.assertEqual(dict(GATE.netd_selectors(loss['before'])), {
                        explicit: 1,
                        '23000: from all fwmark 0x64/0x1ffff iif lo lookup eth0': 0,
                        '15040: from all fwmark 0x10064/0x1ffff iif lo uidrange 10137-10137 lookup eth0': 1,
                        '22040: from all fwmark 0x64/0x1ffff iif lo uidrange 10137-10137 lookup eth0': 1,
                    })
                    if renumber:
                        renumber_eth0(loss['helper_lifecycle']['before_stop'], 103)
                        renumber_eth0(loss['after'], 101)
                    GATE.validate_report(report, SHA)

    def test_restricted_permission_rules_fail_when_missing_duplicated_or_misbound(self):
        for permission, explicit in RESTRICTED_RULES.items():
            for change in ('missing', 'duplicate', 'none-mark', 'mask', 'implicit', 'uid-permission'):
                report = restricted_report(permission)
                loss = report['provenance']['route_recovery']['rpdb_loss']
                for snapshot in (loss['before'], loss['fault'], loss['after'],
                                 loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                    rules = snapshot['rules']
                    if change == 'missing':
                        rules.remove(explicit)
                    elif change == 'duplicate':
                        rules.append(explicit)
                    elif change == 'none-mark':
                        rules[rules.index(explicit)] = eth0_rules(100)[0]
                    elif change == 'mask':
                        rules[rules.index(explicit)] = explicit.split('/')[0] + '/0x1ffff iif lo lookup eth0'
                    elif change == 'implicit':
                        rules.append(eth0_rules(100)[1])
                    else:
                        uid = eth0_uid_rules(100, 40, [(10137, 10137)])[0]
                        rules[rules.index(uid)] = uid.replace('0x10064/0x1ffff',
                                                             explicit.split('fwmark ')[1].split(' ')[0])
                with self.subTest(permission=permission, change=change):
                    self.assert_rejected(report)

    def test_known_permission_changes_still_fail_with_matching_global_rules(self):
        for old_permission in ('NONE', 'NETWORK', 'SYSTEM'):
            for new_permission in ('NONE', 'NETWORK', 'SYSTEM'):
                if old_permission == new_permission:
                    continue
                report = per_app_report() if old_permission == 'NONE' else restricted_report(old_permission)
                after = report['provenance']['route_recovery']['rpdb_loss']['after']
                network = next(item for item in after['netd']['networks'] if item['interfaces'] == ['eth0'])
                network['details'][-1] = 'Required permission: ' + new_permission
                old_rules = eth0_rules(100) if old_permission == 'NONE' else [RESTRICTED_RULES[old_permission]]
                new_rules = eth0_rules(100) if new_permission == 'NONE' else [RESTRICTED_RULES[new_permission]]
                after['rules'] = [row for row in after['rules'] if row not in old_rules] + new_rules
                with self.subTest(old=old_permission, new=new_permission):
                    self.assert_rejected(report)

    def test_permission_metadata_rejects_unknown_tokens_and_wrong_types(self):
        for value in ('Required permission: network', 'Required permission: UNKNOWN',
                      'Required permission: NETWORK|SYSTEM', 'Required permission: 1', True, 1, None):
            report = restricted_report('NETWORK')
            after = report['provenance']['route_recovery']['rpdb_loss']['after']
            network = next(item for item in after['netd']['networks'] if item['interfaces'] == ['eth0'])
            network['details'][-1] = value
            with self.subTest(value=value):
                self.assert_rejected(report)

    def test_per_app_renumbering_rejects_partial_stale_or_altered_selectors(self):
        for stage in ('after', 'before_stop'):
            for change in ('missing-explicit', 'missing-implicit', 'duplicate', 'stale',
                           'uid', 'range', 'priority', 'mask', 'iif', 'table',
                           'foreign-local', 'foreign-default'):
                with self.subTest(stage=stage, change=change):
                    report = per_app_report()
                    loss = report['provenance']['route_recovery']['rpdb_loss']
                    snapshot = loss[stage] if stage in loss else loss['helper_lifecycle'][stage]
                    renumber_eth0(snapshot, 101)
                    explicit, implicit = eth0_uid_rules(101, 40, [(10137, 10137)])
                    rules = snapshot['rules']
                    if change.startswith('missing-'):
                        rules.remove(explicit if change == 'missing-explicit' else implicit)
                    elif change == 'duplicate':
                        rules.append(explicit)
                    elif change == 'stale':
                        rules.append(eth0_uid_rules(100, 40, [(10137, 10137)])[0])
                    elif change.startswith('foreign-'):
                        rules[:] = [row for row in rules if not row.startswith(
                            '25000:' if change == 'foreign-local' else '29040:')]
                    else:
                        old, new = {
                            'uid': ('10137-10137', '10138-10138'),
                            'range': ('10137-10137', '10136-10138'),
                            'priority': ('15040:', '15041:'),
                            'mask': ('/0x1ffff', '/0xffff'),
                            'iif': ('iif lo', 'iif eth0'),
                            'table': ('lookup eth0', 'lookup main'),
                        }[change]
                        rules[rules.index(explicit)] = explicit.replace(old, new)
                    self.assert_rejected(report)

    def test_per_app_metadata_requires_both_rules_even_without_renumbering(self):
        for change in ('missing', 'duplicate', 'no-metadata'):
            with self.subTest(change=change):
                report = per_app_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                for snapshot in (loss['before'], loss['fault'], loss['after'],
                                 loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                    explicit, _ = eth0_uid_rules(100, 40, [(10137, 10137)])
                    if change == 'missing':
                        snapshot['rules'].remove(explicit)
                    elif change == 'duplicate':
                        snapshot['rules'].append(explicit)
                    else:
                        eth0_uid_metadata(snapshot, 'uids{ 0-99999 }')
                if change == 'no-metadata':
                    # Undeclared rows remain foreign: their NetID cannot change.
                    renumber_eth0(loss['after'], 101)
                self.assert_rejected(report)

    def test_per_app_duplicates_need_exact_counts_without_merging_overlaps(self):
        report = completed_report()
        loss = report['provenance']['route_recovery']['rpdb_loss']
        intervals = [(10000, 10000), (10000, 10000), (10000, 10005), (10002, 10002)]
        for snapshot in (loss['before'], loss['fault'], loss['after'],
                         loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
            eth0_uid_metadata(snapshot, 'unrestricted',
                              'prio 0 uids{ 10000 10000 10000-10005 10002 }; prio 999 uids{ }')
            snapshot['rules'] += eth0_uid_rules(100, 0, intervals)
        renumber_eth0(loss['after'], 102)
        selectors = GATE.netd_selectors(loss['after'])
        self.assertEqual(sum(selectors.values()), 10)
        duplicate = eth0_uid_rules(102, 0, [(10000, 10000)])[0]
        self.assertEqual(selectors[duplicate], 2)
        GATE.validate_report(report, SHA)
        loss['after']['rules'].remove(duplicate)
        self.assert_rejected(report)

    def test_stable_canonical_uid_metadata_preserves_full_report_evidence(self):
        for allowed, per_app in (
                ('uids{ }', None), ('uids{ 0 10000 10002-10005 2147483647 }', None),
                ('uids{ 10000 10000 10000-10005 10002 }',
                 'prio 0 uids{ 10000 10000 10000-10005 10002 }; prio 999 uids{ }')):
            for renumber in (False, True):
                with self.subTest(allowed=allowed, per_app=per_app, renumber=renumber):
                    report = completed_report()
                    loss = report['provenance']['route_recovery']['rpdb_loss']
                    for snapshot in (loss['before'], loss['fault'], loss['after'],
                                     loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                        eth0_uid_metadata(snapshot, allowed, per_app)
                        if per_app:
                            snapshot['rules'] += eth0_uid_rules(100, 0,
                                [(10000, 10000), (10000, 10000), (10000, 10005), (10002, 10002)])
                    if renumber:
                        renumber_eth0(loss['helper_lifecycle']['before_stop'], 103)
                        renumber_eth0(loss['after'], 102)
                    GATE.validate_report(report, SHA)

    def test_uid_metadata_rejects_malformed_noncanonical_or_out_of_bounds_values(self):
        invalid = {
            'allowed': ('', 'unknown', 'uids{}', 'uids{ <BAD: 0-1> }', 'uids{ -1 }',
                        'uids{ 01 }', 'uids{ 1-1 }', 'uids{ 2-1 }', 'uids{ 2147483648 }',
                        'uids{ 2 1 }', 'uids{ 1-3 1-2 }'),
            'per_app': ('', 'prio 0 unrestricted', 'prio -1 uids{ }', 'prio 01 uids{ }',
                        'prio 1000 uids{ }', 'prio 0 uids{ <BAD: 0-1> }',
                        'prio 0 uids{ }; prio 0 uids{ }', 'prio 10 uids{ }; prio 0 uids{ }',
                        'prio 0 uids{ };prio 10 uids{ }'),
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    report = completed_report()
                    after = report['provenance']['route_recovery']['rpdb_loss']['after']
                    eth0_uid_metadata(after, value if field == 'allowed' else 'unrestricted',
                                      value if field == 'per_app' else None)
                    self.assert_rejected(report)

    def test_renumbering_never_excuses_eth0_uid_priority_or_permission_changes(self):
        for stage in ('after', 'before_stop'):
            for change in ('allowed', 'uid', 'priority', 'permission'):
                with self.subTest(stage=stage, change=change):
                    report = completed_report()
                    loss = report['provenance']['route_recovery']['rpdb_loss']
                    for snapshot in (loss['before'], loss['fault'], loss['after'],
                                     loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                        eth0_uid_metadata(snapshot, 'uids{ 10000 }', 'prio 0 uids{ 10000 }')
                        snapshot['rules'] += eth0_uid_rules(100, 0, [(10000, 10000)])
                    snapshot = loss[stage] if stage in loss else loss['helper_lifecycle'][stage]
                    renumber_eth0(snapshot, 102)
                    eth0_uid_metadata(snapshot, 'uids{ 10001 }' if change == 'allowed' else 'uids{ 10000 }',
                                      'prio 10 uids{ 10000 }' if change == 'priority' else
                                      'prio 0 uids{ 10001 }' if change == 'uid' else 'prio 0 uids{ 10000 }')
                    if change == 'permission':
                        network = next(item for item in snapshot['netd']['networks'] if item['interfaces'] == ['eth0'])
                        network['details'][-1] = 'Required permission: SYSTEM'
                    self.assert_rejected(report)

    def test_all_running_snapshots_require_independent_netd_evidence(self):
        for name in ('before', 'fault', 'after', 'before_stop', 'after_start'):
            with self.subTest(name=name):
                report = completed_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                snapshot = loss[name] if name in loss else loss['helper_lifecycle'][name]
                snapshot.pop('netd')
                self.assert_rejected(report)

    def test_netd_requires_bounded_unique_typed_inventory_and_bound_eth0_fib(self):
        changes = (
            (('networks',), None), (('networks',), []), (('networks',), [True]),
            (('networks', 1, 'net_id'), True), (('networks', 1, 'net_id'), '100'),
            (('networks', 1, 'net_id'), 0), (('networks', 1, 'net_id'), 65536),
            (('networks', 1, 'net_id'), 99), (('networks', 1, 'type'), 'VIRTUAL'),
            (('networks', 1, 'interfaces'), ['eth0', 'wlan0']),
            (('networks', 1, 'interfaces'), ['eth0', 'eth0']),
            (('networks', 1, 'interfaces'), ['eth0\n']),
            (('networks', 2, 'interfaces'), ['eth0']),
            (('networks', 1, 'details'), []),
            (('networks', 1, 'details'), ['Required permission: NONE']),
            (('networks', 1, 'details'), ['Allowed UID ranges: 10123-10123', 'Required permission: NONE']),
            (('networks', 1, 'details'), ['Required permission: SYSTEM']),
            (('networks', 1, 'details'), ['Required permission: NONE'] * 2),
            (('networks', 0, 'details'), ['Unknown detail: value']),
            (('networks', 0, 'details'), []),
            (('networks', 0, 'details'), ['Allowed UID ranges: unrestricted', 'Allowed UID ranges: uids{ }']),
            (('networks', 0, 'details'), ['Allowed UID ranges: unrestricted', 'Required permission: NONE']),
            (('networks', 2, 'details'), ['Allowed UID ranges: unrestricted']),
            (('networks', 2, 'details'), ['Allowed UID ranges: unrestricted',
                                         'Required permission: NONE', 'Required permission: SYSTEM']),
            (('eth0_ifindex',), True), (('eth0_ifindex',), '2'),
            (('eth0_ifindex',), 0), (('eth0_ifindex',), 0x80000000),
            (('eth0_fib',), None), (('eth0_fib',), []),
            (('eth0_fib',), ['default dev wlan0']),
            (('eth0_fib',), ['default dev eth0 dev wlan0']),
            (('eth0_fib',), ['default dev eth0'] * 2),
            (('eth0_fib',), ['x' * 2049 + ' dev eth0']),
        )
        for path, value in changes:
            with self.subTest(path=path, value=value):
                report = completed_report()
                target = report['provenance']['route_recovery']['rpdb_loss']['after']['netd']
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(report)

    def test_netd_renumbering_cannot_excuse_partial_duplicate_or_unrelated_rules(self):
        for stage in ('after', 'before_stop'):
            for change in ('one-rule', 'duplicate', 'old-rule', 'mask', 'selector', 'foreign'):
                with self.subTest(stage=stage, change=change):
                    report = completed_report()
                    loss = report['provenance']['route_recovery']['rpdb_loss']
                    snapshot = loss[stage] if stage in loss else loss['helper_lifecycle'][stage]
                    renumber_eth0(snapshot, 102)
                    if change == 'one-rule':
                        snapshot['rules'][snapshot['rules'].index(eth0_rules(102)[1])] = eth0_rules(100)[1]
                    elif change == 'duplicate':
                        snapshot['rules'].append(eth0_rules(102)[0])
                    elif change == 'old-rule':
                        snapshot['rules'].append(eth0_rules(100)[0])
                    elif change in ('mask', 'selector'):
                        old, new = ('/0x1ffff', '/0xffff') if change == 'mask' else ('iif lo', 'iif eth0')
                        snapshot['rules'] = [row.replace(old, new) for row in snapshot['rules']]
                    else:
                        snapshot['rules'].append('12000: from all uidrange 1000-1000 lookup main')
                    self.assert_rejected(report)

    def test_eth0_renumbering_preserves_interface_fib_and_every_other_network(self):
        for change in ('ifindex', 'fib', 'permission', 'other-interface', 'other-id', 'old-id', 'occupied-id'):
            with self.subTest(change=change):
                report = completed_report()
                after = report['provenance']['route_recovery']['rpdb_loss']['after']
                renumber_eth0(after, 101 if change == 'occupied-id' else 102)
                observed = after['netd']
                if change == 'ifindex':
                    observed['eth0_ifindex'] = 3
                elif change == 'fib':
                    observed['eth0_fib'] = ['default via 10.0.2.3 dev eth0']
                elif change == 'permission':
                    observed['networks'][1]['details'] = ['Allowed UID ranges: unrestricted',
                                                        'Required permission: SYSTEM']
                elif change == 'other-interface':
                    observed['networks'][1]['interfaces'] = ['wlan1']
                elif change == 'other-id':
                    observed['networks'][1]['net_id'] = 98
                    observed['networks'].sort(key=lambda item: item['net_id'])
                elif change == 'old-id':
                    observed['networks'].append({'net_id': 100, 'type': 'DUMMY', 'interfaces': [],
                                                'details': ['Allowed UID ranges: unrestricted']})
                    observed['networks'].sort(key=lambda item: item['net_id'])
                self.assert_rejected(report)

    def test_netd_changes_during_fault_and_unproven_mark_changes_still_fail(self):
        for change in ('fault', 'no-owner-change', 'same-id-metadata'):
            with self.subTest(change=change):
                report = completed_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                snapshot = loss['fault'] if change == 'fault' else loss['after']
                if change == 'same-id-metadata':
                    snapshot['netd']['networks'][2]['details'] = ['Allowed UID ranges: unrestricted',
                                                               'Required permission: SYSTEM']
                else:
                    renumber_eth0(snapshot, 102)
                    if change == 'no-owner-change':
                        snapshot['netd'] = netd_state()
                self.assert_rejected(report)

    def test_stable_netid_still_requires_both_exact_unique_policy_rules(self):
        for change in ('missing', 'duplicate', 'wrong-mark', 'reserved-id'):
            with self.subTest(change=change):
                report = completed_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                for snapshot in (loss['before'], loss['fault'], loss['after'],
                                 loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                    if change == 'missing':
                        snapshot['rules'].remove(eth0_rules(100)[0])
                    elif change == 'duplicate':
                        snapshot['rules'].append(eth0_rules(100)[0])
                    elif change == 'wrong-mark':
                        snapshot['rules'] = [row.replace('0x10064/', '0x10066/') for row in snapshot['rules']]
                    else:
                        renumber_eth0(snapshot, 98)
                self.assert_rejected(report)

    def test_helper_requires_observed_stop_before_any_new_core_start(self):
        for path, value in (
                (('helper_lifecycle',), None), (('helper_lifecycle', 'before_stop'), None),
                (('helper_lifecycle', 'stopped'), {}), (('helper_lifecycle', 'after_start'), None),
                (('helper_lifecycle', 'stopped', 'core_state'), 'unknown'),
                (('helper_lifecycle', 'stopped', 'core_state'), 'running'),
                (('helper_lifecycle', 'stopped', 'helper_table'), True),
                (('helper_lifecycle', 'stopped', 'helper_table'), 76501405),
                (('helper_lifecycle', 'stopped', 'helper_fib'), None),
                (('helper_lifecycle', 'stopped', 'helper_fib'), helper(91719807)['fib']),
                (('helper_lifecycle', 'stopped', 'rules'), None),
                (('helper_lifecycle', 'stopped', 'rules'), []),
                (('helper_lifecycle', 'stopped', 'rules'), ['1: from all lookup 91719807']),
                (('helper_lifecycle', 'after_start', 'core_pid'), 401),
                (('helper_lifecycle', 'before_stop', 'core_start_ticks'), 10000)):
            with self.subTest(path=path, value=value):
                report = completed_report()
                target = report['provenance']['route_recovery']['rpdb_loss']
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(report)
        report = completed_report()
        lifecycle = report['provenance']['route_recovery']['rpdb_loss']['helper_lifecycle']
        for name in ('before_stop', 'after_start'):
            lifecycle[name]['rules'].remove('0: from all lookup local')
        self.assert_rejected(report)

    def test_helper_must_have_one_exact_rule_and_only_interface_loopback_routes(self):
        for key, value in (
                ('table', True), ('table', '76501405'), ('table', 255),
                ('table', 2022), ('table', 2147483648),
                ('rule', '1: from all fwmark 0x1 lookup 76501405'),
                ('fib', None), ('fib', []), ('fib', ['default dev eth0']),
                ('fib', ['local 127.0.0.2 dev eth0 scope host']),
                ('fib', ['local 127.0.0.0/8 dev eth0 scope host']),
                ('fib', ['local 127.0.0.1 dev lo scope host']),
                ('fib', ['local 127.0.0.1 dev magicnet0 scope host']),
                ('fib', ['local 127.0.0.1 dev eth0 scope link']),
                ('fib', helper(76501405)['fib'] * 2),
                ('fib', ['local 127.0.0.1 dev eth0 scope host',
                         'local 127.0.0.1/32 dev eth0 scope host'])):
            with self.subTest(key=key, value=value):
                report = completed_report()
                report['provenance']['route_recovery']['rpdb_loss']['before']['helper'][key] = value
                self.assert_rejected(report)
        for extra in ('1: from all lookup 76501405', '1: from all lookup 76501406',
                      '1: from all fwmark 0x1 lookup 76501406'):
            with self.subTest(extra=extra):
                report = completed_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                for snapshot in (loss['before'], loss['fault'], loss['after'],
                                 loss['helper_lifecycle']['before_stop'], loss['helper_lifecycle']['after_start']):
                    snapshot['rules'].append(extra)
                self.assert_rejected(report)

    def test_helper_cannot_change_during_fault_or_leave_retired_resources(self):
        for change in ('fault-fib', 'old-rule', 'old-fib', 'unread-old-fib', 'missing-old-fib'):
            with self.subTest(change=change):
                report = completed_report()
                loss = report['provenance']['route_recovery']['rpdb_loss']
                if change == 'fault-fib':
                    loss['fault']['helper']['fib'].pop()
                elif change == 'old-rule':
                    loss['after']['rules'].append(loss['before']['helper']['rule'])
                elif change == 'old-fib':
                    loss['after']['previous_helper_fib'] = loss['before']['helper']['fib']
                elif change == 'unread-old-fib':
                    loss['after']['previous_helper_fib'] = None
                else:
                    loss['after'].pop('previous_helper_fib')
                self.assert_rejected(report)

    def test_calibrated_helper_never_excuses_other_rule_changes(self):
        for snapshot in ('after', 'calibration'):
            for change in ('removed', 'added'):
                with self.subTest(snapshot=snapshot, change=change):
                    report = completed_report()
                    loss = report['provenance']['route_recovery']['rpdb_loss']
                    target = loss['after'] if snapshot == 'after' else loss['helper_lifecycle']['after_start']
                    if change == 'removed':
                        target['rules'].remove('0: from all lookup local')
                    else:
                        target['rules'].append('18000: from all lookup 99999')
                    self.assert_rejected(report)

    def test_random_helper_table_may_be_reused_without_excusing_any_change(self):
        report = completed_report()
        loss = report['provenance']['route_recovery']['rpdb_loss']
        loss['after']['rules'] = loss['before']['rules'].copy()
        loss['after']['helper'] = copy.deepcopy(loss['before']['helper'])
        loss['after']['previous_helper_fib'] = loss['after']['helper']['fib'].copy()
        GATE.validate_report(report, SHA)
        prior = loss['helper_lifecycle']['before_stop']
        prior['rules'] = loss['before']['rules'].copy()
        prior['helper'] = copy.deepcopy(loss['before']['helper'])
        loss['helper_lifecycle']['stopped']['helper_table'] = prior['helper']['table']
        GATE.validate_report(report, SHA)
        loss['after']['helper']['fib'].pop()
        loss['after']['previous_helper_fib'].pop()
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

    def test_all_three_udp_observations_are_required_and_tcp_cannot_substitute(self):
        for name in ('baseline_app', 'fault_app', 'recovered_app'):
            with self.subTest(name=name, change='missing'):
                report = completed_report()
                report['provenance']['route_recovery']['rpdb_loss'].pop(name)
                self.assert_rejected(report)
            for change in ('tcp', 'legacy', 'missing_receiver_bound', 'missing_receiver_closed',
                           'missing_request_attempted'):
                with self.subTest(name=name, change=change):
                    report = completed_report()
                    result = report['provenance']['route_recovery']['rpdb_loss'][name]
                    if change == 'tcp':
                        result['transport'] = 'tcp'
                    elif change == 'legacy':
                        for key in ('transport', 'receiver_bound', 'receiver_closed', 'request_attempted'):
                            result.pop(key)
                    else:
                        result.pop(change.removeprefix('missing_'))
                    self.assert_rejected(report)

    def test_udp_requires_real_requests_ready_receivers_cleanup_and_strict_results(self):
        for name in ('baseline_app', 'fault_app', 'recovered_app'):
            expected = name != 'fault_app'
            for key, value in (
                    ('receiver_bound', False), ('receiver_bound', 1),
                    ('receiver_closed', False), ('receiver_closed', 'true'),
                    ('request_attempted', False), ('request_attempted', 1),
                    ('complete', False), ('complete', 1), ('ok', not expected), ('ok', int(expected)),
                    ('uid', 0), ('uid', 10124), ('uid', True),
                    ('accepted', int(not expected)), ('accepted', expected),
                    ('elapsed_ms', 0), ('elapsed_ms', True), ('elapsed_ms', '12'),
                    ('elapsed_ms', 15001), ('reason', 'receiver_bind'), ('reason', 'receiver_cleanup'),
                    ('reason', 'timeout' if expected else 'sentinel')):
                with self.subTest(name=name, key=key, value=value):
                    report = completed_report()
                    report['provenance']['route_recovery']['rpdb_loss'][name][key] = value
                    self.assert_rejected(report)

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
                           ('down_flags', -2), ('up_flags', -1), ('interface', 'lo'),
                           ('restore_method', None), ('restore_method', 'link_up')):
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
                reconnect = report['provenance']['route_recovery']['uplink_reconnect']
                observed = reconnect['recovery_after']
                observed.update(recovery_attempts=attempts, checked_at=50)
                reconnect['last_observation']['state'] = observed.copy()
                GATE.validate_report(report, SHA)

    def test_uplink_requires_complete_baseline_and_last_observations(self):
        changes = (((), None), (('state',), None), (('state', 'status'), 'unknown'),
                   (('state', 'warning'), True), (('state', 'consecutive_failures'), 1),
                   (('state', 'recovery_attempts'), True), (('state', 'checked_at'), 0),
                   (('state', 'next_check_at'), False), (('state', 'recovery_status'), 'unknown'),
                   (('ready',), None), (('ready',), False), (('ready',), 1))
        for name in ('baseline', 'last_observation'):
            for path, value in changes:
                with self.subTest(name=name, path=path, value=value):
                    report = completed_report()
                    reconnect = report['provenance']['route_recovery']['uplink_reconnect']
                    target = reconnect
                    for key in (name, *path)[:-1]:
                        target = target[key]
                    target[(name, *path)[-1]] = value
                    self.assert_rejected(report)
            report = completed_report()
            report['provenance']['route_recovery']['uplink_reconnect'].pop(name)
            self.assert_rejected(report)

    def test_uplink_recomputes_original_interface_default_in_both_observations(self):
        for name in ('baseline', 'last_observation'):
            for routes in (None, [], ['default via 10.0.2.2 dev eth0'],
                           ['192.168.1.0/24 dev wlan0 scope link'],
                           ['default via 192.168.1.1 dev wlan0 linkdown'],
                           ['default via 192.168.1.1 dev wlan01'],
                           ['default via 192.168.1.1 dev wlan0\n']):
                with self.subTest(name=name, routes=routes):
                    report = completed_report()
                    report['provenance']['route_recovery']['uplink_reconnect'][name]['routes'] = routes
                    self.assert_rejected(report)
            for selected in (False, 1, None):
                report = completed_report()
                report['provenance']['route_recovery']['uplink_reconnect'][name]['selected_default'] = selected
                self.assert_rejected(report)
        report = completed_report()
        report['provenance']['route_recovery']['uplink_reconnect']['interface'] = 'eth0'
        report['provenance']['route_recovery']['uplink_reconnect']['restore_method'] = 'link_up'
        GATE.validate_report(report, SHA)

    def test_uplink_requires_actual_same_uid_tcp_success_before_and_after(self):
        for name in ('baseline', 'last_observation'):
            for tcp in (None, {}, {'called': False, 'reason': 'not_ready'},
                        {'called': True, 'reason': 'probe_error'},
                        {'called': True, 'result': udp_result(True)}):
                with self.subTest(name=name, tcp=tcp):
                    report = completed_report()
                    report['provenance']['route_recovery']['uplink_reconnect'][name]['tcp'] = tcp
                    self.assert_rejected(report)
            for key, value in (('complete', False), ('complete', 1), ('ok', False),
                               ('uid', 0), ('uid', 10124), ('uid', True),
                               ('accepted', 0), ('accepted', True), ('reason', 'timeout'),
                               ('elapsed_ms', 0), ('elapsed_ms', True), ('elapsed_ms', 15001)):
                with self.subTest(name=name, key=key, value=value):
                    report = completed_report()
                    tcp = report['provenance']['route_recovery']['uplink_reconnect'][name]['tcp']
                    tcp['result'][key] = value
                    self.assert_rejected(report)

    def test_uplink_observations_bind_final_state_and_preserve_budget(self):
        report = completed_report()
        reconnect = report['provenance']['route_recovery']['uplink_reconnect']
        reconnect['last_observation']['state']['checked_at'] += 1
        self.assert_rejected(report)
        report = completed_report()
        reconnect = report['provenance']['route_recovery']['uplink_reconnect']
        reconnect['baseline']['state']['recovery_attempts'] = 0
        self.assert_rejected(report)
        reconnect['baseline']['state']['recovery_attempts'] = 2
        self.assert_rejected(report)
        reconnect['last_observation']['state']['recovery_attempts'] = 2
        reconnect['recovery_after']['recovery_attempts'] = 2
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
