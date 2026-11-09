#!/usr/bin/env python3
"""Require complete Android evidence, or a successful run for the release commit."""
import argparse
from collections import Counter
import json
import math
import os
import re
import stat
import subprocess
import time


MAX_REPORT_BYTES = 1024 * 1024
REPORT_SCOPE = 'Android-15-KernelSU-v3.2.0-pinned-kernel-x86_64-standalone-TUN-fixture'
# Independent of the producer: removing a harness phase must not relax the gate.
REQUIRED_PHASES = {
    'environment', 'kernelsu-bootstrap', 'install-before-first-boot',
    'cold-boot', 'app-uid-tun-controls', 'tun-route-recovery',
    'invalid-config-rollback', 'stop-cleanup', 'restart-idempotence',
    'upgrade-preservation', 'disable-reboot', 'enable-reboot', 'uninstall-reboot',
}
REQUIRED_PAYLOADS = {'bin/magicnet-cli', 'bin/sing-box', 'bin/jq', 'bin/yq', 'bin/curl'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def matches(value, expected):
    return isinstance(value, dict) and all(
        type(value.get(key)) is type(item) and value[key] == item
        for key, item in expected.items())


def digest(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def positive_int(value):
    return type(value) is int and value > 0


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate Android evidence JSON key')
        value[key] = item
    return value


def finite_number(text):
    value = float(text)
    require(math.isfinite(value), 'Non-finite Android evidence number')
    return value


def text_rows(value, label):
    require(isinstance(value, list) and len(value) <= 1024
            and all(isinstance(row, str) and re.fullmatch(r'[ -~]{1,1024}', row)
                    and row == ' '.join(row.split()) for row in value),
            'Invalid route recovery ' + label)
    return Counter(value)


def route_snapshot(value):
    require(matches(value, {'tun_name': 'magicnet0'})
            and all(positive_int(value.get(key)) for key in
                    ('core_pid', 'core_start_ticks', 'tun_ifindex')),
            'Route recovery lacks a live core and TUN identity')
    rules = text_rows(value.get('rules'), 'rules')
    fib = text_rows(value.get('fib'), 'FIB')
    require(any(re.search(r'\bdev magicnet0\b', row) for row in fib),
            'Route recovery lacks the live TUN FIB')
    return rules, fib


def route_helper(snapshot, rules):
    helper = snapshot.get('helper')
    require(isinstance(helper, dict) and type(helper.get('table')) is int
            and 255 < helper['table'] <= 0x7fffffff and helper['table'] != 2022,
            'Route helper lacks a valid auxiliary table')
    rule = f"1: from all lookup {helper['table']}"
    require(helper.get('rule') == rule and rules[rule] == 1
            and sum(count for row, count in rules.items() if re.match(r'0*1:', row)) == 1,
            'Route helper is missing, ambiguous or has unknown selectors')
    fib = text_rows(helper.get('fib'), 'helper FIB')
    interfaces = []
    for row, count in fib.items():
        match = re.fullmatch(r'local 127\.0\.0\.1(?:/32)? dev ([a-zA-Z0-9_.-]{1,15}) scope host', row)
        require(match is not None and count == 1 and match[1] not in ('lo', 'magicnet0'),
                'Route helper has an unknown FIB shape')
        interfaces.append(match[1])
    require(bool(interfaces) and len(interfaces) == len(set(interfaces)),
            'Route helper lacks unique interface loopback routes')
    return {'rule': rule, 'table': helper['table'], 'fib': fib}


def validate_helper_lifecycle(loss, before, before_helper):
    lifecycle = loss.get('helper_lifecycle')
    require(isinstance(lifecycle, dict), 'Route helper lacks a stop/start ownership observation')
    prior, stopped, started = (lifecycle.get(name) for name in ('before_stop', 'stopped', 'after_start'))
    prior_rules, _ = route_snapshot(prior)
    started_rules, _ = route_snapshot(started)
    prior_helper = route_helper(prior, prior_rules)
    started_helper = route_helper(started, started_rules)
    require(matches(stopped, {'core_state': 'stopped', 'helper_table': prior_helper['table']}),
            'Route helper ownership lacks a confirmed stopped core')
    stopped_rules = text_rows(stopped.get('rules'), 'stopped rules')
    require(all(rules['0: from all lookup local'] == 1
                for rules in (prior_rules, stopped_rules, started_rules)),
            'Route helper calibration lacks the Android local policy rule')
    require(not any(re.match(r'0*1:', row) for row in stopped_rules)
            and not text_rows(stopped.get('helper_fib'), 'stopped helper FIB'),
            'Route helper survived core stop or its table was not observed empty')
    require(started['core_start_ticks'] > prior['core_start_ticks']
            and all(started[key] == before[key] for key in ('core_pid', 'core_start_ticks', 'tun_ifindex'))
            and started_helper == before_helper
            and prior_rules - Counter([prior_helper['rule']])
            == started_rules - Counter([started_helper['rule']]),
            'Route helper calibration changed other rules or does not describe the fault core')


def validate_route_recovery(evidence):
    require(matches(evidence, {'schema': 1, 'status': 'verified',
                              'scope': 'disposable-android-app-uid-tun',
                              'positive': True, 'reject': True,
                              'positive_after': True, 'restored': True})
            and type(evidence.get('app_uid')) is int and evidence['app_uid'] >= 10000,
            'Application-UID TUN route recovery controls are incomplete')
    loss = evidence.get('rpdb_loss')
    require(matches(loss, {'status': 'verified', 'core_identity_unchanged': True,
                          'tun_unchanged': True, 'fib_unchanged': True,
                          'unowned_rules_unchanged': True, 'ready_after_fault': False,
                          'app_after_fault': False, 'health_after_fault_rpdb_missing': True,
                          'recovery_entry': 'connectivity.tick', 'ready_after_recovery': True,
                          'app_after_recovery': True})
            and positive_int(loss.get('removed_rule_count'))
            and positive_int(loss.get('recovery_tick_count')),
            'RPDB loss or production recovery was not demonstrated')
    app_fault = loss.get('fault_app')
    require(matches(app_fault, {'complete': True, 'ok': False, 'uid': evidence['app_uid'], 'accepted': 0})
            and app_fault.get('reason') in ('connect', 'timeout')
            and positive_int(app_fault.get('elapsed_ms')) and app_fault['elapsed_ms'] <= 15000,
            'RPDB fault lacks a completed application-UID negative control')
    before, fault, after = (loss.get(name) for name in ('before', 'fault', 'after'))
    before_rules, before_fib = route_snapshot(before)
    fault_rules, fault_fib = route_snapshot(fault)
    after_rules, _ = route_snapshot(after)
    before_helper = route_helper(before, before_rules)
    fault_helper = route_helper(fault, fault_rules)
    after_helper = route_helper(after, after_rules)
    validate_helper_lifecycle(loss, before, before_helper)
    require(before_helper == fault_helper, 'RPDB fault changed the core route helper')
    previous_helper_fib = text_rows(after.get('previous_helper_fib'), 'previous helper FIB')
    if before_helper['table'] == after_helper['table']:
        require(after_helper == before_helper and previous_helper_fib == after_helper['fib'],
                'Reused helper table changed without ownership evidence')
    else:
        require(before_helper['rule'] not in after_rules and not previous_helper_fib,
                'Recovery left the previous helper rule or auxiliary table behind')
    owned = text_rows(loss.get('owned_rules'), 'owned rules')
    removed = before_rules - fault_rules
    require(bool(owned) and before_helper['rule'] not in owned
            and not owned - before_rules and not fault_rules - before_rules
            and sum(removed.values()) == loss['removed_rule_count']
            and not removed - owned and before_rules - owned == fault_rules - owned
            and not owned - after_rules
            and before_rules - owned - Counter([before_helper['rule']])
            == after_rules - owned - Counter([after_helper['rule']]),
            'RPDB snapshots do not prove removal and restoration of owned rules')
    identity = ('core_pid', 'core_start_ticks')
    require(all(before[key] == fault[key] for key in (*identity, 'tun_ifindex'))
            and before_fib == fault_fib
            and tuple(after[key] for key in identity) != tuple(before[key] for key in identity)
            and after['core_start_ticks'] > before['core_start_ticks'],
            'RPDB fault changed the core/TUN/FIB, or recovery did not restart the core')
    previous, recovered = loss.get('recovery_before'), loss.get('recovery_after')
    require(matches(previous, {'recovery_limit': 3})
            and previous.get('status') in ('present', 'missing', 'pending')
            and type(previous.get('recovery_attempts')) is int
            and 0 <= previous['recovery_attempts'] < 3
            and matches(recovered, {'status': 'present', 'warning': False,
                                    'recovery_status': 'ok', 'recovery_limit': 3,
                                    'consecutive_failures': 0})
            and type(recovered.get('recovery_attempts')) is int
            and previous['recovery_attempts'] < recovered['recovery_attempts'] <= 3
            and positive_int(recovered.get('last_recovery_at'))
            and positive_int(recovered.get('checked_at')),
            'RPDB recovery lacks a fresh production recovery observation')
    first_missing = loss.get('first_missing')
    require(matches(first_missing, {'status': 'missing', 'consecutive_failures': 1,
                                   'recovery_attempts': previous['recovery_attempts']})
            and matches(loss.get('first_missing_identity'), {key: before[key] for key in identity}),
            'RPDB recovery did not preserve the core after the first missing observation')
    reconnect = evidence.get('uplink_reconnect')
    require(matches(reconnect, {'status': 'verified', 'down_observed': True,
                               'up_observed': True, 'ready_after_recovery': True,
                               'app_after_recovery': True, 'control_transport_verified': True,
                               'control_channel_survived': True, 'restore_guard_finished': True})
            and reconnect.get('interface') in ('wlan0', 'eth0')
            and all(type(reconnect.get(key)) is int and reconnect[key] >= 0
                    for key in ('down_flags', 'up_flags'))
            and reconnect['down_flags'] & 1 == 0 and reconnect['up_flags'] & 1 == 1,
            'Local uplink reconnect was not verified')
    uplink = reconnect.get('recovery_after')
    require(matches(uplink, {'status': 'present', 'warning': False,
                            'consecutive_failures': 0, 'recovery_limit': 3})
            and type(uplink.get('recovery_attempts')) is int
            and recovered['recovery_attempts'] <= uplink['recovery_attempts'] <= 3
            and positive_int(uplink.get('checked_at')),
            'Local uplink reconnect lacks a production route observation')


def validate_report(report, sha):
    require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha),
            'Invalid implementation commit')
    require(matches(report, {'schema': 1, 'status': 'passed', 'scope': REPORT_SCOPE}),
            'Android lifecycle report did not pass the required scope')
    cases = report.get('cases')
    require(isinstance(cases, list) and len(cases) == len(REQUIRED_PHASES)
            and all(isinstance(case, dict) and isinstance(case.get('name'), str)
                    for case in cases)
            and {case['name'] for case in cases} == REQUIRED_PHASES,
            'Android lifecycle phases are missing, duplicated or unknown')
    for case in cases:
        seconds = case.get('seconds')
        require(case.get('status') == 'passed' and type(seconds) in (int, float)
                and 0 <= seconds <= 5400 and 'reason' not in case,
                'Android lifecycle phase lacks a completed observation: ' + case['name'])
    provenance = report.get('provenance')
    require(matches(provenance, {'schema': 1, 'scope': 'disposable-x86_64-avd-only',
                                'source_sha': sha}), 'Android evidence source identity mismatch')
    require(all(digest(provenance.get(key)) for key in ('production_zip_sha256', 'fixture_zip_sha256')),
            'Android package identity is missing')
    payloads = provenance.get('payload_sha256')
    require(isinstance(payloads, dict) and REQUIRED_PAYLOADS <= payloads.keys()
            and all(digest(value) for value in payloads.values()),
            'Android runtime payload identity is missing')
    metadata = provenance.get('metadata_sha256')
    require(isinstance(metadata, dict) and digest(metadata.get('licenses/curl/build-provenance.json')),
            'Android production curl metadata is missing')
    require(matches(provenance.get('device'), {'sdk': 35}), 'Android SDK evidence is missing')
    kernelsu = provenance.get('kernelsu')
    require(matches(kernelsu, {'mode': 'pinned-kernel-userspace-late-load'})
            and isinstance(kernelsu.get('kernel_version'), str)
            and re.fullmatch(r'Kernel Version: [1-9][0-9]*', kernelsu['kernel_version'])
            and isinstance(kernelsu.get('kmi'), str) and 0 < len(kernelsu['kmi']) <= 128,
            'Native KernelSU identity is missing')
    reboots = provenance.get('reboot_checks')
    require(isinstance(reboots, list) and 5 <= len(reboots) <= 16,
            'Android lifecycle reboot evidence is incomplete')
    for reboot in reboots:
        require(matches(reboot, {'status': 'passed', 'new_boot_observed': True,
                                'root_verified': True, 'selinux_enforcing': True,
                                'kernelsu_reactivation': 'verified_native_init'}),
                'Android reboot lacks native KernelSU evidence')
        native = reboot.get('kernelsu_native_boot')
        require(matches(native, {'mode': 'pinned-kernel-native-init', 'kernel_interface': True,
                                 'domain_verified': True, 'selinux_enforcing': True,
                                 'busybox_verified': True})
                and matches(native.get('stages'), {stage: 'passed' for stage in
                            ('post-fs-data', 'services', 'boot-completed')}),
                'KernelSU native init did not complete')
    validate_route_recovery(provenance.get('route_recovery'))
    return report


def require_report(path, sha):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                'Android evidence must be a regular file')
        data = stream.read(MAX_REPORT_BYTES + 1)
    require(0 < len(data) <= MAX_REPORT_BYTES, 'Android evidence exceeds the report budget')
    report = json.loads(data, object_pairs_hook=unique_keys,
                        parse_float=finite_number, parse_constant=finite_number)
    return validate_report(report, sha)


def api(path):
    result = subprocess.run(['gh', 'api', path], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Unable to read Android acceptance from GitHub')
    return json.loads(result.stdout)


def inspect_runs(runs, sha, repository):
    matching = [run for run in runs
                if run.get('head_sha') == sha and run.get('head_branch') == 'main'
                and run.get('event') == 'push'
                and run.get('head_repository', {}).get('full_name') == repository]
    if not matching:
        return None
    run = max(matching, key=lambda item: item['id'])
    if run.get('status') != 'completed':
        return None
    if run.get('conclusion') != 'success':
        raise RuntimeError('Android acceptance failed for the release commit')
    return run['id']


def verify_jobs(jobs):
    required = {'Simulation harness contracts', 'Android 15 / KernelSU / x86_64',
                'Android Simulation Gate'}
    found = set()
    for job in jobs:
        if job.get('name') in required:
            if job.get('status') != 'completed' or job.get('conclusion') != 'success':
                raise RuntimeError('A required Android acceptance job did not succeed')
            found.add(job['name'])
    if found != required:
        raise RuntimeError('Required Android acceptance jobs are missing')


def require_acceptance(repository, sha, *, timeout=5100, query=api,
                       clock=time.monotonic, sleep=time.sleep):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid repository identity')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Invalid release commit')
    deadline = clock() + timeout
    path = (f'repos/{repository}/actions/workflows/android-kernelsu-acceptance.yml/runs'
            f'?head_sha={sha}&branch=main&event=push&per_page=100')
    while clock() < deadline:
        run_id = inspect_runs(query(path)['workflow_runs'], sha, repository)
        if run_id is not None:
            verify_jobs(query(f'repos/{repository}/actions/runs/{run_id}/jobs?per_page=100')['jobs'])
            print(f'Android acceptance succeeded for {sha}: run {run_id}', flush=True)
            return run_id
        print('Waiting for Android acceptance of the release commit', flush=True)
        sleep(min(30, max(0, deadline - clock())))
    raise RuntimeError('Android acceptance did not complete before the release deadline')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', help='Validate the completed local simulation report')
    parser.add_argument('--source-sha', help='Exact implementation commit required by --report')
    args = parser.parse_args()
    if (args.report is None) != (args.source_sha is None):
        parser.error('--report and --source-sha must be supplied together')
    try:
        if args.report is not None:
            require_report(args.report, args.source_sha)
            print(f'Android lifecycle and route recovery evidence verified for {args.source_sha}', flush=True)
        else:
            require_acceptance(os.environ['GITHUB_REPOSITORY'], os.environ['RELEASE_COMMIT_SHA'])
    except (KeyError, ValueError, RuntimeError, OSError, RecursionError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'::error::{error}') from error
