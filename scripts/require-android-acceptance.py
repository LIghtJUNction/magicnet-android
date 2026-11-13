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
NETD_PERMISSIONS = {'NONE': 0, 'NETWORK': 0x40000, 'SYSTEM': 0xc0000}


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


def canonical_uid_ranges(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    if value == 'uids{ }':
        return True
    match = re.fullmatch(r'uids\{ (.+) \}', value)
    if not match:
        return False
    ranges = []
    for token in match[1].split(' '):
        item = re.fullmatch(r'(0|[1-9][0-9]{0,9})(?:-(0|[1-9][0-9]{0,9}))?', token)
        if not item:
            return False
        start, end = int(item[1]), int(item[2] or item[1])
        if not start <= end <= 0x7fffffff or (item[2] is not None and start == end):
            return False
        ranges.append((start, end))
    return ranges == sorted(ranges)


def canonical_per_app_ranges(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    previous = -1
    for section in value.split('; '):
        match = re.fullmatch(r'prio (0|[1-9][0-9]{0,2}) (uids\{.*\})', section)
        if not match or int(match[1]) <= previous or not canonical_uid_ranges(match[2]):
            return False
        previous = int(match[1])
    return True


def netd_networks(networks):
    require(isinstance(networks, list) and 1 <= len(networks) <= 256,
            'Invalid netd network inventory')
    ids = []
    for network in networks:
        require(isinstance(network, dict)
                and network.keys() == {'net_id', 'type', 'interfaces', 'details'}
                and type(network['net_id']) is int and 1 <= network['net_id'] <= 65535
                and isinstance(network['type'], str)
                and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}', network['type']),
                'Invalid netd network identity')
        interfaces, details = network['interfaces'], network['details']
        require(isinstance(interfaces, list) and len(interfaces) <= 64
                and all(isinstance(item, str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', item)
                        for item in interfaces)
                and interfaces == sorted(set(interfaces)),
                'Invalid or ambiguous netd interface inventory')
        require(isinstance(details, list) and len(details) <= 64
                and all(isinstance(item, str) and len(item) <= 2048
                        and re.fullmatch(r'(Required permission|Per-app UID ranges|Allowed UID ranges): [ -~]+', item)
                        and item == ' '.join(item.split()) for item in details)
                and details == sorted(set(details)),
                'Invalid or ambiguous netd network details')
        fields = [item.split(':', 1)[0] for item in details]
        require(len(fields) == len(set(fields)) and 'Allowed UID ranges' in fields
                and ('Required permission' in fields) == (network['type'] == 'PHYSICAL'),
                'Incomplete or repeated netd network metadata')
        ids.append(network['net_id'])
    require(ids == sorted(set(ids)), 'Unordered or repeated netd network identities')
    return networks


def netd_ethernet(networks):
    ethernet = [network for network in networks if 'eth0' in network['interfaces']]
    require(len(ethernet) == 1 and ethernet[0]['net_id'] >= 100
            and ethernet[0]['type'] == 'PHYSICAL' and ethernet[0]['interfaces'] == ['eth0'],
            'Netd does not prove one physical eth0 network')
    details = dict(item.split(': ', 1) for item in ethernet[0]['details'])
    require(details.get('Required permission') in NETD_PERMISSIONS,
            'Netd eth0 permission is not a known Android permission')
    allowed, per_app = details['Allowed UID ranges'], details.get('Per-app UID ranges')
    require((allowed == 'unrestricted' or canonical_uid_ranges(allowed))
            and (per_app is None or canonical_per_app_ranges(per_app)),
            'Netd eth0 UID metadata is not canonical')
    return ethernet[0]


def netd_observation(snapshot):
    observed = snapshot.get('netd')
    require(isinstance(observed, dict)
            and observed.keys() == {'networks', 'eth0_ifindex', 'eth0_fib'},
            'Route snapshot lacks complete netd ownership evidence')
    ethernet = netd_ethernet(netd_networks(observed['networks']))
    fib = observed['eth0_fib']
    require(type(observed['eth0_ifindex']) is int and 1 <= observed['eth0_ifindex'] <= 0x7fffffff
            and isinstance(fib, list) and 1 <= len(fib) <= 256
            and all(isinstance(row, str) and re.fullmatch(r'[ -~]{1,2048}', row)
                    and row == ' '.join(row.split()) and row.split().count('dev') == 1
                    and re.search(r'(?:^| )dev eth0(?: |$)', row) for row in fib)
            and fib == sorted(set(fib)),
            'Netd eth0 identity or complete interface FIB is unavailable')
    return ethernet['net_id']


def netd_selectors(snapshot):
    net_id = netd_observation(snapshot)
    network = next(item for item in snapshot['netd']['networks'] if item['net_id'] == net_id)
    details = dict(item.split(': ', 1) for item in network['details'])
    permission = NETD_PERMISSIONS[details['Required permission']]
    selectors = Counter({
        f'16000: from all fwmark {permission | 0x10000 | net_id:#x}/'
        f'{permission | 0x1ffff:#x} iif lo lookup eth0': 1,
        # RouteController omits the global implicit rule for restricted networks.
        f'23000: from all fwmark {net_id:#x}/0x1ffff iif lo lookup eth0': int(permission == 0),
    })
    # Android 15 RouteController::modifyPhysicalNetwork installs explicit and
    # implicit UID rules for every range at its subpriority. UidRanges retains
    # duplicates and overlaps, so completeness includes their multiplicities.
    for priority, ranges in re.findall(r'prio ([0-9]+) uids\{([^}]*)\}',
                                       details.get('Per-app UID ranges', '')):
        for interval in ranges.split():
            start, _, end = interval.partition('-')
            uid = f'{start}-{end or start}'
            for base, mark in ((15000, 0x10000 | net_id), (22000, net_id)):
                selectors[f'{base + int(priority)}: from all fwmark {mark:#x}/0x1ffff '
                          f'iif lo uidrange {uid} lookup eth0'] += 1
    return selectors


def foreign_rules_preserved(before, after, before_rules, after_rules):
    old_id, new_id = netd_observation(before), netd_observation(after)
    old, new = before['netd'], after['netd']
    selectors = [netd_selectors(before), netd_selectors(after)]
    require(all(rules[row] == count for rules, expected in zip((before_rules, after_rules), selectors)
                for row, count in expected.items()),
            'Netd identity lacks its exact complete eth0 policy rules')
    if old_id == new_id:
        require(old == new, 'Unchanged netd identity has changed network metadata')
        return before_rules == after_rules
    old_network = next(item for item in old['networks'] if item['net_id'] == old_id)
    new_network = next(item for item in new['networks'] if item['net_id'] == new_id)
    require(old['eth0_ifindex'] == new['eth0_ifindex'] and old['eth0_fib'] == new['eth0_fib']
            and (old_network | {'net_id': new_id}) == new_network
            and old_id not in [item['net_id'] for item in new['networks']]
            and new_id not in [item['net_id'] for item in old['networks']]
            and [item for item in old['networks'] if item['net_id'] != old_id]
            == [item for item in new['networks'] if item['net_id'] != new_id],
            'Netd change is not confined to a new eth0 network identity')
    # Only unchanged netd metadata authorizes NetID changes in these complete
    # selectors. UID default/local rules and all other rows remain protected.
    return before_rules - selectors[0] == after_rules - selectors[1]


def route_snapshot(value):
    require(matches(value, {'tun_name': 'magicnet0'})
            and all(positive_int(value.get(key)) for key in
                    ('core_pid', 'core_start_ticks', 'tun_ifindex')),
            'Route recovery lacks a live core and TUN identity')
    rules = text_rows(value.get('rules'), 'rules')
    fib = text_rows(value.get('fib'), 'FIB')
    require(any(re.search(r'\bdev magicnet0\b', row) for row in fib),
            'Route recovery lacks the live TUN FIB')
    require(all(rules[row] == count for row, count in netd_selectors(value).items()),
            'Route snapshot lacks the observed netd eth0 policy rules')
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


def single_ethernet(snapshot):
    netd_observation(snapshot)
    networks = snapshot['netd']['networks']
    physical = [network for network in networks if network['type'] == 'PHYSICAL']
    require(len(physical) == 1 and physical[0]['interfaces'] == ['eth0']
            and not any('wlan0' in network['interfaces'] for network in networks),
            'Route recovery was not isolated to the physical eth0 uplink')


def validate_network_fixture(evidence, loss):
    fixture = evidence.get('network_fixture')
    require(matches(fixture, {'scope': 'disposable-single-eth0', 'qemu': True,
                              'abi': 'x86_64', 'control_transport_verified': True,
                              'wifi_disabled': True, 'prepared': True, 'restored': True})
            and type(fixture.get('wifi_initial_enabled')) is bool
            and type(fixture.get('wifi_final_enabled')) is bool
            and fixture['wifi_initial_enabled'] == fixture['wifi_final_enabled'],
            'Route recovery lacks disposable network preparation and Wi-Fi restoration')
    observations = fixture.get('stable_observations')
    require(isinstance(observations, list) and len(observations) == 2
            and observations[0] == observations[1],
            'Route recovery lacks two matching network baseline observations')
    for snapshot in observations:
        require(isinstance(snapshot, dict) and snapshot.keys() == {'netd', 'rules', 'egress'}
                and matches(snapshot, {'egress': 'eth0'}),
                'Route recovery network baseline lacks observed eth0 egress')
        single_ethernet(snapshot)
        rules = text_rows(snapshot.get('rules'), 'network baseline rules')
        require(rules['0: from all lookup local'] == 1
                and all(rules[row] == count for row, count in netd_selectors(snapshot).items()),
                'Route recovery network baseline lacks exact netd selectors')
    lifecycle = loss['helper_lifecycle']
    for snapshot in (loss['before'], loss['fault'], loss['after'],
                     lifecycle['before_stop'], lifecycle['after_start']):
        single_ethernet(snapshot)


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
            and foreign_rules_preserved(prior, started, prior_rules - Counter([prior_helper['rule']]),
                                        started_rules - Counter([started_helper['rule']])),
            'Route helper calibration changed other rules or does not describe the fault core')


def validate_cellular_lifecycle(reconnect):
    lifecycle = reconnect.get('cellular_lifecycle')
    require(matches(lifecycle, {'acknowledged': True})
            and lifecycle.keys() == {'before', 'down', 'after', 'acknowledged'},
            'Cellular reconnect lacks an acknowledged owner lifecycle')
    for stage, running in (('before', True), ('down', False), ('after', True)):
        snapshot = lifecycle[stage]
        expected_fields = {'owner', 'networks'} | ({'flags'} if stage == 'down' else set())
        require(isinstance(snapshot, dict) and snapshot.keys() == expected_fields,
                'Cellular lifecycle lacks a complete ' + stage + ' observation')
        owner = snapshot['owner']
        require(matches(owner, {'phone_id': 0, 'user_data_enabled': running,
                                'data_enabled': running, 'data_state': 2 if running else 0})
                and owner.keys() == {'phone_id', 'sub_id', 'user_data_enabled',
                                     'data_enabled', 'data_state', 'connections'}
                and type(owner['sub_id']) is int and 1 <= owner['sub_id'] <= 0x7fffffff
                and isinstance(owner['connections'], list)
                and len(owner['connections']) == int(running),
                'Cellular owner did not confirm its ' + stage + ' lifecycle state')
        netd_networks(snapshot['networks'])
        if running:
            connection = owner['connections'][0]
            require(matches(connection, {'state': 'CONNECTED', 'transport': 'WWAN',
                                         'interface': 'eth0'})
                    and connection.keys() == {'state', 'transport', 'net_id', 'interface'}
                    and type(connection['net_id']) is int and 100 <= connection['net_id'] <= 65535,
                    'Cellular owner lacks one connected WWAN eth0 network')
            ethernet = netd_ethernet(snapshot['networks'])
            require(connection['net_id'] == ethernet['net_id']
                    and sum(network['type'] == 'PHYSICAL' for network in snapshot['networks']) == 1
                    and not any('wlan0' in network['interfaces'] for network in snapshot['networks']),
                    'Cellular owner does not match an isolated netd eth0 network')

    before, down, after = (lifecycle[stage] for stage in ('before', 'down', 'after'))
    require(all(snapshot['owner']['sub_id'] == before['owner']['sub_id']
                for snapshot in (down, after)),
            'Cellular lifecycle changed the active subscription')
    ethernet = netd_ethernet(before['networks'])
    previous_id = ethernet['net_id']
    unreachable = [network for network in before['networks'] if network['type'] == 'UNREACHABLE']
    require(unreachable == [{'net_id': 52, 'type': 'UNREACHABLE', 'interfaces': [],
                              'details': ['Allowed UID ranges: unrestricted']}],
            'Cellular lifecycle lacks the supported empty unreachable UID network')
    # This single-modem fixture moves exactly the disconnected network's UID
    # preferences to netd's unreachable network. No other metadata is ignored.
    per_app = [line for line in ethernet['details'] if line.startswith('Per-app UID ranges: ')]
    expected_down = [network | {'details': sorted(network['details'] + per_app)}
                     if network['net_id'] == 52 else network
                     for network in before['networks'] if network['net_id'] != previous_id]
    require(down['networks'] == expected_down,
            'Cellular teardown changed more than its network and exact unreachable UID transfer')
    require(type(down['flags']) is int and 0 <= down['flags'] <= 0xffffffff
            and down['flags'] & 1 == 0 and down['flags'] == reconnect['down_flags'],
            'Cellular teardown lacks matching observed down flags')
    restored_id = netd_ethernet(after['networks'])['net_id']
    expected_after = [network | {'net_id': restored_id} if network['net_id'] == previous_id else network
                      for network in before['networks']]
    require(after['networks'] == sorted(expected_after, key=lambda network: network['net_id']),
            'Cellular reconnect did not restore all network metadata and UID ownership')


def uplink_observation(value, interface, uid, minimum_attempts):
    require(isinstance(value, dict), 'Local uplink lacks an independent observation')
    state = value.get('state')
    require(matches(state, {'status': 'present', 'warning': False,
                            'consecutive_failures': 0, 'recovery_limit': 3})
            and type(state.get('recovery_attempts')) is int
            and minimum_attempts <= state['recovery_attempts'] <= 3
            and positive_int(state.get('checked_at'))
            and state.get('recovery_status') in
                ('none', 'pending', 'ok', 'failed', 'busy', 'cooldown', 'exhausted')
            and all(key in state and (state[key] is None or type(state[key]) is int and state[key] >= 0)
                    for key in ('next_check_at', 'retry_in_seconds', 'last_recovery_at')),
            'Local uplink lacks a present production route observation')
    routes = text_rows(value.get('routes'), 'uplink routes')
    require(matches(value, {'selected_default': True, 'ready': True})
            and any(row.startswith('default ') and 'linkdown' not in row
                    and re.search(r'\bdev ' + interface + r'(?: |$)', row) for row in routes),
            'Local uplink lacks its original default route or service readiness')
    tcp = value.get('tcp')
    result = tcp.get('result') if isinstance(tcp, dict) else None
    require(matches(tcp, {'called': True}) and 'reason' not in tcp
            and matches(result, {'complete': True, 'ok': True, 'uid': uid,
                                 'accepted': 1, 'reason': 'sentinel'})
            and result.get('transport', 'tcp') == 'tcp'
            and positive_int(result.get('elapsed_ms')) and result['elapsed_ms'] <= 15000,
            'Local uplink lacks a completed application-UID TCP control')
    return state


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
    for name, expected in (('baseline_app', True), ('fault_app', False), ('recovered_app', True)):
        result = loss.get(name)
        require(matches(result, {'complete': True, 'ok': expected, 'uid': evidence['app_uid'],
                                 'accepted': int(expected), 'transport': 'udp',
                                 'receiver_bound': True, 'receiver_closed': True,
                                 'request_attempted': True})
                and result.get('reason') in (('sentinel',) if expected else ('connect', 'timeout'))
                and positive_int(result.get('elapsed_ms')) and result['elapsed_ms'] <= 15000,
                'RPDB ' + name + ' lacks a completed application-UID UDP control')
    before, fault, after = (loss.get(name) for name in ('before', 'fault', 'after'))
    before_rules, before_fib = route_snapshot(before)
    fault_rules, fault_fib = route_snapshot(fault)
    after_rules, _ = route_snapshot(after)
    before_helper = route_helper(before, before_rules)
    fault_helper = route_helper(fault, fault_rules)
    after_helper = route_helper(after, after_rules)
    validate_helper_lifecycle(loss, before, before_helper)
    validate_network_fixture(evidence, loss)
    require(before_helper == fault_helper and before['netd'] == fault['netd'],
            'RPDB fault changed the core route helper or netd ownership evidence')
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
            and foreign_rules_preserved(before, after,
                                        before_rules - owned - Counter([before_helper['rule']]),
                                        after_rules - owned - Counter([after_helper['rule']])),
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
                               'control_channel_survived': True, 'restore_guard_finished': True,
                               'default_interfaces': ['eth0']})
            and reconnect.get('interface') == 'eth0'
            and all(type(reconnect.get(key)) is int and 0 <= reconnect[key] <= 0xffffffff
                    for key in ('down_flags', 'up_flags'))
            and reconnect['down_flags'] & 1 == 0 and reconnect['up_flags'] & 1 == 1,
            'Local uplink reconnect was not verified')
    validate_cellular_lifecycle(reconnect)
    require(reconnect.get('restore_method') == 'android_mobile_data_toggle',
            'Local uplink restore method is missing or inconsistent')
    baseline = uplink_observation(reconnect.get('baseline'), reconnect['interface'],
                                  evidence['app_uid'], recovered['recovery_attempts'])
    final = uplink_observation(reconnect.get('last_observation'), reconnect['interface'],
                              evidence['app_uid'], baseline['recovery_attempts'])
    require(matches(reconnect.get('recovery_after'), final) and final == reconnect['recovery_after'],
            'Local uplink recovery does not match its last complete observation')


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
