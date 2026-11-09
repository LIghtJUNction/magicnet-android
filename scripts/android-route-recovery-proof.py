#!/usr/bin/env python3
"""Real RPDB-loss/reconnect controls for the disposable KernelSU AVD.

Only active-ledger IPv4 selectors are removed. The installed CLI owns recovery;
this harness never edits recovery state, accelerates its clock or restarts the
core between fault and recovery observations. The enclosing TUN proof restores
the original config even when a control fails.
"""
from __future__ import annotations

from collections import Counter
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import time

MOD = '/data/adb/modules/MagicNet'
CLI = MOD + '/cli'
BB = '/data/adb/ksu/bin/busybox'
IP = '/system/bin/ip'
LEDGER = MOD + '/.state/network/kernel-route-table.state'
TUN = 'magicnet0'
LIMIT = 65536
TICK_INTERVAL = 60
BASELINE_TIMEOUT = 180
RECOVERY_TIMEOUT = 600
POLL_INTERVAL = 5
TUN_FIELDS = ('status', 'warning', 'checked_at', 'next_check_at', 'retry_in_seconds',
              'consecutive_failures', 'recovery_attempts', 'recovery_limit',
              'recovery_status', 'last_recovery_at')
UDP_FIELDS = ('complete', 'ok', 'uid', 'reason', 'accepted', 'elapsed_ms', 'transport',
              'receiver_bound', 'receiver_closed', 'request_attempted')


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def lines(text):
    require(isinstance(text, str) and len(text.encode()) <= LIMIT, 'kernel_output_budget')
    rows = [' '.join(line.replace(' [detached]', '').split()) for line in text.splitlines() if line.strip()]
    require(len(rows) <= 256 and all(len(row) <= 2048 for row in rows), 'kernel_rows_budget')
    return rows


def rules(text):
    rows = lines(text)
    require(all(re.fullmatch(r'[0-9]{1,10}: [a-zA-Z0-9_.,:/\\ -]+', row) for row in rows),
            'invalid_rule_snapshot')
    return rows


def owned_rules(text, boot):
    fields, owned = {}, []
    for row in lines(text):
        key, sep, value = row.partition('=')
        require(sep, 'invalid_ownership_ledger')
        if key == 'rule4':
            owned.extend(rules(value))
        elif key == 'rule6':
            rules(value)
        else:
            require(key not in fields, 'duplicate_ownership_field')
            fields[key] = value
    require(fields == {'schema': '2', 'phase': 'active', 'boot': boot,
                       'table': '2022', 'interface': TUN}, 'inactive_or_foreign_ledger')
    require(owned and len(owned) <= 128, 'empty_or_oversized_ownership')
    for row in owned:
        priority = int(row.split(':', 1)[0])
        require((9000 <= priority <= 9099 or priority == 32768)
                and (re.search(r'\blookup 2022(?: |$)', row)
                     or (priority <= 9010 and (re.search(r'\bgoto 9010(?: |$)', row)
                                               or row.endswith((' nop', ' unreachable'))))),
                'unexpected_owned_selector')
    return owned


def core_identity(text):
    rows = text.splitlines()
    require(len(rows) == 2 and re.fullmatch(r'[1-9][0-9]*', rows[0]), 'invalid_core_identity')
    pid = int(rows[0])
    match = re.fullmatch(r'([0-9]+) \(sing-box\) (.+)', rows[1])
    require(match and int(match[1]) == pid, 'invalid_core_stat')
    fields = match[2].split()
    require(len(fields) >= 20 and fields[0] not in ('Z', 'X') and fields[19].isdigit()
            and int(fields[19]) > 0, 'invalid_core_starttime')
    return {'core_pid': pid, 'core_start_ticks': int(fields[19])}


def guard_identity(text):
    match = re.fullmatch(r'([1-9][0-9]*) \(.+\) ([^\n]+)\n?', text)
    require(match, 'restore_guard_identity_invalid')
    fields = match[2].split()
    require(len(fields) >= 20 and fields[19].isdigit() and int(fields[19]) > 0,
            'restore_guard_identity_invalid')
    return int(match[1]), int(fields[19]), fields[0]


def app_result(result, uid, expected):
    return (isinstance(result, dict) and result.get('complete') is True and result.get('ok') is expected
            and type(result.get('uid')) is int and result['uid'] == uid
            and result.get('reason') in (('sentinel',) if expected else ('connect', 'timeout'))
            and type(result.get('elapsed_ms')) is int and 0 < result['elapsed_ms'] <= 15000
            and type(result.get('accepted')) is int
            and result.get('accepted') == (1 if expected else 0))


def udp_result(result, uid, expected):
    return (app_result(result, uid, expected) and result.get('transport') == 'udp'
            and all(result.get(key) is True for key in
                    ('receiver_bound', 'receiver_closed', 'request_attempted')))


def without_helper(snapshot):
    return Counter(snapshot['rules']) - Counter([snapshot['helper']['rule']])


class Control:
    def __init__(self, adb, evidence):
        self.adb, self.evidence = adb, evidence
        self.last_tick = -float('inf')

    def command(self, text, timeout=10):
        cp = self.adb(text, timeout=timeout)
        require(type(cp.returncode) is int and cp.returncode == 0, 'device_command_failed')
        require(isinstance(cp.stdout, str) and len(cp.stdout.encode()) <= LIMIT, 'device_output_budget')
        return cp.stdout

    def machine(self, name):
        value = json.loads(self.command(CLI + ' --json ' + name.replace('.', ' ')),
                           object_pairs_hook=unique_keys)
        require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1
                and value.get('ok') is True and value.get('command') == name
                and isinstance(value.get('data'), dict), 'invalid_machine_envelope')
        return value['data']

    def connectivity(self):
        value = self.machine('connectivity.status').get('tun_auto_route')
        require(isinstance(value, dict) and all(key in value for key in TUN_FIELDS),
                'tun_recovery_status_unavailable')
        require(value['status'] in ('not_required', 'pending', 'present', 'missing', 'unknown', 'paused', 'stale')
                and value['recovery_status'] in ('none', 'pending', 'ok', 'failed', 'busy', 'cooldown', 'exhausted')
                and type(value['warning']) is bool and type(value['recovery_limit']) is int
                and value['recovery_limit'] == 3, 'invalid_recovery_status')
        for key in ('consecutive_failures', 'recovery_attempts'):
            require(type(value[key]) is int and 0 <= value[key] <= 1000, 'invalid_recovery_count')
        for key in ('checked_at', 'next_check_at', 'retry_in_seconds', 'last_recovery_at'):
            require(value[key] is None or type(value[key]) is int and value[key] >= 0,
                    'invalid_recovery_time')
        return {key: value[key] for key in TUN_FIELDS}

    def ready(self, expected):
        value = self.machine('service.status')
        core = value.get('core', {}).get('sing_box', {})
        ready = value.get('readiness', {})
        return (core.get('process_state') == 'running' and value.get('api', {}).get('ready') is True
                and ready.get('dataplane') is expected and ready.get('overall') is expected)

    def identity(self):
        return core_identity(self.command(
            f'p=$({BB} pidof sing-box) || exit 1; '
            'case "$p" in ""|*[!0-9]*) exit 1;; esac; '
            f'test "$(readlink /proc/$p/exe)" = {MOD}/bin/sing-box || exit 1; '
            'printf "%s\\n" "$p"; cat /proc/$p/stat'))

    def rule_snapshot(self):
        rows = rules(self.command(IP + ' -4 rule show'))
        require(rows.count('0: from all lookup local') == 1, 'local_rule_anchor_missing_or_duplicated')
        return rows

    def helper_fib(self, table):
        # A successful full dump observes empty/deleted tables too. Never turn
        # a failed targeted table lookup into an empty ownership observation.
        marker = re.compile(r' table ' + str(table) + r'(?= |$)')
        rows = lines(self.command(IP + ' -4 route show table all'))
        require(rows, 'route_table_dump_empty')
        return sorted(marker.sub('', row) for row in rows if marker.search(row))

    def helper(self, rows):
        candidates = [row for row in rows if row.partition(':')[0] == '1']
        require(len(candidates) == 1, 'helper_rule_ambiguous')
        match = re.fullmatch(r'1: from all lookup ([0-9]+)', candidates[0])
        require(match and 256 <= int(match[1]) <= 2147483647 and int(match[1]) != 2022,
                'invalid_helper_rule')
        table = int(match[1])
        fib = self.helper_fib(table)
        devices = []
        for row in fib:
            match = re.fullmatch(r'local 127\.0\.0\.1(?:/32)? dev ([a-zA-Z0-9_.-]{1,15}) scope host', row)
            require(match and match[1] not in ('lo', TUN), 'invalid_helper_fib')
            devices.append(match[1])
        require(devices and len(set(devices)) == len(devices), 'empty_or_duplicate_helper_fib')
        return {'rule': candidates[0], 'table': table, 'fib': fib}

    def snapshot(self):
        identity = self.identity()
        index = self.command('cat /sys/class/net/' + TUN + '/ifindex').strip()
        require(re.fullmatch(r'[1-9][0-9]*', index), 'invalid_tun_identity')
        result = identity | {'tun_name': TUN, 'tun_ifindex': int(index), 'rules': self.rule_snapshot(),
                             'fib': lines(self.command(IP + " -4 route show table ' 2022'"))}
        require(result['fib'] and all('dev ' + TUN in row for row in result['fib']),
                'foreign_or_empty_tun_fib')
        result['helper'] = self.helper(result['rules'])
        require(self.identity() == identity, 'core_changed_during_snapshot')
        return result

    def observe_lifecycle(self, stage):
        lifecycle = self.evidence.setdefault('helper_lifecycle', {})
        self.evidence['stage'] = 'helper_' + stage
        if stage == 'before_stop':
            lifecycle[stage] = self.snapshot()
        elif stage == 'stopped':
            state = self.machine('service.status').get('core', {}).get('sing_box', {}).get('process_state')
            require(state == 'stopped', 'helper_stop_not_observed')
            self.command('test ! -e /sys/class/net/' + TUN)
            table = lifecycle['before_stop']['helper']['table']
            stopped = lifecycle[stage] = {'core_state': state, 'rules': self.rule_snapshot(),
                                          'helper_table': table, 'helper_fib': self.helper_fib(table)}
            require(not stopped['helper_fib']
                    and not any(row.partition(':')[0] == '1' for row in stopped['rules']),
                    'helper_not_removed_by_close')
        elif stage == 'after_start':
            require('stopped' in lifecycle, 'helper_stop_snapshot_missing')
            before = lifecycle['before_stop']
            after = lifecycle[stage] = self.snapshot()
            require(after['core_start_ticks'] > before['core_start_ticks']
                    and without_helper(before) == without_helper(after), 'helper_activation_changed_foreign_rules')
        else:
            raise RuntimeError('invalid_helper_lifecycle_stage')

    def tick(self, force=False):
        if force or time.monotonic() - self.last_tick >= TICK_INTERVAL:
            self.command(CLI + ' connectivity tick', timeout=180)
            self.last_tick = time.monotonic()
            self.evidence['recovery_tick_count'] += 1
            return True
        return False

    def wait(self, predicate, timeout, reason):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.connectivity()
            if predicate(state):
                return state
            if self.tick():
                state = self.connectivity()
                if predicate(state):
                    return state
            time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))
        raise RuntimeError(reason)

    def remove_owned(self, before, owned):
        current, remaining = Counter(before), Counter(owned)
        require(not remaining - current, 'ledger_rule_missing_before_fault')
        priorities = {row.partition(':')[0] for row in owned}
        require(all(row in remaining for row in before if row.partition(':')[0] in priorities),
                'foreign_rule_at_owned_priority')
        for _ in range(128):
            if not remaining:
                return
            row = next(iter(remaining))
            priority, _, selector = row.partition(': ')
            # Every argument is from an exact live ledger record, never eval or
            # a broad priority flush. Netlink may match a zero-valued sibling;
            # verify that exactly one recorded sibling disappeared each time.
            live = Counter(self.rule_snapshot())
            require(live == current, 'rules_changed_before_delete')
            self.command(shlex.join([IP, '-4', 'rule', 'del', 'priority', priority, *selector.split()]))
            after = Counter(self.rule_snapshot())
            removed = current - after
            require(not after - current and sum(removed.values()) == 1 and not removed - remaining,
                    'deletion_changed_unowned_rules')
            remaining.subtract(removed)
            remaining += Counter()
            current = after
        raise RuntimeError('rule_deletion_budget')

    def rpdb_loss(self, sentinel, uid):
        evidence = self.evidence

        def observe_app(key, expected, reason):
            result = sentinel()
            require(isinstance(result, dict), 'app_probe_result_unavailable')
            evidence[key] = {field: result.get(field) for field in UDP_FIELDS}
            require(udp_result(result, uid, expected), reason)

        evidence['stage'] = 'baseline'
        baseline = self.wait(lambda state: state['status'] == 'present' and not state['warning']
                             and state['consecutive_failures'] == 0,
                             BASELINE_TIMEOUT, 'healthy_baseline_deadline')
        require(baseline['recovery_attempts'] < baseline['recovery_limit'] and self.ready(True),
                'healthy_baseline_required')
        before = evidence['before'] = self.snapshot()
        activated = evidence.get('helper_lifecycle', {}).get('after_start')
        require(isinstance(activated, dict) and all(activated.get(key) == before[key] for key in
                ('core_pid', 'core_start_ticks', 'tun_name', 'tun_ifindex', 'helper')),
                'helper_ownership_not_bound_to_core')
        boot = self.command('cat /proc/sys/kernel/random/boot_id').strip()
        require(re.fullmatch(r'[0-9a-f-]{36}', boot), 'invalid_boot_identity')
        owned = evidence['owned_rules'] = owned_rules(self.command(
            f'test -f {LEDGER} && test ! -L {LEDGER} && {BB} head -c {LIMIT + 1} {LEDGER}'), boot)
        require(not Counter(owned) - Counter(before['rules']), 'ledger_rule_missing_before_fault')
        capture = [row for row in owned if re.search(r'\blookup 2022(?: |$)', row)]
        require(capture, 'owned_capture_rule_unavailable')
        evidence['recovery_before'] = baseline
        observe_app('baseline_app', True, 'baseline_app_not_captured')
        evidence['stage'] = 'remove_owned_rpdb'
        # Keep goto targets alive: an unowned goto can reference an owned nop.
        # Removing only table lookups breaks capture without changing that rule.
        self.remove_owned(before['rules'], capture)
        fault = evidence['fault'] = self.snapshot()
        removed = Counter(before['rules']) - Counter(fault['rules'])
        require(not removed - Counter(capture), 'fault_removed_non_capture_rule')
        evidence['removed_rule_count'] = sum(removed.values())
        for key, fields in (('core_identity_unchanged', ('core_pid', 'core_start_ticks')),
                            ('tun_unchanged', ('tun_name', 'tun_ifindex')),
                            ('fib_unchanged', ('fib', 'helper'))):
            evidence[key] = all(before[field] == fault[field] for field in fields)
            require(evidence[key], key + '_failed')
        foreign = without_helper(before) - Counter(owned)
        evidence['unowned_rules_unchanged'] = without_helper(fault) - Counter(owned) == foreign
        require(evidence['unowned_rules_unchanged'] and evidence['removed_rule_count'] > 0,
                'fault_not_confined_to_owned_rules')
        require(self.ready(False), 'fault_machine_readiness_not_rejected')
        evidence['ready_after_fault'] = False
        health = re.sub(r'\x1b\[[0-9;]*m', '', self.command(CLI + ' health', timeout=30))
        evidence['health_after_fault_rpdb_missing'] = any(
            '[warn] Dataplane:' in row and 'ipv4_rpdb=missing' in row and 'ipv4_fib=present' in row
            for row in health.splitlines())
        require(evidence['health_after_fault_rpdb_missing'], 'health_did_not_report_rpdb_loss')
        observe_app('fault_app', False, 'fault_app_rejection_not_proven')
        evidence['app_after_fault'] = False
        evidence['stage'] = 'watchdog_recovery'
        evidence['recovery_tick_count'] = 0

        def recovered(state):
            if state['status'] == 'missing' and 'first_missing' not in evidence:
                require(state['consecutive_failures'] == 1
                        and state['recovery_attempts'] == baseline['recovery_attempts'],
                        'missing_confirmation_not_observed')
                identity = self.identity()
                require(all(identity[key] == before[key] for key in identity), 'premature_core_restart')
                evidence.update(first_missing=state, first_missing_identity=identity)
            return (state['status'] == 'present' and state['recovery_status'] == 'ok'
                    and state['recovery_attempts'] > baseline['recovery_attempts'])

        # The background watchdog may already have recorded missing=1. Capture
        # that real observation before an eligible tick can perform recovery.
        recovered(self.connectivity())
        self.tick(force=True)  # Normal entry; production still enforces its due time.
        evidence['recovery_after'] = self.wait(recovered, RECOVERY_TIMEOUT, 'automatic_recovery_deadline')
        require('first_missing' in evidence, 'missing_confirmation_not_observed')
        after = evidence['after'] = self.snapshot()
        previous = after['previous_helper_fib'] = self.helper_fib(before['helper']['table'])
        if after['helper']['table'] == before['helper']['table']:
            require(after['helper'] == before['helper'] and Counter(previous) == Counter(after['helper']['fib']),
                    'reused_helper_table_changed')
        else:
            require(not previous and before['helper']['rule'] not in after['rules'],
                    'previous_helper_not_removed')
        require((after['core_pid'], after['core_start_ticks'])
                != (before['core_pid'], before['core_start_ticks']), 'managed_restart_not_observed')
        require(not Counter(owned) - Counter(after['rules'])
                and without_helper(after) - Counter(owned) == foreign, 'recovery_rule_set_mismatch')
        require(self.ready(True), 'recovery_not_ready')
        evidence['ready_after_recovery'] = True
        observe_app('recovered_app', True, 'recovered_app_not_captured')
        evidence.update(app_after_recovery=True, status='verified', stage='complete')


def control_peers(text):
    """Established TCP peers owned by adbd, excluding its listeners and Unix pipes."""
    descriptors, sep, tables = text.partition('\nTCP\n')
    require(sep and descriptors.startswith('ADBD\n'), 'adb_transport_snapshot_invalid')
    sockets = set()
    for row in descriptors.splitlines()[1:]:
        match = re.fullmatch(r'socket:\[([0-9]+)\]', row)
        if match:
            sockets.add(match[1])
    require(descriptors.count('\n') > 1, 'adb_descriptors_unavailable')
    peers, headers = [], 0
    for row in tables.splitlines():
        fields = row.split()
        if fields and fields[0] == 'sl' and 'local_address' in fields and 'st' in fields:
            headers += 1
            continue
        require(len(fields) >= 10 and re.fullmatch(r'[0-9]+:', fields[0])
                and re.fullmatch(r'[0-9A-Fa-f]{2}', fields[3]) and fields[9].isdigit(),
                'invalid_adb_tcp_table')
        if fields[9] not in sockets or fields[3] != '01':
            continue
        address = fields[2].partition(':')[0]
        require(re.fullmatch(r'[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}', address), 'invalid_adb_peer')
        raw = bytes.fromhex(address)
        raw = b''.join(raw[offset:offset + 4][::-1] for offset in range(0, len(raw), 4))
        peer = ipaddress.ip_address(raw)
        peers.append(str(peer.ipv4_mapped if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped else peer))
    require(headers == 2 and len(peers) <= 32, 'adb_peer_budget_or_missing_table')
    return peers


def uplink_reconnect(control, sentinel, uid, evidence):
    evidence.update(status='not_verified', stage='select_uplink')
    routes = lines(control.command(IP + ' -4 route show table all'))
    interfaces = {match[1] for row in routes if row.startswith('default ') and 'linkdown' not in row
                  for match in [re.search(r'\bdev (wlan0|eth0)(?: |$)', row)] if match}
    # Android keeps a default in each network table. Resolve the active egress
    # through the kernel without sending a packet or assuming Wi-Fi beats eth0.
    route = control.command(IP + ' -4 route get 192.0.2.1')
    selected = set(re.findall(r'\bdev ([a-zA-Z0-9_.-]+)(?=\s|$)', route))
    require(len(selected) == 1 and selected <= interfaces, 'ambiguous_or_missing_uplink')
    interface = evidence['interface'] = selected.pop()
    evidence['default_interfaces'] = sorted(interfaces)
    # Refuse to lower an interface carrying a TCP adbd peer. Emulator pipe/Unix
    # transports and peers on a different interface keep the control channel up.
    peers = control_peers(control.command(
        f'p=$({BB} pidof adbd) || exit 1; test -n "$p" || exit 1; printf "ADBD\\n"; '
        'for n in $p; do test -r /proc/$n/fd || exit 1; '
        'for f in /proc/$n/fd/*; do readlink "$f" || exit 1; done; done; '
        'printf "TCP\\n"; cat /proc/net/tcp /proc/net/tcp6'))
    for peer in peers:
        route = control.command(shlex.join([IP, '-6' if ':' in peer else '-4', 'route', 'get', peer]))
        require(re.search(r'\bdev [a-zA-Z0-9_.-]+(?:\s|$)', route)
                and not re.search(r'\bdev ' + interface + r'(?:\s|$)', route),
                'uplink_carries_adb_control_or_unknown_route')
    evidence['control_transport_verified'] = True

    def flags():
        text = control.command('cat /sys/class/net/' + interface + '/flags').strip()
        require(re.fullmatch(r'0x[0-9a-fA-F]+', text), 'invalid_interface_flags')
        return int(text, 16)

    require(flags() & 1, 'uplink_not_initially_up')
    up = shlex.join([IP, 'link', 'set', 'dev', interface, 'up'])
    # Independent, short-lived restore guard also survives a host interruption.
    guard = shlex.join([BB, 'sh', '-c', BB + ' sleep 10; ' + up])
    guard_pid, guard_start, _ = guard_identity(control.command(
        f'{BB} nohup {BB} true </dev/null >/dev/null 2>&1 || exit 1; '
        f'{BB} nohup {guard} </dev/null >/dev/null 2>&1 & p=$!; cat /proc/$p/stat'))
    evidence.update(restore_guard_pid=guard_pid, restore_guard_start_ticks=guard_start)
    try:
        evidence['stage'] = 'uplink_down'
        control.command(shlex.join([IP, 'link', 'set', 'dev', interface, 'down']))
        evidence['down_flags'] = flags()  # A separate live ADB request while down.
        evidence['down_observed'] = evidence['down_flags'] & 1 == 0
        require(evidence['down_observed'], 'uplink_down_not_observed')
        evidence['control_channel_survived'] = True
    finally:
        try:
            control.command(up)
        finally:
            # Do not carry the guard's delayed `up` into the next lifecycle phase.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                text = control.command(f'if [ -r /proc/{guard_pid}/stat ]; then '
                                       f'cat /proc/{guard_pid}/stat; else echo gone; fi')
                identity = None if text.strip() == 'gone' else guard_identity(text)
                if identity is None or identity[:2] != (guard_pid, guard_start) or identity[2] in ('Z', 'X'):
                    evidence['restore_guard_finished'] = True
                    break
                time.sleep(1)
            require(evidence.get('restore_guard_finished') is True, 'uplink_restore_guard_deadline')
        evidence['up_flags'] = flags()
        evidence['up_observed'] = evidence['up_flags'] & 1 == 1
    require(evidence['up_observed'], 'uplink_restore_failed')
    evidence['stage'] = 'reconnect'
    control.tick(force=True)
    def recovered(state):
        routes = lines(control.command(IP + ' -4 route show table all'))
        routed = any(row.startswith('default ') and 'linkdown' not in row
                     and re.search(r'\bdev ' + interface + r'(?: |$)', row) for row in routes)
        return (routed and state['status'] == 'present' and control.ready(True)
                and app_result(sentinel(), uid, True))
    evidence['recovery_after'] = control.wait(recovered, RECOVERY_TIMEOUT, 'uplink_reconnect_deadline')
    evidence.update(ready_after_recovery=True, app_after_recovery=True,
                    status='verified', stage='complete')


def verify(adb, instrument, component, evidence=None):
    evidence = {} if evidence is None else evidence
    evidence.update(schema=1, status='not_verified', scope='disposable-android-app-uid-tun')
    if os.environ.get('MAGICNET_DISPOSABLE_AVD') != '1' or not re.fullmatch(
            r'emulator-[0-9]+', os.environ.get('ANDROID_SERIAL', '')):
        evidence['reason'] = 'disposable_avd_required'
        return evidence
    spec = importlib.util.spec_from_file_location('route_tun_proof', Path(__file__).with_name('android-tun-proof.py'))
    proof = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proof)
    rpdb = evidence['rpdb_loss'] = {'status': 'not_verified', 'recovery_entry': 'connectivity.tick',
                                   'recovery_tick_count': 0}
    control = Control(adb, rpdb)

    def observe(stage):
        try:
            control.observe_lifecycle(stage)
        except (RuntimeError, ValueError, KeyError, TypeError, OSError) as error:
            evidence['reason'] = str(error) if isinstance(error, RuntimeError) else 'helper_observation_failed'
            raise RuntimeError('helper_control_failed') from None

    def fault(sentinel, uid, udp_sentinel):
        evidence['app_uid'] = uid
        try:
            control.rpdb_loss(udp_sentinel, uid)
            reconnect = evidence['uplink_reconnect'] = {'recovery_tick_count': 0}
            uplink_reconnect(Control(adb, reconnect), sentinel, uid, reconnect)
        except (RuntimeError, ValueError, KeyError, TypeError, OSError) as error:
            # RuntimeError text is exclusively a fixed token from this harness.
            evidence['reason'] = str(error) if isinstance(error, RuntimeError) else 'fault_observation_failed'
            raise RuntimeError('route_control_failed') from None

    result = proof.verify(adb, instrument, component, fault_control=fault, lifecycle_observer=observe)
    evidence['tun_controls'] = result
    evidence.update({key: result.get(key) is True for key in ('positive', 'reject', 'positive_after', 'restored')})
    if result['status'] == 'verified' and all(evidence.get(key, {}).get('status') == 'verified'
                                           for key in ('rpdb_loss', 'uplink_reconnect')):
        evidence['status'] = 'verified'
        evidence.pop('reason', None)
    return evidence
