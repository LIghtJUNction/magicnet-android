#!/usr/bin/env python3
"""Host safety/accounting tests, not evidence of Android packet forwarding."""
from collections import Counter
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('route_proof', ROOT / 'scripts/android-route-recovery-proof.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
BOOT = '12345678-1234-1234-1234-123456789abc'
OWNED = ['9000: from all to 172.19.0.0/30 lookup 2022',
         '9000: from all iif lo lookup 2022', '9001: from all goto 9010',
         '9010: from all nop']
ETH0_RULES = ['16000: from all fwmark 0x10064/0x1ffff iif lo lookup eth0',
              '23000: from all fwmark 0x64/0x1ffff iif lo lookup eth0']
FOREIGN = ['0: from all lookup local', '32766: from all lookup main',
           '18000: from all fwmark 0x64/0x1ffff lookup wlan0'] + ETH0_RULES
LEDGER = ('schema=2\nphase=active\nboot=' + BOOT + '\ntable=2022\ninterface=magicnet0\n'
          + ''.join('rule4=' + row + '\n' for row in OWNED))
FIB = 'default dev magicnet0 scope link\n'
HELPER_FIB = ['local 127.0.0.1 dev eth0 scope host', 'local 127.0.0.1 dev wlan0 scope host']
ETH0_FIB = ['default via 10.0.2.2 dev eth0 proto static',
            '10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15']
NETWORKS = [
    {'net_id': 51, 'type': 'DUMMY', 'interfaces': ['dummy0'], 'details': ['Allowed UID ranges: unrestricted']},
    {'net_id': 52, 'type': 'UNREACHABLE', 'interfaces': [], 'details': ['Allowed UID ranges: unrestricted']},
    {'net_id': 99, 'type': 'LOCAL', 'interfaces': [], 'details': ['Allowed UID ranges: unrestricted']},
    {'net_id': 100, 'type': 'PHYSICAL', 'interfaces': ['eth0'],
     'details': ['Allowed UID ranges: unrestricted', 'Required permission: NONE']},
    {'net_id': 101, 'type': 'PHYSICAL', 'interfaces': ['wlan0'],
     'details': ['Allowed UID ranges: unrestricted', 'Required permission: NONE']},
]
UID_DETAILS = [
    'Allowed UID ranges: uids{ 10000 10000 10000-10003 10002-10005 10123 }',
    'Per-app UID ranges: prio 0 uids{ 10000 10000-10003 10002-10005 10123 }; prio 10 uids{ 10123 }',
    'Required permission: NONE',
]
HEADER = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode'
TCP = '0: 0F02000A:15B3 0202000A:C012 01 00000000:00000000 00:00000000 00000000 0 0 77'


def state(status='present', failures=0, attempts=0):
    return dict(status=status, warning=status in ('missing', 'unknown'), checked_at=100,
                next_check_at=160, retry_in_seconds=60, consecutive_failures=failures,
                recovery_attempts=attempts, recovery_limit=3,
                recovery_status='ok' if attempts else 'none',
                last_recovery_at=90 if attempts else None)


class Device:
    """In-memory command model verifies harness decisions and mutation boundaries."""
    def __init__(self):
        self.helper_table = 1000001
        self.helpers = {self.helper_table: list(HELPER_FIB)}
        self.rules = FOREIGN + OWNED + [self.helper_rule()]
        self.networks = copy.deepcopy(NETWORKS)
        self.eth0_ifindex, self.eth0_fib = 17, list(ETH0_FIB)
        self.renumber_on_start = False
        self.pid, self.start, self.ifindex = 420, 700, 11
        self.running = True
        self.reuse_helper = False
        self.retain_old_helper_fib = False
        self.state = state()
        self.ledger = LEDGER
        self.calls = []
        self.health_green = False
        self.recover = True
        self.restart_on_delete = False
        self.delete_sibling = False
        self.foreign_on_recover = False
        self.flags = 0x1003
        self.flag_reads = 0
        self.fail_down_observation = False
        self.uplinks = ['wlan0']
        self.selected_uplink = 'wlan0'
        self.peers = 'ADBD\n/dev/null\nsocket:[77]\nTCP\n' + HEADER + '\n' + HEADER + '\n'

    def helper_rule(self):
        return '1: from all lookup ' + str(self.helper_table)

    def stop(self):
        self.rules = list((Counter(self.rules) - Counter(OWNED) - Counter([self.helper_rule()])).elements())
        if not self.retain_old_helper_fib:
            self.helpers.pop(self.helper_table, None)
        self.running = False

    def start_core(self):
        self.pid += 1
        self.start += 100
        self.ifindex += 1
        self.helper_table += 0 if self.reuse_helper else 1
        self.helpers[self.helper_table] = list(HELPER_FIB)
        self.rules += OWNED + [self.helper_rule()]
        if self.renumber_on_start:
            self.renumber_eth0()
        self.running = True

    def renumber_eth0(self):
        network = next(item for item in self.networks if item['interfaces'] == ['eth0'])
        old_id = network['net_id']
        network['net_id'] += 2
        for prefix in (0x10000, 0):
            old, new = f'fwmark {prefix | old_id:#x}/', f'fwmark {prefix | network["net_id"]:#x}/'
            self.rules = [row.replace(old, new) if row.endswith('iif lo lookup eth0') else row
                          for row in self.rules]

    def netd_dump(self):
        records = []
        for network in sorted(self.networks, key=lambda item: item['net_id']):
            records.append(f'      {network["net_id"]} {network["type"]}'
                           + (' ' + ','.join(network['interfaces']) if network['interfaces'] else ''))
            records.extend('        ' + row for row in network['details'])
            records.append('')
        return ('NetdNativeService\n  NetworkController\n    Default network: 101\n\n    Networks:\n'
                + '\n'.join(records) + '\n    Interface <-> last network map:\n'
                '    Interface addresses:\n    Permission of users:\n    Protectable users:\n')

    def app(self):
        captured = self.running and not Counter(OWNED) - Counter(self.rules)
        return dict(ok=captured, complete=True, uid=10123,
                    reason='sentinel' if captured else 'connect', accepted=1 if captured else 0,
                    elapsed_ms=10, transport='udp', receiver_bound=True, receiver_closed=True,
                    request_attempted=True)

    def adb(self, command, timeout=10):
        self.calls.append(command)
        output, rc = '', 0
        if command.startswith('p=$(' + proof.BB + ' pidof sing-box)'):
            fields = ['S'] + ['0'] * 18 + [str(self.start)]
            output = f'{self.pid}\n{self.pid} (sing-box) ' + ' '.join(fields) + '\n'
        elif command == 'cat /sys/class/net/magicnet0/ifindex':
            output = str(self.ifindex)
        elif command == proof.NETD:
            output = self.netd_dump()
        elif command == 'cat /sys/class/net/eth0/ifindex':
            output = str(self.eth0_ifindex)
        elif command == proof.IP + ' -4 route show table eth0':
            output = '\n'.join(self.eth0_fib)
        elif command == proof.IP + ' -4 rule show':
            output = '\n'.join(self.rules)
        elif command == proof.IP + " -4 route show table ' 2022'":
            output = FIB
        elif command == 'cat /proc/sys/kernel/random/boot_id':
            output = BOOT
        elif command.startswith('test -f ' + proof.LEDGER):
            output = self.ledger
        elif command.startswith(proof.IP + ' -4 rule del priority '):
            args = shlex.split(command)
            row = args[5] + ': ' + ' '.join(args[6:])
            if self.delete_sibling and row == OWNED[0] and OWNED[1] in self.rules:
                row = OWNED[1]
            self.rules.remove(row)
            if self.restart_on_delete:
                self.pid += 1
        elif command == proof.CLI + ' service stop sing-box':
            self.stop()
        elif command == proof.CLI + ' service start sing-box':
            self.start_core()
        elif command == 'test ! -e /sys/class/net/magicnet0':
            rc = 1 if self.running else 0
        elif command == proof.CLI + ' --json service status':
            ready = self.app()['ok']
            output = json.dumps(dict(schema=1, ok=True, command='service.status', data={
                'core': {'sing_box': {'process_state': 'running' if self.running else 'stopped'}},
                'api': {'ready': self.running},
                'readiness': {'dataplane': ready, 'overall': ready}}))
        elif command == proof.CLI + ' --json connectivity status':
            output = json.dumps(dict(schema=1, ok=True, command='connectivity.status',
                                     data={'tun_auto_route': self.state}))
        elif command == proof.CLI + ' health':
            output = ('[ok] Dataplane: healthy' if self.health_green else
                      '[warn] Dataplane: auto_route=enabled ipv4_rpdb=missing ipv4_fib=present')
        elif command == proof.CLI + ' connectivity tick':
            if not self.app()['ok']:
                self.state = state('missing', self.state['consecutive_failures'] + 1)
                if self.recover and self.state['consecutive_failures'] >= 2:
                    self.stop()
                    self.start_core()
                    if self.foreign_on_recover:
                        self.rules.remove(FOREIGN[2])
                    self.state = state(attempts=1)
        elif command == proof.IP + ' -4 route show table all':
            output = ''.join(f'default via 10.0.2.2 dev {name} table {name} proto static\n'
                             for name in self.uplinks) + FIB
            output += ''.join(row.replace(' scope host', f' table {table} scope host') + '\n'
                              for table, rows in self.helpers.items() for row in rows)
        elif command == proof.IP + ' -4 route get 192.0.2.1':
            output = (f'192.0.2.1 via 10.0.2.2 dev {self.selected_uplink} '
                      f'table {self.selected_uplink} src 10.0.2.15 uid 0\n') if self.selected_uplink else ''
        elif command.startswith('p=$(' + proof.BB + ' pidof adbd)'):
            output = self.peers
        elif command == proof.IP + ' -4 route get 10.0.2.2':
            output = '10.0.2.2 dev wlan0 src 10.0.2.15'
        elif command == 'cat /sys/class/net/wlan0/flags':
            self.flag_reads += 1
            if self.fail_down_observation and self.flag_reads == 2:
                rc = 1
            output = hex(self.flags)
        elif command.startswith(proof.BB + ' nohup '):
            output = '500 (sh) S ' + '0 ' * 18 + '850\n'
        elif command == 'if [ -r /proc/500/stat ]; then cat /proc/500/stat; else echo gone; fi':
            output = 'gone\n'
        elif command == proof.IP + ' link set dev wlan0 down':
            self.flags &= ~1
        elif command == proof.IP + ' link set dev wlan0 up':
            self.flags |= 1
        else:
            raise AssertionError('unexpected command: ' + command)
        return subprocess.CompletedProcess(['adb'], rc, output, '')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.device = Device()
        self.evidence = {'recovery_entry': 'connectivity.tick', 'recovery_tick_count': 0}
        self.control = proof.Control(self.device.adb, self.evidence)
        self.clock = 0

    def sleep(self, seconds):
        self.clock += seconds

    def run_control(self, sentinel=None):
        with patch.object(proof.time, 'monotonic', lambda: self.clock), patch.object(proof.time, 'sleep', self.sleep):
            self.calibrate()
            self.control.rpdb_loss(sentinel or self.device.app, 10123)

    def calibrate(self):
        self.control.observe_lifecycle('before_stop')
        self.control.command(proof.CLI + ' service stop sing-box')
        self.control.observe_lifecycle('stopped')
        self.control.command(proof.CLI + ' service start sing-box')
        self.control.observe_lifecycle('after_start')

    def test_complete_netd_inventory_is_canonical_and_preserves_uid_metadata(self):
        self.device.networks[1]['details'].append('Per-app UID ranges: prio 1 uids{ 10000-10001 }')
        self.device.networks.reverse()
        text = self.device.netd_dump().replace('      ', '\t').replace('Default network:', 'Default  network:')
        expected = sorted(copy.deepcopy(self.device.networks), key=lambda item: item['net_id'])
        for network in expected:
            network['details'].sort()
        self.assertEqual(proof.parse_netd_networks(text), expected)
        self.assertEqual(self.control.netd_observation(),
                         {'networks': expected, 'eth0_ifindex': 17, 'eth0_fib': sorted(ETH0_FIB)})
        self.assertNotIn('netd_failure', self.evidence)

    def test_missing_ambiguous_truncated_or_unknown_netd_records_are_rejected(self):
        text = self.device.netd_dump()
        variants = [
            '', text.split('Interface <-> last network map:')[0],
            text + '\nNetworkController\n', text + '\nNetworks:\n',
            text + '\n*** SERVICE netd DUMP TIMEOUT\n',
            text.replace('Required permission: NONE', 'Unknown property: NONE', 1),
            text.replace('        Required permission: NONE\n', '', 1),
            text.replace('        Allowed UID ranges: unrestricted\n', '', 1),
            text.replace('Allowed UID ranges: unrestricted',
                         'Allowed UID ranges: unrestricted\n        Allowed UID ranges: uids{ }', 1),
            text.replace('51 DUMMY dummy0', '51 DUMMY dummy0\n        Required permission: NONE'),
            text.replace('52 UNREACHABLE', '51 UNREACHABLE'),
            text.replace('100 PHYSICAL eth0', '65536 PHYSICAL eth0'),
            text.replace('100 PHYSICAL eth0', '100 physical eth0'),
            text.replace('100 PHYSICAL eth0', '100 PHYSICAL eth0,eth0'),
            text + '\0', 'x' * proof.NETD_LIMIT + text,
        ]
        for index, observed in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                proof.parse_netd_networks(observed)

    def test_netd_read_failure_or_empty_success_never_becomes_an_empty_inventory(self):
        original = self.device.adb
        for code, output in ((1, ''), (124, ''), (0, ''), (0, 'x' * (proof.NETD_LIMIT + 1))):
            def adb(command, **kwargs):
                return (subprocess.CompletedProcess(['adb'], code, output, '') if command == proof.NETD
                        else original(command, **kwargs))
            self.control.adb = adb
            with self.subTest(code=code, size=len(output)), self.assertRaises(RuntimeError):
                self.control.snapshot()
        self.assertNotIn(proof.IP + ' -4 rule show', self.device.calls)
        self.assertNotIn('netd_failure', self.evidence)

    def test_unsupported_netd_metadata_is_preserved_without_adopting_the_network(self):
        for details in (
                ['Allowed UID ranges: unrestricted', 'Required permission: NETWORK'],
                ['Allowed UID ranges: unrestricted', 'Required permission: SYSTEM'],
                ['Allowed UID ranges: uids{ <BAD: 10000-10001> }', 'Required permission: NONE'],
                ['Allowed UID ranges: unrestricted', 'Per-app UID ranges: prio 1000 uids{ 10000 }',
                 'Required permission: NONE']):
            self.setUp()
            self.device.networks[3]['details'] = details
            with self.subTest(details=details), self.assertRaisesRegex(
                    RuntimeError, '^netd_eth0_ownership_unavailable$'):
                self.calibrate()
            self.assertEqual(self.evidence['netd_failure'], {
                'stage': 'helper_before_stop',
                'observation': {'networks': self.device.networks, 'eth0_ifindex': 17,
                                'eth0_fib': sorted(ETH0_FIB)}})
            self.assertEqual(self.evidence['helper_lifecycle'], {})
            self.assertNotIn(proof.CLI + ' service stop sing-box', self.device.calls)

    def test_ambiguous_eth0_interfaces_are_preserved_and_still_rejected(self):
        for network, interfaces in ((3, ['eth0', 'wlan1']), (4, ['eth0', 'wlan0'])):
            self.setUp()
            self.device.networks[network]['interfaces'] = interfaces
            self.evidence['stage'] = 'watchdog_recovery'
            with self.subTest(network=network), self.assertRaisesRegex(
                    RuntimeError, '^netd_eth0_ownership_unavailable$'):
                self.control.snapshot()
            self.assertEqual(self.evidence['netd_failure'], {
                'stage': 'watchdog_recovery',
                'observation': {'networks': self.device.networks, 'eth0_ifindex': 17,
                                'eth0_fib': sorted(ETH0_FIB)}})
            self.assertNotIn(proof.IP + ' -4 rule show', self.device.calls)

    def test_eth0_requires_one_supported_physical_network_and_a_complete_fib(self):
        for changes in ({'net_id': 98}, {'type': 'VIRTUAL'}, {'interfaces': ['eth0', 'wlan1']},
                        {'details': ['Required permission: NONE']},
                        {'details': ['Allowed UID ranges: unknown', 'Required permission: NONE']},
                        {'details': ['Allowed UID ranges: unrestricted', 'Required permission: NETWORK']},
                        {'details': ['Allowed UID ranges: unrestricted', 'Required permission: NONE',
                                     'Per-app UID ranges: prio -1 uids{ 10000 }']}):
            self.setUp()
            self.device.networks[3].update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.control.netd_observation()
        for fib in ([], ['default dev wlan0'], [ETH0_FIB[0]] * 2,
                    ['default dev eth0 dev wlan0'], ['default dev eth0 dev eth0']):
            self.setUp()
            self.device.eth0_fib = fib
            with self.subTest(fib=fib), self.assertRaisesRegex(RuntimeError, 'invalid_eth0_fib'):
                self.control.netd_observation()
        for index in (0, -1, 2147483648, 'unknown'):
            self.setUp()
            self.device.eth0_ifindex = index
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, 'invalid_eth0_identity'):
                self.control.netd_observation()

    def test_uid_metadata_accepts_empty_and_bounded_canonical_ranges(self):
        for allowed in ('uids{ }', 'uids{ 0 10000 10002-10005 2147483647 }'):
            self.device.networks[3]['details'] = [
                'Allowed UID ranges: ' + allowed, 'Per-app UID ranges: prio 0 uids{ }; prio 999 uids{ 0 }',
                'Required permission: NONE']
            with self.subTest(allowed=allowed):
                self.assertEqual(self.control.netd_observation()['networks'], self.device.networks)
        self.assertNotIn('netd_failure', self.evidence)

    def test_uid_metadata_rejects_noncanonical_values_and_priorities(self):
        for value in ('', '<BAD>', 'uids{}', 'uids{ 01 }', 'uids{ -1 }', 'uids{ 2147483648 }',
                      'uids{ 2-1 }', 'uids{ 1-1 }', 'uids{ 2 1 }', 'uids{ 1-3 1-2 }'):
            with self.subTest(value=value):
                self.assertFalse(proof.ethernet_metadata([
                    'Allowed UID ranges: ' + value, 'Required permission: NONE']))
        for value in ('', 'prio -1 uids{ }', 'prio 01 uids{ }', 'prio 1000 uids{ }',
                      'prio 0 unrestricted', 'prio 0 uids{ 1-1 }',
                      'prio 0 uids{ }; prio 0 uids{ }', 'prio 10 uids{ }; prio 0 uids{ }'):
            with self.subTest(value=value):
                self.assertFalse(proof.ethernet_metadata([
                    'Allowed UID ranges: unrestricted', 'Per-app UID ranges: ' + value,
                    'Required permission: NONE']))

    def test_stable_uid_restrictions_and_overlaps_survive_calibration_and_recovery(self):
        for renumber in (False, True):
            self.setUp()
            self.device.networks[3]['details'] = list(UID_DETAILS)
            self.device.renumber_on_start = renumber
            with self.subTest(renumber=renumber):
                self.run_control()
                lifecycle = self.evidence['helper_lifecycle']
                for snapshot in (lifecycle['before_stop'], lifecycle['after_start'],
                                 self.evidence['before'], self.evidence['fault'], self.evidence['after']):
                    self.assertEqual(proof.ethernet_network(snapshot['netd'])['details'], UID_DETAILS)
                self.assertEqual(self.evidence['status'], 'verified')
                self.assertNotIn('netd_failure', self.evidence)

    def test_legal_uid_metadata_changes_cannot_be_normalized_as_a_netid_rebuild(self):
        self.device.networks[3]['details'] = list(UID_DETAILS)
        before = {'netd': self.control.netd_observation()}
        before_rules = Counter(self.device.rules)
        self.device.renumber_eth0()
        after = {'netd': self.control.netd_observation()}
        after_rules = Counter(self.device.rules)
        for index, replacement in (
                (0, UID_DETAILS[0].replace('10000 10000 ', '10000 ')),
                (0, UID_DETAILS[0].replace('10002-10005', '10004-10005')),
                (1, UID_DETAILS[1].replace('prio 10', 'prio 11'))):
            changed = copy.deepcopy(after)
            proof.ethernet_network(changed['netd'])['details'][index] = replacement
            with self.subTest(replacement=replacement):
                self.assertFalse(proof.foreign_rules_preserved(before, changed, before_rules, after_rules))

    def test_snapshot_brackets_kernel_reads_with_matching_netd_observations(self):
        original = self.device.adb
        def adb(command, **kwargs):
            if command == proof.IP + ' -4 rule show':
                self.device.renumber_eth0()
            return original(command, **kwargs)
        self.control.adb = adb
        with self.assertRaisesRegex(RuntimeError, 'netd_changed_during_snapshot'):
            self.control.snapshot()
        observed = [i for i, command in enumerate(self.device.calls) if command == proof.NETD]
        self.assertEqual(len(observed), 2)
        self.assertLess(observed[0], self.device.calls.index(proof.IP + ' -4 rule show'))
        self.assertGreater(observed[1], self.device.calls.index(proof.IP + ' -4 rule show'))

    def test_only_observed_eth0_rebuild_can_rename_the_exact_android_rule_pair(self):
        self.device.renumber_on_start = True
        self.run_control()
        lifecycle = self.evidence['helper_lifecycle']
        old = proof.ethernet_network(lifecycle['before_stop']['netd'])
        active = proof.ethernet_network(self.evidence['before']['netd'])
        new = proof.ethernet_network(self.evidence['after']['netd'])
        self.assertEqual([old['net_id'], active['net_id'], new['net_id']], [100, 102, 104])
        self.assertEqual(self.evidence['before']['netd'], self.evidence['fault']['netd'])
        self.assertTrue(self.evidence['recovered_app']['ok'])
        self.assertEqual(self.evidence['status'], 'verified')

    def test_platform_metadata_cannot_change_during_the_fault(self):
        original = self.device.adb
        def adb(command, **kwargs):
            result = original(command, **kwargs)
            if ' rule del ' in command and not any('lookup 2022' in row for row in self.device.rules):
                self.device.networks[0]['details'] = ['Allowed UID ranges: uids{ 10000 }']
            return result
        self.control.adb = adb
        with self.assertRaisesRegex(RuntimeError, 'fault_not_confined_to_owned_rules'):
            self.run_control()
        self.assertNotIn('recovery_after', self.evidence)

    def test_netd_metadata_other_than_eth0_id_cannot_be_normalized(self):
        before = {'netd': self.control.netd_observation()}
        before_rules = Counter(self.device.rules)
        self.device.renumber_eth0()
        after = {'netd': self.control.netd_observation()}
        after_rules = Counter(self.device.rules)
        self.assertTrue(proof.foreign_rules_preserved(before, after, before_rules, after_rules))
        variants = []
        for field, value in (('eth0_ifindex', 18), ('eth0_fib', ['default via 10.0.2.3 dev eth0'])):
            changed = copy.deepcopy(after)
            changed['netd'][field] = value
            variants.append(changed)
        for change in ('permission', 'uid_range', 'remove_network', 'retained_old_id'):
            changed = copy.deepcopy(after)
            networks = changed['netd']['networks']
            if change == 'permission':
                networks[3]['details'][-1] = 'Required permission: SYSTEM'
            elif change == 'uid_range':
                networks[0]['details'] = ['Allowed UID ranges: uids{ 10000 }']
            elif change == 'remove_network':
                networks.pop(0)
            else:
                networks.append({'net_id': 100, 'type': 'LOCAL', 'interfaces': [],
                                 'details': ['Allowed UID ranges: unrestricted']})
                networks.sort(key=lambda item: item['net_id'])
            variants.append(changed)
        for index, changed in enumerate(variants):
            with self.subTest(index=index):
                self.assertFalse(proof.foreign_rules_preserved(before, changed, before_rules, after_rules))
        occupied = copy.deepcopy(before)
        occupied['netd']['networks'].append({'net_id': 102, 'type': 'LOCAL', 'interfaces': [],
                                             'details': ['Allowed UID ranges: unrestricted']})
        self.assertFalse(proof.foreign_rules_preserved(occupied, after, before_rules, after_rules))

    def test_exact_eth0_pair_is_required_even_without_a_netid_change(self):
        before = {'netd': self.control.netd_observation()}
        before_rules = Counter(self.device.rules)
        for renumber in (False, True):
            if renumber:
                self.device.renumber_eth0()
            after = {'netd': self.control.netd_observation()}
            after_rules = Counter(self.device.rules)
            pair = list(proof.ethernet_rules(after['netd']))
            for replacement in (None, pair[0].replace('/0x1ffff', '/0xffff'),
                                pair[0].replace('iif lo', 'iif lo uidrange 0-0'),
                                pair[0].replace('16000:', '16001:')):
                changed = after_rules - Counter([pair[0]])
                if replacement:
                    changed[replacement] += 1
                with self.subTest(renumber=renumber, replacement=replacement):
                    self.assertFalse(proof.foreign_rules_preserved(before, after, before_rules, changed))
            self.assertFalse(proof.foreign_rules_preserved(before, after, before_rules,
                                                           after_rules + Counter([pair[1]])))

    def test_normal_tick_proves_missing_then_real_observations_of_recovery(self):
        self.run_control()
        result = self.evidence
        self.assertEqual(result['status'], 'verified')
        self.assertNotIn('netd_failure', result)
        self.assertEqual(result['removed_rule_count'], 2)
        self.assertEqual(result['first_missing']['consecutive_failures'], 1)
        self.assertEqual(result['before']['core_pid'], result['fault']['core_pid'])
        self.assertNotEqual(result['before']['core_pid'], result['after']['core_pid'])
        self.assertEqual(result['recovery_after']['recovery_attempts'], 1)
        self.assertEqual(result['baseline_app']['accepted'], 1)
        self.assertEqual(result['fault_app']['accepted'], 0)
        self.assertEqual(result['recovered_app']['accepted'], 1)
        self.assertTrue(all(set(result[key]) == set(proof.UDP_FIELDS) for key in
                            ('baseline_app', 'fault_app', 'recovered_app')))
        self.assertGreaterEqual(self.clock, 60)
        self.assertFalse(any('service restart' in call or '.state/machines/' in call
                             for call in self.device.calls))
        lifecycle = result['helper_lifecycle']
        self.assertEqual(lifecycle['stopped']['helper_fib'], [])
        self.assertEqual(lifecycle['after_start']['helper'], result['before']['helper'])
        self.assertEqual(result['before']['helper'], result['fault']['helper'])
        self.assertNotEqual(result['before']['helper']['table'], result['after']['helper']['table'])
        self.assertEqual(result['after']['previous_helper_fib'], [])
        first_delete = next(i for i, call in enumerate(self.device.calls) if ' rule del ' in call)
        self.assertFalse(any(' service stop ' in call or ' service start ' in call
                             for call in self.device.calls[first_delete:]))

    def test_helper_table_number_can_be_reused_after_observed_close(self):
        self.device.reuse_helper = True
        self.run_control()
        before, after = self.evidence['before'], self.evidence['after']
        self.assertEqual(before['helper'], after['helper'])
        self.assertEqual(after['previous_helper_fib'], after['helper']['fib'])
        self.assertEqual(self.evidence['status'], 'verified')

    def test_startup_cannot_launder_a_helper_not_removed_by_close(self):
        self.device.retain_old_helper_fib = True
        with self.assertRaisesRegex(RuntimeError, 'helper_not_removed_by_close'):
            self.run_control()
        self.assertNotIn(proof.CLI + ' service start sing-box', self.device.calls)

    def test_second_or_unknown_priority_one_rule_is_not_adopted(self):
        for row in ('1: from all lookup 777777', '1: from all fwmark 0x1 lookup 777777'):
            self.setUp()
            self.device.rules.append(row)
            with self.subTest(rule=row), self.assertRaisesRegex(RuntimeError, 'helper_rule_ambiguous'):
                self.run_control()
            self.assertNotIn(proof.CLI + ' service stop sing-box', self.device.calls)

    def test_helper_fib_must_be_exclusively_unique_interface_loopback_host_routes(self):
        for fib in ([], ['default dev eth0'], ['local 127.0.0.2 dev eth0 scope host'],
                    ['local 127.0.0.1 dev lo scope host'],
                    ['local 127.0.0.1 dev magicnet0 scope host'], [HELPER_FIB[0]] * 2):
            self.setUp()
            self.device.helpers[self.device.helper_table] = fib
            with self.subTest(fib=fib), self.assertRaises(RuntimeError):
                self.run_control()
            self.assertNotIn(proof.CLI + ' service stop sing-box', self.device.calls)

    def test_empty_or_missing_local_anchor_cannot_prove_a_stopped_snapshot(self):
        for observed in ('', '32766: from all lookup main', '0: from all lookup local\n' * 2):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                if command == proof.IP + ' -4 rule show' and not self.device.running:
                    return subprocess.CompletedProcess(['adb'], 0, observed, '')
                return original(command, **kwargs)
            self.control.adb = adb
            with self.subTest(observed=observed), self.assertRaisesRegex(RuntimeError, 'local_rule_anchor'):
                self.run_control()
            self.assertNotIn(proof.CLI + ' service start sing-box', self.device.calls)

    def test_stopped_fib_read_failure_or_empty_global_dump_is_not_an_empty_helper(self):
        for code in (0, 1, 124):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                if command == proof.IP + ' -4 route show table all' and not self.device.running:
                    return subprocess.CompletedProcess(['adb'], code, '', 'read unavailable' if code else '')
                return original(command, **kwargs)
            self.control.adb = adb
            with self.subTest(code=code), self.assertRaises(RuntimeError):
                self.run_control()
            self.assertNotIn(proof.CLI + ' service start sing-box', self.device.calls)

    def test_recovery_cannot_leave_previous_helper_fib_behind(self):
        def sentinel():
            self.device.retain_old_helper_fib = True
            return self.device.app()
        with self.assertRaisesRegex(RuntimeError, 'previous_helper_not_removed'):
            self.run_control(sentinel)

    def test_unobserved_core_change_after_calibration_cannot_claim_helper_ownership(self):
        self.calibrate()
        self.device.stop()
        self.device.start_core()
        with patch.object(proof.time, 'monotonic', lambda: self.clock), patch.object(proof.time, 'sleep', self.sleep):
            with self.assertRaisesRegex(RuntimeError, 'helper_ownership_not_bound_to_core'):
                self.control.rpdb_loss(self.device.app, 10123)
        self.assertFalse(any(' rule del ' in call for call in self.device.calls))

    def test_exact_zero_selector_may_delete_only_recorded_sibling(self):
        self.device.delete_sibling = True
        self.run_control()
        self.assertEqual(self.evidence['removed_rule_count'], 2)
        self.assertEqual(Counter(self.device.rules) - Counter([self.device.helper_rule()]),
                         Counter(FOREIGN + OWNED))

    def test_android_goto_target_survives_lookup_only_fault(self):
        # Real API 35 artifact: goto 9002 is outside the active ledger, while
        # nop 9002 is owned. Deleting the nop changes goto to [unresolved].
        owned = ['9001: from all fwmark 0x400000/0xe00000 lookup 2022',
                 '9002: from all nop', '32768: not from all fwmark 0x200000/0xe00000 lookup 2022']
        foreign = FOREIGN + ['9000: from all fwmark 0x200000/0xe00000 goto 9002']
        ledger = LEDGER.split('rule4=', 1)[0] + ''.join('rule4=' + row + '\n' for row in owned)
        with patch.dict(globals(), OWNED=owned, FOREIGN=foreign, LEDGER=ledger):
            self.device = Device()
            original = self.device.adb
            def adb(command, **kwargs):
                result = original(command, **kwargs)
                if ' rule del ' in command and '9002: from all nop' not in self.device.rules:
                    self.device.rules = [row + ' [unresolved]' if row.endswith('goto 9002') else row
                                         for row in self.device.rules]
                return result
            self.control = proof.Control(adb, self.evidence)
            self.run_control()
            self.assertEqual(self.evidence['owned_rules'], owned)
            self.assertEqual(self.evidence['removed_rule_count'], 2)
            self.assertEqual(Counter(self.evidence['fault']['rules']),
                             Counter(foreign + ['9002: from all nop', self.evidence['before']['helper']['rule']]))
            self.assertTrue(all('lookup 2022' in call for call in self.device.calls if ' rule del ' in call))
        with self.assertRaisesRegex(RuntimeError, 'invalid_rule_snapshot'):
            proof.rules('9000: from all goto 9002 [unresolved]')

    def test_ledger_without_capture_selectors_never_deletes_goto_or_nop(self):
        self.device.ledger = '\n'.join(row for row in LEDGER.splitlines() if 'lookup 2022' not in row)
        with self.assertRaisesRegex(RuntimeError, 'owned_capture_rule_unavailable'):
            self.run_control()
        self.assertFalse(any(' rule del ' in call for call in self.device.calls))

    def test_foreign_same_priority_aborts_before_any_delete(self):
        self.device.rules.append('9000: from all fwmark 0x42 lookup main')
        with self.assertRaisesRegex(RuntimeError, 'foreign_rule_at_owned_priority'):
            self.run_control()
        self.assertFalse(any(' rule del ' in call for call in self.device.calls))

    def test_wrong_boot_or_prepared_ledger_aborts_before_any_delete(self):
        for text in (LEDGER.replace(BOOT, '0' * 36), LEDGER.replace('active', 'prepared'),
                     LEDGER + 'table=2022\n', LEDGER.replace('rule4=9000:', 'rule4=8000:')):
            self.device = Device()
            self.device.ledger = text
            self.control = proof.Control(self.device.adb, self.evidence)
            with self.subTest(ledger=text), self.assertRaises(RuntimeError):
                self.run_control()
            self.assertFalse(any(' rule del ' in call for call in self.device.calls))

    def test_process_restart_during_injection_is_not_route_loss_evidence(self):
        self.device.restart_on_delete = True
        with self.assertRaisesRegex(RuntimeError, 'core_identity_unchanged_failed'):
            self.run_control()

    def test_health_false_green_fails_before_recovery(self):
        self.device.health_green = True
        with self.assertRaisesRegex(RuntimeError, 'health_did_not_report_rpdb_loss'):
            self.run_control()
        self.assertNotIn('recovery_after', self.evidence)

    def test_completed_app_timeout_proves_no_marker_but_instrumentation_timeout_does_not(self):
        def sentinel():
            result = self.device.app()
            if not result['ok']:
                result['reason'] = 'timeout'
                result['elapsed_ms'] = 5000
            return result
        self.run_control(sentinel)
        self.assertEqual(self.evidence['fault_app']['reason'], 'timeout')
        for changes in ({'complete': False}, {'uid': 0}, {'accepted': 1}, {'reason': 'transport'},
                        {'elapsed_ms': 0}, {'elapsed_ms': 15001}, {'elapsed_ms': True}):
            failed = dict(ok=False, complete=True, uid=10123, reason='timeout', accepted=0,
                          elapsed_ms=5000) | changes
            with self.subTest(changes=changes):
                self.assertFalse(proof.app_result(failed, 10123, False))

    def test_udp_receiver_or_request_failure_never_proves_a_route_failure(self):
        for key in ('receiver_bound', 'receiver_closed', 'request_attempted'):
            for value in (False, None, 0, 1, 'true'):
                self.setUp()
                def sentinel():
                    result = self.device.app()
                    return result if result['ok'] else result | {key: value}
                with self.subTest(key=key, value=value), self.assertRaisesRegex(
                        RuntimeError, 'fault_app_rejection_not_proven'):
                    self.run_control(sentinel)
                self.assertNotIn('recovery_after', self.evidence)

    def test_tcp_cannot_substitute_for_udp_at_any_rpdb_observation(self):
        for changed_probe, reason in ((1, 'baseline_app_not_captured'),
                                      (2, 'fault_app_rejection_not_proven'),
                                      (3, 'recovered_app_not_captured')):
            self.setUp()
            calls = []
            def sentinel():
                calls.append(True)
                result = self.device.app()
                return result | {'transport': 'tcp'} if len(calls) == changed_probe else result
            with self.subTest(probe=changed_probe), self.assertRaisesRegex(RuntimeError, reason):
                self.run_control(sentinel)
            self.assertNotEqual(self.evidence.get('status'), 'verified')

    def test_a5c_successful_marker_after_rule_loss_is_not_a_negative_control(self):
        def sentinel():
            return self.device.app() | {'ok': True, 'reason': 'sentinel', 'accepted': 1}
        with self.assertRaisesRegex(RuntimeError, 'fault_app_rejection_not_proven'):
            self.run_control(sentinel)
        self.assertTrue(self.evidence['fault_app']['ok'])
        self.assertFalse(self.evidence['ready_after_fault'])
        self.assertNotIn('recovery_after', self.evidence)

    def test_missing_automatic_recovery_hits_real_deadline_without_manual_restart(self):
        self.device.recover = False
        with self.assertRaisesRegex(RuntimeError, 'automatic_recovery_deadline'):
            self.run_control()
        self.assertGreaterEqual(self.clock, proof.RECOVERY_TIMEOUT)
        self.assertEqual(self.device.pid, 421)
        self.assertFalse(any('service restart' in call for call in self.device.calls))

    def test_background_first_missing_is_read_before_eligible_explicit_tick(self):
        original = self.device.adb
        background, ticks = [], []
        self.clock = 1000
        def adb(command, **kwargs):
            if command == proof.CLI + ' connectivity tick':
                ticks.append(self.clock)
            result = original(command, **kwargs)
            if (' rule del ' in command and not background
                    and not any('lookup 2022' in row for row in self.device.rules)):
                original(proof.CLI + ' connectivity tick')
                background.append(self.clock)
                self.assertEqual(self.device.state['consecutive_failures'], 1)
            if command != proof.CLI + ' connectivity tick':
                # Every individual read remains within its real command budget.
                self.assertGreaterEqual(kwargs.get('timeout', 10), 8)
                self.clock += 8
            return result
        self.control.adb = adb
        self.run_control()
        self.assertGreaterEqual(ticks[-1] - background[0], proof.TICK_INTERVAL)
        self.assertEqual(self.evidence['first_missing']['consecutive_failures'], 1)
        self.assertEqual(self.evidence['first_missing_identity']['core_pid'], 421)
        self.assertEqual(self.evidence['after']['core_pid'], 422)
        self.assertEqual(self.evidence['status'], 'verified')

    def test_wait_reads_pending_confirmation_before_due_tick(self):
        self.calibrate()
        self.device.rules = FOREIGN + [row for row in OWNED if 'lookup 2022' not in row] + [self.device.helper_rule()]
        self.device.state = state('missing', failures=1)
        self.clock, self.control.last_tick = 60, 0
        observed = []
        def recovered(value):
            observed.append((value['status'], value['consecutive_failures'], self.device.pid))
            return value['status'] == 'present' and value['recovery_attempts'] == 1
        with patch.object(proof.time, 'monotonic', lambda: self.clock), patch.object(proof.time, 'sleep', self.sleep):
            self.control.wait(recovered, proof.RECOVERY_TIMEOUT, 'test_deadline')
        self.assertEqual(observed[0], ('missing', 1, 421))
        self.assertEqual(observed[-1], ('present', 0, 422))

    def test_recovery_cannot_destroy_foreign_rules(self):
        self.device.foreign_on_recover = True
        with self.assertRaisesRegex(RuntimeError, 'recovery_rule_set_mismatch'):
            self.run_control()
        self.assertTrue(self.evidence['ready_after_recovery'])
        self.assertTrue(self.evidence['recovered_app']['ok'])
        self.assertNotEqual(self.evidence.get('status'), 'verified')

    def test_unknown_or_malformed_observation_cannot_become_ready(self):
        for value in (None, {}, state() | {'warning': 0}, state() | {'recovery_attempts': True},
                      state() | {'recovery_limit': 4}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.device.state = value
                self.control.connectivity()

    def test_disposable_opt_in_and_explicit_emulator_are_required_before_any_command(self):
        for env in ({}, {'MAGICNET_DISPOSABLE_AVD': '1', 'ANDROID_SERIAL': 'physical-device'}):
            with patch.dict(os.environ, env, clear=True):
                result = proof.verify(lambda *_: self.fail('must not contact device'), None, None)
            self.assertEqual(result['status'], 'not_verified')

    def test_uplink_down_up_preserves_live_adb_and_app_path(self):
        evidence = {}
        proof.uplink_reconnect(self.control, self.device.app, 10123, evidence)
        self.assertEqual(evidence['status'], 'verified')
        self.assertTrue(evidence['down_observed'])
        self.assertTrue(evidence['up_observed'])
        self.assertTrue(evidence['control_channel_survived'])
        self.assertTrue(evidence['restore_guard_finished'])

    def test_uplink_carrying_adb_is_rejected_before_mutation(self):
        self.device.peers += TCP + '\n'
        with self.assertRaisesRegex(RuntimeError, 'uplink_carries_adb_control'):
            proof.uplink_reconnect(self.control, self.device.app, 10123, {})
        self.assertFalse(any('link set' in call for call in self.device.calls))

    def test_android_multiple_defaults_use_kernel_selected_egress(self):
        self.device.uplinks = ['eth0', 'wlan0']
        evidence = {}
        proof.uplink_reconnect(self.control, self.device.app, 10123, evidence)
        self.assertEqual(evidence['status'], 'verified')
        self.assertEqual(evidence['interface'], 'wlan0')
        self.assertEqual(evidence['default_interfaces'], ['eth0', 'wlan0'])
        self.assertFalse(any('link set dev eth0' in call for call in self.device.calls))

    def test_unknown_or_non_default_egress_is_rejected_before_mutation(self):
        for selected in ('', 'magicnet0', 'lo', 'eth0'):
            self.device.calls.clear()
            self.device.selected_uplink = selected
            with self.subTest(selected=selected), self.assertRaisesRegex(RuntimeError, 'ambiguous_or_missing_uplink'):
                proof.uplink_reconnect(self.control, self.device.app, 10123, {})
            self.assertFalse(any('link set' in call for call in self.device.calls))

    def test_failed_down_observation_still_restores_uplink(self):
        self.device.fail_down_observation = True
        with self.assertRaisesRegex(RuntimeError, 'device_command_failed'):
            proof.uplink_reconnect(self.control, self.device.app, 10123, {})
        self.assertIn(proof.IP + ' link set dev wlan0 up', self.device.calls[-3:])
        self.assertTrue(self.device.flags & 1)

    def test_live_restore_guard_must_finish_before_next_phase(self):
        original = self.device.adb
        def adb(command, **kwargs):
            if command.startswith('if [ -r /proc/500/stat ]'):
                output = '500 (sh) S ' + '0 ' * 18 + '850\n' if self.clock < 10 else 'gone\n'
                return subprocess.CompletedProcess(['adb'], 0, output, '')
            return original(command, **kwargs)
        self.control.adb = adb
        evidence = {}
        with patch.object(proof.time, 'monotonic', lambda: self.clock), patch.object(proof.time, 'sleep', self.sleep):
            proof.uplink_reconnect(self.control, self.device.app, 10123, evidence)
        self.assertEqual(self.clock, 10)
        self.assertTrue(evidence['restore_guard_finished'])

    def test_unfinished_restore_guard_fails_even_after_uplink_is_up(self):
        original = self.device.adb
        def adb(command, **kwargs):
            if command.startswith('if [ -r /proc/500/stat ]'):
                return subprocess.CompletedProcess(['adb'], 0, '500 (sh) S ' + '0 ' * 18 + '850\n', '')
            return original(command, **kwargs)
        self.control.adb = adb
        with patch.object(proof.time, 'monotonic', lambda: self.clock), patch.object(proof.time, 'sleep', self.sleep):
            with self.assertRaisesRegex(RuntimeError, 'uplink_restore_guard_deadline'):
                proof.uplink_reconnect(self.control, self.device.app, 10123, {})
        self.assertTrue(self.device.flags & 1)
        self.assertEqual(self.clock, 15)

    def test_adb_transport_unknown_is_not_an_off_interface_proof(self):
        for text in ('ADBD\nTCP\n', 'ADBD\n/dev/null\nTCP\n' + HEADER,
                     'ADBD\n/dev/null\nTCP\n' + HEADER + '\ncorrupt\n' + HEADER):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                proof.control_peers(text)
        self.assertEqual(proof.control_peers(self.device.peers + TCP + '\n'), ['10.0.2.2'])


if __name__ == '__main__':
    unittest.main()
