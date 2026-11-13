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
from types import SimpleNamespace
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
RESTRICTED_RULES = {
    'NETWORK': '16000: from all fwmark 0x50064/0x5ffff iif lo lookup eth0',
    'SYSTEM': '16000: from all fwmark 0xd0064/0xdffff iif lo lookup eth0',
}
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
CELLULAR = json.loads((ROOT / 'tests/fixtures/android-route-recovery-cellular.json').read_text())


def state(status='present', failures=0, attempts=0):
    return dict(status=status, warning=status in ('missing', 'unknown'), checked_at=100,
                next_check_at=160, retry_in_seconds=60, consecutive_failures=failures,
                recovery_attempts=attempts, recovery_limit=3,
                recovery_status='ok' if attempts else 'none',
                last_recovery_at=90 if attempts else None)


def app_rules(net_id, priority, intervals):
    return [f'{base + priority}: from all fwmark {mark:#x}/0x1ffff '
            f'iif lo uidrange {low}-{high} lookup eth0'
            for low, high in intervals
            for base, mark in ((15000, 0x10000 | net_id), (22000, net_id))]


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
        self.qemu, self.abi, self.wifi_on = '1', 'x86_64', True
        self.user_data_enabled = self.data_enabled = self.cellular_connected = True
        self.data_state, self.sub_id, self.mobile_new_net_id = 2, 1, True
        self.stopped_cellular = None

    def registry_dump(self):
        phase = 'before' if self.cellular_connected else 'down'
        text = CELLULAR[phase]['registry']
        if self.cellular_connected:
            network = next((item for item in self.networks if item['interfaces'] == ['eth0']),
                           self.stopped_cellular)
            text = text.replace('netId: 101,', f'netId: {network["net_id"]},')
        text = text.replace('mDataConnectionState=' + ('2' if self.cellular_connected else '0'),
                            f'mDataConnectionState={self.data_state}')
        for field, value in (('mUserMobileDataState= ', self.user_data_enabled),
                             ('mIsDataEnabled=', self.data_enabled)):
            text = text.replace(field + ('true' if self.cellular_connected else 'false'),
                                field + str(value).lower())
        return text.replace('mActiveDataSubId=1', f'mActiveDataSubId={self.sub_id}').replace(
            'mDefaultSubId=1', f'mDefaultSubId={self.sub_id}')

    def phone_dump(self):
        return CELLULAR['before']['phone'].replace('mDefaultDataSubId=1', f'mDefaultDataSubId={self.sub_id}')

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

    def renumber_eth0(self, step=2):
        network = next(item for item in self.networks if item['interfaces'] == ['eth0'])
        old_id = network['net_id']
        network['net_id'] += step
        for prefix in (0x10000, 0x50000, 0xd0000, 0):
            old, new = f'fwmark {prefix | old_id:#x}/', f'fwmark {prefix | network["net_id"]:#x}/'
            self.rules = [row.replace(old, new) if row.endswith(' lookup eth0') else row
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

    def tcp_app(self):
        result = self.app()
        return {key: result[key] for key in proof.APP_FIELDS}

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
        elif command == proof.REGISTRY:
            output = self.registry_dump()
        elif command == proof.PHONE:
            output = self.phone_dump()
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
        elif command == 'getprop ro.kernel.qemu':
            output = self.qemu
        elif command == 'getprop ro.product.cpu.abi':
            output = self.abi
        elif command == proof.WIFI + ' status':
            output = ('Wifi is enabled' if self.wifi_on else 'Wifi is disabled') + '\nWifiInfo: private-ssid\n'
        elif command in (proof.WIFI + ' set-wifi-enabled enabled', proof.WIFI + ' set-wifi-enabled disabled'):
            self.wifi_on = command.endswith(' enabled')
            self.networks = [item for item in self.networks if 'wlan0' not in item['interfaces']]
            if self.wifi_on:
                self.networks.append(copy.deepcopy(NETWORKS[-1]))
            self.rules = [row for row in self.rules if not row.endswith(' lookup wlan0')]
            if self.wifi_on:
                self.rules.append(FOREIGN[2])
            self.uplinks = ['eth0', 'wlan0'] if self.wifi_on else ['eth0']
            self.selected_uplink = 'wlan0' if self.wifi_on else 'eth0'
        elif command.startswith('p=$(' + proof.BB + ' pidof adbd)'):
            output = self.peers
        elif command == proof.IP + ' -4 route get 10.0.2.2':
            output = '10.0.2.2 dev wlan0 src 10.0.2.15'
        elif (command == 'cat /sys/class/net/eth0/flags'
              or command.startswith('if [ -r /sys/class/net/') and command.endswith('/flags; else echo 0x0; fi')):
            self.flag_reads += 1
            if self.fail_down_observation and self.flag_reads == 2:
                rc = 1
            output = hex(self.flags)
        elif command.startswith(proof.BB + ' nohup '):
            output = '500 (sh) S ' + '0 ' * 18 + '850\n'
        elif command == 'if [ -r /proc/500/stat ]; then cat /proc/500/stat; else echo gone; fi':
            output = 'gone\n'
        elif command == proof.MOBILE_DATA + ' disable':
            self.user_data_enabled = self.data_enabled = self.cellular_connected = False
            self.data_state = 0
            self.flags &= ~1
            self.stopped_cellular = next(item for item in self.networks if item['interfaces'] == ['eth0'])
            self.networks.remove(self.stopped_cellular)
            unreachable = next(item for item in self.networks if item['net_id'] == 52)
            unreachable['details'] += [row for row in self.stopped_cellular['details']
                                       if row.startswith('Per-app UID ranges: ')]
            unreachable['details'].sort()
            self.uplinks = [name for name in self.uplinks if name != 'eth0']
        elif command == proof.MOBILE_DATA + ' enable':
            self.user_data_enabled = self.data_enabled = self.cellular_connected = True
            self.data_state = 2
            self.flags |= 1
            if self.stopped_cellular is not None:
                self.networks.append(self.stopped_cellular)
                if self.mobile_new_net_id:
                    self.renumber_eth0(step=1)
                self.stopped_cellular = None
            unreachable = next(item for item in self.networks if item['net_id'] == 52)
            unreachable['details'] = [row for row in unreachable['details']
                                      if not row.startswith('Per-app UID ranges: ')]
            if 'eth0' not in self.uplinks:
                self.uplinks.append('eth0')
        elif command == proof.IP + ' link set dev wlan0 down':
            self.flags &= ~1
        elif command.startswith(proof.IP + ' link set dev wlan0 up'):
            self.flags |= 1
        else:
            raise AssertionError('unexpected command: ' + command)
        return subprocess.CompletedProcess(['adb'], rc, output, '')


class NetworkFixtureTests(unittest.TestCase):
    def setUp(self):
        self.device, self.evidence, self.clock = Device(), {}, 0
        self.control = proof.Control(self.device.adb, {})

    def sleep(self, seconds):
        self.clock += seconds

    def run_fixture(self, body=lambda: None):
        with patch.object(proof.time, 'monotonic', lambda: self.clock), \
                patch.object(proof.time, 'sleep', self.sleep):
            with proof.single_uplink_fixture(self.control, self.evidence):
                body()

    def run_report(self, *, evidence=None, udp_sentinel=None, failure_observer=None, cleanup_observer=None):
        def inner_verify(adb, _instrument, _component, *, fault_control, lifecycle_observer):
            self.assertFalse(self.device.wifi_on)
            try:
                lifecycle_observer('before_stop')
                adb(proof.CLI + ' service stop sing-box')
                lifecycle_observer('stopped')
                adb(proof.CLI + ' service start sing-box')
                lifecycle_observer('after_start')
                fault_control(self.device.tcp_app, 10123, udp_sentinel or self.device.app)
                return dict(status='verified', positive=True, reject=True, positive_after=True, restored=True)
            finally:
                if cleanup_observer:
                    cleanup_observer()

        module = SimpleNamespace(verify=inner_verify)
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
        with patch.dict(os.environ, MAGICNET_DISPOSABLE_AVD='1', ANDROID_SERIAL='emulator-5554'), \
                patch.object(proof.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(proof.importlib.util, 'module_from_spec', return_value=module), \
                patch.object(proof.time, 'monotonic', lambda: self.clock), \
                patch.object(proof.time, 'sleep', self.sleep):
            return proof.verify(self.control.adb, None, None, evidence, failure_observer=failure_observer)

    def test_enabled_wifi_is_disabled_before_two_stable_ethernet_observations_then_restored(self):
        def body():
            self.assertFalse(self.device.wifi_on)
            self.assertTrue(self.evidence['prepared'])
            self.assertEqual(self.clock, proof.POLL_INTERVAL)
            observations = self.evidence['stable_observations']
            self.assertEqual(len(observations), 2)
            self.assertEqual(observations[0], observations[1])
            self.assertIsNot(observations[0], observations[1])
            self.assertEqual(observations[0]['egress'], 'eth0')
            physical = [item for item in observations[0]['netd']['networks'] if item['type'] == 'PHYSICAL']
            self.assertEqual([item['interfaces'] for item in physical], [['eth0']])
            self.assertIn(ETH0_RULES[0], observations[0]['rules'])
        self.run_fixture(body)
        self.assertTrue(self.device.wifi_on)
        self.assertTrue(self.evidence['wifi_initial_enabled'])
        self.assertTrue(self.evidence['wifi_final_enabled'])
        self.assertTrue(self.evidence['restored'])
        self.assertTrue(self.evidence['control_transport_verified'])
        self.assertNotIn('private-ssid', json.dumps(self.evidence))
        self.assertLess(self.device.calls.index('getprop ro.product.cpu.abi'),
                        self.device.calls.index(proof.WIFI + ' set-wifi-enabled disabled'))

    def test_initially_disabled_wifi_remains_disabled(self):
        self.device.adb(proof.WIFI + ' set-wifi-enabled disabled')
        self.device.calls.clear()
        self.run_fixture()
        self.assertFalse(self.evidence['wifi_initial_enabled'])
        self.assertFalse(self.evidence['wifi_final_enabled'])
        self.assertTrue(self.evidence['restored'])
        self.assertNotIn(proof.WIFI + ' set-wifi-enabled enabled', self.device.calls)
        self.assertEqual(self.device.calls.count(proof.WIFI + ' set-wifi-enabled disabled'), 1)

    def test_real_device_or_wrong_abi_is_rejected_before_wifi_mutation(self):
        for attribute, value in (('qemu', '0'), ('qemu', ''), ('abi', 'arm64-v8a'), ('abi', 'x86')):
            self.setUp()
            setattr(self.device, attribute, value)
            with self.subTest(attribute=attribute, value=value), self.assertRaisesRegex(
                    RuntimeError, '^disposable_x86_emulator_required$'):
                self.run_fixture(lambda: self.fail('must not enter proof'))
            self.assertFalse(any('set-wifi-enabled' in call for call in self.device.calls))

    def test_wifi_carried_or_ambiguous_adb_transport_is_rejected_before_disable(self):
        for route in ('10.0.2.2 dev wlan0 src 10.0.2.15', '', '10.0.2.2 dev eth0 dev wlan0'):
            self.setUp()
            self.device.peers += TCP + '\n'
            original = self.device.adb
            def adb(command, **kwargs):
                return (subprocess.CompletedProcess(['adb'], 0, route, '')
                        if command == proof.IP + ' -4 route get 10.0.2.2'
                        else original(command, **kwargs))
            self.control.adb = adb
            with self.subTest(route=route), self.assertRaisesRegex(RuntimeError, 'uplink_carries_adb_control'):
                self.run_fixture(lambda: self.fail('must not enter proof'))
            self.assertFalse(any('set-wifi-enabled' in call for call in self.device.calls))

    def test_unknown_wifi_status_is_not_guessed_or_copied_into_evidence(self):
        for text in ('', 'Wifi is unknown\nprivate-ssid', 'Wifi is enabled unexpectedly',
                     'private-ssid\nWifi is enabled'):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                return (subprocess.CompletedProcess(['adb'], 0, text, '') if command == proof.WIFI + ' status'
                        else original(command, **kwargs))
            self.control.adb = adb
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError, '^wifi_state_unavailable$'):
                self.run_fixture(lambda: self.fail('must not enter proof'))
            self.assertFalse(any('set-wifi-enabled' in call for call in self.device.calls))
            self.assertNotIn('private-ssid', json.dumps(self.evidence))

    def test_async_wlan_teardown_and_policy_changes_reset_stable_observations(self):
        original = self.device.adb
        def adb(command, **kwargs):
            result = original(command, **kwargs)
            if command == proof.NETD and self.clock == 0:
                current = self.device.networks
                self.device.networks = current + [copy.deepcopy(NETWORKS[-1])]
                result.stdout = self.device.netd_dump()
                self.device.networks = current
            if command == proof.IP + ' -4 rule show' and self.clock == proof.POLL_INTERVAL:
                result.stdout += '\n31000: from all fwmark 0x0/0xffff lookup wlan0'
            return result
        self.control.adb = adb
        self.run_fixture()
        self.assertEqual(self.clock, proof.POLL_INTERVAL * 3)
        self.assertNotIn('31000: from all fwmark 0x0/0xffff lookup wlan0',
                         self.evidence['stable_observations'][0]['rules'])

    def test_persistent_competing_network_or_wrong_egress_never_enters_proof(self):
        for failure in ('physical', 'virtual_wlan', 'egress', 'selector'):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                result = original(command, **kwargs)
                if command == proof.NETD and failure in ('physical', 'virtual_wlan'):
                    current = self.device.networks
                    extra = copy.deepcopy(NETWORKS[-1])
                    if failure == 'virtual_wlan':
                        extra['type'] = 'VIRTUAL'
                        extra['details'] = ['Allowed UID ranges: unrestricted']
                    self.device.networks = current + [extra]
                    result.stdout = self.device.netd_dump()
                    self.device.networks = current
                if command == proof.IP + ' -4 route get 192.0.2.1' and failure == 'egress':
                    result.stdout = '192.0.2.1 dev wlan0'
                if command == proof.IP + ' -4 rule show' and failure == 'selector':
                    result.stdout = result.stdout.replace(ETH0_RULES[0], '')
                return result
            self.control.adb = adb
            with self.subTest(failure=failure), self.assertRaisesRegex(RuntimeError, '^single_uplink_baseline_deadline$'):
                self.run_fixture(lambda: self.fail('must not enter proof'))
            self.assertEqual(self.clock, proof.BASELINE_TIMEOUT)
            self.assertFalse(self.evidence['prepared'])
            self.assertTrue(self.evidence['restored'])
            self.assertTrue(self.device.wifi_on)

    def test_body_failure_and_partial_disable_failure_restore_initial_state(self):
        for during_disable in (False, True):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                result = original(command, **kwargs)
                if during_disable and command == proof.WIFI + ' set-wifi-enabled disabled':
                    result.returncode = 1
                return result
            self.control.adb = adb
            def body():
                raise RuntimeError('fixture_test_failure')
            with self.subTest(during_disable=during_disable), self.assertRaisesRegex(
                    RuntimeError, '^device_command_failed$' if during_disable else '^fixture_test_failure$'):
                self.run_fixture(body)
            self.assertTrue(self.evidence['restored'])
            self.assertTrue(self.evidence['wifi_final_enabled'])
            self.assertTrue(self.device.wifi_on)

    def test_competing_network_reappearing_after_preparation_is_rejected_before_fault(self):
        for stage in ('snapshot', 'uplink'):
            self.setUp()
            def body():
                self.device.adb(proof.WIFI + ' set-wifi-enabled enabled')
                if stage == 'snapshot':
                    self.control.snapshot()
                else:
                    proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, {}, required_interface='eth0')
            with self.subTest(stage=stage), self.assertRaisesRegex(RuntimeError, '^single_uplink_changed$'):
                self.run_fixture(body)
            self.assertTrue(self.evidence['restored'])
            self.assertFalse(self.control.single_ethernet_required)
            self.assertFalse(any('link set' in call or ' rule del ' in call for call in self.device.calls))

    def test_failed_restore_command_or_readback_retains_failure_and_never_verifies(self):
        for failure in ('command', 'readback', 'timeout'):
            self.setUp()
            original = self.device.adb
            restoring = False
            def adb(command, **kwargs):
                nonlocal restoring
                if command == proof.WIFI + ' set-wifi-enabled enabled':
                    restoring = True
                    if failure in ('command', 'timeout'):
                        return subprocess.CompletedProcess(['adb'], int(failure == 'command'), '', '')
                if restoring and command == proof.WIFI + ' status' and failure == 'readback':
                    return subprocess.CompletedProcess(['adb'], 1, 'private-ssid', '')
                return original(command, **kwargs)
            self.control.adb = adb
            with self.subTest(failure=failure):
                result = self.run_report()
                self.assertEqual(result['rpdb_loss']['status'], 'verified')
                self.assertEqual(result['uplink_reconnect']['status'], 'verified')
                self.assertEqual(result['tun_controls']['status'], 'verified')
                self.assertEqual(result['status'], 'not_verified')
                self.assertFalse(result['restored'])
                self.assertFalse(result['network_fixture']['restored'])
                self.assertEqual(result['reason'], 'network_fixture_restore_failed')
                self.assertIn('restore_reason', result['network_fixture'])
                self.assertNotIn('private-ssid', json.dumps(result))

    def test_whole_route_proof_runs_on_cellular_eth0_and_restores_wifi_before_success(self):
        result = self.run_report(failure_observer=lambda: self.fail('must not capture diagnostics on success'))
        self.assertEqual(result['status'], 'verified')
        self.assertTrue(result['restored'])
        self.assertTrue(result['network_fixture']['restored'])
        self.assertTrue(self.device.wifi_on)
        self.assertEqual(result['uplink_reconnect']['interface'], 'eth0')
        self.assertEqual(result['uplink_reconnect']['restore_method'], 'android_mobile_data_toggle')
        self.assertTrue(all('link set dev wlan0' not in call for call in self.device.calls))
        first_disable = self.device.calls.index(proof.WIFI + ' set-wifi-enabled disabled')
        first_stop = self.device.calls.index(proof.CLI + ' service stop sing-box')
        final_enable = self.device.calls.index(proof.WIFI + ' set-wifi-enabled enabled')
        self.assertLess(first_disable, first_stop)
        self.assertGreater(final_enable, self.device.calls.index(proof.MOBILE_DATA + ' enable'))
        self.assertTrue(all('wlan0' not in item['interfaces']
                            for key in ('before', 'fault', 'after')
                            for item in result['rpdb_loss'][key]['netd']['networks']))

    def test_failure_observer_sees_original_fault_before_cleanup_once_and_cannot_replace_reason(self):
        for capture_fails in (False, True):
            self.setUp()
            result, events = {}, []
            def udp():
                return self.device.app() | {'ok': False, 'reason': 'timeout', 'elapsed_ms': 5000, 'accepted': 0}
            def capture():
                events.append('capture')
                self.assertFalse(self.device.wifi_on)
                self.assertEqual(result['reason'], 'baseline_app_not_captured')
                self.assertEqual(result['rpdb_loss']['baseline_app']['reason'], 'timeout')
                self.assertNotIn('fault', result['rpdb_loss'])
                if capture_fails:
                    raise ValueError('private-diagnostic-failure')
            with self.subTest(capture_fails=capture_fails):
                self.run_report(evidence=result, udp_sentinel=udp, failure_observer=capture,
                                cleanup_observer=lambda: events.append('cleanup'))
                self.assertEqual(events, ['capture', 'cleanup'])
                self.assertEqual(result['status'], 'not_verified')
                self.assertEqual(result['reason'], 'baseline_app_not_captured')
                self.assertTrue(result['network_fixture']['restored'])
                self.assertTrue(self.device.wifi_on)
                self.assertEqual(result.get('failure_observer_failure'), 'capture_failed' if capture_fails else None)
                self.assertNotIn('private-diagnostic-failure', json.dumps(result))


class CellularLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.device, self.evidence, self.clock = Device(), {'recovery_tick_count': 0}, 0
        self.device.adb(proof.WIFI + ' set-wifi-enabled disabled')
        network = next(item for item in self.device.networks if item['interfaces'] == ['eth0'])
        network['details'].append('Per-app UID ranges: prio 40 uids{ 10134 }')
        network['details'].sort()
        self.device.calls.clear()
        self.control = proof.Control(self.device.adb, self.evidence)

    def sleep(self, seconds):
        self.clock += seconds

    def run_control(self):
        with patch.object(proof.time, 'monotonic', lambda: self.clock), \
                patch.object(proof.time, 'sleep', self.sleep):
            proof.uplink_reconnect(self.control, self.device.tcp_app, 10123,
                                   self.evidence, required_interface='eth0')

    def test_three_captured_current_sections_preserve_actual_owner_and_netd_changes(self):
        observed, networks = {}, {}
        for phase, enabled, net_id in (('before', True, 101), ('down', False, None), ('up', True, 102)):
            fixture = CELLULAR[phase]
            owner = proof.cellular_owner(fixture['registry'], fixture['phone'])
            expected = {'phone_id': 0, 'sub_id': 1, 'user_data_enabled': enabled,
                        'data_enabled': enabled, 'data_state': 2 if enabled else 0,
                        'connections': ([{'state': 'CONNECTED', 'transport': 'WWAN',
                                          'net_id': net_id, 'interface': 'eth0'}] if enabled else [])}
            self.assertEqual(owner, expected)
            observed[phase] = owner
            networks[phase] = proof.parse_netd_networks(fixture['netd'])
            self.assertEqual(int(fixture['flags'], 16), 0x1003 if enabled else 0x1002)
            self.assertNotIn('<redacted>', json.dumps(owner))
        self.assertTrue(proof.cellular_online(observed['before'], networks['before']))
        self.assertTrue(proof.cellular_online(observed['up'], networks['up']))
        self.assertEqual(proof.cellular_stopped_networks(networks['before']), networks['down'])
        self.assertTrue(proof.cellular_networks_restored(networks['before'], networks['up']))

    def test_real_sized_registry_and_history_do_not_supply_current_owner_fields(self):
        before, down = CELLULAR['before'], CELLULAR['down']
        history = '\n'.join('  historical entry ' + 'x' * 100 for _ in range(650))
        text = down['registry'] + history + '\n' + before['registry'].partition('local logs:\n')[0].replace(
            'last known state:\n', '').replace('  Phone Id=0\n', '')
        self.assertGreater(len(text.encode()), proof.LIMIT)
        self.assertEqual(proof.cellular_owner(text, down['phone']),
                         proof.cellular_owner(down['registry'], down['phone']))
        text = text.replace('    mUserMobileDataState= false\n', '', 1)
        with self.assertRaises(RuntimeError):
            proof.cellular_owner(text, down['phone'])
        phone = before['phone'].replace('  mDefaultDataSubId=1\n', '')
        phone += 'historical logs:\n  mDefaultDataSubId=1\n'
        with self.assertRaises(RuntimeError):
            proof.cellular_owner(before['registry'], phone)

    def test_missing_duplicate_malformed_and_timeout_current_registry_are_rejected(self):
        before = CELLULAR['before']
        text = before['registry']
        connection = next(row for row in text.splitlines() if 'mPreciseDataConnectionStates=' in row)
        variants = [
            '', text.partition('local logs:\n')[0], text + 'DUMP TIMEOUT (2s) EXPIRED\n',
            text + '\x00', 'x' * (proof.NETD_LIMIT + 1),
            text.replace('last known state:', 'last unknown state:'),
            text.replace('  Phone Id=0\n', '  Phone Id=0\n  Phone Id=1\n'),
            text.replace('  Phone Id=0\n', '  Phone Id=0\n  Phone Id=0\n'),
            text.replace('mUserMobileDataState= true', 'mUserMobileDataState= TRUE'),
            text.replace('    mIsDataEnabled=true\n', ''),
            text.replace('mIsDataEnabled=true', 'mIsDataEnabled=true\n    mIsDataEnabled=false'),
            text.replace('mIsDataEnabled=true', 'mIsDataEnabled= true'),
            text.replace('mDataConnectionState=2', 'mDataConnectionState=6'),
            text.replace('mDefaultPhoneId=0', 'mDefaultPhoneId=1'),
            text.replace('mActiveDataSubId=1', 'mActiveDataSubId=2'),
            text.replace('mDefaultSubId=1', 'mDefaultSubId=0'),
            text.replace('mActiveDataSubId=1', 'mActiveDataSubId=2147483648'),
            text.replace(connection + '\n', ''),
            text.replace(connection, connection + '\n' + connection),
            text.replace('Pair{1 ', 'Pair{2 '),
            text.replace('transport: WWAN', 'transport: WLAN'),
            text.replace('InterfaceName: eth0', 'InterfaceName: wlan0'),
            text.replace('state: CONNECTED', 'state: UNKNOWN'),
            text.replace('id: 1, netId:', 'id: 0, netId:'),
            text.replace('netId: 101,', 'netId: 99,'),
            text.replace('netId: 101,', 'netId: 65536,'),
            text.replace('netId: 101,', 'netId: 101, netId: 101,'),
            text.replace('APN Setting: [ApnSetting] <redacted>', 'APN Setting: [ApnSetting] changed'),
            text.replace('network validation status: unsupported}', 'network validation status: unsupported'),
        ]
        for index, registry in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                proof.cellular_owner(registry, before['phone'])

    def test_phone_globals_boundary_and_default_subscription_are_required(self):
        before = CELLULAR['before']
        text = before['phone']
        variants = [
            '', text.replace('------- End PhoneGlobals -------\n', ''),
            text + text, text + 'DUMP TIMEOUT (2s) EXPIRED\n',
            text.replace('mDefaultDataSubId=1', 'mDefaultDataSubId=2'),
            text.replace('mDefaultDataSubId=1', 'mDefaultDataSubId=01'),
            text.replace('  mDefaultDataSubId=1', '    mDefaultDataSubId=1'),
            text.replace('mDefaultDataSubId=1', 'mDefaultDataSubId=1\n  mDefaultDataSubId=1'),
        ]
        for index, phone in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                proof.cellular_owner(before['registry'], phone)

    def test_unready_owner_or_competing_network_aborts_before_guard_or_disable(self):
        for failure in ('user_data_enabled', 'data_enabled', 'cellular_connected',
                        'data_state', 'competing_network'):
            self.setUp()
            if failure == 'competing_network':
                self.device.networks.append(copy.deepcopy(NETWORKS[-1]))
            else:
                setattr(self.device, failure, 4 if failure == 'data_state' else False)
            with self.subTest(failure=failure), self.assertRaisesRegex(RuntimeError, '^cellular_baseline_not_ready$'):
                self.run_control()
            self.assertFalse(any(' data disable' in call or ' nohup ' in call for call in self.device.calls))
            self.assertFalse(self.evidence['cellular_lifecycle']['acknowledged'])

    def test_invalid_eth0_metadata_aborts_before_guard_or_disable(self):
        for changes in (
                {'net_id': 98},
                {'details': ['Allowed UID ranges: unrestricted', 'Required permission: UNKNOWN']},
                {'details': ['Allowed UID ranges: uids{ 10123 10000 }', 'Required permission: NONE']}):
            self.setUp()
            network = next(item for item in self.device.networks if item['interfaces'] == ['eth0'])
            network.update(changes)
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.run_control()
            self.assertFalse(any(' data disable' in call or ' nohup ' in call for call in self.device.calls))
            self.assertFalse(self.evidence['cellular_lifecycle']['acknowledged'])

    def test_existing_unreachable_preferences_are_unsupported_before_mutation(self):
        for change in (
                {'details': ['Allowed UID ranges: unrestricted', 'Per-app UID ranges: prio 40 uids{ 10135 }']},
                {'net_id': 53}, {'interfaces': ['dummy0']},
                {'details': ['Allowed UID ranges: uids{ 10134 }']}):
            self.setUp()
            next(item for item in self.device.networks if item['net_id'] == 52).update(change)
            with self.subTest(change=change), self.assertRaisesRegex(
                    RuntimeError, '^unsupported_cellular_unreachable_baseline$'):
                self.run_control()
            self.assertFalse(any(' data disable' in call or ' nohup ' in call for call in self.device.calls))

    def test_owner_and_old_network_teardown_are_recorded_before_data_enable(self):
        before = copy.deepcopy(self.device.networks)
        self.run_control()
        lifecycle = self.evidence['cellular_lifecycle']
        self.assertEqual(self.evidence['status'], 'verified')
        self.assertEqual(lifecycle['before']['networks'], before)
        expected = [item for item in before if item['net_id'] != 100]
        expected[1]['details'].append('Per-app UID ranges: prio 40 uids{ 10134 }')
        self.assertEqual(lifecycle['down']['networks'], expected)
        self.assertEqual(lifecycle['down']['flags'], self.evidence['down_flags'])
        self.assertEqual(lifecycle['down']['owner']['connections'], [])
        self.assertFalse(lifecycle['down']['owner']['user_data_enabled'])
        self.assertTrue(lifecycle['acknowledged'])
        self.assertEqual(lifecycle['after']['owner']['connections'][0]['net_id'], 101)
        self.assertTrue(lifecycle['after']['owner']['user_data_enabled'])
        self.assertLess(self.device.calls.index(proof.REGISTRY),
                        self.device.calls.index(proof.MOBILE_DATA + ' disable'))
        self.assertTrue(self.evidence['restore_guard_finished'])
        guard = next(call for call in self.device.calls if call.startswith(proof.BB + ' nohup '))
        self.assertIn('sleep 30;', guard)
        self.assertIn(proof.MOBILE_DATA + ' enable', guard)
        self.assertEqual(self.evidence['restore_method'], 'android_mobile_data_toggle')
        self.assertFalse(any('link set dev eth0' in call or 'route add' in call
                             or 'service restart' in call for call in self.device.calls))

    def test_completed_shutdown_allows_same_net_id_to_be_reused(self):
        self.device.mobile_new_net_id = False
        self.run_control()
        lifecycle = self.evidence['cellular_lifecycle']
        self.assertTrue(lifecycle['acknowledged'])
        self.assertEqual(lifecycle['before']['networks'], lifecycle['after']['networks'])

    def test_delayed_owner_flags_and_old_netd_deletion_are_all_awaited(self):
        for owner_delay, netd_delay, flags_delay in ((3, 0, 0), (0, 7, 0), (0, 0, 4), (3, 7, 5)):
            self.setUp()
            original, owner_up, netd_up = self.device.adb, self.device.registry_dump(), self.device.netd_dump()
            down, enabled_at = False, []
            def adb(command, **kwargs):
                nonlocal down
                if command == proof.MOBILE_DATA + ' disable':
                    down = True
                if command == proof.MOBILE_DATA + ' enable':
                    self.assertTrue(self.evidence['cellular_lifecycle']['acknowledged'])
                    enabled_at.append(self.clock)
                    down = False
                if down:
                    self.assertGreater(kwargs['timeout'], 0)
                    self.assertLessEqual(kwargs['timeout'], min(3, 15 - self.clock))
                result = original(command, **kwargs)
                if down and command == proof.REGISTRY and self.clock < owner_delay:
                    result.stdout = owner_up
                if down and command == proof.NETD and self.clock < netd_delay:
                    result.stdout = netd_up
                if down and command == 'cat /sys/class/net/eth0/flags' and self.clock < flags_delay:
                    result.stdout = '0x1003'
                return result
            self.control.adb = adb
            with self.subTest(owner=owner_delay, netd=netd_delay, flags=flags_delay):
                self.run_control()
                self.assertEqual(enabled_at, [max(owner_delay, netd_delay, flags_delay)])
                self.assertEqual(self.evidence['status'], 'verified')

    def test_unknown_or_unfinished_shutdown_fails_and_still_restores(self):
        for failure in ('user_enabled', 'data_enabled', 'data_state', 'connection', 'old_netd',
                        'flags_up', 'foreign_network', 'uid_migration', 'dump_timeout', 'read_error'):
            self.setUp()
            original, owner_up, netd_up = self.device.adb, self.device.registry_dump(), self.device.netd_dump()
            down = False
            def adb(command, **kwargs):
                nonlocal down
                if command == proof.MOBILE_DATA + ' disable':
                    down = True
                if command == proof.MOBILE_DATA + ' enable':
                    down = False
                result = original(command, **kwargs)
                if down and command == proof.REGISTRY:
                    if failure == 'user_enabled':
                        result.stdout = result.stdout.replace('mUserMobileDataState= false',
                                                              'mUserMobileDataState= true')
                    elif failure == 'data_enabled':
                        result.stdout = result.stdout.replace('mIsDataEnabled=false', 'mIsDataEnabled=true')
                    elif failure == 'data_state':
                        result.stdout = result.stdout.replace('mDataConnectionState=0', 'mDataConnectionState=4')
                    elif failure == 'connection':
                        result.stdout = owner_up
                    elif failure == 'dump_timeout':
                        result.stdout += 'DUMP TIMEOUT (2s) EXPIRED\n'
                    elif failure == 'read_error':
                        result.returncode = 1
                if down and command == proof.NETD:
                    if failure == 'old_netd':
                        result.stdout = netd_up.replace('100 PHYSICAL eth0', '100 PHYSICAL')
                    elif failure == 'foreign_network':
                        result.stdout = result.stdout.replace('51 DUMMY dummy0', '53 DUMMY dummy0')
                    elif failure == 'uid_migration':
                        result.stdout = result.stdout.replace('uids{ 10134 }', 'uids{ 10135 }')
                if down and command == 'cat /sys/class/net/eth0/flags' and failure == 'flags_up':
                    result.stdout = '0x1003'
                return result
            self.control.adb = adb
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                self.run_control()
            lifecycle = self.evidence['cellular_lifecycle']
            self.assertFalse(lifecycle['acknowledged'])
            self.assertIn('down', lifecycle)
            self.assertTrue(self.evidence['up_observed'])
            self.assertTrue(self.evidence['restore_guard_finished'])
            self.assertTrue(self.device.user_data_enabled)
            self.assertEqual(self.evidence['status'], 'not_verified')
            self.assertNotIn('recovery_after', self.evidence)
            if failure in ('user_enabled', 'data_enabled', 'data_state', 'connection', 'old_netd', 'flags_up'):
                self.assertEqual(self.clock, 15)

    def test_shutdown_service_and_observations_share_one_deadline(self):
        original, owner_up = self.device.adb, self.device.registry_dump()
        down, enabled_at = False, []
        def adb(command, **kwargs):
            nonlocal down
            if command == proof.MOBILE_DATA + ' disable':
                down = True
            if command == proof.MOBILE_DATA + ' enable':
                enabled_at.append(self.clock)
                down = False
            if down:
                timeout = kwargs['timeout']
                self.assertLessEqual(timeout, min(3, 15 - self.clock))
                self.clock += timeout
            result = original(command, **kwargs)
            if down and command == proof.REGISTRY:
                result.stdout = owner_up
            return result
        self.control.adb = adb
        with self.assertRaisesRegex(RuntimeError, '^cellular_shutdown_deadline$'):
            self.run_control()
        self.assertEqual(enabled_at, [15])
        self.assertFalse(self.evidence['cellular_lifecycle']['acknowledged'])
        self.assertTrue(self.evidence['up_observed'])

    def test_control_transport_is_checked_before_owner_and_guard(self):
        self.device.peers += TCP + '\n'
        original = self.device.adb
        def adb(command, **kwargs):
            return (subprocess.CompletedProcess(['adb'], 0, '10.0.2.2 dev eth0', '')
                    if command == proof.IP + ' -4 route get 10.0.2.2' else original(command, **kwargs))
        self.control.adb = adb
        with self.assertRaisesRegex(RuntimeError, 'uplink_carries_adb_control'):
            self.run_control()
        self.assertNotIn(proof.REGISTRY, self.device.calls)
        self.assertFalse(any(' data disable' in call or ' nohup ' in call for call in self.device.calls))

    def test_partial_disable_command_failure_and_host_interrupt_still_enable_data(self):
        for interrupted in (False, True):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                result = original(command, **kwargs)
                if command == proof.MOBILE_DATA + ' disable':
                    if interrupted:
                        raise KeyboardInterrupt()
                    result.returncode = 1
                return result
            self.control.adb = adb
            with self.subTest(interrupted=interrupted), self.assertRaises(
                    KeyboardInterrupt if interrupted else RuntimeError):
                self.run_control()
            self.assertTrue(self.evidence['up_observed'])
            self.assertTrue(self.evidence['restore_guard_finished'])
            self.assertFalse(self.evidence['cellular_lifecycle']['acknowledged'])
            self.assertTrue(self.device.user_data_enabled)
            self.assertIn(proof.MOBILE_DATA + ' enable', self.device.calls)

    def test_missing_or_unreadable_flags_are_not_shutdown_evidence(self):
        for code, error in ((1, 'No such file or directory'), (1, 'read failed'), (124, 'timed out'), (0, '')):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                if command == 'cat /sys/class/net/eth0/flags' and not self.device.flags & 1:
                    return subprocess.CompletedProcess(['adb'], code, '', error)
                return original(command, **kwargs)
            self.control.adb = adb
            with self.subTest(code=code, error=error), self.assertRaises(RuntimeError):
                self.run_control()
            lifecycle = self.evidence['cellular_lifecycle']
            self.assertFalse(lifecycle['acknowledged'])
            self.assertIsNone(lifecycle['down']['flags'])
            self.assertNotIn('down_flags', self.evidence)
            self.assertTrue(self.evidence['up_observed'])
            self.assertTrue(self.evidence['restore_guard_finished'])
            self.assertIn(proof.MOBILE_DATA + ' enable', self.device.calls)
            self.assertFalse(any('eth0/flags' in call and 'echo 0x0' in call for call in self.device.calls))

    def test_guard_must_finish_with_its_own_bounded_wait(self):
        for finishes in (True, False):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                if command.startswith('if [ -r /proc/500/stat ]'):
                    text = ('gone\n' if finishes and self.clock >= 30 else
                            '500 (sh) S ' + '0 ' * 18 + '850\n')
                    return subprocess.CompletedProcess(['adb'], 0, text, '')
                return original(command, **kwargs)
            self.control.adb = adb
            with self.subTest(finishes=finishes):
                if finishes:
                    self.run_control()
                    self.assertEqual(self.clock, 30)
                    self.assertEqual(self.evidence['status'], 'verified')
                else:
                    with self.assertRaisesRegex(RuntimeError, '^uplink_restore_guard_deadline$'):
                        self.run_control()
                    self.assertEqual(self.clock, 35)
                    self.assertEqual(self.evidence['status'], 'not_verified')
                self.assertTrue(self.device.flags & 1)

    def test_restored_flags_without_owner_or_original_metadata_never_verify(self):
        for failure in ('user_enabled', 'data_enabled', 'subscription', 'uid', 'other_network'):
            self.setUp()
            original = self.device.adb
            def adb(command, **kwargs):
                result = original(command, **kwargs)
                if command == proof.MOBILE_DATA + ' enable':
                    if failure == 'user_enabled':
                        self.device.user_data_enabled = False
                    elif failure == 'data_enabled':
                        self.device.data_enabled = False
                    elif failure == 'subscription':
                        self.device.sub_id = 2
                    elif failure == 'uid':
                        network = next(item for item in self.device.networks if item['interfaces'] == ['eth0'])
                        network['details'] = [row.replace('uids{ 10134 }', 'uids{ 10135 }')
                                              for row in network['details']]
                    elif failure == 'other_network':
                        self.device.networks.append({'net_id': 200, 'type': 'LOCAL', 'interfaces': [],
                                                     'details': ['Allowed UID ranges: unrestricted']})
                return result
            self.control.adb = adb
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                self.run_control()
            self.assertTrue(self.evidence['cellular_lifecycle']['acknowledged'])
            self.assertIn('after', self.evidence['cellular_lifecycle'])
            self.assertTrue(self.evidence['up_observed'])
            self.assertTrue(self.evidence['restore_guard_finished'])
            self.assertEqual(self.evidence['status'], 'not_verified')
            if failure in ('user_enabled', 'data_enabled'):
                self.assertEqual(self.clock, proof.RECOVERY_TIMEOUT)


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
                ['Allowed UID ranges: unrestricted', 'Required permission: UNKNOWN'],
                ['Allowed UID ranges: unrestricted', 'Required permission: NETWORK|SYSTEM'],
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
                        {'details': ['Allowed UID ranges: unrestricted', 'Required permission: network']},
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

    def test_known_restricted_permissions_bind_exact_global_and_per_app_rules(self):
        for permission, explicit in RESTRICTED_RULES.items():
            for renumber in (False, True):
                self.setUp()
                self.device.networks[3]['details'] = [
                    'Allowed UID ranges: uids{ 0-99999 }',
                    'Per-app UID ranges: prio 40 uids{ 10137 }', 'Required permission: ' + permission]
                self.device.rules = [row for row in self.device.rules if row not in ETH0_RULES]
                self.device.rules += [explicit] + app_rules(100, 40, [(10137, 10137)])
                self.device.renumber_on_start = renumber
                with self.subTest(permission=permission, renumber=renumber):
                    expected = Counter([explicit] + app_rules(100, 40, [(10137, 10137)]))
                    selectors = proof.ethernet_rules(self.control.netd_observation())
                    self.assertEqual(selectors, expected)
                    self.assertEqual(selectors[ETH0_RULES[1]], 0)
                    self.run_control()
                    self.assertEqual(self.evidence['status'], 'verified')

    def test_restricted_permission_cannot_adopt_missing_wrong_or_implicit_rules(self):
        for permission, explicit in RESTRICTED_RULES.items():
            for change in ('missing', 'duplicate', 'none-mark', 'wrong-mask', 'implicit', 'extra-implicit'):
                self.setUp()
                self.device.networks[3]['details'][-1] = 'Required permission: ' + permission
                self.device.rules = [row for row in self.device.rules if row not in ETH0_RULES] + [explicit]
                if change == 'missing':
                    self.device.rules.remove(explicit)
                elif change == 'duplicate':
                    self.device.rules.append(explicit)
                elif change == 'none-mark':
                    self.device.rules[self.device.rules.index(explicit)] = ETH0_RULES[0]
                elif change == 'wrong-mask':
                    self.device.rules[self.device.rules.index(explicit)] = explicit.split('/')[0] + '/0x1ffff iif lo lookup eth0'
                else:
                    self.device.rules += [ETH0_RULES[1]] * (1 if change == 'implicit' else 2)
                with self.subTest(permission=permission, change=change), self.assertRaisesRegex(
                        RuntimeError, 'netd_eth0_rules_not_bound'):
                    self.control.snapshot()

    def test_permission_changes_fail_even_when_both_rule_sets_match_their_metadata(self):
        for old_permission, old_rule in [('NONE', ETH0_RULES[0]), *RESTRICTED_RULES.items()]:
            for new_permission, new_rule in [('NONE', ETH0_RULES[0]), *RESTRICTED_RULES.items()]:
                if old_permission == new_permission:
                    continue
                self.setUp()
                self.device.networks[3]['details'][-1] = 'Required permission: ' + old_permission
                self.device.rules = [row for row in self.device.rules if row not in ETH0_RULES] + [old_rule]
                if old_permission == 'NONE':
                    self.device.rules.append(ETH0_RULES[1])
                before = {'netd': self.control.netd_observation()}
                before_rules = Counter(self.device.rules)
                self.device.networks[3]['details'][-1] = 'Required permission: ' + new_permission
                self.device.rules = [row for row in self.device.rules if row not in (old_rule, ETH0_RULES[1])] + [new_rule]
                if new_permission == 'NONE':
                    self.device.rules.append(ETH0_RULES[1])
                after = {'netd': self.control.netd_observation()}
                with self.subTest(old=old_permission, new=new_permission):
                    self.assertFalse(proof.foreign_rules_preserved(
                        before, after, before_rules, Counter(self.device.rules)))

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
            self.device.rules += app_rules(100, 0, [(10000, 10000), (10000, 10003),
                                                    (10002, 10005), (10123, 10123)])
            self.device.rules += app_rules(100, 10, [(10123, 10123)])
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
        self.device.rules += app_rules(100, 0, [(10000, 10000), (10000, 10003),
                                                (10002, 10005), (10123, 10123)])
        self.device.rules += app_rules(100, 10, [(10123, 10123)])
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

    def test_captured_android_15_per_app_netid_rebuild_preserves_foreign_rules(self):
        # Run 43253655173: the app recovered, while eth0 changed netId100 ->101.
        self.device.networks.pop()  # This snapshot has no wlan0 network.
        self.device.networks[3]['details'] = [
            'Allowed UID ranges: uids{ 0-99999 }',
            'Per-app UID ranges: prio 40 uids{ 10137 }', 'Required permission: NONE']
        captured = [
            '15040: from all fwmark 0x10064/0x1ffff iif lo uidrange 10137-10137 lookup eth0',
            '22040: from all fwmark 0x64/0x1ffff iif lo uidrange 10137-10137 lookup eth0',
            '25000: from all fwmark 0x0/0x10000 iif lo uidrange 10137-10137 lookup eth0_local',
            '29040: from all fwmark 0x0/0xffff iif lo uidrange 10137-10137 lookup eth0']
        self.device.rules += captured
        before = {'netd': self.control.netd_observation()}
        before_rules = Counter(self.device.rules)
        after = copy.deepcopy(before)
        after['netd']['networks'][3]['net_id'] = 101
        after_rules = Counter(row.replace('fwmark 0x10064/', 'fwmark 0x10065/')
                             .replace('fwmark 0x64/', 'fwmark 0x65/')
                             if row.endswith(' lookup eth0') else row
                             for row in self.device.rules)
        self.assertEqual(proof.ethernet_rules(before['netd']), Counter(ETH0_RULES + captured[:2]))
        self.assertTrue(proof.foreign_rules_preserved(before, after, before_rules, after_rules))
        for row in captured[2:]:
            with self.subTest(foreign=row):
                self.assertFalse(proof.foreign_rules_preserved(
                    before, after, before_rules, after_rules - Counter([row])))

    def test_per_app_selectors_require_complete_declared_multiplicities(self):
        self.device.networks[3]['details'] = [
            'Allowed UID ranges: unrestricted',
            'Per-app UID ranges: prio 0 uids{ 0 0 }; prio 40 uids{ 10137-10139 }; prio 999 uids{ }',
            'Required permission: NONE']
        expected = app_rules(100, 0, [(0, 0), (0, 0)]) + app_rules(100, 40, [(10137, 10139)])
        self.device.rules += expected
        self.assertEqual(proof.ethernet_rules(self.control.netd_observation()),
                         Counter(ETH0_RULES + expected))
        self.control.snapshot()
        duplicate = expected[0]
        for count in (0, 1, 3):
            self.device.rules = [row for row in self.device.rules if row != duplicate] + [duplicate] * count
            with self.subTest(count=count), self.assertRaisesRegex(RuntimeError, 'netd_eth0_rules_not_bound'):
                self.control.snapshot()

    def test_per_app_netid_rebuild_rejects_missing_duplicate_or_foreign_selectors(self):
        self.device.networks[3]['details'] = [
            'Allowed UID ranges: unrestricted',
            'Per-app UID ranges: prio 40 uids{ 10137 }', 'Required permission: NONE']
        self.device.rules += app_rules(100, 40, [(10137, 10137)])
        before = {'netd': self.control.netd_observation()}
        before_rules = Counter(self.device.rules)
        for renumber in (False, True):
            if renumber:
                self.device.renumber_eth0()
            after = {'netd': self.control.netd_observation()}
            after_rules = Counter(self.device.rules)
            row = next(row for row in after_rules if row.startswith('15040:'))
            variants = [None, row.replace('15040:', '15041:'), row.replace('/0x1ffff', '/0xffff'),
                        row.replace('10137-10137', '10138-10138'), row.replace('iif lo', 'iif eth0'),
                        row.replace('lookup eth0', 'lookup wlan0'),
                        row.replace('0x10066/', '0x10064/') if renumber else row + ' oif eth0']
            for replacement in variants:
                changed = after_rules - Counter([row])
                if replacement:
                    changed[replacement] += 1
                with self.subTest(renumber=renumber, replacement=replacement):
                    self.assertFalse(proof.foreign_rules_preserved(before, after, before_rules, changed))
            self.assertFalse(proof.foreign_rules_preserved(before, after, before_rules,
                                                           after_rules + Counter([row])))
            for extra in (row.replace('15040:', '15041:'), row.replace('10137-10137', '10138-10138')):
                self.assertFalse(proof.foreign_rules_preserved(before, after, before_rules,
                                                               after_rules + Counter([extra])))

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
        def sentinel():
            return self.device.tcp_app() | {'url': 'private-value', 'marker': 'private-value'}
        proof.uplink_reconnect(self.control, sentinel, 10123, evidence)
        self.assertEqual(evidence['status'], 'verified')
        self.assertTrue(evidence['down_observed'])
        self.assertTrue(evidence['up_observed'])
        self.assertTrue(evidence['control_channel_survived'])
        self.assertTrue(evidence['restore_guard_finished'])
        for key in ('baseline', 'last_observation'):
            observed = evidence[key]
            self.assertTrue(observed['selected_default'])
            self.assertTrue(observed['ready'])
            self.assertEqual(observed['state']['status'], 'present')
            self.assertEqual(observed['tcp'], {'called': True, 'result': self.device.tcp_app()})
        self.assertEqual(evidence['last_observation']['state'], evidence['recovery_after'])
        self.assertNotIn('private-value', json.dumps(evidence))

    def test_wifi_restore_is_in_both_the_guard_and_foreground(self):
        evidence = {}
        proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
        restore = (proof.IP + ' link set dev wlan0 up'
                   ' && /system/bin/cmd wifi set-wifi-enabled disabled'
                   f' && {proof.BB} sleep 2'
                   ' && /system/bin/cmd wifi set-wifi-enabled enabled')
        self.assertEqual(evidence['restore_method'], 'android_wifi_toggle')
        self.assertIn(restore, self.device.calls)
        guard = next(call for call in self.device.calls if call.startswith(proof.BB + ' nohup '))
        self.assertIn(restore, guard)

    def test_cellular_restore_does_not_toggle_wifi(self):
        self.device.adb(proof.WIFI + ' set-wifi-enabled disabled')
        self.device.calls.clear()
        evidence = {}
        proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
        self.assertEqual(evidence['restore_method'], 'android_mobile_data_toggle')
        self.assertFalse(any('cmd wifi' in call for call in self.device.calls))
        self.assertIn(proof.MOBILE_DATA + ' enable', self.device.calls)

    def test_wifi_interface_recreation_is_observed_with_a_bounded_wait(self):
        for returns in (True, False):
            self.setUp()
            original = self.device.adb
            restored = False
            def adb(command, **kwargs):
                nonlocal restored
                if command.startswith(proof.IP + ' link set dev wlan0 up'):
                    restored = True
                if restored and command.startswith('if [ -r /sys/class/net/'):
                    value = '0x1003' if returns and self.clock >= 3 else '0x0'
                    return subprocess.CompletedProcess(['adb'], 0, value, '')
                return original(command, **kwargs)
            self.control.adb = adb
            evidence = {}
            with self.subTest(returns=returns), \
                    patch.object(proof.time, 'monotonic', lambda: self.clock), \
                    patch.object(proof.time, 'sleep', self.sleep):
                if returns:
                    proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
                    self.assertEqual(self.clock, 3)
                    self.assertTrue(evidence['up_observed'])
                else:
                    with self.assertRaisesRegex(RuntimeError, '^uplink_restore_failed$'):
                        proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
                    self.assertEqual(self.clock, 30)
                    self.assertFalse(evidence['up_observed'])

    def test_wifi_restore_command_failure_cannot_report_recovery(self):
        original = self.device.adb
        def adb(command, **kwargs):
            if command.startswith(proof.IP + ' link set dev wlan0 up'):
                return subprocess.CompletedProcess(['adb'], 1, '', '')
            return original(command, **kwargs)
        self.control.adb = adb
        evidence = {}
        with self.assertRaisesRegex(RuntimeError, 'device_command_failed'):
            proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
        self.assertEqual(evidence['status'], 'not_verified')
        self.assertTrue(evidence['restore_guard_finished'])
        self.assertNotIn('recovery_after', evidence)

    def test_uplink_baseline_must_succeed_before_guard_or_link_mutation(self):
        for failure in ('state', 'ready', 'tcp', 'udp', 'invalid_result'):
            self.setUp()
            evidence, calls = {}, []
            if failure == 'state':
                self.device.state = state('unknown')
            def sentinel():
                calls.append(True)
                result = self.device.tcp_app()
                if failure == 'tcp':
                    return result | {'ok': False, 'reason': 'timeout', 'accepted': 0, 'elapsed_ms': 5000}
                if failure == 'udp':
                    return self.device.app()
                return result | {'reason': 'private-value'} if failure == 'invalid_result' else result
            with self.subTest(failure=failure), patch.object(self.control, 'ready', return_value=failure != 'ready'):
                with self.assertRaisesRegex(RuntimeError, '^uplink_baseline_not_ready$'):
                    proof.uplink_reconnect(self.control, sentinel, 10123, evidence)
            self.assertFalse(any('link set' in call or ' nohup ' in call for call in self.device.calls))
            self.assertEqual(evidence['baseline']['tcp']['called'], failure not in ('state', 'ready'))
            self.assertEqual(len(calls), int(failure not in ('state', 'ready')))
            self.assertNotIn('private-value', json.dumps(evidence))

    def test_uplink_timeout_retains_each_failed_predicate_and_short_circuit(self):
        for failure in ('route', 'state', 'ready', 'tcp'):
            self.setUp()
            evidence, ready_calls, tcp_calls = {}, [], []
            original_adb, original_ready = self.device.adb, self.control.ready
            def down():
                return proof.IP + ' link set dev wlan0 down' in self.device.calls
            def adb(command, **kwargs):
                result = original_adb(command, **kwargs)
                if command == proof.IP + ' link set dev wlan0 down':
                    if failure == 'route':
                        self.device.uplinks = ['eth0']
                    if failure == 'state':
                        self.device.state = state('unknown')
                return result
            def ready(expected):
                ready_calls.append(down())
                return original_ready(expected) and not (down() and failure == 'ready')
            def sentinel():
                tcp_calls.append(down())
                result = self.device.tcp_app()
                return (result | {'ok': False, 'reason': 'timeout', 'accepted': 0, 'elapsed_ms': 5000}
                        if down() and failure == 'tcp' else result)
            self.control.adb = adb
            with self.subTest(failure=failure), patch.object(self.control, 'ready', ready), \
                    patch.object(proof.time, 'monotonic', lambda: self.clock), \
                    patch.object(proof.time, 'sleep', self.sleep):
                with self.assertRaisesRegex(RuntimeError, '^uplink_reconnect_deadline$'):
                    proof.uplink_reconnect(self.control, sentinel, 10123, evidence)
            observed = evidence['last_observation']
            self.assertGreaterEqual(self.clock, proof.RECOVERY_TIMEOUT)
            self.assertTrue(evidence['up_observed'])
            self.assertTrue(evidence['restore_guard_finished'])
            self.assertTrue(evidence['baseline']['tcp']['result']['ok'])
            if failure in ('route', 'state'):
                self.assertEqual(ready_calls, [False])
                self.assertIsNone(observed['ready'])
            if failure != 'tcp':
                self.assertEqual(tcp_calls, [False])
                reason = {'route': 'selected_default_missing', 'state': 'tun_not_present',
                          'ready': 'not_ready'}[failure]
                self.assertEqual(observed['tcp'], {'called': False, 'reason': reason})
            else:
                self.assertTrue(observed['ready'])
                self.assertTrue(observed['tcp']['called'])
                self.assertEqual(observed['tcp']['result']['reason'], 'timeout')
                self.assertEqual(observed['tcp']['result']['accepted'], 0)
            self.assertEqual(observed['selected_default'], failure != 'route')

    def test_uplink_errors_preserve_partial_evidence_without_raw_exception_text(self):
        for failure in ('route', 'ready', 'tcp'):
            self.setUp()
            evidence = {}
            original_adb, original_ready = self.device.adb, self.control.ready
            def down():
                return proof.IP + ' link set dev wlan0 down' in self.device.calls
            def adb(command, **kwargs):
                if down() and failure == 'route' and command == proof.IP + ' -4 route show table all':
                    return subprocess.CompletedProcess(['adb'], 1, 'private-value', 'private-value')
                return original_adb(command, **kwargs)
            def ready(expected):
                if down() and failure == 'ready':
                    raise ValueError('private-value')
                return original_ready(expected)
            def sentinel():
                if down() and failure == 'tcp':
                    raise RuntimeError('private-value')
                return self.device.tcp_app()
            self.control.adb = adb
            with self.subTest(failure=failure), patch.object(self.control, 'ready', ready):
                with self.assertRaises((RuntimeError, ValueError)):
                    proof.uplink_reconnect(self.control, sentinel, 10123, evidence)
            observed = evidence['last_observation']
            self.assertTrue(evidence['up_observed'])
            self.assertEqual(observed['tcp']['called'], failure == 'tcp')
            self.assertEqual(observed['tcp']['reason'], {
                'route': 'route_not_observed', 'ready': 'readiness_not_observed', 'tcp': 'probe_error'}[failure])
            self.assertNotIn('private-value', json.dumps(evidence))

    def test_uplink_carrying_adb_is_rejected_before_mutation(self):
        self.device.peers += TCP + '\n'
        with self.assertRaisesRegex(RuntimeError, 'uplink_carries_adb_control'):
            proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, {})
        self.assertFalse(any('link set' in call for call in self.device.calls))

    def test_android_multiple_defaults_use_kernel_selected_egress(self):
        self.device.uplinks = ['eth0', 'wlan0']
        evidence = {}
        proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
        self.assertEqual(evidence['status'], 'verified')
        self.assertEqual(evidence['interface'], 'wlan0')
        self.assertEqual(evidence['default_interfaces'], ['eth0', 'wlan0'])
        self.assertFalse(any('link set dev eth0' in call for call in self.device.calls))

    def test_unknown_or_non_default_egress_is_rejected_before_mutation(self):
        for selected in ('', 'magicnet0', 'lo', 'eth0'):
            self.device.calls.clear()
            self.device.selected_uplink = selected
            with self.subTest(selected=selected), self.assertRaisesRegex(RuntimeError, 'ambiguous_or_missing_uplink'):
                proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, {})
            self.assertFalse(any('link set' in call for call in self.device.calls))

    def test_failed_down_observation_still_restores_uplink(self):
        self.device.fail_down_observation = True
        with self.assertRaisesRegex(RuntimeError, 'device_command_failed'):
            proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, {})
        self.assertTrue(any(call.startswith(proof.IP + ' link set dev wlan0 up')
                            for call in self.device.calls[-3:]))
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
            proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, evidence)
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
                proof.uplink_reconnect(self.control, self.device.tcp_app, 10123, {})
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
