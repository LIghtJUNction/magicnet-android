#!/usr/bin/env python3
"""Host safety/accounting tests, not evidence of Android packet forwarding."""
from collections import Counter
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
FOREIGN = ['0: from all lookup local', '32766: from all lookup main',
           '18000: from all fwmark 0x64/0x1ffff lookup wlan0']
LEDGER = ('schema=2\nphase=active\nboot=' + BOOT + '\ntable=2022\ninterface=magicnet0\n'
          + ''.join('rule4=' + row + '\n' for row in OWNED))
FIB = 'default dev magicnet0 scope link\n'
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
        self.rules = FOREIGN + OWNED
        self.pid, self.start, self.ifindex = 421, 800, 12
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

    def app(self):
        captured = not Counter(OWNED) - Counter(self.rules)
        return dict(ok=captured, complete=True, uid=10123,
                    reason='sentinel' if captured else 'connect', accepted=1 if captured else 0,
                    elapsed_ms=10)

    def adb(self, command, timeout=10):
        self.calls.append(command)
        output, rc = '', 0
        if command.startswith('p=$(' + proof.BB + ' pidof sing-box)'):
            fields = ['S'] + ['0'] * 18 + [str(self.start)]
            output = f'{self.pid}\n{self.pid} (sing-box) ' + ' '.join(fields) + '\n'
        elif command == 'cat /sys/class/net/magicnet0/ifindex':
            output = str(self.ifindex)
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
        elif command == proof.CLI + ' --json service status':
            ready = self.app()['ok']
            output = json.dumps(dict(schema=1, ok=True, command='service.status', data={
                'core': {'sing_box': {'process_state': 'running'}}, 'api': {'ready': True},
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
                    self.rules = FOREIGN + OWNED
                    if self.foreign_on_recover:
                        self.rules.remove(FOREIGN[-1])
                    self.pid, self.start, self.ifindex = 422, 900, 13
                    self.state = state(attempts=1)
        elif command == proof.IP + ' -4 route show table all':
            output = ''.join(f'default via 10.0.2.2 dev {name} table {name} proto static\n'
                             for name in self.uplinks) + FIB
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
            self.control.rpdb_loss(sentinel or self.device.app, 10123)

    def test_normal_tick_proves_missing_then_real_observations_of_recovery(self):
        self.run_control()
        result = self.evidence
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['removed_rule_count'], len(OWNED))
        self.assertEqual(result['first_missing']['consecutive_failures'], 1)
        self.assertEqual(result['before']['core_pid'], result['fault']['core_pid'])
        self.assertNotEqual(result['before']['core_pid'], result['after']['core_pid'])
        self.assertEqual(result['recovery_after']['recovery_attempts'], 1)
        self.assertGreaterEqual(self.clock, 60)
        self.assertFalse(any('service restart' in call or '.state/machines/' in call
                             for call in self.device.calls))

    def test_exact_zero_selector_may_delete_only_recorded_sibling(self):
        self.device.delete_sibling = True
        self.run_control()
        self.assertEqual(self.evidence['removed_rule_count'], 4)
        self.assertEqual(self.device.rules, FOREIGN + OWNED)

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

    def test_missing_automatic_recovery_hits_real_deadline_without_manual_restart(self):
        self.device.recover = False
        with self.assertRaisesRegex(RuntimeError, 'automatic_recovery_deadline'):
            self.run_control()
        self.assertGreaterEqual(self.clock, proof.RECOVERY_TIMEOUT)
        self.assertEqual(self.device.pid, 421)
        self.assertFalse(any('service restart' in call for call in self.device.calls))

    def test_recovery_cannot_destroy_foreign_rules(self):
        self.device.foreign_on_recover = True
        with self.assertRaisesRegex(RuntimeError, 'recovery_rule_set_mismatch'):
            self.run_control()

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
