#!/usr/bin/env python3
"""Exercise host observation with local child processes, never an Android device."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/android-host-observer.py'
SPEC = importlib.util.spec_from_file_location('host_observer', SCRIPT)
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)


def proc_stat(pid=77, ticks=123, state='S', comm='odd ) worker name'):
    fields = [state] + ['0'] * 40
    for index, value in {1: 9, 11: 4, 12: 5, 17: 3, 19: ticks, 21: 20}.items():
        fields[index] = str(value)
    return (f'{pid} ({comm}) ' + ' '.join(fields) + '\n').encode()


def launch_record(child, observer=None):
    observer = observer or {'pid': 88, 'start_ticks': 100}
    return {'schema': 1, 'scope': 'host-diagnostics-only', 'launch_status': 'spawned',
            'observer': observer,
            'emulator': {'status': 'observed', 'ppid': observer['pid'], **child},
            'cgroup': {'status': 'unavailable'}}


def start_observer(out):
    observer = subprocess.Popen(
        [sys.executable, str(SCRIPT), '--output', str(out),
         '--state', str(out / 'private-state'), 'watch', '--',
         sys.executable, '-c', 'import time;time.sleep(5)'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if (out / OBS.LAUNCH).is_file():
            return observer, json.loads((out / OBS.LAUNCH).read_text())
        if observer.poll() is not None:
            break
        time.sleep(0.01)
    finish_observer(observer)
    raise RuntimeError('observer launch deadline')


def finish_observer(observer):
    # The test child also has a fixed self-exit deadline, including on failure.
    try:
        observer.wait(timeout=7)
    except subprocess.TimeoutExpired:
        observer.kill()
        observer.wait(timeout=3)


class ProcessTests(unittest.TestCase):
    def run_child(self, code, arguments=()):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / 'out'
            argv = [sys.executable, '-c', code, *arguments]
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--output', str(out),
                 '--state', str(root / 'private-state.json'), 'watch', '--', *argv],
                capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            launch = json.loads((out / OBS.LAUNCH).read_text())
            receipt = json.loads((out / OBS.EXIT).read_text())
            self.assertNotEqual(launch['emulator']['pid'], launch['observer']['pid'])
            self.assertEqual(receipt['emulator_pid'], launch['emulator']['pid'])
            self.assertEqual((out / 'emulator.pid').read_text(), str(receipt['emulator_pid']) + '\n')
            self.assertEqual(launch['argv_sha256'],
                             hashlib.sha256(b'\0'.join(a.encode() for a in argv)).hexdigest())
            return launch, receipt, (out / 'emulator.log').read_bytes(), result

    def test_real_exit_codes_are_not_converted_to_signals(self):
        for code in (0, 17, 137):
            with self.subTest(code=code):
                _, receipt, _, _ = self.run_child(f'raise SystemExit({code})')
                self.assertEqual(receipt['returncode'], code)
                self.assertEqual(receipt['exit_code'], code)
                self.assertIsNone(receipt['signal'])

    def test_real_signal_exit_is_negative_and_never_called_oom(self):
        for number in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=number):
                _, receipt, _, _ = self.run_child(f'import os;os.kill(os.getpid(),{int(number)})')
                self.assertEqual(receipt['returncode'], -number)
                self.assertIsNone(receipt['exit_code'])
                self.assertEqual(receipt['signal'], number)
                self.assertNotIn('oom', json.dumps(receipt).lower())

    def test_instant_exit_keeps_wait_result_when_proc_identity_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = OBS.process
            def process(pid, *args, **kwargs):
                if pid == os.getpid():
                    return original(pid, *args, **kwargs)
                return {'status': 'missing', 'pid': pid}
            with patch.object(OBS, 'process', side_effect=process):
                self.assertEqual(OBS.watch(root, root / 'state',
                                           [sys.executable, '-c', 'raise SystemExit(0)']), 0)
            launch = json.loads((root / OBS.LAUNCH).read_text())
            receipt = json.loads((root / OBS.EXIT).read_text())
            self.assertEqual(launch['emulator']['status'], 'missing')
            self.assertNotIn('start_ticks', launch['emulator'])
            self.assertEqual(receipt['returncode'], 0)
            self.assertEqual(OBS.exit_observation(root, launch)['status'], 'unknown')

    def test_argv_is_passed_as_a_list_without_shell_or_metadata_disclosure(self):
        canary = 'private-canary;$(echo must-not-execute)'
        launch, receipt, output, result = self.run_child(
            'import json,os,sys;print(json.dumps({"pid":os.getpid(),"argv":sys.argv[1:]}))',
            [canary, 'argument with spaces'])
        payload = json.loads(output)
        self.assertEqual(payload['argv'], [canary, 'argument with spaces'])
        self.assertEqual(payload['pid'], launch['emulator']['pid'])
        self.assertNotIn(canary, json.dumps([launch, receipt]) + result.stdout + result.stderr)

    def test_large_direct_log_does_not_block_parent_wait(self):
        _, receipt, output, _ = self.run_child('import sys;sys.stdout.buffer.write(b"x"*524288)')
        self.assertEqual(len(output), 524288)
        self.assertEqual(receipt['exit_code'], 0)

    def test_stat_comm_parentheses_and_spaces_do_not_shift_starttime(self):
        value = OBS.parse_stat(proc_stat(), 77)
        self.assertEqual(value['start_ticks'], 123)
        self.assertEqual(value['cpu_ticks'], 9)
        self.assertEqual(value['threads'], 3)
        self.assertEqual(value['rss_pages'], 20)
        with self.assertRaises(ValueError):
            OBS.parse_stat(proc_stat(), 78)

    def test_process_missing_reused_and_zombie_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            slot = root / '77'
            slot.mkdir()
            (slot / 'stat').write_bytes(proc_stat())
            (slot / 'exe').symlink_to('/private/path/qemu-system-x86_64')
            self.assertEqual(OBS.process(77, 123, root)['status'], 'observed')
            reused = OBS.process(77, 122, root)
            self.assertEqual(reused, {'status': 'pid_reused', 'pid': 77})
            (slot / 'stat').write_bytes(proc_stat(state='Z'))
            self.assertEqual(OBS.process(77, 123, root)['status'], 'zombie')
            (slot / 'stat').unlink()
            self.assertEqual(OBS.process(77, 123, root)['status'], 'missing')

    def test_missing_and_oversized_identity_are_unknown_not_alive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '77').mkdir()
            (root / '77/stat').write_bytes(b'x' * (OBS.PROC_LIMIT + 1))
            self.assertEqual(OBS.process(77, 123, root)['status'], 'unknown')
        for identity in ({'pid': True, 'start_ticks': 1}, {'pid': -1, 'start_ticks': 1},
                         {'pid': 1, 'start_ticks': True}, {'pid': 1 << 32, 'start_ticks': 1}):
            with self.assertRaises(ValueError):
                OBS.identity(identity)

    def test_failed_launch_records_no_private_executable_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / 'out'
            code = OBS.watch(out, root / 'state', ['/missing/private-canary/emulator'])
            self.assertEqual(code, 1)
            launch = json.loads((out / OBS.LAUNCH).read_text())
            self.assertEqual(launch['launch_status'], 'failed')
            self.assertIsNone(launch['emulator'])
            self.assertNotIn('private-canary', json.dumps(launch))
            self.assertFalse((out / OBS.EXIT).exists())

    def test_launch_record_failure_still_waits_without_killing_or_restarting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = OBS.write_json
            def write(path, value):
                if path.name == OBS.LAUNCH:
                    raise OSError('private-canary')
                return original(path, value)
            with patch.object(OBS, 'write_json', side_effect=write):
                result = OBS.watch(root / 'out', root / 'state',
                                   [sys.executable, '-c', 'print("one launch")'])
            self.assertEqual(result, 0)
            self.assertEqual((root / 'out/emulator.log').read_text(), 'one launch\n')
            self.assertEqual(json.loads((root / 'out' / OBS.EXIT).read_text())['exit_code'], 0)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                         'Linux pidfd API required')
    def test_cleanup_signals_only_the_actual_observer_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            observer, launch = start_observer(out)
            try:
                self.assertEqual(launch['emulator']['ppid'], observer.pid)
                self.assertEqual(launch['observer']['pid'], observer.pid)
                OBS.terminate(out)
                self.assertEqual(observer.wait(timeout=3), 0)
                receipt = json.loads((out / OBS.EXIT).read_text())
                self.assertEqual(receipt['returncode'], -signal.SIGTERM)
                self.assertEqual(json.loads((out / 'emulator-host-cleanup.json').read_text())['status'],
                                 'sigterm_sent')
            finally:
                finish_observer(observer)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                         'Linux pidfd API required')
    def test_cleanup_leaves_a_real_unrelated_live_process_intact(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            observer, launch = start_observer(out)
            foreign = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(5)'])
            try:
                # Even a valid-looking stored ppid cannot replace live parentage.
                replaced = dict(launch)
                replaced['emulator'] = OBS.process(foreign.pid) | {'ppid': observer.pid}
                OBS.write_json(out / OBS.LAUNCH, replaced)
                OBS.terminate(out)
                self.assertIsNone(foreign.poll())
                self.assertIsNone(observer.poll())
                refused = json.loads((out / 'emulator-host-cleanup.json').read_text())
                self.assertEqual(refused['status'], 'unknown')
                self.assertEqual(refused['refusal'], 'parent_mismatch')
            finally:
                OBS.write_json(out / OBS.LAUNCH, launch)
                OBS.terminate(out)
                finish_observer(observer)
                if foreign.poll() is None:
                    foreign.terminate()
                foreign.wait(timeout=3)

    def test_cleanup_refuses_incomplete_or_mismatched_launch_ownership(self):
        valid = launch_record({'pid': 77, 'start_ticks': 123})
        variants = [
            {'emulator': valid['emulator']},
            valid | {'schema': True}, valid | {'scope': 'other'},
            valid | {'launch_status': 'failed'}, valid | {'observer': None},
            valid | {'observer': {'pid': 77, 'start_ticks': 123}},
            valid | {'emulator': valid['emulator'] | {'ppid': 99}},
            valid | {'emulator': valid['emulator'] | {'start_ticks': 99}},
        ]
        for record in variants:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                OBS.write_json(out / OBS.LAUNCH, record)
                with patch.object(OBS.os, 'pidfd_open') as pin, \
                     patch.object(OBS.signal, 'pidfd_send_signal') as send:
                    OBS.terminate(out)
                pin.assert_not_called()
                send.assert_not_called()
                self.assertEqual(json.loads((out / 'emulator-host-cleanup.json').read_text())['status'],
                                 'unknown')

    def test_cleanup_pins_before_identity_and_requires_live_matching_observer(self):
        cases = [('observed', 'observed', 88, True),
                 ('pid_reused', 'observed', 88, False),
                 ('missing', 'observed', 88, False), ('unknown', 'observed', 88, False),
                 ('zombie', 'observed', 88, False), ('observed', 'missing', 88, False),
                 ('observed', 'pid_reused', 88, False), ('observed', 'unknown', 88, False),
                 ('observed', 'zombie', 88, False), ('observed', 'observed', 99, False)]
        for child_status, owner_status, ppid, allowed in cases:
            with self.subTest(child=child_status, owner=owner_status, ppid=ppid), \
                 tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                OBS.write_json(out / OBS.LAUNCH, launch_record({'pid': 77, 'start_ticks': 123}))
                order = []
                real_close = os.close
                def close(fd):
                    if fd == 100000:
                        order.append('close')
                    else:
                        real_close(fd)
                def process(pid, expected):
                    order.append('child' if pid == 77 else 'owner')
                    return {'status': child_status if pid == 77 else owner_status,
                            'pid': pid, 'ppid': ppid}
                with patch.object(OBS.os, 'pidfd_open', side_effect=lambda pid: order.append('pin') or 100000), \
                     patch.object(OBS, 'process', side_effect=process), \
                     patch.object(OBS.signal, 'pidfd_send_signal',
                                  side_effect=lambda *args: order.append('signal')) as send, \
                     patch.object(OBS.os, 'close', side_effect=close):
                    OBS.terminate(out)
                self.assertEqual(order[:2], ['pin', 'child'])
                self.assertEqual(send.call_count, int(allowed))
                if allowed:
                    self.assertEqual(order, ['pin', 'child', 'owner', 'signal', 'close'])
                    send.assert_called_once_with(100000, signal.SIGTERM)
                self.assertEqual(order[-1], 'close')

    def test_cleanup_never_falls_back_to_kill_pid_without_pidfd(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            OBS.write_json(out / OBS.LAUNCH, launch_record({'pid': 77, 'start_ticks': 123}))
            with patch.object(OBS.os, 'pidfd_open', side_effect=OSError('private-canary')), \
                 patch.object(OBS.os, 'kill') as kill, \
                 patch.object(OBS.signal, 'pidfd_send_signal') as send:
                OBS.terminate(out)
            kill.assert_not_called()
            send.assert_not_called()
            self.assertNotIn('private-canary', (out / 'emulator-host-cleanup.json').read_text())


class BoundedInputTests(unittest.TestCase):
    def test_file_limit_symlinks_fifo_and_duplicate_keys_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            data.write_bytes(b'x' * (OBS.JSON_LIMIT + 1))
            with self.assertRaises(ValueError):
                OBS.read_json(data)
            link = root / 'link'
            link.symlink_to(data)
            with self.assertRaises(OSError):
                OBS.read_bytes(link, 10)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                OBS.read_bytes(fifo, 10)
            data.write_text('{"pid":1,"pid":2}')
            with self.assertRaises(ValueError):
                OBS.read_json(data)

    def test_command_success_size_and_time_limits_are_real(self):
        output, status = OBS.bounded_command(
            [sys.executable, '-c', 'print("ok")'], time.monotonic() + 3)
        self.assertEqual((output, status), (b'ok\n', 'complete'))
        output, status = OBS.bounded_command(
            [sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*100000)'],
            time.monotonic() + 3, 128)
        self.assertEqual(len(output), 128)
        self.assertEqual(status, 'size_limit')
        start = time.monotonic()
        _, status = OBS.bounded_command(
            [sys.executable, '-c', 'import time;time.sleep(10)'], start + 0.1)
        self.assertEqual(status, 'timeout')
        self.assertLess(time.monotonic() - start, 2)

    def test_oom_lines_are_whitelisted_and_do_not_prove_causation(self):
        data = (b'[10.5] Out of memory: Killed process 77 (private-canary) secret=canary\n'
                b'[10.4] oom-kill: task_memcg=/private/path,pid=77,task=private-canary\n'
                b'[10.6] Out of memory: Killed process 99 (unrelated)\n'
                b'[10.7] arbitrary private-canary output\n')
        result = OBS.kernel_oom(data, {77})
        self.assertEqual(result['oom_line_count'], 3)
        self.assertEqual(len(result['matching_pid_events']), 2)
        self.assertTrue(all(e['pid'] == 77 for e in result['matching_pid_events']))
        self.assertEqual(result['scope'], 'observations_only_not_process_causation')
        self.assertNotIn('private', json.dumps(result))
        self.assertNotIn('canary', json.dumps(result))
        self.assertEqual(len(OBS.kernel_oom(data * 30, {77})['matching_pid_events']), 16)


class CgroupTests(unittest.TestCase):
    def test_baseline_uses_child_membership_and_unknown_counters_are_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / 'proc'
            (proc / '77').mkdir(parents=True)
            (proc / '77/cgroup').write_text('0::/child-group\n')
            cg = root / 'cgroup'
            group = cg / 'child-group'
            group.mkdir(parents=True)
            (group / 'memory.events').write_text('low 0\nhigh 2\nmax 3\noom 1\noom_kill 1\n')
            (group / 'memory.events.local').write_text('oom 0\noom_kill 0\n')
            (group / 'memory.current').write_text('4096\n')
            (group / 'memory.max').write_text('max\n')
            reference = OBS.cgroup_reference(77, proc, cg)
            self.assertEqual(reference['relative'], '/child-group')
            observed = OBS.memory_observation(reference, cg)
            self.assertEqual(observed['values']['memory.events']['oom_kill'], 1)
            self.assertEqual(observed['values']['memory.events.local']['oom_kill'], 0)
            self.assertIsNone(observed['values']['memory.peak'])
            self.assertNotIn('child-group', json.dumps(observed))
            (group / 'memory.events').write_text('oom_kill 0\noom_kill 1\n')
            self.assertIsNone(OBS.memory_observation(reference, cg)['values']['memory.events'])
            (group / 'memory.events').write_bytes(b'x' * (OBS.PROC_LIMIT + 1))
            self.assertIsNone(OBS.memory_observation(reference, cg)['values']['memory.events'])
            changed = reference | {'inode': reference['inode'] + 1}
            self.assertEqual(OBS.memory_observation(changed, cg)['status'], 'identity_changed')

    def test_outside_or_missing_cgroup_remains_unavailable(self):
        for reference in ({}, {'relative': '/../private', 'device': 1, 'inode': 1},
                          {'relative': '/missing', 'device': True, 'inode': 1}):
            self.assertEqual(OBS.memory_observation(reference)['status'], 'unavailable')


class FragmentSocket:
    def __init__(self, payload, fragment=1, timeout=False):
        self.payload = payload
        self.fragment = fragment
        self.timeout = timeout
        self.request = b''
        self.timeouts = []
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def settimeout(self, timeout):
        self.timeouts.append(timeout)
    def sendall(self, request):
        self.request += request
    def recv(self, size):
        if self.timeout:
            raise TimeoutError
        size = min(size, self.fragment)
        part, self.payload = self.payload[:size], self.payload[size:]
        return part


def adb_packet(body):
    return b'OKAY' + f'{len(body):04x}'.encode() + body


class AdbTests(unittest.TestCase):
    def query(self, packet, **options):
        stream = FragmentSocket(packet, **options)
        with patch.object(OBS.socket, 'create_connection', return_value=stream), \
             patch.object(OBS.subprocess, 'Popen') as spawn:
            value = OBS.adb_observation('emulator-5554', time.monotonic() + 1)
        spawn.assert_not_called()
        self.assertEqual(stream.request, b'000chost:devices')
        self.assertTrue(all(0 < t <= 1 for t in stream.timeouts))
        return value

    def test_fragmented_read_only_query_filters_other_serials(self):
        value = self.query(adb_packet(b'private-canary\tdevice\nemulator-5554\toffline\n'))
        self.assertEqual(value, {'status': 'observed', 'device_count': 2, 'target_state': 'offline'})
        self.assertNotIn('private-canary', json.dumps(value))
        self.assertEqual(self.query(adb_packet(b''))['target_state'], 'missing')

    def test_malformed_truncated_oversized_and_ambiguous_answers_fail_closed(self):
        variants = [
            b'NOPE', b'OKAYzzzz', b'OKAYffff', b'OKAY0004ab',
            adb_packet(b'emulator-5554\tdevice\nemulator-5554\toffline\n'),
            adb_packet(b'emulator-5554\tunknown-canary\n'),
            adb_packet(b'private-canary malformed row\n'),
            adb_packet(b'\xff'), adb_packet(b'a\tdevice\n' * 65),
        ]
        for packet in variants:
            with self.subTest(packet=packet[:16]):
                value = self.query(packet)
                self.assertEqual(value['status'], 'malformed')
                self.assertNotIn('canary', json.dumps(value))

    def test_server_failure_timeout_absence_and_invalid_serial_are_distinct(self):
        self.assertEqual(self.query(b'FAIL')['status'], 'server_rejected')
        self.assertEqual(self.query(b'', timeout=True)['status'], 'timeout')
        with patch.object(OBS.socket, 'create_connection', side_effect=ConnectionRefusedError):
            self.assertEqual(OBS.adb_observation('emulator-5554', time.monotonic() + 1)['status'],
                             'unavailable')
        with patch.object(OBS.socket, 'create_connection') as connect:
            self.assertEqual(OBS.adb_observation('private-canary', time.monotonic() + 1)['status'],
                             'invalid_serial')
        connect.assert_not_called()


class SnapshotTests(unittest.TestCase):
    def launch(self, out):
        reference = {'relative': '/fixture', 'device': 1, 'inode': 2}
        launch = launch_record({'pid': 77, 'start_ticks': 123})
        launch['cgroup'] = {'identity_sha256': OBS.cgroup_key(reference)}
        OBS.write_json(out / OBS.LAUNCH, launch)
        return launch, reference

    def test_missing_observer_and_no_exit_receipt_does_not_invent_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            _, reference = self.launch(out)
            state = out / 'private-state'
            OBS.write_json(state, reference)
            def process(pid, expected):
                return {'status': 'observed' if pid == 77 else 'missing', 'pid': pid}
            with patch.object(OBS, 'process', side_effect=process), \
                 patch.object(OBS, 'memory_observation', return_value={'status': 'unavailable'}), \
                 patch.object(OBS, 'adb_observation', return_value={'status': 'unavailable'}), \
                 patch.object(OBS, 'bounded_command', return_value=(b'', 'unavailable')):
                OBS.snapshot(out, state, 'emulator-5554')
                first = (out / OBS.SNAPSHOT).read_bytes()
                OBS.mark_stop(out)
                OBS.snapshot(out, state, 'emulator-5554')
            record = json.loads(first)
            self.assertTrue(record['observer_lost'])
            self.assertEqual(record['emulator']['status'], 'observed')
            self.assertEqual(record['exit']['status'], 'not_recorded')
            self.assertNotIn('returncode', record['exit'])
            self.assertEqual((out / OBS.SNAPSHOT).read_bytes(), first)
            stop = json.loads((out / OBS.STOP).read_text())
            self.assertGreaterEqual(stop['requested']['monotonic_ns'], record['finished']['monotonic_ns'])

    def test_missing_private_cgroup_state_preserves_valid_process_and_exit_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            launch, _ = self.launch(out)
            OBS.write_json(out / OBS.EXIT, {
                'returncode': 0, 'emulator_pid': 77, 'observer': launch['observer'],
                'observed': {'monotonic_ns': 100}})
            with patch.object(OBS, 'process', side_effect=lambda pid, expected:
                              {'status': 'observed', 'pid': pid, 'start_ticks': expected}), \
                 patch.object(OBS, 'memory_observation') as memory, \
                 patch.object(OBS, 'adb_observation', return_value={'status': 'unavailable'}), \
                 patch.object(OBS, 'bounded_command', return_value=(b'', 'unavailable')):
                OBS.snapshot(out, out / 'missing-private-state', 'emulator-5554')
            memory.assert_not_called()
            report = json.loads((out / OBS.SNAPSHOT).read_text())
            self.assertEqual(report['launch'], 'observed')
            self.assertEqual(report['emulator']['status'], 'observed')
            self.assertEqual(report['observer']['status'], 'observed')
            self.assertEqual(report['exit']['status'], 'observed')
            self.assertEqual(report['exit']['returncode'], 0)
            self.assertEqual(report['cgroup'], {'status': 'unavailable'})
            self.assertNotIn('values', report['cgroup'])

    def test_exit_receipt_requires_child_and_observer_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            launch, _ = self.launch(out)
            receipt = {'returncode': -9, 'emulator_pid': 77,
                       'observer': {'pid': 88, 'start_ticks': 100},
                       'observed': {'monotonic_ns': 100}}
            OBS.write_json(out / OBS.EXIT, receipt)
            self.assertEqual(OBS.exit_observation(out, launch)['signal'], 9)
            for mutation in ({'returncode': True}, {'emulator_pid': 99},
                             {'observer': {'pid': 88, 'start_ticks': 101}}):
                OBS.write_json(out / OBS.EXIT, receipt | mutation)
                self.assertEqual(OBS.exit_observation(out, launch)['status'], 'unknown')

    def test_unavailable_or_malformed_launch_cannot_leak_payload(self):
        for launch in ([], {'schema': True}, {'schema': 1, 'cgroup': 'private-canary'}):
            with self.subTest(launch=launch), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                OBS.write_json(out / OBS.LAUNCH, launch)
                with patch.object(OBS, 'process') as process, \
                     patch.object(OBS, 'adb_observation', return_value={'status': 'unavailable'}), \
                     patch.object(OBS, 'bounded_command', return_value=(b'', 'unavailable')):
                    OBS.snapshot(out, out / 'absent-state', 'emulator-5554')
                process.assert_not_called()
                report = (out / OBS.SNAPSHOT).read_text()
                self.assertNotIn('private-canary', report)
                self.assertEqual(json.loads(report)['launch'], 'unknown')


if __name__ == '__main__':
    unittest.main()
