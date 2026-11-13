#!/usr/bin/env python3
"""Passive, bounded host evidence; never used to accept an Android test.

Only the explicit cleanup commands may signal the existing emulator. The watch
process launches the unchanged argv once, then waits without a timeout/restart.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

JSON_LIMIT = 32768
PROC_LIMIT = 16384
KERNEL_LIMIT = 524288
ADB_LIMIT = 8192
SNAPSHOT_SECONDS = 12
CGROOT = Path('/sys/fs/cgroup')
EVENT_KEYS = {'low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill'}
LAUNCH = 'emulator-host-launch.json'
EXIT = 'emulator-host-exit.json'
SNAPSHOT = 'emulator-host-before-stop.json'
STOP = 'emulator-host-stop-request.json'


def uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def stamp():
    return {'monotonic_ns': time.monotonic_ns(), 'unix_ns': time.time_ns()}


def read_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('not_regular')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('size_limit')
        return data
    finally:
        os.close(fd)


def unique_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate_key')
        out[key] = value
    return out


def read_json(path):
    return json.loads(read_bytes(path, JSON_LIMIT), object_pairs_hook=unique_keys)


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if len(data) > JSON_LIMIT:
        raise ValueError('size_limit')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.host-observer-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def parse_stat(data, pid):
    text = data.decode('ascii')
    start, separator, rest = text.rpartition(') ')
    if not separator or not start.startswith(str(pid) + ' ('):
        raise ValueError('invalid_stat')
    fields = rest.split()
    if len(fields) < 22 or len(fields[0]) != 1 or fields[0] not in 'RSDZTWtXxKWPIN':
        raise ValueError('invalid_stat')
    numbers = [int(fields[i]) for i in (1, 11, 12, 17, 19, 21)]
    if not all(uint(v) for v in numbers):
        raise ValueError('invalid_stat')
    ppid, user, system, threads, ticks, rss = numbers
    return {'pid': pid, 'start_ticks': ticks, 'state': fields[0], 'ppid': ppid,
            'cpu_ticks': user + system, 'threads': threads, 'rss_pages': rss}


def identity(value):
    if (not isinstance(value, dict) or not uint(value.get('pid'), (1 << 31) - 1)
            or value['pid'] == 0 or not uint(value.get('start_ticks'))):
        raise ValueError('invalid_identity')
    return {key: value[key] for key in ('pid', 'start_ticks')}


def process(pid, expected=None, proc=Path('/proc')):
    if not uint(pid, (1 << 31) - 1) or pid == 0:
        return {'status': 'unknown'}
    try:
        path = proc / str(pid)
        observed = parse_stat(read_bytes(path / 'stat', PROC_LIMIT), pid)
        if expected is not None and observed['start_ticks'] != expected:
            return {'status': 'pid_reused', 'pid': pid}
        try:
            name = Path(os.readlink(path / 'exe')).name
            observed['executable'] = name if re.fullmatch(r'[A-Za-z0-9_.+-]{1,80}', name) else 'unknown'
        except OSError:
            observed['executable'] = 'unavailable'
        again = parse_stat(read_bytes(path / 'stat', PROC_LIMIT), pid)
        if again['start_ticks'] != observed['start_ticks']:
            return {'status': 'pid_reused', 'pid': pid}
        return observed | {'status': 'zombie' if observed['state'] == 'Z' else 'observed'}
    except FileNotFoundError:
        return {'status': 'missing', 'pid': pid}
    except (OSError, ValueError, UnicodeError):
        return {'status': 'unknown', 'pid': pid}


def cgroup_reference(pid, proc=Path('/proc'), root=CGROOT):
    lines = read_bytes(proc / str(pid) / 'cgroup', PROC_LIMIT).decode('ascii').splitlines()
    matches = [line[3:] for line in lines if line.startswith('0::')]
    if len(matches) != 1 or not re.fullmatch(r'/[A-Za-z0-9_./:@+-]*', matches[0]):
        raise ValueError('cgroup_unavailable')
    relative = matches[0]
    if any(part in ('.', '..') for part in relative.split('/')):
        raise ValueError('cgroup_unavailable')
    path = root / relative.lstrip('/')
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('cgroup_unavailable')
    info = resolved.stat()
    return {'relative': relative, 'device': info.st_dev, 'inode': info.st_ino}


def cgroup_key(reference):
    return hashlib.sha256(json.dumps(reference, sort_keys=True).encode()).hexdigest()


def memory_observation(reference, root=CGROOT):
    try:
        if (not isinstance(reference, dict) or set(reference) != {'relative', 'device', 'inode'}
                or not isinstance(reference['relative'], str)
                or not re.fullmatch(r'/[A-Za-z0-9_./:@+-]*', reference['relative'])
                or any(p in ('.', '..') for p in reference['relative'].split('/'))
                or not all(uint(reference[k]) for k in ('device', 'inode'))):
            raise ValueError('invalid_cgroup')
        path = (root / reference['relative'].lstrip('/')).resolve(strict=True)
        if not path.is_relative_to(root.resolve()):
            raise ValueError('invalid_cgroup')
        info = path.stat()
        if (info.st_dev, info.st_ino) != (reference['device'], reference['inode']):
            return {'status': 'identity_changed'}
        values = {}
        for name in ('memory.events', 'memory.events.local', 'memory.current', 'memory.peak', 'memory.max'):
            try:
                text = read_bytes(path / name, PROC_LIMIT).decode('ascii').strip()
                if name.startswith('memory.events'):
                    parsed = {}
                    for line in text.splitlines():
                        key, number = line.split()
                        if key in parsed or not re.fullmatch(r'[0-9]{1,20}', number) or not uint(int(number)):
                            raise ValueError('invalid_counter')
                        if key in EVENT_KEYS:
                            parsed[key] = int(number)
                    if not parsed:
                        raise ValueError('missing_counters')
                    values[name] = parsed
                elif text == 'max' and name == 'memory.max':
                    values[name] = 'max'
                elif re.fullmatch(r'[0-9]{1,20}', text) and uint(int(text)):
                    values[name] = int(text)
                else:
                    raise ValueError('invalid_counter')
            except (OSError, ValueError, UnicodeError):
                values[name] = None
        return {'status': 'observed', 'identity_sha256': cgroup_key(reference), 'values': values}
    except (OSError, ValueError):
        return {'status': 'unavailable'}


def watch(output, state, argv):
    if not argv or len(argv) > 128 or sum(len(x.encode()) for x in argv) > PROC_LIMIT:
        raise ValueError('invalid_argv')
    output.mkdir(parents=True, exist_ok=True)
    observer = identity(process(os.getpid()))
    launch = {'schema': 1, 'scope': 'host-diagnostics-only', 'started': stamp(),
              'observer': observer, 'emulator': None,
              'argv_sha256': hashlib.sha256(b'\0'.join(x.encode() for x in argv)).hexdigest(),
              'cgroup': {'status': 'unavailable'}}
    # Direct file output avoids pipe backpressure. No shell, session change,
    # signal forwarding, restart, guest command, or wait timeout is introduced.
    try:
        with (output / 'emulator.log').open('wb') as log:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, shell=False)
    except OSError:
        write_json(output / LAUNCH, launch | {'launch_status': 'failed'})
        return 1
    launch['emulator'] = process(child.pid)
    try:
        reference = cgroup_reference(child.pid)
        launch['cgroup'] = memory_observation(reference)
        write_json(state, reference)  # Private runner temp state; never uploaded.
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        write_json(output / LAUNCH, launch | {'launch_status': 'spawned'})
        (output / 'emulator.pid').write_text(str(child.pid) + '\n')
    except (OSError, ValueError):
        print('host observer launch record unavailable', file=sys.stderr)
    # Even a recording failure must not terminate or restart the child.
    result = child.wait()
    receipt = {'schema': 1, 'scope': 'host-diagnostics-only', 'observed': stamp(),
               'emulator_pid': child.pid, 'observer': observer, 'returncode': result,
               'exit_code': result if result >= 0 else None,
               'signal': -result if result < 0 else None}
    write_json(output / EXIT, receipt)
    return 0


def adb_observation(serial, deadline, address=('127.0.0.1', 5037)):
    if not re.fullmatch(r'emulator-[0-9]{1,5}', serial):
        return {'status': 'invalid_serial'}
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError
        return value
    try:
        # Query the existing server directly: unlike the adb client this cannot
        # auto-start/replace a daemon or reconnect/reset an emulator transport.
        with socket.create_connection(address, timeout=remaining()) as stream:
            def receive(size):
                data = b''
                while len(data) < size:
                    stream.settimeout(remaining())
                    part = stream.recv(size - len(data))
                    if not part:
                        raise ValueError('truncated')
                    data += part
                return data
            request = b'host:devices'
            stream.settimeout(remaining())
            stream.sendall(f'{len(request):04x}'.encode() + request)
            reply = receive(4)
            if reply == b'FAIL':
                return {'status': 'server_rejected'}
            if reply != b'OKAY':
                raise ValueError('invalid_status')
            prefix = receive(4)
            if not re.fullmatch(rb'[0-9a-fA-F]{4}', prefix) or int(prefix, 16) > ADB_LIMIT:
                raise ValueError('invalid_length')
            rows = receive(int(prefix, 16)).decode('ascii').splitlines()
            if len(rows) > 64:
                raise ValueError('too_many_devices')
            found = []
            for row in rows:
                name, state = row.split('\t')
                if name == serial:
                    found.append(state)
            if len(found) > 1 or (found and found[0] not in
                    {'device', 'offline', 'unauthorized', 'bootloader', 'recovery', 'sideload', 'rescue'}):
                raise ValueError('invalid_state')
            return {'status': 'observed', 'device_count': len(rows),
                    'target_state': found[0] if found else 'missing'}
    except (TimeoutError, socket.timeout):
        return {'status': 'timeout'}
    except OSError:
        return {'status': 'unavailable'}
    except (ValueError, UnicodeError):
        return {'status': 'malformed'}


def bounded_command(argv, deadline, limit=KERNEL_LIMIT):
    """Only a diagnostic reader is killed on timeout; never the emulator."""
    if time.monotonic() >= deadline:
        return b'', 'timeout'
    try:
        reader = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  stdin=subprocess.DEVNULL, shell=False)
    except OSError:
        return b'', 'unavailable'
    data = bytearray()
    outcome = 'complete'
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(reader.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(max(0, remaining)):
                    outcome = 'timeout'
                    break
                part = os.read(reader.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
                if len(data) > limit:
                    outcome = 'size_limit'
                    break
    finally:
        reader.stdout.close()
        try:
            if outcome == 'complete':
                code = reader.wait(timeout=min(0.25, max(0, deadline - time.monotonic())))
            else:
                code = None
        except subprocess.TimeoutExpired:
            code = None
        if code is None:
            if reader.poll() is None:
                reader.kill()
            try:
                reader.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
    if outcome == 'complete' and code != 0:
        outcome = 'unavailable'
    return bytes(data[:limit]), outcome


def kernel_oom(data, identity_pids):
    events = []
    count = 0
    for line in data.decode('ascii', errors='replace').splitlines():
        matched = re.search(r'(?:Out of memory|Memory cgroup out of memory): Killed process ([0-9]{1,10})\b', line)
        selected = re.search(r'\boom-kill:.*\bpid=([0-9]{1,10})\b', line)
        if not (matched or selected):
            continue
        count += 1
        pid = int((matched or selected).group(1))
        if pid not in identity_pids or len(events) >= 16:
            continue
        timestamp = re.search(r'\[\s*([0-9]{1,12}(?:\.[0-9]{1,9})?)\]', line)
        events.append({'pid': pid, 'kind': 'killed_process' if matched else 'oom_selection',
                       'kernel_seconds': float(timestamp.group(1)) if timestamp else None})
    return {'matching_pid_events': events, 'oom_line_count': count,
            'scope': 'observations_only_not_process_causation'}


def exit_observation(output, launch):
    try:
        record = read_json(output / EXIT)
        code = record['returncode']
        if (type(code) is not int or not -64 <= code <= 255
                or record['emulator_pid'] != identity(launch['emulator'])['pid']
                or identity(record['observer']) != identity(launch['observer'])
                or not uint(record['observed']['monotonic_ns'])):
            raise ValueError('invalid_exit')
        return {'status': 'observed', 'returncode': code,
                'exit_code': code if code >= 0 else None, 'signal': -code if code < 0 else None,
                'observed_monotonic_ns': record['observed']['monotonic_ns']}
    except FileNotFoundError:
        return {'status': 'not_recorded'}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unknown'}


def snapshot(output, state, serial):
    # This file is never replaced by post-cleanup evidence or a later snapshot.
    if (output / SNAPSHOT).exists():
        return
    deadline = time.monotonic() + SNAPSHOT_SECONDS
    result = {'schema': 1, 'scope': 'host-diagnostics-only', 'captured': stamp(),
              'budget_seconds': SNAPSHOT_SECONDS, 'launch': 'unknown',
              'emulator': {'status': 'unknown'}, 'observer': {'status': 'unknown'},
              'exit': {'status': 'unknown'}, 'cgroup': {'status': 'unavailable'}}
    identities = set()
    try:
        launch = read_json(output / LAUNCH)
        if (not isinstance(launch, dict) or type(launch.get('schema')) is not int
                or launch['schema'] != 1 or not isinstance(launch.get('cgroup'), dict)):
            raise ValueError('invalid_launch')
        for name in ('emulator', 'observer'):
            item = identity(launch[name])
            identities.add(item['pid'])
            result[name] = process(item['pid'], item['start_ticks'])
        result['launch'] = 'observed'
        result['exit'] = exit_observation(output, launch)
        result['observer_lost'] = (None if result['observer']['status'] == 'unknown'
                                  else result['exit']['status'] != 'observed'
                                  and result['observer']['status'] in {'missing', 'pid_reused', 'zombie'})
        reference = read_json(state)
        if cgroup_key(reference) != launch['cgroup'].get('identity_sha256'):
            raise ValueError('invalid_cgroup')
        result['cgroup'] = memory_observation(reference)
    except (OSError, ValueError, UnicodeError, KeyError, TypeError):
        pass
    result['adb'] = adb_observation(serial, min(deadline, time.monotonic() + 3))
    data, outcome = bounded_command(['sudo', '-n', 'dmesg', '--raw'],
                                    min(deadline, time.monotonic() + 3))
    result['kernel_oom'] = kernel_oom(data, identities) | {'read_status': outcome}
    result['finished'] = stamp()
    write_json(output / SNAPSHOT, result)


def mark_stop(output):
    if not (output / STOP).exists():
        write_json(output / STOP, {'schema': 1, 'scope': 'explicit-workflow-cleanup',
                                   'requested': stamp()})


def terminate(output):
    """Existing Stop-step SIGTERM, pinned to the recorded child with a pidfd."""
    result = {'schema': 1, 'scope': 'explicit-workflow-cleanup', 'observed': stamp(),
              'status': 'unknown'}
    descriptor = None
    try:
        launch = read_json(output / LAUNCH)
        child = identity(launch['emulator'])
        # Pin first, then compare starttime. A later PID reuse cannot redirect
        # the signal; unavailable pidfd support never falls back to kill(pid).
        descriptor = os.pidfd_open(child['pid'])
        observed = process(child['pid'], child['start_ticks'])
        result['status'] = observed['status']
        if observed['status'] == 'observed':
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            result['status'] = 'sigterm_sent'
    except ProcessLookupError:
        result['status'] = 'already_exited'
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    write_json(output / 'emulator-host-cleanup.json', result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('mode', choices=['watch', 'snapshot', 'mark-stop', 'terminate'])
    parser.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.mode == 'watch':
            argv = args.argv[1:] if args.argv[:1] == ['--'] else args.argv
            return watch(args.output, args.state, argv)
        if args.argv:
            raise ValueError('unexpected_arguments')
        if args.mode == 'snapshot':
            snapshot(args.output, args.state, args.serial)
        elif args.mode == 'mark-stop':
            mark_stop(args.output)
        else:
            terminate(args.output)
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('host observer evidence unavailable', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
