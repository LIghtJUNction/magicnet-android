#!/usr/bin/env python3
"""Compose the real MagicNet controller and kamfw fswatch lifecycle locks."""
import fcntl
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUSYBOX = shutil.which('busybox')

BOOTSTRAP = r'''
print() { printf '%s\n' "$*"; }
set_i18n() { :; }
i18n() { printf '%s\n' "$1"; }
t() { cat; }
success() { :; }
warn() { printf '%s\n' "$*" >&2; }
error() { printf '%s\n' "$*" >&2; }
import() { if [ "$1" = fswatch ]; then . "$KAMFW_DIR/fswatch.sh"; fi; }
'''

DRIVER = r'''
set -eu
. "$KAMFW_DIR/.kamfwrc"
. "$MODDIR/lib/magicnet/common.sh"
. "$MODDIR/lib/magicnet/supervisors.sh"
# Use Android's CLI boundary for every shell; Bash's fixture-only reader
# would otherwise bypass the same bounded proc-reader adapter used below.
magicnet_host_proc_reader_allowed() { return 1; }
if [ "$FSWATCH_TEST_BACKEND" = util-linux ]; then
    # Select the host backend without replacing either actual lock function.
    magicnet_fswatch_busybox_bin() { return 1; }
fi
case "$1" in
start) magicnet_fswatch_start ;;
stop) magicnet_fswatch_stop ;;
*) exit 2 ;;
esac
'''

# Only the platform proc-reader boundary is substituted. The controller,
# flock runners, process ownership checks, PID publication and loop are real.
PROC_READER = r'''
from pathlib import Path
import sys
try:
    command, root, pid = sys.argv[1:]
    process = Path(root) / str(int(pid))
    if command == '__proc-cmdline':
        with (process / 'cmdline').open('rb') as stream:
            data = stream.read(65537)
        if len(data) > 65536 or not data.endswith(b'\0'):
            raise ValueError('invalid argv')
        values = data[:-1].split(b'\0')
        if any(not value or b'\n' in value or b'\r' in value for value in values):
            raise ValueError('invalid argv')
        sys.stdout.buffer.write(b'\n'.join(values) + b'\n')
    elif command == '__proc-stat':
        fields = (process / 'stat').read_text().rsplit(') ', 1)[1].split()
        print(fields[0], int(fields[19]))
    else:
        raise ValueError('unsupported command')
except (OSError, ValueError, IndexError):
    sys.exit(1)
'''


class Fixture:
    def __init__(self, shell, backend):
        self.temporary = tempfile.TemporaryDirectory(prefix='magicnet-kamfw-locks-')
        self.root = Path(self.temporary.name)
        self.shell = shell
        self.children = []
        for directory in ('.config', '.cache', '.log', 'lib/kamfw', '.state/fswatch'):
            (self.root / directory).mkdir(parents=True)
        (self.root / 'lib/magicnet').symlink_to(ROOT / 'src/MagicNet/lib/magicnet')
        source = ROOT / 'src/MagicNet/lib/kamfw/fswatch.sh'
        if not source.is_file():
            raise AssertionError('initialize the pinned src/MagicNet/lib/kamfw submodule')
        (self.root / 'lib/kamfw/fswatch.sh').symlink_to(source)
        (self.root / 'lib/kamfw/.kamfwrc').write_text(BOOTSTRAP)
        (self.root / 'driver.sh').write_text(DRIVER)
        self.executable('cli', PROC_READER)
        busybox = '/bin/false'
        if backend == 'busybox':
            # Android's absolute shell path is the only host adaptation. Every
            # flock/start-stop-daemon operation still executes actual BusyBox.
            self.executable('busybox-host',
                            'import os, sys\n'
                            'args = sys.argv[1:]\n'
                            "if args and args[0] == 'start-stop-daemon':\n"
                            "    args = ['/bin/sh' if value == '/system/bin/sh' else value for value in args]\n"
                            f'os.execv({BUSYBOX!r}, [{BUSYBOX!r}, *args])\n')
            busybox = str(self.root / 'busybox-host')
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('MAGICNET_', 'KAM_'))}
        self.env.update(MODDIR=str(self.root), MODPATH=str(self.root), KAM_HOME=str(self.root),
                        KAMFW_DIR=str(self.root / 'lib/kamfw'), KAM_FSWATCH_BUSYBOX_BIN=busybox,
                        TMPDIR=str(self.root / '.cache'), MAGICNET_FSWATCH_INTERVAL='1',
                        FSWATCH_TEST_BACKEND=backend)
        self.pidfile = self.root / '.state/fswatch/magicnet-config.pid'
        self.loop = str(self.root / '.state/fswatch/magicnet-config.loop.sh')
        self.locks = [self.root / f'.state/fswatch/magicnet-config.{kind}.lock'
                      for kind in ('controller', 'lifecycle')]

    def executable(self, relative, source):
        path = self.root / relative
        path.write_text(f'#!{sys.executable}\n' + source)
        path.chmod(0o700)

    def spawn(self, action):
        process = subprocess.Popen([*self.shell, str(self.root / 'driver.sh'), action],
                                   env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True)
        self.children.append(process)
        return process

    def finish(self, process, timeout=8):
        try:
            output = process.communicate(timeout=timeout)[0]
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output = process.communicate(timeout=2)[0]
            raise AssertionError(f'fswatch lifecycle exceeded {timeout}s: {output}') from None
        return process.returncode, output

    def run(self, action, timeout=8):
        return self.finish(self.spawn(action), timeout)

    def workers(self):
        result = []
        for directory in Path('/proc').iterdir():
            if not directory.name.isdigit():
                continue
            try:
                argv = (directory / 'cmdline').read_bytes().split(b'\0')
                if argv == [argv[0], self.loop.encode(), b'']:
                    result.append(int(directory.name))
            except (OSError, IndexError):
                pass
        return sorted(result)

    def has_open_lock(self, path, process_group):
        for directory in Path('/proc').iterdir():
            if not directory.name.isdigit():
                continue
            try:
                if os.getpgid(int(directory.name)) != process_group:
                    continue
                for descriptor in (directory / 'fd').iterdir():
                    try:
                        if os.readlink(descriptor) == str(path):
                            return True
                    except FileNotFoundError:
                        continue
            except (OSError, ProcessLookupError):
                continue
        return False

    def close(self):
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=2)
        for pid in self.workers():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.temporary.cleanup()


class RealKamfwLifecycleTests(unittest.TestCase):
    def wait_for_lock_open(self, fixture, path, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), 'launcher exited before reaching the real lock')
            if fixture.has_open_lock(path, process.pid):
                return
            time.sleep(0.02)
        self.fail(f'launcher did not open {path.name}')

    def assert_released_locks(self, fixture, pid):
        self.assertNotEqual(fixture.locks[0], fixture.locks[1])
        for path in fixture.locks:
            self.assertTrue(path.is_file(), f'actual lock was not opened: {path.name}')
            with path.open('a') as descriptor:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for descriptor in Path(f'/proc/{pid}/fd').iterdir():
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            self.assertNotIn(target, [str(path) for path in fixture.locks],
                             'detached watcher inherited a lifecycle/controller lock')

    def test_real_framework_start_stop_and_concurrent_start(self):
        shells = [['bash'], ['sh']]
        if shutil.which('mksh'):
            shells.append([shutil.which('mksh')])
        if BUSYBOX:
            shells.append([BUSYBOX, 'sh'])
        backends = ['util-linux', 'busybox'] if BUSYBOX else ['util-linux']
        for shell in shells:
            for backend in backends:
                with self.subTest(shell=shell, backend=backend):
                    fixture = Fixture(shell, backend)
                    try:
                        self.assertEqual(fixture.run('start'), (0, ''))
                        first = int(fixture.pidfile.read_text())
                        self.assertEqual(fixture.workers(), [first])
                        self.assert_released_locks(fixture, first)
                        self.assertEqual(fixture.run('start'), (0, ''))
                        self.assertEqual(int(fixture.pidfile.read_text()), first)
                        self.assertEqual(fixture.run('stop'), (0, ''))
                        self.assertFalse(fixture.pidfile.exists())
                        self.assertEqual(fixture.workers(), [])
                        launchers = [fixture.spawn('start') for _ in range(4)]
                        for launcher in launchers:
                            self.assertEqual(fixture.finish(launcher), (0, ''))
                        current = int(fixture.pidfile.read_text())
                        self.assertEqual(fixture.workers(), [current])
                        self.assert_released_locks(fixture, current)
                        self.assertEqual(fixture.run('stop'), (0, ''))
                        self.assertEqual(fixture.workers(), [])
                        print(f'Real kamfw fswatch passed: {shell[0]} / {backend}', flush=True)
                    finally:
                        fixture.close()

    def test_real_lifecycle_lock_serializes_start_and_stop(self):
        backends = ['util-linux', 'busybox'] if BUSYBOX else ['util-linux']
        for backend in backends:
            with self.subTest(backend=backend):
                fixture = Fixture(['sh'], backend)
                try:
                    with fixture.locks[1].open('a') as descriptor:
                        fcntl.flock(descriptor, fcntl.LOCK_EX)
                        start = fixture.spawn('start')
                        # A real inner flock must open the lifecycle inode and
                        # block behind us while MagicNet holds its controller.
                        self.wait_for_lock_open(fixture, fixture.locks[1], start)
                        stop = fixture.spawn('stop')
                        self.wait_for_lock_open(fixture, fixture.locks[0], stop)
                        self.assertIsNone(start.poll())
                        self.assertIsNone(stop.poll())
                        self.assertFalse(fixture.pidfile.exists())
                        self.assertEqual(fixture.workers(), [])
                    self.assertEqual(fixture.finish(start), (0, ''))
                    self.assertEqual(fixture.finish(stop), (0, ''))
                    self.assertFalse(fixture.pidfile.exists())
                    self.assertEqual(fixture.workers(), [])
                finally:
                    fixture.close()

    def test_busy_controller_lock_is_bounded_and_does_not_launch(self):
        fixture = Fixture(['sh'], 'util-linux')
        try:
            with fixture.locks[0].open('a') as descriptor:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                started = time.monotonic()
                result, _output = fixture.run('start', timeout=14)
                elapsed = time.monotonic() - started
                self.assertNotEqual(result, 0)
                self.assertGreaterEqual(elapsed, 9)
                self.assertLess(elapsed, 14)
                self.assertFalse(fixture.pidfile.exists())
                self.assertEqual(fixture.workers(), [])
            self.assertEqual(fixture.run('start'), (0, ''))
            self.assertEqual(fixture.run('stop'), (0, ''))
        finally:
            fixture.close()


if __name__ == '__main__':
    unittest.main()
