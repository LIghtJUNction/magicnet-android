#!/usr/bin/env python3
"""Execute ADB deadline and exit-status contracts with a deliberately stalled adb."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AdbDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        adb = self.root / 'adb'
        adb.write_text('''#!/bin/sh
case "$FAKE_ADB" in
  stall) exec sleep 60 ;;
  boot)
    case "$*" in
      *wait-for-device*) sleep "${FAKE_ADB_BOOT_DELAY:-0}" ;;
      *getprop*) echo 1 ;;
    esac
    exit 0 ;;
  fail) exit 37 ;;
esac
''')
        adb.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root)+':'+os.environ['PATH'],
                        MAGICNET_ADB_CALL_TIMEOUT='1', MAGICNET_BOOT_TIMEOUT='1', FAKE_ADB='stall')

    def run_shell(self, command, **env):
        return subprocess.run(['bash', '-c', '. "$1"; '+command, '_', str(ROOT/'scripts/lib/android-adb.sh')],
                              text=True, capture_output=True, env=self.env | env, timeout=5)

    def test_wait_for_disconnected_device_has_deadline(self):
        started = time.monotonic()
        result = self.run_shell('wait_boot')
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic()-started, 4)

    def test_ordinary_adb_call_also_has_deadline(self):
        result = self.run_shell('adb shell id')
        self.assertEqual(result.returncode, 124)

    def test_adb_failure_is_not_changed_to_success(self):
        result = self.run_shell('adb shell id', FAKE_ADB='fail')
        self.assertEqual(result.returncode, 37)

    def test_successful_boot_still_works(self):
        # Bash SECONDS has whole-second resolution. A success check must not
        # inherit the one-second budget used to force the timeout cases.
        result = self.run_shell('wait_boot', FAKE_ADB='boot', MAGICNET_BOOT_TIMEOUT='5')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_delayed_ready_device_distinguishes_success_and_timeout_budgets(self):
        # Model bounded ADB startup overhead without relying on the wall-clock
        # phase: the old budget must expire, while the success budget must pass.
        for budget, expected in (('1', 1), ('5', 0)):
            with self.subTest(budget=budget):
                result = self.run_shell('wait_boot', FAKE_ADB='boot',
                                        FAKE_ADB_BOOT_DELAY='1.2', MAGICNET_BOOT_TIMEOUT=budget)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_bad_deadline_is_rejected(self):
        for value in ('0', '-1', '1;exit 0', '601'):
            result = self.run_shell('adb shell id', MAGICNET_ADB_CALL_TIMEOUT=value)
            self.assertEqual(result.returncode, 64)


if __name__ == '__main__':
    unittest.main()
