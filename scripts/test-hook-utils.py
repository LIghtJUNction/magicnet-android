#!/usr/bin/env python3
"""Behavioral checks for the shared Bash hook API; no downloads or root needed."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UTILS = ROOT / "hooks/lib/utils.sh"
MISSING = "magicnet_test_command_that_does_not_exist_46e9b"


class HookUtilsTests(unittest.TestCase):
    def run_shell(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", script, "test-hook-utils", str(UTILS)],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )

    def test_source_is_silent_and_preserves_callers_environment(self):
        result = self.run_shell('ID=caller; . "$1"; test "$ID" = caller')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_required_command_has_optional_message_and_local_scratch(self):
        result = self.run_shell(
            '. "$1"; command_name=caller; message=caller; '
            'require_command bash; test "$command_name" = caller; test "$message" = caller'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_has_command_failure_returns_instead_of_exiting(self):
        for argument in (MISSING, ""):
            with self.subTest(argument=argument):
                result = self.run_shell(
                    f'. "$1"; if has_command {argument}; then exit 9; fi; printf reached'
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.endswith("reached"))
                self.assertNotIn("unbound variable", result.stderr)

    def test_missing_requirement_exits_with_literal_message(self):
        for message in ("", "100% unavailable: %s ${HOME}"):
            with self.subTest(message=message):
                result = self.run_shell(
                    f'. "$1"; require_command {MISSING} \'{message}\'; printf unreachable'
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn("unreachable", result.stdout)
                self.assertIn(message or f"Command '{MISSING}' is required", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_build_helpers_do_not_replace_installer_functions(self):
        result = self.run_shell(
            'ui_print() { printf installer; }; . "$1"; ui_print'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "installer")


class LockedToolHookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.module = self.root / "module"
        library = self.root / "hooks/lib"
        library.mkdir(parents=True)
        for name in ("utils.sh", "release_utils.sh", "release_locks.sh"):
            shutil.copyfile(ROOT / "hooks/lib" / name, library / name)
        # Stub asset preparation only; exercise the actual hook and atomic promotion
        # helpers without networking or changing the production release locks.
        with (library / "release_utils.sh").open("a") as output:
            output.write("""
hook_prepare_locked_asset() {
    printf '%s\\n' "$1" >>"$MAGICNET_TEST_TOOL_TRACE"
    [ "$1" != "$MAGICNET_TEST_FAIL_TOOL" ] || return 1
    RELEASE_LOCK_TAG="fixture-$1"
    mkdir -p "$(dirname "$2")" || return 1
    printf '%s\\n' "$1" >"$2"
}
""")
        tools = self.root / "tools"
        tools.mkdir()
        curl = tools / "curl"
        curl.write_text("#!/bin/sh\nexit 99\n")
        curl.chmod(0o755)
        self.trace = self.root / "trace"
        self.env = dict(os.environ)
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            self.env.pop(name, None)
        self.env.update(
            KAM_HOOKS_ROOT=str(library.parent),
            KAM_MODULE_ROOT=str(self.module),
            MAGICNET_TEST_TOOL_TRACE=str(self.trace),
            MAGICNET_TEST_FAIL_TOOL="",
            PATH=f"{tools}:{os.environ['PATH']}",
        )

    def run_hook(self, fail_tool=""):
        # KAM must receive failure even when the shell does not enable errexit.
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", str(ROOT / "hooks/pre-build/4900.update_tools.sh")],
            env=dict(self.env, MAGICNET_TEST_FAIL_TOOL=fail_tool),
            text=True, capture_output=True, timeout=5, check=False,
        )
        return result, self.trace.read_text().splitlines()

    def test_yq_failure_stops_before_jq_and_fails_the_hook(self):
        result, calls = self.run_hook("yq")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["yq"])
        self.assertEqual(list((self.module / "bin").iterdir()), [])
        self.assertEqual(list((self.module / ".state/tools").iterdir()), [])

    def test_jq_failure_fails_the_hook_after_successful_yq(self):
        result, calls = self.run_hook("jq")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["yq", "jq"])
        self.assertEqual((self.module / "bin/yq").read_text(), "yq\n")
        self.assertEqual((self.module / ".state/tools/yq.version").read_text(), "fixture-yq\n")
        self.assertFalse((self.module / "bin/jq").exists())
        self.assertFalse((self.module / ".state/tools/jq.version").exists())

    def test_success_installs_both_tools_in_order(self):
        result, calls = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["yq", "jq"])
        for name in ("yq", "jq"):
            with self.subTest(tool=name):
                self.assertEqual((self.module / "bin" / name).read_text(), f"{name}\n")
                self.assertEqual(
                    (self.module / ".state/tools" / f"{name}.version").read_text(),
                    f"fixture-{name}\n",
                )


if __name__ == "__main__":
    unittest.main()
