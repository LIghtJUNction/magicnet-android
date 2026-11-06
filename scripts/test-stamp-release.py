#!/usr/bin/env python3
"""Check version stamping and build drift against real isolated Git commits."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("stamp_release", Path(__file__).with_name("stamp-release.py"))
STAMP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAMP)


class StampTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="magicnet-stamp-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original = {
            "kam.toml": '[prop]\nid = "MagicNet"\nname = "Keep this name"\nversion = "v1.8.5"\nversionCode = 10613\n'
                        '[mmrl.repo]\nlicense = "MIT"\nchangelog = "https://github.com/LIghtJUNction/MagicNet/blob/main/docs/releases/v1.8.5.md"\n'
                        'changelog_file = "docs/releases/v1.8.5.md"\n',
            "src/MagicNet/module.prop": 'id=MagicNet\nname=Keep this name\nversion=v1.8.5\nversionCode=10613\n',
            "update.json": json.dumps(STAMP.updater("v1.8.5", 10613)),
            "docs/releases/v1.8.5.md": "# Existing release notes\n",
        }
        for name, text in self.original.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("add", ".")
        self.git("commit", "-m", "Source baseline")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True,
                                       stderr=subprocess.PIPE).strip()

    def test_custom_version_updates_all_fields_and_is_idempotent(self):
        result = STAMP.stamp(self.root, "1.9.0", "10700")
        self.assertEqual(result, {"version": "v1.9.0", "version_code": "10700"})
        expected = {path: (self.root / path).read_bytes() for path in STAMP.METADATA_FILES}
        self.assertEqual(json.loads((self.root / "update.json").read_text()), STAMP.updater("v1.9.0", 10700))
        self.assertIn('name = "Keep this name"', (self.root / "kam.toml").read_text())
        STAMP.stamp(self.root, "v1.9.0", "10700")
        self.assertEqual(expected, {path: (self.root / path).read_bytes() for path in STAMP.METADATA_FILES})
        self.assertEqual(STAMP.verify(self.root, "v1.9.0", "10700"), result)

    def test_current_version_preserves_committed_release_notes(self):
        STAMP.stamp(self.root, "v1.8.5", "10613")
        STAMP.verify(self.root, "v1.8.5", "10613")
        self.assertEqual((self.root / "docs/releases/v1.8.5.md").read_text(), self.original["docs/releases/v1.8.5.md"])

    def test_bad_input_does_not_change_any_metadata(self):
        for version, code in (("1.9", "10700"), ("v01.9.0", "10700"), ("1.9.0;echo bad", "10700"),
                              ("1.9.0", "0"), ("1.9.0", "01"), ("1.9.0", "2147483648"),
                              ("1.9.0", "true"), ("1.9.0", "10700\n")):
            with self.subTest(version=version, code=code), self.assertRaises(ValueError):
                STAMP.stamp(self.root, version, code)
            self.assertEqual(self.git("status", "--porcelain"), "")

    def test_inconsistent_source_is_rejected_before_writes(self):
        path = self.root / "update.json"
        path.write_text(json.dumps(STAMP.updater("v1.8.4", 10612)))
        with self.assertRaises(ValueError):
            STAMP.stamp(self.root, "v1.9.0", "10700")
        self.assertEqual((self.root / "kam.toml").read_text(), self.original["kam.toml"])
        self.assertFalse((self.root / "docs/releases/v1.9.0.md").exists())

    def test_missing_fields_and_notes_fail_before_writes(self):
        path = self.root / "kam.toml"
        path.write_text(self.original["kam.toml"].replace('versionCode = 10613\n', ''))
        with self.assertRaises(KeyError):
            STAMP.stamp(self.root, "v1.9.0", "10700")
        path.write_text(self.original["kam.toml"])
        (self.root / "docs/releases/v1.8.5.md").unlink()
        with self.assertRaisesRegex(ValueError, "Missing source release notes"):
            STAMP.stamp(self.root, "v1.9.0", "10700")
        self.assertEqual(path.read_text(), self.original["kam.toml"])

    def test_duplicate_module_properties_are_rejected(self):
        path = self.root / "src/MagicNet/module.prop"
        path.write_text(path.read_text() + "version=v1.8.5\n")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            STAMP.stamp(self.root, "v1.9.0", "10700")

    def test_unofficial_update_urls_are_rejected(self):
        path = self.root / "update.json"
        path.write_text(path.read_text().replace("LIghtJUNction/MagicNet", "someone/other"))
        with self.assertRaisesRegex(ValueError, "unofficial"):
            STAMP.stamp(self.root, "v1.9.0", "10700")

    def test_kam_json_reserialization_is_allowed_but_drift_is_rejected(self):
        STAMP.stamp(self.root, "1.9.0", "10700")
        path = self.root / "update.json"
        path.write_text(json.dumps(json.loads(path.read_text()), sort_keys=True))
        STAMP.verify(self.root, "1.9.0", "10700")
        path = self.root / "kam.toml"
        path.write_text(path.read_text().replace("Keep this name", "Changed by build"))
        with self.assertRaisesRegex(ValueError, "outside the permitted"):
            STAMP.verify(self.root, "1.9.0", "10700")

    def test_build_cannot_change_target_version_or_generated_notes(self):
        STAMP.stamp(self.root, "1.9.0", "10700")
        with self.assertRaises(ValueError):
            STAMP.verify(self.root, "1.9.1", "10700")
        (self.root / "docs/releases/v1.9.0.md").write_text("Wrong build notes\n")
        with self.assertRaisesRegex(ValueError, "release notes"):
            STAMP.verify(self.root, "1.9.0", "10700")

    def test_explicit_notes_are_checked(self):
        path = self.root / "provided.md"
        path.write_text("# Supplied release notes\n")
        STAMP.stamp(self.root, "1.9.0", "10700", path)
        STAMP.verify(self.root, "1.9.0", "10700", path)


if __name__ == "__main__":
    unittest.main()
