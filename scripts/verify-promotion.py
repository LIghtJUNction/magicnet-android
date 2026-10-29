#!/usr/bin/env python3
"""Exercise real stage-to-live promotion with the compiled CLI and pinned core.

Every fixture and report is kept below this checkout.  No proxy core is started,
no Android device is used, and no subscription or Tailscale account is contacted.
The legacy case deliberately serializes the previous absolute managed-path form
into a consistent active configuration, checkpoint, settings and LKG; it does not
execute or copy a historical product implementation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "module/test-artifacts"
CONFIG = ".config/sing-box/config.json"
CHECKPOINT = ".state/private/runtime-checkpoint.json"
SETTINGS = ".config/magicnet/runtime-settings.json"
LKG = ".state/lifecycle/last-known-good.json"
PRIVATE_LKG = ".state/private/last-known-good.json"
JOURNAL = ".state/private/runtime-path-relocation.json"
INTENT = ".config/magicnet/service-intent"
TAILSCALE = ".state/private/tailscale"
CORE_CACHE = ".state/private/core-cache.db"
PERSISTED_JSON = (CONFIG, CHECKPOINT, SETTINGS, LKG)
RELOCATION_FILES = (CONFIG, LKG, PRIVATE_LKG, CHECKPOINT, SETTINGS)
IDENTITY_BYTES = b"synthetic-promotion-tailnet-identity\x00retain-exactly\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def read_json(path: Path):
    return json.loads(path.read_bytes())


def put(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def put_json(path: Path, value) -> None:
    put(path, encoded(value))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def map_values(value, transform):
    if isinstance(value, dict):
        return {key: map_values(item, transform) for key, item in value.items()}
    if isinstance(value, list):
        return [map_values(item, transform) for item in value]
    return transform(value) if isinstance(value, str) else value


def stale_strings(value, prefix: str) -> list[str]:
    found = []

    def inspect(item):
        if item == prefix or item.startswith(prefix + "/"):
            found.append(item)
        return item

    map_values(value, inspect)
    return found


def module_path(root: Path, value: str) -> Path:
    return Path(value) if Path(value).is_absolute() else root / value


class Harness:
    def __init__(self, cli: Path, core: Path):
        self.cli, self.core = cli, core
        self.cases = []
        self.current = None

    def run(self, root: Path, args: list[str], *, expected=0, core=False):
        executable = root / "bin/sing-box" if core else root / "bin/magicnet-cli"
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("MAGICNET_") and key not in ("MODDIR", "MAGIC_DNS_LEAK_GUARD")}
        env.update(MAGICNET_ROOT=str(root), MAGICNET_API="http://127.0.0.1:9")
        started = time.monotonic()
        result = subprocess.run([str(executable), *args], cwd=root, env=env,
                                capture_output=True, text=True, timeout=90)
        self.current["steps"].append({
            "program": "pinned-core" if core else "compiled-cli",
            "location": "staging" if "modules_update" in root.parts else "live",
            "args": [item.replace(str(root), "$MODULE_ROOT") for item in args],
            "exit_code": result.returncode,
            "stdout": result.stdout.strip()[:8192].replace(str(root), "$MODULE_ROOT"),
            "stderr": result.stderr.strip()[:8192].replace(str(root), "$MODULE_ROOT"),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        })
        if expected is not None:
            require(result.returncode == expected,
                    f"{'core' if core else 'cli'} {args[0]} returned {result.returncode}: {result.stderr.strip()}")
        return result

    def status_stopped(self, root: Path):
        response = self.run(root, ["--json", "service", "status"])
        envelope = json.loads(response.stdout)
        require(envelope.get("schema") == 1 and envelope.get("ok") is True,
                "Service status is not a successful schema-1 envelope")
        value = envelope["data"]
        require(value["configured"]["enabled"] is False, "Stopped service intent changed")
        require(value["process"]["running"] is False, "A proxy core unexpectedly started")
        require(value["process"]["ownership"] == "none", "Unexpected core process ownership")
        require((root / INTENT).read_bytes() == b"stopped\n", "Persisted stopped intent changed")
        return value

    def fixture(self, base: Path):
        stage, live = base / "modules_update/MagicNet", base / "modules/MagicNet"
        (stage / "bin").mkdir(mode=0o700, parents=True)
        live.parent.mkdir(mode=0o700, parents=True)
        shutil.copy2(self.cli, stage / "bin/magicnet-cli")
        (stage / "bin/sing-box").symlink_to(self.core)
        shutil.copytree(ROOT / "assets/rules", stage / ".config/sing-box/rules")
        shutil.copy2(ROOT / "module/module.prop", stage / "module.prop")
        self.run(stage, ["__install"])
        self.run(stage, ["service", "stop"])
        self.status_stopped(stage)
        return stage, live

    def configure(self, base: Path, stage: Path, custom: bool):
        config = read_json(stage / CONFIG)
        endpoint = {"type": "tailscale", "tag": "promotion-tailnet", "system_interface": False,
                    "hostname": "synthetic-promotion-fixture", "accept_routes": False}
        preservation = {}
        if custom:
            external = base / "user-controlled"
            custom_rules = external / "rules.json"
            custom_cache = external / "cache.db"
            custom_tailnet = external / "tailnet"
            put_json(custom_rules, {"version": 3, "rules": [{"domain_suffix": ["fixture.invalid"]}]})
            put(custom_cache, b"synthetic-custom-cache-canary\n")
            config["route"]["rule_set"].append({"type": "local", "tag": "promotion-user-rule",
                                                  "format": "source", "path": str(custom_rules)})
            config["route"]["rules"].insert(0, {"rule_set": ["promotion-user-rule"], "outbound": "direct"})
            config["experimental"]["cache_file"]["path"] = str(custom_cache)
            endpoint["state_directory"] = str(custom_tailnet)
            custom_tailnet.mkdir(mode=0o700)
            preservation = {"rule_path": str(custom_rules), "cache_path": str(custom_cache),
                            "tailscale_path": str(custom_tailnet),
                            "rule_sha256": digest(custom_rules.read_bytes()),
                            "cache_sha256": digest(custom_cache.read_bytes())}
        config["endpoints"] = [endpoint]
        payload = stage / ".state/private/payload/tmp/promotion-config.json"
        put_json(payload, config)
        self.run(stage, ["config-editor", "save-file", "sing-box", str(payload)])
        payload.unlink(missing_ok=True)
        settings = read_json(stage / SETTINGS)
        tunnel = settings["tailscale"]
        require(tunnel["enabled"] is True, "Synthetic Tailscale endpoint was not persisted")
        require(tunnel.get("owned_directory", False) is not custom, "Incorrect Tailscale directory ownership")
        state_dir = module_path(stage, tunnel["endpoint"]["state_directory"])
        identity = state_dir / "tailscaled.state"
        put(identity, IDENTITY_BYTES)
        if not custom:
            require((state_dir / ".magicnet-owned").read_bytes().strip() == b"MagicNet",
                    "Managed Tailscale state has no valid ownership marker")
        preservation.update({"identity_sha256": digest(IDENTITY_BYTES),
                             "tailscale_revision": tunnel["revision"],
                             "tailscale_enabled": tunnel["enabled"], "custom": custom})
        self.status_stopped(stage)
        return preservation

    def legacy_absolute_form(self, stage: Path):
        """Produce only the documented old persisted paths, with consistent evidence."""
        def to_absolute(value):
            if (value in (CORE_CACHE, TAILSCALE)
                    or value.startswith(".config/sing-box/rules/")):
                return str(stage / value)
            return value

        for name in (*PERSISTED_JSON, PRIVATE_LKG):
            path = stage / name
            if name == PRIVATE_LKG and not path.exists():
                continue
            require(path.is_file(), f"Missing initialization evidence: {name}")
            put_json(path, map_values(read_json(path), to_absolute))
        checkpoint = read_json(stage / CHECKPOINT)
        checkpoint["fingerprint"] = digest((stage / CONFIG).read_bytes())
        put_json(stage / CHECKPOINT, checkpoint)
        config = read_json(stage / CONFIG)
        manifest = read_json(stage / ".config/sing-box/rules/manifest.json")
        by_tag = {rule["tag"]: rule for rule in config["route"]["rule_set"]}
        require(all(by_tag[rule["tag"]]["path"] == str(stage / ".config/sing-box/rules" / rule["path"])
                    for rule in manifest["files"]), "Legacy fixture does not contain all 55 absolute rule paths")
        require(config["experimental"]["cache_file"]["path"] == str(stage / CORE_CACHE),
                "Legacy fixture has no absolute owned cache path")
        require(read_json(stage / SETTINGS)["tailscale"]["endpoint"]["state_directory"] == str(stage / TAILSCALE),
                "Legacy fixture has no absolute owned Tailscale path")
        self.run(stage, ["check", "-c", str(stage / CONFIG)], core=True)
        self.current["legacy_fixture"] = {"method": "consistent synthetic absolute managed fields",
                                          "checkpoint_matches_active": True, "rule_count": len(manifest["files"])}

    def verify_preserved(self, live: Path, old_stage: Path, preservation):
        config, settings = read_json(live / CONFIG), read_json(live / SETTINGS)
        for name in (*PERSISTED_JSON, PRIVATE_LKG):
            if name == PRIVATE_LKG and not (live / name).exists():
                continue
            require(not stale_strings(read_json(live / name), str(old_stage)),
                    f"Staging-root reference remains in {name}")
        checkpoint = read_json(live / CHECKPOINT)
        require(checkpoint["fingerprint"] == digest((live / CONFIG).read_bytes()),
                "Checkpoint fingerprint differs from the effective configuration")
        tunnel = settings["tailscale"]
        require(tunnel["revision"] == preservation["tailscale_revision"], "Promotion changed Tailscale revision")
        require(tunnel["enabled"] == preservation["tailscale_enabled"], "Promotion changed Tailscale intent")
        state_dir = module_path(live, tunnel["endpoint"]["state_directory"])
        identity = state_dir / "tailscaled.state"
        require(identity.read_bytes() == IDENTITY_BYTES, "Tailscale identity bytes changed or disappeared")
        require(stat.S_IMODE(identity.stat().st_mode) == 0o600, "Tailscale identity permissions changed")
        manifest = read_json(live / ".config/sing-box/rules/manifest.json")
        by_tag = {rule["tag"]: rule for rule in config["route"]["rule_set"]}
        require(len(manifest["files"]) == 55, "Expected the pinned 55-rule inventory")
        for entry in manifest["files"]:
            rule = by_tag[entry["tag"]]
            expected = ".config/sing-box/rules/" + entry["path"]
            require(rule["path"] == expected, f"Managed rule is not module-relative: {entry['tag']}")
            require(digest((live / expected).read_bytes()) == entry["sha256"], "A pinned rule changed")
        if preservation["custom"]:
            require(by_tag["promotion-user-rule"]["path"] == preservation["rule_path"],
                    "Custom rule path was rewritten")
            require(config["experimental"]["cache_file"]["path"] == preservation["cache_path"],
                    "Custom cache path was rewritten")
            require(tunnel["endpoint"]["state_directory"] == preservation["tailscale_path"],
                    "Custom Tailscale path was rewritten")
            require(not tunnel.get("owned_directory", False), "Custom directory was incorrectly claimed")
            require(digest(Path(preservation["rule_path"]).read_bytes()) == preservation["rule_sha256"],
                    "Custom rule bytes changed")
            require(digest(Path(preservation["cache_path"]).read_bytes()) == preservation["cache_sha256"],
                    "Custom cache bytes changed")
        else:
            require(config["experimental"]["cache_file"]["path"] == CORE_CACHE,
                    "Managed cache path is not module-relative")
            require(tunnel["endpoint"]["state_directory"] == TAILSCALE,
                    "Managed Tailscale path is not module-relative")
            require(tunnel.get("owned_directory") is True, "Managed Tailscale ownership was lost")
            require((state_dir / ".magicnet-owned").read_bytes().strip() == b"MagicNet",
                    "Managed Tailscale ownership marker changed")
        self.status_stopped(live)
        return {"rule_count": 55, "staging_references": 0, "identity_sha256": digest(identity.read_bytes()),
                "custom_paths_preserved": preservation["custom"], "core_running": False,
                "configured_enabled": False, "checkpoint_matches_active": True}

    def one_case(self, name: str, *, legacy=False, custom=False):
        self.current = {"case": name, "steps": [], "status": "RUNNING"}
        self.cases.append(self.current)
        base = None
        try:
            with tempfile.TemporaryDirectory(prefix="promotion-", dir=REPORTS) as temporary:
                base = Path(temporary)
                self.current["fixture_directory"] = str(base.relative_to(ROOT))
                stage, live = self.fixture(base)
                preservation = self.configure(base, stage, custom)
                if legacy:
                    self.legacy_absolute_form(stage)
                before_identity = preservation["identity_sha256"]
                stage.rename(live)
                require(not stage.exists() and live.is_dir(), "The fixture was not actually renamed")
                if legacy:
                    missing = self.run(live, ["check", "-c", str(live / CONFIG)], expected=None, core=True)
                    require(missing.returncode != 0, "Legacy absolute fixture did not expose the removed staging root")
                else:
                    self.run(live, ["check", "-c", str(live / CONFIG)], core=True)
                self.run(live, ["__install"])
                self.run(live, ["check", "-c", str(live / CONFIG)], core=True)
                self.run(live, ["config-editor", "validate", "sing-box"])
                self.run(live, ["config", "apply"])
                self.current["assertions"] = self.verify_preserved(live, stage, preservation)
                before = {name: digest((live / name).read_bytes()) for name in PERSISTED_JSON}
                self.run(live, ["__install"])
                self.run(live, ["config", "apply"])
                after = {name: digest((live / name).read_bytes()) for name in PERSISTED_JSON}
                require(before == after, "Repeated activation changed already-relocated persisted state")
                self.verify_preserved(live, stage, preservation)
                self.current["assertions"].update({"actual_directory_rename": True,
                                                    "idempotent_persisted_bytes": True,
                                                    "identity_before_sha256": before_identity})
                self.current["status"] = "PASS"
        except (AssertionError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            self.current["status"] = "FAIL"
            self.current["error"] = str(error)
        finally:
            if base is not None:
                self.current["temporary_directory_removed"] = not base.exists()

    def recovery_case(self, phase: str, published_count: int, *, conflict=False):
        label = f"{phase} relocation journal after {published_count}/5 publications"
        if conflict:
            label += ": external change refuses all writes, evidence retained, then explicit resolution"
        self.current = {"case": label, "steps": [], "status": "RUNNING"}
        self.cases.append(self.current)
        base = None
        try:
            with tempfile.TemporaryDirectory(prefix="promotion-recovery-", dir=REPORTS) as temporary:
                base = Path(temporary)
                self.current["fixture_directory"] = str(base.relative_to(ROOT))
                stage, live = self.fixture(base)
                preservation = self.configure(base, stage, False)
                # The second LKG is an older supported recovery location.  Seed
                # it with the actual current validated bytes, not a guessed core
                # configuration, so all five publication boundaries are covered.
                put(stage / PRIVATE_LKG, (stage / LKG).read_bytes())
                after = {path: (stage / path).read_bytes() for path in RELOCATION_FILES}
                require(not any(stale_strings(json.loads(data), str(stage)) for data in after.values()),
                        "Recovery fixture requires the rebuilt module-relative defaults")
                self.legacy_absolute_form(stage)
                before = {path: (stage / path).read_bytes() for path in RELOCATION_FILES}
                require(all(before[path] != after[path] for path in RELOCATION_FILES),
                        "Each relocation file must have a real before/after difference")
                stage.rename(live)
                for path in RELOCATION_FILES[:published_count]:
                    put(live / path, after[path])
                journal = {"schema": 1, "phase": phase, "files": [
                    {"path": path, "before": base64.b64encode(before[path]).decode(),
                     "after": base64.b64encode(after[path]).decode()} for path in RELOCATION_FILES
                ]}
                put_json(live / JOURNAL, journal)
                self.current["interruption_fixture"] = {
                    "method": "durable production-schema journal plus before/after file publication prefix",
                    "phase": phase, "published_files": published_count, "file_count": 5,
                    "process_killed": False,
                }
                if conflict:
                    externally_changed = read_json(live / CONFIG)
                    externally_changed["log"]["level"] = "info"
                    put_json(live / CONFIG, externally_changed)
                    snapshot = {path: (live / path).read_bytes() for path in (*RELOCATION_FILES, JOURNAL)}
                    denied = self.run(live, ["__install"], expected=None)
                    require(denied.returncode != 0 and "runtime.paths_conflict" in denied.stderr,
                            "An external change did not block relocation")
                    require(all((live / path).read_bytes() == data for path, data in snapshot.items()),
                            "Conflicted relocation changed a managed file or its journal")
                    self.status_stopped(live)
                    # Resolve only this synthetic test's deliberate external edit.
                    # The production command itself must never overwrite it.
                    put(live / CONFIG, after[CONFIG] if published_count else before[CONFIG])
                    self.current["conflict"] = {"rejected_without_publication": True,
                                                  "recovery_evidence_retained": True,
                                                  "explicit_fixture_resolution": True}
                self.run(live, ["__install"])
                require(not (live / JOURNAL).exists(), "Successful recovery left its relocation journal")
                self.run(live, ["check", "-c", str(live / CONFIG)], core=True)
                self.run(live, ["config", "apply"])
                self.current["assertions"] = self.verify_preserved(live, stage, preservation)
                settled = {path: (live / path).read_bytes() for path in RELOCATION_FILES}
                self.run(live, ["__install"])
                require(all((live / path).read_bytes() == data for path, data in settled.items()),
                        "Repeated recovery changed settled state")
                self.current["assertions"].update({"actual_directory_rename": True,
                                                    "recovery_journal_removed": True,
                                                    "idempotent_persisted_bytes": True})
                if phase == "rollback":
                    self.current["assertions"]["scope"] = (
                        "Compiled install recovers rollback evidence and then replans valid relative paths; "
                        "proving the isolated rollback direction requires the controller's separate Go test."
                    )
                self.current["status"] = "PASS"
        except (AssertionError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            self.current["status"] = "FAIL"
            self.current["error"] = str(error)
        finally:
            if base is not None:
                self.current["temporary_directory_removed"] = not base.exists()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="module/test-artifacts/promotion-verification.json")
    args = parser.parse_args()
    report_path = (ROOT / args.report).resolve()
    require(report_path.is_relative_to(ROOT), "Report must remain inside this checkout")
    REPORTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    cli, core = ROOT / "assets/bin/linux-amd64/magicnet-cli", ROOT / "assets/bin/linux-amd64/sing-box"
    require(cli.is_file() and core.is_file(), "Build the host CLI and pinned core before running this test")
    start = time.monotonic()
    version = subprocess.run([str(cli), "version"], env={**os.environ, "MAGICNET_ROOT": str(ROOT)},
                             capture_output=True, text=True, timeout=10)
    require(version.returncode == 0, "Compiled CLI version could not be read")
    harness = Harness(cli, core)
    harness.one_case("fresh module-relative defaults and owned Tailscale survive real promotion")
    harness.one_case("persisted absolute owned paths and checkpoint/LKG recover after promotion", legacy=True)
    harness.one_case("custom external rules/cache/Tailscale paths and bytes survive promotion", custom=True)
    for published in range(6):
        harness.recovery_case("prepared", published)
    harness.recovery_case("committed", 5)
    harness.recovery_case("rollback", 2)
    harness.recovery_case("prepared", 2, conflict=True)
    passed = sum(case["status"] == "PASS" for case in harness.cases)
    report = {"schema": 1, "test": "compiled stage-to-live promotion", "status": "PASS" if passed == len(harness.cases) else "FAIL",
              "compiled_cli_version": json.loads(version.stdout), "cli_sha256": digest(cli.read_bytes()),
              "core_sha256": digest(core.read_bytes()), "input_sha256": "502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a",
              "external_network_used": False, "device_used": False, "core_started": False,
              "actual_manager_used": False, "fixture": "synthetic isolated host directories, actual rename",
              "passed": passed, "failed": len(harness.cases) - passed, "cases": harness.cases,
              "not_run": ["actual Android root-manager promotion/reboot", "Tailscale authentication/data-plane traffic"],
              "elapsed_seconds": round(time.monotonic() - start, 3)}
    put_json(report_path, report)
    print(json.dumps({"report": str(report_path), "status": report["status"], "passed": passed, "failed": report["failed"]}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
