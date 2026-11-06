#!/usr/bin/env python3
"""Compare public installer outcomes on identical, disposable offline fixtures.

Build both revisions' installer/components binaries, then pass their paths here.
Only the human-readable elapsed duration is normalized; exit status, every other
output byte, file contents, permissions, directories and symlinks must match.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive(entries: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, data)
    return out.getvalue()


def write(root: Path, name: str, data: bytes) -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def snapshot(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        value = os.readlink(path) if stat.S_ISLNK(mode) else (
            digest(path.read_bytes()) if stat.S_ISREG(mode) else "directory")
        result[str(path.relative_to(root))] = [stat.S_IMODE(mode), value]
    return result


def fixture(root: Path, case: str) -> tuple[list[str], int, int]:
    payload = {"bin/sing-box": b"synthetic-engine\n", "webroot/index.html": b"synthetic-ui\n"}
    components, component_zips = [], {}
    for index, (name, data) in enumerate(payload.items()):
        raw = archive({name: data})
        checksum = digest(raw)
        component_zips[checksum] = raw
        components.append({"id": f"part-{index}", "sha256": checksum, "size": len(raw),
            "asset": f"MagicNet-component-part-{index}-{checksum}.zip", "files": [
                {"path": name, "sha256": digest(data), "size": len(data), "mode": 0o755 if index == 0 else 0o644}]})
    manifest = {"schema": 1, "module": "MagicNet", "version": "v1.8.5",
                "architecture": {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine()),
                "repository": "LIghtJUNction/magicnet-android", "components": components}
    bundled = dict(payload)
    expected, repeat = 0, 1
    root.mkdir()
    write(root, "module/.config/user.txt", b"keep user intent\n")
    if case in {"current-reuse", "previous-reuse", "cache", "corrupt-local", "missing", "bad-cache"}:
        bundled = {}
    if case in {"current-reuse", "previous-reuse"}:
        prefix = "module" if case == "current-reuse" else "previous"
        for name, data in payload.items():
            write(root, f"{prefix}/{name}", data)
    if case in {"cache", "corrupt-local", "bad-cache"}:
        for checksum, raw in component_zips.items():
            write(root, f"cache/{checksum}.zip", b"corrupt" if case == "bad-cache" else raw)
        if case == "corrupt-local":
            write(root, "module/bin/sing-box", b"old-corrupt-engine")
    if case == "obsolete":
        old = copy.deepcopy(manifest)
        old["components"][0]["files"][0]["path"] = "bin/obsolete"
        write(root, "module/components.installed.json", json.dumps(old).encode())
        write(root, "module/bin/obsolete", b"old binary")
    if case == "missing":
        bundled["bin/sing-box"] = payload["bin/sing-box"]
        write(root, "module/bin/sing-box", b"old working engine")
    if case == "corrupt-bundled":
        bundled["bin/sing-box"] = b"X" * len(payload["bin/sing-box"])
    if case == "wrong-architecture":
        manifest["architecture"] = "unsupported"
    if case == "traversal":
        components[0]["files"][0]["path"] = "../outside"
    if case == "parent-collision":
        components[1]["files"][0]["path"] = "bin/sing-box/child"
    if case == "destination-symlink":
        write(root, "outside/untouched", b"must survive")
        (root / "module/bin").symlink_to("../outside", target_is_directory=True)
    if case == "unknown-workspace":
        write(root, "module/.components-install/foreign.txt", b"unknown owner")
    if case == "recover-promotion":
        write(root, "module/.components-install/.magicnet-components-v1", b"")
        write(root, "module/.components-install/.rollback/bin/sing-box", b"old engine")
        write(root, "module/.components-install/.promotion.json", json.dumps({"schema": 1,
            "changes": [{"path": "bin/sing-box", "existed": True, "install": True}]}).encode())
        write(root, "module/bin/sing-box", b"interrupted replacement")
    if case == "permissions":
        for index, mode in enumerate((0o600, 0o700, 0o644, 0o755)):
            data = bytes([index])
            name = f"webroot/mode-{mode:o}"
            bundled[name] = data
            components[1]["files"].append({"path": name, "sha256": digest(data), "size": 1, "mode": mode})
    if case == "repeat-install":
        repeat = 2
    if case in {"missing", "bad-cache", "corrupt-bundled", "wrong-architecture", "traversal",
                "parent-collision", "destination-symlink", "unknown-workspace"}:
        expected = 1
    bundled["components.json"] = json.dumps(manifest, separators=(",", ":")).encode()
    write(root, "source.zip", archive(bundled))
    args = ["--archive", str(root / "source.zip"), "--module-dir", str(root / "module"),
            "--previous-dir", str(root / "previous"), "--cache-dir", str(root / "cache"), "--offline"]
    if case == "missing-arguments":
        args, expected = [], 1
    elif case == "help":
        args = ["--help"]
    return args, expected, repeat


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    opts = parser.parse_args()
    binaries = [path.resolve() for path in (opts.baseline, opts.candidate)]
    cases = ["full", "current-reuse", "previous-reuse", "cache", "corrupt-local", "obsolete",
             "missing", "bad-cache", "corrupt-bundled", "wrong-architecture", "traversal",
             "parent-collision", "destination-symlink", "unknown-workspace", "recover-promotion",
             "permissions", "repeat-install", "missing-arguments", "help"]
    with tempfile.TemporaryDirectory(prefix="magicnet-installer-parity-") as temp:
        directory = Path(temp)
        root, executable = directory / "fixture", directory / "magicnet-components"
        for case in cases:
            observations = []
            for binary in binaries:
                if root.exists():
                    shutil.rmtree(root)
                executable.unlink(missing_ok=True)
                executable.symlink_to(binary)
                args, expected, repeat = fixture(root, case)
                commands = []
                for _ in range(repeat):
                    result = subprocess.run([str(executable), *args], capture_output=True, timeout=30)
                    assert result.returncode == expected, (case, binary, result.stderr.decode())
                    stdout = re.sub(rb"(\[done\] MagicNet .* ready: \d+ components in )\d+\.\d+s", rb"\1<elapsed>s", result.stdout)
                    commands.append((result.returncode, stdout, result.stderr))
                observations.append((commands, snapshot(root)))
            assert observations[0] == observations[1], f"installer behavior differs: {case}"
    print(json.dumps({"scenarios": len(cases), "mismatches": 0,
                      "comparisons": ["exit", "stdout", "stderr", "file bytes", "permissions", "directories", "symlinks"],
                      "normalization": "human-readable [done] elapsed duration only"}, indent=2))


if __name__ == "__main__":
    main()
