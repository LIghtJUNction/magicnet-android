#!/usr/bin/env python3
"""Compare component artifacts and isolated peak RSS with an original packager."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile


def worker(packager, source, helper, output):
    spec = importlib.util.spec_from_file_location("packager", packager)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    started = time.perf_counter()
    module.split(Path(source), Path(helper), Path(output), "LIghtJUNction/MagicNet", "amd64")
    duration = time.perf_counter() - started
    hashes = {}
    for path in sorted(Path(output).iterdir()):
        with path.open("rb") as stream:
            hashes[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"seconds": duration, "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, "artifacts": hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--worker", nargs=3, metavar=("SOURCE", "HELPER", "OUTPUT"))
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.baseline, *args.worker)))
        return
    if not 1 <= args.runs <= 10:
        parser.error("--runs must be between 1 and 10")
    candidate = Path(__file__).with_name("package-components.py")
    with tempfile.TemporaryDirectory(prefix="magicnet-package-parity-") as temporary:
        root = Path(temporary)
        source, helper = root / "source.zip", root / "helper"
        helper.write_bytes(b"synthetic bootstrap; never executed\n")
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in {
                "module.prop": b"id=MagicNet\nversion=v1.8.5\nversionCode=10613\n",
                "customize.sh": b"#!/system/bin/sh\nimport rich\n",
                ".config/sing-box/config.json": b"{}\n",
                "webroot/index.html": b"<html>synthetic panel</html>",
                ".config/sing-box/rules/example.srs": b"synthetic rule",
                ".cache/private.json": b"synthetic cache must be removed",
            }.items():
                archive.writestr(name, value)
            # Three 16 MiB entries exercise streaming, including a dereferenced
            # CLI alias. Generate without retaining a full payload in this host.
            block = bytes(range(256)) * 4096
            for name in ("bin/sing-box", "bin/magicnet-cli", "cli"):
                with archive.open(name, "w") as output:
                    for _ in range(16):
                        output.write(block)
        results = {"baseline": [], "candidate": []}
        reference = None
        for run in range(args.runs):
            # Alternate order to reduce systematic warm-cache bias.
            order = [("baseline", args.baseline), ("candidate", candidate)]
            if run % 2:
                order.reverse()
            for name, script in order:
                output = root / f"{name}-{run}"
                command = [sys.executable, str(Path(__file__).resolve()), str(script.resolve()),
                           "--worker", str(source), str(helper), str(output)]
                completed = subprocess.run(command, text=True, capture_output=True, timeout=120, check=True)
                result = json.loads(completed.stdout)
                if reference is None:
                    reference = result["artifacts"]
                if result["artifacts"] != reference:
                    different = sorted(name for name in set(reference) | set(result["artifacts"])
                                       if reference.get(name) != result["artifacts"].get(name))
                    raise AssertionError(f"Artifact bytes differ: {different}")
                results[name].append({key: value for key, value in result.items() if key != "artifacts"})
        summary = {name: {"median_seconds": statistics.median(row["seconds"] for row in rows),
                          "median_max_rss_kib": statistics.median(row["max_rss_kib"] for row in rows)}
                   for name, rows in results.items()}
        print(json.dumps({"payload_mib": 48, "runs_per_version": args.runs,
                          "identical_artifacts": len(reference), "mismatches": 0,
                          "measurement": summary, "runs": results}, indent=2))


if __name__ == "__main__":
    main()
