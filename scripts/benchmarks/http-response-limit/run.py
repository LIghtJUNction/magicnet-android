#!/usr/bin/env python3
"""Prepare isolated source snapshots and run the HTTP response-limit benchmark."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile

SOURCE = "crates/magicnet-cli/src/local_http.rs"
BODY_BYTES = 8 * 1024 * 1024
CALLER_LIMIT = 1024 * 1024
SCOPE = "loopback_API_response_limit_not_RSS_or_network_throughput"
CASES = ("content_length", "close_delimited")
METRICS = (
    "peak_live_heap_bytes",
    "client_socket_read_bytes",
    "client_read_calls",
    "total_requested_heap_bytes",
    "allocation_calls",
    "live_heap_bytes_at_return",
    "elapsed_us",
    "server_write_accepted_body_bytes",
)
READ_BOUNDARY = (
    "\n        if count == 0 {\n"
    "            let length = framing.ok_or"
)
READ_COUNTER = (
    "\n        crate::record_response_read(count);"
    "\n        if count == 0 {\n"
    "            let length = framing.ok_or"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_checked(
    command: list[str], cwd: Path, *, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, check=False, timeout=timeout
    )
    if result.returncode:
        diagnostic = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"{Path(command[0]).name} exited {result.returncode}: {diagnostic}"
        )
    return result


def git(repo: Path, *args: str) -> bytes:
    return run_checked(["git", *args], repo).stdout


def instrument(original: bytes, variant: str) -> bytes:
    text = original.decode("utf-8")
    if len(original) > 1024 * 1024:
        raise ValueError(f"{variant}: source snapshot exceeds 1 MiB")
    signature = re.search(
        r"pub\(crate\) fn request_with_timeout\((.*?)\)\s*->",
        text,
        re.DOTALL,
    )
    if signature is None:
        raise ValueError(f"{variant}: unsupported native HTTP entry point")
    has_limit = re.search(r"\blimit\s*:\s*usize\b", signature.group(1)) is not None
    if has_limit != (variant == "after"):
        raise ValueError(
            f"{variant}: wrong response-limit API; the baseline must precede "
            "the caller-limit parameter and the working tree must include it"
        )
    if text.count(READ_BOUNDARY) != 1 or "crate::record_response_read" in text:
        raise ValueError(f"{variant}: missing, ambiguous, or already instrumented read boundary")
    return text.replace(READ_BOUNDARY, READ_COUNTER, 1).encode("utf-8")


def validate_samples(raw: bytes, variant: str, iterations: int) -> list[dict]:
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    if len(rows) != len(CASES) * iterations:
        raise ValueError(f"{variant}: incomplete sample count")
    for case in CASES:
        selected = [row for row in rows if row.get("case") == case]
        if sorted(row.get("iteration", -1) for row in selected) != list(range(1, iterations + 1)):
            raise ValueError(f"{variant}/{case}: missing or repeated samples")
        header_bytes = 63 if case == "content_length" else 38
        for row in selected:
            expected = {
                "schema": 1,
                "variant": variant,
                "scope": SCOPE,
                "response_body_offered_bytes": BODY_BYTES,
                "caller_limit_bytes": CALLER_LIMIT,
                "outcome": "caller_limit_rejected",
            }
            if any(row.get(key) != value for key, value in expected.items()):
                raise ValueError(f"{variant}/{case}: unexpected benchmark scope or outcome")
            if any(type(row.get(key)) is not int or row[key] < 0 for key in METRICS):
                raise ValueError(f"{variant}/{case}: invalid measurement")
            if (
                row["client_read_calls"] == 0
                or row["client_socket_read_bytes"] == 0
                or row["allocation_calls"] == 0
                or row["live_heap_bytes_at_return"] > row["peak_live_heap_bytes"]
                or row["peak_live_heap_bytes"] > row["total_requested_heap_bytes"]
                or row["server_write_accepted_body_bytes"] > BODY_BYTES
                or type(row.get("server_completed_body")) is not bool
                or row["server_completed_body"]
                != (row["server_write_accepted_body_bytes"] == BODY_BYTES)
            ):
                raise ValueError(f"{variant}/{case}: inconsistent measurement")
            # These are fixture invariants, not performance thresholds.
            if variant == "before":
                if row["client_socket_read_bytes"] != BODY_BYTES + header_bytes:
                    raise ValueError("baseline did not consume the offered response")
            elif case == "close_delimited":
                if row["client_socket_read_bytes"] != CALLER_LIMIT + 1 + header_bytes:
                    raise ValueError("candidate did not stop at the overflow byte")
            # Header fragments can precede a final read that also contains body bytes.
            elif row["client_socket_read_bytes"] > header_bytes + 8192:
                raise ValueError("candidate continued reading after the oversized header")
    return rows


def summarize(results: dict[str, list[dict]]) -> dict:
    groups = []
    for variant in ("before", "after"):
        for case in CASES:
            selected = [row for row in results[variant] if row["case"] == case]
            groups.append({
                "variant": variant,
                "case": case,
                "samples": len(selected),
                "metrics": {
                    key: {
                        "median": statistics.median(row[key] for row in selected),
                        "min": min(row[key] for row in selected),
                        "max": max(row[key] for row in selected),
                    }
                    for key in METRICS
                },
            })
    return {"schema": 1, "scope": SCOPE, "groups": groups}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="local Git commit before caller-limit support")
    parser.add_argument("--output", required=True, type=Path, help="new directory for JSON evidence only")
    parser.add_argument("--iterations", type=int, default=7)
    parser.add_argument("--order", choices=("before-first", "after-first"), default="before-first")
    parser.add_argument("--rustc", default="rustc", help="Rust compiler executable")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100:
        parser.error("--iterations must be in 1..=100")

    bundle = Path(__file__).resolve().parent
    repo = bundle.parents[2]
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error("--output already exists; choose a new directory to preserve prior results")
    baseline = git(repo, "rev-parse", "--verify", "--end-of-options", f"{args.baseline}^{{commit}}")
    baseline = baseline.decode("ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", baseline) is None:
        raise ValueError("Git returned an invalid baseline commit")
    head = git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    sources = {
        "before": git(repo, "show", f"{baseline}:{SOURCE}"),
        "after": (repo / SOURCE).read_bytes(),
    }
    candidate_matches_head = sources["after"] == git(repo, "show", f"{head}:{SOURCE}")
    harness = (bundle / "benchmark.rs").read_bytes()
    order = ("before", "after") if args.order == "before-first" else ("after", "before")
    started_at = datetime.now(timezone.utc).isoformat()
    raw_results: dict[str, bytes] = {}
    results: dict[str, list[dict]] = {}
    snapshots = {}
    build_warnings = {}

    with tempfile.TemporaryDirectory(prefix="magicnet-http-limit-") as directory:
        work = Path(directory)
        (work / "benchmark.rs").write_bytes(harness)
        for variant, original in sources.items():
            instrumented = instrument(original, variant)
            name = f"local_http-{variant}.instrumented.rs"
            (work / name).write_bytes(instrumented)
            snapshots[variant] = {
                "source_sha256": sha256(original),
                "source_bytes": len(original),
                "instrumented_sha256": sha256(instrumented),
                "instrumentation": "one response-read counter call before the EOF branch",
            }
        compiler = run_checked([args.rustc, "--version", "--verbose"], work)
        for variant in ("before", "after"):
            executable = f"http-limit-{variant}"
            if platform.system() == "Windows":
                executable += ".exe"
            command = [args.rustc, "--edition=2024", "-C", "opt-level=3"]
            if variant == "after":
                command += ["--cfg", "magicnet_candidate"]
            command += ["benchmark.rs", "-o", executable]
            completed = run_checked(command, work)
            build_warnings[variant] = completed.stderr.decode("utf-8", errors="replace").replace(
                str(work), "<temporary-workdir>"
            )
        for variant in order:
            executable = work / f"http-limit-{variant}"
            if platform.system() == "Windows":
                executable = executable.with_suffix(".exe")
            completed = run_checked([str(executable), str(args.iterations)], work)
            raw_results[variant] = completed.stdout
            results[variant] = validate_samples(completed.stdout, variant, args.iterations)

    summary = summarize(results)
    manifest = {
        "schema": 1,
        "scope": SCOPE,
        "started_at_utc": started_at,
        "baseline_commit": baseline,
        "candidate_head_commit": head,
        "candidate_source_matches_head": candidate_matches_head,
        "source_path": SOURCE,
        "source_snapshots": snapshots,
        "harness_sha256": sha256(harness),
        "runner_sha256": sha256(Path(__file__).read_bytes()),
        "compiler": compiler.stdout.decode("utf-8").strip(),
        "compile_flags": ["--edition=2024", "-C", "opt-level=3"],
        "candidate_cfg": "magicnet_candidate",
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        },
        "iterations_per_case": args.iterations,
        "warmups_per_case": 1,
        "variant_order": list(order),
        "response_body_bytes": BODY_BYTES,
        "caller_limit_bytes": CALLER_LIMIT,
        "build_warnings": build_warnings,
        "result_sha256": {variant: sha256(raw_results[variant]) for variant in ("before", "after")},
        "not_measured": [
            "process_RSS", "process_PSS", "Go_heap", "Android_runtime_memory",
            "valid_download_throughput", "Internet_speed", "routing", "battery",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    for variant in ("before", "after"):
        (output / f"{variant}.jsonl").write_bytes(raw_results[variant])
    for name, value in (("manifest.json", manifest), ("summary.json", summary)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"HTTP limit benchmark failed: {error}") from None
