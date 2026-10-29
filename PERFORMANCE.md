# Performance observations

These are builder measurements of the frozen Linux amd64 controller in a temporary stopped-module fixture. They are not Android startup, active data-plane, throughput, or stability results. No comparison with the previous MagicNet implementation was made.

## Method

- Host: Linux x86_64, kernel 6.18.55; cgroup memory limit 8 GiB, CPU quota 8.
- Artifact SHA-256: `e8c39d918366bed0e21e08132077abfac14fae536adb0eb5e3af7cc4691c83ab`.
- Core SHA-256: `4a3b5a35871a723cf9111727c5f5bd3c5523d5779b4d03ad6af9727a53fae451`.
- Configuration SHA-256 for this run: `ce1f633ba4f7e2d0ae95d504f8f7279d4c281cacab036bb08944ca2e84aa97f8`. Configuration includes a fresh synthetic API secret; the secret itself is not recorded.
- Filesystem cache was warm. Each sample started a new CLI process; the core stayed stopped. There was no public-network request.
- Each command has 30 samples. Python monotonic timing includes launching the small C measurement helper, the CLI, output capture and wait. Observer overhead is not subtracted.
- The C helper uses per-child `wait4` peak RSS. It avoids the inherited Python image being counted as CLI memory. This is process peak RSS, not active-service steady-state memory.
- A missing GNU time executable interrupted the first harness before measurements; the final harness uses the included independent C helper. No timing from that aborted run is used.

## Results

| Command | n | Median ms | Min–max ms | Median peak RSS KiB | Max peak RSS KiB | Failed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `cli --json capabilities` | 30 | 3.132 | 2.736–4.882 | 8320.0 | 8576 | 0 |
| `cli --json service status` | 30 | 3.104 | 2.739–4.316 | 8448.0 | 8704 | 0 |
| `cli --json sub status` | 30 | 3.492 | 2.989–4.442 | 8576.0 | 8832 | 0 |

Raw observations: [host-performance.json](test-results/host-performance.json). Reproduce with `python3 tests/host_performance.py` after building the host artifacts.

## Unmeasured gates

Android cold/warm startup, phase-specific startup timing, real sched_process_exec counts, active idle scanning, TUN versus eBPF RSS/CPU, mixed versus Go/default stack A/B, Android application latency, physical DNS leakage, hotspot IPv4/IPv6 return paths and at least 600 seconds of public-network soak are **NOT_RUN**. No Android device or applicable workload/account was provided. No accepted performance budget was supplied, so the observed numbers are not presented as meeting a target or improving the prior product.
