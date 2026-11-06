# MagicNet implementation rewrite

## Contract and baseline

The rewrite keeps observable product behavior and replaces internal implementations by responsibility. The comparison baseline is the complete source tree at `9d545e100080ef454f7bc7c11fb9c2508b639e4e`; its framework is `MemDeco-WG/kamfw@bb0dc7582ee2c27e31e49d2d3b714b97528defef`. The associated recipe baseline is `LIghtJUNction/MagicNet@d81d03792ef7ca973f7ab798f0e74061834218d2`. Git history and detached baseline worktrees retain the original implementations for differential tests.

Compatibility concerns inputs, outputs, exit status, persistent intent, resource ownership and recovery. Private functions and source layout are implementation details. Existing tests that inspect an old function's spelling must follow the replacement call path or exercise its behavior; they must continue to enforce the original requirement.

## Observable functionality

| Surface | Required behavior | Comparison evidence |
| --- | --- | --- |
| Installation and upgrade | Magisk, KernelSU and APatch entrypoints; verified components; configuration preservation; rollback; clean uninstall | Installer and archive tests; synthetic manager lifecycle |
| Framework | Import-once modules; lifecycle phases; locales; logs; cached downloads; launcher; watchdog and fswatch ownership | Original/new shell traces across supported host shells |
| Service and network | Explicit tun/ebpf; owned processes; readiness; DNS, route, hotspot and Wi-Fi policies; bounded locks | Original/new CLI snapshots and lifecycle fixtures |
| Subscriptions and routing | All supported source formats; atomic update/rollback; selectors; user and application rules; configured/effective separation | Existing transactional, protocol and routing tests |
| Connectivity | Low-frequency Google connection checks; explicit warnings; exponential recovery; subscription refresh | Deterministic time and network fault fixtures |
| Diagnostics and automation | Complete single-file diagnostics with redaction; bounded resources; schema-1 machine interface; MCP authentication and disclosure boundaries | CLI envelope, support-bundle, redaction and resource tests |
| WebUI | All 14 pages; private payload handling; asynchronous bridge; separate read/write lanes; background reconciliation; unsaved drafts; locales; accessibility | Same-input differential fixtures, UI tests, typecheck, build and browser scenarios |
| Delivery | Exact dependency pins; no tests, fixtures, development caches or credentials in installable archives | Archive entry and package lifecycle checks |

## Measurement protocol

Baseline and candidate use the same host toolchain, generated inputs and dependencies. Timing uses repeated runs after warmup; memory figures name the process and unit. Host command timing, Node process RSS and mocked Android observations are reported separately. A smaller source file or archive is not a measurement of Android runtime RSS or network throughput.

The WebUI comparison is reproducible from its directory:

```sh
node --experimental-strip-types --import ./test-register.mjs \
  scripts/compare-baseline.mjs /absolute/path/to/baseline/webui
```

It compares application and routing parsers, connection lists, grouping, traffic sampling and statistics, alerts, node delay parsing and reports. The connection benchmark uses 6,000 input rows, 4,800 unique connections, three warmups and eleven measured calls in independent Node processes. It preserves first-seen connection identity and stable ordering.

Baseline WebUI validation on 2026-11-06: 346 tests passed, typecheck passed and production build passed. Candidate results and full rewrite coverage are recorded in the completed verification report. This document defines the acceptance surface; it does not claim unexecuted Android device or external network tests.
