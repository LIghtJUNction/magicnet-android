# Historical first-candidate verification (superseded)

This report describes only first candidate eb4c8ba89a04f9aaa4ee4a2fe6dc62e47949ed97 and its cc1920418acb7b323d04b8978832a89851325cf7 binaries. Its hashes and PASS counts do not identify or validate the repaired v1.8.1 candidate. See the root VERIFICATION.md for current repair evidence.

# Builder verification — independent rebuild 0.3.1

This report describes tests executed by the builders on the newly written implementation. It is **not independent acceptance**, an Android deployment report or proof that an unexecuted device scenario works. The separate [requirements matrix](REQUIREMENTS.md) retains all M01–M39 scenarios and explicitly separates implementation from the tested slice.

## Frozen input and source identity

The only project requirements input was the complete recursive `BUILD_PROMPT.md`: 335,805 bytes, eight packages, 53 Markdown documents, SHA-256 `502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a`. The implementation lead read the entire file in sequential chunks. Subtasks received that input and current-round interface agreements. No old MagicNet implementation, binary, test, analysis/evidence directory or retained acceptance case was read. The build reused only the explicitly approved fixed core/rules/components and general dependencies/toolchains listed in [BUILD_NOTES.md](../BUILD_NOTES.md).

The independently written functional Go, Java, WebUI and module source was frozen at commit `cc1920418acb7b323d04b8978832a89851325cf7`. The delivered controller embeds that full revision; the Go build information records it with `vcs.modified=false`. Later delivery changes comprise reports, new host test harnesses, source archival, and a license-collector correction that stores notices with `.txt` suffixes. The source archive's `SOURCE_ARCHIVE_INFO.json` and `dist/SOURCE_FILES.json` record the final delivery commit and tree, separately from the functional binary revision.

Isolation was an instructed fresh context on a shared filesystem, not an operating-system-enforced private sandbox. There is no claim of stronger isolation. There was no web Pro development session, source push, Release creation or device operation.

## Final executed checks

| Check | Result | Exact scope and evidence |
| --- | --- | --- |
| Complete Go race run | **PASS** | `go test -race -p=1 -json ./... -count=1`; 53 top-level tests, 63 records including nested cases, no failures or skips; 80.556 s. `test-results/go-verification.json`, `test-results/go-cases.json` |
| Complete Go static vet | **PASS** | `go vet ./...`; exit 0, 1.499 s; same final tree after license text correction |
| Compiled controller integration | **PASS**, 11/11 | Final Linux CLI plus real pinned core configuration check; capabilities, rejected machine write, private local-source transaction/receipt, invalid payload preservation, real scheduler repeat/repair/off, actual authenticated MCP, 85 tools, unknown-argument rejection, notification no-op, private boundary, owned stop, encrypted backup round trip. `test-results/host-control.json` |
| Real core protocol traffic | **PASS**, 9/9 | Synthetic loopback SOCKS, VLESS `none`, VLESS TLS, VMess, Shadowsocks, Trojan TLS, AnyTLS, Hysteria2 and TUIC. Each verifies the expected target response bytes through the configured proxy client and server. `test-results/host-network.json` |
| JavaScript contracts | **PASS**, 13/13 | URL identity, draft ownership, capability/envelope interpretation, payload bounds, native callback timeout and overflow retaining write ownership. `webui/tests/contracts.test.mjs` |
| Browser route/layout matrix | **PASS**, 540/540 | 15 routes × three languages × two themes × six viewport sizes in Playwright 1.56.1 / Chromium 141. No page errors or horizontal overflow; selected screenshots inspected. `webui/test-artifacts/browser-report.json` |
| Browser against actual HTTP backend | **PASS**, 9/9 | Final CLI + pinned core, authenticated HTTP, same request ID replay, changed arguments HTTP 409, full private local payload, same-operation/generation receipt, VLESS field retention, node/source counts, output privacy and cross-route draft. `webui/test-artifacts/http-integration-report.json` |
| Real installer package fixtures | **PASS**, 11/11 | Final installer validates core/full archives, full offline install, core plus read-only component cache, complete reuse, identical final bytes/modes, one-manifest migration, explicit early same-root upgrade refusal, link/hash rejection before publication and private canaries absent. `module/test-artifacts/package-verification.json` |
| Package repeatability | **PASS**, 14/14 artifacts | A second `scripts/package.py` run with the same frozen inputs produced the same SHA-256 for every package output. This tests packaging repeatability, not a second from-scratch compiler/toolchain reproduction. `module/test-artifacts/reproducibility.json` |
| Android arm64 cross-build and inspection | **PASS** | Actual controller, installer, fixed full-tag core and DEX were generated. Android ELF machine 183, PIE interpreter, Go metadata, fixed revision, Java source digest and 55 rule hashes are recorded in `assets/BUILD_INPUTS.json`. This does not execute Android code |
| Host control measurements | **PASS: measurements obtained** | 30 fresh CLI processes per workload, 90 total, no command failures; per-child `wait4` RSS and elapsed timing. [PERFORMANCE.md](../PERFORMANCE.md), `test-results/host-performance.json` |

The result counts are test slices, not a count of complete product requirements proven. A scenario with host PASS evidence can still have its complete Android acceptance gate marked NOT_RUN.

### What the integration tests exercise

The full Go run uses the actual fixed Linux core for default generation, policy overlays, route/reference validation, Tailscale userspace configuration, WireGuard import, subscriptions and VLESS Encryption field checks. Deterministic transaction fixtures cover prepared, partially published, activated/committed and externally modified recovery states. They verify preservation and conflict behavior; they do not simulate arbitrary kernel or filesystem power-loss semantics.

The extra control tests validate stopped `tun → ebpf → tun` configuration changes without starting the core, preserving explicit IPv4-only behavior, MTU and UDP timeout. A five-cycle host process test starts and stops the real pinned core with a non-TUN test configuration. Separate identity tests refuse foreign route/rule objects or changed process command identity; they do not claim actual Android kernel cleanup. The manual route deletion test checks the full exact owned helper arguments, not host route mutation.

The compiled scheduler fixture starts its actual owned `fswatch` process, observes a valid waiting owner with no active refresh, repeats the same interval without spawning another owner, stops the owned supervisor, repairs it by setting the same interval, saves `off`, and confirms the core remained stopped. Due-task cancellation also has a controlled Go test. A real 12-hour wait and a long public-source refresh were not run.

The protocol loopback tests use real sockets, actual core client/server instances and expected target response bytes. They are useful evidence of the compiled protocol paths. They do not exercise Android application UID rules, physical-network DNS, TUN/eBPF, real remote provider behavior or an enabled VLESS Encryption service. `encryption=none` traffic and acceptance/preservation of legal encrypted fields are different checks.

The browser tests run in a new temporary profile. Host CJK fonts were installed only for test rendering so Chinese screenshots are readable. They do not depend on or inspect a user's signed-in browser. The test harness required an approved elevated executor because the default sandbox disallows loopback sockets and some `/proc` observations; product authentication and origin restrictions were not relaxed.

## Installation artifacts

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `MagicNet-full.zip` | 53,121,614 | `69255cac72111510db8e0f8362c8262eee29cfd965bbe87509cdec4fb1a0530a` |
| `MagicNet-core.zip` | 7,842,848 | `2341f1269261d306ab4db91b356dc3dfe689577af2c61049cd4bad5cad8b3c11` |
| `MagicNet.zip` | 7,842,848 | Same exact bytes as core |
| `magicnet_installer.zip` | 7,842,848 | Same exact bytes as core |

There are seven content-addressed component ZIPs: control, engine, rules, WebUI, Android bridge, eCapture and panel. Their exact names, file identities and digests are in `dist/components.json`; all published ZIP digests and source archive digests are in `dist/SHA256SUMS`. Installed component payload totals 127,322,355 bytes before runtime-generated configuration or state. Only the current component generations are present in the delivery directory.

The completed local installer fixtures use the final Linux installer to validate Android package bytes. Full, read-only offline component cache and complete installed-component reuse converge on the same byte/mode inventory, SHA-256 `bbe112dd982725e3f5151e81c85a680e56aaaee62d1bc3adc3e167bc344801ae`. These run with synthetic module roots and restricted network access; no actual root manager was invoked.

**Known installation support boundary:** upgrading an already installed module into the exact same source/destination directory is rejected before publication with `install.in_place_upgrade_requires_staging`. Normal manager staging in `modules_update/MagicNet` and fresh installation are implemented and covered by local fixtures. Same-directory upgrade is not represented as a successful migration or hidden under NOT_RUN.

The source archive includes the final new tracked tree, the complete approved core tree including its tracked WireGuard replacement, the frozen recipe, license texts, dependency locks and an inventory of every included blob. Optional core GUI client gitlinks are listed as omitted because they do not participate in this headless module build. Toolchains, Go download caches, runtime state and historical Git objects are excluded. Fixed build scripts retrieve required inputs with locked identities.

## Failures encountered and resolved

The first final aggregate race command returned exit 1 even though all 63 product/installer test records passed. A copied upstream license collector candidate named `notice.go` was incorrectly scanned as an incomplete Go package. The collector now rejects source/binary suffixes as notice candidates and stores actual license texts with `.txt` suffixes while retaining original source paths, lengths and SHA-256. It preserves 592 notice texts for 436 module identities. `go list ./...` then returned only the three intended project packages; the complete race run and vet were rerun and passed. The original aggregate failure record remains in `test-results/go-verification-before-license-fix.json`.

The new compiled scheduler harness initially requested `sub schedule status` through `--json`, which is not in the frozen machine-command allowlist. The product correctly returned `machine.command_unsupported`. The harness was corrected to inspect the documented schedule projection in `--json sub status`; all 11 compiled control cases then passed. This was a test invocation correction, not a product relaxation. The initial record remains in `test-results/host-control-before-harness-fix.json`.

Initial performance probes either lacked GNU `time` or inherited Python's high-water RSS across `fork`. Those values were discarded. The final measurements use a small C `fork`/`exec`/`wait4` observer and document its overhead. Initial host screenshots without CJK glyphs were also not accepted as visual verification; the retained set was rerendered with the explicit test font.

## NOT_RUN and external gates

| Gate | Why no PASS is asserted |
| --- | --- |
| Root manager install/upgrade/uninstall, boot, disable/remove, reboot reconciliation | No Android device/root manager was available. Cross-build and synthetic staging do not demonstrate manager behavior |
| TUN/eBPF attachment, cgroup/TC programs, owned-resource cleanup and native network restoration | No supported device kernel, privileged data plane or physical network was supplied |
| IPv4/IPv6 hotspot TCP/UDP and return path | No tethering interface or client; route identity tests do not prove client packets |
| Multi-user/shared-UID applications, app DNS behavior, GMS/Play and two OEM policy environments | No actual applications, Android binder environment or OEM policy state |
| Native WebUI bridge, WebView accessibility/touch/keyboard and manager permissions | Host Chromium verifies only web code and the host bridge |
| Wi-Fi changes, VPN coexistence and device resolver behavior | Host synthetic fixtures lack those Android services and network transitions |
| WARP/Tailscale login and real Tailnet reachability | No supplied account/provider endpoint; userspace config and privacy were locally checked |
| Enabled VLESS Encryption service including TCP/UDP/half-open/XHTTP | No compatible remote service was supplied; field/key/core validation is separately PASS |
| Real eCapture TLS/GoTLS/NSPR traffic | Fixed binary and invocation/error handling are implemented; no supported Android tracing environment was available |
| Official stable update download/install through manager | Update code and durable replay/journal logic were locally tested, but no release was installed and no device was changed |
| Device cold/warm/idle performance, controlled stack A/B and ≥600-second public-network soak | No device or accepted device-specific budgets; host measurements do not substitute |
| Complete cross-entry/provider matrix and arbitrary power-loss failures | Executed representative and deterministic cases are listed; exhaustive external combinations and physical failure injection remain unexecuted |
| Independent acceptance | Reserved for the parent coordinator with separately retained cases; builder self-tests cannot supply it |

Unknown runtime capability remains unknown or a concrete provider error. This delivery does not turn observations such as process alive, core syntax accepted, route present, file nonempty, manager exit 0 or ping response into stronger claims of complete service readiness, capture success or application connectivity.

## Repeatable checks

Use a fresh temporary fixture and the new build outputs, never an installed user module:

```sh
GOCACHE="$PWD/.tools/gocache" GOMODCACHE="$PWD/.tools/gomodcache" \
  .tools/go/bin/go test -race -p=1 ./... -count=1
GOCACHE="$PWD/.tools/gocache" GOMODCACHE="$PWD/.tools/gomodcache" \
  .tools/go/bin/go vet ./...
python3 tests/host_control.py
python3 tests/host_network.py
node webui/tests/contracts.test.mjs
python3 scripts/verify-package.py
python3 tests/host_performance.py
```

The browser and actual HTTP fixture setup is documented in [BUILD_NOTES.md](../BUILD_NOTES.md). [docs/RUNTIME_VERIFICATION.md](RUNTIME_VERIFICATION.md) traces subscription, VLESS Encryption and policy-specific requirements to named tests. The final combined-tree reports above supersede earlier partial-subtask timings without broadening their scope.
