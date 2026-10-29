# Independent build and delivery notes

This repair tree targets the **MagicNet v1.8.1 / versionCode 10609 candidate**, reconstructed from recipe **0.3.1**, with a new Go control plane, offline WebUI, Android module scripts, and manifest-driven installer. Product version, recipe version, candidate channel and implementation commit are distinct metadata. The approved sing-box core, classification data, eCapture binary, and Zashboard assets remain third-party components. They are identified below rather than described as independently rewritten code.

The sole project requirement input remains `BUILD_PROMPT.md`, SHA-256 `502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a`. The initial independent implementation used no prior MagicNet implementation, generated implementation, historical tests/evidence, or MagicSingBox template. This repair starts from its own first-candidate source at `eb4c8ba89a04f9aaa4ee4a2fe6dc62e47949ed97`; only the newly disclosed coverage-audit report and three regression probes/results were subsequently made available as regression material. Existing user configuration is migration data, not implementation source. Later M40/release-workflow changes are outside this frozen input and are not claimed as reconstructed here.

The first candidate's controller/installer identified implementation commit `cc1920418acb7b323d04b8978832a89851325cf7`; that identifier does not identify the repaired programs. The repaired controller/installer were rebuilt from clean functional commit `280f044a0dc63f49965a910efd9509abd13a316b`. `assets/BUILD_INPUTS.json`, each executable's Go VCS metadata and the CLI `version` receipt agree on that identity. Later delivery commits change documentation and observed verification results, not the frozen functional source. The prior license-collector correction remains: actual program source files are excluded from notices, copied notices have `.txt` delivery names, and `source_path` plus their original bytes/hashes remain recorded. It resolved a real whole-tree Go test failure caused by an upstream `notice.go` filename; the failure was not hidden by narrowing the Go package pattern.

## Repair scope and regression boundaries

The disclosed P1 findings concern absolute module-owned paths surviving staging promotion, obsolete updater-success replay bypassing present blockers, and a partially applied network-access repair losing an earlier UID's rollback baseline. The control plane repair and its focused recovery tests are documented by the corresponding source and reports. The WebUI repair addresses a separate P2: a successful first-source import could leave a newer dirty source draft intact but collapsed. Visibility now includes dirty state, independently of the manual-open flag and committed source count; explicit cancellation restores the baseline and permits clean collapse.

`scripts/verify-promotion.py` performs real filesystem promotion from a synthetic `modules_update/MagicNet` root to `modules/MagicNet` with the compiled CLI and fixed core. Its twelve cases cover new relative defaults; persisted module-owned absolute paths; external custom rule, cache and Tailscale paths; prepared-journal interruptions at zero through five published files; committed cleanup; rollback followed by replanning; and an external-writer conflict that must preserve the journal without publishing other changes. It checks the active config, checkpoint, saved settings, both last-known-good representations, all 55 rule identities, exact Tailscale identity bytes/modes, stopped intent and repeated invocation. Production journal states are constructed directly; no fault switch is added to the product. This host directory-move test is distinct from an actual root manager/reboot gate.

`webui/tests/source-draft-http.mjs` creates a fresh module root and browser profile for each 390 px and 1280 px case. It runs a real local-file subscription import through the authenticated HTTP bridge and pinned core check, delays delivery of the unchanged successful response, edits C while the B invocation still owns the writer, and checks that C stays dirty and visible after the configured count changes from zero to one. It also verifies navigation, explicit cancellation, complete payload transfer/consumption, public-output privacy, stopped core state and no horizontal overflow. No provider response or subscription receipt is fabricated.

The baseline `module/test-artifacts/promotion-baseline.json` records the copied first-candidate binary failing all three promotion scenarios; it is deliberately a failure record. Repaired-binary outcomes belong to `promotion-verification.json`, and targeted UI outcomes to `webui/test-artifacts/source-draft-http-report.json`. The final promotion and HTTP UI reports identify the rebuilt functional commit and CLI SHA-256. `promotion-development.json` separately retains the earlier temporary build result; it is not presented as the final run.

## What was built and what was reused

| Part | Origin and treatment | Reviewable result |
| --- | --- | --- |
| Control plane, CLI, machine API, MCP, runtime policy generation | New implementation from the recipe | `cmd/`, `internal/`, `go.mod`, `go.sum` |
| WebUI | New HTML, CSS and ES modules; no framework, CDN or network font requirement | `webui/` |
| Component installer and Android integration scripts | New Go installer plus bounded shell manager entry points | `module/installer/`, `module/*.sh`, `module/migration.json` |
| Android package-label/network-policy bridge | New Java reflection bridge, compiled without an Android SDK | `module/java/MagicNetBridge.java`; DEX JAR in `assets/bin/android-arm64/` |
| sing-box | Approved, unmodified fixed fork, compiled separately for Linux amd64 and Android arm64 | `LIghtJUNction/sing-box@871b7a3440cd9c850f1b09ef3b4ada9babb4384b` |
| Local classification data | Exactly 55 approved inventory items from the immutable release attached to the fixed rules revision | `assets/rules/manifest.json`, per-file SHA-256, original provenance/licenses |
| eCapture | Approved upstream Android arm64 release binary; not rebuilt here | `gojue/ecapture`, tag `v2.5.2` |
| Zashboard | Approved upstream offline static distribution, no bundled fonts | `Zephyruso/zashboard`, tag `v3.16.0`, `dist-no-fonts.zip` |
| jq/yq duties | JSON and YAML parsing implemented in Go, with pinned `gopkg.in/yaml.v3`; no shell JSON/YAML interpreter dependency | CLI/parser tests and `go.mod` |

The fixed core's `submodules/wireguard-go` is a **tracked source tree**, Git tree `c813a5db524eef79b40a99a1d5d6aa02748c1675`. It is included in the core checkout and satisfies the local `replace` in the core's `go.mod`. The optional Apple/Android/desktop client gitlinks are separate; this module build does not use their UI code. `scripts/fetch-build-inputs.py --include-core-clients` can fetch those declared fixed gitlinks when a complete upstream client checkout is desired.

## Locked resources

All downloads below are checked before extraction or execution. `scripts/fetch-build-inputs.py` contains the exact official URLs and hashes; `scripts/import-rules.py` also checks that the rules release tag resolves to the approved commit and that its checksum document equals the locked snapshot.

| Resource | Version / identity | SHA-256 of downloaded archive |
| --- | --- | --- |
| Go for the Linux build host | `go1.26.10.linux-amd64.tar.gz` | `ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5` |
| Temurin JDK | `21.0.9+10`, Linux x64 HotSpot | `810d3773df7e0d6c4394e4e244b264c8b30e0b05a0acf542d065fd78a6b65c2f` |
| Google D8/R8 | `8.10.21`, `r8.jar` | `bbdf3f6431af895d72a5f4bed6fbdde2b43241ec98b36992c554ce4a6dd7892b` |
| Rules binaries | `magicnet-rules.tar.gz` | `1ade898a44cc7727b1d98404e206f796a4a0432b1aa2be98289cc7823b0ae0bf` |
| Rules source snapshot | `magicnet-rules-sources.tar.gz` | `b88342e8f1151d0d1d9a6d73543a8eb8ba789a8a43398591d7652c3ac111ba5f` |
| Rules upstream provenance | `upstream-manifest.json` | `2f91f78d6e3b6a93e845d6345afb039f01a9d577717d23a0423a4bac4f801592` |
| eCapture | `ecapture-v2.5.2-android-arm64.tar.gz` | `3531f47f60a45c02662188fb151fa8bbf9c40e5c245ff293e5a50477b99df2d1` |
| Zashboard | `v3.16.0/dist-no-fonts.zip` | `1d8c7aca69e6ddead5e4fe6e92ceda23a499105f675d053362f7c9b53a9730f9` |

Rules source revision: `f3335f9420d07b8c50b26488df2a9492da6bbb44`. Release tag: `rules-20260918-1ade898a44cc7727`. The 55 runtime items contain 3,210,427 payload bytes: 54 compiled SRS files and the source-format `sukka-chatgpt-voice.json`. The manifest records each recipe tag, relative runtime filename, format, size, SHA-256, and upstream filename. Archives, checksums, upstream provenance and per-source licenses are retained separately from the selected runtime inventory.

Original upstream locations:

- <https://github.com/LIghtJUNction/sing-box/tree/871b7a3440cd9c850f1b09ef3b4ada9babb4384b>
- <https://github.com/LIghtJUNction/MagicNetRules/tree/f3335f9420d07b8c50b26488df2a9492da6bbb44>
- <https://github.com/LIghtJUNction/MagicNetRules/releases/tag/rules-20260918-1ade898a44cc7727>
- <https://github.com/gojue/ecapture/releases/tag/v2.5.2>
- <https://github.com/Zephyruso/zashboard/releases/tag/v3.16.0>
- <https://go.dev/dl/>, <https://github.com/adoptium/temurin21-binaries>, <https://storage.googleapis.com/r8-releases/raw/8.10.21/r8.jar>

## Reproducible build

Build tools live under `.tools/`; Go module and build caches are local to this source tree. A Linux amd64 host with Git, Python 3 with the safe `tarfile` extraction filter, Bash, and HTTPS access is sufficient. Android does not need Go, Python, Node, javac, an NDK, or an SDK at runtime. The module uses its packaged executables, Android's shell/app_process, and the root manager's installation environment.

```sh
python3 scripts/fetch-build-inputs.py
bash scripts/build.sh all
```

The source revision is injected into `magicnet.local/rebuild/internal/magicnet.Commit`. `MAGICNET_SOURCE_REVISION` explicitly overrides the label when supplied. In a checkout or worktree with its own `.git` marker and matching top-level directory, the default is that repository's HEAD. These control builds retain `-buildvcs=true`, and only their commands receive the explicit worktree Git binding needed by Go 1.26.10. Later documentation/verification commits can be separate. The script also supports `core`, `cli`, `java`, and `cli-linux` (only the Linux controller) when one stage needs to be repeated.

An unpacked source archive has no `.git`. Its control binaries use explicit `-buildvcs=false`; they do not inherit an enclosing repository or caller-provided `GIT_DIR`/`GIT_WORK_TREE`. The revision defaults to `SOURCE_ARCHIVE_INFO.json`'s `functional_binary_source_commit`, then `uncommitted` only when provenance is unavailable. Final archive metadata requires both `SOURCE_ARCHIVE_INFO.json` and `SOURCE_FILES.json`: it verifies the complete current set of functional `cmd/`, `internal/`, `module/`, build scripts, `go.mod`/`go.sum` and WebUI runtime files, including byte lengths, modes and SHA-256. Missing, added or changed functional files fail the provenance check. The output records `source_mode=archive`, descriptor/inventory hashes and the observed functional-source fingerprint; it does not invent `vcs.modified=false` or claim Git verification of unpacked files. The source manifest binds the extracted content to the reviewed archive; its authenticity still rests on the delivered archive's independently checked SHA-256.

`scripts/verify-archive-build.py` actually compiled only the Linux CLI inside `.tools/archive-build-fixture`, a directory without `.git` located beneath this worktree, with unrelated outer Git environment variables deliberately supplied. All nine checks passed: successful compilation, archive revision fallback, no inherited VCS fields, exact functional inventory, explicit override priority, `uncommitted` when the descriptor is absent, and rejection of an unrecorded functional edit. Its descriptor commit is an explicitly labelled synthetic canary, not a claimed product source revision. The report is `module/test-artifacts/archive-build-verification.json`; no core or Android rebuild was needed for that test.

Both core targets use `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=true`, `-p 1` by default, and these tags:

```text
with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,
with_tailscale,with_ebpf,with_xhttp,with_awg,badlinkname,tfogo_checklinkname0
```

The core version string is `1.15.0-alpha.10-magicnet.871b7a3440cd`. The fixed source requires Go 1.25.5 or newer; this build uses the locked Go 1.26.10 toolchain. Core VCS metadata must report the full approved revision and `vcs.modified=false`. The Android artifact is ELF64 AArch64 with the Android linker; the Linux artifact is ELF64 x86-64. `assets/BUILD_INPUTS.json` is generated from the actual binaries using `go version -m`, their ELF headers, SHA-256, and sizes.

The Java bridge is compiled with `javac --release 8`, then D8 `--min-api 26`. Its JAR contains `classes.dex` and a manifest binding the JAR to the exact Java source SHA-256. `scripts/write-build-metadata.py` rejects a stale Java bridge. The JAR and release ZIP entries use fixed timestamps. API 26 is the bridge's compilation target; it is not a claim that every product capability works on all Android 8 devices.

The license-source download step uses disposable copies of `go.mod`/`go.sum`, so collecting optional dependency notices does not alter the approved core tree. It downloads only pinned module versions and executes no downloaded module scripts. `scripts/collect-licenses.py` reads the two complete module graphs offline and copies original notice texts from the verified Go cache.

## Packages and component identity

`scripts/package.py` produces seven components: `control`, `engine`, `rules`, `webui`, `android-bridge`, `ecapture`, and `panel`. Each component ID is the SHA-256 of a sorted inventory of relative path, mode, byte length, and content SHA-256. ZIP order, timestamps and compression do not define component identity. The archive SHA is recorded separately.

`MagicNet-core.zip`, `MagicNet.zip`, and `magicnet_installer.zip` contain identical bytes. `MagicNet-full.zip` contains the complete runtime, including the fixed core, all rules, the DEX bridge, eCapture and the offline panel. Individual content-addressed component ZIPs, `components.json`, `SHA256SUMS`, and `package-sizes.json` accompany them. Those generated records are authoritative for final sizes and hashes.

The repaired full module contains 53,135,512 bytes (SHA-256 `f8db57170e5e1274ca84737142b27be1e5b451eb8e20b2f6b56957e18d0741aa`). Each of the three identical core aliases contains 7,856,617 bytes (SHA-256 `6abc06adda67aa41670bc116c3293ac3b2040aeaea5fd25f9f8e5f86bffd3f6e`). Source-archive identity is added after the delivery commit in `dist/source-archive.json` and the complete `dist/DELIVERY_MANIFEST.json`. First-candidate archives remain frozen in the separate original checkout; their hashes are not presented as repaired artifacts. `scripts/product_metadata.py` requires the module properties, WebUI package and actual CLI receipt to agree on v1.8.1 / 10609, recipe 0.3.1 and candidate channel. The metadata writer checks clean VCS revision in Git mode or verified source-inventory provenance in archive mode. Packaging refuses mismatched product metadata, a changed functional-source fingerprint or stale binary hashes. The installer validates the new fields against `module.prop` while retaining read compatibility with old version-only ownership manifests.

The core package resolves missing components in this order: verified bytes already present in the candidate root; matching bytes in the previous installed root; matching payload bundled in the selected archive; an explicitly supplied read-only offline cache; then the exact official release tag and component archive named in the current core manifest. A complete full install and complete installed-component reuse require no download. No `latest` endpoint or downloaded component-supplied manifest can override the selected core's identities.

The independent builder delivered local results without a Git push, Release upload, root-manager device installation or reboot. Candidate-branch synchronization, if performed by the coordinator, is recorded separately. Consequently, this work does not establish that the newly named component archives are available at the official release URL. Before publishing them, use the full package or provide the accompanying component directory as the installer cache. An online core install that cannot obtain its exact component fails explicitly.

## Installer validation, migration and the staging boundary

The root manager evaluates `customize.sh`. It extracts only a uniquely named bootstrap installer into the candidate root, without overwriting an installed helper first. That installer verifies the entire archive before staging runtime components. The bootstrap is removed on completion or an ordinary failure.

Validation covers relative path safety, duplicate ZIP entries, local/central ZIP header disagreement, CRC and size, compression expansion limits, unsafe modes/links, unmanifested files, duplicate JSON keys, ambiguous module properties, module ID/version, ELF architecture, component hashes, and exact file modes. Downloads use HTTPS, revalidate each allowed redirect/destination, reject private/reserved IPs, pin the checked destination IPs for the connection, and ignore proxy environment variables.

The component manifest carries `version`, `version_code`, `recipe_version` and `channel` separately, plus `source_mode` and `source_provenance`. Its fixed `release_tag` identifies the intended component namespace; `channel=candidate` is not a publication claim. No release upload occurs in the build scripts.

Install changes are prepared in a private directory and recorded in a durable journal before replacement. Rollback restores only bytes whose ownership is still proven. External changes produce a recovery conflict and retained evidence. Obsolete component files are removed only when the previous successful ownership manifest still matches their bytes, size and mode; modified or unowned files remain intact. Component identity documents and the success receipt participate in the same replacement journal.

`module/migration.json` is the single migration inventory. It preserves declared configuration/private state while replacing immutable rules and excluding volatile payload/download directories. The former active sing-box configuration is retained under `.migration-backup/.config/sing-box/config.json`. The new runtime recovers supported node/endpoint and saved-setting intent, then generates and core-checks the fixed policy. It does not copy the old complete route template into the new implementation. Ambiguous historical raw routing intent remains in the backup and is reported for review.

**Known, enforced limitation:** upgrading an already installed module in the same live directory is rejected as `install.in_place_upgrade_requires_staging`, before creating an install lock, staging changes, migrating data, or publishing components. The manager must supply a separate candidate root such as `/data/adb/modules_update/MagicNet`. A fresh `/data/adb/modules/MagicNet` installation is supported. This limitation is implemented and tested; it is not labelled as an unexecuted test. A same-directory upgrade is not accepted because an installer-only component journal cannot promise whole-module rollback after a later configuration migration failure.

The installer provides:

```text
magicnet-installer verify <module.zip>
magicnet-installer verify-installed <candidate-root>
magicnet-installer install --root <candidate-root> --old <installed-root> \
  --archive <module.zip> [--cache-dir <offline-components>]
```

Android roots are derived from the actual executable location and constrained to the fixed module locations. Host fixtures may use isolated temporary roots. Shell service/boot/uninstall entry points call the controller's owned-resource lifecycle. The action menu has Chinese, English, Russian, Japanese and Korean text. Volume down changes selection; volume up confirms. Stop/update use a second confirmation whose initial selection is cancellation. Missing keys, closed pipes and noninteractive use do not wait indefinitely.

## WebUI behavior and privacy boundaries

The UI includes fourteen navigation pages plus the direct proxy-group route: overview, traffic paths, apps, nodes/groups, blocking, proxy chain, subscriptions, Tailscale, complete configuration editing, local panel, health, terminal, tools and recent output. Structured routing, custom outbounds, full overrides, app policies, service/mode/hotspot actions, Wi-Fi/network settings, DNS/WARP, reviewed network restriction changes, authenticated module updates, MCP, private backup and capture controls call the fixed CLI APIs.

Chinese, English and Russian share one message catalog. Theme selection supports light, dark and system preference. The UI uses system fonts and no remote dependencies. Responsive layouts include 320/360/390/430 px widths, landscape, and desktop. Native dialogs support keyboard cancellation/focus restoration; the navigation palette uses Ctrl/Cmd-K or `/` outside editors. In-memory configuration and subscription drafts survive page/locale/theme navigation. Only nonsecret presentation preferences are persisted in browser storage.

Without a native bridge or an explicit authenticated local HTTP session, the UI is a read-only preview with unknown observations. It does not probe a loopback service or invent healthy device status. Native execution uses the fixed module CLI, structured argv where the manager provides it, and safe argument quoting for the documented exec fallback. The terminal parses CLI arguments and rejects shell substitution/pipes/redirection.

The HTTP entry is obtained only after explicitly starting the controller's local server. The session key is consumed from the URL fragment, exchanged for the token and removed from browser history. Tokens remain in memory. Requests are same-origin and authenticated. A transport operation ID identifies the invocation; a subscription receipt's separate backend task ID and generation identify the actual transaction. Success requires the receipt from that command's exit, matching private inspected task/generation, a changed baseline generation, the intended mode/source set, and a committed result. A later unrelated generation cannot complete the current draft.

Subscription editing normalizes host/scheme/default port and raw Unicode consistently while preserving signed ASCII path/query bytes, repeated keys, plus signs, percent-escape case and source ordering. It rejects an invalid entire candidate or more than five unique sources instead of truncating it. Sources are transferred in bounded UTF-8/base64 chunks to a private payload file. Append failure prevents application. URL lists, provider headers, credentials, full configuration, app identities, captures and private backup payloads do not enter shared recent-output records. Backup passwords are passed in private payload files, not process arguments.

One workflow owns writes across its multi-command upload. A caller timeout or HTTP disconnection does not free the underlying execution slot; the actual exit is observed separately. Native callback output is bounded across stdout and stderr to 8,388,608 UTF-16 units and 65,536 events, including empty events. Overflow clears retained text and waits for a real exit. Read-only refreshes remain separate from the writer.

## Verification records and their scope

The new repair regressions are described above and are rerun against the final repaired binaries. Existing first-candidate browser/protocol evidence remains attributed to its original source and artifact identity; the 540-case browser matrix is not being rerun for this focused change. The following table identifies retained or regenerated records explicitly:

| Evidence | What it proves | What it does not prove |
| --- | --- | --- |
| `webui/tests/contracts.test.mjs` | Fourteen current URL/draft/envelope/payload/ownership tests, including the zero-to-one source count and visible dirty-draft regression | Real Android bridge delivery |
| `webui/test-artifacts/source-draft-http-report.json` | Current targeted real-controller import, authentic delayed response, visible dirty C, cancellation and privacy at 390 px and 1280 px | OEM WebView compatibility, provider downloads or proxy traffic |
| `webui/test-artifacts/browser-report.json` | Retained first-candidate 540 route/locale/theme/viewport cases and keyboard checks | A rerun of all those cases on the repair |
| `webui/test-artifacts/http-integration-report.json` | Retained first-candidate nine-case real CLI/HTTP/core-check regression, including request-ID replay/409 and VLESS field persistence | A new repaired-binary run unless separately regenerated |
| `module/installer/main_test.go` | Archive ambiguity, canonical identity, migration exclusions/links, journal recovery, external-writer preservation, obsolete-file ownership, duplicate JSON, and early same-root refusal | A root manager's actual staging/boot lifecycle |
| `module/test-artifacts/package-verification.json` | Regenerated after final repair packaging: product/version binding plus full/offline-component/reuse convergence, migration/readback, bad hash/link failures, private canary absence and explicit in-place refusal | Device installation, SELinux permissions, reboot, public release availability |
| `module/test-artifacts/promotion-verification.json` | Real compiled controller/core after stage-to-live directory movement and durable relocation-journal recovery | An Android manager's actual promotion or reboot |
| `module/test-artifacts/archive-build-verification.json` | A real Linux CLI build from a verified synthetic archive fixture, with no own Git metadata and hostile inherited Git variables | Full clean toolchain/core reproduction or an independently authenticated source archive |
| `module/test-artifacts/reproducibility.json` | Two independent packaging runs produced byte-identical SHA-256 for all fourteen `package.py` outputs on this host, before separately adding the source archive | Cross-toolchain compiler reproducibility or Android execution |
| `assets/BUILD_INPUTS.json` | Actual binary hashes, architecture, Go metadata, clean approved core revision, 55 rule hashes, and Java source-to-JAR binding | Execution of Android ELF/DEX on a device |

The first-candidate browser fixture installed Noto Sans CJK SC 2.004 only in the host test process so Chinese screenshots were readable. The product still uses the device's fonts. Font download SHA-256: `2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b`. The initial host lacked Chinese glyphs; those initial tofu screenshots were not accepted as visual verification. The focused repair browser cases use the English locale and do not create delivered screenshots. Browser PNGs are excluded from the tracked repair source and source archive.

The retained first-candidate browser timing samples are seven measured navigations after one warm-up for each of 390×844 and 1280×900. Raw samples and environment are in `browser-report.json`. They measure host preview becoming visible, without network or CPU throttling; they are not repair-version measurements, Android startup latency, sustained performance, a historical-product comparison, or proof of an agreed performance budget.

For that first-candidate host run, the 390 px median was 66.6 ms and nearest-rank P95 was 71.7 ms; the 1280 px median was 74.7 ms and nearest-rank P95 was 81.7 ms. With seven observations, nearest-rank P95 is the largest observed sample.

Repeat the focused checks after freezing/rebuilding binaries:

```sh
node webui/tests/contracts.test.mjs
PLAYWRIGHT_BROWSERS_PATH=/path/to/playwright-browsers \
  node webui/tests/source-draft-http.mjs
GOTOOLCHAIN=local GOCACHE="$PWD/.tools/gocache" \
  GOMODCACHE="$PWD/.tools/gomodcache" .tools/go/bin/go test ./module/installer
python3 scripts/write-build-metadata.py
python3 scripts/verify-promotion.py
python3 scripts/package.py
python3 scripts/verify-package.py
```

`webui/tests/browser.mjs` uses Playwright 1.56.1/Chromium 141 and an explicitly served static WebUI. `webui/tests/http-integration.mjs` uses only the isolated `module/test-artifacts/host` fixture and its private authenticated entry log. Never point these synthetic write tests at a user's installed module.

## Licenses and source availability

`assets/THIRD_PARTY.json` records fixed origins. The package preserves the core's original GPL-3.0-or-later notice, including its additional naming/association wording, the full GPL-3.0 text, the Go standard library BSD notice, eCapture's Apache-2.0 license, Zashboard's MIT license, and the rules' upstream per-source notices.

`assets/licenses/dependencies/index.json` maps the union of the two pinned Go module graphs to original copied notice files, with original relative paths and SHA-256. The collection currently covers 436 module/version identities and 592 notice files. It includes the controller's `gopkg.in/yaml.v3`, `golang.org/x/net`, `github.com/cilium/ebpf`, `github.com/sagernet/netlink` and transitive dependencies. Two optional test dependencies, `github.com/RyuaNerin/testingutil@v0.1.0` and `github.com/zeebo/assert@v1.1.0`, have no license text in their pinned module archives and are not linked into any inspected distributed Go binary; the index says so explicitly. No license text was invented for them and their source is not bundled in runtime packages.

The source deliverable retains the newly implemented code, the exact approved core source including its tracked WireGuard replacement, dependency locks and build instructions. Optional GUI client submodules and build caches are not required for the headless module build. The fetch script reconstructs the allowed source/resources from immutable identities. This delivery does not replace upstream attribution or suggest upstream authors endorsed this independent build.

## Remaining device and external validation

Android arm64 artifacts were compiled and inspected, but were not executed on a real device in this build environment. Real KernelSU/APatch/Magisk WebUI bridges, manager install/upgrade/uninstall, Java binder/reflection permissions, SELinux behavior, volume keys, reboot recovery, TUN/eBPF ownership, tc/cgroup support, hotspot IPv4/IPv6, external VPN coexistence, OEM resolver behavior, multi-user/shared-UID policy changes, Tailscale, eCapture, external/public proxy-server handshakes and long-running traffic remain device or external validation work. The separately recorded nine-protocol synthetic loopback matrix does use real fixed-core processes and actual local handshakes; it does not establish behavior with public providers or production endpoints. Product-wide minimum Android/WebView versions remain unknown. Host fixture results do not convert the outstanding device/external rows into a pass.
