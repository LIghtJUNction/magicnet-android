# Runtime, subscription, and policy verification

Date: 2026-10-29. Scope: the independent Go runtime reconstruction in this repository. This report records the runtime agent's own checks. The integration owner separately verifies the final combined tree, host protocol interoperability, Android artifacts, packaging, lifecycle, and control interfaces.

## Authority and evidence boundaries

The sole project requirement input was `../input/BUILD_PROMPT.md`, with supplied SHA-256 `502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a`. Runtime, subscription, policy, relevant control interfaces, engine/VLESS Encryption, quality, and root contracts were read from that input. No previous MagicNet implementation, historical generated product, old test corpus, or historical evidence was used as an implementation source.

The implementation uses the explicitly approved fixed sing-box fork at revision `871b7a3440cd9c850f1b09ef3b4ada9babb4384b`, and the bundled MagicNetRules manifest at revision `f3335f9420d07b8c50b26488df2a9492da6bbb44`. The asset owner supplied the actual Linux core and 55 verified rule assets. Runtime tests consume those real artifacts; they do not replace `sing-box check` with a stub. Asset retrieval and release-tag verification belong to the asset owner's report.

The runtime test fixture copies the packaged rules into a temporary module root and invokes `assets/bin/linux-amd64/sing-box`. The core configuration checks instantiate and validate the actual core configuration. They do not start Android TUN/eBPF forwarding or prove that a remote proxy account is usable.

HTTPS tests use a controlled local TLS server, a test trust root, and explicit resolver/dial injection. The policy sees specified public test answers; the dial injection connects the test to its local server. Production has no such injection configured and dials only the validated literal addresses. These tests exercise real HTTP/TLS I/O, decompression, redirect handling, retry, cancellation, and policy decisions. They are not measurements of a public subscription provider, a real hostile DNS deployment, or a real Android application's traffic.

## Implemented boundaries

| Area | Principal functions | Persistence and behavior |
| --- | --- | --- |
| Source identity and fetch | `NormalizeSubscriptionURL`, `NormalizeSubscriptionList`, `ResolveSubscriptionHost`, `PublicSubscriptionAddress`, `SubscriptionFetcher.Fetch` | Canonical request URL identity preserves ASCII path/query bytes and query ordering. Public HTTPS only; all resolved addresses checked; redirects revalidated; no environment proxy; verified TLS; bounded headers, decompressed body, retries, DNS, connection, source and batch deadlines. |
| Native import | `ParseSubscription`, `ParseShareLink`, `clashProxy`, `ValidateProxyNode`, `ValidateVLESSEncryption` | JSON, complete YAML parsing, share links and base64 wrapping. Supported semantic fields are retained; unknown/unrepresentable connection fields fail the source. There is no installed external converter. |
| Node identity | `MergeSubscriptionNodes`, `UpdatePolicySelectors` | Recursive connection-semantic identities, source-local reference rewriting, stable conflict tags, complete source provenance, literal filtering, retained user-owned nodes and valid selector fallback. |
| Atomic source generations | `ApplySubscriptionURLs`, `ApplyLocalSubscription`, `RefreshSubscriptions`, `ClearSubscriptions`, `recoverSubscription` | Immutable private generation directory; current pointer and source intent commit together with configuration and ownership checkpoints. A pending journal is recovered before a new writer. Clear removes source intent while retaining the working configuration. |
| Shared configuration transactions | `performRuntimeChange`, `restoreRuntimeTransaction`, `verifyRuntimeCommit`, `RecoverRuntime` | Checked independent baseline; exact snapshots of changed intent and ownership; external modification conflicts; durable commit recovers forward; incomplete activation/commit recovers the old generation. |
| Initialization and migration | `EnsureDefaultConfig`, `initialConfigCandidate`, `beginRuntimeInitialization`, `recoverRuntimeInitialization` | Regenerates the fixed policy, retains nodes/groups/selector choices from the authorized private migration backup, preserves the backup, and journals initialization. Old raw network policy is not copied into the new default policy. Unmanaged old policy remains available in the backup and is flagged for review. |
| Refresh scheduling | `SetSubscriptionSchedule`, `TickSubscriptionSchedule`, `SubscriptionScheduleStatus` | One fswatch supervisor owns the waiting schedule; a separate record owns the current refresh. Repeated enable repairs a provably absent/stale loop. Off persists intent, requests cancellation bound to PID/start/boot/task identity, and waits at most eight seconds before returning an explicit pending result. Unknown ownership is never killed. The shared observer additionally verifies executable and bounded `/proc/cmdline` SHA-256 identity. |
| Default policy | `PolicyAssets`, `DefaultPolicy`, `UpdatePolicySelectors` | Fixed local rule inventory and SHA-256 validation; fail-closed proxy/AI defaults; named selectors; ordered route/DNS definitions; no ordinary subscription-driven rule updates. |
| Overrides and routing | `OverrideOperation`, `ApplyRoutingOverlay`, `StripRoutingOwned`, `undoMergePatch` | Revision checks; preview/set/apply/reset; bounded structured routing; target/cycle/collision validation; explicit DNS detours; exact private ownership and external-change conflicts. Preview does not initialize an absent active configuration. |
| Runtime settings | `MaterializeConfig`, `materializeFromBase`, `applyRuntimeSettings`, `NetworkStatus`, `DNSStatus` | Network/DNS/mode/domain/block/chain materialization. Chain selector changes are undone before regeneration. DNS effective status is observed from active configuration and does not assert application connectivity. |
| Configuration editor/template | `configEditor`, `saveEditedConfig`, `syncTemplate`, `validateTemplateRepo` | Controlled private payloads; actual check; preserved runtime intent; fixed commit and SHA-256 for configured GitHub/GitLab templates; atomic sync. |
| Tunnels | `ParseWireGuardConfiguration`, `warpAction`, `tailscaleAction`, `tailscaleLogout`, `CoreConfigWithSecrets` | WireGuard endpoint checked on import even while disabled; userspace Tailscale; private auth sidecar; actual endpoint-based Tailnet routing before LAN; logout deletes only proved module-owned state and retains unknown/custom directories. |
| Public state | `SubscriptionStatus`, `RuntimeStatus`, `subscriptionLast` | Public enums/counts exclude source URLs, node names, hashes, credentials and raw errors. Private inspect has bounded source/usage reads. Read-only status does not create state directories. Refresh counts derive from the latest 200 owned log events. |

The subscription batch budget is **eight minutes**. Each source defaults to **45 seconds total**, including DNS, redirects, retry delays and body reading; the connection default is **10 seconds**. Configurable ceilings are 120 seconds per source and 30 seconds per connection. All addresses in one connection attempt share a single connection deadline. Headers are bounded to 64 KiB and each decompressed source to 8 MiB. At most five distinct remote sources are accepted.

The active configuration limit is 4 MiB, ownership checkpoint limit 16 MiB, and transaction/initialization journal limit 32 MiB. Oversized recovery evidence is rejected before a journal or new active generation is committed.

## Commands actually run

Commands use the downloaded repository-local Go 1.26.10 toolchain and the repository-local module/build caches:

```sh
GOMODCACHE=$PWD/.tools/gomodcache GOCACHE=$PWD/.tools/gocache .tools/go/bin/go test ./internal/magicnet -count=1
GOMODCACHE=$PWD/.tools/gomodcache GOCACHE=$PWD/.tools/gocache .tools/go/bin/go test -race ./internal/magicnet -count=1
GOMODCACHE=$PWD/.tools/gomodcache GOCACHE=$PWD/.tools/gocache .tools/go/bin/go vet ./internal/magicnet
```

| Run | Observed result | Exact scope |
| --- | --- | --- |
| Early full Go suite | PASS, 9.944 s | Initial parser, identity, controlled fetch, policy and transaction tests. |
| Expanded full Go suite | PASS, 19.140 s | Included actual VE matrix checks, migration, chain undo, DNS, preview and scheduler cancellation. |
| Recovery boundary subset | PASS, 12.727 s | `TestRealCoreSubscriptionRecoveryAtTransactionBoundaries` and invalid independent-baseline rejection. |
| Expanded race suite | PASS, 50.172 s | Runtime suite as it existed before the final tunnel/HTTP-limit additions. |
| Full Go suite with tunnel and HTTP-limit additions | PASS, 36.909 s | Included actual WireGuard and Tailscale configuration checks, private key injection, gzip/header limits, retry/cancellation and privacy canary. |
| Final full race suite before the last connection-budget delta | PASS, 61.488 s | Included interrupted initialization recovery and bounded recovery-metadata changes. |
| `go vet ./internal/magicnet` | PASS, exit 0 | Static checks at that full-suite revision. |
| Final connection-budget delta and all fetch tests | PASS, 5.058 s | `go test -race ./internal/magicnet -run 'TestSafeFetch' -count=1`, including the added shared-deadline assertion. |

The last implementation delta after the full race run adds one deadline around the entire resolved-address connection loop. Its dedicated test and all existing fetch tests passed with the race detector. The integration owner performs the final combined-tree build/test after integrating its own control and lifecycle work. After these recorded runs, the integration owner strengthened the common owner observer with a bounded `/proc/cmdline` SHA-256 identity and added that digest to `newSubscriptionOwner`; that shared-control delta is covered by the integration owner's subsequent full run, not retrospectively claimed by this report.

A default sandbox run was **BLOCKED by the test environment**, not recorded as a product pass: the sandbox's process namespace could not prove the test process's `/proc` identity, and local listening sockets were denied. The successful runs above were executed with approved host access for synthetic local sockets and process-identity checks. No device, customer subscription, personal key, public proxy service, release, or deployment was used.

## Subscription contract slices

The entries below deliberately identify the measured slice rather than declaring an entire acceptance ID passed.

| Contract slice | Test / implementation evidence | Status and limits |
| --- | --- | --- |
| SUB-001/002, SUB-A01/A02: URL identity, list normalization, five-source ceiling | `TestSubscriptionURLIdentity`; `NormalizeSubscriptionURL`, `NormalizeSubscriptionList` | PASS for canonical scheme/host/port/path, IDNA, fragment removal, preserved percent/query bytes, duplicate/order handling and six-source rejection. Full GUI chunk/payload workflow belongs to control/UI testing. |
| SUB-003, SUB-A03/A04: public destination policy | `TestSubscriptionAddressPolicy`, `TestSafeFetchRedirectAndTLS` | PASS for tested private/special IPv4/IPv6, mixed public/private answers, forbidden redirect and redirect-loop rejection before dangerous target requests. Real public DNS rebinding infrastructure: NOT_RUN. |
| SUB-003: network resource boundaries | `TestSafeFetchGzipHeaderRetryAndCancellation`, `TestSafeFetchSharesConnectBudgetAcrossAddresses` | PASS for decompressed response above 8 MiB, headers above 64 KiB, two 503 retries, cancellation, environment proxy isolation, one connection deadline across addresses. Full 5 × 45-second wall-clock batch: NOT_RUN. |
| SUB-004: atomic acquisition and same-source cache | `TestRealCoreMultiSourceAtomicityAndCache` | PASS with controlled TLS for A success/B failure, old-generation preservation, two-source success/reorder, same-URL cache fallback, require-fresh rejection and no cache fallback for invalid fresh content. Public provider availability/authentication: NOT_RUN. |
| SUB-005/006: complete native semantics | `TestYAMLAnchorsAndVMessFields`, `TestVLESSEncryptionAcrossNativeInputs` | PASS for tested YAML anchors, flow/nested forms, separate VMess server/Host/SNI/path, missing SOCKS credential rejection, mixed unknown fields failing, and Encryption field fidelity. Every possible protocol/transport extension: NOT_RUN; unsupported semantic fields return explicit failure. |
| SUB-005/006: external converter paths | `ParseSubscription` uses the native parser only | NOT_IMPLEMENTED / not provided in this round: external converter execution, subprocess timeout and converter-on fallback. This is an implementation choice under SUB-005, not an environment-limited unexecuted path; no external converter is bundled or claimed. The native parser rejects fields it cannot preserve. |
| SUB-007: stable identities/provenance | `TestStableSemanticIdentityAndReferences`, `TestRealCoreMultiSourceAtomicityAndCache` | PASS for same display name/different endpoints, true semantic duplicate with different names, provenance accumulation, reordered sources, reserved tags, source-local detour/group rewriting and ambiguous reference rejection. |
| SUB-008/009: UA/filter/usage bounds | `TestSubscriptionUsageAndBounds`, controlled multi-source test | PASS for UA 256/257-byte boundary, case-insensitive literal filters, non-regex matching, local 8 MiB boundary, duplicate/negative/exponent/zero-expiry rejection, maximum accepted numeric values and retained source rows. All 32/33-filter and Unicode boundary combinations: NOT_RUN. |
| SUB-010/011: candidate and stopped-state semantics | `TestRealCoreDefaultAndLocalImport`, `TestRealCoreChainUndoDNSAndTemplate`, `TestRealCoreOverlayApplyResetAndRepeat` | PASS using real core checks, stored source generations, stopped-state preservation, private state canary, stable repeated materialization and preserved overlay/template/source behavior. Running Android activation/readiness failure matrix: NOT_RUN in this runtime suite. |
| SUB-012, SUB-A12: recoverable generation boundaries | `TestRealCoreSubscriptionRecoveryAtTransactionBoundaries` | PASS for constructed on-disk crash states at prepared, activated, partially committed source metadata and committed journal cleanup; conflict evidence retained; resumed recovery idempotent; old config/checkpoint/source pointer/success timestamp restored on rollback. These are deterministic disk-boundary fixtures, not arbitrary power-loss or Android SIGKILL experiments. |
| SUB-012: independent baseline | `TestRealCoreRejectsInvalidIndependentRecoveryBaseline` | PASS: invalid active and independent backup bytes reject another generation without changing the source pointer. |
| SUB-013/014, SUB-A13/A16: schedule ownership/cancel | `TestSubscriptionScheduleOwnerAndBoundedCancellation`; shared locks and owner identity | PASS for fswatch ownership while waiting, one active refresh fixture, off canceling the owned context, no old schedule resurrection, supervisor remaining owned/alive, and unknown refresh ownership rejection. Repeated enable repair through an actual compiled CLI daemon, Android disable/uninstall and PID-reuse process races: NOT_RUN by this agent. |
| SUB-014, SUB-A15: clear | `TestRealCoreDefaultAndLocalImport` | PASS: current configured count becomes zero while active configuration bytes remain unchanged. Full concurrent manual/update/stop/clear stress: NOT_RUN by this agent. |
| SUB-015, C-SUB-002/003/005: generation-bound public/private state | `TestRealCoreMultiSourceAtomicityAndCache`, `TestSubscriptionPublicTokensRejectPrivateCanary`, `TestRuntimeStatusReadsDoNotCreateState` | PASS for current committed count differing from failed candidate count, per-source fetch result, generation association, no node/server/password in public output, unknown quota rows, malformed public token rejection and read-only storage behavior. UI late-result/draft receipt reconciliation belongs to UI/control verification. |

## VLESS Encryption evidence

| Contract slice | Actual evidence | Result |
| --- | --- | --- |
| VE-002/003 syntax and exact preservation | `TestVLESSEncryptionAcrossNativeInputs` passes generated values through JSON, YAML, share link query decoding and base64 links while checking independent TLS/WS Host fields. | PASS for those paths and fixtures. |
| VE-005 appearance/RTT/key matrix | `TestRealCoreVLESSEncryptionMatrix` generates real X25519 public keys with `crypto/ecdh` and real ML-KEM-768 encapsulation keys with `crypto/mlkem`. Three appearances × two RTT values × both key sizes are submitted to the actual pinned core. | PASS, configuration/initialization layer only. No all-zero placeholder keys. |
| VE-005 length and multi-key | The same test checks legal padding plus both key sizes, and a value containing sixteen 1184-byte keys, about 25 KiB. | PASS, no truncation and actual core acceptance. |
| VE-005 failures | Parser tests reject wrong type, `NONE`, unknown appearance, empty/missing keys and padded base64; actual core test rejects invalid padding. | PASS for tested failures. Full malformed cryptographic-key corpus: NOT_RUN. |
| VE-003 migration and subsequent source update | `TestRealCoreMigrationRegeneratesPolicyAndRetainsNodes` preserves an enabled Encryption value from the authorized private backup and retains that node when a later subscription is imported. | PASS. |
| VE-003 structured override/editor/restart/backup matrix | Implementation accepts and preserves the field; generic ownership/editor/recovery tests exist. | The complete Encryption-specific cross-product of these lifecycle paths is NOT_RUN. |
| VE-004/005 encrypted server interoperability and half-open cancellation | No compatible controlled Encryption server was supplied to this agent. | NOT_RUN. Core check does not prove an encrypted TCP/UDP handshake, application response, or XHTTP delayed-download behavior. The fetch-cancellation test is not an Encryption-handshake test. |

## Policy and routing evidence

| Contract slice | Actual evidence | Result and remaining scope |
| --- | --- | --- |
| Default inventory and actual core acceptance | `TestRealCoreDefaultAndLocalImport`; `PolicyAssets` verifies all required local assets against the manifest before constructing defaults. | PASS for actual-core acceptance using the real fixed assets. Independent asset-provenance validation is reported by the asset owner. |
| POLICY-A01 tag boundary | `TestRoutingOverlayOwnershipAndLimits` tests 256/257 UTF-8 bytes, including multibyte characters. | PASS. The implementation also enforces 256 rules, 64 outbounds and 128 members; a complete limit-boundary table for those counts was NOT_RUN here. |
| POLICY-A02 graph and collision | `TestRoutingOverlayOwnershipAndLimits` | PASS for normalized duplicate domain, missing target, built-in collision, cyclic groups and ambiguous ownership cases covered by the test. |
| POLICY-A03/A04 ordering and DNS | Overlay tests inspect protected insertion position; tunnel test checks actual Tailnet `preferred_by` before LAN; DNS/runtime test verifies direct-template restoration. | PASS for these generated-configuration assertions and actual core acceptance. This is not the complete real engine matcher first-match matrix. Missing-template/DNS-tag-collision edge cases are implemented but not all separately executed here. |
| POLICY-A05 ownership and regeneration | `TestRoutingOverlayOwnershipAndLimits`, `TestRealCoreOverlayApplyResetAndRepeat`, `TestRealCoreChainUndoDNSAndTemplate` | PASS for exact owned-item removal, preserving a later user/subscription node, repeated materialization, reset, active overlay on template sync, and chain reference cleanup. |
| POLICY-A06 revision/conflict/preview | `TestRoutingOverlayOwnershipAndLimits`, `TestRealCoreOverlayApplyResetAndRepeat`, `TestOverridePreviewDoesNotInitializeConfiguration` | PASS for owned-item edit conflict, stale revision rejection, preview no active-file creation and stopped activation. Full Android activation failure injection: NOT_RUN. |
| POLICY-A07 Encryption in structured custom routes | `validateStructuredOutbound` includes `encryption`; generic Encryption/core validation is tested. | Complete structured-editor-specific Encryption matrix: NOT_RUN. |
| Named business classification / source rule matcher | Ordering is generated from the recipe and real assets are loaded. | Full live matcher cases for AI, Voice TCP/UDP, iCloud/Apple, Bing/Microsoft, games, Telegram, foreign-domain/CN-IP overlap and substring-negative domains: NOT_RUN by this agent. Do not infer their traffic result from tag presence or `check`. |

## Other runtime observations

`TestRealCoreChainUndoDNSAndTemplate` passes chain enable/repeat/disable without dangling references, restores the ad-block default after a disable/enable cycle, restores the direct DNS template after changing profiles, and preserves source nodes plus active overlays across template regeneration. A remote pinned GitHub/GitLab template download and integrity-failure server fixture were not run.

`TestNetworkCIDRAndWireGuardValidation` covers usable derived TUN DNS address space and rejection of malformed WireGuard keys. `TestRealCoreWireGuardImportAndTailscaleUserspace` generates valid test WireGuard keys, validates import while disabled, checks enable/disable configurations, saves a userspace Tailscale endpoint, verifies that the auth canary is absent from the active config and present only in transient secret injection, verifies Tailnet rule precedence, and rejects `system_interface=true`. Neither WARP handshake nor Tailnet login, discovery, TSMP, MagicDNS response, private application service, exit-node routing or cloud logout was run. Tailscale online status remains unknown.

`TestRealCoreInterruptedInitializationRecoversForward` constructs a partially written initialization transaction and verifies complete forward recovery plus idempotence against the actual core. The migration test verifies that the original private backup remains byte-for-byte unchanged and that an old raw route canary is absent from the regenerated policy. It does not claim migration of arbitrary historical policy syntax without explicit ownership; the retained backup and private migration report expose that review boundary.

## Remaining external gates

No Android device, TUN/eBPF dataplane, Android UID inventory, hotspot client, vendor kernel, live DNS leak measurement, real application flow, public subscription account, WARP account, Tailnet identity, or VLESS Encryption server was used by this runtime agent. Those dimensions remain **NOT_RUN** unless a separate, current integration report records actual evidence.

No claim in this file upgrades a local parser assertion, a controlled TLS fixture, a real core configuration check, or a process-level test into Android networking or real-service interoperability. Final combined-tree builds, cross-compiles, package installation and the integration owner's additional tests must be reported separately.
