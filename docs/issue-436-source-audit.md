# Issue 436: TUN warning propagation

This change addresses a remaining false-green connection indication associated
with [MagicNet issue 436](https://github.com/LIghtJUNction/MagicNet/issues/436).
It does not establish who removes rules during an APatch network transition.

## Source and release scope

- Reviewed Android main at `387fe9ec7aba14033e2c6ac1c23dca19ae6bff8d` (PR #5).
- MagicNet v1.9.3 / 10621 identifies Android source
  `a27f2889d236d2ffa36e1970a4d9f9e1a4baab1b` in its release notes and gitlink.
  Its merge base with Android main is
  `edf2d9926e9a71000667596c9f80edd547e96363`; the two tips are divergent.
- `connectivity.rs`, `connectivity_tun.rs`, `diagnostics_tun.rs` and
  `webui/src/composables/connectivityStatus.ts` are identical between those tips.
  Thus the warning propagation defect exists on both reviewed source lines.
- Product recovery was introduced earlier by
  `48efc93601ed1bb66871c1274034a372da2ffc06`, which is an ancestor of the
  release source. PR #5's acceptance changes are not that product implementation.
- The reviewed core gitlink is
  `3a155d21872b22e6b9b75326c98d11f7ff159a2e`; its sing-tun dependency is
  `v0.9.7-0.20261028024126-5b0a1a7a394e`. Its auto-redirect mark rules differ
  from the official 1.14.3 UID/goto group described in the original report.

## Verified gap and change

The product already observes RPDB/FIB separately from successful proxy probes.
However, a cached TUN warning was absent from top-level `connectivity.warning`.
WebUI then discarded that backend boolean while decoding status and reconstructed
its own proxy-only warning. An online proxy result could therefore still produce
the green connection presentation despite missing/unknown TUN evidence.

Top-level warning now includes the projected TUN warning, and WebUI preserves
the backend warning. Proxy `status=online` retains its documented probe scope;
it no longer suppresses the connection attention indication. The projection is
read-only, uses the same core identity for nested and aggregate warnings, and
does not change the JSON field set or expose routes or UIDs. Existing consumers
use the same warning field and bounded TUN recovery capability.

The new runtime assertion failed before the product change (aggregate warning
false despite nested TUN warning true). Regression fixtures cover matching and
changed core generations, successful proxy probes, service-status decoding and
the overview/shell attention presentation. The existing isolated recovery
fixture covers surviving TUN routes with lost rules, an owned-core restart,
foreign-process preservation, uncertain evidence and explicit stop intent.

## Recovery and validation boundary

No routing mutation or new recovery mechanism is added. Existing recovery keeps
90 seconds of startup grace, two complete missing observations for the same
core generation, lifecycle-locked rechecks, shared 300-second cooldown and a
three-attempt per-boot budget with 300/600/1200-second backoff. Unknown evidence,
Direct mode, transactions and stop intent retain their existing vetoes.

Validation is confined to disposable host processes and synthetic kernel
snapshots in the cloud container. It does not demonstrate ordinary UID packet
delivery, physical APatch network-switch behavior, or the origin of lost rules.
KernelSU acceptance-script unit tests do not substitute for those observations.
Physical-device regression still needs controlled Wi-Fi/mobile/reconnect/airplane
transitions with before/after RPDB/FIB, owned-core identity, ordinary UID route
and application-delivery evidence. No device, production endpoint, release
index or published package was modified.

## Cloud checks (2026-11-23)

- `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- Focused Rust: `connectivity::` 33 passed; `connectivity_runtime` 28 passed;
  `diagnostics::tun::` 25 passed (including the owned-core recovery fixture).
- `npm run check`: 401 tests passed, type checking and production build passed.
- `python3 scripts/test-android-route-recovery-proof.py`: 97 passed. These are
  harness unit tests, not an Android acceptance run.
- Unfiltered `cargo test --workspace --locked`: 920 unit tests passed, one
  ignored, three failed. The failures are
  `mcp_server::rpc::tests::cli_timeout_terminates_background_children`,
  `utils::tests::deadline_covers_pipes_held_after_the_direct_child_exits` and
  `utils::tests::timeout_terminates_background_children_in_the_command_group`.
  All three independently reproduce at unmodified base `387fe9e` in this
  container. A continuation excluding those failures passed the other 920 unit
  tests, then reached a fourth environment-dependent integration failure:
  `observation_state::live_singbox_with_unreadable_argv_is_unknown_not_stopped`.
  Its attempt to write `/proc/<pid>/comm` is rejected as read-only; the same
  failure independently reproduces at the unmodified base. Full workspace
  regression is therefore not green here.
- The six integration targets after `observation_state` were then run explicitly:
  `proc_reader`, `process_lifecycle`, `runtime_resource_bounds`, `service_launch`,
  `supervisor_evidence`, `transparent_recovery`: all 41 tests passed.
- `scripts/kam-test.sh quick`: blocked by missing `kam`; it was not replaced
  with a claim of package or device validation.

## CI fixture follow-up

Code Quality run `45124382857`, shell job `137525349789`, failed at
`test-start-stop-rollback.py` with nine assertions before readiness probing.
The same nine failures reproduce independently at both `413ac9e` and unmodified
base `387fe9e`. Neither the fixture nor its lifecycle source changed in #12.
The fixture did not recognize `ip rule show table ' 2022'` or the numeric route
table argument, so the real ownership preflight exited before the probes.

The fixture-only patch from release-line commit `a27f288` is now carried here.
It checks argument count as well as rendering, retaining the leading space in
one table argument, and models filtered rule queries. All existing readiness,
rollback, retry, sleep and ownership assertions remain in force; production
code, permissions and CI gates are unchanged. Local sh and bash runs each pass
all 15 tests after the patch.
