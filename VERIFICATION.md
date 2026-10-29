# Repair verification — MagicNet v1.8.1 / 10609 candidate

This is the developer verification record for the repaired candidate built from recipe 0.3.1. It is not Android device acceptance or an official Release. Final identities are recorded in `assets/BUILD_INPUTS.json` and `dist/DELIVERY_MANIFEST.json`; those distinguish the actual controller revision from the final documentation/packaging commit.

## Scope and provenance

The frozen input remains the complete BUILD_PROMPT.md: 335,805 bytes, eight packages, 53 Markdown files, SHA-256 `502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a`. Repair starts from the first independent candidate `eb4c8ba89a04f9aaa4ee4a2fe6dc62e47949ed97`. The coordinator subsequently disclosed three failing probes and their coverage audit. Those are now developer regression inputs, not unseen acceptance evidence. No old MagicNet product source, binary or unrelated retained acceptance case was read.

The first candidate remains unchanged. A shared filesystem and explicit reading constraints provide instruction isolation, not a hard operating-system boundary. Later M40/release-workflow changes were outside the frozen input and are not claimed as reconstructed. No old repository, remote push, CI release or device operation was performed.

Product identity is **v1.8.1 / versionCode 10609**, with separate **recipe_version 0.3.1** and **channel candidate**. Module properties, controller receipt, WebUI metadata, component manifest and build metadata agree on these fields. This is a local candidate; no new official release assets have been published.

## Repairs

### P1-A: stage promotion and owned paths

New fixed-rule, core-cache and owned Tailscale paths are module-relative. Core check and run both use the physical module root as their working directory. A manager's staging directory is no longer a persistent runtime identity.

Existing absolute paths are normalized only when fixed asset/tag/format or owned Tailscale marker/intent prove ownership, and only for the current root or paired modules/modules_update roots. Custom external paths remain unchanged. Active config, settings, runtime checkpoint/fingerprint and last-known-good material are updated using `.state/private/runtime-path-relocation.json`. Every current file must match original or intended bytes; external changes preserve conflict evidence. Prepared/committed recovery finishes forward; an explicit rollback restores all prior bytes before a later retry. Tailscale identity contents and stopped service intent remain unchanged.

The compiled harness performs actual directory renames and fixed-core checks, verifies all 55 rules and private identity bytes/modes, and covers custom paths, six partial-publication boundaries, commit cleanup, rollback/replanning and external conflict. Separate Go tests verify the exact rollback direction before replanning. This is distinct from actual Android manager/reboot execution.

### P1-B: current blockers precede update replay

The acceptance lock now protects current owner, manager markers and recovery checks before receipt replay or new-worker acceptance. Valid pending record publication recovers under the lock and current state is checked again. Malformed/conflicting journals cannot publish invalid candidates. An interrupted manager `installing` phase also requires recovery. There is no unlocked historical-success fallback when the worker lock is busy.

Healthy completed same-ID/same-intent replay, changed-intent conflict, expired receipts and bounded ID history remain implemented. Blocked old and new IDs preserve ledger, intent, journal and owner bytes. Publication tests cover zero/one/two private files written plus canonical publication failure/recovery. No test downloads a release or calls a root manager.

### P1-C: complete original policy baseline and per-identity progress

Network-access journals retain every original UID, Android user, shared-package identity and policy. Fresh restricted-only inspection cannot replace that full baseline after partial repair. Each setter has durable pending progress and readback. Retries reconcile original/intended values, including successful writes whose response was lost; every terminal phase verifies the complete identity set.

Rollback is idempotent across interrupted prefixes. External policy bits or package identity changes cause a conflict without overwriting outside state. Repair cannot replace an unfinished rollback or add unrelated identities to an unresolved baseline. Completed rollback does not own later changes. Existing complete legacy journals retain all records. Tests use a synthetic app_process provider, not Android binder policy.

### P2: newer source drafts remain visible

Editor visibility now includes dirty state. When import B succeeds and configured_count changes from zero to one, a newer draft C remains visible and dirty until explicit cancellation or submission. Two viewport cases use the real authenticated HTTP import and delay only delivery of the unchanged successful response.

### Version and source delivery

Product version and recipe version are distinct. External converter subprocess execution, timeout and fallback are explicitly **NOT_IMPLEMENTED / not provided in this round**. SUB-005 permits the implemented native parser; unsupported semantics fail explicitly. The absent optional converter is not labelled as an environment-limited NOT_RUN.

The archive reads the functional commit from actual build metadata and the controller receipt, rather than a first-candidate constant. Browser PNGs remain local evidence and are excluded from tracked source and the source archive. JSON reports, implementation, licenses and test data remain included. No-Git source builds explicitly avoid inherited parent-repository VCS discovery and retain their archive provenance.

## Executed developer evidence

Final compiled-binary reports were regenerated against clean functional commit `280f044a0dc63f49965a910efd9509abd13a316b`. Linux CLI SHA-256 is `cb5ed46ad892e2478751a2f2c215091289dd37dc5e0c77d94caed1c0faec7255`. Temporary development reports retain their original receipt/SHA and do not become final results.

| Check | Evidence and scope |
| --- | --- |
| Complete repaired Go race suite | PASS: 56 top-level tests, 72 records including nested cases, no skip/fail, 93.347 s. `test-results/repair-go-verification.json`, `repair-go-cases.json` |
| Complete Go vet | PASS: 0.557 s, same frozen repaired Go implementation |
| Compiled updater/policy regressions | PASS: 28/28. `test-results/repair-acceptance.json`: current gates, publication, full baseline, ignored setter, partial failure, response/readback loss, rollback and external conflicts |
| Compiled promotion | PASS: 12/12. `module/test-artifacts/promotion-verification.json`: actual directory moves and fixed core checks, no actual manager |
| Current WebUI contracts | PASS: 14/14, including dirty zero-to-one source visibility. `webui/test-artifacts/repair-contracts.json` |
| Focused real HTTP UI | PASS: both viewports. `webui/test-artifacts/source-draft-http-report.json`: 390 and 1280 px, fresh profiles/fixtures, authentic import response |
| Final installer/package fixtures | PASS: 12 checks. `module/test-artifacts/package-verification.json`: product binding, full/offline/reuse, migration, exact bytes/modes and invalid-input preservation |
| Packaging repeatability | PASS: all 14 outputs byte-identical across two same-input package runs. `module/test-artifacts/reproducibility.json`; not compiler reproducibility |
| No-Git archive build | PASS: actual Linux CLI compilation and nine provenance checks in `module/test-artifacts/archive-build-verification.json`; no fixed-core recompilation |
| Host controller integration | PASS: 11/11 final-CLI cases in `test-results/host-control.json`; local import, scheduler ownership, MCP boundary and encrypted backup |
| Source integrity | `dist/SOURCE_FILES.json` and `source-verification.json`: included content size/mode/digest verification |

The retained first-candidate 540-case browser matrix, nine-protocol loopback results, original HTTP suite and performance values remain historical unless a separate repair report explicitly reruns them. [FIRST_CANDIDATE_VERIFICATION.md](docs/FIRST_CANDIDATE_VERIFICATION.md) preserves that record. They are not blanket validation of changed repair code. [REQUIREMENTS.md](docs/REQUIREMENTS.md) retains the M01–M39 implementation and verification mapping.

## Frozen artifact identities

Product **v1.8.1 / 10609 candidate**, recipe **0.3.1**, functional commit `280f044a0dc63f49965a910efd9509abd13a316b`. Both controller/installer targets have `vcs.modified=false`; the unmodified fixed core retains its approved revision.

| Binary | Bytes | SHA-256 |
| --- | ---: | --- |
| `assets/bin/linux-amd64/magicnet-cli` | 10801314 | `cb5ed46ad892e2478751a2f2c215091289dd37dc5e0c77d94caed1c0faec7255` |
| `assets/bin/linux-amd64/magicnet-installer` | 6590626 | `c1e8307a0c6bf2e0d769d0346ec20e21111ae2893e70df49ce79d9c150fa0ed4` |
| `assets/bin/linux-amd64/sing-box` | 65773730 | `4a3b5a35871a723cf9111727c5f5bd3c5523d5779b4d03ad6af9727a53fae451` |
| `assets/bin/android-arm64/magicnet-cli` | 11206952 | `0f1145ada22d85c98094370a1977d91e5fe27a776ad43c88e086edcb8c0a62e1` |
| `assets/bin/android-arm64/magicnet-installer` | 6750504 | `d51cd7e521c6aa3e198ac35a92ead69ba84215b150b097f4965d90a71b2e2d0a` |
| `assets/bin/android-arm64/sing-box` | 67371304 | `9e0689f4e5bb0a7a670bee9aeadd3256a3544b99947af776477d488576692a1d` |

The full Android module is 53,135,512 bytes, SHA-256 `f8db57170e5e1274ca84737142b27be1e5b451eb8e20b2f6b56957e18d0741aa`. Each identical core alias is 7,856,617 bytes, SHA-256 `6abc06adda67aa41670bc116c3293ac3b2040aeaea5fd25f9f8e5f86bffd3f6e`. The source tar and final delivery commit are recorded outside the self-referential source tree in `dist/source-archive.json` and `dist/DELIVERY_MANIFEST.json`. `PACKAGE_SHA256SUMS` preserves the original packaging-only checksum document; `SHA256SUMS` covers the final artifacts.

## NOT_RUN and support boundaries

No Android device was supplied. Real root-manager install/promotion/boot/uninstall, SELinux, native bridge/WebView behavior, binder permissions, TUN/eBPF and cgroup/TC attachment, IPv4/IPv6 hotspot clients, real applications/shared-UID DNS and OEM policy remain NOT_RUN. Host directory moves and synthetic app_process cannot substitute for those observations.

WARP/Tailnet account interoperability, enabled VLESS Encryption remote traffic, actual Android eCapture and official-release installation remain NOT_RUN. Device performance budgets, stack A/B and a public-network soak of at least 600 seconds are also NOT_RUN. Core field checks and synthetic loopback traffic are separate evidence.

Same-directory replacement of an installed module still fails before publication with `install.in_place_upgrade_requires_staging`; normal manager staging is the supported upgrade path. New component assets have not been published, so local review uses full or supplied offline components.

Independent acceptance of the frozen repair belongs to the parent coordinator. Disclosed failures and these developer regressions are not counted again as unseen independent tests.

## Repeat the affected checks

```sh
GIT_DIR="$(git rev-parse --absolute-git-dir)" GIT_WORK_TREE="$PWD" \
GOCACHE="$PWD/.tools/gocache" GOMODCACHE="$PWD/.tools/gomodcache" \
  .tools/go/bin/go test -race -p=1 ./... -count=1
python3 tests/repair_acceptance.py
python3 scripts/verify-promotion.py
node webui/tests/contracts.test.mjs
node webui/tests/source-draft-http.mjs
python3 scripts/verify-package.py
```

Use only the harnesses' fresh temporary module roots. Browser setup is documented in BUILD_NOTES.md. Final package/source digests are in `dist/SHA256SUMS`; the original packaging-only checksum snapshot is retained separately when source artifacts are appended.
