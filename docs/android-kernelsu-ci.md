# Android KernelSU network checks

The **Android KernelSU Acceptance** workflow runs on pull requests, main pushes,
merge queues and release calls, with an optional manual public benchmark.
New main pushes replace obsolete automatic runs; pinned release calls keep running.
The job installs the module into a disposable Android 15/API 35 `google_apis` x86_64 emulator. The AVD keeps the
SDK userspace and ramdisk, but boots a pinned API35/6.6 x86_64 GKI built against
Android CI build 12525588 with KernelSU v3.2.0 and the required x86_64 syscall
hardening compatibility patches. The source manifest and build recipe are pinned;
cached build outputs are verified before boot. The SDK image is revision 9. After Android userspace starts, official `ksud` uses upstream
`late-load` only to initialize userspace/lifecycle stages; it does not inject a
KernelSU LKM into the stock emulator kernel. This is not a physical-phone,
stock-kernel LKM, ARM64, or authenticated Google Play test.

## What changed after the false-positive audit

The old benchmark ran BusyBox wget as the root adbd user. Production TUN excludes
UID 0, so those requests did not establish app/TUN capture. It also ignored the
corpus's expected status, allowed one domestic and one global success to hide
other failed services, and counted a timed-out download by its byte count alone.

Requests now originate in a separate, test-only Android APK, without root,
shared UID, account cookies or storage permissions. The APK uses Android's normal
TLS and hostname verification. The host rejects a missing or malformed result,
root identity, a nonzero ADB exit, a wrong HTTP status, redirected/body-bearing
204, partial response, exceeded byte budget, or any failed target/round. The old
80%/"any endpoint" gate is gone. Requested throughput failures also fail the run.
The retained `--strict-external` CLI flag cannot weaken this policy.

The actual Java request engine is executed against local HTTPS fixtures in PR and
release checks: trusted/untrusted certificates, error status, redirected 204,
HTTPS downgrade, premature EOF, known/unknown-length bodies, bounded throughput
and stalls. Test successes are not reused from the old host cache scope. CI also
builds and verifies the real test APK; the exact compiled fork checks both sentinel
route configurations.

## Required route-loss recovery

The `tun-route-recovery` phase keeps the application-UID TCP controls and uses
a non-DNS UDP marker for RPDB loss: the fixed Android TCP REDIRECT path can still
work without these rules. A temporary receiver lives inside the test app; the
client sends only to the fixed test destination, whose UDP route overrides to
loopback. Bind, cleanup or request-setup errors cannot count as a negative probe.
The harness deletes only live IPv4
`lookup 2022` selectors in the current ownership ledger, preserving jump targets,
the core generation, `magicnet0` and TUN forwarding table. The test requires
readiness to become false and a new application connection to fail, then waits
for the normal `connectivity tick` recovery path to restore both rules and flow.
It also exercises a controlled virtual uplink down/up transition, requiring a
fresh TCP positive control before interruption and retaining the final route,
readiness and app observation if recovery times out. Production
grace, confirmation and cooldown periods remain active; the fixture does not
fabricate canonical state or require Google or a subscription provider.
The first fixture activation observes the normal stop/start boundary to prove
ownership of the core's random redirect table. Recovery may replace that proven
helper; its complete rule/FIB evidence and every other unowned rule are checked.
Across recovery, an `eth0` network-ID change requires complete [netd observations](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-15.0.0_r23/server/NetworkController.cpp)
binding both IDs to the same interface, permissions and FIB. Only the exact
global selectors and the per-app selectors declared by unchanged UID metadata may
change their network ID. The latter use priorities `15000 + preference` and
`22000 + preference`, the observed UID interval, `iif lo`, table `eth0` and mark
mask `0x1ffff`, as defined by the pinned [Android 15 RouteController](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-15.0.0_r23/server/RouteController.cpp).
Every derived selector must have its exact expected multiplicity in both snapshots.
The permission must remain one of `NONE`, `NETWORK` or `SYSTEM`; the global
explicit rule includes the matching permission bits in its mark and mask.
Only `NONE` has a global implicit rule. Per-app selectors remain permission
independent. Default/local UID rules and all other unowned rules remain identical.
The producer and independent release validator each enforce these constraints.
Rejected network observations retain their failure stage.

The report retains the fault observations, recovery action, app controls and
configuration/resource restoration. A separate bounded JSON validator requires
the exact source SHA and every mandatory lifecycle phase, rejects malformed,
missing, skipped or inconsistent evidence, and runs even after lifecycle failure.
Host parser tests validate this gate; the actual emulator run establishes the
kernel and application evidence. This reproduces the recoverable missing-rule
condition from #436; it does not identify which OEM component originally removed
the rules or establish physical ARM64 modem behavior.

## Sustained device observations

Short connectivity rounds and lifecycle acceptance do not establish stability.
`scripts/android-network-soak.py` repeats application-UID HTTPS requests over a
declared wall-clock window and samples the installed core's process generation,
RSS, threads, file descriptors and machine-interface readiness every cycle.
It never switches nodes or restarts the core. Every failed request, latency
spike above the chosen budget, sampled readiness loss, process restart or excess
resource growth fails the run. Missing evidence or an interrupted window is
`INCOMPLETE`, never `PASS`; completed cycles are saved while the run continues.
Measured latency from failed requests also counts toward the latency budget and
summary; missing or non-finite elapsed measurements make the evidence incomplete.
The host tool requires Linux and holds a kernel file lock for each output
directory from initial invalidation through final publication. An overlapping
invocation exits 2 without changing the owner's reports or contacting the device.
Use different output directories for concurrent runs. The persistent `.soak.lock`
file is intentional; the kernel releases its lock when the owning process exits.

The opt-in public benchmark workflow now also requires a 600-second observation
against three public domestic/global targets, with a 1500 ms full-request budget.
The accounting tests run in the automatic harness. Public observations still do
not run on every PR and do not certify a physical OEM phone.
The AVD uses `--root-mode adb` after the existing root-adbd preflight; physical
phones default to `su -M -c`. Both transports must report UID 0 before sampling.

For a connected physical phone, build/install the test-only APK, then run:

```sh
ANDROID_SDK_ROOT=/path/to/sdk bash scripts/build-android-network-probe.sh /tmp/magicnet-probe.apk
adb -s DEVICE_SERIAL install -t --no-incremental /tmp/magicnet-probe.apk
python3 scripts/android-network-soak.py --serial DEVICE_SERIAL \
  --targets tests/android-probe/soak-targets.tsv --output artifacts/device-soak \
  --duration 1800 --interval 20 --max-latency-ms 1000
adb -s DEVICE_SERIAL uninstall best.lmm.magicnet.probe
```

The latency includes DNS, TCP, TLS and the HTTP response; it is not ICMP ping.
Record the active selectors before testing: a service-specific group may remain
pinned to a different node when the main selector changes. Results contain target
IDs rather than URLs or node names. Sampling cannot exclude failures between
samples. The report deliberately does not claim TUN path proof, authenticated
app usability, UDP/QUIC, IPv6, DNS privacy, handover or sleep/wake acceptance.

## TUN path proof

Before public probes, the disposable AVD runs a positive/reject/positive control.
A host loopback server emits a fresh random marker. An adb reverse maps it to
**device loopback only**. The test application connects to `198.18.0.42`, not that
loopback address. A temporary rule must match the installed TUN inbound, the exact
destination/port **and the test app UID**, then override the destination to the
loopback fixture. Success requires the exact marker and one fixture connection.
The reject control must refuse the connection without reaching the fixture; the
second positive must recover. Root remains excluded throughout.

Configuration is saved through the existing private CLI payload/validated editor
and restarted through the normal module lifecycle. The original active config
must be restored and compared before a proof can pass. The helper refuses physical
phones and non-x86 emulator identities. A failed/interrupted restoration is a
failed test: discard the AVD, never publish/cache its mutated disk.

Only the CLI's exact pre-write configuration-lock busy error may be retried,
up to three attempts with a one-second pause. The report counts these retries.
Unknown failures, validator errors and restart errors are not retried. Persistent
contention still fails the proof; restoration must still match the original config.

This proves **one test UID's TCP capture**, not every app's UID, UDP/QUIC, provider
compatibility, DNS privacy, IPv6, sleep/wake or network handover. A sentinel pass
cannot close the real-device Play/GMS issue.

## Installation, deadlines and reports

A separate test ZIP replaces ABI-specific payloads before the real KernelSU
installation. CLI, core, jq and yq are required, with eCapture/Proxylink replaced
when bundled. The production ARM64 archive remains unchanged; fixture preparation
and lifecycle checks reject missing or incompatible runtime payloads. `ksud` is staged under `/sdcard/Download/MagicNet`, then copied to its
actual executable userspace destination; `/sdcard` is not used as executable storage.

The opt-in public phase requires all 13 offline lifecycle cases to pass, including
module uninstall. `android-public-runtime.py prepare` then performs the necessary
single installation and boot of the current complete x86_64 fixture through the
same real KernelSU installer and lifecycle. The public wrapper verifies that
prepared runtime before changing the anonymous feed; it does not install again,
replace executable payloads after installation, attempt stock-kernel KMI/LKM
initialization, reinstall the probe APK, or replay `service.sh`. Module CLI calls
run through real `ksud debug su` and BusyBox standalone semantics; one explicit
CLI restart after the feed update must become machine-ready before health/TUN
checks and probes. The benchmark explicitly selects `--root-mode ksud` with the
prepared report directory, so sentinel configuration changes and restarts use
the same KernelSU transport. All three controls and restoration must pass, then
current executable identity, core generation, domain and readiness are checked
again before any public HTTPS or throughput request. Invalid preparation or
live evidence fails without a fallback and leaves an `INCOMPLETE` summary.
The preparation report is temporary CI evidence, not device canonical state.

Offline acceptance and the optional public runtime use Android x86_64 curl built
from the production curl/OpenSSL/zlib/CA lock. TLS, gzip and libcurl are statically
linked; the CA bundle is embedded without a system-store fallback. Provenance
records the NDK and final ELF identity. Installed execution and local TLS positive/
negative controls establish capability beyond cross-build success. The original
production archive and all 13 offline lifecycle cases remain the acceptance source.

All ADB calls, including `wait-for-device`, have deadlines. Exit diagnostics have
an overall budget and preserve the original test exit code. Process memory that
could not be read is `null`, not an invented zero. No custom corpus URL, config,
subscription token or account login is emitted by the benchmark report.

Reports contain the individual failures, the TUN controls/restoration result,
source commit, scope and explicit `not_tested` fields. The public subscription is
only an anonymous fixture. Public sites and free nodes may fail or reject CI;
that is reported as **FAIL/INCOMPLETE**, not converted into a successful acceptance.

The pristine AVD cache is saved before installation and never after mutation.
The workflow always stops/discards the emulator. Google Play search, images,
actual downloads, GMS and Wi-Fi/mobile transitions still require the affected
physical device and a known-working proxy path.

## BusyBox runtime preflight

Before userspace activation and again inside the KernelSU domain, the offline
lifecycle harness checks BusyBox grep, byte-based awk trimming/user-ID extraction,
and system sed on ASCII module metadata. JSON/Unicode tags use packaged jq, not
the former sed tag extractor. Every reboot repeats the preflight through the
existing late-load path. Matching, nonmatching, whitespace and UTF-8 cases
exercise the supported product operations;
a missing runtime identity, wrong result, crash or timeout fails acceptance.
There is no alternate binary, skipped TUN control or relaxed restoration rule.

The original UTF-8 sed/awk character-set probes reproduced SIGSEGV in both the
manager binary and system Bionic regex implementation. Replacing sed with regex
gsub was insufficient. The product list parsers now trim by byte membership and
extract user IDs before checking ASCII digits. `test-android-utf8.py` executes
these real functions, plus long Unicode JSON and malformed-config controls,
against the unmodified KernelSU binary verified by SHA-256. This is a host
parser regression, not Android networking acceptance or a general Bionic fix.

`simulation.json` retains `provenance.busybox_checks`: SHA-256, the numeric
BusyBox version, stage, per-case exit codes and output-match booleans. Each probe
batch has a 20-second total budget and each command a maximum of three seconds;
partial failure evidence survives in the final report. Raw input/output is not
retained by these new probes.

Exit diagnostics also write `config-regex-exit-codes.json`, repeating only the
three startup grep predicates on the current configuration, suppressing their
output. Exit 1 means no match; 2 indicates an error, and 139 commonly indicates
SIGSEGV through a shell. These are post-failure observations, not proof of which
command failed earlier; node validity and selector consistency still require
the existing product checks. Diagnostics share the existing 25-second budget
and cannot change the acceptance result. A passing preflight is not proof that
BusyBox cannot fail later or on another input.
