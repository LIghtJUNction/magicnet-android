# MagicNet Workflows

MagicNet keeps code quality, packaging and real-device simulation separate.
See [Android simulation](../../docs/android-simulation.md) for the acceptance
phases, safety boundaries, cache policy and remaining coverage limits.

## android-kernelsu-acceptance.yml

This runs on every pull request, merge group, push to `main` and manual dispatch.
Uncached harness checks precede an Android 15 x86_64 AVD booted with a
source-pinned API35/6.6 KernelSU v3.2.0 kernel built from manifest 12525588.
The revision-9 SDK image and cached kernel outputs are integrity-checked before boot. Official x86_64 `ksud` then
requires that kernel interface to be active and uses upstream `late-load` for
userspace/lifecycle initialization after each boot. The automatic path uses a
local fixture, real KernelSU installation/reboots and app-UID TUN controls.
`Android Simulation Gate` rejects failed or unexecuted jobs. Its required-check
status in branch protection must be configured separately.

The former `init.yml` was removed. Its `kam validate`, `kam check`, release-workflow,
subscription-usage and artifact-cleanup tests now run in the Android build job
before packaging. The Code Quality shell lint remains in place.

The reusable entry also accepts `source_sha`, `release_version`, and
`release_version_code`. Main-repository releases verify the pinned source SHA
and inject the same target metadata before the harness and Android build.

## exec.yml

`exec.yml` builds and verifies the source repository on `push` to `main`,
`pull_request`, and manual dispatch. It has read-only repository permissions and
uploads Actions artifacts. Manual `force_tests=true` ignores cached test results;
`release_quality=true` runs the full build quality suite.

The reusable workflow accepts an immutable `source_sha`, a `recipe_sha`, the
selected `release_version` and `release_version_code`, and `release_quality`.
It checks out that source commit and stamps the selected metadata in the build
workspace. The source commit remains unchanged. Its `artifact_id` output lets
the caller select the exact build artifact.

### Build, verify, or publish a version

Use [Build and release MagicNet](https://github.com/LIghtJUNction/MagicNet/actions/workflows/release.yml)
in the **main MagicNet repository**, selecting **main** in **Run workflow**.
That workflow owns version selection, release snapshots, GitHub Releases and the
stable update index. The complete procedure is in the
[release guide](https://github.com/LIghtJUNction/MagicNet/blob/main/docs/releasing.md).

| `mode` | Result |
| --- | --- |
| `build` | Build and validate packages; upload Actions artifacts. This is the default. |
| `verify` | Also run every release quality check and Android/KernelSU acceptance; create no Release. |
| `publish` | Run the same gates, publish a Release, then update the stable index for a stable release. |

Select `bump=patch`, `minor`, or `major` to increment the newer source/published
version. To choose an exact version, set `bump=none` and enter `version=1.9.0`
or `v1.9.0`. With `bump=none` and an empty `version`, use the source-declared version.

Leave `version_code` empty for automatic selection: an unchanged version keeps
the source code; a changed version increments the larger source/published code.
An explicit code must be an integer from `1` to `2147483647`; publication requires
a code greater than previously published versions. `build` and `verify` use the
main repository's stable index as their preview baseline; `publish` also checks
public GitHub Releases, including prereleases.

Leave `source_ref` empty to use the main repository's pinned source gitlink.
Set it to `main`, a branch, tag, or full SHA to select another source revision;
the workflow resolves it to one immutable commit for both build and Android
acceptance. Select a commit that contains the new reusable workflow and
`scripts/stamp-release.py`; older source revisions lack this release interface.

For example, `mode=verify`, `bump=patch`, `source_ref=main` validates the next patch
from the latest source. Change `mode` to `publish` to publish it. Set
`prerelease=true` only with `mode=publish`; prereleases leave the stable update
index unchanged.

Official packages and download URLs belong to `LIghtJUNction/MagicNet`.
Artifacts include `update.json`, `build-source.json` with the selected source and
recipe SHAs, and a verified `SHA256SUMS` manifest. Release tags target the main
repository's fixed release snapshot. Existing published assets are not
overwritten; recovery uses the original run and snapshot as described in the
release guide.

### Build caches

Go module downloads and compiled packages are cached with keys covering the Go
version, NDK, module lockfiles, fork revision, and build-script inputs. A new fork
revision restores compatible previous entries and saves an updated cache after a
successful job, avoiding a permanently frozen cache keyed only by `go.sum`.

Rust caches include registry/git dependencies and `target/`. Module and quality
jobs have separate namespaces; keys include the compiler, lockfile/configuration,
and workspace sources, plus the NDK for Android builds. Restore prefixes retain
compatible dependency outputs across source and lockfile changes. Cargo still
checks fingerprints; the workflow never skips compilation based only on a cache hit.

`cargo-ndk` is pinned and cached in its own install directory; exact hits skip
`cargo install`. Node/npm and Bun download caches cover either WebUI package
manager. Tests, type checks, packaging, checksums, and smoke tests still run.
No final release ZIP is included in these new caches.

Only Kam's own cache is enabled in setup-kam. Its whole-`~/.rustup` cache is
disabled so it cannot overwrite a freshly installed Rust toolchain. The release
build installs its required `aarch64-linux-android` target; the AVD job also
installs `x86_64-linux-android`. The first run populates the new namespaces;
real speedups depend on later hits.

## quality.yml

`quality.yml` keeps code-level checks independent from packaging:

- Rust: formatting, Clippy with warnings denied, and workspace tests using locked dependencies and all targets/features.
- Shell: `bash scripts/lint-shell.sh` checks host tooling and first-party device scripts, including sourced runtime fragments. `bash scripts/test-host.sh` runs fixture-based regressions.
- WebUI: `npm ci` installs locked dependencies; `npm run check` runs tests, Vue component type checking with `vue-tsc`, and the build. After Chromium installation, `npm run test:ui` covers phone, landscape and desktop layouts, modal focus, keyboard clearance and draft retention. Browser fixtures do not access a device.

Local `scripts/pre-commit.sh` reuses these entrypoints and passes
`--with-routing-assets` to include the routing/DNS integration tests that require
a host sing-box binary and prepared rule sets. The CI fixture suite excludes
those two checks. Device, packaging, and installation checks remain separate.

## On-demand previews and network observations

`webui-preview.yml` replaces the duplicate automatic `webui.yml` check. It exports
source and built preview artifacts on manual dispatch; Code Quality owns automatic
WebUI tests. Public endpoints in `network-regression.yml` are observed only on
manual dispatch. Its real DNS NAT packet tests run without cached passes.

`public_benchmark=false` is the default for Android dispatch. Enabling it adds the
legacy public-proxy observation after offline acceptance; it does not substitute
for lifecycle or app-UID proof. Installation-onboarding, uninstall-browser,
network-evidence and rules-release workflows retain their distinct checks.

## Local customization

These are the MagicNet-specific workflows, not an unmodified shared baseline.
Review `kam sync workflow` changes so it does not reintroduce the removed
standalone validation or duplicate automatic WebUI jobs.
