#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
GO="${MAGICNET_GO:-$PROJECT_ROOT/.tools/go/bin/go}"
export GOTOOLCHAIN=local
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOMODCACHE="${GOMODCACHE:-$PROJECT_ROOT/.tools/gomodcache}"
export GOCACHE="${GOCACHE:-$PROJECT_ROOT/.tools/gocache}"
JDK="${MAGICNET_JDK:-$PROJECT_ROOT/.tools/jdk-21.0.9+10}"
CORE_REVISION=871b7a3440cd9c850f1b09ef3b4ada9babb4384b
CORE_TAGS=with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,with_tailscale,with_ebpf,with_xhttp,with_awg,badlinkname,tfogo_checklinkname0
build_cli() {
  cd "$PROJECT_ROOT"
  # A Git checkout/worktree must own its .git marker. An unpacked archive
  # never inherits VCS identity from an enclosing repository or environment.
  local identity source_mode source_revision control_git_dir build_vcs target
  local -a build_identity git_environment targets
  identity="$(python3 scripts/product_metadata.py --build-identity)"
  mapfile -t build_identity <<< "$identity"
  source_mode="${build_identity[0]}"; source_revision="${build_identity[1]}"
  git_environment=(env -u GIT_DIR -u GIT_WORK_TREE -u GIT_COMMON_DIR -u GIT_INDEX_FILE)
  if [[ "$source_mode" = git ]]; then
    control_git_dir="${build_identity[2]}"
    git_environment+=("GIT_DIR=$control_git_dir" "GIT_WORK_TREE=$PROJECT_ROOT")
    build_vcs=true
  else
    build_vcs=false
  fi
  if [[ "${1:-}" = linux-only ]]; then targets=(linux/amd64); else targets=(linux/amd64 android/arm64); fi
  for target in "${targets[@]}"; do
    target_os="${target%/*}"; target_arch="${target#*/}"; out="$PROJECT_ROOT/assets/bin/$target_os-$target_arch"
    mkdir -p "$out"
    "${git_environment[@]}" CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO" build -p "${MAGICNET_BUILD_JOBS:-1}" -trimpath "-buildvcs=$build_vcs" -ldflags "-s -w -X magicnet.local/rebuild/internal/magicnet.Commit=$source_revision" -o "$out/magicnet-cli" ./cmd/magicnet
    if [[ "${1:-}" != linux-only ]]; then
      "${git_environment[@]}" CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO" build -p "${MAGICNET_BUILD_JOBS:-1}" -trimpath "-buildvcs=$build_vcs" -ldflags '-s -w' -o "$out/magicnet-installer" ./module/installer
    fi
  done
}
build_core() {
  cd "$PROJECT_ROOT/third_party/sing-box"
  test "$(git rev-parse HEAD)" = "$CORE_REVISION"
  test -z "$(git status --porcelain --untracked-files=no)"
  for target in linux/amd64 android/arm64; do
    target_os="${target%/*}"; target_arch="${target#*/}"; out="$PROJECT_ROOT/assets/bin/$target_os-$target_arch"
    mkdir -p "$out"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "$GO" build -p "${MAGICNET_BUILD_JOBS:-1}" -trimpath -buildvcs=true -tags "$CORE_TAGS" -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.15.0-alpha.10-magicnet.871b7a3440cd -checklinkname=0 -s -w" -o "$out/sing-box" ./cmd/sing-box
  done
  "$PROJECT_ROOT/assets/bin/linux-amd64/sing-box" version
}
build_java() {
  cd "$PROJECT_ROOT"
  rm -rf "$PROJECT_ROOT/.tools/java-classes" "$PROJECT_ROOT/.tools/dex"
  mkdir -p .tools/java-classes .tools/dex assets/bin/android-arm64
  "$JDK/bin/javac" --release 8 -Xlint:-options -d .tools/java-classes module/java/MagicNetBridge.java
  "$JDK/bin/java" -cp .tools/r8-8.10.21.jar com.android.tools.r8.D8 --min-api 26 --output .tools/dex .tools/java-classes/*.class
  python3 - <<'PY'
import hashlib, pathlib
source = pathlib.Path('module/java/MagicNetBridge.java').read_bytes()
pathlib.Path('.tools/bridge-manifest.mf').write_text('Manifest-Version: 1.0\nMagicNet-Source-SHA256: '+hashlib.sha256(source).hexdigest()+'\nMagicNet-D8-Version: 8.10.21\nMagicNet-Min-API: 26\n\n')
PY
  "$JDK/bin/jar" --create --file assets/bin/android-arm64/magicnet-bridge.jar --manifest .tools/bridge-manifest.mf --date=2026-01-01T00:00:00Z -C .tools/dex classes.dex
}
case "${1:-all}" in
  cli) build_cli;;
  cli-linux) build_cli linux-only;;
  core) build_core;;
  java) build_java;;
  all) build_core; build_cli; build_java; cd "$PROJECT_ROOT"; python3 scripts/import-rules.py; python3 scripts/download-license-sources.py; python3 scripts/collect-licenses.py; python3 scripts/prepare-vendor.py; python3 scripts/write-build-metadata.py; python3 scripts/package.py;;
  *) printf '%s\n' 'Usage: scripts/build.sh [all|cli|cli-linux|core|java]' >&2; exit 2;;
esac
