#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=hooks/lib/utils.sh
. "$KAM_HOOKS_ROOT/lib/utils.sh"
PROJECT_ROOT="${KAM_PROJECT_ROOT:-$(cd "$KAM_HOOKS_ROOT/.." && pwd)}"
TARGET_DIR="${KAM_MODULE_ROOT}/bin"
LICENSE_DIR="${KAM_MODULE_ROOT}/licenses/curl"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

bash "$PROJECT_ROOT/scripts/build-android-curl.sh" arm64-v8a "$WORK/result"
python3 "$PROJECT_ROOT/scripts/android-curl-artifact.py" verify "$WORK/result" --abi arm64-v8a
# Source tarballs and the standalone CA test copy stay outside the payload;
# curl contains the CA bytes and carries their unchanged license notices.
mkdir -p "$TARGET_DIR" "$LICENSE_DIR"
for name in curl-COPYING.txt OpenSSL-LICENSE.txt zlib-README.txt Mozilla-CA-NOTICE.txt; do
    install -m 0644 "$WORK/result/licenses/$name" "$LICENSE_DIR/$name"
done
install -m 0644 "$WORK/result/build-provenance.json" "$LICENSE_DIR/build-provenance.json"
install -m 0755 "$WORK/result/curl" "$TARGET_DIR/curl"
log_success "Installed production Android arm64 curl with embedded CA and source/license provenance"
