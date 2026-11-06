#!/usr/bin/env bash
# Compatibility entry point: public CI uses the same production Android curl.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -eq 1 ]] || { printf '%s\n' 'usage: prepare-android-public-curl.sh OUTPUT_DIRECTORY' >&2; exit 1; }
OUT="$1"
[[ ! -L "$OUT" ]] || { printf '%s\n' 'output directory must not be a symlink' >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# An unsuccessful compatibility preparation must not attest an earlier build.
rm -f "$OUT/curl" "$OUT/cacert.pem" "$OUT/build-provenance.json"
export MAGICNET_CURL_JOBS="${MAGICNET_CURL_JOBS:-${MAGICNET_PUBLIC_CURL_JOBS:-2}}"
export MAGICNET_CURL_SOURCE_CACHE="${MAGICNET_CURL_SOURCE_CACHE:-${MAGICNET_PUBLIC_CURL_SOURCE_CACHE:-}}"
export MAGICNET_CURL_NDK_SHA256="${MAGICNET_CURL_NDK_SHA256:-${MAGICNET_PUBLIC_CURL_NDK_SHA256:-}}"
exec bash "$ROOT/scripts/build-android-curl.sh" x86_64 "$OUT"
