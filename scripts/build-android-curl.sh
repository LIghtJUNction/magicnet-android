#!/usr/bin/env bash
# Shared production builder. Target ELF is inspected, never executed on the host.
set -Eeuo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { printf '[android-curl] ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# -eq 2 ]] || fail 'usage: build-android-curl.sh <arm64-v8a|x86_64> OUTPUT_DIRECTORY'
case "$1" in
    arm64-v8a|arm64) ABI=arm64-v8a; TRIPLE=aarch64-linux-android; OPENSSL_TARGET=android-arm64 ;;
    x86_64|amd64) ABI=x86_64; TRIPLE=x86_64-linux-android; OPENSSL_TARGET=android-x86_64 ;;
    *) fail 'unsupported Android curl ABI' ;;
esac
OUT="$2"
[[ ! -L "$OUT" ]] || fail 'output directory must not be a symlink'
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
# Build privately; callers consume the output only after this command and the
# complete-set verifier succeed. No cached target ELF is treated as a build.
WORK="$(mktemp -d)"
finish() {
    local result=$?
    trap - EXIT
    rm -rf "$WORK"
    exit "$result"
}
trap finish EXIT
for tool in curl python3 sha256sum make perl pkg-config install timeout; do
    command -v "$tool" >/dev/null || fail "required host tool unavailable: $tool"
done
PKG_CONFIG_ABS="$(command -v pkg-config)"
JOBS="${MAGICNET_CURL_JOBS:-2}"
[[ "$JOBS" =~ ^[1-8]$ ]] || fail 'build jobs must be 1..8'
LOCK_FIELDS="$(python3 "$ROOT/scripts/android-curl-artifact.py" lock-fields)"
mapfile -t INPUTS <<<"$LOCK_FIELDS"
[[ "${#INPUTS[@]}" -eq 16 ]] || fail 'invalid source lock fields'
API="${INPUTS[0]}"
CURL_VERSION="${INPUTS[1]}" OPENSSL_VERSION="${INPUTS[2]}" ZLIB_VERSION="${INPUTS[3]}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$NDK" && -d "${ANDROID_HOME:-/nonexistent}/ndk" ]]; then
    NDK="$(find "$ANDROID_HOME/ndk" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
fi
NDK="${NDK:-/opt/android-ndk}"
TOOLS="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
[[ -f "$NDK/source.properties" ]] || fail 'Android NDK identity unavailable'
for tool in "${TRIPLE}${API}-clang" llvm-ar llvm-ranlib llvm-nm llvm-strip; do
    [[ -x "$TOOLS/$tool" ]] || fail "Android NDK target tool unavailable: $tool"
done
NDK_SHA="$(sha256sum "$NDK/source.properties" | cut -d ' ' -f 1)"
[[ -z "${MAGICNET_CURL_NDK_SHA256:-}" || "$NDK_SHA" == "$MAGICNET_CURL_NDK_SHA256" ]] ||
    fail 'Android NDK differs from the workflow fingerprint'
fetch() {
    local name="$1" url="$2" expected="$3" cache="${MAGICNET_CURL_SOURCE_CACHE:-}"
    if [[ -n "$cache" && -f "$cache/$name" ]]; then
        cp "$cache/$name" "$WORK/$name"
    else
        timeout --kill-after=5s 240s curl -q --fail --location --silent --show-error \
            --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 180 \
            --retry 2 "$url" -o "$WORK/$name"
    fi
    printf '%s  %s\n' "$expected" "$WORK/$name" | sha256sum --check --strict
    if [[ -n "$cache" && ! -f "$cache/$name" ]]; then
        mkdir -p "$cache"
        cp "$WORK/$name" "$cache/$name.partial.$$"
        mv -f "$cache/$name.partial.$$" "$cache/$name"
    fi
}
for index in 4 7 10 13; do
    fetch "${INPUTS[$index]}" "${INPUTS[$((index + 1))]}" "${INPUTS[$((index + 2))]}"
done
python3 - "$WORK" "${INPUTS[4]}" "${INPUTS[7]}" "${INPUTS[10]}" <<'PY'
from pathlib import Path
import sys
import tarfile
root = Path(sys.argv[1])
for name in sys.argv[2:]:
    with tarfile.open(root / name) as archive:
        members = archive.getmembers()
        if len(members) > 30000 or sum(max(0, m.size) for m in members) > 512 * 1024 * 1024:
            raise SystemExit('source archive exceeds budget')
        archive.extractall(root, members=members, filter='data')
PY
PREFIX="$WORK/prefix"
unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LIBS CC CXX AR RANLIB NM STRIP \
    PKG_CONFIG PKG_CONFIG_PATH PKG_CONFIG_SYSROOT_DIR LIBRARY_PATH LD_LIBRARY_PATH LD_PRELOAD \
    CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH CONFIG_SITE CROSS_COMPILE CROSS_SYSROOT \
    MAKEFLAGS MAKEOVERRIDES MFLAGS GNUMAKEFLAGS
export ANDROID_NDK_ROOT="$NDK" PATH="$TOOLS:$PATH"
export CC="$TOOLS/${TRIPLE}${API}-clang" AR="$TOOLS/llvm-ar"
export RANLIB="$TOOLS/llvm-ranlib" NM="$TOOLS/llvm-nm" STRIP="$TOOLS/llvm-strip"
export CFLAGS='-O2 -fPIC -ffunction-sections -fdata-sections'
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" PKG_CONFIG_PATH=''
export PKG_CONFIG="$PKG_CONFIG_ABS"
(
    cd "$WORK/zlib-$ZLIB_VERSION"
    timeout 60 ./configure --static --prefix="$PREFIX"
    timeout --kill-after=5s 180s make -j"$JOBS"
    timeout 60 make install
)
(
    cd "$WORK/openssl-$OPENSSL_VERSION"
    CC=clang timeout 60 perl Configure "$OPENSSL_TARGET" "-D__ANDROID_API__=$API" \
        no-shared no-module no-tests no-dso --prefix="$PREFIX" --libdir=lib \
        --openssldir=/nonexistent/magicnet-curl
    timeout --kill-after=5s 600s make -j"$JOBS" build_libs
    timeout 60 make install_dev
)
export CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib -Wl,--gc-sections"
export LIBS='-lssl -lcrypto -lz -ldl'
(
    cd "$WORK/curl-$CURL_VERSION"
    timeout 180 ./configure --enable-option-checking=fatal --host="$TRIPLE" \
        --with-pic --disable-shared --enable-static --with-openssl="$PREFIX" --with-zlib="$PREFIX" \
        --with-ca-embed="$WORK/${INPUTS[13]}" --without-ca-bundle --without-ca-path \
        --without-ca-fallback --disable-openssl-auto-load-config --without-libpsl --without-libidn2 \
        --without-brotli --without-zstd --without-nghttp2 --without-nghttp3 --without-ngtcp2 \
        --without-quiche --disable-ares --enable-threaded-resolver --disable-ldap --disable-ldaps
    timeout --kill-after=5s 300s make -j"$JOBS"
    "$STRIP" src/curl
)
STAGED="$WORK/result"
mkdir "$STAGED"
install -m 0755 "$WORK/curl-$CURL_VERSION/src/curl" "$STAGED/curl"
install -m 0644 "$WORK/${INPUTS[13]}" "$STAGED/cacert.pem"
python3 "$ROOT/scripts/android-curl-artifact.py" record --abi "$ABI" --folder "$STAGED" \
    --source "$WORK" --ndk "$NDK/source.properties" --compiler "$CC"
python3 "$ROOT/scripts/android-curl-artifact.py" verify "$STAGED" --abi "$ABI" --ndk-sha256 "$NDK_SHA"
# Output directories are build workspaces; fixed names are owned by this builder.
for name in curl cacert.pem build-provenance.json licenses; do
    [[ ! -L "$OUT/$name" ]] || fail 'refusing an output symlink'
done
rm -rf "$OUT/licenses"
cp -a "$STAGED/licenses" "$OUT/licenses"
install -m 0644 "$STAGED/cacert.pem" "$OUT/cacert.pem"
install -m 0644 "$STAGED/build-provenance.json" "$OUT/build-provenance.json"
install -m 0755 "$STAGED/curl" "$OUT/curl"
printf '[android-curl] Android %s/API%s built; runtime HTTPS capability NOT TESTED\n' "$ABI" "$API"
