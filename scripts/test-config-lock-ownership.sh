#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mksh_bin=$(command -v mksh) || {
    printf 'Config lock ownership regressions require mksh\n' >&2
    exit 1
}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

shells=(bash sh "$mksh_bin")
if command -v busybox >/dev/null 2>&1; then shells+=(busybox); fi
for shell in "${shells[@]}"; do
    MODDIR="$fixture/$(basename "$shell")"
    export MODDIR
    mkdir -p "$MODDIR/lib"
    ln -s "$ROOT/src/MagicNet/lib/magicnet" "$MODDIR/lib/magicnet"
    shell_command=("$shell")
    if [[ "$shell" == busybox ]]; then shell_command+=(sh); fi
    timeout 20 "${shell_command[@]}" -s <<'SHELL'
set -eu
import() { :; }
warn() { :; }
. "$MODDIR/lib/magicnet/common.sh"

# Exercise real shell PIDs/starttimes without requiring a Rust build. Keep
# fault injection limited to the existing bounded proc-reader test seam.
magicnet_proc_reader_test_hook() (
    [ "$1" = stat ] && [ "${LOCK_TEST_PROC_ERROR:-0}" = 0 ] || return 2
    IFS= read -r test_stat <"$2/$3/stat" || return 2
    test_tail=${test_stat##*) }
    # shellcheck disable=SC2086 # Linux proc stat has whitespace-separated fields.
    set -- $test_tail
    [ "$#" -ge 20 ] || return 2
    test_state=$1
    shift 19
    printf '%s %s\n' "$test_state" "$1"
)
assert_rc() {
    test_expected=$1
    shift
    if "$@"; then test_actual=0; else test_actual=$?; fi
    [ "$test_actual" -eq "$test_expected" ] || {
        printf 'expected=%s actual=%s command=%s\n' "$test_expected" "$test_actual" "$*" >&2
        exit 1
    }
}
worker=''
cleanup() {
    if [ -n "$worker" ]; then
        kill -KILL "$worker" 2>/dev/null || true
        wait "$worker" 2>/dev/null || true
    fi
}
trap cleanup EXIT
marker="$MODDIR/.state/config.lock/pid"
parent_start=$(magicnet_proc_start "$$")

# A nested callback reuses the current critical section. It must neither
# overwrite the acquired token nor release it before the outer callback ends.
inner() { test "$(cat "$marker")" = "$MAGICNET_CONFIG_LOCK_OWNER"; }
outer() {
    first_owner=$MAGICNET_CONFIG_LOCK_OWNER
    magicnet_with_config_lock inner
    test "$(cat "$marker")" = "$first_owner"
}
magicnet_with_config_lock outer
test ! -e "${marker%/pid}"
test -z "${MAGICNET_CONFIG_LOCK_OWNER:-}"
fail_callback() { return 7; }
assert_rc 7 magicnet_with_config_lock fail_callback
test ! -e "${marker%/pid}"

# Failed acquisition must preserve the prior acquired identity, including in
# a child which inherited it. That child cannot release the live parent lock.
magicnet_config_lock_acquire
parent_owner=$MAGICNET_CONFIG_LOCK_OWNER
test "$parent_owner" = "$$:$parent_start"
MAGICNET_CONFIG_LOCK_TIMEOUT=0 assert_rc 1 magicnet_config_lock_acquire
test "$MAGICNET_CONFIG_LOCK_OWNER" = "$parent_owner"
(
    magicnet_config_lock_release
    test "$(cat "$marker")" = "$parent_owner"
    MAGICNET_CONFIG_LOCK_OWNER=$parent_owner
    MAGICNET_CONFIG_LOCK_TIMEOUT=0 assert_rc 1 magicnet_config_lock_acquire
    test "$MAGICNET_CONFIG_LOCK_OWNER" = "$parent_owner"
    magicnet_config_lock_release
    test "$(cat "$marker")" = "$parent_owner"
)
magicnet_config_lock_release
test ! -e "${marker%/pid}"

# Release uses the exact successful token if a later starttime probe fails.
# Conversely, a PID-only acquisition remains releasable when probes recover.
magicnet_config_lock_acquire
LOCK_TEST_PROC_ERROR=1 magicnet_config_lock_release
test ! -e "${marker%/pid}"
LOCK_TEST_PROC_ERROR=1 magicnet_config_lock_acquire
test "$MAGICNET_CONFIG_LOCK_OWNER" = "$$"
magicnet_config_lock_release
test ! -e "${marker%/pid}"

# Legacy PID-only markers remain supported. A PID/starttime marker without a
# cached acquisition token stays untouched when its identity is unreadable.
mkdir "${marker%/pid}"
printf '%s\n' "$$" >"$marker"
magicnet_config_lock_release
test ! -e "${marker%/pid}"
mkdir "${marker%/pid}"
printf '%s\n' "$$:$parent_start" >"$marker"
LOCK_TEST_PROC_ERROR=1 assert_rc 2 magicnet_config_lock_release
test "$(cat "$marker")" = "$$:$parent_start"
magicnet_config_lock_release
test ! -e "${marker%/pid}"

# The background critical section belongs to the worker, not to $$, which
# remains the live parent in all supported shells. Killing only that worker
# must make its lock reclaimable while the parent continues to run.
mkfifo "$MODDIR/hold"
critical_work() {
    : >"$MODDIR/acquired"
    read -r unused <"$MODDIR/hold"
}
(magicnet_with_config_lock critical_work) &
worker=$!
attempt=0
while [ ! -e "$MODDIR/acquired" ] && [ "$attempt" -lt 200 ]; do
    sleep 0.01
    attempt=$((attempt + 1))
done
test -e "$MODDIR/acquired"
worker_owner=$(cat "$marker")
test "${worker_owner%%:*}" = "$worker"
test "$worker" != "$$"
MAGICNET_CONFIG_LOCK_TIMEOUT=0 assert_rc 1 magicnet_config_lock_acquire
test "$(cat "$marker")" = "$worker_owner"
kill -KILL "$worker"
wait "$worker" 2>/dev/null || true
worker=''
kill -0 "$$"
MAGICNET_CONFIG_LOCK_TIMEOUT=0 magicnet_config_lock_acquire
test "$(cat "$marker")" = "$$:$parent_start"
magicnet_config_lock_release
test ! -e "${marker%/pid}"
SHELL
    printf 'Config lock ownership passed: %s\n' "${shell##*/}"
done
