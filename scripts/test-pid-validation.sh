#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mksh_bin=$(command -v mksh) || {
    printf 'PID arithmetic regressions require mksh\n' >&2
    exit 1
}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

shells=(bash sh "$mksh_bin")
if command -v busybox >/dev/null 2>&1; then shells+=(busybox); fi
for shell in "${shells[@]}"; do
    MODDIR="$fixture/$(basename "$shell")"
    export MODDIR
    mkdir -p "$MODDIR/lib" "$MODDIR/.state/sing-box"
    ln -s "$ROOT/src/MagicNet/lib/magicnet" "$MODDIR/lib/magicnet"
    shell_command=("$shell")
    if [[ "$shell" == busybox ]]; then shell_command+=(sh); fi
    "${shell_command[@]}" -s <<'SHELL'
set -eu
import() { :; }
set_i18n() { :; }
info() { :; }
warn() { :; }
error() { :; }
. "$MODDIR/lib/magicnet/common.sh"
. "$MODDIR/lib/magicnet/singbox_subscribe/update.sh"
. "$MODDIR/lib/magicnet/singbox_subscribe/config.sh"
. "$MODDIR/lib/magicnet/singbox_lifecycle.sh"

assert_rc() {
    test_expected=$1
    shift
    if "$@"; then test_actual=0; else test_actual=$?; fi
    [ "$test_actual" -eq "$test_expected" ] || {
        echo "unexpected status: expected=$test_expected actual=$test_actual command=$*" >&2
        exit 1
    }
}

# Read the real shell's proc identity through the existing test seam. The
# production Rust proc reader is not available in this shell-only host test.
magicnet_proc_reader_test_hook() (
    [ "$1" = stat ] && [ "${PID_TEST_PROC_ERROR:-0}" = 0 ] || return 2
    IFS= read -r test_stat <"$2/$3/stat" || return 2
    test_tail=${test_stat##*) }
    # shellcheck disable=SC2086 # proc fields are whitespace-separated.
    set -- $test_tail
    [ "$#" -ge 20 ] || return 2
    test_state=$1
    shift 19
    echo "$test_state $1"
)

# Both stop paths must reject malformed PIDs before reaching kill. The mock
# records calls, so no real process receives a signal during this regression.
kill() { echo "$*" >>"$MODDIR/signals"; }

# Validation must also work with no external commands available. In mksh the
# old comparison rejects every positive PID; changing only the upper bound
# would still accept wrapped inputs such as 2147483648 and 4294967297.
test_path=$PATH
PATH=/no-external-pid-validator
for pid in 1 9 10 999999 4194304 999999999 1000000000 1999999999 \
    2000000000 2147483640 2147483646 2147483647; do
    assert_rc 0 magicnet_pid_valid "$pid"
done
for pid in '' 0 00 01 0000000001 -1 +1 1.0 '1+1' '1 ' ' 1' 1a \
    2147483648 2147483649 2147483650 2999999999 4294967295 \
    4294967296 4294967297 6442450943 9999999999 10000000000 \
    999999999999999999999999999; do
    assert_rc 1 magicnet_pid_valid "$pid"
done
assert_rc 1 magicnet_pid_valid
PATH=$test_path
export PATH

start=$(magicnet_proc_start "$$")
assert_rc 0 magicnet_config_lock_owner_matches "$$:$start"
assert_rc 0 magicnet_config_lock_owner_matches "$$"
assert_rc 1 magicnet_config_lock_owner_matches "$$:0"
# pid_t's maximum is valid syntax but outside Linux's allocatable PID range.
test ! -d /proc/2147483647
assert_rc 1 magicnet_config_lock_owner_matches '2147483647:1'

mkdir "$MODDIR/.state/config.lock"
echo "$$:$start" >"$MODDIR/.state/config.lock/pid"
PID_TEST_PROC_ERROR=1
assert_rc 2 magicnet_config_lock_owner_matches "$$:$start"
assert_rc 1 magicnet_config_lock_reclaim "$$:$start"
test "$(cat "$MODDIR/.state/config.lock/pid")" = "$$:$start"
PID_TEST_PROC_ERROR=0
magicnet_config_lock_release
test ! -e "$MODDIR/.state/config.lock"

mkdir "$MODDIR/.state/config.lock"
echo '2147483647:1' >"$MODDIR/.state/config.lock/pid"
magicnet_config_lock_acquire
test "$(cat "$MODDIR/.state/config.lock/pid")" = "$$:$start"
magicnet_config_lock_release
test ! -e "$MODDIR/.state/config.lock"

update_lock="$MODDIR/.state/sing-box/subscription-update.lock"
mkdir "$update_lock"
echo "$$:$start:nonce" >"$update_lock/owner"
assert_rc 0 magicnet_singbox_update_lock_live
PID_TEST_PROC_ERROR=1
assert_rc 2 magicnet_singbox_update_lock_live
assert_rc 0 magicnet_singbox_update_lock_active
test "$(cat "$update_lock/owner")" = "$$:$start:nonce"
PID_TEST_PROC_ERROR=0
echo '2147483647:1:nonce' >"$update_lock/owner"
assert_rc 1 magicnet_singbox_update_lock_live
assert_rc 1 magicnet_singbox_update_lock_active
test ! -e "$update_lock"

for pid in '' 0 01 -1 2147483648 4294967295 4294967296 4294967297 \
    9999999999 999999999999999999999999; do
    mkdir "$MODDIR/.state/config.lock" "$update_lock"
    echo "$pid:1" >"$MODDIR/.state/config.lock/pid"
    echo "$pid:1:nonce" >"$update_lock/owner"
    assert_rc 2 magicnet_config_lock_owner_matches "$pid:1"
    assert_rc 1 magicnet_config_lock_reclaim "$pid:1"
    assert_rc 2 magicnet_singbox_update_lock_live
    assert_rc 0 magicnet_singbox_update_lock_active
    test "$(cat "$MODDIR/.state/config.lock/pid")" = "$pid:1"
    test "$(cat "$update_lock/owner")" = "$pid:1:nonce"
    rm "$MODDIR/.state/config.lock/pid" "$update_lock/owner"
    rmdir "$MODDIR/.state/config.lock" "$update_lock"

    echo "$pid" >"$MODDIR/pids"
    : >"$MODDIR/signals"
    assert_rc 2 singbox_signal_pids_file "$MODDIR/pids" 15
    assert_rc 2 magicnet_singbox_signal_pids_file "$MODDIR/pids" 15 config.json
    test ! -s "$MODDIR/signals"
done

echo 1 >"$MODDIR/pids"
: >"$MODDIR/signals"
singbox_signal_pids_file "$MODDIR/pids" 15
magicnet_singbox_signal_pids_file "$MODDIR/pids" 9 config.json
test "$(cat "$MODDIR/signals")" = '-15 1
-9 1'
echo "PID range, lock recovery, and signal validation passed (${KSH_VERSION:-$0})"
SHELL
done
