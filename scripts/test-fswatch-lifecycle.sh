#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mksh_bin=$(command -v mksh) || {
    printf 'Fswatch lifecycle regressions require mksh\n' >&2
    exit 1
}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

shells=(bash sh "$mksh_bin")
if command -v busybox >/dev/null 2>&1; then shells+=(busybox); fi
for shell in "${shells[@]}"; do
    MODDIR="$fixture/$(basename "$shell")"
    export MODDIR
    mkdir -p "$MODDIR/lib" "$MODDIR/.config" "$MODDIR/.log"
    ln -s "$ROOT/src/MagicNet/lib/magicnet" "$MODDIR/lib/magicnet"
    : >"$MODDIR/cli"
    shell_command=("$shell")
    if [[ "$shell" == busybox ]]; then shell_command+=(sh); fi
    timeout 20 "${shell_command[@]}" -s <<'SHELL'
set -eu
import() { :; }
set_i18n() { :; }
warn() { printf '%s\n' "$*" >&2; }
i18n() { printf '%s\n' "$1"; }
t() { cat; }
magicnet_json_escape() { printf '%s' "$1"; }
. "$MODDIR/lib/magicnet/common.sh"
. "$MODDIR/lib/magicnet/supervisors.sh"
magicnet_module_disabled() { return 1; }
magicnet_trim_log_file() { :; }
guard="$MODDIR/.state/fswatch/magicnet-config.lifecycle.lock"
pid_file="$MODDIR/.state/fswatch/magicnet-config.pid"
events="$MODDIR/events"
exec 7>"$MODDIR/other-descriptor"
job_one=''
job_two=''
stop_job=''
cleanup() {
    : >"$MODDIR/resume-status"
    : >"$MODDIR/resume-launch"
    for job in "$job_one" "$job_two" "$stop_job"; do
        [ -z "$job" ] || wait "$job" 2>/dev/null || true
    done
    if [ -s "$pid_file" ]; then
        read -r managed_pid <"$pid_file"
        kill "$managed_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
wait_for() {
    wait_attempt=0
    while [ ! -e "$1" ] && [ "$wait_attempt" -lt 200 ]; do
        sleep 0.01
        wait_attempt=$((wait_attempt + 1))
    done
    test -e "$1"
}
assert_guard_held() {
    if flock -n "$guard" true; then
        printf 'fswatch mutation escaped lifecycle serialization\n' >&2
        return 1
    fi
}

# Model the kamfw contract: start always replaces/publishes a worker. Pause
# two initial status reads at the actual check/start boundary so both callers
# see stopped, then let MagicNet decide how many launches are needed.
fswatch() {
    case "$1" in
    status)
        if [ "${FSWATCH_TEST_INITIAL_BARRIER:-0}" = 1 ] && [ "${mock_status_seen:-0}" = 0 ]; then
            mock_status_seen=1
            IFS=' ' read -r mock_self mock_stat </proc/self/stat
            : >"$MODDIR/status-$mock_self"
            wait_for "$MODDIR/resume-status"
            return 1
        fi
        [ -s "$pid_file" ] || return 1
        read -r mock_pid <"$pid_file"
        kill -0 "$mock_pid"
        ;;
    start)
        assert_guard_held
        printf 'retained\n' >&7
        printf 'start\n' >>"$events"
        if [ "${FSWATCH_TEST_PAUSE_LAUNCH:-0}" = 1 ]; then
            : >"$MODDIR/launch-paused"
            wait_for "$MODDIR/resume-launch"
        fi
        sleep 30 &
        printf '%s\n' "$!" >"$pid_file"
        ;;
    *) return 2 ;;
    esac
}
magicnet_supervisor_stop_pidfile() {
    assert_guard_held
    printf 'stop\n' >>"$events"
    if [ -s "$1" ]; then
        read -r stopped_pid <"$1"
        kill "$stopped_pid"
        rm -f "$1"
    fi
}
magicnet_supervisor_kill_orphans() { return 0; }

FSWATCH_TEST_INITIAL_BARRIER=1 magicnet_fswatch_start &
job_one=$!
FSWATCH_TEST_INITIAL_BARRIER=1 magicnet_fswatch_start &
job_two=$!
wait_for "$MODDIR/status-$job_one"
wait_for "$MODDIR/status-$job_two"
: >"$MODDIR/resume-status"
wait "$job_one"
wait "$job_two"
job_one=''
job_two=''
test "$(cat "$events")" = start
read -r first_pid <"$pid_file"
kill -0 "$first_pid"
# A live detached worker cannot retain the lifecycle descriptor.
flock -n "$guard" true
magicnet_fswatch_start
test "$(cat "$pid_file")" = "$first_pid"
test "$(cat "$events")" = start
magicnet_fswatch_stop
test ! -e "$pid_file"

# Stop shares the same gate: it waits for an in-flight start to publish, then
# removes the new watcher. No late PID publication can undo a completed stop.
FSWATCH_TEST_PAUSE_LAUNCH=1 magicnet_fswatch_start &
job_one=$!
wait_for "$MODDIR/launch-paused"
magicnet_fswatch_stop &
stop_job=$!
sleep 0.2
test "$(cat "$events")" = 'start
stop
start'
: >"$MODDIR/resume-launch"
wait "$job_one"
wait "$stop_job"
job_one=''
stop_job=''
test ! -e "$pid_file"
test "$(cat "$events")" = 'start
stop
start
stop'
flock -n "$guard" true
test "$(cat "$MODDIR/other-descriptor")" = 'retained
retained'
SHELL
    printf 'Fswatch lifecycle passed: %s\n' "${shell##*/}"
done
