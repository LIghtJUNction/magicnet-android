#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
MODDIR="$fixture/module"
KAM_HOME="$MODDIR"
KAMFW_DIR=''
export MODDIR KAM_HOME KAMFW_DIR
mkdir -p "$MODDIR/.state/watchdog" "$MODDIR/.log"
pid_file="$MODDIR/.state/watchdog/magicnet-kernel.pid"
lock_file="$MODDIR/.state/watchdog/magicnet-connectivity.lifecycle.lock"
cleanup() {
    if [ -f "$pid_file" ]; then kill "$(cat "$pid_file")" 2>/dev/null || true; fi
    rm -rf "$fixture"
}
trap cleanup EXIT

print() { printf '%s\n' "$*"; }
set_i18n() { :; }
i18n() { printf '%s\n' "$1"; }
t() { cat; }
success() { :; }
warn() { :; }
error() { printf '%s\n' "$*" >&2; }
import() {
    if [ "$1" = watchdog ]; then
        # shellcheck disable=SC1091
        . "$ROOT/src/MagicNet/lib/kamfw/watchdog.sh"
    fi
}
# shellcheck disable=SC1091
. "$ROOT/src/MagicNet/lib/magicnet/common.sh"
# shellcheck disable=SC1091
. "$ROOT/src/MagicNet/lib/magicnet/supervisors.sh"
# shellcheck disable=SC1091
. "$ROOT/scripts/test-lib/proc-reader-hook.sh"
magicnet_module_disabled() { [ -f "$MODDIR/disable" ]; }
magicnet_kernel_running() { return "${core_result:-0}"; }
magicnet_hotspot_watchdog_stop() { :; }

# A disconnected/unknown/disabled service must not acquire a monitor that can
# later resurrect it. Unknown process discovery is surfaced to the caller.
core_result=1
magicnet_connectivity_watchdog_start
test ! -f "$pid_file"
core_result=2
if magicnet_connectivity_watchdog_start; then exit 1; else test "$?" -eq 2; fi
core_result=0
touch "$MODDIR/disable"
magicnet_connectivity_watchdog_start
test ! -f "$pid_file"
rm "$MODDIR/disable"

starts=()
for ((attempt = 0; attempt < 4; attempt++)); do
    magicnet_connectivity_watchdog_start &
    starts+=("$!")
done
for pid in "${starts[@]}"; do wait "$pid"; done
tracked=$(cat "$pid_file")
test "$(magicnet_supervisor_orphan_pids watchdog)" = "$tracked"
magicnet_supervisor_pidfile_matches "$pid_file" "$tracked"
grep -F "connectivity tick" "${pid_file%.pid}.loop.sh" >/dev/null
# Observe the real child delay; quoting and generated loop syntax are internal.
sleep_seen=0
for ((attempt = 0; attempt < 50; attempt++)); do
    children=$(ps -A -o pid=,ppid= | awk -v owner="$tracked" '$2 == owner { print $1 }')
    for child in $children; do
        sleep_argv=()
        mapfile -d '' -t sleep_argv <"/proc/$child/cmdline" 2>/dev/null || continue
        if [[ ${#sleep_argv[@]} -eq 2 && ${sleep_argv[0]##*/} == sleep && ${sleep_argv[1]} == 60 ]]; then
            sleep_seen=1
            break
        fi
    done
    [[ $sleep_seen -eq 0 ]] || break
    sleep 0.02
done
test "$sleep_seen" -eq 1

# The persistent sleeper must not inherit the launcher lock, and another
# startup must keep the same healthy process instead of repeatedly replacing it.
(
    exec 7>"$lock_file"
    flock -n 7
)
for fd in /proc/"$tracked"/fd/*; do
    test "$(readlink "$fd" 2>/dev/null || true)" != "$lock_file"
done
magicnet_connectivity_watchdog_start
test "$(cat "$pid_file")" = "$tracked"

magicnet_watchdog_stop
test ! -f "$pid_file"
if magicnet_supervisor_orphan_pids watchdog >/dev/null; then exit 1; else test "$?" -eq 1; fi
printf '%s\n' 'connectivity watchdog lifecycle test passed'
