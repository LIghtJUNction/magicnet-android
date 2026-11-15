#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
MODDIR="$fixture/module"
KAM_HOME="$MODDIR"
export MODDIR KAM_HOME
mkdir -p "$MODDIR/.state/wifi-policy" "$MODDIR/.log"
pid_file="$MODDIR/.state/wifi-policy/magicnet-wifi-policy.pid"
lock_file="$MODDIR/.state/wifi-policy/magicnet-wifi-policy.lifecycle.lock"
cleanup() {
    : >"$fixture/launch-release"
    for pid in $(cat "$fixture/launches" 2>/dev/null || true); do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$fixture"
}
trap cleanup EXIT

set_i18n() { :; }
import() { :; }
# shellcheck disable=SC1091
. "$ROOT/src/MagicNet/lib/magicnet/common.sh"
# shellcheck disable=SC1090
. "${1:-$ROOT/src/MagicNet/lib/magicnet/supervisors.sh}"
# shellcheck disable=SC1091
. "$ROOT/scripts/test-lib/proc-reader-hook.sh"
magicnet_module_disabled() { return 1; }
magicnet_wifi_policy_enabled() { return 0; }

cat >"$MODDIR/cli" <<'EOF'
#!/bin/sh
child=''
trap '[ -z "$child" ] || kill "$child" 2>/dev/null || true; exit 0' TERM INT EXIT
sleep 60 &
child=$!
wait "$child"
EOF
chmod 700 "$MODDIR/cli"
real_nohup=$(command -v nohup)
nohup() {
    printf '%s\n' "$BASHPID" >>"$fixture/launches"
    while [ ! -f "$fixture/launch-release" ]; do sleep 0.01; done
    exec "$real_nohup" "$@"
}

wait_for_launch() {
    for ((attempt = 0; attempt < 100; attempt++)); do
        test ! -s "$fixture/launches" || return 0
        sleep 0.01
    done
    printf '%s\n' 'Wi-Fi launcher did not reach the fixture barrier' >&2
    return 1
}

# Both callers see the unpublished process before its argv has settled.
# Startup must serialize this interval, then keep the first healthy watcher.
magicnet_wifi_policy_start &
first=$!
wait_for_launch
magicnet_wifi_policy_start &
second=$!
sleep 0.2
: >"$fixture/launch-release"
wait "$first"
wait "$second"
tracked=$(cat "$pid_file")
pids=$(magicnet_supervisor_orphan_pids wifi-policy)
test "$pids" = "$tracked" || {
    printf 'concurrent Wi-Fi start left loops [%s], tracked [%s]\n' "$pids" "$tracked" >&2
    exit 1
}
test "$(wc -l <"$fixture/launches")" -eq 1
(
    exec 7>"$lock_file"
    flock -n 7
)
for fd in /proc/"$tracked"/fd/*; do
    test "$(readlink "$fd" 2>/dev/null || true)" != "$lock_file"
done
magicnet_wifi_policy_start
test "$(cat "$pid_file")" = "$tracked"
magicnet_wifi_policy_stop
test ! -e "$pid_file"

# Stop waits for startup's readiness and PID publication instead of deleting
# an unsettled owner file and leaving its process alive after stop returned.
rm -f "$fixture/launches" "$fixture/launch-release"
magicnet_wifi_policy_start &
starting_pid=$!
wait_for_launch
(
    magicnet_wifi_policy_stop
    : >"$fixture/stop-returned"
) &
stopping_pid=$!
sleep 0.2
premature_stop=0
test ! -f "$fixture/stop-returned" || premature_stop=1
: >"$fixture/launch-release"
wait "$starting_pid"
wait "$stopping_pid"
test "$premature_stop" -eq 0 || {
    printf '%s\n' 'Wi-Fi stop returned before startup settled its PID' >&2
    exit 1
}
test ! -e "$pid_file"
if magicnet_supervisor_orphan_pids wifi-policy >/dev/null; then
    printf '%s\n' 'Wi-Fi start/stop race left an exact loop' >&2
    exit 1
fi
printf '%s\n' 'Wi-Fi policy lifecycle tests passed'
