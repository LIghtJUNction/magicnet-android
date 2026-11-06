#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

export MODDIR="$fixture/module"
mkdir -p "$MODDIR/.config/sing-box" "$MODDIR/bin"
ln -s "$(command -v jq)" "$MODDIR/bin/jq"
events="$fixture/events"
: >"$events"

cat >"$MODDIR/.config/sing-box/config.json" <<'JSON'
{"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}
JSON
for cache_name in cache.db cache.db-wal cache.db-shm cache.db-journal; do
  printf 'bootstrap-selector\n' >"$MODDIR/.config/sing-box/$cache_name"
done

magicnet_json_escape() { printf '%s' "$1"; }
set_i18n() { :; }
. "$ROOT/src/MagicNet/lib/magicnet/runtime_config.sh"
. "$ROOT/src/MagicNet/lib/magicnet/supervisors.sh"
. "$ROOT/src/MagicNet/lib/magicnet/singbox_subscribe/config.sh"
. "$ROOT/src/MagicNet/lib/magicnet/singbox_subscribe/update.sh"

# Stop only the fixture workers; run the actual aggregate start/stop functions.
magicnet_watchdog_stop() { printf 'supervisors-stop\n' >>"$events"; return "${worker_stop_rc:-0}"; }
magicnet_fswatch_stop() { :; }
magicnet_wifi_policy_stop() { :; }
magicnet_subscription_refresh_stop() { :; }
magicnet_hotspot_route_cleanup() { printf 'hotspot-cleanup\n' >>"$events"; return "${hotspot_cleanup_rc:-0}"; }
magicnet_disable_dns_capture() { printf 'dns-capture-disable\n' >>"$events"; }
magicnet_disable_dns_leak_guard() { printf 'dns-leak-guard-disable\n' >>"$events"; }
magicnet_after_kernel_start_unlocked() { printf 'post-start\n' >>"$events"; }
magicnet_singbox_owned_pids_to_file() {
  : >"$2"
  return 1
}
magicnet_singbox_ensure_start_owned() { :; }
magicnet_singbox_api_listener_exists() { return 1; }
ss() { :; }
ip() { :; }
warn() { :; }
magicnet_warn() { :; }
magicnet_detach_pid_from_app_cgroup() { :; }
magicnet_singbox_record_runtime_fingerprint() { :; }
magicnet_kernel_running() {
  if test -n "${failure_state:-}"; then
    test "$(cat "$failure_state")" = running
  else
    return "${kernel_state:-0}"
  fi
}
magicnet_connectivity_watchdog_start() { printf 'connectivity-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"; }
magicnet_subscription_refresh_start() { printf 'refresh-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"; }
magicnet_wifi_policy_start() {
  printf 'wifi-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"
  return "${wifi_start_rc:-0}"
}
magicnet_hotspot_watchdog_start() { printf 'hotspot-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"; }
magicnet_fswatch_start() { printf 'restore-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"; }
magicnet_fswatch_status() { return 0; }

# A subscription-owned restart records the complete set without restoring
# workers while the caller still owns the config transaction.
export MAGICNET_SUB_FSWATCH_WAS_ACTIVE=1
export MAGICNET_SUB_RESET_BOOTSTRAP_CACHE=1
MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE=1
MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING=0
MAGICNET_SUB_FSWATCH_RESTORE_PENDING=0
magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json"
test "${MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING:-0}" -eq 1
test "$MAGICNET_SUB_FSWATCH_RESTORE_PENDING" -eq 1
test "$(tr '\n' ' ' <"$events")" = 'supervisors-stop hotspot-cleanup dns-capture-disable dns-leak-guard-disable post-start '
for cache_name in cache.db cache.db-wal cache.db-shm cache.db-journal; do
  test ! -e "$MODDIR/.config/sing-box/$cache_name"
done
# A failed activation can call restart again during rollback after fswatch
# has stopped. Preserve the original restore intent across both restarts.
MAGICNET_SUB_FSWATCH_WAS_ACTIVE=0
magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json"
test "$MAGICNET_SUB_FSWATCH_RESTORE_PENDING" -eq 1
: >"$events"
unset MAGICNET_SUB_FSWATCH_WAS_ACTIVE MAGICNET_SUB_RESET_BOOTSTRAP_CACHE \
  MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING \
  MAGICNET_SUB_FSWATCH_RESTORE_PENDING

# A failed post-start phase must tear down the newly started generation. The
# old generation is already gone at this point; leaving PID 222 alive would
# expose a core without its TUN/DNS policy and make the next request flaky.
failure_state="$fixture/failure-state"
printf 'stopped\n' >"$failure_state"
# Signal helpers use private subshells; liveness must remain shared like /proc.
failure_pid_file="$fixture/failure-pids"
: >"$failure_pid_file"
magicnet_singbox_owned_pids_to_file() {
  : >"$2"
  if test -s "$failure_pid_file"; then
    cat "$failure_pid_file" >"$2"
    return 0
  fi
  return 1
}
magicnet_singbox_ensure_start_owned() {
  printf 'running\n' >"$failure_state"
  printf '222\n' >"$failure_pid_file"
}
magicnet_after_kernel_start_unlocked() { return 1; }
kill() {
  case "$*" in
  *222*)
    : >"$failure_pid_file"
    printf 'stopped\n' >"$failure_state"
    ;;
  esac
  return 0
}
export MAGICNET_SUB_STOP_TIMEOUT=0 MAGICNET_SUB_KILL_TIMEOUT=0
CONFIG_LOCK_HELD=0
set +e
magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json"
failure_restart_rc=$?
set -e
test "$failure_restart_rc" -ne 0
test "$(cat "$failure_state")" = stopped
test ! -s "$failure_pid_file"
unset failure_state failure_pid_file failure_restart_rc
unset MAGICNET_SUB_STOP_TIMEOUT MAGICNET_SUB_KILL_TIMEOUT CONFIG_LOCK_HELD
: >"$events"

# The update wrapper restores all configured workers after the lock returns,
# even if fswatch was disabled before activation.
CONFIG_LOCK_HELD=0
magicnet_singbox_update_lock_acquire() { :; }
magicnet_singbox_update_lock_release() { :; }
magicnet_singbox_transaction_reconcile() { :; }
magicnet_singbox_cleanup_stale_candidates() { :; }
magicnet_singbox_update_cleanup_stage() { :; }
magicnet_singbox_update_status() { :; }
error() { :; }
magicnet_with_config_lock() {
  CONFIG_LOCK_HELD=1
  "$@"
  local rc=$?
  CONFIG_LOCK_HELD=0
  return "$rc"
}
magicnet_singbox_update_subscription_unlocked() {
  test "$MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE" -eq 1
  printf 'transaction-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"
  MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING=1
  MAGICNET_SUB_FSWATCH_RESTORE_PENDING="$restore_fswatch"
}

for restore_fswatch in 0 1; do
  for attempt in 1 2 3; do
    : >"$events"
    magicnet_singbox_update_subscription
    expected='transaction-lock=1 connectivity-lock=0 refresh-lock=0 wifi-lock=0 hotspot-lock=0 '
    if test "$restore_fswatch" -eq 1; then expected+='restore-lock=0 '; fi
    test "$(tr '\n' ' ' <"$events")" = "$expected"
    test -z "${MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE+x}"
    test -z "${MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING+x}"
    test -z "${MAGICNET_SUB_FSWATCH_RESTORE_PENDING+x}"
  done
done

# Initial journal recovery and failure rollback also run under the config
# lock. Their restore request must survive until the wrapper releases it.
magicnet_singbox_transaction_reconcile() {
  test "$CONFIG_LOCK_HELD" -eq 1
  test "$MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE" -eq 1
  printf 'reconcile-lock=%s\n' "$CONFIG_LOCK_HELD" >>"$events"
  MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING=1
  MAGICNET_SUB_FSWATCH_RESTORE_PENDING=0
  return "${recovery_result:-0}"
}
magicnet_singbox_update_subscription_unlocked() { return "$update_result"; }
for update_result in 0 1; do
  : >"$events"
  actual=0
  magicnet_singbox_update_subscription || actual=$?
  test "$actual" -eq "$update_result"
  expected='reconcile-lock=1 '
  if test "$update_result" -ne 0; then expected+='reconcile-lock=1 '; fi
  expected+='connectivity-lock=0 refresh-lock=0 wifi-lock=0 hotspot-lock=0 '
  test "$(tr '\n' ' ' <"$events")" = "$expected"
done
: >"$events"
recovery_result=1
actual=0
magicnet_singbox_update_subscription || actual=$?
test "$actual" -eq 1
test "$(tr '\n' ' ' <"$events")" = 'reconcile-lock=1 connectivity-lock=0 refresh-lock=0 wifi-lock=0 hotspot-lock=0 '
test -z "${MAGICNET_SUB_DEFER_SUPERVISORS_RESTORE+x}"
test -z "${MAGICNET_SUB_SUPERVISORS_RESTORE_PENDING+x}"
unset recovery_result

# Hotspot cleanup is separate from worker ownership and DNS cleanup. A stale
# hotspot cleanup failure must not strand a ready core; strict failures still
# prevent startup, and both DNS cleanups remain attempted.
magicnet_singbox_owned_pids_to_file() { : >"$2"; return 1; }
magicnet_singbox_ensure_start_owned() { printf 'core-start\n' >>"$events"; }
magicnet_after_kernel_start_unlocked() { printf 'post-start\n' >>"$events"; }
MAGICNET_SUB_FSWATCH_WAS_ACTIVE=0
for hotspot_cleanup_rc in 1 2; do
  : >"$events"
  magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json"
  grep -qx core-start "$events"
  grep -qx post-start "$events"
  grep -qx wifi-lock=0 "$events"
  grep -qx hotspot-lock=0 "$events"
done
hotspot_cleanup_rc=0
for worker_stop_rc in 1 2; do
  : >"$events"
  actual=0
  magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json" || actual=$?
  test "$actual" -eq "$worker_stop_rc"
  grep -qx dns-capture-disable "$events"
  grep -qx dns-leak-guard-disable "$events"
  if grep -qx core-start "$events"; then exit 1; fi
  if grep -qx hotspot-cleanup "$events"; then exit 1; fi
done
worker_stop_rc=0
magicnet_disable_dns_capture() { printf 'dns-capture-disable\n' >>"$events"; return 1; }
: >"$events"
if magicnet_singbox_restart_owned "$MODDIR/.config/sing-box/config.json"; then exit 1; fi
grep -qx dns-leak-guard-disable "$events"
if grep -qx core-start "$events"; then exit 1; fi

# A matching supervisor's indeterminate ownership remains a strict result,
# including when the core is already ready and restoration is deferred.
for wifi_start_rc in 1 2; do
  : >"$events"
  actual=0
  magicnet_singbox_supervisor_restore 0 || actual=$?
  test "$actual" -eq "$wifi_start_rc"
done
unset wifi_start_rc

# A failed/unknown core must not gain maintenance workers that could revive it.
for kernel_state in 1 2; do
  : >"$events"
  actual=0
  magicnet_singbox_supervisor_restore 1 || actual=$?
  if test "$kernel_state" -eq 1; then test "$actual" -eq 0; else test "$actual" -eq 2; fi
  test ! -s "$events"
done

printf 'subscription activation order test passed\n'
