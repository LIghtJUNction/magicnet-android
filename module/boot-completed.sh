#!/system/bin/sh
MODDIR="${0%/*}"
case "$MODDIR" in /data/adb/modules/MagicNet) ;; *) exit 1;; esac
[ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
# Idempotent lifecycle reconciliation owns the process and networking resources.
"$MODDIR/bin/magicnet-cli" state reconcile || exit "$?"
"$MODDIR/bin/magicnet-cli" service ensure || exit "$?"
exec "$MODDIR/bin/magicnet-cli" supervisor start all
