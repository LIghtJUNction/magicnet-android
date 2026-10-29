#!/system/bin/sh
MODDIR="${0%/*}"
case "$MODDIR" in /data/adb/modules/MagicNet) ;; *) exit 1;; esac
[ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
"$MODDIR/bin/magicnet-cli" service ensure || exit "$?"
exec "$MODDIR/bin/magicnet-cli" supervisor start all
