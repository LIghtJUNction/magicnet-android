#!/system/bin/sh
MODDIR="${0%/*}"
case "$MODDIR" in /data/adb/modules/MagicNet) ;; *) exit 1;; esac
# Cleanup is delegated to the controller's owned-resource lifecycle; no global flush.
exec "$MODDIR/bin/magicnet-cli" __uninstall
