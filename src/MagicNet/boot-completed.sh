#!/system/bin/sh
# shellcheck shell=ash

case "$0" in
    */*) . "${0%/*}/lib/magicnet/entry.sh" || exit 1 ;;
    *) . "${MODDIR:-$(pwd)}/lib/magicnet/entry.sh" || exit 1 ;;
esac

if [ -x "${0%/*}/certificate-policy" ]; then
    "${0%/*}/certificate-policy" apply || printf '%s\n' '[MagicNet] Certificate policy failed; check certificate-policy status.' >&2
fi

kamfw run boot-completed -- "$@"
