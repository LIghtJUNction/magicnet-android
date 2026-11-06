# shellcheck shell=ash
# One state root and one private cache root for builds, installs and runtime.

magicnet_private_runtime_directory() {
    [ ! -L "$1" ] || return 1
    if [ ! -d "$1" ]; then
        (umask 077; mkdir "$1" 2>/dev/null) || [ -d "$1" ] || return 1
    fi
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    chmod 700 "$1"
}

# The caller serializes migration. Each successful move survives interruption;
# a retry merges the remaining entries without overwriting canonical data.
magicnet_merge_runtime_directory() (
    _source=$1 _target=$2 _recovery=$3
    [ -d "$_source" ] && [ ! -L "$_source" ] || exit 1
    magicnet_private_runtime_directory "$_target" || exit 1
    magicnet_private_runtime_directory "$_recovery" || exit 1
    for _entry in "$_source/"* "$_source/".[!.]* "$_source/"..?*; do
        [ -e "$_entry" ] || [ -L "$_entry" ] || continue
        _name=${_entry##*/}
        _destination="$_target/$_name"
        [ ! -L "$_entry" ] && [ ! -L "$_destination" ] || exit 1
        if [ -d "$_entry" ] && { [ ! -e "$_destination" ] || [ -d "$_destination" ]; }; then
            magicnet_merge_runtime_directory "$_entry" "$_destination" "$_recovery/$_name" || exit 1
        elif [ ! -e "$_destination" ]; then
            mv "$_entry" "$_destination" || exit 1
        elif [ -f "$_entry" ] && [ -f "$_destination" ] && cmp -s "$_entry" "$_destination"; then
            rm "$_entry" || exit 1
        else
            # The current path wins. Preserve a differing legacy value only as
            # private recovery material, never as another consumer input.
            _saved="$_recovery/$_name"
            _suffix=0
            while [ -e "$_saved" ] || [ -L "$_saved" ]; do
                _suffix=$((_suffix + 1))
                _saved="$_recovery/$_name.$_suffix"
            done
            mv "$_entry" "$_saved" || exit 1
        fi
    done
    rmdir "$_source" || exit 1
    rmdir "$_recovery" 2>/dev/null || true
)

magicnet_migrate_runtime_dirs() (
    _root=${1:-${MODDIR}}
    [ -d "$_root" ] && [ ! -L "$_root" ] || exit 1
    magicnet_private_runtime_directory "$_root/.state" || exit 1
    magicnet_private_runtime_directory "$_root/.cache" || exit 1
    for _legacy in .local/state .tmp; do
        [ -e "$_root/$_legacy" ] || [ -L "$_root/$_legacy" ] || continue
        case "$_legacy" in
        .local/state)
            [ ! -L "$_root/.local" ] || exit 1
            _canonical=.state _name=local-state
            ;;
        .tmp) _canonical=.cache _name=tmp ;;
        esac
        magicnet_private_runtime_directory "$_root/.state/directory-migration" || exit 1
        magicnet_merge_runtime_directory "$_root/$_legacy" "$_root/$_canonical" \
            "$_root/.state/directory-migration/$_name" || exit 1
    done
    rmdir "$_root/.local" "$_root/.state/directory-migration" 2>/dev/null || true
)

magicnet_prepare_runtime_dirs() {
    magicnet_private_runtime_directory "${MODDIR}/.state" || return 1
    magicnet_private_runtime_directory "${MODDIR}/.cache" || return 1
    if [ -e "${MODDIR}/.local/state" ] || [ -L "${MODDIR}/.local/state" ] ||
        [ -e "${MODDIR}/.tmp" ] || [ -L "${MODDIR}/.tmp" ]; then
        magicnet_with_config_lock magicnet_migrate_runtime_dirs || return 1
    fi
}
