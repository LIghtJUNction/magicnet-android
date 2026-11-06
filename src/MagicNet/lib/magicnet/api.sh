# shellcheck shell=ash
# Endpoint validation belongs to the CLI; shell callers inspect local listeners.
magicnet_singbox_api_endpoint() {
    [ -x "${MODDIR}/cli" ] || return 1
    if _magicnet_api_endpoint=$("${MODDIR}/cli" api endpoint 2>/dev/null); then
        set -- "$_magicnet_api_endpoint"
    else
        unset _magicnet_api_endpoint
        return 1
    fi
    unset _magicnet_api_endpoint
    [ -n "$1" ] && printf '%s\n' "$1"
}

magicnet_singbox_api_port() {
    if _magicnet_api_port=$(magicnet_singbox_api_endpoint); then
        set -- "${_magicnet_api_port##*:}"
    else
        unset _magicnet_api_port
        return 1
    fi
    unset _magicnet_api_port
    case "$1" in '' | 0 | *[!0-9]*) return 1 ;; esac
    [ "$1" -le 65535 ] 2>/dev/null && printf '%s\n' "$1"
}

magicnet_singbox_api_listener_exists() {
    _listener_port=$(magicnet_singbox_api_port) || return 1
    set -- "$_listener_port"
    unset _listener_port
    ss -lnt 2>/dev/null | grep -Eq ":$1[[:space:]]"
}

magicnet_singbox_listener_owned() {
    case "${1:-}" in '' | *[!0-9]*) return 1 ;; esac
    _listener_port=$(magicnet_singbox_api_port) || return 1
    set -- "$1" "$_listener_port"
    unset _listener_port
    ss -lntp 2>/dev/null | awk -v port="$2" -v owner="pid=$1," '
        $0 ~ ":" port "[[:space:]]" && index($0, owner) { found=1 }
        END { exit !found }
    '
}
