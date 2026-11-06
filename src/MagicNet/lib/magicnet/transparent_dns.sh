# shellcheck shell=ash
# Network policy helpers (IPv6 preference, TUN MTU, UDP timeout).
# Kernel DNS capture / leak-guard live in network.sh, not here.
magicnet_network_policy_conf() {
    printf '%s\n' "${MODDIR}/.config/magicnet/network-policy.conf"
}

# The token and CIDR readers share one exact-key parser. A malformed first
# assignment is skipped, preserving the established first-valid-value rule.
magicnet_network_policy_read() {
    set -- "$1" "$2" "$(magicnet_network_policy_conf)"
    [ -f "$3" ] || return 1
    awk -F= -v key="$1" -v pattern="$2" '
        $1 == key {
            value = substr($0, index($0, "=") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value ~ pattern) { print value; found = 1; exit }
        }
        END { exit found ? 0 : 1 }
    ' "$3"
}

magicnet_network_policy_value() {
    magicnet_network_policy_read "$1" '^[A-Za-z0-9_-]+$'
}

magicnet_network_policy_cidr_value() {
    magicnet_network_policy_read "$1" '^[0-9A-Fa-f.:/]+$'
}

magicnet_dns_capture_policy_port() {
    set -- "${MAGIC_DNS_CAPTURE_PORT:-${MAGICNET_DNS_CAPTURE_PORT:-$(magicnet_network_policy_value MAGICNET_DNS_CAPTURE_PORT 2>/dev/null || true)}}"
    case "$1" in
    '' | 0* | *[!0-9]* | ??????*) set -- 1053 ;;
    *) [ "$1" -le 65535 ] || set -- 1053 ;;
    esac
    printf '%s\n' "$1"
}

magicnet_ipv6_mode() {
    set -- "${MAGICNET_IPV6_MODE:-$(magicnet_network_policy_value MAGICNET_IPV6_MODE 2>/dev/null || true)}"
    case "$1" in
    ipv4_only | prefer_ipv4 | prefer_ipv6) ;;
    ipv4-only | compat | disabled) set -- ipv4_only ;;
    prefer-ipv6) set -- prefer_ipv6 ;;
    *) set -- prefer_ipv4 ;;
    esac
    printf '%s\n' "$1"
}

magicnet_tun_mtu() {
    set -- "${MAGICNET_TUN_MTU:-$(magicnet_network_policy_value MAGICNET_TUN_MTU 2>/dev/null || true)}"
    case "$1" in
    '' | *[!0-9]*) set -- 1400 ;;
    *) [ "$1" -ge 1280 ] && [ "$1" -le 1500 ] || set -- 1400 ;;
    esac
    printf '%s\n' "$1"
}

magicnet_udp_timeout() {
    set -- "${MAGICNET_UDP_TIMEOUT:-$(magicnet_network_policy_value MAGICNET_UDP_TIMEOUT 2>/dev/null || true)}"
    case "$1" in 1m | 3m | 5m | 10m | 15m | 30m) ;; *) set -- 5m ;; esac
    printf '%s\n' "$1"
}

magicnet_ipv4_tun_cidr_valid() {
    printf '%s\n' "$1" | awk '
        function octet(value) {
            return value ~ /^[0-9]+$/ && length(value) <= 3 &&
                (length(value) == 1 || substr(value, 1, 1) != "0") &&
                value + 0 <= 255
        }
        {
            if (NR != 1) exit 1
            if (split($0, cidr, "/") != 2) exit 1
            if (cidr[2] !~ /^[1-9][0-9]*$/ || length(cidr[2]) > 2 || cidr[2] + 0 < 8 || cidr[2] + 0 > 30) exit 1
            if (split(cidr[1], address, ".") != 4) exit 1
            for (i = 1; i <= 4; i++) if (!octet(address[i])) exit 1
            if (address[1] + 0 == 0 || address[1] + 0 == 127 || address[1] + 0 >= 224) exit 1
            # sing-tun derives DNS from the next address. Keep that address
            # inside this prefix and away from its IPv4 broadcast address.
            number = ((address[1] * 256 + address[2]) * 256 + address[3]) * 256 + address[4]
            size = 2 ^ (32 - cidr[2])
            if (number % size >= size - 2) exit 1
        }
        END { if (NR != 1) exit 1 }
    '
}

magicnet_ipv6_tun_cidr_valid() {
    printf '%s\n' "$1" | awk '
        function hex(value, result, j) {
            result = 0
            value = tolower(value)
            for (j = 1; j <= length(value); j++)
                result = result * 16 + index("0123456789abcdef", substr(value, j, 1)) - 1
            return result
        }
        {
            if (NR != 1) exit 1
            if (split($0, cidr, "/") != 2) exit 1
            if (cidr[2] !~ /^[1-9][0-9]*$/ || length(cidr[2]) > 3 || cidr[2] + 0 < 64 || cidr[2] + 0 > 126) exit 1
            addr = cidr[1]
            if (addr !~ /^[fF][cCdD][0-9A-Fa-f][0-9A-Fa-f]:/ || addr !~ /^[0-9A-Fa-f:]+$/) exit 1
            n = split(addr, halves, "::")
            if (n > 2) exit 1
            groups = 0
            for (h = 1; h <= n; h++) {
                if (halves[h] == "") continue
                parts = split(halves[h], group, ":")
                for (i = 1; i <= parts; i++) {
                    if (group[i] == "" || length(group[i]) > 4 || group[i] !~ /^[0-9A-Fa-f]+$/) exit 1
                    hextet[h == 1 ? i : 8 - parts + i] = hex(group[i])
                    groups++
                }
            }
            if (n == 2) {
                if (groups > 7) exit 1
            } else if (groups != 8) {
                exit 1
            }
            # Compare only 16-bit chunks: whole IPv6 values exceed awk exact
            # integer precision. All-one host bits leave no DNS next address.
            host_bits = 128 - cidr[2]
            for (i = 8; host_bits > 0; i--) {
                bits = host_bits > 16 ? 16 : host_bits
                size = 2 ^ bits
                if (hextet[i] % size != size - 1) has_next = 1
                host_bits -= bits
            }
            if (!has_next) exit 1
        }
        END { if (NR != 1) exit 1 }
    '
}

magicnet_tun_inet() {
    set -- "${MAGICNET_TUN_INET:-$(magicnet_network_policy_cidr_value MAGICNET_TUN_INET 2>/dev/null || true)}"
    magicnet_ipv4_tun_cidr_valid "$1" || set -- 172.19.0.1/30
    printf '%s\n' "$1"
}

magicnet_tun_inet6() {
    set -- "${MAGICNET_TUN_INET6:-$(magicnet_network_policy_cidr_value MAGICNET_TUN_INET6 2>/dev/null || true)}"
    magicnet_ipv6_tun_cidr_valid "$1" || set -- fdfe:dcba:9876::1/126
    printf '%s\n' "$1"
}

magicnet_singbox_dns_strategy_for_mode() {
    magicnet_ipv6_mode
}
