magicnet_block_dir() {
    printf '%s\n' "${MODDIR}/.config/magicnet"
}

magicnet_block_conf() {
    printf '%s\n' "$(magicnet_block_dir)/block.conf"
}

magicnet_block_manual_file() {
    printf '%s\n' "$(magicnet_block_dir)/block-domain-suffix.list"
}

magicnet_block_community_file() {
    printf '%s\n' "$(magicnet_block_dir)/community-ban-domain-suffix.list"
}

magicnet_block_community_rules_file() {
    printf '%s\n' "$(magicnet_block_dir)/community-ban-rules.list"
}

magicnet_block_allow_file() {
    printf '%s\n' "$(magicnet_block_dir)/block-allow-rules.list"
}

magicnet_block_conf_url_is_safe() {
    # Align with CLI validate_subscription_url + shell_inert_conf_value:
    # HTTPS only, no credentials, inert charset, and no private IP literals.
    case "$1" in
        https://*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *@*) return 1 ;;
    esac
    case "$1" in
        ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/?=%+,-]*) return 1 ;;
    esac
    _block_url_host="${1#https://}"
    _block_url_host="${_block_url_host%%/*}"
    _block_url_host="${_block_url_host%%\?*}"
    _block_url_host="${_block_url_host%%#*}"
    case "$_block_url_host" in
        \[*\]*)
            _block_url_host="${_block_url_host#\[}"
            _block_url_host="${_block_url_host%%\]*}"
            case "$_block_url_host" in
                ::1|::|0:0:0:0:0:0:0:1|0:0:0:0:0:0:0:0|fe80:*|fc*|fd*)
                    unset _block_url_host
                    return 1
                    ;;
            esac
            ;;
        *:*)
            _block_url_host="${_block_url_host%:*}"
            ;;
    esac
    case "$_block_url_host" in
        localhost|localhost.*|127.*|0.0.0.0|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            unset _block_url_host
            return 1
            ;;
    esac
    unset _block_url_host
    return 0
}

magicnet_block_load_conf() {
    _conf="$(magicnet_block_conf)"
    MAGICNET_BLOCK_ENABLED=1
    MAGICNET_BLOCK_COMMUNITY_ENABLED=1
    _default_url="https://raw.githubusercontent.com/LIghtJUNction/MagicNet/main/src/MagicNet/.config/magicnet/community-ban.yaml"
    MAGICNET_BLOCK_URL="$_default_url"
    _invalid=0
    _seen_enabled=0
    _seen_community=0
    _seen_url=0

    if [ -f "$_conf" ]; then
        # block.conf is data, not shell. Accept only its complete allowlisted
        # assignment schema; any unknown, malformed, duplicate, or injected
        # line invalidates the whole file and leaves safe defaults in effect.
        while IFS= read -r _line || [ -n "$_line" ]; do
            case "$_line" in
                MAGICNET_BLOCK_ENABLED=0|MAGICNET_BLOCK_ENABLED=1)
                    if [ "$_seen_enabled" -ne 0 ]; then
                        _invalid=1
                    else
                        MAGICNET_BLOCK_ENABLED="${_line#MAGICNET_BLOCK_ENABLED=}"
                        _seen_enabled=1
                    fi
                    ;;
                MAGICNET_BLOCK_COMMUNITY_ENABLED=0|MAGICNET_BLOCK_COMMUNITY_ENABLED=1)
                    if [ "$_seen_community" -ne 0 ]; then
                        _invalid=1
                    else
                        MAGICNET_BLOCK_COMMUNITY_ENABLED="${_line#MAGICNET_BLOCK_COMMUNITY_ENABLED=}"
                        _seen_community=1
                    fi
                    ;;
                MAGICNET_BLOCK_URL=*)
                    _value="${_line#MAGICNET_BLOCK_URL=}"
                    if [ "$_seen_url" -ne 0 ] || ! magicnet_block_conf_url_is_safe "$_value"; then
                        _invalid=1
                    else
                        MAGICNET_BLOCK_URL="$_value"
                        _seen_url=1
                    fi
                    ;;
                *) _invalid=1 ;;
            esac
        done < "$_conf"
        if [ "$_seen_enabled" -ne 1 ] || [ "$_seen_community" -ne 1 ] || [ "$_seen_url" -ne 1 ]; then
            _invalid=1
        fi
    fi
    if [ "$_invalid" -ne 0 ]; then
        MAGICNET_BLOCK_ENABLED=1
        MAGICNET_BLOCK_COMMUNITY_ENABLED=1
        # Consumed by blocklist callers after this loader returns.
        # shellcheck disable=SC2034
        MAGICNET_BLOCK_URL="$_default_url"
    fi
    unset _conf _default_url _invalid _seen_enabled _seen_community _seen_url _line _value
}

magicnet_block_list_values() {
    magicnet_list_file_values "$1"
}

magicnet_block_normalize_allow_rules() {
    _allow_file="$(magicnet_block_allow_file)"
    [ -f "$_allow_file" ] || {
        unset _allow_file
        return 0
    }
    _allow_tmp="${_allow_file}.magicnet-normalize.$$"
    if ! awk '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            return value
        }
        function normalize(line,    value, comma, kind, payload, lower, scheme_end, authority, slash, host) {
            value = trim(line)
            comma = index(value, ",")
            if (!comma) return line
            kind = toupper(trim(substr(value, 1, comma - 1)))
            if (kind != "DOMAIN" && kind != "DOMAIN-SUFFIX") return line
            payload = trim(substr(value, comma + 1))
            lower = tolower(payload)
            if (index(lower, "http://") == 1) {
                scheme_end = 8
            } else if (index(lower, "https://") == 1) {
                scheme_end = 9
            } else {
                return line
            }
            authority = substr(payload, scheme_end)
            slash = match(authority, /[\/?#]/)
            if (slash) authority = substr(authority, 1, slash - 1)
            sub(/^.*@/, "", authority)
            if (authority ~ /:[0-9]+$/) sub(/:[0-9]+$/, "", authority)
            host = tolower(authority)
            sub(/[.]+$/, "", host)
            if (host == "" || host ~ /[[:space:]\/:,@]/) return line
            return kind "," host
        }
        {
            output = normalize($0)
            key = trim(output)
            if (key != "" && key !~ /^#/ && seen[key]++) next
            print output
        }
    ' "$_allow_file" >"$_allow_tmp"; then
        rm -f "$_allow_tmp"
        unset _allow_file _allow_tmp
        return 1
    fi
    if cmp -s "$_allow_file" "$_allow_tmp"; then
        rm -f "$_allow_tmp"
    elif ! mv -f "$_allow_tmp" "$_allow_file"; then
        rm -f "$_allow_tmp"
        unset _allow_file _allow_tmp
        return 1
    fi
    unset _allow_file _allow_tmp
}

magicnet_block_manual_suffixes() {
    magicnet_block_list_values "$(magicnet_block_manual_file)" | awk '{ print "DOMAIN-SUFFIX," $0 }'
}

magicnet_block_community_rules() {
    _allow_file="$(magicnet_block_allow_file)"
    if [ -s "$(magicnet_block_community_rules_file)" ]; then
        if [ -s "$_allow_file" ]; then
            magicnet_block_list_values "$(magicnet_block_community_rules_file)" | grep -Fvx -f "$_allow_file"
        else
            magicnet_block_list_values "$(magicnet_block_community_rules_file)"
        fi
    else
        if [ -s "$_allow_file" ]; then
            magicnet_block_list_values "$(magicnet_block_community_file)" | awk '{ print "DOMAIN-SUFFIX," $0 }' | grep -Fvx -f "$_allow_file"
        else
            magicnet_block_list_values "$(magicnet_block_community_file)" | awk '{ print "DOMAIN-SUFFIX," $0 }'
        fi
    fi
    unset _allow_file
}

magicnet_block_all_rules() {
    magicnet_block_load_conf
    [ "$MAGICNET_BLOCK_ENABLED" = "1" ] || return 0
    magicnet_block_manual_suffixes
    if [ "$MAGICNET_BLOCK_COMMUNITY_ENABLED" = "1" ]; then
        magicnet_block_community_rules
    fi
}

magicnet_block_has_domains() {
    magicnet_block_all_rules | grep -q .
}

# Both rule families share a single structured renderer. Rule lists stay data;
# large lists no longer launch one JSON-escape pipeline per domain.
magicnet_block_render_singbox_rule() (
    _block_kind=$1
    case "$_block_kind" in
    allow) _block_rules="$(magicnet_block_list_values "$(magicnet_block_allow_file)")" || return 1 ;;
    block) _block_rules="$(magicnet_block_all_rules)" || return 1 ;;
    *) return 1 ;;
    esac
    [ -n "$_block_rules" ] || return 0
    _block_jq=$(magicnet_jq) || return 1
    printf '%s\n' "$_block_rules" | "$_block_jq" -R -s --arg kind "$_block_kind" -e '
        def trim: gsub("^[ \t]+|[ \t]+$"; "");
        def stable_unique: reduce .[] as $v ([]; if index($v) == null then . + [$v] else . end);
        (split("\n") | map(split(","))) as $rows
        | def values($type): [$rows[] | select(.[0] == $type) | .[1] // "" | trim | select(. != "")] | stable_unique;
        {domain: ([if $kind == "allow" then "__magicnet_ad_allow__" else "__magicnet_block__" end] + values("DOMAIN"))}
        | reduce [["domain_suffix", "DOMAIN-SUFFIX"], ["domain_keyword", "DOMAIN-KEYWORD"]][] as $field
            (.; values($field[1]) as $items | if ($items | length) > 0 then .[$field[0]]=$items else . end)
        | .outbound = (if $kind == "allow" then "ad-allow" else "ad-block" end)
    ' || return 1
    printf ',\n'
)

magicnet_block_allow_singbox_rules() { magicnet_block_render_singbox_rule allow; }
magicnet_block_singbox_rules() { magicnet_block_render_singbox_rule block; }

magicnet_block_ensure_ad_selectors() (
    _selector_config=$1
    _selector_tmp="${_selector_config}.magicnet-selectors.new"
    _selector_jq=$(magicnet_jq) || return 1
    magicnet_jq_install_config "$_selector_config" "$_selector_tmp" "$_selector_jq" -e '
        def selector($tag; $members; $default):
            {type:"selector", tag:$tag, interrupt_exist_connections:true, outbounds:$members, default:$default};
        def block: selector("ad-block"; ["block", "direct", "proxy"]; "block");
        def allow: selector("ad-allow"; ["final", "direct", "proxy"]; "final");
        if (.outbounds | type) != "array" or (any(.outbounds[]; .tag == "ad-block") | not) then
            error("ad-block selector is missing")
        else any(.outbounds[]; .tag == "ad-allow") as $has_allow
            | .outbounds |= map(
                if .tag == "ad-block" then block, (if $has_allow then empty else allow end)
                elif .tag == "ad-allow" then allow else . end)
        end
    ' "$_selector_config"
)

magicnet_block_apply_singbox() {
    type magicnet_singbox_apply_route_rules >/dev/null 2>&1 || {
        _route_rules_lib="${MODDIR}/lib/magicnet/singbox_route_rules.sh"
        if [ ! -f "$_route_rules_lib" ] && type magicnet_lib_dir >/dev/null 2>&1; then
            _route_rules_lib="$(magicnet_lib_dir)/singbox_route_rules.sh"
        fi
        . "$_route_rules_lib"
        unset _route_rules_lib
    }
    magicnet_singbox_apply_route_rules block
}

magicnet_block_apply_unlocked() {
    _block_rc=0
    magicnet_block_apply_singbox || _block_rc=1
    return "$_block_rc"
}

magicnet_block_apply() {
    magicnet_with_config_lock magicnet_block_apply_unlocked
}
