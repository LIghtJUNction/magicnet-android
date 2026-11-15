# shellcheck shell=ash
# Managed routing edits operate on JSON structure, independent of indentation.
magicnet_singbox_insert_route_rules() (
    _insert_config=$1 _insert_tmp=$2 _insert_rules=$3 _insert_mode=$4
    case "$_insert_mode" in block | route) ;; *) return 1 ;; esac
    [ "$_insert_config" != "$_insert_tmp" ] && [ ! -L "$_insert_tmp" ] || return 1
    _insert_jq=$(magicnet_jq) || return 1
    umask 077
    "$_insert_jq" --arg mode "$_insert_mode" --rawfile additions "$_insert_rules" -e '
        def marked($names): [.. | strings] | any(. as $value | $names | index($value));
        def managed:
            if $mode == "block" then marked(["__magicnet_ad_allow__", "__magicnet_block__"])
            else ((.domain_suffix // []) | index("__magicnet_route__") != null) end;
        # Non-final metadata actions must run before managed terminal routes.
        def protected_rule($tailnets):
            has("clash_mode") or has("preferred_by")
            or .ip_is_private == true or .outbound == "lan"
            or (.outbound as $tag | $tailnets | index($tag) != null)
            or .action == "sniff" or .action == "hijack-dns" or .action == "reject"
            or .action == "resolve" or .action == "route-options"
            or (.outbound == "block" and (.protocol == "icmp" or has("ip_cidr")));
        def precedes_managed($tailnets):
            protected_rule($tailnets)
            or marked(["__magicnet_app_direct__", "__magicnet_app_proxy__"])
            or ($mode == "block" and marked(["__magicnet_route__"]));
        if (.route.rules | type) != "array" then error("route.rules must be an array") else . end
        | [.endpoints[]? | select(.type == "tailscale") | .tag] as $tailnets
        | ($additions | sub(",[[:space:]]*$"; "") | "[" + . + "]" | fromjson) as $new
        | (.route.rules | map(select(managed | not))) as $rules
        | if $mode == "route" and ($new | length) > 0
            and (any($rules[]; .action == "sniff") | not) then
            error("custom route insertion requires a sniff rule")
          # Domain policy needs the metadata produced by sniffing. Keep base
          # rules in their original order, including interleaved user rules.
          else ((([$rules | to_entries[] | select(.value | precedes_managed($tailnets)) | .key]
              | last) // -1) + 1) as $at
            | .route.rules = ($rules[:$at] + $new + $rules[$at:])
          end
    ' "$_insert_config" >"$_insert_tmp"
)

# A rule family is one transaction: render, verify its markers, then publish
# the complete JSON object. Selector repairs belong to the same candidate.
magicnet_singbox_apply_route_rules() (
    _rules_mode=$1
    case "$_rules_mode" in
    block) magicnet_block_normalize_allow_rules || return 1 ;;
    route) ;;
    *) return 1 ;;
    esac
    _rules_config="${MODDIR}/.config/sing-box/config.json"
    [ -f "$_rules_config" ] || return 0
    _rules_tmp="${_rules_config}.magicnet-${_rules_mode}.new"
    _rules_base="${_rules_config}.magicnet-${_rules_mode}.base"
    _rules_fragment="${MODDIR}/.cache/magicnet-${_rules_mode}-singbox.rules"
    [ ! -L "$_rules_tmp" ] && [ ! -L "$_rules_base" ] && [ ! -L "$_rules_fragment" ] || return 1
    trap 'rm -f "$_rules_tmp" "$_rules_base" "${_rules_base}.magicnet-selectors.new" "$_rules_fragment"' 0
    trap 'exit 1' 1 2 3 15
    umask 077
    mkdir -p "${_rules_fragment%/*}" || return 1
    case "$_rules_mode" in
    block)
        { magicnet_block_allow_singbox_rules && magicnet_block_singbox_rules; } >"$_rules_fragment" || return 1
        _rules_block=0 _rules_allow=0
        magicnet_block_has_domains && _rules_block=1
        magicnet_block_list_values "$(magicnet_block_allow_file)" | grep -q . && _rules_allow=1
        set -- "__magicnet_block__=$_rules_block" "__magicnet_ad_allow__=$_rules_allow"
        ;;
    route)
        magicnet_route_singbox_rules >"$_rules_fragment" || return 1
        _rules_route=0
        magicnet_route_has_rules && _rules_route=1
        set -- "__magicnet_route__=$_rules_route"
        ;;
    esac
    for _rules_expectation do
        [ "${_rules_expectation#*=}" = 0 ] ||
            grep -q "\"${_rules_expectation%=*}\"" "$_rules_fragment" || return 1
    done
    _rules_source=$_rules_config
    if [ "$_rules_mode" = block ]; then
        cp "$_rules_config" "$_rules_base" && magicnet_block_ensure_ad_selectors "$_rules_base" || return 1
        _rules_source=$_rules_base
    fi
    magicnet_singbox_insert_route_rules "$_rules_source" "$_rules_tmp" "$_rules_fragment" "$_rules_mode" || return 1
    for _rules_expectation do
        _rules_present=0
        grep -q "\"${_rules_expectation%=*}\"" "$_rules_tmp" && _rules_present=1
        [ "$_rules_present" = "${_rules_expectation#*=}" ] || return 1
    done
    magicnet_json_object_valid "$_rules_tmp" && chmod 600 "$_rules_tmp" && mv -f "$_rules_tmp" "$_rules_config"
)
