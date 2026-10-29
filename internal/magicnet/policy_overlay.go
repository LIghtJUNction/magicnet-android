package magicnet

import (
	"regexp"
	"strings"
)

type RoutingOwned struct {
	Outbounds  []M `json:"outbounds"`
	Endpoints  []M `json:"endpoints"`
	DNSServers []M `json:"dns_servers"`
	RouteRules []M `json:"route_rules"`
	DNSRules   []M `json:"dns_rules"`
}

var routingPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func ApplyRoutingOverlay(base M, raw any) (M, RoutingOwned, error) {
	owned := RoutingOwned{}
	if raw == nil {
		return base, owned, nil
	}
	o := rtMap(raw)
	if o == nil || !rtAllowedKeys(o, "schema rules outbounds") {
		return nil, owned, E("override.routing_invalid", "Routing overlay must be a schema-1 object")
	}
	schema, ok := rtInt(o["schema"])
	if !ok || schema != 1 {
		return nil, owned, E("override.routing_invalid", "Unsupported routing overlay schema")
	}
	rules, rok := o["rules"].([]any)
	if !rok && o["rules"] != nil {
		return nil, owned, E("override.routing_invalid", "Routing rules must be an array")
	}
	outbounds, ook := o["outbounds"].([]any)
	if !ook && o["outbounds"] != nil {
		return nil, owned, E("override.routing_invalid", "Routing outbounds must be an array")
	}
	if len(rules) > 256 || len(outbounds) > 64 {
		return nil, owned, E("override.routing_limit", "Routing overlay exceeds its resource limits")
	}
	config := rtClone(base).(map[string]any)
	targets := map[string]M{}
	for _, key := range []string{"outbounds", "endpoints"} {
		for _, v := range rtArray(config[key]) {
			m := rtMap(v)
			tag := rtString(m["tag"])
			if tag == "" {
				continue
			}
			if targets[tag] != nil {
				return nil, owned, E("override.routing_tag_collision", "Existing target tags collide")
			}
			targets[tag] = m
		}
	}
	for _, v := range outbounds {
		n := rtMap(v)
		if n == nil {
			return nil, owned, E("override.routing_invalid", "Custom outbound must be an object")
		}
		n = rtClone(n).(map[string]any)
		if !validNodeTag(rtString(n["tag"])) {
			return nil, owned, E("override.routing_invalid", "Target names must contain 1–256 UTF-8 bytes without control characters")
		}
		if targets[rtString(n["tag"])] != nil || reservedSubscriptionTag(rtString(n["tag"])) {
			return nil, owned, E("override.routing_tag_collision", "Custom target conflicts with an existing or reserved tag")
		}
		if err := validateStructuredOutbound(n); err != nil {
			return nil, owned, err
		}
		targets[rtString(n["tag"])] = n
		owned.Outbounds = append(owned.Outbounds, n)
	}
	if err := validateTargetGraph(targets); err != nil {
		return nil, owned, err
	}
	for _, n := range owned.Outbounds {
		config["outbounds"] = append(rtArray(config["outbounds"]), n)
	}
	dns := rtMap(config["dns"])
	route := rtMap(config["route"])
	if dns == nil || route == nil {
		return nil, owned, E("override.routing_dns_missing", "Routing requires existing DNS and route configuration")
	}
	serverTags := map[string]bool{}
	var localTemplate, remoteTemplate M
	for _, v := range rtArray(dns["servers"]) {
		m := rtMap(v)
		tag := rtString(m["tag"])
		serverTags[tag] = true
		if rtString(m["type"]) != "https" && rtString(m["type"]) != "tls" && rtString(m["type"]) != "quic" && rtString(m["type"]) != "h3" {
			continue
		}
		if tag == "doh-cloudflare" {
			localTemplate = m
		}
		if tag == "doh-google" {
			remoteTemplate = m
		}
	}
	seen := map[string]bool{}
	dnsForTarget := map[string]string{}
	for _, v := range rules {
		r := rtMap(v)
		if r == nil || !rtAllowedKeys(r, "kind value outbound") {
			return nil, owned, E("override.routing_invalid", "Invalid routing rule")
		}
		kind, value, target := rtString(r["kind"]), rtString(r["value"]), rtString(r["outbound"])
		switch kind {
		case "domain":
			var err error
			value, err = canonicalDomain(strings.TrimSpace(value))
			if err != nil {
				return nil, owned, E("override.routing_invalid", "Invalid domain suffix")
			}
		case "app":
			if !routingPackagePattern.MatchString(value) {
				return nil, owned, E("override.routing_invalid", "Invalid application package")
			}
		default:
			return nil, owned, E("override.routing_invalid", "Routing kind must be app or domain")
		}
		if !validNodeTag(target) || targets[target] == nil {
			return nil, owned, E("override.routing_target_missing", "Routing target does not exist")
		}
		key := kind + "\x00" + value
		if seen[key] {
			return nil, owned, E("override.routing_duplicate", "The normalized routing rule is duplicated")
		}
		seen[key] = true
		condition := M{}
		if kind == "domain" {
			condition["domain_suffix"] = []any{value}
		} else {
			condition["package_name"] = []any{value}
		}
		routeRule := rtClone(condition).(map[string]any)
		routeRule["outbound"] = target
		owned.RouteRules = append(owned.RouteRules, routeRule)
		dnsRule := rtClone(condition).(map[string]any)
		if rtString(targets[target]["type"]) == "block" {
			dnsRule["action"] = "reject"
		} else {
			serverTag := dnsForTarget[target]
			if serverTag == "" {
				template := remoteTemplate
				if directTarget(target, targets, map[string]bool{}) {
					template = localTemplate
				}
				if template == nil {
					return nil, owned, E("override.routing_dns_missing", "The required encrypted DNS template is missing")
				}
				serverTag = "magicnet-routing-dns-" + SubscriptionSourceID(target)[:16]
				if serverTags[serverTag] {
					return nil, owned, E("override.routing_tag_collision", "Generated DNS tag collides with existing configuration")
				}
				serverTags[serverTag] = true
				server := rtClone(template).(map[string]any)
				server["tag"] = serverTag
				server["detour"] = target
				owned.DNSServers = append(owned.DNSServers, server)
				dnsForTarget[target] = serverTag
			}
			dnsRule["server"] = serverTag
		}
		owned.DNSRules = append(owned.DNSRules, dnsRule)
	}
	for _, v := range owned.DNSServers {
		dns["servers"] = append(rtArray(dns["servers"]), v)
	}
	route["rules"] = insertProtected(rtArray(route["rules"]), owned.RouteRules, false)
	dns["rules"] = insertProtected(rtArray(dns["rules"]), owned.DNSRules, true)
	return config, owned, nil
}

func validateStructuredOutbound(n M) error {
	t := rtString(n["type"])
	common := "type tag detour server server_port"
	fields := map[string]string{
		"selector":    "type tag outbounds default interrupt_exist_connections",
		"urltest":     "type tag outbounds url interval tolerance idle_timeout interrupt_exist_connections",
		"socks":       common + " version username password network udp_over_tcp",
		"http":        common + " username password tls path headers",
		"shadowsocks": common + " method password network plugin plugin_opts multiplex",
		"trojan":      common + " password network tls multiplex transport",
		"vless":       common + " uuid flow encryption network tls multiplex transport packet_encoding",
		"vmess":       common + " uuid security alter_id global_padding authenticated_length network tls multiplex transport packet_encoding",
		"hysteria2":   common + " password up_mbps down_mbps obfs tls network server_ports hop_interval",
		"tuic":        common + " uuid password congestion_control udp_relay_mode udp_over_stream zero_rtt_handshake heartbeat network tls",
		"anytls":      common + " password tls idle_session_check_interval idle_session_timeout min_idle_session client_metadata",
	}
	allowed, ok := fields[t]
	if !ok || !rtAllowedKeys(n, allowed) {
		return E("override.routing_invalid", "Unsupported structured outbound type or field")
	}
	if t == "selector" || t == "urltest" {
		members, ok := rtStringList(n["outbounds"])
		if !ok || len(members) == 0 {
			return E("override.routing_invalid", "A proxy group requires members")
		}
		if len(members) > 128 {
			return E("override.routing_limit", "A proxy group supports at most 128 members")
		}
		seen := map[string]bool{}
		for _, s := range members {
			if !validNodeTag(s) {
				return E("override.routing_invalid", "Invalid group member")
			}
			if seen[s] {
				return E("override.routing_duplicate", "Duplicate group member")
			}
			seen[s] = true
		}
		if d, ok := n["default"]; ok {
			if !stringIn(rtString(d), members...) {
				return E("override.routing_target_missing", "Group default must be a member")
			}
		}
		return nil
	}
	if err := ValidateProxyNode(n); err != nil {
		return E("override.routing_invalid", "Invalid proxy fields or VLESS encryption")
	}
	if v, ok := n["tls"]; ok {
		tls := rtMap(v)
		if tls == nil || !rtAllowedKeys(tls, "enabled disable_sni server_name insecure alpn min_version max_version cipher_suites certificate certificate_path certificate_public_key_sha256 utls reality ech") {
			return E("override.routing_invalid", "Unsupported structured TLS field")
		}
		if x, ok := tls["utls"]; ok {
			if m := rtMap(x); m == nil || !rtAllowedKeys(m, "enabled fingerprint") {
				return E("override.routing_invalid", "Invalid uTLS options")
			}
		}
		if x, ok := tls["reality"]; ok {
			if m := rtMap(x); m == nil || !rtAllowedKeys(m, "enabled public_key short_id") {
				return E("override.routing_invalid", "Invalid Reality options")
			}
		}
	}
	if v, ok := n["transport"]; ok {
		tr := rtMap(v)
		allowed := map[string]string{"ws": "type path headers max_early_data early_data_header_name", "grpc": "type service_name idle_timeout ping_timeout permit_without_stream", "http": "type host path method headers idle_timeout ping_timeout", "httpupgrade": "type host path headers", "quic": "type"}[rtString(tr["type"])]
		if tr == nil || allowed == "" || !rtAllowedKeys(tr, allowed) {
			return E("override.routing_invalid", "Complex transport requires the full private configuration editor")
		}
	}
	return nil
}

func validateTargetGraph(targets map[string]M) error {
	state := map[string]int{}
	var visit func(string) error
	visit = func(tag string) error {
		if state[tag] == 1 {
			return E("override.routing_cycle", "Outbound references form a cycle")
		}
		if state[tag] == 2 {
			return nil
		}
		n := targets[tag]
		if n == nil {
			return E("override.routing_target_missing", "Referenced outbound does not exist")
		}
		state[tag] = 1
		refs := []string{}
		if d := rtString(n["detour"]); d != "" {
			refs = append(refs, d)
		}
		if members, ok := rtStringList(n["outbounds"]); ok {
			refs = append(refs, members...)
		}
		for _, ref := range refs {
			if err := visit(ref); err != nil {
				return err
			}
		}
		state[tag] = 2
		return nil
	}
	for tag := range targets {
		if err := visit(tag); err != nil {
			return err
		}
	}
	return nil
}

func directTarget(tag string, targets map[string]M, seen map[string]bool) bool {
	if seen[tag] {
		return false
	}
	seen[tag] = true
	n := targets[tag]
	if n == nil {
		return false
	}
	if rtString(n["type"]) == "direct" {
		return true
	}
	if d := rtString(n["detour"]); d != "" {
		return directTarget(d, targets, seen)
	}
	return false
}

func protectedRoutingRule(m M, dns bool) bool {
	if m == nil {
		return false
	}
	if _, ok := m["clash_mode"]; ok {
		return true
	}
	if _, ok := m["preferred_by"]; ok {
		return true
	}
	if rtBool(m["ip_is_private"]) {
		return true
	}
	if rtString(m["action"]) == "hijack-dns" || rtString(m["action"]) == "sniff" {
		return true
	}
	if s := rtString(m["outbound"]); s == "lan" || s == "tailscale" {
		return true
	}
	if dns {
		if s := rtString(m["server"]); strings.Contains(s, "tailscale") {
			return true
		}
		if ds, ok := rtStringList(m["domain_suffix"]); ok {
			for _, s := range ds {
				if s == "lan" || s == "local" || s == "localhost" || s == "ts.net" {
					return true
				}
			}
		}
	}
	return false
}

func insertProtected(existing []any, added []M, dns bool) []any {
	boundary := 0
	for i, v := range existing {
		if protectedRoutingRule(rtMap(v), dns) {
			boundary = i + 1
		}
	}
	out := append([]any{}, existing[:boundary]...)
	for _, v := range added {
		out = append(out, v)
	}
	out = append(out, existing[boundary:]...)
	return out
}

func StripRoutingOwned(config M, owned RoutingOwned) (M, error) {
	result := rtClone(config).(map[string]any)
	types := []struct {
		parent M
		key    string
		items  []M
	}{{result, "outbounds", owned.Outbounds}, {result, "endpoints", owned.Endpoints}, {rtMap(result["dns"]), "servers", owned.DNSServers}, {rtMap(result["route"]), "rules", owned.RouteRules}, {rtMap(result["dns"]), "rules", owned.DNSRules}}
	for _, entry := range types {
		if len(entry.items) == 0 {
			continue
		}
		if entry.parent == nil {
			return nil, E("override.routing_conflict", "Previously owned routing data was externally removed")
		}
		arr := rtArray(entry.parent[entry.key])
		for _, expected := range entry.items {
			found := -1
			for i, item := range arr {
				if rtEqual(item, expected) {
					if found >= 0 {
						return nil, E("override.routing_conflict", "Previously owned routing data was duplicated")
					}
					found = i
				}
			}
			if found < 0 {
				return nil, E("override.routing_conflict", "Previously owned routing data was externally changed")
			}
			arr = append(arr[:found:found], arr[found+1:]...)
		}
		entry.parent[entry.key] = arr
	}
	return result, nil
}

func MergePatch(base, patch M) M {
	result := rtClone(base).(map[string]any)
	for k, v := range patch {
		if v == nil {
			delete(result, k)
			continue
		}
		if object := rtMap(v); object != nil {
			b := rtMap(result[k])
			if b == nil {
				b = M{}
			}
			result[k] = MergePatch(b, object)
		} else {
			result[k] = rtClone(v)
		}
	}
	return result
}

func undoMergePatch(current, base, effective, patch M) (M, error) {
	result := rtClone(current).(map[string]any)
	for key, p := range patch {
		if key == "$magicnet_routing" {
			continue
		}
		before, bexists := base[key]
		after, aexists := effective[key]
		now, nexists := result[key]
		if pm := rtMap(p); pm != nil && rtMap(now) != nil && rtMap(before) != nil && rtMap(after) != nil {
			v, e := undoMergePatch(rtMap(now), rtMap(before), rtMap(after), pm)
			if e != nil {
				return nil, e
			}
			result[key] = v
			continue
		}
		if nexists != aexists || !rtEqual(now, after) {
			return nil, E("override.routing_conflict", "A field owned by the active override was externally changed")
		}
		if bexists {
			result[key] = rtClone(before)
		} else {
			delete(result, key)
		}
	}
	return result, nil
}

func protectedOverride(base, candidate M) error {
	if !rtEqual(base["inbounds"], candidate["inbounds"]) {
		return E("override.protected", "Managed inbounds cannot be overridden")
	}
	for _, key := range []string{"clash_api", "cache_file"} {
		if !rtEqual(rtMap(base["experimental"])[key], rtMap(candidate["experimental"])[key]) {
			return E("override.protected", "Managed API and cache settings cannot be overridden")
		}
	}
	if !rtEqual(rtMap(base["route"])["rule_set"], rtMap(candidate["route"])["rule_set"]) {
		return E("override.protected", "Managed local rule assets cannot be overridden")
	}
	find := func(c M, tag string) any {
		for _, v := range rtArray(c["outbounds"]) {
			if rtString(rtMap(v)["tag"]) == tag {
				return v
			}
		}
		return nil
	}
	if !rtEqual(find(base, "hotspot"), find(candidate, "hotspot")) {
		return E("override.protected", "The managed hotspot selector cannot be overridden")
	}
	return nil
}
