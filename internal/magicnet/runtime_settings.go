package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strings"
	"time"
)

type RuntimeNetwork struct {
	IPv6Mode   string `json:"ipv6_mode"`
	MTU        int    `json:"mtu"`
	UDPTimeout string `json:"udp_timeout"`
	DNSPort    int    `json:"dns_port"`
	TunIPv4    string `json:"tun_ipv4"`
	TunIPv6    string `json:"tun_ipv6"`
}
type RuntimeChain struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode"`
	Upstream string `json:"upstream"`
	Exit     string `json:"exit"`
}
type RuntimeBlock struct {
	Enabled          bool     `json:"enabled"`
	Community        bool     `json:"community"`
	URL              string   `json:"url,omitempty"`
	Domains          []string `json:"domains"`
	Allow            []string `json:"allow"`
	CommunityDomains []string `json:"community_domains,omitempty"`
}
type RuntimeTunnel struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode,omitempty"`
	Revision       int64  `json:"revision"`
	Endpoint       M      `json:"endpoint,omitempty"`
	LogoutPending  bool   `json:"logout_pending,omitempty"`
	OwnedDirectory bool   `json:"owned_directory,omitempty"`
}
type RuntimeSettings struct {
	Schema       int                 `json:"schema"`
	Network      RuntimeNetwork      `json:"network"`
	DNSProfile   string              `json:"dns_profile"`
	Mode         string              `json:"mode"`
	RouteDomains map[string][]string `json:"route_domains"`
	Chain        RuntimeChain        `json:"chain"`
	Block        RuntimeBlock        `json:"block"`
	Warp         RuntimeTunnel       `json:"warp"`
	Tailscale    RuntimeTunnel       `json:"tailscale"`
}

func defaultRuntimeSettings() RuntimeSettings {
	return RuntimeSettings{Schema: 1, Network: RuntimeNetwork{"prefer_ipv4", 1400, "5m", 1053, "172.19.0.1/30", "fd12::2/126"}, DNSProfile: "default", Mode: "rule", RouteDomains: map[string][]string{}, Chain: RuntimeChain{Mode: "manual"}, Block: RuntimeBlock{Enabled: true, Domains: []string{}, Allow: []string{}}, Warp: RuntimeTunnel{Mode: "rule"}}
}
func (a *App) runtimeSettings() (RuntimeSettings, error) {
	s := defaultRuntimeSettings()
	e := ReadJSON(a.Path(".config", "magicnet", "runtime-settings.json"), 512<<10, &s)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return s, E("runtime.settings_invalid", "Runtime settings cannot be read")
	}
	if s.RouteDomains == nil {
		s.RouteDomains = map[string][]string{}
	}
	if e = validateRuntimeSettings(s); e != nil {
		return s, e
	}
	return s, nil
}

func validateRuntimeSettings(s RuntimeSettings) error {
	if s.Schema != 1 || !stringIn(s.Mode, "rule", "global", "direct") || !stringIn(s.DNSProfile, "default", "cloudflare-doh", "cloudflare-dot", "cloudflare-udp") {
		return E("runtime.settings_invalid", "Invalid runtime settings")
	}
	n := s.Network
	if !stringIn(n.IPv6Mode, "prefer_ipv4", "prefer_ipv6", "ipv4_only") || n.MTU < 1280 || n.MTU > 1500 || !stringIn(n.UDPTimeout, "1m", "3m", "5m", "10m", "15m", "30m") || n.DNSPort < 1 || n.DNSPort > 65535 {
		return E("network.invalid", "Invalid network settings")
	}
	for _, x := range []struct {
		cidr string
		v4   bool
	}{{n.TunIPv4, true}, {n.TunIPv6, false}} {
		p, e := netip.ParsePrefix(x.cidr)
		if e != nil || p.Addr().Is4() != x.v4 || !p.Addr().IsGlobalUnicast() {
			return E("network.cidr_invalid", "Invalid TUN address prefix")
		}
		next := p.Addr().Next()
		if !next.IsValid() || !p.Contains(next) {
			return E("network.cidr_invalid", "TUN prefix must leave room for its derived DNS address")
		}
		if x.v4 {
			if p.Bits() > 30 || p.Addr() == p.Masked().Addr() {
				return E("network.cidr_invalid", "TUN IPv4 address is not usable")
			}
			last := next.Next()
			if !p.Contains(last) {
				return E("network.cidr_invalid", "TUN IPv4 DNS address cannot be the broadcast address")
			}
		} else if p.Bits() > 126 {
			return E("network.cidr_invalid", "TUN IPv6 prefix must leave a DNS address")
		}
	}
	if !stringIn(s.Chain.Mode, "manual", "auto") {
		return E("chain.invalid", "Invalid proxy chain mode")
	}
	return nil
}

type RuntimeCheckpoint struct {
	Schema        int                   `json:"schema"`
	Base          M                     `json:"base"`
	Effective     M                     `json:"effective"`
	Patch         M                     `json:"patch"`
	RoutingOwned  RoutingOwned          `json:"routing_owned"`
	RuntimeOwned  RoutingOwned          `json:"runtime_owned"`
	Fingerprint   string                `json:"fingerprint"`
	SelectorEdits []RuntimeSelectorEdit `json:"selector_edits,omitempty"`
}

type RuntimeSelectorEdit struct {
	Tag    string `json:"tag"`
	Before M      `json:"before"`
	After  M      `json:"after"`
}

func runtimeSelectorFields(config M) map[string]M {
	fields := map[string]M{}
	for _, value := range rtArray(config["outbounds"]) {
		m := rtMap(value)
		if !stringIn(rtString(m["tag"]), "proxy", "ad-block") {
			continue
		}
		s := M{"outbounds": rtClone(m["outbounds"])}
		if v, ok := m["default"]; ok {
			s["default"] = v
		}
		fields[rtString(m["tag"])] = s
	}
	return fields
}

func undoRuntimeSelectorEdits(config M, edits []RuntimeSelectorEdit) error {
	for _, edit := range edits {
		var current M
		for _, v := range rtArray(config["outbounds"]) {
			if m := rtMap(v); rtString(m["tag"]) == edit.Tag {
				current = m
				break
			}
		}
		if current == nil {
			return E("override.routing_conflict", "A managed selector was removed")
		}
		before, _ := rtStringList(edit.Before["outbounds"])
		after, _ := rtStringList(edit.After["outbounds"])
		members, _ := rtStringList(current["outbounds"])
		kept := []string{}
		for _, member := range members {
			if stringIn(member, after...) && !stringIn(member, before...) {
				continue
			}
			kept = append(kept, member)
		}
		for _, member := range before {
			if !stringIn(member, after...) && !stringIn(member, kept...) {
				kept = append(kept, member)
			}
		}
		current["outbounds"] = rtStrings(kept)
		if rtEqual(current["default"], edit.After["default"]) {
			if value, ok := edit.Before["default"]; ok {
				current["default"] = value
			} else {
				delete(current, "default")
			}
		}
	}
	return nil
}

func (a *App) runtimeBase(config M) (M, error) {
	var cp RuntimeCheckpoint
	e := ReadJSON(a.Path(".state", "private", "runtime-checkpoint.json"), 16<<20, &cp)
	if errors.Is(e, os.ErrNotExist) {
		return rtClone(config).(map[string]any), nil
	}
	if e != nil || cp.Schema != 1 || cp.Base == nil || cp.Effective == nil {
		return nil, E("override.routing_conflict", "Runtime checkpoint is invalid")
	}
	current, e := StripRoutingOwned(config, cp.RoutingOwned)
	if e != nil {
		return nil, e
	}
	effective, e := StripRoutingOwned(cp.Effective, cp.RoutingOwned)
	if e != nil {
		return nil, e
	}
	current, e = undoMergePatch(current, cp.Base, effective, cp.Patch)
	if e != nil {
		return nil, e
	}
	if e = undoRuntimeSelectorEdits(current, cp.SelectorEdits); e != nil {
		return nil, e
	}
	return StripRoutingOwned(current, cp.RuntimeOwned)
}

func (a *App) MaterializeConfig(ctx context.Context, data []byte) ([]byte, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	doc, e := a.readOverride(true)
	if e != nil {
		return nil, e
	}
	return a.materializeWith(ctx, data, s, doc.Patch)
}

func (a *App) materializeWith(ctx context.Context, data []byte, s RuntimeSettings, patch M) ([]byte, error) {
	v, e := rtDecodeJSON(data)
	if e != nil || rtMap(v) == nil {
		return nil, E("config.invalid", "Configuration must be an object")
	}
	base, e := a.runtimeBase(rtMap(v))
	if e != nil {
		return nil, e
	}
	return a.materializeFromBase(ctx, base, s, patch)
}

func (a *App) materializeFromBase(ctx context.Context, base M, s RuntimeSettings, patch M) ([]byte, error) {
	var e error
	base, e = a.MaterializePlatform(ctx, base)
	if e != nil {
		return nil, e
	}
	beforeSelectors := runtimeSelectorFields(base)
	base, owned, e := a.applyRuntimeSettings(base, s)
	if e != nil {
		return nil, e
	}
	plainPatch := rtClone(patch).(map[string]any)
	overlay := plainPatch["$magicnet_routing"]
	delete(plainPatch, "$magicnet_routing")
	candidate := MergePatch(base, plainPatch)
	if e = protectedOverride(base, candidate); e != nil {
		return nil, e
	}
	candidate, routing, e := ApplyRoutingOverlay(candidate, overlay)
	if e != nil {
		return nil, e
	}
	delete(candidate, "$magicnet_routing")
	b := rtJSON(candidate)
	if len(b) > 4<<20 {
		return nil, E("config.limit", "Materialized configuration exceeds 4 MiB")
	}
	edits := []RuntimeSelectorEdit{}
	for tag, after := range runtimeSelectorFields(base) {
		if before := beforeSelectors[tag]; before != nil && !rtEqual(before, after) {
			edits = append(edits, RuntimeSelectorEdit{tag, before, after})
		}
	}
	checkpoint := &RuntimeCheckpoint{Schema: 1, Base: base, Effective: candidate, Patch: patch, RoutingOwned: routing, RuntimeOwned: owned, Fingerprint: digest(b), SelectorEdits: edits}
	if jsonSize(checkpoint) > 16<<20 {
		return nil, E("config.limit", "Runtime ownership metadata exceeds its recovery limit")
	}
	a.RuntimeCheckpoint = checkpoint
	return b, nil
}

func (a *App) CommitRuntimeCheckpoint() error {
	cp, ok := a.RuntimeCheckpoint.(*RuntimeCheckpoint)
	if !ok || cp == nil {
		return nil
	}
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		return e
	}
	if digest(b) != cp.Fingerprint {
		return E("override.rollback_conflict", "Candidate checkpoint does not match the active configuration")
	}
	if e = WriteJSON(a.Path(".state", "private", "runtime-checkpoint.json"), cp); e != nil {
		return e
	}
	a.RuntimeCheckpoint = nil
	return nil
}

func (a *App) applyRuntimeSettings(config M, s RuntimeSettings) (M, RoutingOwned, error) {
	owned := RoutingOwned{}
	if e := validateRuntimeSettings(s); e != nil {
		return nil, owned, e
	}
	dns := rtMap(config["dns"])
	route := rtMap(config["route"])
	if dns == nil || route == nil {
		return nil, owned, E("config.invalid", "Managed DNS and route sections are required")
	}
	dns["strategy"] = s.Network.IPv6Mode
	for _, v := range rtArray(config["inbounds"]) {
		m := rtMap(v)
		switch rtString(m["tag"]) {
		case "tun-in", "ebpf-in":
			m["udp_timeout"] = s.Network.UDPTimeout
			if rtString(m["type"]) == "tun" {
				m["mtu"] = s.Network.MTU
				addresses := []string{s.Network.TunIPv4}
				if s.Network.IPv6Mode != "ipv4_only" {
					addresses = append(addresses, s.Network.TunIPv6)
				}
				m["address"] = rtStrings(addresses)
			} else if rtString(m["type"]) == "ebpf" {
				for _, plane := range []string{"local", "shared"} {
					if p := rtMap(m[plane]); p != nil {
						p["ipv6"] = s.Network.IPv6Mode != "ipv4_only"
					}
				}
			}
		case "dns-in":
			m["listen_port"] = s.Network.DNSPort
		}
	}
	experimental := rtMap(config["experimental"])
	if experimental != nil {
		if api := rtMap(experimental["clash_api"]); api != nil {
			api["default_mode"] = s.Mode
		}
	}
	// Profiles are explicit resolver address choices. Detours remain attached
	// to the policy target, so a group change also changes its DNS path.
	for _, v := range rtArray(dns["servers"]) {
		m := rtMap(v)
		if m == nil {
			continue
		}
		tag := rtString(m["tag"])
		if tag != "doh-google" && tag != "doh-cloudflare" && !strings.HasPrefix(tag, "magicnet-dns-") {
			continue
		}
		local := rtString(m["detour"]) == "direct" || tag == "doh-cloudflare"
		for _, selector := range SystemSelectorDefaults {
			if selector.Tag == rtString(m["detour"]) && selector.Default == "direct" {
				local = true
				break
			}
		}
		if s.DNSProfile == "default" {
			m["type"] = "https"
			m["server_port"] = 443
			m["path"] = "/dns-query"
			if local {
				m["server"] = "1.1.1.1"
				m["tls"] = M{"enabled": true, "server_name": "cloudflare-dns.com"}
			} else {
				m["server"] = "8.8.8.8"
				m["tls"] = M{"enabled": true, "server_name": "dns.google"}
			}
		} else {
			m["server"] = "1.1.1.1"
			delete(m, "path")
			delete(m, "tls")
			switch s.DNSProfile {
			case "cloudflare-doh":
				m["type"] = "https"
				m["server_port"] = 443
				m["path"] = "/dns-query"
				m["tls"] = M{"enabled": true, "server_name": "cloudflare-dns.com"}
			case "cloudflare-dot":
				m["type"] = "tls"
				m["server_port"] = 853
				m["tls"] = M{"enabled": true, "server_name": "cloudflare-dns.com"}
			case "cloudflare-udp":
				m["type"] = "udp"
				m["server_port"] = 53
			}
		}
	}
	if !s.Block.Enabled {
		for _, v := range rtArray(config["outbounds"]) {
			m := rtMap(v)
			if rtString(m["tag"]) == "ad-block" {
				m["default"] = "direct"
				members, _ := rtStringList(m["outbounds"])
				if !stringIn("direct", members...) {
					m["outbounds"] = rtStrings(append(members, "direct"))
				}
			}
		}
	}
	for _, domain := range s.Block.Allow {
		d, e := canonicalDomain(domain)
		if e != nil {
			return nil, owned, E("block.invalid", "Invalid allow domain")
		}
		owned.RouteRules = append(owned.RouteRules, M{"domain_suffix": []any{d}, "outbound": "ad-allow"})
		owned.DNSRules = append(owned.DNSRules, M{"domain_suffix": []any{d}, "server": "magicnet-dns-ad-allow"})
	}
	if s.Block.Enabled {
		domains := append([]string{}, s.Block.Domains...)
		if s.Block.Community {
			domains = append(domains, s.Block.CommunityDomains...)
		}
		if len(domains) > 0 {
			owned.RouteRules = append(owned.RouteRules, M{"domain_suffix": rtStrings(domains), "outbound": "block"})
			owned.DNSRules = append(owned.DNSRules, M{"domain_suffix": rtStrings(domains), "action": "reject"})
		}
	}
	for _, target := range []string{"direct", "proxy", "block", "warp"} {
		domains := s.RouteDomains[target]
		if len(domains) == 0 {
			continue
		}
		if target == "warp" && !s.Warp.Enabled {
			return nil, owned, E("route.target_missing", "WARP routing requires an enabled imported endpoint")
		}
		owned.RouteRules = append(owned.RouteRules, M{"domain_suffix": rtStrings(domains), "outbound": target})
		dr := M{"domain_suffix": rtStrings(domains)}
		if target == "block" {
			dr["action"] = "reject"
		} else {
			server := "doh-google"
			if target == "direct" {
				server = "doh-cloudflare"
			}
			if target == "warp" {
				server = "magicnet-warp-dns"
			}
			dr["server"] = server
		}
		owned.DNSRules = append(owned.DNSRules, dr)
	}
	if s.Warp.Enabled {
		if s.Warp.Endpoint == nil {
			return nil, owned, E("warp.not_configured", "Import a WireGuard configuration first")
		}
		ep := rtClone(s.Warp.Endpoint).(map[string]any)
		ep["tag"] = "warp"
		ep["system"] = false
		owned.Endpoints = append(owned.Endpoints, ep)
		owned.DNSServers = append(owned.DNSServers, M{"type": "https", "tag": "magicnet-warp-dns", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": M{"enabled": true, "server_name": "cloudflare-dns.com"}, "detour": "warp"})
		if s.Warp.Mode == "global" {
			owned.RouteRules = append(owned.RouteRules, M{"outbound": "warp"})
			owned.DNSRules = append(owned.DNSRules, M{"server": "magicnet-warp-dns"})
		}
	}
	if s.Tailscale.Enabled {
		if s.Tailscale.Endpoint == nil {
			return nil, owned, E("tailscale.not_configured", "Configure a userspace Tailscale endpoint first")
		}
		ep := rtClone(s.Tailscale.Endpoint).(map[string]any)
		ep["system_interface"] = false
		delete(ep, "auth_key")
		tag := rtString(ep["tag"])
		if tag == "" {
			tag = "tailscale"
			ep["tag"] = tag
		}
		owned.Endpoints = append(owned.Endpoints, ep)
		owned.DNSServers = append(owned.DNSServers, M{"type": "tailscale", "tag": "magicnet-tailscale-dns", "endpoint": tag})
		// preferred_by asks the endpoint for actual peers/accepted routes. It
		// deliberately does not capture all CGNAT or the Tailscale IPv6 prefix.
		rr := M{"preferred_by": []any{tag}, "outbound": tag}
		dr := M{"domain_suffix": []any{"ts.net"}, "server": "magicnet-tailscale-dns"}
		route["rules"] = insertBeforeLAN(rtArray(route["rules"]), rr)
		dns["rules"] = insertBeforeLAN(rtArray(dns["rules"]), dr)
		owned.RouteRules = append(owned.RouteRules, rr)
		owned.DNSRules = append(owned.DNSRules, dr)
	}
	if s.Chain.Enabled {
		targets := map[string]M{}
		for _, v := range rtArray(config["outbounds"]) {
			m := rtMap(v)
			targets[rtString(m["tag"])] = m
		}
		up, exit := targets[s.Chain.Upstream], targets[s.Chain.Exit]
		if up == nil || exit == nil || s.Chain.Upstream == s.Chain.Exit {
			return nil, owned, E("chain.target_missing", "Choose two distinct existing proxy nodes")
		}
		if ValidateProxyNode(up) != nil || ValidateProxyNode(exit) != nil {
			return nil, owned, E("chain.invalid", "Proxy chains require concrete proxy endpoints")
		}
		cloned := rtClone(exit).(map[string]any)
		cloned["tag"] = "magicnet-chain-exit"
		cloned["detour"] = s.Chain.Upstream
		owned.Outbounds = append(owned.Outbounds, cloned)
		groupType := "selector"
		if s.Chain.Mode == "auto" {
			groupType = "urltest"
		}
		group := M{"type": groupType, "tag": "magicnet-chain", "outbounds": []any{"magicnet-chain-exit"}}
		if groupType == "urltest" {
			group["url"] = "https://www.gstatic.com/generate_204"
			group["interval"] = "3m"
		} else {
			group["default"] = "magicnet-chain-exit"
		}
		owned.Outbounds = append(owned.Outbounds, group)
		for _, v := range rtArray(config["outbounds"]) {
			m := rtMap(v)
			if rtString(m["tag"]) == "proxy" {
				members, _ := rtStringList(m["outbounds"])
				if !stringIn("magicnet-chain", members...) {
					members = append(members, "magicnet-chain")
				}
				m["outbounds"] = rtStrings(members)
				m["default"] = "magicnet-chain"
			}
		}
	}
	for _, n := range owned.Outbounds {
		config["outbounds"] = append(rtArray(config["outbounds"]), n)
	}
	for _, n := range owned.Endpoints {
		for _, v := range rtArray(config["endpoints"]) {
			if rtString(rtMap(v)["tag"]) == rtString(n["tag"]) {
				return nil, owned, E("runtime.tag_collision", "A managed endpoint tag conflicts with an existing endpoint")
			}
		}
		config["endpoints"] = append(rtArray(config["endpoints"]), n)
	}
	for _, n := range owned.DNSServers {
		for _, v := range rtArray(dns["servers"]) {
			if rtString(rtMap(v)["tag"]) == rtString(n["tag"]) {
				return nil, owned, E("runtime.tag_collision", "A managed DNS tag conflicts with an existing server")
			}
		}
		dns["servers"] = append(rtArray(dns["servers"]), n)
	}
	// Tailnet rules have already been inserted before LAN; append only the
	// remaining owned rules at the protected/user/business boundary.
	var rr, dd []M
	for _, r := range owned.RouteRules {
		if r["preferred_by"] == nil {
			rr = append(rr, r)
		}
	}
	for _, r := range owned.DNSRules {
		if rtString(r["server"]) != "magicnet-tailscale-dns" {
			dd = append(dd, r)
		}
	}
	route["rules"] = insertProtected(rtArray(route["rules"]), rr, false)
	dns["rules"] = insertProtected(rtArray(dns["rules"]), dd, true)
	return config, owned, nil
}

func insertBeforeLAN(rules []any, rule M) []any {
	at := 0
	for i, v := range rules {
		m := rtMap(v)
		if m["clash_mode"] != nil || m["action"] == "sniff" || m["action"] == "hijack-dns" {
			at = i + 1
			continue
		}
		break
	}
	out := append([]any{}, rules[:at]...)
	out = append(out, rule)
	return append(out, rules[at:]...)
}

func (a *App) CoreConfigWithSecrets(data []byte) ([]byte, error) {
	var config M
	if err := DecodeJSON(data, &config); err != nil {
		return nil, err
	}
	keys := map[string]string{}
	e := ReadJSON(a.Path(".config", "magicnet", "tailscale-auth.json"), 64<<10, &keys)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, E("tailscale.key_unavailable", "Private Tailscale credentials cannot be read")
	}
	for _, v := range rtArray(config["endpoints"]) {
		m := rtMap(v)
		if rtString(m["type"]) == "tailscale" {
			if rtBool(m["system_interface"]) {
				return nil, E("tailscale.system_interface_forbidden", "Tailscale must use userspace networking")
			}
			if rtString(m["auth_key"]) == "" {
				if key := keys[rtString(m["tag"])]; key != "" {
					m["auth_key"] = key
				}
			}
		}
	}
	return rtJSON(config), nil
}

func (a *App) NetworkStatus(ctx context.Context) (M, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	var effective any
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e == nil {
		var m M
		if DecodeJSON(b, &m) == nil {
			for _, v := range rtArray(m["inbounds"]) {
				in := rtMap(v)
				if rtString(in["tag"]) == "tun-in" || rtString(in["tag"]) == "ebpf-in" {
					effective = M{"mtu": in["mtu"], "udp_timeout": in["udp_timeout"], "ipv6_mode": rtMap(m["dns"])["strategy"], "mode": in["type"]}
				}
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, E("network.observation_failed", "Network configuration cannot be observed")
	}
	return M{"configured": s.Network, "effective": effective, "effective_is_configuration": true, "application_network": "unknown"}, nil
}

func (a *App) DNSStatus(ctx context.Context) (M, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	effective := M{"profile": "unknown", "capture_port": nil, "physical_leak_guard": nil, "application_dns": "unknown"}
	b, re := ReadRegular(a.ConfigPath(), 4<<20)
	if re == nil {
		var config M
		if DecodeJSON(b, &config) != nil {
			return nil, E("dns.observation_failed", "Effective DNS configuration is invalid")
		}
		servers := map[string]M{}
		for _, v := range rtArray(rtMap(config["dns"])["servers"]) {
			if m := rtMap(v); m != nil {
				servers[rtString(m["tag"])] = m
			}
		}
		remote, local := servers["doh-google"], servers["doh-cloudflare"]
		if remote != nil && local != nil {
			if rtString(remote["type"]) == "https" && rtString(remote["server"]) == "8.8.8.8" && rtString(local["type"]) == "https" && rtString(local["server"]) == "1.1.1.1" {
				effective["profile"] = "default"
			}
			if rtString(remote["server"]) == "1.1.1.1" && rtString(local["server"]) == "1.1.1.1" && remote["type"] == local["type"] {
				switch rtString(remote["type"]) {
				case "https":
					effective["profile"] = "cloudflare-doh"
				case "tls":
					effective["profile"] = "cloudflare-dot"
				case "udp":
					effective["profile"] = "cloudflare-udp"
				}
			}
		}
		for _, v := range rtArray(config["inbounds"]) {
			if m := rtMap(v); rtString(m["tag"]) == "dns-in" {
				effective["capture_port"] = m["listen_port"]
			}
		}
	} else if !errors.Is(re, os.ErrNotExist) {
		return nil, E("dns.observation_failed", "Effective DNS configuration cannot be read")
	}
	return M{"configured": M{"profile": s.DNSProfile, "capture_port": s.Network.DNSPort, "physical_leak_guard": os.Getenv("MAGIC_DNS_LEAK_GUARD") == "1"}, "effective": effective, "effective_is_configuration": true}, nil
}

func (a *App) RuntimeStatus(ctx context.Context, domain string) (M, error) {
	switch domain {
	case "subscription":
		return a.SubscriptionStatus(ctx, false)
	case "subscription-refresh":
		return a.SubscriptionScheduleStatus(ctx)
	case "dns":
		return a.DNSStatus(ctx)
	case "tailscale":
		return a.TailscaleStatus(ctx)
	case "overrides":
		return a.OverrideStatus(false)
	}
	return nil, E("runtime.domain_unknown", "Unknown runtime status domain")
}

func (a *App) writeRuntimeSettings(s RuntimeSettings) error {
	if e := validateRuntimeSettings(s); e != nil {
		return e
	}
	return WriteJSON(a.Path(".config", "magicnet", "runtime-settings.json"), s)
}

// Keep serialization deterministic for revision-free content fingerprints.
func runtimeSettingsBytes(s RuntimeSettings) []byte {
	b, _ := json.MarshalIndent(s, "", "  ")
	return append(b, '\n')
}

var _ = time.Second
