package magicnet

import (
	"context"
	"strings"
	"testing"
)

func overlayBase() M {
	return M{"outbounds": []any{M{"type": "direct", "tag": "direct"}, M{"type": "block", "tag": "block"}, M{"type": "selector", "tag": "proxy", "outbounds": []any{"block"}, "default": "block"}}, "dns": M{"servers": []any{M{"type": "https", "tag": "doh-cloudflare", "server": "1.1.1.1", "detour": "direct"}, M{"type": "https", "tag": "doh-google", "server": "8.8.8.8", "detour": "proxy"}}, "rules": []any{M{"clash_mode": "direct", "server": "doh-cloudflare"}, M{"domain_suffix": []any{"ordinary.example"}, "server": "doh-google"}}}, "route": M{"rules": []any{M{"clash_mode": "direct", "outbound": "direct"}, M{"protocol": "dns", "action": "hijack-dns"}, M{"ip_is_private": true, "outbound": "direct"}, M{"domain_suffix": []any{"ordinary.example"}, "outbound": "proxy"}}}}
}

func TestRoutingOverlayOwnershipAndLimits(t *testing.T) {
	base := overlayBase()
	overlay := M{"schema": 1, "rules": []any{M{"kind": "domain", "value": "  EXAMPLE.COM ", "outbound": "Custom"}, M{"kind": "app", "value": "com.example.reader", "outbound": "block"}}, "outbounds": []any{M{"type": "selector", "tag": "Custom", "outbounds": []any{"proxy", "direct"}, "default": "proxy"}}}
	materialized, owned, e := ApplyRoutingOverlay(base, overlay)
	if e != nil {
		t.Fatal(e)
	}
	rules := rtArray(rtMap(materialized["route"])["rules"])
	if len(rules) != 6 || rtString(rtMap(rules[3])["outbound"]) != "Custom" {
		t.Fatal("overlay order changed")
	}
	domains, _ := rtStringList(owned.RouteRules[0]["domain_suffix"])
	if domains[0] != "example.com" {
		t.Fatal("domain normalization drift")
	}
	materialized["outbounds"] = append(rtArray(materialized["outbounds"]), testTrojan("new-subscription", "new.example.invalid"))
	reset, e := StripRoutingOwned(materialized, owned)
	if e != nil || len(rtArray(reset["outbounds"])) != 4 {
		t.Fatal("reset removed a later subscription", e)
	}
	mutated := rtClone(materialized).(map[string]any)
	for _, v := range rtArray(mutated["outbounds"]) {
		m := rtMap(v)
		if m["tag"] == "Custom" {
			m["default"] = "direct"
		}
	}
	if _, e := StripRoutingOwned(mutated, owned); ErrorCode(e) != "override.routing_conflict" {
		t.Fatal(e)
	}
	duplicate := rtClone(overlay).(map[string]any)
	duplicate["rules"] = append(rtArray(duplicate["rules"]), M{"kind": "domain", "value": "example.com", "outbound": "direct"})
	if _, _, e := ApplyRoutingOverlay(base, duplicate); ErrorCode(e) != "override.routing_duplicate" {
		t.Fatal(e)
	}
	for _, test := range []struct {
		o    M
		code string
	}{
		{M{"schema": 1, "outbounds": []any{M{"type": "selector", "tag": "proxy", "outbounds": []any{"direct"}}}}, "override.routing_tag_collision"},
		{M{"schema": 1, "outbounds": []any{M{"type": "selector", "tag": "a", "outbounds": []any{"b"}}, M{"type": "selector", "tag": "b", "outbounds": []any{"a"}}}}, "override.routing_cycle"},
		{M{"schema": 1, "rules": []any{M{"kind": "domain", "value": "example.com", "outbound": "missing"}}}, "override.routing_target_missing"},
		{M{"schema": 1, "outbounds": []any{M{"type": "selector", "tag": strings.Repeat("a", 257), "outbounds": []any{"direct"}}}}, "override.routing_invalid"},
	} {
		if _, _, e := ApplyRoutingOverlay(base, test.o); ErrorCode(e) != test.code {
			t.Fatal(e, test.code)
		}
	}
	valid := M{"schema": 1, "outbounds": []any{M{"type": "selector", "tag": strings.Repeat("界", 85) + "a", "outbounds": []any{"direct"}}}}
	if _, _, e := ApplyRoutingOverlay(base, valid); e != nil {
		t.Fatal("256 UTF-8 bytes rejected", e)
	}
}

func TestRealCoreOverlayApplyResetAndRepeat(t *testing.T) {
	a := realCoreFixture(t)
	if e := a.EnsureDefaultConfig(context.Background()); e != nil {
		t.Fatal(e)
	}
	patch := M{"$magicnet_routing": M{"schema": 1, "rules": []any{M{"kind": "domain", "value": "example.invalid", "outbound": "Private route"}}, "outbounds": []any{M{"type": "selector", "tag": "Private route", "outbounds": []any{"direct", "proxy"}, "default": "direct"}}}}
	m, e := a.OverrideOperation(context.Background(), "preview", M{"patch": patch})
	if e != nil || m["valid"] != true {
		t.Fatal(e, m)
	}
	m, e = a.OverrideOperation(context.Background(), "set", M{"patch": patch, "expected_revision": 0})
	if e != nil {
		t.Fatal(e)
	}
	m, e = a.OverrideOperation(context.Background(), "apply", M{"expected_revision": 1})
	if e != nil {
		t.Fatal(e)
	}
	first, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	candidate, e := a.MaterializeConfig(context.Background(), first)
	if e != nil {
		t.Fatal(e)
	}
	if string(first) != string(candidate) {
		t.Fatal("repeated materialization changed configuration")
	}
	checkRealCore(t, a, candidate)
	if _, e = a.OverrideOperation(context.Background(), "set", M{"patch": M{"log": M{"level": "info"}}, "expected_revision": 0}); ErrorCode(e) != "override.conflict" {
		t.Fatal(e)
	}
	if _, e = a.OverrideOperation(context.Background(), "reset", M{"expected_revision": 1}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.OverrideOperation(context.Background(), "apply", M{"expected_revision": 2}); e != nil {
		t.Fatal(e)
	}
}

func TestNetworkCIDRAndWireGuardValidation(t *testing.T) {
	s := defaultRuntimeSettings()
	for _, cidr := range []string{"172.20.0.1/30"} {
		s.Network.TunIPv4 = cidr
		if e := validateRuntimeSettings(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, cidr := range []string{"172.20.0.2/30", "172.20.0.3/30"} {
		s.Network.TunIPv4 = cidr
		if e := validateRuntimeSettings(s); e == nil {
			t.Fatal("invalid IPv4 DNS space", cidr)
		}
	}
	s = defaultRuntimeSettings()
	s.Network.TunIPv6 = "fd12::3/126"
	if e := validateRuntimeSettings(s); e == nil {
		t.Fatal("invalid IPv6 DNS space")
	}
	if _, e := ParseWireGuardConfiguration([]byte("[Interface]\nPrivateKey=invalid\nAddress=172.16.0.2/32\n[Peer]\nPublicKey=invalid\nEndpoint=example.invalid:2408\nAllowedIPs=0.0.0.0/0\n")); e == nil {
		t.Fatal("invalid WireGuard keys accepted")
	}
}
