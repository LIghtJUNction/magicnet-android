package magicnet

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func (a *App) HandleRuntime(ctx context.Context, args []string, machine bool) (M, error, bool) {
	if len(args) == 0 {
		return nil, nil, false
	}
	family := args[0]
	if !stringIn(family, "setup", "sub", "override", "config", "config-editor", "network", "dns", "mode", "route", "block", "chain", "tailscale", "warp") {
		return nil, nil, false
	}
	var m M
	var err error
	switch family {
	case "setup":
		if len(args) != 2 {
			err = E("command.arguments", "setup requires one HTTPS subscription URL")
			break
		}
		if strings.ContainsAny(args[1], "\r\n") {
			err = E("subscription.input_invalid", "The single-source entry accepts one URL")
			break
		}
		m, err = a.ApplySubscriptionURLs(ctx, []byte(args[1]))
	case "sub":
		m, err = a.handleSubscription(ctx, args[1:])
	case "override":
		if len(args) == 2 && (args[1] == "status" || args[1] == "inspect") {
			m, err = a.OverrideStatus(args[1] == "inspect")
			break
		}
		if len(args) == 2 && args[1] == "apply" {
			saved, e := a.readOverride(false)
			if e != nil {
				err = e
				break
			}
			m, err = a.OverrideOperation(ctx, "apply", M{"expected_revision": saved.Revision})
			break
		}
		if len(args) != 3 || !stringIn(args[1], "preview-file", "set-file", "reset-file", "apply-file") {
			err = E("command.arguments", "Override requires a controlled private payload file")
			break
		}
		var b []byte
		b, err = a.privatePayload(args[2], 4<<20)
		if err != nil {
			break
		}
		var payload M
		if err = DecodeJSON(b, &payload); err != nil {
			err = E("override.invalid", "Invalid override payload")
			break
		}
		m, err = a.OverrideOperation(ctx, strings.TrimSuffix(args[1], "-file"), payload)
	case "config":
		if len(args) != 2 || args[1] != "apply" {
			err = E("command.arguments", "config supports apply")
			break
		}
		m, err = a.changeRuntimeSettings(ctx, func(*RuntimeSettings) error { return nil })
	case "config-editor":
		m, err = a.configEditor(ctx, args[1:])
	case "network":
		if len(args) == 2 && args[1] == "status" {
			m, err = a.NetworkStatus(ctx)
			break
		}
		if len(args) == 2 && args[1] == "preflight" {
			m, err = a.networkPreflight(ctx)
			break
		}
		if len(args) == 2 && args[1] == "apply" {
			m, err = a.changeRuntimeSettings(ctx, func(*RuntimeSettings) error { return nil })
			break
		}
		if len(args) != 5 || args[1] != "set" {
			err = E("command.arguments", "network set requires IPv6 mode, MTU and UDP timeout")
			break
		}
		mtu, e := strconv.Atoi(args[3])
		if e != nil {
			err = E("network.invalid", "MTU must be an integer")
			break
		}
		m, err = a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
			s.Network.IPv6Mode = args[2]
			s.Network.MTU = mtu
			s.Network.UDPTimeout = args[4]
			return validateRuntimeSettings(*s)
		})
	case "dns":
		if len(args) == 2 && args[1] == "status" {
			m, err = a.DNSStatus(ctx)
			break
		}
		if len(args) >= 2 && args[1] == "test" && len(args) <= 3 {
			domain := "example.com"
			if len(args) == 3 {
				domain = args[2]
			}
			m, err = a.dnsTest(ctx, domain)
			break
		}
		if len(args) == 2 && args[1] == "apply" {
			m, err = a.changeRuntimeSettings(ctx, func(*RuntimeSettings) error { return nil })
			break
		}
		if len(args) != 3 || args[1] != "set" {
			err = E("command.arguments", "dns set requires a profile")
			break
		}
		m, err = a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error { s.DNSProfile = args[2]; return validateRuntimeSettings(*s) })
	case "mode":
		if len(args) == 1 {
			s, e := a.runtimeSettings()
			err = e
			m = M{"mode": s.Mode}
			break
		}
		if len(args) != 2 || !stringIn(args[1], "rule", "global", "direct") {
			err = E("mode.invalid", "Mode must be rule, global or direct")
			break
		}
		m, err = a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error { s.Mode = args[1]; return nil })
	case "route":
		m, err = a.routeAction(ctx, args[1:])
	case "block":
		m, err = a.blockAction(ctx, args[1:])
	case "chain":
		m, err = a.chainAction(ctx, args[1:])
	case "tailscale":
		if len(args) == 2 && args[1] == "status" {
			m, err = a.TailscaleStatus(ctx)
			break
		}
		if len(args) != 3 || !stringIn(args[1], "enable", "disable", "logout") {
			err = E("command.arguments", "Tailscale mutation requires its current revision")
			break
		}
		revision, e := strconv.ParseInt(args[2], 10, 64)
		if e != nil || revision < 0 {
			err = E("tailscale.invalid", "Invalid Tailscale revision")
			break
		}
		m, err = a.tailscaleAction(ctx, args[1], revision)
	case "warp":
		m, err = a.warpAction(ctx, args[1:])
	}
	return m, err, true
}

func (a *App) handleSubscription(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "A subscription action is required")
	}
	action := args[0]
	switch action {
	case "status", "inspect":
		if len(args) != 1 {
			return nil, E("command.arguments", "Unexpected subscription status arguments")
		}
		return a.SubscriptionStatus(ctx, action == "inspect")
	case "set":
		if len(args) != 3 || !stringIn(args[1], "sing-box", "singbox") || strings.ContainsAny(args[2], "\r\n") {
			return nil, E("command.arguments", "sub set replaces one sing-box source")
		}
		return a.ApplySubscriptionURLs(ctx, []byte(args[2]))
	case "set-file", "apply-file":
		if len(args) != 3 || !stringIn(args[1], "sing-box", "singbox") {
			return nil, E("command.arguments", "A base64 encoded URL list is required")
		}
		data, e := base64.StdEncoding.DecodeString(args[2])
		if e != nil {
			return nil, E("subscription.input_invalid", "Invalid source-list encoding")
		}
		return a.ApplySubscriptionURLs(ctx, data)
	case "update":
		if len(args) != 2 || !stringIn(args[1], "sing-box", "singbox", "all") {
			return nil, E("command.arguments", "Invalid subscription update target")
		}
		return a.RefreshSubscriptions(ctx)
	case "update-all":
		if len(args) != 1 {
			return nil, E("command.arguments", "Unexpected update-all arguments")
		}
		return a.RefreshSubscriptions(ctx)
	case "clear":
		if len(args) != 1 {
			return nil, E("command.arguments", "Unexpected clear arguments")
		}
		return a.ClearSubscriptions(ctx)
	case "get", "list", "file":
		if action == "get" && (len(args) != 2 || !stringIn(args[1], "sing-box", "singbox")) || action == "list" && len(args) != 1 || action == "file" && (len(args) > 2 || len(args) == 2 && !stringIn(args[1], "sing-box", "singbox")) {
			return nil, E("command.arguments", "Invalid private source read")
		}
		s, e := a.subscriptionSnapshot()
		if e != nil {
			return nil, e
		}
		if action == "get" {
			first := ""
			if len(s.URLs) > 0 {
				first = s.URLs[0]
			}
			return M{"text": first, "legacy_first_only": true}, nil
		}
		if action == "file" {
			path := ""
			if s.Mode == "local_file" {
				path = a.Path(".config", "sing-box", "subscription.local")
			}
			return M{"text": path, "mode": s.Mode}, nil
		}
		return M{"text": strings.Join(s.URLs, "\n"), "urls": s.URLs}, nil
	case "resolve-host":
		if len(args) != 3 {
			return nil, E("command.arguments", "A hostname and port are required")
		}
		port, e := strconv.Atoi(args[2])
		if e != nil {
			return nil, E("subscription.url_policy", "Invalid port")
		}
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		ips, e := ResolveSubscriptionHost(c, args[1], port)
		if e != nil {
			return nil, e
		}
		lines := []string{}
		for _, ip := range ips {
			lines = append(lines, ip.String())
		}
		return M{"text": strings.Join(lines, "\n"), "addresses": lines, "evidence": "dns_and_public_address_policy_only"}, nil
	case "schedule":
		if len(args) == 2 && args[1] == "status" {
			return a.SubscriptionScheduleStatus(ctx)
		}
		if len(args) == 3 && args[1] == "set" {
			return a.SetSubscriptionSchedule(ctx, args[2])
		}
		return nil, E("command.arguments", "Invalid schedule arguments")
	case "user-agent", "filter":
		if len(args) < 2 {
			return nil, E("command.arguments", "Preference action is required")
		}
		ua, filters, e := a.subscriptionPreferences()
		if e != nil {
			return nil, e
		}
		if (action == "user-agent" && args[1] == "get" || action == "filter" && args[1] == "list") && len(args) == 2 {
			if action == "user-agent" {
				return M{"text": ua, "user_agent": ua}, nil
			}
			return M{"text": strings.Join(filters, "\n"), "filters": filters}, nil
		}
		path := a.Path(".config", "sing-box", "subscription.user-agent")
		if action == "filter" {
			path = a.Path(".config", "sing-box", "subscription-filter.list")
		}
		var data []byte
		if args[1] == "set" && len(args) == 3 {
			data, e = base64.StdEncoding.DecodeString(args[2])
			if e != nil {
				return nil, E("subscription.input_invalid", "Invalid preference encoding")
			}
			if action == "user-agent" {
				v, e := ValidateUserAgent(string(data))
				if e != nil {
					return nil, e
				}
				data = []byte(v + "\n")
			} else {
				v, e := NormalizeSubscriptionFilters(data)
				if e != nil {
					return nil, e
				}
				data = []byte(strings.Join(v, "\n") + "\n")
			}
		} else if args[1] != "clear" || len(args) != 2 {
			return nil, E("command.arguments", "Invalid subscription preference operation")
		}
		e = a.withLock(ctx, "subscription-preferences", 2*time.Second, func() error {
			if args[1] == "clear" {
				return removeRuntimeFile(path)
			}
			return AtomicWrite(path, data, 0600)
		})
		if e != nil {
			return nil, e
		}
		return M{"saved": true, "applies_on_next_refresh": true}, a.Publish(ctx)
	}
	return nil, E("command.unknown", "Unknown subscription action")
}

func (a *App) routeAction(ctx context.Context, args []string) (M, error) {
	if len(args) == 1 && args[0] == "list" {
		s, e := a.runtimeSettings()
		return M{"domains": s.RouteDomains}, e
	}
	if len(args) == 1 && args[0] == "apply" {
		return a.changeRuntimeSettings(ctx, func(*RuntimeSettings) error { return nil })
	}
	if len(args) != 3 || !stringIn(args[0], "add-domain", "remove-domain") || !stringIn(args[1], "direct", "proxy", "block", "warp") {
		return nil, E("route.invalid", "Invalid domain routing operation")
	}
	domain, e := canonicalDomain(args[2])
	if e != nil {
		return nil, E("route.invalid", "Invalid domain suffix")
	}
	return a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		list := s.RouteDomains[args[1]]
		next := []string{}
		for _, v := range list {
			if v != domain {
				next = append(next, v)
			}
		}
		if args[0] == "add-domain" {
			next = append(next, domain)
		}
		if len(next) > 256 {
			return E("route.limit", "At most 256 domain rules per target are allowed")
		}
		s.RouteDomains[args[1]] = next
		return nil
	})
}

func (a *App) blockAction(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "Blocklist action is required")
	}
	action := args[0]
	if len(args) == 1 && (action == "list" || action == "diff") {
		s, e := a.runtimeSettings()
		if e != nil {
			return nil, e
		}
		if action == "diff" {
			return M{"custom_count": len(s.Block.Domains), "allow_count": len(s.Block.Allow), "community_count": len(s.Block.CommunityDomains), "pending": false}, nil
		}
		return M{"enabled": s.Block.Enabled, "community": s.Block.Community, "domains": s.Block.Domains, "allow": s.Block.Allow, "source_url": s.Block.URL}, nil
	}
	return a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		switch action {
		case "enable", "disable", "apply":
			if len(args) != 1 {
				return E("command.arguments", "Unexpected blocklist arguments")
			}
			if action != "apply" {
				s.Block.Enabled = action == "enable"
			}
		case "community":
			if len(args) != 2 || !stringIn(args[1], "on", "off") {
				return E("block.invalid", "Community mode must be on or off")
			}
			s.Block.Community = args[1] == "on"
		case "url":
			if len(args) != 2 {
				return E("block.invalid", "A public HTTPS source is required")
			}
			u, e := NormalizeSubscriptionURL(args[1])
			if e != nil {
				return E("block.invalid", "Blocklist source must be public HTTPS")
			}
			s.Block.URL = u
		case "update":
			if len(args) != 1 || s.Block.URL == "" {
				return E("block.not_configured", "Configure an explicit blocklist source first")
			}
			f, e := (&SubscriptionFetcher{}).Fetch(ctx, s.Block.URL, "")
			if e != nil {
				return e
			}
			domains := []string{}
			seen := map[string]bool{}
			for _, line := range strings.Split(string(f.Body), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
					continue
				}
				line = strings.TrimPrefix(strings.TrimSuffix(line, "^"), "||")
				d, e := canonicalDomain(line)
				if e != nil {
					return E("block.invalid", "Blocklist contains an unsupported rule")
				}
				if !seen[d] {
					domains = append(domains, d)
					seen[d] = true
				}
				if len(domains) > 50000 {
					return E("block.limit", "Blocklist exceeds 50000 domains")
				}
			}
			s.Block.CommunityDomains = domains
		case "add-domain", "remove-domain", "allow-rule", "unallow-rule":
			if len(args) != 2 {
				return E("block.invalid", "A domain suffix is required")
			}
			d, e := canonicalDomain(args[1])
			if e != nil {
				return E("block.invalid", "Invalid blocklist domain")
			}
			list := &s.Block.Domains
			if action == "allow-rule" || action == "unallow-rule" {
				list = &s.Block.Allow
			}
			next := []string{}
			for _, v := range *list {
				if v != d {
					next = append(next, v)
				}
			}
			if action == "add-domain" || action == "allow-rule" {
				next = append(next, d)
			}
			if len(next) > 256 {
				return E("block.limit", "Custom block rules exceed 256 entries")
			}
			*list = next
		default:
			return E("command.unknown", "Unknown blocklist action")
		}
		return nil
	})
}

func (a *App) chainAction(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "Proxy chain action is required")
	}
	if len(args) == 1 && args[0] == "status" {
		s, e := a.runtimeSettings()
		return M{"configured": s.Chain, "effective_connectivity": "unknown"}, e
	}
	return a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		switch args[0] {
		case "enable", "disable", "clear-upstream", "clear-exit":
			if len(args) != 1 {
				return E("chain.invalid", "Invalid chain arguments")
			}
			switch args[0] {
			case "enable":
				s.Chain.Enabled = true
			case "disable":
				s.Chain.Enabled = false
			case "clear-upstream":
				s.Chain.Upstream = ""
				s.Chain.Enabled = false
			case "clear-exit":
				s.Chain.Exit = ""
				s.Chain.Enabled = false
			}
		case "set-upstream", "select-upstream", "set-exit", "select-exit", "mode":
			if len(args) != 2 {
				return E("chain.invalid", "A chain value is required")
			}
			if args[0] == "mode" {
				if !stringIn(args[1], "manual", "auto") {
					return E("chain.invalid", "Chain mode must be manual or auto")
				}
				s.Chain.Mode = args[1]
			} else {
				if !validNodeTag(args[1]) {
					return E("chain.invalid", "Invalid chain target")
				}
				if strings.HasSuffix(args[0], "upstream") {
					s.Chain.Upstream = args[1]
				} else {
					s.Chain.Exit = args[1]
				}
			}
		default:
			return E("command.unknown", "Unknown chain action")
		}
		return nil
	})
}

func (a *App) dnsTest(ctx context.Context, domain string) (M, error) {
	d, e := canonicalDomain(domain)
	if e != nil {
		return nil, E("dns.invalid", "Invalid DNS test domain")
	}
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Network.DNSPort)))
	}}
	start := time.Now()
	ips, e := resolver.LookupNetIP(c, "ip", d)
	if e != nil {
		return nil, E("dns.test_failed", "The local managed DNS listener did not resolve the test domain")
	}
	addresses := []string{}
	for _, ip := range ips {
		addresses = append(addresses, ip.String())
	}
	return M{"resolved": true, "addresses": addresses, "duration_ms": time.Since(start).Milliseconds(), "application_dns_verified": false}, nil
}

func (a *App) networkPreflight(ctx context.Context) (M, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	if e = validateRuntimeSettings(s); e != nil {
		return nil, e
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return M{"state": "unknown", "tun_conflict": nil, "dns_capture": "unknown"}, nil
	}
	conflict := false
	for _, i := range interfaces {
		if i.Name == "magicnet0" {
			continue
		}
		addresses, e := i.Addrs()
		if e != nil {
			return M{"state": "unknown", "tun_conflict": nil}, nil
		}
		for _, a := range addresses {
			p, e := netip.ParsePrefix(a.String())
			if e != nil {
				continue
			}
			for _, cidr := range []string{s.Network.TunIPv4, s.Network.TunIPv6} {
				candidate, _ := netip.ParsePrefix(cidr)
				if p.Contains(candidate.Addr()) || candidate.Contains(p.Addr()) {
					conflict = true
				}
			}
		}
	}
	state := "configuration_valid"
	if conflict {
		state = "conflict"
	}
	return M{"state": state, "tun_conflict": conflict, "dns_capture": "unknown", "dns_port": s.Network.DNSPort, "physical_leak_guard": "unknown", "application_dns": "unknown"}, nil
}

var _ = url.QueryEscape
var _ = errors.Is
var _ = os.ErrNotExist
