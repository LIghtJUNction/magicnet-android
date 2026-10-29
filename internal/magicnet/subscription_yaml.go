package magicnet

import (
	"fmt"
	"strconv"
	"strings"
)

func parseClashList(raw, groups any, result *ParsedSubscription) (*ParsedSubscription, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, E("subscription.format_unsupported", "YAML subscription needs a proxies array")
	}
	for _, item := range list {
		m := rtMap(item)
		if m == nil {
			return nil, E("subscription.node_invalid", "Invalid YAML proxy")
		}
		n, err := clashProxy(m)
		if err != nil {
			return nil, err
		}
		if err = addParsedOutbound(result, n); err != nil {
			return nil, err
		}
	}
	if groups != nil {
		list, ok := groups.([]any)
		if !ok {
			return nil, E("subscription.semantic_incomplete", "Invalid YAML groups")
		}
		for _, item := range list {
			m := rtMap(item)
			if m == nil || !rtAllowedKeys(m, "name type proxies url interval tolerance interrupt_exist_connections") {
				return nil, E("subscription.semantic_incomplete", "Unsupported YAML group option")
			}
			members, ok := rtStringList(m["proxies"])
			if !ok {
				return nil, E("subscription.semantic_incomplete", "YAML provider groups require explicit members")
			}
			for i, member := range members {
				switch member {
				case "DIRECT":
					members[i] = "direct"
				case "REJECT", "REJECT-DROP":
					members[i] = "block"
				}
			}
			t := rtString(m["type"])
			switch t {
			case "select":
				t = "selector"
			case "url-test":
				t = "urltest"
			default:
				return nil, E("subscription.semantic_incomplete", "Unsupported YAML group strategy")
			}
			n := M{"type": t, "tag": rtString(m["name"]), "outbounds": rtStrings(members)}
			if t == "urltest" {
				for _, key := range []string{"url", "tolerance", "interrupt_exist_connections"} {
					if v, ok := m[key]; ok {
						n[key] = v
					}
				}
				if v, ok := m["interval"]; ok {
					seconds, e := rtParseInt(v)
					if e != nil || seconds < 1 {
						return nil, E("subscription.node_invalid", "Invalid group interval")
					}
					n["interval"] = fmt.Sprintf("%ds", seconds)
				}
			}
			result.Groups = append(result.Groups, n)
		}
	}
	if result.ParsedCount == 0 {
		return nil, E("subscription.empty_result", "The source contains no proxy nodes")
	}
	return result, nil
}

func clashProxy(m M) (M, error) {
	const keys = "name type server port uuid password username cipher alterId security flow encryption servername sni skip-cert-verify alpn client-fingerprint reality-opts network ws-opts http-opts h2-opts grpc-opts http-upgrade-opts xhttp-opts plugin plugin-opts udp udp-over-tcp packet-encoding ip-version tfo mptcp interface-name routing-mark dialer-proxy smux obfs obfs-password obfs-opts up down ports hop-interval heartbeat-interval reduce-rtt fast-open congestion-controller udp-relay-mode disable-sni tls idle-session-check-interval idle-session-timeout min-idle-session client-metadata"
	if !rtAllowedKeys(m, keys) {
		return nil, E("subscription.semantic_incomplete", "A YAML proxy contains unsupported connection fields")
	}
	t := rtString(m["type"])
	switch t {
	case "ss":
		t = "shadowsocks"
	case "socks5":
		t = "socks"
	case "hy2":
		t = "hysteria2"
	}
	if t == "direct" || t == "reject" {
		return M{"type": "direct"}, nil
	}
	port, e := rtParseInt(m["port"])
	if e != nil {
		return nil, E("subscription.node_invalid", "Invalid YAML proxy port")
	}
	n := M{"type": t, "tag": rtString(m["name"]), "server": rtString(m["server"]), "server_port": port}
	for _, key := range []string{"uuid", "password", "username", "flow", "encryption"} {
		if v, ok := m[key]; ok {
			n[key] = v
		}
	}
	if t == "shadowsocks" {
		n["method"] = m["cipher"]
	}
	if t == "vmess" {
		n["security"] = firstString(rtString(m["cipher"]), rtString(m["security"]), "auto")
		if v, ok := m["alterId"]; ok {
			a, e := rtParseInt(v)
			if e != nil || a < 0 {
				return nil, E("subscription.node_invalid", "Invalid VMess alter id")
			}
			n["alter_id"] = a
		}
	}
	for src, dst := range map[string]string{"packet-encoding": "packet_encoding", "dialer-proxy": "detour", "interface-name": "bind_interface", "routing-mark": "routing_mark", "tfo": "tcp_fast_open", "mptcp": "tcp_multi_path", "idle-session-check-interval": "idle_session_check_interval", "idle-session-timeout": "idle_session_timeout", "min-idle-session": "min_idle_session", "client-metadata": "client_metadata"} {
		if v, ok := m[src]; ok {
			n[dst] = v
		}
	}
	if v, ok := m["udp"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, E("subscription.node_invalid", "Invalid YAML UDP option")
		}
		if !b {
			n["network"] = "tcp"
		}
	}
	if v, ok := m["udp-over-tcp"]; ok {
		b, ok := v.(bool)
		if !ok {
			return nil, E("subscription.node_invalid", "Invalid UDP-over-TCP option")
		}
		n["udp_over_tcp"] = M{"enabled": b}
	}
	if v, ok := m["ip-version"]; ok {
		mapped := map[string]string{"dual": "", "ipv4": "ipv4_only", "ipv6": "ipv6_only", "ipv4-prefer": "prefer_ipv4", "ipv6-prefer": "prefer_ipv6"}
		s, ok := mapped[rtString(v)]
		if !ok {
			return nil, E("subscription.semantic_incomplete", "Unsupported IP strategy")
		}
		if s != "" {
			n["domain_strategy"] = s
		}
	}
	tlsEnabled := t == "trojan" || t == "hysteria2" || t == "tuic" || t == "anytls"
	tls := M{"enabled": tlsEnabled}
	if v, ok := m["tls"]; ok {
		switch val := v.(type) {
		case bool:
			tls["enabled"] = val
		case map[string]any:
			tls = rtClone(val).(map[string]any)
		default:
			return nil, E("subscription.node_invalid", "Invalid YAML TLS options")
		}
	}
	for src, dst := range map[string]string{"skip-cert-verify": "insecure", "alpn": "alpn", "disable-sni": "disable_sni"} {
		if v, ok := m[src]; ok {
			tls[dst] = v
		}
	}
	if s := firstString(rtString(m["servername"]), rtString(m["sni"])); s != "" {
		tls["server_name"] = s
	}
	if fp := rtString(m["client-fingerprint"]); fp != "" {
		tls["utls"] = M{"enabled": true, "fingerprint": fp}
	}
	if v, ok := m["reality-opts"]; ok {
		r := rtMap(v)
		if r == nil || !rtAllowedKeys(r, "public-key short-id") {
			return nil, E("subscription.semantic_incomplete", "Unsupported Reality options")
		}
		tls["enabled"] = true
		tls["reality"] = M{"enabled": true, "public_key": r["public-key"], "short_id": r["short-id"]}
	}
	if rtBool(tls["enabled"]) || len(tls) > 1 || m["tls"] != nil {
		n["tls"] = tls
	}
	if e = clashTransport(m, n); e != nil {
		return nil, e
	}
	if v, ok := m["smux"]; ok {
		s := rtMap(v)
		if s == nil || !rtAllowedKeys(s, "enabled protocol max-connections min-streams max-streams padding brutal-opts") {
			return nil, E("subscription.semantic_incomplete", "Unsupported multiplex options")
		}
		mux := M{}
		for k, v := range s {
			if k == "brutal-opts" {
				b := rtMap(v)
				if b == nil || !rtAllowedKeys(b, "enabled up down") {
					return nil, E("subscription.semantic_incomplete", "Unsupported multiplex bandwidth")
				}
				x := M{"enabled": b["enabled"]}
				for src, dst := range map[string]string{"up": "up_mbps", "down": "down_mbps"} {
					if v, ok := b[src]; ok {
						z, e := clashBandwidth(v)
						if e != nil {
							return nil, e
						}
						x[dst] = z
					}
				}
				mux["brutal"] = x
			} else {
				mux[strings.ReplaceAll(k, "-", "_")] = v
			}
		}
		n["multiplex"] = mux
	}
	if v, ok := m["plugin"]; ok {
		if t != "shadowsocks" {
			return nil, E("subscription.semantic_incomplete", "Plugin requires Shadowsocks")
		}
		n["plugin"] = v
		if opts, exists := m["plugin-opts"]; exists {
			switch x := opts.(type) {
			case string:
				n["plugin_opts"] = x
			case map[string]any:
				if !rtAllowedKeys(x, "mode host path tls mux skip-cert-verify") {
					return nil, E("subscription.semantic_incomplete", "Unsupported plugin options")
				}
				parts := []string{}
				for _, k := range []string{"mode", "host", "path", "tls", "mux", "skip-cert-verify"} {
					if v, ok := x[k]; ok {
						if b, ok := v.(bool); ok {
							if b {
								parts = append(parts, k)
							}
						} else if s, ok := v.(string); ok {
							if strings.Contains(s, ";") {
								return nil, E("subscription.semantic_incomplete", "Ambiguous plugin option")
							}
							parts = append(parts, k+"="+s)
						} else {
							return nil, E("subscription.node_invalid", "Invalid plugin option")
						}
					}
				}
				n["plugin_opts"] = strings.Join(parts, ";")
			default:
				return nil, E("subscription.node_invalid", "Invalid plugin options")
			}
		}
	} else if _, ok := m["plugin-opts"]; ok {
		return nil, E("subscription.semantic_incomplete", "Plugin options require a plugin")
	}
	if t == "hysteria2" {
		for src, dst := range map[string]string{"up": "up_mbps", "down": "down_mbps"} {
			if v, ok := m[src]; ok {
				b, e := clashBandwidth(v)
				if e != nil {
					return nil, e
				}
				n[dst] = b
			}
		}
		if v, ok := m["ports"]; ok {
			switch x := v.(type) {
			case string:
				n["server_ports"] = strings.Split(x, ",")
			case []any:
				n["server_ports"] = x
			default:
				return nil, E("subscription.node_invalid", "Invalid port hopping")
			}
		}
		if v, ok := m["hop-interval"]; ok {
			n["hop_interval"] = v
		}
		if v, ok := m["obfs"]; ok {
			obfs := M{"type": v, "password": m["obfs-password"]}
			if x, ok := m["obfs-opts"]; ok {
				opts := rtMap(x)
				if opts == nil || !rtAllowedKeys(opts, "password") {
					return nil, E("subscription.semantic_incomplete", "Unsupported obfuscation")
				}
				obfs["password"] = opts["password"]
			}
			n["obfs"] = obfs
		}
	} else {
		for _, k := range []string{"up", "down", "ports", "hop-interval", "obfs", "obfs-password", "obfs-opts"} {
			if _, ok := m[k]; ok {
				return nil, E("subscription.semantic_incomplete", "Unexpected protocol options")
			}
		}
	}
	if t == "tuic" {
		for src, dst := range map[string]string{"congestion-controller": "congestion_control", "udp-relay-mode": "udp_relay_mode", "reduce-rtt": "zero_rtt_handshake"} {
			if v, ok := m[src]; ok {
				n[dst] = v
			}
		}
		if v, ok := m["heartbeat-interval"]; ok {
			if s, ok := v.(string); ok {
				n["heartbeat"] = s
			} else {
				seconds, e := rtParseInt(v)
				if e != nil {
					return nil, E("subscription.node_invalid", "Invalid heartbeat")
				}
				n["heartbeat"] = fmt.Sprintf("%ds", seconds)
			}
		}
		if v, ok := m["fast-open"]; ok {
			n["zero_rtt_handshake"] = v
		}
	} else {
		for _, k := range []string{"congestion-controller", "udp-relay-mode", "reduce-rtt", "heartbeat-interval", "fast-open"} {
			if _, ok := m[k]; ok {
				return nil, E("subscription.semantic_incomplete", "Unexpected TUIC parameter")
			}
		}
	}
	if e = ValidateProxyNode(n); e != nil {
		return nil, e
	}
	return n, nil
}

func clashTransport(m, n M) error {
	t := rtString(m["network"])
	if t == "" || t == "tcp" {
		for _, k := range []string{"ws-opts", "http-opts", "h2-opts", "grpc-opts", "http-upgrade-opts", "xhttp-opts"} {
			if _, ok := m[k]; ok {
				return E("subscription.semantic_incomplete", "Transport options require their matching network")
			}
		}
		return nil
	}
	tr := M{"type": t}
	key := map[string]string{"ws": "ws-opts", "http": "http-opts", "h2": "h2-opts", "grpc": "grpc-opts", "httpupgrade": "http-upgrade-opts", "xhttp": "xhttp-opts"}[t]
	if key == "" {
		if t == "quic" {
			n["transport"] = tr
			return nil
		}
		return E("subscription.semantic_incomplete", "Unsupported YAML transport")
	}
	for _, k := range []string{"ws-opts", "http-opts", "h2-opts", "grpc-opts", "http-upgrade-opts", "xhttp-opts"} {
		if k != key {
			if _, ok := m[k]; ok {
				return E("subscription.semantic_incomplete", "Conflicting transport options")
			}
		}
	}
	opts := M{}
	if v, ok := m[key]; ok {
		opts = rtMap(v)
		if opts == nil {
			return E("subscription.node_invalid", "Invalid transport options")
		}
	}
	switch t {
	case "ws":
		if !rtAllowedKeys(opts, "path headers max-early-data early-data-header-name") {
			return E("subscription.semantic_incomplete", "Unsupported WebSocket option")
		}
		for k, v := range opts {
			tr[strings.ReplaceAll(k, "-", "_")] = v
		}
	case "grpc":
		if !rtAllowedKeys(opts, "grpc-service-name service-name idle-timeout ping-timeout permit-without-stream") {
			return E("subscription.semantic_incomplete", "Unsupported gRPC option")
		}
		for k, v := range opts {
			if k == "grpc-service-name" {
				k = "service-name"
			}
			tr[strings.ReplaceAll(k, "-", "_")] = v
		}
	case "h2", "http":
		tr["type"] = "http"
		if !rtAllowedKeys(opts, "host path method headers") {
			return E("subscription.semantic_incomplete", "Unsupported HTTP transport option")
		}
		for k, v := range opts {
			if k == "path" {
				if xs, ok := v.([]any); ok {
					if len(xs) != 1 {
						return E("subscription.semantic_incomplete", "Multiple HTTP paths cannot be represented")
					}
					v = xs[0]
				}
			}
			tr[k] = v
		}
	case "httpupgrade":
		if !rtAllowedKeys(opts, "host path headers") {
			return E("subscription.semantic_incomplete", "Unsupported HTTP upgrade option")
		}
		for k, v := range opts {
			tr[k] = v
		}
	case "xhttp":
		// Native core spelling is deliberately required for advanced XHTTP
		// fields; their full semantics are checked by the fixed engine.
		if !rtAllowedKeys(opts, "host path mode headers extra") {
			return E("subscription.semantic_incomplete", "Unsupported XHTTP wrapper option")
		}
		for k, v := range opts {
			if k == "extra" {
				extra := rtMap(v)
				if extra == nil {
					return E("subscription.node_invalid", "Invalid XHTTP extra")
				}
				for x, y := range extra {
					if x == "type" || x == "host" || x == "path" || x == "mode" {
						return E("subscription.semantic_incomplete", "Conflicting XHTTP extra")
					}
					tr[x] = y
				}
			} else {
				tr[k] = v
			}
		}
	}
	n["transport"] = tr
	return nil
}

func clashBandwidth(v any) (int64, error) {
	if n, ok := rtInt(v); ok && n >= 0 {
		return n, nil
	}
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(s), "mbps"), "mb"))
		if n, e := strconv.ParseInt(s, 10, 64); e == nil && n >= 0 {
			return n, nil
		}
	}
	return 0, E("subscription.node_invalid", "Invalid bandwidth value")
}
