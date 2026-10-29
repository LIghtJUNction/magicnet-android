package magicnet

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

func ParseShareLink(text string) (M, error) {
	if strings.HasPrefix(strings.ToLower(text), "vmess://") {
		return parseVMessLink(text[len("vmess://"):])
	}
	if strings.HasPrefix(strings.ToLower(text), "ss://") {
		return parseShadowsocksLink(text)
	}
	u, err := url.Parse(text)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return nil, E("subscription.node_invalid", "Invalid share URI")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, E("subscription.node_invalid", "Invalid share URI query")
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, E("subscription.semantic_incomplete", "Repeated share parameters are ambiguous")
		}
	}
	if u.Path != "" && u.Path != "/" {
		return nil, E("subscription.semantic_incomplete", "Unexpected share URI path")
	}
	host, port, err := splitServerPort(u.Host)
	if err != nil {
		return nil, err
	}
	t := strings.ToLower(u.Scheme)
	if t == "socks5" {
		t = "socks"
	}
	if t == "hy2" {
		t = "hysteria2"
	}
	if t == "https" {
		t = "http"
	}
	n := M{"type": t, "tag": u.Fragment, "server": host, "server_port": port}
	allowed := "sni servername peer alpn allowInsecure insecure fp type security host path serviceName headerType packetEncoding packet_encoding remarks remark"
	switch t {
	case "vless":
		allowed += " flow encryption pbk sid mode extra"
		if u.User == nil {
			return nil, E("subscription.node_invalid", "VLESS UUID is required")
		}
		n["uuid"] = u.User.Username()
		if _, set := u.User.Password(); set {
			return nil, E("subscription.node_invalid", "Unexpected VLESS password")
		}
		if _, ok := q["flow"]; ok {
			n["flow"] = q.Get("flow")
		}
		if _, ok := q["encryption"]; ok {
			n["encryption"] = q.Get("encryption")
		}
	case "trojan", "anytls", "hysteria2":
		allowed += " obfs obfs-password upmbps downmbps mport"
		if u.User == nil {
			return nil, E("subscription.node_invalid", "Proxy password is required")
		}
		n["password"] = u.User.Username()
		if password, set := u.User.Password(); set {
			n["password"] = u.User.Username() + ":" + password
		}
		if t == "hysteria2" {
			if q.Get("obfs") != "" {
				n["obfs"] = M{"type": q.Get("obfs"), "password": q.Get("obfs-password")}
			}
			for _, k := range []string{"upmbps", "downmbps"} {
				if q.Get(k) != "" {
					v, e := strconv.Atoi(q.Get(k))
					if e != nil || v < 0 {
						return nil, E("subscription.node_invalid", "Invalid bandwidth")
					}
					key := "up_mbps"
					if k == "downmbps" {
						key = "down_mbps"
					}
					n[key] = v
				}
			}
			if q.Get("mport") != "" {
				n["server_ports"] = strings.Split(q.Get("mport"), ",")
			}
		} else if q.Get("obfs") != "" || q.Get("obfs-password") != "" || q.Get("upmbps") != "" || q.Get("downmbps") != "" || q.Get("mport") != "" {
			return nil, E("subscription.semantic_incomplete", "Protocol parameters cannot be represented")
		}
	case "tuic":
		allowed += " congestion_control udp_relay_mode disable_sni heartbeat zero_rtt_handshake"
		if u.User == nil {
			return nil, E("subscription.node_invalid", "TUIC credentials are required")
		}
		n["uuid"] = u.User.Username()
		n["password"], _ = u.User.Password()
		for _, k := range []string{"congestion_control", "udp_relay_mode", "heartbeat"} {
			if q.Get(k) != "" {
				n[k] = q.Get(k)
			}
		}
		if _, ok := q["zero_rtt_handshake"]; ok {
			b, e := shareBool(q.Get("zero_rtt_handshake"))
			if e != nil {
				return nil, e
			}
			n["zero_rtt_handshake"] = b
		}
	case "socks", "http":
		allowed += " version"
		if u.User != nil {
			n["username"] = u.User.Username()
			n["password"], _ = u.User.Password()
		}
		if q.Get("version") != "" {
			if t != "socks" {
				return nil, E("subscription.semantic_incomplete", "HTTP version query is unsupported")
			}
			n["version"] = q.Get("version")
		}
	default:
		return nil, E("subscription.format_unsupported", "Unsupported share protocol")
	}
	keys := M{}
	for k := range q {
		keys[k] = true
	}
	if !rtAllowedKeys(keys, allowed) {
		return nil, E("subscription.semantic_incomplete", "Unrecognized share parameter; nothing was imported")
	}
	if rtString(n["tag"]) == "" {
		n["tag"] = firstString(q.Get("remarks"), q.Get("remark"), t)
	}
	if q.Get("packetEncoding") != "" || q.Get("packet_encoding") != "" {
		if t != "vless" {
			return nil, E("subscription.semantic_incomplete", "Unexpected packet encoding")
		}
		n["packet_encoding"] = firstString(q.Get("packetEncoding"), q.Get("packet_encoding"))
	}
	defaultTLS := t == "trojan" || t == "anytls" || t == "hysteria2" || t == "tuic" || u.Scheme == "https"
	if err = applyShareTLS(n, q, defaultTLS); err != nil {
		return nil, err
	}
	if err = applyShareTransport(n, q); err != nil {
		return nil, err
	}
	if err = ValidateProxyNode(n); err != nil {
		return nil, err
	}
	return n, nil
}

func firstString(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
func shareBool(s string) (bool, error) {
	switch s {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	}
	return false, E("subscription.node_invalid", "Invalid boolean share parameter")
}

func applyShareTLS(n M, q url.Values, enabled bool) error {
	security := q.Get("security")
	if security != "" {
		switch security {
		case "tls", "reality":
			enabled = true
		case "none":
			enabled = false
		default:
			return E("subscription.semantic_incomplete", "Unsupported share security mode")
		}
	}
	tls := M{"enabled": enabled}
	if s := firstString(q.Get("sni"), q.Get("servername"), q.Get("peer")); s != "" {
		tls["server_name"] = s
	}
	if s := q.Get("alpn"); s != "" {
		tls["alpn"] = strings.Split(s, ",")
	}
	if s := firstString(q.Get("allowInsecure"), q.Get("insecure")); s != "" {
		b, err := shareBool(s)
		if err != nil {
			return err
		}
		tls["insecure"] = b
	}
	if s := q.Get("fp"); s != "" {
		tls["utls"] = M{"enabled": true, "fingerprint": s}
	}
	if security == "reality" {
		tls["reality"] = M{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
	} else if q.Get("pbk") != "" || q.Get("sid") != "" {
		return E("subscription.semantic_incomplete", "Reality fields require Reality security")
	}
	if s := q.Get("disable_sni"); s != "" {
		b, e := shareBool(s)
		if e != nil {
			return e
		}
		tls["disable_sni"] = b
	}
	if len(tls) > 1 || enabled || security != "" {
		n["tls"] = tls
	}
	return nil
}

func applyShareTransport(n M, q url.Values) error {
	t := q.Get("type")
	if t == "" || t == "tcp" {
		if q.Get("headerType") != "" && q.Get("headerType") != "none" || q.Get("host") != "" || q.Get("path") != "" || q.Get("serviceName") != "" || q.Get("mode") != "" || q.Get("extra") != "" {
			return E("subscription.semantic_incomplete", "TCP transport extensions cannot be silently ignored")
		}
		return nil
	}
	if rtString(n["type"]) != "vless" && rtString(n["type"]) != "trojan" && rtString(n["type"]) != "vmess" {
		return E("subscription.semantic_incomplete", "Transport is not supported for this protocol")
	}
	tr := M{"type": t}
	switch t {
	case "ws":
		tr["path"] = q.Get("path")
		if q.Get("host") != "" {
			tr["headers"] = M{"Host": q.Get("host")}
		}
	case "grpc":
		tr["service_name"] = q.Get("serviceName")
	case "h2", "http":
		tr["type"] = "http"
		tr["path"] = q.Get("path")
		if q.Get("host") != "" {
			tr["host"] = strings.Split(q.Get("host"), ",")
		}
	case "httpupgrade", "xhttp", "splithttp":
		if t == "splithttp" {
			tr["type"] = "xhttp"
		}
		tr["host"] = q.Get("host")
		tr["path"] = q.Get("path")
		if q.Get("mode") != "" {
			if t == "httpupgrade" {
				return E("subscription.semantic_incomplete", "Unexpected transport mode")
			}
			tr["mode"] = q.Get("mode")
		}
		if q.Get("extra") != "" {
			v, e := rtDecodeJSON([]byte(q.Get("extra")))
			if e != nil || rtMap(v) == nil {
				return E("subscription.node_invalid", "Invalid XHTTP extra options")
			}
			for k, v := range rtMap(v) {
				if k == "type" || k == "host" || k == "path" || k == "mode" {
					return E("subscription.semantic_incomplete", "Conflicting transport options")
				}
				tr[k] = v
			}
		}
	case "quic":
		if q.Get("host") != "" || q.Get("path") != "" {
			return E("subscription.semantic_incomplete", "QUIC extensions cannot be represented")
		}
	default:
		return E("subscription.semantic_incomplete", "Unsupported transport")
	}
	if t != "grpc" && q.Get("serviceName") != "" {
		return E("subscription.semantic_incomplete", "Unexpected gRPC service name")
	}
	if q.Get("headerType") != "" && q.Get("headerType") != "none" {
		return E("subscription.semantic_incomplete", "Unsupported transport header")
	}
	if t != "xhttp" && t != "splithttp" && (q.Get("mode") != "" || q.Get("extra") != "") {
		return E("subscription.semantic_incomplete", "Unexpected transport option")
	}
	n["transport"] = tr
	return nil
}

func parseVMessLink(encoded string) (M, error) {
	b, err := rtBase64(encoded)
	if err != nil {
		return nil, E("subscription.node_invalid", "Invalid VMess encoding")
	}
	v, err := rtDecodeJSON(b)
	if err != nil || rtMap(v) == nil {
		return nil, E("subscription.node_invalid", "Invalid VMess document")
	}
	m := rtMap(v)
	if !rtAllowedKeys(m, "v ps add port id aid scy net type host path tls sni alpn fp allowInsecure encryption") {
		return nil, E("subscription.semantic_incomplete", "Unsupported VMess field")
	}
	if enc := rtString(m["encryption"]); enc != "" && enc != "none" {
		return nil, E("subscription.semantic_incomplete", "VMess encryption field is not representable")
	}
	port, err := rtParseInt(m["port"])
	if err != nil {
		return nil, E("subscription.node_invalid", "Invalid VMess port")
	}
	n := M{"type": "vmess", "tag": firstString(rtString(m["ps"]), "vmess"), "server": rtString(m["add"]), "server_port": port, "uuid": rtString(m["id"]), "security": firstString(rtString(m["scy"]), "auto")}
	if aid, exists := m["aid"]; exists {
		a, e := rtParseInt(aid)
		if e != nil || a < 0 {
			return nil, E("subscription.node_invalid", "Invalid VMess alter id")
		}
		n["alter_id"] = a
	}
	q := url.Values{}
	for src, dst := range map[string]string{"net": "type", "host": "host", "path": "path", "sni": "sni", "alpn": "alpn", "fp": "fp"} {
		if s := rtString(m[src]); s != "" {
			q.Set(dst, s)
		}
	}
	if rtString(m["type"]) != "" && rtString(m["type"]) != "none" {
		q.Set("headerType", rtString(m["type"]))
	}
	if rtString(m["net"]) == "grpc" {
		q.Set("serviceName", q.Get("path"))
		q.Del("path")
	}
	if s := rtString(m["tls"]); s != "" {
		if s != "tls" && s != "none" {
			return nil, E("subscription.semantic_incomplete", "Invalid VMess TLS mode")
		}
		q.Set("security", s)
	}
	if insecure, exists := m["allowInsecure"]; exists {
		switch x := insecure.(type) {
		case bool:
			q.Set("insecure", strconv.FormatBool(x))
		case string:
			q.Set("insecure", x)
		case json.Number:
			q.Set("insecure", x.String())
		default:
			return nil, E("subscription.node_invalid", "Invalid TLS verification flag")
		}
	}
	if err := applyShareTLS(n, q, false); err != nil {
		return nil, err
	}
	if err := applyShareTransport(n, q); err != nil {
		return nil, err
	}
	if err := ValidateProxyNode(n); err != nil {
		return nil, err
	}
	return n, nil
}

func parseShadowsocksLink(text string) (M, error) {
	without := text[len("ss://"):]
	fragment := ""
	if i := strings.IndexByte(without, '#'); i >= 0 {
		fragment, _ = url.PathUnescape(without[i+1:])
		without = without[:i]
	}
	query := ""
	if i := strings.IndexByte(without, '?'); i >= 0 {
		query = without[i+1:]
		without = without[:i]
	}
	without = strings.TrimSuffix(without, "/")
	if !strings.Contains(without, "@") {
		b, e := rtBase64(without)
		if e != nil {
			return nil, E("subscription.node_invalid", "Invalid Shadowsocks encoding")
		}
		without = string(b)
	}
	i := strings.LastIndexByte(without, '@')
	if i <= 0 {
		return nil, E("subscription.node_invalid", "Missing Shadowsocks credentials")
	}
	credentials := without[:i]
	server := without[i+1:]
	if !strings.Contains(credentials, ":") {
		b, e := rtBase64(credentials)
		if e != nil {
			return nil, E("subscription.node_invalid", "Invalid Shadowsocks credentials")
		}
		credentials = string(b)
	} else {
		var e error
		credentials, e = url.PathUnescape(credentials)
		if e != nil {
			return nil, E("subscription.node_invalid", "Invalid Shadowsocks credentials")
		}
	}
	method, password, ok := strings.Cut(credentials, ":")
	if !ok {
		return nil, E("subscription.node_invalid", "Invalid Shadowsocks credentials")
	}
	host, port, e := splitServerPort(server)
	if e != nil {
		return nil, e
	}
	n := M{"type": "shadowsocks", "tag": firstString(fragment, "shadowsocks"), "server": host, "server_port": port, "method": method, "password": password}
	q, e := url.ParseQuery(query)
	if e != nil {
		return nil, E("subscription.node_invalid", "Invalid Shadowsocks query")
	}
	for k, vs := range q {
		if k != "plugin" || len(vs) != 1 {
			return nil, E("subscription.semantic_incomplete", "Unsupported Shadowsocks query")
		}
	}
	if plugin := q.Get("plugin"); plugin != "" {
		name, opts, _ := strings.Cut(plugin, ";")
		n["plugin"] = name
		n["plugin_opts"] = opts
	}
	if e = ValidateProxyNode(n); e != nil {
		return nil, e
	}
	return n, nil
}
