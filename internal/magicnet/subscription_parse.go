package magicnet

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type ParsedSubscription struct {
	Nodes       []M
	Groups      []M
	Format      string
	ParsedCount int
}

func ValidateVLESSEncryption(v any) error {
	s, ok := v.(string)
	if !ok {
		return E("subscription.node_invalid", "VLESS encryption must be a string")
	}
	if s == "" || s == "none" {
		return nil
	}
	t := strings.Split(strings.TrimSpace(s), ".")
	if len(t) < 4 || t[0] != "mlkem768x25519plus" || !(t[1] == "native" || t[1] == "xorpub" || t[1] == "random") || !(t[2] == "0rtt" || t[2] == "1rtt") {
		return E("subscription.node_invalid", "Invalid VLESS encryption structure")
	}
	hasKey := false
	for _, part := range t[3:] {
		part = strings.TrimSpace(part)
		if part == "" {
			return E("subscription.node_invalid", "Invalid VLESS encryption segment")
		}
		if !hasKey && len(part) < 20 {
			for _, c := range part {
				if c > 127 || c < 33 {
					return E("subscription.node_invalid", "Invalid VLESS encryption padding")
				}
			}
			continue // Exact padding initialization is checked by the pinned core.
		}
		b, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || strings.Contains(part, "=") || (len(b) != 32 && len(b) != 1184) {
			return E("subscription.node_invalid", "Invalid VLESS encryption public key")
		}
		if base64.RawURLEncoding.EncodeToString(b) != part {
			return E("subscription.node_invalid", "Noncanonical VLESS encryption public key")
		}
		hasKey = true
	}
	if !hasKey {
		return E("subscription.node_invalid", "VLESS encryption requires a public key")
	}
	return nil
}

func ValidateSubscriptionDocument(data []byte) ([]byte, error) {
	if len(data) == 0 || int64(len(data)) > SubscriptionDocumentLimit || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, E("subscription.input_invalid", "Subscription document must be nonempty UTF-8 and at most 8 MiB")
	}
	if data[len(data)-1] != '\n' && int64(len(data)) < SubscriptionDocumentLimit {
		data = append(append([]byte{}, data...), '\n')
	}
	return data, nil
}

func ParseSubscription(data []byte) (*ParsedSubscription, error) { return parseSubscription(data, 0) }

func parseSubscription(data []byte, wrapped int) (*ParsedSubscription, error) {
	if _, err := ValidateSubscriptionDocument(data); err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	result := &ParsedSubscription{Nodes: []M{}, Groups: []M{}}
	if data[0] == '{' || data[0] == '[' {
		v, err := rtDecodeJSON(data)
		if err != nil {
			return nil, E("subscription.format_unsupported", "Invalid JSON subscription")
		}
		result.Format = "sing_box_json"
		if m := rtMap(v); m != nil {
			if p, exists := m["proxies"]; exists {
				result.Format = "clash_yaml"
				return parseClashList(p, m["proxy-groups"], result)
			}
			v = m["outbounds"]
		}
		list, ok := v.([]any)
		if !ok {
			return nil, E("subscription.format_unsupported", "JSON subscription needs an outbound array")
		}
		for _, item := range list {
			m := rtMap(item)
			if m == nil {
				return nil, E("subscription.node_invalid", "Invalid outbound object")
			}
			if err := addParsedOutbound(result, m); err != nil {
				return nil, err
			}
		}
	} else if looksLikeLinks(string(data)) {
		result.Format = "share_links"
		lines := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
		for _, line := range strings.Split(lines, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			n, err := ParseShareLink(line)
			if err != nil {
				return nil, err
			}
			if err = addParsedOutbound(result, n); err != nil {
				return nil, err
			}
		}
	} else {
		if wrapped == 0 {
			compact := strings.Map(func(r rune) rune {
				if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
					return -1
				}
				return r
			}, string(data))
			if b, e := rtBase64(compact); e == nil && utf8.Valid(b) && len(bytes.TrimSpace(b)) > 0 {
				p, e := parseSubscription(b, 1)
				if e == nil {
					p.Format = "base64_" + p.Format
					return p, nil
				}
			}
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			return nil, E("subscription.format_unsupported", "Invalid YAML subscription")
		}
		var extra yaml.Node
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, E("subscription.format_unsupported", "Multiple YAML documents are not supported")
		}
		var decoded any
		if err := document.Decode(&decoded); err != nil {
			return nil, E("subscription.semantic_incomplete", "Invalid or excessively aliased YAML")
		}
		value, err := yamlJSONValue(decoded, 0)
		if err != nil {
			return nil, E("subscription.semantic_incomplete", "YAML cannot be represented faithfully")
		}
		m := rtMap(value)
		if m == nil {
			return nil, E("subscription.format_unsupported", "Unsupported subscription format")
		}
		if _, ok := m["outbounds"]; ok {
			p, e := parseSubscription(rtJSON(m), 1)
			if e != nil {
				return nil, e
			}
			p.Format = "sing_box_yaml"
			return p, nil
		}
		result.Format = "clash_yaml"
		return parseClashList(m["proxies"], m["proxy-groups"], result)
	}
	if result.ParsedCount == 0 {
		return nil, E("subscription.empty_result", "The source contains no proxy nodes")
	}
	return result, nil
}

func yamlJSONValue(v any, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("depth limit")
	}
	switch x := v.(type) {
	case map[string]any:
		m := M{}
		for k, v := range x {
			y, e := yamlJSONValue(v, depth+1)
			if e != nil {
				return nil, e
			}
			m[k] = y
		}
		return m, nil
	case map[any]any:
		m := M{}
		for k, v := range x {
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("nonstring key")
			}
			y, e := yamlJSONValue(v, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = y
		}
		return m, nil
	case []any:
		if len(x) > 100000 {
			return nil, fmt.Errorf("array limit")
		}
		a := make([]any, len(x))
		for i, v := range x {
			y, e := yamlJSONValue(v, depth+1)
			if e != nil {
				return nil, e
			}
			a[i] = y
		}
		return a, nil
	case string, bool, nil, int, int64, float64:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported scalar")
	}
}

func looksLikeLinks(s string) bool {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	for _, p := range []string{"ss://", "socks://", "socks5://", "vmess://", "vless://", "trojan://", "hysteria2://", "hy2://", "anytls://", "tuic://", "http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(line), p) {
			return true
		}
	}
	return false
}

func addParsedOutbound(p *ParsedSubscription, n M) error {
	t := rtString(n["type"])
	if t == "direct" || t == "block" || t == "dns" {
		return nil
	}
	if t == "selector" || t == "urltest" {
		if _, ok := rtStringList(n["outbounds"]); !ok {
			return E("subscription.node_invalid", "Invalid subscription group members")
		}
		p.Groups = append(p.Groups, rtClone(n).(map[string]any))
		return nil
	}
	if err := ValidateProxyNode(n); err != nil {
		return err
	}
	p.Nodes = append(p.Nodes, rtClone(n).(map[string]any))
	p.ParsedCount++
	return nil
}

func ValidateProxyNode(n M) error {
	typeName := rtString(n["type"])
	switch typeName {
	case "socks", "http", "shadowsocks", "trojan", "vless", "vmess", "hysteria2", "tuic", "anytls":
	default:
		return E("subscription.format_unsupported", "Unsupported proxy protocol")
	}
	port, ok := rtInt(n["server_port"])
	if !ok || port < 1 || port > 65535 || !validServer(rtString(n["server"])) {
		return E("subscription.node_invalid", "Invalid proxy server or port")
	}
	for _, k := range []string{"uuid", "password", "username", "method", "flow", "detour", "tag", "server"} {
		if v, exists := n[k]; exists {
			if _, ok := v.(string); !ok {
				return E("subscription.node_invalid", "Invalid proxy field type")
			}
		}
	}
	if typeName == "socks" || typeName == "http" {
		if (rtString(n["username"]) != "") != (rtString(n["password"]) != "") {
			return E("subscription.node_invalid", "Proxy authentication requires both username and password")
		}
	}
	if typeName == "vless" || typeName == "vmess" || typeName == "tuic" {
		if !rtUUID(rtString(n["uuid"])) {
			return E("subscription.node_invalid", "Invalid proxy UUID")
		}
	}
	if typeName == "trojan" || typeName == "hysteria2" || typeName == "anytls" || typeName == "tuic" || typeName == "shadowsocks" {
		if rtString(n["password"]) == "" {
			return E("subscription.node_invalid", "Proxy password is required")
		}
	}
	if typeName == "shadowsocks" && rtString(n["method"]) == "" {
		return E("subscription.node_invalid", "Shadowsocks method is required")
	}
	if v, exists := n["encryption"]; exists {
		if typeName != "vless" {
			return E("subscription.node_invalid", "Unexpected encryption field")
		}
		if err := ValidateVLESSEncryption(v); err != nil {
			return err
		}
	}
	for _, key := range []string{"tls", "transport", "multiplex"} {
		if v, exists := n[key]; exists && rtMap(v) == nil {
			return E("subscription.node_invalid", "Invalid structured proxy option")
		}
	}
	return nil
}

func rtUUID(s string) bool {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return false
	}
	for i := range s {
		if !asciiHex(s[i]) {
			return false
		}
	}
	return true
}
