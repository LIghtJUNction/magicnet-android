package magicnet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const SubscriptionDocumentLimit int64 = 8 << 20
const SubscriptionListLimit int64 = 64 << 10

// NormalizeSubscriptionURL preserves signed ASCII suffix bytes. In particular it
// does not round-trip the query through url.Values, which would reorder keys.
func NormalizeSubscriptionURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !utf8.ValidString(raw) || len(raw) > int(SubscriptionListLimit) {
		return "", E("subscription.input_invalid", "Invalid subscription URL")
	}
	for _, c := range raw {
		if unicode.IsControl(c) || unicode.IsSpace(c) || c == '\\' {
			return "", E("subscription.url_policy", "Subscription URL violates the HTTPS policy")
		}
	}
	i := strings.Index(raw, "://")
	if i < 0 || !strings.EqualFold(raw[:i], "https") {
		return "", E("subscription.url_policy", "Only public HTTPS subscription URLs are allowed")
	}
	rest := raw[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, suffix := rest[:end], rest[end:]
	if authority == "" || strings.ContainsAny(authority, "@%") {
		return "", E("subscription.url_policy", "Subscription URL authority is invalid")
	}
	u, err := url.Parse("https://" + authority)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" {
		return "", E("subscription.url_policy", "Subscription URL authority is invalid")
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return "", E("subscription.url_policy", "Invalid IP address")
		}
		host = "[" + ip.String() + "]"
	} else {
		host, err = canonicalDomain(host)
		if err != nil {
			return "", E("subscription.url_policy", "Invalid subscription hostname")
		}
	}
	port := u.Port()
	if strings.HasSuffix(authority, ":") {
		return "", E("subscription.url_policy", "Invalid subscription port")
	}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", E("subscription.url_policy", "Invalid subscription port")
		}
		if p != 443 {
			host += ":" + strconv.Itoa(p)
		}
	}
	if f := strings.IndexByte(suffix, '#'); f >= 0 {
		suffix = suffix[:f]
	}
	if suffix == "" || suffix[0] == '?' {
		suffix = "/" + suffix
	}
	var encoded strings.Builder
	for j := 0; j < len(suffix); j++ {
		b := suffix[j]
		if b == '%' {
			if j+2 >= len(suffix) || !asciiHex(suffix[j+1]) || !asciiHex(suffix[j+2]) {
				return "", E("subscription.url_policy", "Invalid URL percent encoding")
			}
		}
		if b >= 128 {
			fmt.Fprintf(&encoded, "%%%02X", b)
		} else {
			encoded.WriteByte(b)
		}
	}
	result := "https://" + strings.ToLower(host) + encoded.String()
	if _, err = url.Parse(result); err != nil {
		return "", E("subscription.url_policy", "Invalid subscription URL")
	}
	return result, nil
}

func asciiHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

func canonicalDomain(s string) (string, error) {
	if !utf8.ValidString(s) || strings.ContainsAny(s, "\x00/\\:@[]?#%") {
		return "", fmt.Errorf("invalid domain")
	}
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil || len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("invalid domain")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain")
			}
		}
	}
	return strings.ToLower(ascii), nil
}

// NormalizeSubscriptionList is the only source-identity implementation used by
// imports, caches, inspection, migration and refresh.
func NormalizeSubscriptionList(data []byte) ([]string, int, error) {
	if len(data) > int(SubscriptionListLimit) || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, 0, E("subscription.input_invalid", "Subscription list is invalid or exceeds 64 KiB")
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	seen := map[string]bool{}
	var urls []string
	requested := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		requested++
		u, err := NormalizeSubscriptionURL(line)
		if err != nil {
			return nil, requested, err
		}
		if !seen[u] {
			urls = append(urls, u)
			seen[u] = true
		}
	}
	if len(urls) == 0 {
		return nil, requested, E("subscription.input_invalid", "An empty list does not clear subscriptions; use sub clear")
	}
	if len(urls) > 5 {
		return nil, requested, E("subscription.source_limit", "At most five distinct subscription sources are allowed")
	}
	return urls, requested, nil
}

func SubscriptionSourceID(normalizedURL string) string {
	s := sha256.Sum256([]byte(normalizedURL))
	return hex.EncodeToString(s[:])
}

var forbiddenSubscriptionPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func PublicSubscriptionAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range forbiddenSubscriptionPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func validNodeTag(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validServer(s string) bool {
	if ip, e := netip.ParseAddr(s); e == nil {
		return ip.IsValid() && ip.Zone() == ""
	}
	_, err := canonicalDomain(s)
	return err == nil
}

func splitServerPort(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, E("subscription.node_invalid", "A node needs an explicit valid host and port")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || !validServer(h) {
		return "", 0, E("subscription.node_invalid", "Invalid node server or port")
	}
	return h, n, nil
}

func ValidateUserAgent(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return "", E("subscription.input_invalid", "User-Agent must contain 1–256 UTF-8 bytes")
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return "", E("subscription.input_invalid", "User-Agent contains control characters")
		}
	}
	return value, nil
}

func NormalizeSubscriptionFilters(data []byte) ([]string, error) {
	if len(data) > 8<<10 || !utf8.Valid(data) {
		return nil, E("subscription.input_invalid", "Invalid filter list")
	}
	var out []string
	seen := map[string]bool{}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	for _, value := range strings.Split(text, "\n") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > 64 {
			return nil, E("subscription.input_invalid", "Filter terms must not exceed 64 UTF-8 bytes")
		}
		for _, c := range value {
			if unicode.IsControl(c) {
				return nil, E("subscription.input_invalid", "Filter terms contain control characters")
			}
		}
		key := strings.ToLower(value)
		if !seen[key] {
			out = append(out, value)
			seen[key] = true
		}
	}
	if len(out) > 32 {
		return nil, E("subscription.input_invalid", "At most 32 distinct filter terms are allowed")
	}
	return out, nil
}
