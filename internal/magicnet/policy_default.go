package magicnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const PolicyRevision = "f3335f9420d07b8c50b26488df2a9492da6bbb44"

type RuleAsset struct {
	Tag    string `json:"tag"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
}
type RuleManifest struct {
	Schema   int         `json:"schema"`
	Revision string      `json:"revision"`
	Files    []RuleAsset `json:"files"`
}

var PolicyRuleTags = strings.Fields("lyc-geosite-ads lyc-geosite-cn lyc-geoip-cn lyc-geoip-telegram metacubex-geosite-cn metacubex-geoip-cn metacubex-geosite-geolocation-not-cn hagezi-light karing-acl4ssr-wechat service-wechat-dns karing-acl4ssr-china-domain karing-acl4ssr-china-ip sukka-chatgpt-voice meta-tencent meta-category-doh meta-category-ip-geo-detect meta-connectivity-check meta-speedtest meta-openai meta-google-gemini meta-xai meta-anthropic meta-bing@cn meta-bing meta-category-game-platforms-download meta-win-update meta-apple-update meta-icloud meta-apple meta-microsoft meta-category-scholar-!cn meta-category-ai-!cn meta-category-dev meta-category-media meta-category-games-!cn meta-category-social-media-!cn meta-telegram meta-twitter meta-whatsapp meta-google meta-google-play meta-category-entertainment meta-category-communication meta-github meta-huggingface meta-gitlab meta-docker meta-npmjs meta-notion meta-discord meta-slack meta-reddit meta-spotify meta-netflix meta-youtube")

func (a *App) PolicyAssets() ([]any, error) {
	dir := a.Path(".config", "sing-box", "rules")
	var manifest RuleManifest
	if err := ReadJSON(filepath.Join(dir, "manifest.json"), 256<<10, &manifest); err != nil {
		return nil, E("policy.assets_missing", "The fixed local policy asset manifest is unavailable")
	}
	if manifest.Schema != 1 || manifest.Revision != PolicyRevision {
		return nil, E("policy.assets_invalid", "Policy asset revision does not match the build")
	}
	byTag := map[string]RuleAsset{}
	for _, f := range manifest.Files {
		if _, exists := byTag[f.Tag]; exists {
			return nil, E("policy.assets_invalid", "Duplicate policy asset tag")
		}
		byTag[f.Tag] = f
	}
	result := []any{}
	for _, tag := range PolicyRuleTags {
		f, ok := byTag[tag]
		if !ok || !(f.Format == "source" || f.Format == "binary") || filepath.IsAbs(f.Path) || filepath.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "../") || f.Path == ".." {
			return nil, E("policy.assets_missing", "A required policy asset is missing or invalid")
		}
		path := filepath.Join(dir, f.Path)
		b, err := ReadRegular(path, 32<<20)
		if err != nil || len(b) == 0 {
			return nil, E("policy.assets_missing", "A required policy asset cannot be read")
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, E("policy.assets_invalid", "Policy asset digest verification failed")
		}
		// Both core check and run have the module root as their working
		// directory. Relative owned paths survive manager stage promotion.
		result = append(result, M{"type": "local", "tag": tag, "format": f.Format, "path": filepath.Join(".config", "sing-box", "rules", f.Path)})
	}
	return result, nil
}

// DefaultPolicy is generated from the public recipe inventory. It does not
// import a historical MagicNet/MagicSingBox configuration.
func (a *App) DefaultPolicy() (M, error) {
	assets, err := a.PolicyAssets()
	if err != nil {
		return nil, err
	}
	outbounds := []any{M{"type": "direct", "tag": "direct"}, M{"type": "block", "tag": "block"}}
	for _, s := range SystemSelectorDefaults {
		members := []string{s.Default}
		for _, v := range []string{"proxy", "direct", "block"} {
			if v != s.Tag && !stringIn(v, members...) {
				members = append(members, v)
			}
		}
		if s.Tag == "proxy" || strings.HasPrefix(s.Tag, "ai-") {
			members = []string{"block"}
		}
		outbounds = append(outbounds, M{"type": "selector", "tag": s.Tag, "outbounds": rtStrings(members), "default": s.Default, "interrupt_exist_connections": false})
	}
	servers := []any{
		M{"type": "local", "tag": "bootstrap-local-dns"},
		M{"type": "https", "tag": "doh-google", "server": "8.8.8.8", "server_port": 443, "path": "/dns-query", "tls": M{"enabled": true, "server_name": "dns.google"}, "detour": "proxy"},
		M{"type": "https", "tag": "doh-cloudflare", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "tls": M{"enabled": true, "server_name": "cloudflare-dns.com"}, "detour": "direct"},
	}
	for _, s := range SystemSelectorDefaults {
		base := servers[1]
		if s.Default == "direct" {
			base = servers[2]
		}
		server := rtClone(base).(map[string]any)
		server["tag"] = "magicnet-dns-" + s.Tag
		server["detour"] = s.Tag
		servers = append(servers, server)
	}
	routes := []any{M{"clash_mode": "direct", "outbound": "direct"}, M{"clash_mode": "global", "outbound": "proxy"}, M{"action": "sniff"}, M{"protocol": "dns", "action": "hijack-dns"}, M{"port": 53, "action": "hijack-dns"}, M{"ip_is_private": true, "outbound": "lan"}, M{"ip_cidr": rtStrings([]string{"100.64.0.0/10", "224.0.0.0/4", "ff00::/8"}), "outbound": "lan"}}
	dnsRules := []any{M{"clash_mode": "direct", "server": "doh-cloudflare"}, M{"clash_mode": "global", "server": "doh-google"}, M{"domain_suffix": rtStrings([]string{"lan", "local", "localhost"}), "server": "doh-cloudflare"}}
	add := func(tags []string, target string, dns bool) {
		routes = append(routes, M{"rule_set": rtStrings(tags), "outbound": target})
		if dns {
			dnsRules = append(dnsRules, M{"rule_set": rtStrings(tags), "server": "magicnet-dns-" + target})
		}
	}
	// Native application hints are exact package identities, never substrings.
	routes = append(routes, M{"package_name": rtStrings([]string{"com.tencent.mm", "com.tencent.mobileqq"}), "outbound": "cn-direct"})
	dnsRules = append(dnsRules, M{"package_name": rtStrings([]string{"com.tencent.mm", "com.tencent.mobileqq"}), "server": "magicnet-dns-cn-direct"})
	add([]string{"hagezi-light", "lyc-geosite-ads"}, "ad-block", true)
	add([]string{"meta-openai"}, "ai-chatgpt", true)
	add([]string{"sukka-chatgpt-voice"}, "ai-chatgpt", false)
	add([]string{"meta-google-gemini"}, "ai-gemini", true)
	add([]string{"meta-xai"}, "ai-grok", true)
	add([]string{"meta-anthropic"}, "ai-claude", true)
	add([]string{"meta-youtube"}, "youtube-proxy", true)
	add([]string{"meta-icloud"}, "icloud", true)
	add([]string{"meta-bing@cn", "meta-bing"}, "bing", true)
	add([]string{"meta-github", "meta-gitlab", "meta-huggingface", "meta-docker", "meta-npmjs", "meta-category-dev"}, "dev-proxy", true)
	// Specific named selectors remain independently selectable.
	// GitHub's dedicated rule precedes its general development classification.
	insertRuleBeforeTag(&routes, M{"rule_set": rtStrings([]string{"meta-github"}), "outbound": "github-proxy"}, "meta-category-dev")
	insertRuleBeforeTag(&dnsRules, M{"rule_set": rtStrings([]string{"meta-github"}), "server": "magicnet-dns-github-proxy"}, "meta-category-dev")
	add([]string{"meta-category-game-platforms-download", "meta-win-update", "meta-apple-update"}, "download-direct", true)
	add([]string{"meta-apple"}, "apple-cn", true)
	add([]string{"meta-microsoft"}, "microsoft-cn", true)
	add([]string{"meta-telegram"}, "telegram-proxy", true)
	add([]string{"lyc-geoip-telegram"}, "telegram-proxy", false)
	add([]string{"meta-discord"}, "discord-proxy", true)
	add([]string{"meta-netflix"}, "netflix-proxy", true)
	add([]string{"meta-spotify"}, "spotify-proxy", true)
	add([]string{"meta-twitter"}, "twitter-proxy", true)
	add([]string{"meta-whatsapp"}, "whatsapp-proxy", true)
	add([]string{"meta-google", "meta-google-play"}, "google-proxy", true)
	add([]string{"meta-category-ai-!cn"}, "ai-proxy", true)
	add([]string{"meta-category-scholar-!cn"}, "proxy-rule", true)
	add([]string{"meta-category-games-!cn"}, "game-proxy", true)
	add([]string{"meta-category-media", "meta-category-entertainment"}, "media-proxy", true)
	add([]string{"meta-notion", "meta-slack", "meta-reddit", "meta-category-social-media-!cn", "meta-category-communication"}, "social-proxy", true)
	add([]string{"meta-category-doh"}, "dns-guard", true)
	add([]string{"meta-category-ip-geo-detect", "meta-speedtest"}, "network-test", true)
	add([]string{"meta-connectivity-check", "meta-tencent", "karing-acl4ssr-wechat", "service-wechat-dns"}, "cn-direct", true)
	add([]string{"metacubex-geosite-geolocation-not-cn"}, "proxy-rule", true)
	add([]string{"lyc-geosite-cn", "metacubex-geosite-cn", "karing-acl4ssr-china-domain"}, "cn-direct", true)
	add([]string{"lyc-geoip-cn", "metacubex-geoip-cn", "karing-acl4ssr-china-ip"}, "cn-direct", false)
	return M{
		"log":          M{"level": "warn", "timestamp": true},
		"dns":          M{"servers": servers, "rules": dnsRules, "final": "doh-google", "strategy": "prefer_ipv4"},
		"inbounds":     []any{M{"type": "tun", "tag": "tun-in", "interface_name": "magicnet0", "address": rtStrings([]string{"172.19.0.1/30", "fd12::2/126"}), "mtu": 1400, "auto_route": true, "strict_route": true, "stack": "mixed", "udp_timeout": "5m"}, M{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7892}, M{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 1053}},
		"outbounds":    outbounds,
		"route":        M{"rules": routes, "rule_set": assets, "final": "final", "auto_detect_interface": true, "default_domain_resolver": "doh-cloudflare"},
		"experimental": M{"clash_api": M{"external_controller": "127.0.0.1:9090", "default_mode": "rule"}, "cache_file": M{"enabled": true, "path": ".state/private/core-cache.db", "store_fakeip": true}},
	}, nil
}

func insertRuleBeforeTag(rules *[]any, rule M, tag string) {
	for i, v := range *rules {
		rs, _ := rtStringList(rtMap(v)["rule_set"])
		if stringIn(tag, rs...) {
			r := append([]any{}, (*rules)[:i]...)
			r = append(r, rule)
			r = append(r, (*rules)[i:]...)
			*rules = r
			return
		}
	}
	*rules = append(*rules, rule)
}

func (a *App) EnsureDefaultConfig(ctx context.Context) error {
	if e := a.ensureOwnedRuntimePaths(ctx); e != nil {
		return e
	}
	if e := a.recoverRuntimeInitialization(ctx); e != nil {
		return e
	}
	if b, e := ReadRegular(a.ConfigPath(), 4<<20); e == nil {
		if len(b) == 0 {
			return E("config.invalid", "The active configuration is empty")
		}
		return a.CheckConfig(ctx, b)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	candidate, changes, e := a.initialConfigCandidate(ctx)
	if e != nil {
		a.ClearMaterialization()
		return e
	}
	return a.beginRuntimeInitialization(ctx, candidate, changes)
}

func UpdatePolicySelectors(config M, nodes []SubscriptionNode, previous []SubscriptionNode, selections map[string]string) ([]string, error) {
	old := map[string]SubscriptionNode{}
	for _, n := range previous {
		old[n.Tag] = n
	}
	out := []any{}
	existing := map[string]bool{}
	for _, v := range rtArray(config["outbounds"]) {
		m := rtMap(v)
		if m == nil {
			return nil, E("subscription.merge_failed", "Invalid current outbound array")
		}
		tag := rtString(m["tag"])
		if before, ok := old[tag]; ok {
			if !rtEqual(m, before.Config) {
				return nil, E("subscription.merge_failed", "An owned subscription node was externally changed")
			}
			continue
		}
		out = append(out, v)
		existing[tag] = true
	}
	nodeTags := []string{}
	newTags := map[string]bool{}
	for _, n := range nodes {
		if existing[n.Tag] {
			return nil, E("subscription.merge_failed", "Subscription tag conflicts with another configuration owner")
		}
		out = append(out, n.Config)
		newTags[n.Tag] = true
		if !n.Group {
			nodeTags = append(nodeTags, n.Tag)
		}
	}
	// Preserve concrete user-owned endpoints as selectable candidates when a
	// subscription generation changes. They are not assigned source ownership.
	for _, v := range out[:len(out)-len(nodes)] {
		m := rtMap(v)
		if ValidateProxyNode(m) == nil && !stringIn(rtString(m["tag"]), nodeTags...) {
			nodeTags = append(nodeTags, rtString(m["tag"]))
		}
	}
	if len(nodeTags) == 0 {
		return nil, E("subscription.empty_result", "No qualified proxy nodes are available")
	}
	warnings := []string{}
	for _, v := range out {
		m := rtMap(v)
		if rtString(m["type"]) != "selector" && rtString(m["type"]) != "urltest" {
			continue
		}
		tag := rtString(m["tag"])
		system := false
		fallback := ""
		for _, s := range SystemSelectorDefaults {
			if s.Tag == tag {
				system = true
				fallback = s.Default
				break
			}
		}
		if system {
			members := []string{}
			if tag == "proxy" || strings.HasPrefix(tag, "ai-") {
				members = append(members, nodeTags...)
				members = append(members, "block")
				fallback = nodeTags[0]
			} else {
				members = append(members, fallback)
				for _, t := range []string{"proxy", "direct", "block"} {
					if t != tag && !stringIn(t, members...) {
						members = append(members, t)
					}
				}
				members = append(members, nodeTags...)
			}
			m["outbounds"] = rtStrings(members)
			choice := selections[tag]
			if !stringIn(choice, members...) {
				if choice != "" {
					warnings = append(warnings, tag)
				}
				choice = fallback
			}
			m["default"] = choice
		} else if !newTags[tag] {
			members, _ := rtStringList(m["outbounds"])
			kept := []string{}
			for _, member := range members {
				if _, removed := old[member]; !removed || newTags[member] {
					kept = append(kept, member)
				}
			}
			if len(kept) == 0 {
				return nil, E("subscription.merge_failed", "Subscription removal would empty a user group")
			}
			m["outbounds"] = rtStrings(kept)
			if def := rtString(m["default"]); def != "" && !stringIn(def, kept...) {
				m["default"] = kept[0]
				warnings = append(warnings, tag)
			}
		}
	}
	config["outbounds"] = out
	return warnings, nil
}
