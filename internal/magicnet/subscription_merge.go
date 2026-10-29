package magicnet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type SubscriptionNode struct {
	Identity    string   `json:"identity"`
	Tag         string   `json:"tag"`
	DisplayName string   `json:"display_name"`
	Sources     []string `json:"sources"`
	Config      M        `json:"config"`
	Group       bool     `json:"group"`
}

type SubscriptionSourceInput struct {
	ID     string
	Parsed *ParsedSubscription
}
type SourceMergeCounts struct {
	Parsed               int
	Imported             int
	Filtered             int
	Duplicate            int
	NotificationFiltered int
	UserFiltered         int
}

var SystemSelectorDefaults = []struct{ Tag, Default string }{
	{"proxy", "block"}, {"select", "proxy"}, {"lan", "direct"}, {"hotspot", "direct"}, {"ad-block", "block"}, {"ad-allow", "final"}, {"cn-direct", "direct"}, {"apple-cn", "direct"}, {"microsoft-cn", "direct"}, {"icloud", "direct"}, {"bing", "proxy"}, {"network-test", "proxy"}, {"dns-guard", "proxy"}, {"ai-chatgpt", "block"}, {"ai-gemini", "block"}, {"ai-grok", "block"}, {"ai-claude", "block"}, {"ai-proxy", "block"}, {"proxy-rule", "proxy"}, {"dev-proxy", "proxy"}, {"social-proxy", "proxy"}, {"download-direct", "direct"}, {"media-proxy", "proxy"}, {"game-proxy", "proxy"}, {"google-proxy", "proxy"}, {"youtube-proxy", "proxy"}, {"github-proxy", "proxy"}, {"discord-proxy", "proxy"}, {"netflix-proxy", "proxy"}, {"spotify-proxy", "proxy"}, {"twitter-proxy", "proxy"}, {"whatsapp-proxy", "proxy"}, {"telegram-proxy", "proxy"}, {"final", "proxy"},
}

func reservedSubscriptionTag(tag string) bool {
	if tag == "direct" || tag == "block" || tag == "proxy-auto" || tag == "tailscale" || tag == "warp" || strings.HasPrefix(tag, "magicnet-") {
		return true
	}
	for _, s := range SystemSelectorDefaults {
		if tag == s.Tag {
			return true
		}
	}
	return false
}

func semanticDigest(n M) string {
	b, _ := json.Marshal(n)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func MergeSubscriptionNodes(inputs []SubscriptionSourceInput, filters []string, previous []SubscriptionNode) ([]SubscriptionNode, []SourceMergeCounts, error) {
	type candidate struct {
		config                 M
		identity, name, source string
		group                  bool
		refs                   map[string]string
	}
	var all []candidate
	counts := make([]SourceMergeCounts, len(inputs))
	for sourceIndex, input := range inputs {
		p := input.Parsed
		if p == nil {
			return nil, nil, E("subscription.merge_failed", "Missing parsed source")
		}
		counts[sourceIndex].Parsed = p.ParsedCount
		items := append(append([]M{}, p.Nodes...), p.Groups...)
		byName := map[string][]int{}
		for i, n := range items {
			byName[rtString(n["tag"])] = append(byName[rtString(n["tag"])], i)
		}
		fingerprints := make([]string, len(items))
		visiting := map[int]bool{}
		var identify func(int) (string, error)
		var resolve func(string) (string, error)
		resolve = func(name string) (string, error) {
			indices := byName[name]
			if len(indices) == 0 {
				if name == "direct" || name == "block" {
					return "system:" + name, nil
				}
				return "", E("subscription.merge_failed", "A node reference is missing in its source")
			}
			var id string
			for _, index := range indices {
				next, e := identify(index)
				if e != nil {
					return "", e
				}
				if id != "" && id != next {
					return "", E("subscription.merge_failed", "A same-name node reference is ambiguous")
				}
				id = next
			}
			return id, nil
		}
		identify = func(i int) (string, error) {
			if fingerprints[i] != "" {
				return fingerprints[i], nil
			}
			if visiting[i] {
				return "", E("subscription.merge_failed", "Subscription references form a cycle")
			}
			visiting[i] = true
			defer delete(visiting, i)
			n := rtClone(items[i]).(map[string]any)
			delete(n, "tag")
			for _, key := range []string{"detour", "default"} {
				if v, ok := n[key]; ok {
					if name, ok := v.(string); ok && name != "" {
						id, e := resolve(name)
						if e != nil {
							return "", e
						}
						n[key] = id
					} else {
						return "", E("subscription.merge_failed", "Invalid node reference")
					}
				}
			}
			if v, ok := n["outbounds"]; ok {
				names, ok := rtStringList(v)
				if !ok {
					return "", E("subscription.merge_failed", "Invalid group reference")
				}
				ids := make([]string, len(names))
				for j, name := range names {
					id, e := resolve(name)
					if e != nil {
						return "", e
					}
					ids[j] = id
				}
				n["outbounds"] = ids
			}
			fingerprints[i] = semanticDigest(n)
			return fingerprints[i], nil
		}
		for i, n := range items {
			id, e := identify(i)
			if e != nil {
				return nil, nil, e
			}
			name := rtString(n["tag"])
			group := i >= len(p.Nodes)
			if !group {
				filtered, notification := subscriptionFiltered(name, filters)
				if filtered {
					counts[sourceIndex].Filtered++
					if notification {
						counts[sourceIndex].NotificationFiltered++
					} else {
						counts[sourceIndex].UserFiltered++
					}
					continue
				}
			}
			refs := map[string]string{}
			for _, key := range []string{"detour", "default"} {
				if s := rtString(n[key]); s != "" {
					refs[key], e = resolve(s)
					if e != nil {
						return nil, nil, e
					}
				}
			}
			if names, ok := rtStringList(n["outbounds"]); ok {
				for j, s := range names {
					refs[fmt.Sprint(j)], e = resolve(s)
					if e != nil {
						return nil, nil, e
					}
				}
			}
			all = append(all, candidate{rtClone(n).(map[string]any), id, name, input.ID, group, refs})
		}
	}
	previousTags := map[string]string{}
	for _, n := range previous {
		if validNodeTag(n.Tag) && !reservedSubscriptionTag(n.Tag) {
			previousTags[n.Identity] = n.Tag
		}
	}
	nameIdentities := map[string]map[string]bool{}
	for _, c := range all {
		name := safeDisplayTag(c.name)
		if nameIdentities[name] == nil {
			nameIdentities[name] = map[string]bool{}
		}
		nameIdentities[name][c.identity] = true
	}
	tags := map[string]string{}
	taken := map[string]string{}
	for _, c := range all {
		if tag := previousTags[c.identity]; tag != "" {
			if other, exists := taken[tag]; exists && other != c.identity {
				return nil, nil, E("subscription.merge_failed", "Stored node identity collision")
			}
			tags[c.identity] = tag
			taken[tag] = c.identity
		}
	}
	for _, c := range all {
		if tags[c.identity] != "" {
			continue
		}
		name := safeDisplayTag(c.name)
		tag := name
		if reservedSubscriptionTag(tag) || len(nameIdentities[name]) > 1 || taken[tag] != "" {
			suffix := "~" + c.identity[:16]
			tag = truncateUTF8(name, 256-len(suffix)) + suffix
		}
		if other, exists := taken[tag]; exists && other != c.identity {
			return nil, nil, E("subscription.merge_failed", "Stable node tag collision")
		}
		tags[c.identity] = tag
		taken[tag] = c.identity
	}
	kept := map[string]bool{}
	for _, c := range all {
		kept[c.identity] = true
	}
	resolveTag := func(id string) (string, error) {
		if strings.HasPrefix(id, "system:") {
			return strings.TrimPrefix(id, "system:"), nil
		}
		if !kept[id] {
			return "", E("subscription.merge_failed", "A required node was removed by filtering")
		}
		return tags[id], nil
	}
	var out []SubscriptionNode
	indices := map[string]int{}
	sourceIndices := map[string]int{}
	for i, s := range inputs {
		sourceIndices[s.ID] = i
	}
	for _, c := range all {
		ci := sourceIndices[c.source]
		if index, exists := indices[c.identity]; exists {
			found := false
			for _, id := range out[index].Sources {
				if id == c.source {
					found = true
				}
			}
			if !found {
				out[index].Sources = append(out[index].Sources, c.source)
			}
			if !c.group {
				counts[ci].Duplicate++
			}
			continue
		}
		n := c.config
		n["tag"] = tags[c.identity]
		for _, key := range []string{"detour", "default"} {
			if id := c.refs[key]; id != "" {
				tag, e := resolveTag(id)
				if e != nil {
					if key == "default" {
						delete(n, key)
						continue
					}
					return nil, nil, e
				}
				n[key] = tag
			}
		}
		if names, ok := rtStringList(n["outbounds"]); ok {
			members := []string{}
			for i := range names {
				id := c.refs[fmt.Sprint(i)]
				if !strings.HasPrefix(id, "system:") && !kept[id] {
					continue
				}
				tag, e := resolveTag(id)
				if e != nil {
					return nil, nil, e
				}
				members = append(members, tag)
			}
			if len(members) == 0 {
				return nil, nil, E("subscription.empty_result", "Filtering left an empty subscription group")
			}
			n["outbounds"] = rtStrings(members)
			if d := rtString(n["default"]); d != "" && !stringIn(d, members...) {
				n["default"] = members[0]
			}
		}
		indices[c.identity] = len(out)
		out = append(out, SubscriptionNode{c.identity, tags[c.identity], c.name, []string{c.source}, n, c.group})
		if !c.group {
			counts[ci].Imported++
		}
	}
	proxyCount := 0
	for _, n := range out {
		if !n.Group {
			proxyCount++
		}
	}
	if proxyCount == 0 {
		return nil, counts, E("subscription.empty_result", "All proxy nodes were filtered or unusable")
	}
	return out, counts, nil
}

func safeDisplayTag(name string) string {
	name = strings.TrimSpace(strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, name))
	if name == "" {
		name = "node"
	}
	return truncateUTF8(name, 256)
}
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
func subscriptionFiltered(name string, filters []string) (bool, bool) {
	name = strings.ToLower(name)
	for _, word := range []string{"剩余流量", "到期", "过期", "套餐", "官网", "订阅", "traffic", "expire", "expired", "subscription", "官方网站", "更新订阅"} {
		if strings.Contains(name, word) {
			return true, true
		}
	}
	for _, word := range filters {
		if strings.Contains(name, strings.ToLower(word)) {
			return true, false
		}
	}
	return false, false
}
