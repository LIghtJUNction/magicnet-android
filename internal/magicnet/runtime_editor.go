package magicnet

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (a *App) configEditor(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "Configuration editor action is required")
	}
	if args[0] == "repo" {
		return a.templateRepo(ctx, args[1:])
	}
	if len(args) < 2 || !stringIn(args[1], "sing-box", "all") {
		return nil, E("command.arguments", "Configuration editor requires a sing-box target")
	}
	action := args[0]
	switch action {
	case "get":
		if len(args) != 2 {
			return nil, E("command.arguments", "Unexpected configuration read arguments")
		}
		b, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return nil, E("config.unavailable", "Configuration cannot be read")
		}
		var m M
		if DecodeJSON(b, &m) != nil {
			return nil, E("config.invalid", "Invalid active configuration")
		}
		for _, v := range rtArray(m["endpoints"]) {
			if ep := rtMap(v); rtString(ep["type"]) == "tailscale" {
				delete(ep, "auth_key")
			}
		}
		return M{"text": string(rtJSON(m))}, nil
	case "path":
		if len(args) != 2 {
			return nil, E("command.arguments", "Unexpected configuration path arguments")
		}
		return M{"text": a.ConfigPath()}, nil
	case "validate":
		if len(args) > 3 {
			return nil, E("command.arguments", "Invalid validation arguments")
		}
		var b []byte
		var e error
		if len(args) == 3 {
			b, e = a.privatePayload(args[2], 4<<20)
		} else {
			b, e = ReadRegular(a.ConfigPath(), 4<<20)
		}
		if e != nil {
			return nil, e
		}
		if e = a.validateManagedConfig(b); e != nil {
			return nil, e
		}
		if e = a.CheckConfig(ctx, b); e != nil {
			return nil, e
		}
		return M{"valid": true, "core_checked": true, "network_verified": false}, nil
	case "save", "save-file":
		if len(args) != 3 {
			return nil, E("command.arguments", "Configuration content is required")
		}
		var b []byte
		var e error
		if action == "save-file" {
			b, e = a.privatePayload(args[2], 4<<20)
		} else {
			b, e = base64.StdEncoding.DecodeString(args[2])
		}
		if e != nil || len(b) > 4<<20 {
			return nil, E("config.invalid", "Configuration payload is invalid or too large")
		}
		return a.saveEditedConfig(ctx, b)
	case "sync-template":
		if len(args) != 2 {
			return nil, E("command.arguments", "Unexpected template sync arguments")
		}
		return a.syncTemplate(ctx)
	}
	return nil, E("command.unknown", "Unknown configuration editor action")
}

func (a *App) validateManagedConfig(data []byte) error {
	if len(data) > 4<<20 {
		return E("config.limit", "Configuration exceeds 4 MiB")
	}
	var config M
	if DecodeJSON(data, &config) != nil || config == nil {
		return E("config.invalid", "Invalid configuration object")
	}
	transparent, mixed := false, false
	for _, v := range rtArray(config["inbounds"]) {
		m := rtMap(v)
		tag := rtString(m["tag"])
		if tag == "tun-in" || tag == "ebpf-in" {
			if !stringIn(rtString(m["type"]), "tun", "ebpf") {
				return E("config.protected", "Managed transparent inbound must be TUN or eBPF")
			}
			transparent = true
		}
		if tag == "mixed-in" {
			mixed = true
			if rtString(m["listen"]) != "127.0.0.1" && rtString(m["listen"]) != "::1" {
				return E("config.protected", "Managed mixed proxy must remain on loopback")
			}
		}
	}
	if !transparent || !mixed {
		return E("config.protected", "Managed transparent and loopback mixed inbounds are required")
	}
	api := rtMap(rtMap(config["experimental"])["clash_api"])
	host, port, e := net.SplitHostPort(rtString(api["external_controller"]))
	if e != nil || !stringIn(host, "127.0.0.1", "::1", "localhost") {
		return E("config.protected", "Managed controller must remain on loopback")
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return E("config.protected", "Invalid managed API port")
	}
	for _, v := range rtArray(config["endpoints"]) {
		ep := rtMap(v)
		if rtString(ep["type"]) == "tailscale" && rtBool(ep["system_interface"]) {
			return E("tailscale.system_interface_forbidden", "Tailscale must use userspace networking")
		}
	}
	for _, v := range rtArray(config["outbounds"]) {
		n := rtMap(v)
		if rtString(n["type"]) == "vless" {
			if v, ok := n["encryption"]; ok {
				if e = ValidateVLESSEncryption(v); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func (a *App) saveEditedConfig(ctx context.Context, data []byte) (M, error) {
	if e := a.validateManagedConfig(data); e != nil {
		return nil, e
	}
	if e := a.CheckConfig(ctx, data); e != nil {
		return nil, e
	}
	var result M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		if e := a.EnsureDefaultConfig(ctx); e != nil {
			return e
		}
		var config M
		if e := DecodeJSON(data, &config); e != nil {
			return e
		}
		s, e := a.runtimeSettings()
		if e != nil {
			return e
		}
		keys := map[string]string{}
		if e = ReadJSON(a.Path(".config", "magicnet", "tailscale-auth.json"), 64<<10, &keys); e != nil && !errors.Is(e, os.ErrNotExist) {
			return E("tailscale.key_unavailable", "Private Tailscale credentials cannot be read")
		}
		var tailscale M
		for _, v := range rtArray(config["endpoints"]) {
			ep := rtMap(v)
			if rtString(ep["type"]) != "tailscale" {
				continue
			}
			if tailscale != nil {
				return E("tailscale.invalid", "Only one managed Tailscale endpoint is allowed")
			}
			tailscale = rtClone(ep).(map[string]any)
			tag := rtString(tailscale["tag"])
			if !validNodeTag(tag) {
				return E("tailscale.invalid", "Tailscale endpoint needs a valid tag")
			}
			if k, ok := tailscale["auth_key"]; ok {
				key, ok := k.(string)
				if !ok || len(key) > 8192 {
					return E("tailscale.invalid", "Invalid Tailscale auth key")
				}
				if key != "" {
					keys[tag] = key
				} else {
					delete(keys, tag)
				}
				delete(tailscale, "auth_key")
			}
			tailscale["system_interface"] = false
		}
		// The editor explicitly owns Tailscale edits. Restore the old owned
		// endpoint temporarily so ordinary ownership checks can unmaterialize
		// the rest of the configuration without mistaking this edit for a race.
		var cp RuntimeCheckpoint
		_ = ReadJSON(a.Path(".state", "private", "runtime-checkpoint.json"), 16<<20, &cp)
		without := []any{}
		for _, v := range rtArray(config["endpoints"]) {
			if rtString(rtMap(v)["type"]) != "tailscale" {
				without = append(without, v)
			}
		}
		for _, ep := range cp.RuntimeOwned.Endpoints {
			if rtString(ep["type"]) == "tailscale" {
				without = append(without, ep)
			}
		}
		config["endpoints"] = without
		base, e := a.runtimeBase(config)
		if e != nil {
			return e
		}
		changes := []RuntimeFileChange{}
		if tailscale != nil {
			dir := rtString(tailscale["state_directory"])
			if dir == "" {
				dir = ownedTailscaleRelative
				tailscale["state_directory"] = dir
			}
			owned := a.isCurrentOwnedTailscalePath(dir)
			if owned {
				tailscale["state_directory"] = ownedTailscaleRelative
				marker := a.Path(".state", "private", "tailscale", ".magicnet-owned")
				if b, me := ReadRegular(marker, 128); me == nil {
					if strings.TrimSpace(string(b)) != "MagicNet" {
						return E("tailscale.invalid", "Tailscale state ownership marker is invalid")
					}
				} else if !errors.Is(me, os.ErrNotExist) {
					return me
				} else {
					if _, se := os.Stat(a.Path(ownedTailscaleRelative)); se == nil {
						return E("tailscale.invalid", "Existing Tailscale directory has unknown ownership")
					}
					changes = append(changes, RuntimeFileChange{Path: ".state/private/tailscale/.magicnet-owned", Data: []byte("MagicNet\n"), BeforeActivate: true})
				}
			}
			s.Tailscale = RuntimeTunnel{Enabled: true, Revision: s.Tailscale.Revision + 1, Endpoint: tailscale, OwnedDirectory: owned}
		} else if s.Tailscale.Endpoint != nil {
			s.Tailscale.Enabled = false
			s.Tailscale.Revision++
		}
		for _, v := range rtArray(base["inbounds"]) {
			in := rtMap(v)
			if rtString(in["type"]) == "tun" && rtString(in["tag"]) == "tun-in" {
				if n, ok := rtInt(in["mtu"]); ok {
					s.Network.MTU = int(n)
				}
				if timeout := rtString(in["udp_timeout"]); timeout != "" {
					s.Network.UDPTimeout = timeout
				}
				if addresses, ok := rtStringList(in["address"]); ok {
					for _, cidr := range addresses {
						if strings.Contains(cidr, ":") {
							s.Network.TunIPv6 = cidr
						} else {
							s.Network.TunIPv4 = cidr
						}
					}
				}
			}
			if rtString(in["tag"]) == "dns-in" {
				if p, ok := rtInt(in["listen_port"]); ok {
					s.Network.DNSPort = int(p)
				}
			}
		}
		if e = validateRuntimeSettings(s); e != nil {
			return e
		}
		override, e := a.readOverride(true)
		if e != nil {
			return e
		}
		candidate, e := a.materializeFromBase(ctx, base, s, override.Patch)
		if e != nil {
			return e
		}
		changes = append(changes, RuntimeFileChange{Path: ".config/magicnet/tailscale-auth.json", Data: rtJSON(keys), BeforeActivate: true}, RuntimeFileChange{Path: ".config/magicnet/runtime-settings.json", Data: runtimeSettingsBytes(s)})
		generation := token()
		if e = a.performRuntimeChange(ctx, candidate, changes, generation); e != nil {
			return e
		}
		result = M{"saved": true, "applied": true, "generation_id": generation, "network_verified": false}
		return nil
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return result, e
}

type TemplateRepository struct {
	URL      string `json:"url"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
	Path     string `json:"path,omitempty"`
}

func (a *App) readTemplateRepo() (TemplateRepository, error) {
	var repo TemplateRepository
	e := ReadJSON(a.Path(".config", "magicnet", "template-repository.json"), 16<<10, &repo)
	if errors.Is(e, os.ErrNotExist) {
		return repo, nil
	}
	if e != nil {
		return repo, E("template.invalid", "Template repository settings cannot be read")
	}
	if e = validateTemplateRepo(repo); e != nil {
		return repo, e
	}
	return repo, nil
}
func validateTemplateRepo(repo TemplateRepository) error {
	u, e := url.Parse(repo.URL)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !stringIn(strings.ToLower(u.Hostname()), "github.com", "gitlab.com") || u.Port() != "" {
		return E("template.invalid", "Template repositories must use an explicit GitHub or GitLab HTTPS repository")
	}
	if len(repo.Revision) != 40 || len(repo.SHA256) != 64 {
		return E("template.invalid", "Template requires an immutable commit and SHA-256")
	}
	for _, s := range []string{repo.Revision, repo.SHA256} {
		for i := range s {
			if !asciiHex(s[i]) {
				return E("template.invalid", "Invalid template digest")
			}
		}
	}
	if repo.Path != "" && (filepath.IsAbs(repo.Path) || filepath.Clean(repo.Path) != repo.Path || strings.HasPrefix(repo.Path, "../")) {
		return E("template.invalid", "Invalid template path")
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/"), "/")
	if len(parts) < 2 {
		return E("template.invalid", "Repository owner and name are required")
	}
	return nil
}

func (a *App) templateRepo(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "Template repository action is required")
	}
	if len(args) == 1 && (args[0] == "get" || args[0] == "get-json") {
		r, e := a.readTemplateRepo()
		if e != nil {
			return nil, e
		}
		if args[0] == "get" {
			return M{"text": r.URL, "bundled": r.URL == ""}, nil
		}
		return M{"repository": r, "bundled": r.URL == ""}, nil
	}
	if len(args) == 1 && args[0] == "reset" {
		if e := removeRuntimeFile(a.Path(".config", "magicnet", "template-repository.json")); e != nil {
			return nil, e
		}
		return M{"saved": true, "bundled": true}, nil
	}
	if len(args) != 2 || !stringIn(args[0], "set", "set-file") {
		return nil, E("command.arguments", "Invalid template repository action")
	}
	var b []byte
	var e error
	if args[0] == "set-file" {
		b, e = a.privatePayload(args[1], 16<<10)
	} else {
		b, e = base64.StdEncoding.DecodeString(args[1])
	}
	if e != nil {
		return nil, E("template.invalid", "Invalid template repository payload")
	}
	var r TemplateRepository
	if DecodeJSON(b, &r) != nil {
		return nil, E("template.invalid", "Invalid template repository JSON")
	}
	if e = validateTemplateRepo(r); e != nil {
		return nil, e
	}
	if e = WriteJSON(a.Path(".config", "magicnet", "template-repository.json"), r); e != nil {
		return nil, e
	}
	return M{"saved": true, "synced": false}, nil
}

func (a *App) syncTemplate(ctx context.Context) (M, error) {
	repo, e := a.readTemplateRepo()
	if e != nil {
		return nil, e
	}
	var base M
	if repo.URL == "" {
		base, e = a.DefaultPolicy()
		if e != nil {
			return nil, e
		}
	} else {
		u, _ := url.Parse(repo.URL)
		path := repo.Path
		if path == "" {
			path = "config.json"
		}
		repository := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
		raw := ""
		if u.Hostname() == "github.com" {
			raw = "https://raw.githubusercontent.com/" + repository + "/" + repo.Revision + "/" + path
		} else {
			raw = "https://gitlab.com/" + repository + "/-/raw/" + repo.Revision + "/" + path
		}
		raw, e = NormalizeSubscriptionURL(raw)
		if e != nil {
			return nil, e
		}
		download, e := (&SubscriptionFetcher{}).Fetch(ctx, raw, "")
		if e != nil {
			return nil, e
		}
		if digest(download.Body) != strings.ToLower(repo.SHA256) {
			return nil, E("template.integrity_failed", "Template SHA-256 verification failed")
		}
		if DecodeJSON(download.Body, &base) != nil || base == nil {
			return nil, E("template.invalid", "Template is not a JSON object")
		}
	}
	var result M
	e = a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		defer a.ClearMaterialization()
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		if e := a.EnsureDefaultConfig(ctx); e != nil {
			return e
		}
		current, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return e
		}
		var config M
		if DecodeJSON(current, &config) != nil {
			return E("config.invalid", "Active configuration is invalid")
		}
		unowned, e := a.runtimeBase(config)
		if e != nil {
			return e
		}
		snapshot, e := a.subscriptionSnapshot()
		if e != nil {
			return e
		}
		owned := map[string]bool{}
		for _, n := range snapshot.Nodes {
			owned[n.Tag] = true
		}
		for _, section := range []string{"outbounds", "endpoints"} {
			existing := map[string]M{}
			for _, v := range rtArray(base[section]) {
				m := rtMap(v)
				existing[rtString(m["tag"])] = m
			}
			for _, v := range rtArray(unowned[section]) {
				m := rtMap(v)
				tag := rtString(m["tag"])
				if section == "outbounds" && reservedSubscriptionTag(tag) {
					continue
				}
				if owned[tag] {
					continue
				}
				if prior, ok := existing[tag]; ok {
					if !rtEqual(prior, m) {
						return E("template.conflict", "A template outbound conflicts with an existing user-owned endpoint")
					}
					continue
				}
				base[section] = append(rtArray(base[section]), rtClone(m))
				existing[tag] = m
			}
		}
		selections := map[string]string{}
		if e = ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &selections); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		count := len(snapshot.Nodes)
		if count == 0 {
			for _, v := range rtArray(base["outbounds"]) {
				if ValidateProxyNode(rtMap(v)) == nil {
					count++
					break
				}
			}
		}
		if count > 0 {
			if _, e = UpdatePolicySelectors(base, snapshot.Nodes, nil, selections); e != nil {
				return e
			}
		} else {
			applyAvailableSelectorChoices(base, selections)
		}
		if e = a.validateManagedConfig(rtJSON(base)); e != nil {
			return e
		}
		settings, e := a.runtimeSettings()
		if e != nil {
			return e
		}
		override, e := a.readOverride(true)
		if e != nil {
			return e
		}
		candidate, e := a.materializeFromBase(ctx, base, settings, override.Patch)
		if e != nil {
			return e
		}
		generation := token()
		if e = a.performRuntimeChange(ctx, candidate, nil, generation); e != nil {
			return e
		}
		result = M{"saved": true, "applied": true, "generation_id": generation, "network_verified": false, "template_verified": true}
		return nil
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return result, e
}
