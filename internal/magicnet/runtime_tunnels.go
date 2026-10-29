package magicnet

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func ParseWireGuardConfiguration(data []byte) (M, error) {
	if len(data) > 64<<10 || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, E("warp.invalid", "WireGuard configuration is invalid or too large")
	}
	interfaceOptions := M{}
	peers := []M{}
	section := ""
	var current M
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if section != "" {
					return nil, E("warp.invalid", "Duplicate WireGuard interface section")
				}
				section = "interface"
				current = interfaceOptions
			case "[peer]":
				section = "peer"
				current = M{}
				peers = append(peers, current)
				if len(peers) > 32 {
					return nil, E("warp.invalid", "Too many WireGuard peers")
				}
			default:
				return nil, E("warp.invalid", "Unsupported WireGuard section")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || section == "" || value == "" {
			return nil, E("warp.invalid", "Invalid WireGuard assignment")
		}
		if _, exists := current[key]; exists {
			return nil, E("warp.invalid", "Duplicate WireGuard field")
		}
		current[key] = value
	}
	if !rtAllowedKeys(interfaceOptions, "privatekey address mtu listenport dns") || len(peers) == 0 {
		return nil, E("warp.invalid", "Unsupported WireGuard interface fields or missing peers")
	}
	key := rtString(interfaceOptions["privatekey"])
	if !validWGKey(key) {
		return nil, E("warp.invalid", "Invalid WireGuard private key")
	}
	addresses := []string{}
	for _, address := range strings.Split(rtString(interfaceOptions["address"]), ",") {
		address = strings.TrimSpace(address)
		if _, e := netip.ParsePrefix(address); e != nil {
			return nil, E("warp.invalid", "Invalid WireGuard interface address")
		}
		addresses = append(addresses, address)
	}
	ep := M{"type": "wireguard", "tag": "warp", "system": false, "address": rtStrings(addresses), "private_key": key, "mtu": 1280}
	for src, dst := range map[string]string{"mtu": "mtu", "listenport": "listen_port"} {
		if v := rtString(interfaceOptions[src]); v != "" {
			n, e := strconv.Atoi(v)
			if e != nil || n < 1 || n > 65535 || src == "mtu" && (n < 1280 || n > 1500) {
				return nil, E("warp.invalid", "Invalid WireGuard numeric field")
			}
			ep[dst] = n
		}
	}
	converted := []any{}
	for _, peer := range peers {
		if !rtAllowedKeys(peer, "publickey presharedkey allowedips endpoint persistentkeepalive reserved") {
			return nil, E("warp.invalid", "Unsupported WireGuard peer field")
		}
		if !validWGKey(rtString(peer["publickey"])) {
			return nil, E("warp.invalid", "Invalid WireGuard public key")
		}
		host, port, e := splitServerPort(rtString(peer["endpoint"]))
		if e != nil {
			return nil, E("warp.invalid", "Invalid WireGuard peer endpoint")
		}
		p := M{"address": host, "port": port, "public_key": peer["publickey"]}
		if s := rtString(peer["presharedkey"]); s != "" {
			if !validWGKey(s) {
				return nil, E("warp.invalid", "Invalid WireGuard preshared key")
			}
			p["pre_shared_key"] = s
		}
		allowed := []string{}
		for _, cidr := range strings.Split(rtString(peer["allowedips"]), ",") {
			cidr = strings.TrimSpace(cidr)
			if _, e := netip.ParsePrefix(cidr); e != nil {
				return nil, E("warp.invalid", "Invalid WireGuard allowed route")
			}
			allowed = append(allowed, cidr)
		}
		p["allowed_ips"] = rtStrings(allowed)
		if s := rtString(peer["persistentkeepalive"]); s != "" {
			n, e := strconv.Atoi(s)
			if e != nil || n < 0 || n > 65535 {
				return nil, E("warp.invalid", "Invalid WireGuard keepalive")
			}
			p["persistent_keepalive_interval"] = n
		}
		if s := rtString(peer["reserved"]); s != "" {
			parts := strings.Split(s, ",")
			if len(parts) != 3 {
				return nil, E("warp.invalid", "WireGuard reserved needs three bytes")
			}
			r := []any{}
			for _, v := range parts {
				n, e := strconv.Atoi(strings.TrimSpace(v))
				if e != nil || n < 0 || n > 255 {
					return nil, E("warp.invalid", "Invalid WireGuard reserved byte")
				}
				r = append(r, n)
			}
			p["reserved"] = r
		}
		converted = append(converted, p)
	}
	ep["peers"] = converted
	return ep, nil
}
func validWGKey(s string) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == 32
}

func (a *App) TailscaleStatus(ctx context.Context) (M, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	configured := s.Tailscale.Endpoint != nil
	if !configured {
		b, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e == nil {
			var c M
			if DecodeJSON(b, &c) == nil {
				for _, v := range rtArray(c["endpoints"]) {
					if rtString(rtMap(v)["type"]) == "tailscale" {
						configured = true
					}
				}
			}
		}
	}
	state := "not_configured"
	if configured {
		state = "disabled"
	}
	if s.Tailscale.Enabled {
		state = "configured"
	}
	if s.Tailscale.LogoutPending {
		state = "logout_pending"
	}
	return M{"revision": s.Tailscale.Revision, "configured": M{"enabled": s.Tailscale.Enabled, "userspace": true, "identity_configured": configured}, "effective": M{"online": nil, "discovery": "unknown", "tsmp": "unknown", "application_connection": "unknown"}, "enabled": s.Tailscale.Enabled, "resumable": configured && !s.Tailscale.LogoutPending, "logout_pending": s.Tailscale.LogoutPending, "state": state}, nil
}

func (a *App) changeRuntimeSettings(ctx context.Context, mutate func(*RuntimeSettings) error) (M, error) {
	var result M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		if e := a.EnsureDefaultConfig(ctx); e != nil {
			return e
		}
		s, e := a.runtimeSettings()
		if e != nil {
			return e
		}
		before := runtimeSettingsBytes(s)
		if e = mutate(&s); e != nil {
			return e
		}
		if e = validateRuntimeSettings(s); e != nil {
			return e
		}
		data, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return e
		}
		doc, e := a.readOverride(true)
		if e != nil {
			return e
		}
		candidate, e := a.materializeWith(ctx, data, s, doc.Patch)
		if e != nil {
			return e
		}
		generation := token()
		if e = a.performRuntimeChange(ctx, candidate, []RuntimeFileChange{{Path: ".config/magicnet/runtime-settings.json", Data: runtimeSettingsBytes(s)}}, generation); e != nil {
			return e
		}
		result = M{"saved": true, "applied": true, "changed": string(before) != string(runtimeSettingsBytes(s)), "generation_id": generation, "network_verified": false}
		return nil
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return result, e
}

func (a *App) tailscaleAction(ctx context.Context, action string, revision int64) (M, error) {
	if action == "logout" {
		return a.tailscaleLogout(ctx, revision)
	}
	return a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		if s.Tailscale.Revision != revision {
			return E("tailscale.conflict", "Tailscale configuration revision changed")
		}
		if s.Tailscale.LogoutPending {
			return E("tailscale.logout_pending", "Complete local logout before enabling Tailscale")
		}
		if s.Tailscale.Endpoint == nil {
			return E("tailscale.not_configured", "Add a userspace Tailscale endpoint in the private configuration editor first")
		}
		if !stringIn(action, "enable", "disable") {
			return E("tailscale.invalid", "Invalid Tailscale action")
		}
		enabled := action == "enable"
		if enabled != s.Tailscale.Enabled {
			s.Tailscale.Enabled = enabled
			s.Tailscale.Revision++
		}
		return nil
	})
}

func (a *App) tailscaleLogout(ctx context.Context, revision int64) (M, error) {
	var result M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		s, e := a.runtimeSettings()
		if e != nil {
			return e
		}
		if s.Tailscale.Revision != revision {
			return E("tailscale.conflict", "Tailscale revision changed")
		}
		running, e := a.IsRunning(ctx)
		if e != nil {
			return e
		}
		s.Tailscale.Enabled = false
		s.Tailscale.LogoutPending = true
		s.Tailscale.Revision++
		if e = a.writeRuntimeSettings(s); e != nil {
			return e
		}
		if e = a.stopCore(ctx); e != nil {
			return E("tailscale.logout_pending", "Core shutdown is not confirmed; local identity was retained")
		}
		if still, e := a.IsRunning(ctx); e != nil || still {
			return E("tailscale.logout_pending", "Core shutdown is not confirmed")
		}
		config, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return e
		}
		doc, e := a.readOverride(true)
		if e != nil {
			return e
		}
		candidate, e := a.materializeWith(ctx, config, s, doc.Patch)
		if e != nil {
			return e
		}
		if e = a.ActivateConfig(ctx, candidate, token(), false); e != nil {
			return E("tailscale.logout_pending", "Disabled configuration could not be activated")
		}
		if s.Tailscale.OwnedDirectory && s.Tailscale.Endpoint != nil {
			dir := rtString(s.Tailscale.Endpoint["state_directory"])
			expected := a.Path(".state", "private", "tailscale")
			if !a.isCurrentOwnedTailscalePath(dir) {
				return E("tailscale.logout_pending", "Tailscale directory ownership does not match")
			}
			dir = expected
			marker, e := ReadRegular(filepath.Join(dir, ".magicnet-owned"), 128)
			if e != nil || strings.TrimSpace(string(marker)) != "MagicNet" {
				return E("tailscale.logout_pending", "Tailscale directory ownership cannot be proved")
			}
			if e = os.RemoveAll(dir); e != nil {
				return E("tailscale.logout_pending", "Owned Tailscale identity cleanup failed")
			}
		}
		keys := map[string]string{}
		e = ReadJSON(a.Path(".config", "magicnet", "tailscale-auth.json"), 64<<10, &keys)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if s.Tailscale.Endpoint != nil {
			delete(keys, rtString(s.Tailscale.Endpoint["tag"]))
		}
		if e = WriteJSON(a.Path(".config", "magicnet", "tailscale-auth.json"), keys); e != nil {
			return e
		}
		s.Tailscale.Endpoint = nil
		s.Tailscale.OwnedDirectory = false
		s.Tailscale.LogoutPending = false
		if e = a.writeRuntimeSettings(s); e != nil {
			return e
		}
		if running {
			if e = a.startCore(ctx, token()); e != nil {
				return E("tailscale.logout_pending", "Identity was removed; the core could not restart")
			}
		}
		result = M{"logged_out": true, "cloud_account_deleted": false, "revision": s.Tailscale.Revision}
		return nil
	})
	_ = a.Publish(ctx)
	return result, e
}

func (a *App) WarpStatus() (M, error) {
	s, e := a.runtimeSettings()
	if e != nil {
		return nil, e
	}
	return M{"configured": s.Warp.Endpoint != nil, "enabled": s.Warp.Enabled, "mode": s.Warp.Mode, "revision": s.Warp.Revision, "effective_connectivity": "unknown"}, nil
}

func (a *App) warpAction(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "WARP action is required")
	}
	action := args[0]
	if action == "status" && len(args) == 1 {
		return a.WarpStatus()
	}
	if action == "test" && len(args) == 1 {
		return a.API(ctx, "GET", "/proxies/warp/delay?url="+url.QueryEscape("https://www.cloudflare.com/cdn-cgi/trace")+"&timeout=10000", nil)
	}
	var endpoint M
	if action == "import-file" {
		if len(args) != 2 {
			return nil, E("command.arguments", "A private WireGuard file is required")
		}
		b, e := ReadRegular(args[1], 64<<10)
		if e != nil {
			return nil, E("warp.file_invalid", "WireGuard configuration cannot be read safely")
		}
		endpoint, e = ParseWireGuardConfiguration(b)
		if e != nil {
			return nil, e
		}
		// Import validates the actual endpoint even while WARP remains disabled.
		// A later enable must not be the first time the pinned core sees it.
		probe := M{"endpoints": []any{endpoint}, "outbounds": []any{M{"type": "direct", "tag": "direct"}}, "route": M{"final": "direct"}}
		if e = a.CheckConfig(ctx, rtJSON(probe)); e != nil {
			return nil, E("warp.config_invalid", "The pinned core rejected the imported WireGuard endpoint")
		}
	} else if len(args) != 1 {
		return nil, E("command.arguments", "Invalid WARP arguments")
	}
	return a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		switch action {
		case "import-file":
			s.Warp.Endpoint = endpoint
			s.Warp.Revision++
		case "enable":
			if s.Warp.Endpoint == nil {
				return E("warp.not_configured", "Import a WireGuard configuration first")
			}
			s.Warp.Enabled = true
		case "disable":
			s.Warp.Enabled = false
		case "global", "rule":
			s.Warp.Mode = action
		case "apply":
		default:
			return E("command.arguments", "Unknown WARP action")
		}
		return nil
	})
}
