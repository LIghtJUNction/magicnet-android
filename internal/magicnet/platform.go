package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type PlatformSettings struct {
	AppMode string            `json:"app_mode"`
	Apps    map[string]string `json:"apps"`
	Hotspot bool              `json:"hotspot"`
	WiFi    WiFiSettings      `json:"wifi"`
}
type WiFiSettings struct {
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"`
	Interval int      `json:"interval"`
	SSIDs    []string `json:"ssids"`
	BSSIDs   []string `json:"bssids"`
}

func (a *App) platformSettings() (PlatformSettings, error) {
	if a.PlatformOverride != nil {
		return *a.PlatformOverride, nil
	}
	p := PlatformSettings{AppMode: "blacklist", Apps: map[string]string{}, WiFi: WiFiSettings{Mode: "blacklist", Interval: 10, SSIDs: []string{}, BSSIDs: []string{}}}
	e := ReadJSON(a.Path(".config", "magicnet", "platform.json"), 64<<10, &p)
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	if p.Apps == nil {
		p.Apps = map[string]string{}
	}
	if e != nil {
		return p, E("platform.settings_invalid", "Cannot read platform settings.")
	}
	return p, nil
}
func (a *App) savePlatform(p PlatformSettings) error {
	b, _ := json.Marshal(p)
	if len(b) > 64<<10 {
		return E("platform.limit", "Platform policy exceeds 64 KiB.")
	}
	return WriteJSON(a.Path(".config", "magicnet", "platform.json"), p)
}

var packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$`)

func (a *App) packageUIDs(ctx context.Context) (map[string][]int, error) {
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, e := Run(c, a.Root, a.findTool("cmd"), []string{"user", "list"}, nil, 64<<10)
	if e != nil {
		return nil, E("app.enumeration_failed", "Android user enumeration failed.")
	}
	ids := regexp.MustCompile(`UserInfo\{([0-9]+):`).FindAllStringSubmatch(string(r.Stdout), 128)
	if len(ids) == 0 {
		return nil, E("app.enumeration_failed", "No verified Android users were reported.")
	}
	out := map[string][]int{}
	for _, id := range ids {
		r, e = Run(c, a.Root, a.findTool("cmd"), []string{"package", "list", "packages", "-U", "--user", id[1]}, nil, 512<<10)
		if e != nil {
			return nil, E("app.enumeration_failed", "Package UID enumeration failed.")
		}
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || !strings.HasPrefix(f[0], "package:") || !strings.HasPrefix(f[1], "uid:") {
				continue
			}
			p := strings.TrimPrefix(f[0], "package:")
			uid, e := strconv.Atoi(strings.TrimPrefix(f[1], "uid:"))
			if e != nil || uid < 0 || !packagePattern.MatchString(p) {
				return nil, E("app.enumeration_failed", "Invalid package identity data.")
			}
			out[p] = append(out[p], uid)
		}
	}
	return out, nil
}
func (a *App) MaterializePlatform(ctx context.Context, config M) (M, error) {
	p, e := a.platformSettings()
	if e != nil {
		return nil, e
	}
	mode, e := a.transparentMode()
	if e != nil {
		return nil, e
	}
	inbounds, _ := config["inbounds"].([]any)
	var tun M
	for _, v := range inbounds {
		m, _ := v.(map[string]any)
		if asString(m["tag"]) == "tun-in" || asString(m["tag"]) == "ebpf-in" {
			tun = m
		}
	}
	if tun == nil {
		return nil, E("config.controlled_inbound_missing", "The managed transparent inbound is missing.")
	}
	uids := map[string][]int{}
	if len(p.Apps) > 0 {
		uids, e = a.packageUIDs(ctx)
		if e != nil {
			return nil, e
		}
	}
	byTarget := map[string][]int{"proxy": {}, "direct": {}, "bypass": {}}
	for pkg, target := range p.Apps {
		us := uids[pkg]
		for _, uid := range us {
			byTarget[target] = append(byTarget[target], uid)
		}
	}
	blocked := map[int]bool{}
	for _, u := range byTarget["bypass"] {
		blocked[u] = true
	}
	include := []int{}
	for _, t := range []string{"proxy", "direct"} {
		vs := []int{}
		for _, u := range byTarget[t] {
			if !blocked[u] {
				vs = append(vs, u)
				include = append(include, u)
			}
		}
		byTarget[t] = vs
	}
	// Remove only exact items written by the platform materializer. External
	// edits of owned entries are conflicts; other writers retain their arrays.
	var owned M
	op := a.Path(".state", "platform-owned.json")
	if e = ReadJSON(op, 4<<20, &owned); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	for _, domain := range []string{"route", "dns"} {
		obj, _ := config[domain].(map[string]any)
		if obj == nil {
			continue
		}
		rules, _ := obj["rules"].([]any)
		previous, _ := owned[domain].([]any)
		for _, old := range previous {
			b, _ := json.Marshal(old)
			found := -1
			for i, r := range rules {
				rb, _ := json.Marshal(r)
				if string(b) == string(rb) {
					found = i
					break
				}
			}
			if found >= 0 {
				rules = append(rules[:found], rules[found+1:]...)
			}
		}
		obj["rules"] = rules
	}
	if mode == "ebpf" {
		ipv6 := rtMap(config["dns"])["strategy"] != "ipv4_only"
		mtu := tun["mtu"]
		_ = mtu
		timeout := tun["udp_timeout"]
		if timeout == nil {
			timeout = "5m"
		}
		local := M{"dns_mode": "respect_policy", "cgroup_path": "/sys/fs/cgroup", "ipv6": ipv6, "bypass_private_address": true}
		if len(byTarget["bypass"]) > 0 {
			local["exclude_uid"] = byTarget["bypass"]
		}
		if p.AppMode == "whitelist" {
			if len(include) > 0 {
				local["include_uid"] = include
			} else {
				local["exclude_uid_range"] = []string{"0:4294967295"}
			}
		}
		ds, _ := a.downstreams(ctx)
		shared := M{"dns_mode": "respect_policy", "ipv6": ipv6, "bypass_private_address": true, "interface": ds}
		if !p.Hotspot {
			shared["include_source_cidr"] = []string{"192.0.2.1/32"}
		}
		replacement := M{"type": "ebpf", "tag": "tun-in", "mode": "hybrid", "network": []string{"tcp", "udp"}, "udp_timeout": timeout, "local": local, "shared": shared}
		for k := range tun {
			delete(tun, k)
		}
		for k, v := range replacement {
			tun[k] = v
		}
	} else {
		if tun["type"] == "ebpf" {
			s, err := a.runtimeSettings()
			if err != nil {
				return nil, err
			}
			timeout := tun["udp_timeout"]
			for k := range tun {
				delete(tun, k)
			}
			addresses := []string{s.Network.TunIPv4}
			if s.Network.IPv6Mode != "ipv4_only" {
				addresses = append(addresses, s.Network.TunIPv6)
			}
			for k, v := range (M{"type": "tun", "tag": "tun-in", "interface_name": "magicnet0", "address": addresses, "mtu": s.Network.MTU, "stack": "mixed", "auto_route": true, "strict_route": true, "udp_timeout": timeout}) {
				tun[k] = v
			}
		}
		delete(tun, "include_uid")
		delete(tun, "exclude_uid")
		delete(tun, "exclude_uid_range")
		if len(byTarget["bypass"]) > 0 {
			tun["exclude_uid"] = byTarget["bypass"]
		}
		if p.AppMode == "whitelist" {
			if len(include) > 0 {
				tun["include_uid"] = include
			} else {
				tun["exclude_uid_range"] = []string{"0:4294967295"}
			}
		}
	}
	newOwned := M{}
	for _, domain := range []string{"route", "dns"} {
		obj, _ := config[domain].(map[string]any)
		if obj == nil {
			continue
		}
		rules, _ := obj["rules"].([]any)
		adds := []any{}
		for _, target := range []string{"proxy", "direct"} {
			if len(byTarget[target]) == 0 {
				continue
			}
			r := M{"user_id": byTarget[target]}
			if domain == "route" {
				r["action"] = "route"
				r["outbound"] = target
			} else {
				r["action"] = "route"
				if target == "direct" {
					r["server"] = "doh-cloudflare"
				} else {
					r["server"] = "doh-google"
				}
			}
			adds = append(adds, r)
		}
		if domain == "route" && p.Hotspot {
			ds, err := a.downstreams(ctx)
			if err != nil {
				return nil, err
			}
			prefixes := []string{}
			for _, name := range ds {
				in, err := net.InterfaceByName(name)
				if err != nil {
					return nil, E("hotspot.observation_failed", "A confirmed downstream disappeared.")
				}
				addresses, err := in.Addrs()
				if err != nil {
					return nil, err
				}
				for _, ad := range addresses {
					ip, prefix, err := net.ParseCIDR(ad.String())
					if err == nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
						prefixes = append(prefixes, prefix.String())
					}
				}
			}
			sort.Strings(prefixes)
			if len(prefixes) > 0 {
				adds = append(adds, M{"inbound": []string{"tun-in"}, "source_ip_cidr": prefixes, "action": "route", "outbound": "hotspot"})
			}
		}
		index := 0
		for i, r := range rules {
			m, _ := r.(map[string]any)
			if m["clash_mode"] != nil || m["ip_is_private"] != nil || m["preferred_by"] != nil || m["action"] == "hijack-dns" {
				index = i + 1
			} else {
				break
			}
		}
		out := append([]any{}, rules[:index]...)
		out = append(out, adds...)
		out = append(out, rules[index:]...)
		obj["rules"] = out
		newOwned[domain] = adds
	}
	a.PlatformOwned = newOwned
	return config, nil
}
func (a *App) platformApply(ctx context.Context) (M, error) {
	var out M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		b, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return e
		}
		b, e = a.MaterializeConfig(ctx, b)
		if e != nil {
			return e
		}
		r, e := a.IsRunning(ctx)
		if e != nil {
			return e
		}
		if e = a.ActivateConfig(ctx, b, token(), r); e != nil {
			return e
		}
		out = M{"applied": true}
		return nil
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return out, e
}
func (a *App) downstreams(ctx context.Context) ([]string, error) {
	if a.Platform != "android" {
		return []string{}, nil
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, e := Run(c, a.Root, a.findTool("dumpsys"), []string{"tethering"}, nil, 512<<10)
	if e != nil {
		return nil, E("hotspot.observation_failed", "Tethering topology is unavailable.")
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	found := []string{}
	for _, in := range interfaces {
		if in.Flags&net.FlagLoopback != 0 || len(in.HardwareAddr) != 6 || strings.HasPrefix(in.Name, "rmnet") || strings.HasPrefix(in.Name, "tun") || in.Name == "magicnet0" {
			continue
		}
		pattern := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(in.Name) + `\b[^\n]*(?:TetheredState|tethered|TETHERED)`)
		if pattern.Match(r.Stdout) {
			found = append(found, in.Name)
		}
	}
	sort.Strings(found)
	return found, nil
}

func (a *App) platformApplyUnlocked(ctx context.Context) (M, error) {
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		return nil, e
	}
	b, e = a.MaterializeConfig(ctx, b)
	if e != nil {
		return nil, e
	}
	r, e := a.IsRunning(ctx)
	if e != nil {
		return nil, e
	}
	if r {
		if o, state, _ := observeOwner(a.Path(".state", "owners", "core.json")); state == "active" {
			if fp, err := a.configFingerprint(b); err == nil && o.Fingerprint == fp {
				if dp := a.dataplaneEvidence(ctx, modeFromConfig(b), o, state); dp["ready"] == true {
					if _, e := a.API(ctx, "GET", "/version", nil); e == nil {
						return M{"applied": true, "changed": false}, a.commitMaterialization()
					}
				}
			}
		}
	}
	e = a.ActivateConfig(ctx, b, token(), r)
	return M{"applied": e == nil}, e
}
func (a *App) wifiObserve(ctx context.Context) (M, error) {
	p, e := a.platformSettings()
	if e != nil {
		return nil, e
	}
	effective := M{"connected": nil, "matched": nil, "mode": "unknown", "desired_mode": "unknown"}
	m := M{"configured": M{"enabled": p.WiFi.Enabled, "mode": p.WiFi.Mode, "interval": p.WiFi.Interval, "ssid_count": len(p.WiFi.SSIDs), "bssid_count": len(p.WiFi.BSSIDs)}, "effective": effective}
	if !p.WiFi.Enabled {
		effective["desired_mode"] = "rule"
	} else {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		r, e := Run(c, a.Root, a.findTool("cmd"), []string{"wifi", "status"}, nil, 64<<10)
		if e == nil {
			text := string(r.Stdout)
			matched := false
			observed := false
			connected := true
			ssid := regexp.MustCompile(`(?m)SSID: (.*?)(?:, BSSID:|$)`).FindStringSubmatch(text)
			bssid := regexp.MustCompile(`(?i)BSSID: ([0-9a-f:]{17})`).FindStringSubmatch(text)
			if len(ssid) > 1 && len(bssid) > 1 {
				observed = true
				for _, s := range p.WiFi.SSIDs {
					if s == strings.Trim(ssid[1], "\"") {
						matched = true
					}
				}
				for _, s := range p.WiFi.BSSIDs {
					if strings.EqualFold(s, bssid[1]) {
						matched = true
					}
				}
			} else if strings.Contains(text, "Wifi is disabled") || strings.Contains(text, "Wi-Fi is disabled") || strings.Contains(text, "Supplicant state: DISCONNECTED") {
				observed = true
				connected = false
			}
			if observed {
				mode := "rule"
				if p.WiFi.Mode == "blacklist" && matched || p.WiFi.Mode == "whitelist" && !matched {
					mode = "direct"
				}
				effective["desired_mode"] = mode
				effective["connected"] = connected
				effective["matched"] = matched
			}
		}
	}
	if running, e := a.IsRunning(ctx); e == nil && running {
		if current, e := a.API(ctx, "GET", "/configs", nil); e == nil {
			mode := asString(current["mode"])
			if stringIn(mode, "direct", "rule", "global") {
				effective["mode"] = mode
			}
		}
	}
	return m, nil
}
func (a *App) handlePlatform(ctx context.Context, args []string, machine bool) (M, error, bool) {
	if len(args) < 2 || !stringIn(args[0], "app", "wifi", "hotspot", "transparent", "network-access") || stringIn(args[1], "status", "inspect", "check", "list", "packages") {
		return a.handlePlatformUnlocked(ctx, args, machine)
	}
	var m M
	var handled bool
	e := a.withLock(ctx, "platform-intent", 2*time.Second, func() error {
		var err error
		m, err, handled = a.handlePlatformUnlocked(ctx, args, machine)
		return err
	})
	if !handled && e != nil {
		handled = true
	}
	return m, e, handled
}
func (a *App) handlePlatformUnlocked(ctx context.Context, args []string, machine bool) (M, error, bool) {
	if len(args) == 0 {
		return nil, nil, false
	}
	family := args[0]
	if !stringIn(family, "app", "wifi", "hotspot", "transparent", "network-access") {
		return nil, nil, false
	}
	if len(args) < 2 {
		return nil, E("command.arguments", "An action is required."), true
	}
	act := args[1]
	p, e := a.platformSettings()
	if e != nil {
		return nil, e, true
	}
	switch family {
	case "transparent":
		if act == "status" {
			s, e := a.ServiceStatus(ctx)
			if e != nil {
				return nil, e, true
			}
			return M{"configured": s["configured"], "effective": s["readiness"], "state": s["state"]}, nil, true
		}
		if act == "set" && len(args) == 3 {
			if !stringIn(args[2], "tun", "ebpf") {
				return nil, E("transparent.mode_invalid", "Only tun and ebpf are supported."), true
			}
			var result M
			e = a.WithLifecycleLock(ctx, 2*time.Second, func() error {
				if e := a.RecoverRuntime(ctx); e != nil {
					return e
				}
				b, e := ReadRegular(a.ConfigPath(), 4<<20)
				if e != nil {
					return e
				}
				a.ModeOverride = args[2]
				b, e = a.MaterializeConfig(ctx, b)
				a.ModeOverride = ""
				if e != nil {
					return e
				}
				e = a.performRuntimeChange(ctx, b, []RuntimeFileChange{{Path: ".config/magicnet/transparent.conf", Data: []byte(args[2] + "\n"), BeforeActivate: true}}, token())
				result = M{"applied": e == nil}
				return e
			})
			if e == nil {
				e = a.Publish(ctx)
			}
			return result, e, true
		}
		if act == "apply" {
			m, e := a.platformApply(ctx)
			return m, e, true
		}
	case "app":
		switch act {
		case "inspect":
			m, e := a.bridge(ctx, "catalog")
			if e != nil {
				return nil, E("app.catalog_unavailable", "Application catalog provider is unavailable."), true
			}
			return m, nil, true
		case "packages":
			uids, e := a.packageUIDs(ctx)
			if e != nil {
				return nil, e, true
			}
			list := []string{}
			q := ""
			if len(args) > 2 {
				q = args[2]
			}
			for n := range uids {
				if strings.Contains(n, q) {
					list = append(list, n)
				}
			}
			sort.Strings(list)
			return M{"packages": list}, nil, true
		case "list", "recommendations":
			return M{"mode": p.AppMode, "packages": p.Apps, "shared_uid_boundary": true, "resolver_delegation": "unknown"}, nil, true
		case "mode":
			if len(args) != 3 || !stringIn(args[2], "blacklist", "whitelist") {
				return nil, E("app.mode_invalid", "Invalid application mode."), true
			}
			p.AppMode = args[2]
		case "add", "remove":
			if len(args) < 3 || len(args) > 4 || !packagePattern.MatchString(args[2]) {
				return nil, E("app.package_invalid", "Invalid package name."), true
			}
			target := "proxy"
			if len(args) == 4 {
				target = args[3]
			}
			if !stringIn(target, "proxy", "direct", "bypass") {
				return nil, E("app.target_invalid", "Invalid policy target."), true
			}
			if act == "remove" {
				delete(p.Apps, args[2])
			} else {
				p.Apps[args[2]] = target
			}
		case "add-many":
			if len(args) < 4 || len(args) > 203 || !stringIn(args[2], "proxy", "direct", "bypass") {
				return nil, E("app.input_invalid", "Invalid application policy list."), true
			}
			for _, n := range args[3:] {
				if !packagePattern.MatchString(n) {
					return nil, E("app.package_invalid", "Invalid package name."), true
				}
				p.Apps[n] = args[2]
			}
		case "apply":
			m, e := a.platformApply(ctx)
			return m, e, true
		default:
			return nil, E("command.unknown", "Unknown application action."), true
		}
		m, e := a.platformApplyIntent(ctx, p)
		return m, e, true
	case "wifi":
		if act == "status" || act == "check" {
			m, e := a.wifiObserve(ctx)
			return m, e, true
		}
		if act == "inspect" {
			m, e := a.wifiObserve(ctx)
			if e == nil {
				m["configuration"] = p.WiFi
			}
			return m, e, true
		}
		switch act {
		case "enable":
			p.WiFi.Enabled = true
		case "disable":
			p.WiFi.Enabled = false
		case "mode":
			if len(args) != 3 || !stringIn(args[2], "blacklist", "whitelist") {
				return nil, E("wifi.mode_invalid", "Invalid Wi-Fi policy mode."), true
			}
			p.WiFi.Mode = args[2]
		case "interval":
			if len(args) != 3 {
				return nil, E("wifi.interval_invalid", "Interval is required."), true
			}
			n, er := strconv.Atoi(args[2])
			if er != nil || n < 3 || n > 300 {
				return nil, E("wifi.interval_invalid", "Interval must be 3–300 seconds."), true
			}
			p.WiFi.Interval = n
		case "add-ssid", "remove-ssid", "add-bssid", "remove-bssid":
			if len(args) != 3 || !utf8.ValidString(args[2]) || len(args[2]) == 0 || strings.ContainsAny(args[2], "\x00\r\n") {
				return nil, E("wifi.entry_invalid", "Invalid Wi-Fi list entry."), true
			}
			entry := args[2]
			list := &p.WiFi.SSIDs
			if strings.HasSuffix(act, "bssid") {
				mac, er := net.ParseMAC(entry)
				if er != nil || len(mac) != 6 {
					return nil, E("wifi.entry_invalid", "Invalid BSSID."), true
				}
				entry = strings.ToLower(mac.String())
				list = &p.WiFi.BSSIDs
			}
			next := []string{}
			found := false
			for _, x := range *list {
				if x == entry {
					found = true
					if strings.HasPrefix(act, "remove") {
						continue
					}
				}
				next = append(next, x)
			}
			if strings.HasPrefix(act, "add") && !found {
				next = append(next, entry)
			}
			*list = next
		default:
			return nil, E("command.unknown", "Unknown Wi-Fi action."), true
		}
		if e = a.savePlatform(p); e != nil {
			return nil, e, true
		}
		applied := false
		if running, re := a.IsRunning(ctx); re != nil {
			return M{"saved": true, "effective": "unknown"}, re, true
		} else if running {
			observed, oe := a.wifiObserve(ctx)
			if oe == nil {
				effective, _ := observed["effective"].(map[string]any)
				desired := asString(effective["desired_mode"])
				if stringIn(desired, "rule", "direct") {
					if _, e = a.API(ctx, "PATCH", "/configs", M{"mode": desired}); e != nil {
						return M{"saved": true, "effective": "pending"}, e, true
					}
					readback, re := a.API(ctx, "GET", "/configs", nil)
					if re != nil || readback["mode"] != desired {
						return M{"saved": true, "effective": "pending"}, E("wifi.readback_failed", "Wi-Fi mode activation was not verified."), true
					}
					applied = true
				}
			}
		}
		if p.WiFi.Enabled {
			if _, e = a.supervisorControl(ctx, "start", "wifi-policy"); e != nil {
				return M{"saved": true}, e, true
			}
		}
		if e = a.Publish(ctx); e != nil {
			return M{"saved": true}, e, true
		}
		return M{"saved": true, "applied": applied}, nil, true
	case "hotspot":
		if act == "status" {
			m, e := a.hotspotStatus(ctx)
			return m, e, true
		}

		if act == "enable" || act == "disable" {
			p.Hotspot = act == "enable"
			_, e = a.platformApplyIntent(ctx, p)
			if e != nil {
				return nil, e, true
			}
		}
		if stringIn(act, "enable", "disable", "reconcile") {
			m, e := a.hotspotReconcile(ctx)
			return m, e, true
		}
	case "network-access":
		m, e := a.networkAccess(ctx, args[1:])
		return m, e, true
	}
	return nil, E("command.arguments", "Unsupported action or argument count."), true
}
func (a *App) bridge(ctx context.Context, args ...string) (M, error) {
	jar := a.Path("bin", "magicnet-bridge.jar")
	if _, e := ReadRegular(jar, 8<<20); e != nil {
		return nil, E("bridge.unavailable", "Android policy bridge is unavailable.")
	}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, e := Run(c, a.Root, a.findTool("app_process"), append([]string{"-Djava.class.path=" + jar, "/system/bin", "MagicNetBridge"}, args...), nil, 512<<10)
	if e != nil {
		return nil, e
	}
	var m M
	if e = DecodeJSON(r.Stdout, &m); e != nil {
		return nil, E("bridge.invalid", "Invalid bridge response.")
	}
	if m["ok"] != true {
		return nil, E("bridge.unsupported", "The required Android provider is unavailable.")
	}
	d, _ := m["data"].(map[string]any)
	return d, nil
}

var _ = fmt.Sprint
var _ = filepath.Join

func (a *App) platformApplyIntent(ctx context.Context, p PlatformSettings) (M, error) {
	data, e := json.Marshal(p)
	if e != nil || len(data) > 64<<10 {
		return nil, E("platform.limit", "Platform policy exceeds its limit.")
	}
	e = a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		b, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil {
			return e
		}
		a.PlatformOverride = &p
		b, e = a.MaterializeConfig(ctx, b)
		a.PlatformOverride = nil
		if e != nil {
			return e
		}
		return a.performRuntimeChange(ctx, b, []RuntimeFileChange{{Path: ".config/magicnet/platform.json", Data: data, BeforeActivate: true}}, token())
	})
	if e != nil {
		return nil, e
	}
	if e = a.Publish(ctx); e != nil {
		return nil, e
	}
	return M{"applied": true}, nil
}
