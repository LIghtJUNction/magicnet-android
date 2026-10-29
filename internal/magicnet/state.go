package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var domains = []string{"service", "transparent", "subscription", "subscription-refresh", "selectors", "app-policy", "supervisors", "wifi", "hotspot", "dns", "mcp", "tailscale", "transactions", "overrides", "module-update"}

func (a *App) publicDomain(ctx context.Context, domain string) (M, error) {
	switch domain {
	case "service":
		return a.ServiceStatus(ctx)
	case "transparent", "wifi", "hotspot":
		m, e, _ := a.handlePlatform(ctx, []string{domain, "status"}, true)
		return m, e
	case "subscription":
		return a.RuntimeStatus(ctx, "subscription")
	case "subscription-refresh":
		return a.RuntimeStatus(ctx, "subscription-refresh")
	case "dns", "tailscale", "overrides":
		return a.RuntimeStatus(ctx, domain)
	case "app-policy":
		p, e := a.platformSettings()
		if e != nil {
			return nil, e
		}
		counts := M{"proxy": 0, "direct": 0, "bypass": 0}
		for _, t := range p.Apps {
			counts[t] = asInt(counts[t]) + 1
		}
		return M{"configured_mode": p.AppMode, "counts": counts, "effective": "unknown"}, nil
	case "selectors":
		var m map[string]string
		e := ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &m)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
		return M{"saved_count": len(m)}, e
	case "supervisors":
		return a.supervisorStatus()
	case "mcp":
		return a.mcpStatus()
	case "transactions":
		m := M{}
		for key, path := range map[string]string{"lifecycle_pending": ".state/lifecycle/journal.json", "cleanup_pending": ".state/lifecycle/stop-resources.json", "runtime_pending": ".state/private/runtime-transaction.json", "initialization_pending": ".state/private/runtime-initialization.json", "path_relocation_pending": runtimePathJournal, "subscription_pending": ".state/private/subscription/journal.json", "backup_pending": ".state/backup/restore-journal.json", "update_publication_pending": ".state/module-update/record-journal.json"} {
			_, e := os.Lstat(a.Path(path))
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				m[key] = nil
			} else {
				m[key] = e == nil
			}
		}
		return m, nil
	case "module-update":
		return a.moduleUpdateStatus()
	}
	return nil, E("state.domain_unknown", "Unknown state domain.")
}
func canonicalTokens(domain string, m M) []byte {
	out := map[string]string{"schema": "1", "domain": domain}
	var add func(string, any)
	add = func(prefix string, v any) {
		switch x := v.(type) {
		case nil:
			out[prefix] = "unknown"
		case bool:
			out[prefix] = fmt.Sprint(x)
		case int:
			out[prefix] = fmt.Sprint(x)
		case int64:
			out[prefix] = fmt.Sprint(x)
		case float64:
			out[prefix] = fmt.Sprint(x)
		case json.Number:
			out[prefix] = x.String()
		case string:
			if len(x) <= 96 && safeToken(x) {
				out[prefix] = x
			} else {
				out[prefix] = "unknown"
			}
		case map[string]any:
			for k, val := range x {
				if safeToken(k) {
					add(prefix+"_"+k, val)
				}
			}
		case []any:
			out[prefix+"_count"] = fmt.Sprint(len(x))
		}
	}
	for k, v := range m {
		if safeToken(k) {
			add(k, v)
		}
	}
	keys := []string{}
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + out[k] + "\n")
	}
	return []byte(b.String())
}
func (a *App) Publish(ctx context.Context) error {
	data := map[string][]byte{}
	for _, d := range domains {
		m, e := a.publicDomain(ctx, d)
		if e != nil {
			m = M{"state": "unknown", "error_code": ErrorCode(e)}
		}
		data[d] = canonicalTokens(d, m)
	}
	return a.withLock(ctx, "publish", 2*time.Second, func() error {
		stage := a.Path(".state", "publication-"+token())
		defer os.RemoveAll(stage)
		for _, d := range domains {
			if e := AtomicWrite(filepath.Join(stage, d+".state"), data[d], 0600); e != nil {
				return e
			}
		}
		old := map[string][]byte{}
		for _, d := range domains {
			p := a.Path(".state", "machines", d+".state")
			b, e := ReadRegular(p, 64<<10)
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			old[d] = b
		}
		written := []string{}
		for _, d := range domains {
			if e := os.MkdirAll(a.Path(".state", "machines"), 0700); e != nil {
				return e
			}
			if e := os.Rename(filepath.Join(stage, d+".state"), a.Path(".state", "machines", d+".state")); e != nil {
				for _, x := range written {
					p := a.Path(".state", "machines", x+".state")
					if old[x] == nil {
						if re := os.Remove(p); re != nil && !errors.Is(re, os.ErrNotExist) {
							return E("state.rollback_failed", "Canonical publication requires recovery.")
						}
					} else {
						if re := AtomicWrite(p, old[x], 0600); re != nil {
							return E("state.rollback_failed", "Canonical publication requires recovery.")
						}
					}
				}
				return e
			}
			written = append(written, d)
		}
		dir, e := os.Open(a.Path(".state", "machines"))
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	})
}
func (a *App) supervisorStatus() (M, error) {
	m := M{}
	for _, name := range []string{"fswatch", "wifi-policy"} {
		_, s, _ := observeOwner(a.Path(".state", "owners", name+".json"))
		var run any = s == "active"
		if s == "unknown" {
			run = nil
		}
		m[name] = M{"owner": s, "running": run}
	}
	return m, nil
}
func (a *App) supervisorControl(ctx context.Context, action, target string) (M, error) {
	if !stringIn(target, "all", "fswatch", "wifi-policy") || !stringIn(action, "status", "start", "stop", "restart") {
		return nil, E("supervisor.invalid", "Invalid supervisor command.")
	}
	if action == "status" {
		return a.supervisorStatus()
	}
	e := a.withLock(ctx, "supervisors", 2*time.Second, func() error {
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		for _, name := range []string{"fswatch", "wifi-policy"} {
			if target != "all" && target != name {
				continue
			}
			p := a.Path(".state", "owners", name+".json")
			_, s, oe := observeOwner(p)
			if oe != nil || s == "unknown" {
				return E("supervisor.ownership_unknown", "Supervisor ownership is unknown.")
			}
			if action == "stop" || action == "restart" {
				if e = stopOwner(ctx, p); e != nil {
					return e
				}
				s = "none"
			}
			if action == "start" || action == "restart" {
				if s != "active" {
					if _, e = a.spawnOwned(name, exe, []string{"__supervisor", name}, "", ""); e != nil {
						return e
					}
				}
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	a.Publish(ctx)
	return a.supervisorStatus()
}
func (a *App) runSupervisor(ctx context.Context, name string) error {
	lastFP := ""
	lastUIDs := ""
	for {
		interval := 10 * time.Second
		if name == "wifi-policy" {
			p, e := a.platformSettings()
			if e == nil {
				interval = time.Duration(p.WiFi.Interval) * time.Second
				if interval < 3*time.Second {
					interval = 10 * time.Second
				}
			}
			m, e := a.wifiObserve(ctx)
			if e == nil {
				eff, _ := m["effective"].(map[string]any)
				mode := asString(eff["desired_mode"])
				if stringIn(mode, "direct", "rule") && (mode != lastFP || eff["mode"] != mode) {
					if _, e = a.API(ctx, "PATCH", "/configs", M{"mode": mode}); e == nil {
						lastFP = mode
						a.Publish(ctx)
					}
				}
			}
		} else {
			p, pe := a.platformSettings()
			if pe == nil && len(p.Apps) > 0 {
				uids, ue := a.packageUIDs(ctx)
				if ue == nil {
					selected := M{}
					for pkg := range p.Apps {
						selected[pkg] = uids[pkg]
					}
					ub, _ := json.Marshal(selected)
					uf := digest(ub)
					if lastUIDs != "" && uf != lastUIDs {
						a.platformApply(ctx)
					}
					lastUIDs = uf
				}
			}
			b, e := ReadRegular(a.ConfigPath(), 4<<20)
			if e == nil {
				fp, e := a.configFingerprint(b)
				if e == nil {
					if lastFP != "" && fp != lastFP {
						a.platformApply(ctx)
					}
					lastFP = fp
				}
			}
			a.hotspotReconcile(ctx)
			a.TickSubscriptionSchedule(ctx)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
