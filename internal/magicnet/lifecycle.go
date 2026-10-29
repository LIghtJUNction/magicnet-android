package magicnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) corePath() string { return a.Path("bin", "sing-box") }
func (a *App) IsRunning(ctx context.Context) (bool, error) {
	_, s, e := observeOwner(a.Path(".state", "owners", "core.json"))
	if e != nil || s == "unknown" {
		return false, E("service.ownership_unknown", "Core ownership is unknown.")
	}
	return s == "active", nil
}
func (a *App) CheckConfig(ctx context.Context, data []byte) error {
	if len(data) > 4<<20 {
		return E("config.limit", "Configuration exceeds 4 MiB.")
	}
	var m M
	if e := DecodeJSON(data, &m); e != nil {
		return E("config.invalid", "Invalid configuration JSON.")
	}
	if m == nil {
		return E("config.invalid", "Configuration must be an object.")
	}
	secretData, se := a.CoreConfigWithSecrets(data)
	if se != nil {
		return se
	}
	return a.checkPreparedConfig(ctx, secretData)
}
func (a *App) checkPreparedConfig(ctx context.Context, data []byte) error {
	dir := a.Path(".state", "check")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	p := filepath.Join(dir, "candidate-"+token()+".json")
	if e := AtomicWrite(p, data, 0600); e != nil {
		return e
	}
	defer os.Remove(p)
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, e := Run(c, a.Root, a.corePath(), []string{"check", "-c", p}, nil, 1<<20)
	if e != nil || r.ExitCode != 0 {
		return E("config.invalid", "The pinned core rejected the candidate configuration.")
	}
	return nil
}
func (a *App) configFingerprint(data []byte) (string, error) {
	var v any
	if e := DecodeJSON(data, &v); e != nil {
		return "", e
	}
	b, _ := json.Marshal(v)
	paths := []string{}
	var walk func(any)
	walk = func(x any) {
		switch z := x.(type) {
		case map[string]any:
			if z["type"] == "local" {
				if p, ok := z["path"].(string); ok {
					paths = append(paths, p)
				}
			}
			for _, y := range z {
				walk(y)
			}
		case []any:
			for _, y := range z {
				walk(y)
			}
		}
	}
	walk(v)
	sort.Strings(paths)
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			p = a.Path(p)
		}
		d, e := ReadRegular(p, 32<<20)
		if e != nil {
			return "", E("rules.unavailable", "A referenced rule set cannot be read.")
		}
		b = append(b, []byte(digest(d))...)
	}
	return digest(b), nil
}
func (a *App) apiEndpoint() (string, string, error) {
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		return "", "", e
	}
	var m M
	if e = DecodeJSON(b, &m); e != nil {
		return "", "", e
	}
	exp, _ := m["experimental"].(map[string]any)
	clash, _ := exp["clash_api"].(map[string]any)
	host := asString(clash["external_controller"])
	if host == "" {
		host = "127.0.0.1:9090"
	}
	ep := "http://" + host
	if a.Platform != "android" {
		if x := os.Getenv("MAGICNET_API"); x != "" {
			ep = x
		}
	}
	u, e := url.Parse(ep)
	if e != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !stringIn(u.Hostname(), "127.0.0.1", "::1", "localhost") {
		return "", "", E("api.endpoint_invalid", "Only a loopback HTTP API endpoint is allowed.")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return "", "", E("api.endpoint_invalid", "An explicit valid loopback port is required.")
	}
	return ep, asString(clash["secret"]), nil
}
func (a *App) API(ctx context.Context, method, path string, body any) (M, error) {
	ep, secret, e := a.apiEndpoint()
	if e != nil {
		return nil, E("api.unavailable", "Core API configuration is unavailable.")
	}
	var b []byte
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
	}
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(c, method, ep+path, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return nil, E("api.unavailable", "The core API did not respond.")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return nil, E("api.output_invalid", "The API response exceeds its limit.")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, E("api.rejected", "The core API rejected the request.")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return M{}, nil
	}
	var out M
	if e = DecodeJSON(data, &out); e != nil {
		return nil, E("api.output_invalid", "Invalid core API response.")
	}
	return out, nil
}
func (a *App) transparentMode() (string, error) {
	if a.ModeOverride != "" {
		return a.ModeOverride, nil
	}
	b, e := ReadRegular(a.Path(".config", "magicnet", "transparent.conf"), 128)
	if errors.Is(e, os.ErrNotExist) {
		return "tun", nil
	}
	if e != nil {
		return "", e
	}
	v := strings.TrimSpace(strings.ReplaceAll(string(b), "\r\n", "\n"))
	if strings.HasPrefix(v, "mode=") {
		v = strings.TrimPrefix(v, "mode=")
	}
	if !stringIn(v, "tun", "ebpf") {
		return "", E("transparent.mode_invalid", "Transparent mode must be tun or ebpf.")
	}
	return v, nil
}
func (a *App) ServiceStatus(ctx context.Context) (M, error) {
	o, owner, oe := observeOwner(a.Path(".state", "owners", "core.json"))
	mode, me := a.transparentMode()
	if me != nil {
		return nil, me
	}
	proc := "stopped"
	var running any = false
	if owner == "active" {
		proc = "running"
		running = true
	} else if owner == "unknown" || oe != nil {
		proc = "unknown"
		running = nil
	}
	apiReady := false
	if owner == "active" {
		_, e := a.API(ctx, "GET", "/version", nil)
		apiReady = e == nil
	}
	effectiveMode := mode
	if owner == "active" {
		if b, e := ReadRegular(a.ConfigPath(), 4<<20); e == nil {
			effectiveMode = modeFromConfig(b)
		}
	}
	dp := a.dataplaneEvidence(ctx, effectiveMode, o, owner)
	state := "stopped"
	overall := false
	if proc == "unknown" {
		state = "unknown"
	} else if proc == "running" {
		state = "not_ready"
		if apiReady && dp["ready"] == true {
			state = "ready"
			overall = true
		} else if dp["ready"] == nil {
			state = "running_unknown"
		}
	}
	if _, e := os.Stat(a.Path(".state", "lifecycle", "journal.json")); e == nil {
		state = "reconfiguring"
		overall = false
	}
	if _, e := os.Stat(a.Path(".state", "lifecycle", "stop-resources.json")); e == nil {
		state = "stop_pending"
		overall = false
	}
	intent, ie := a.ReadServiceIntent()
	var desired any = intent
	if ie != nil {
		desired = nil
	}
	return M{"schema": 1, "process": M{"state": proc, "running": running, "ownership": owner}, "api": M{"ready": apiReady}, "readiness": M{"dataplane": dp, "overall": overall}, "lifecycle": state, "state": state, "configured": M{"enabled": desired, "transparent": mode}, "effective": M{"running": running}}, nil
}
func (a *App) dataplaneEvidence(ctx context.Context, mode string, o *Owner, owner string) M {
	m := M{"mode": mode, "ready": false, "local_ready": false, "shared_ready": false, "shared_tc": "not_applicable", "evidence": "not_running"}
	if owner != "active" {
		if owner == "unknown" {
			m["ready"] = nil
			m["local_ready"] = nil
		}
		return m
	}
	if mode == "tun" {
		return a.observeTUN(o)
	}
	return a.observeEBPF(ctx, o)
}
func (a *App) findTool(name string) string {
	for _, p := range []string{a.Path("bin", name), "/system/bin/" + name, "/system/xbin/" + name, "/usr/sbin/" + name, "/usr/bin/" + name, "/sbin/" + name, "/bin/" + name} {
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return p
		}
	}
	return a.Path("bin", name)
}
func (a *App) startCore(ctx context.Context, gen string) error {
	if _, e := os.Stat(a.Path(".state", "lifecycle", "stop-resources.json")); e == nil {
		if e = a.stopCoreWithEvidence(ctx); e != nil {
			return e
		}
	}
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		return E("config.unavailable", "Active configuration cannot be read.")
	}
	if e = a.CheckConfig(ctx, b); e != nil {
		return e
	}
	fp, e := a.configFingerprint(b)
	if e != nil {
		return e
	}
	private, e := a.CoreConfigWithSecrets(b)
	if e != nil {
		return e
	}
	runtimePath := a.Path(".state", "private", "core-runtime.json")
	if e = AtomicWrite(runtimePath, private, 0600); e != nil {
		return e
	}
	if _, e = a.spawnOwned("core", a.corePath(), []string{"run", "-c", runtimePath}, gen, fp); e != nil {
		return e
	}
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) {
		r, e := a.IsRunning(ctx)
		if e != nil || !r {
			return E("service.start_failed", "The managed core exited during startup.")
		}
		_, e = a.API(ctx, "GET", "/version", nil)
		if e == nil {
			mode := modeFromConfig(b)
			o, owner, _ := observeOwner(a.Path(".state", "owners", "core.json"))
			d := a.dataplaneEvidence(ctx, mode, o, owner)
			if d["ready"] == true {
				resources, re := coreResources(o)
				if re != nil {
					return E("service.resource_observation_failed", "Cannot persist core resource ownership.")
				}
				if re = WriteJSON(a.Path(".state", "lifecycle", "core-resources.json"), resources); re != nil {
					return re
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return E("service.start_timeout", "Startup exceeded its deadline.")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return E("service.not_ready", "Core/API or dataplane readiness was not proved.")
}
func (a *App) stopCore(ctx context.Context) error {
	return a.stopCoreWithEvidence(ctx)
}

type lifecycleJournal struct {
	Generation    string `json:"generation"`
	Old           []byte `json:"old"`
	CandidateHash string `json:"candidate_hash"`
	Running       bool   `json:"running"`
	Phase         string `json:"phase"`
}

func (a *App) ActivateConfig(ctx context.Context, data []byte, generation string, wasRunning bool) error {
	if e := a.CheckConfig(ctx, data); e != nil {
		return e
	}
	old, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	fp, e := a.configFingerprint(data)
	if e != nil {
		return e
	}
	if old != nil {
		of, oe := a.configFingerprint(old)
		if oe == nil && of == fp {
			if !wasRunning {
				return a.commitMaterialization()
			}
			o, s, _ := observeOwner(a.Path(".state", "owners", "core.json"))
			if s == "active" && o.Fingerprint == fp {
				dp := a.dataplaneEvidence(ctx, modeFromConfig(data), o, s)
				if _, ae := a.API(ctx, "GET", "/version", nil); ae == nil && dp["ready"] == true {
					return a.commitMaterialization()
				}
			}
		}
		if a.CheckConfig(ctx, old) != nil {
			old, e = ReadRegular(a.Path(".state", "lifecycle", "last-known-good.json"), 4<<20)
			if e != nil || a.CheckConfig(ctx, old) != nil {
				return E("config.recovery_unavailable", "No independently validated recovery configuration exists.")
			}
		}
	}
	j := lifecycleJournal{generation, old, digest(data), wasRunning, "prepared"}
	jp := a.Path(".state", "lifecycle", "journal.json")
	if e = WriteJSON(jp, j); e != nil {
		return e
	}
	if old != nil {
		if e = AtomicWrite(a.Path(".state", "lifecycle", "last-known-good.json"), old, 0600); e != nil {
			return e
		}
	}
	if wasRunning {
		if e = a.stopCore(ctx); e != nil {
			return e
		}
	}
	j.Phase = "stopped"
	if e = WriteJSON(jp, j); e != nil {
		return e
	}
	if e = AtomicWrite(a.ConfigPath(), data, 0600); e == nil {
		j.Phase = "replaced"
		e = WriteJSON(jp, j)
	}
	if e == nil && wasRunning {
		e = a.startCore(ctx, generation)
	}
	if e != nil {
		a.ClearMaterialization()
		current, ce := ReadRegular(a.ConfigPath(), 4<<20)
		if ce == nil && digest(current) != j.CandidateHash && digest(current) != digest(old) {
			return E("config.rollback_conflict", "Configuration changed outside this transaction; recovery remains pending.")
		}
		_ = a.stopCore(ctx)
		if old != nil {
			if re := AtomicWrite(a.ConfigPath(), old, 0600); re != nil {
				return E("config.recovery_pending", "Recovery write failed.")
			}
			if wasRunning {
				if re := a.startCore(ctx, "recovery-"+generation); re != nil {
					return E("config.recovery_pending", "Recovery startup failed.")
				}
			}
		}
		if re := os.Remove(jp); re != nil {
			return E("config.recovery_pending", "Recovery journal could not be cleared.")
		}
		return e
	}
	if e = a.commitMaterialization(); e != nil {
		return E("config.recovery_pending", "Checkpoint commit failed.")
	}
	if e = AtomicWrite(a.Path(".state", "lifecycle", "last-known-good.json"), data, 0600); e != nil {
		return e
	}
	if e = os.Remove(jp); e != nil {
		return E("config.recovery_pending", "Committed configuration has pending recovery bookkeeping.")
	}
	return nil
}
func (a *App) recoverLifecycle(ctx context.Context) error {
	p := a.Path(".state", "lifecycle", "journal.json")
	var j lifecycleJournal
	e := ReadJSON(p, 8<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return E("config.recovery_pending", "Cannot read recovery journal.")
	}
	if len(j.Old) == 0 || a.CheckConfig(ctx, j.Old) != nil {
		return E("config.recovery_pending", "Recovery baseline is invalid.")
	}
	b, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e == nil && digest(b) != j.CandidateHash && digest(b) != digest(j.Old) {
		return E("config.rollback_conflict", "Recovery cannot overwrite externally changed configuration.")
	}
	if e = a.stopCore(ctx); e != nil {
		return e
	}
	if e = AtomicWrite(a.ConfigPath(), j.Old, 0600); e != nil {
		return e
	}
	if j.Running {
		if e = a.startCore(ctx, "recovery-"+j.Generation); e != nil {
			return e
		}
	}
	return os.Remove(p)
}
func (a *App) serviceAction(ctx context.Context, action string) (M, error) {
	var out M
	e := a.WithLifecycleLock(ctx, 10*time.Second, func() error {
		if _, e := os.Stat(a.Path(".state", "lifecycle", "stop-resources.json")); e == nil {
			if e = a.stopCore(ctx); e != nil {
				return e
			}
		}
		if e := a.recoverBackup(ctx); e != nil {
			return e
		}
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		if e := a.recoverLifecycle(ctx); e != nil {
			return e
		}
		running, e := a.IsRunning(ctx)
		if e != nil {
			return e
		}
		switch action {
		case "toggle":
			if running {
				action = "stop"
			} else {
				action = "start"
			}
		case "ensure":
			intent, e := a.ReadServiceIntent()
			if e != nil {
				return e
			}
			if !intent {
				return nil
			}
		}
		if action == "stop" || action == "restart" {
			if action == "stop" {
				if e = a.setIntent(false); e != nil {
					return e
				}
			}
			if e = a.stopCore(ctx); e != nil {
				return e
			}
			running = false
		}
		if action == "start" || action == "ensure" || action == "restart" {
			if _, e = os.Stat(a.Path("disable")); e == nil {
				return E("service.disabled", "The module is disabled.")
			}
			if e = a.EnsureDefaultConfig(ctx); e != nil {
				return e
			}
			if e = a.setIntent(true); e != nil {
				return e
			}
			if !running {
				if e = a.startCore(ctx, token()); e != nil {
					a.stopCore(ctx)
					return e
				}
			} else {
				status, se := a.ServiceStatus(ctx)
				if se != nil {
					return se
				}
				ready, _ := status["readiness"].(map[string]any)
				if ready["overall"] != true {
					return E("service.not_ready", "The owned core is running but readiness is not proved.")
				}
			}
		}
		out, e = a.ServiceStatus(ctx)
		return e
	})
	pe := a.Publish(ctx)
	if e != nil {
		return nil, e
	}
	if pe != nil {
		return nil, pe
	}
	if out == nil {
		out, _ = a.ServiceStatus(ctx)
	}
	return out, nil
}
func (a *App) ReplaySelectors(ctx context.Context) error {
	var selections map[string]string
	e := ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &selections)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	ps, e := a.API(ctx, "GET", "/proxies", nil)
	if e != nil {
		return e
	}
	proxies, _ := ps["proxies"].(map[string]any)
	for group, node := range selections {
		g, _ := proxies[group].(map[string]any)
		valid := false
		if all, ok := g["all"].([]any); ok {
			for _, n := range all {
				if n == node {
					valid = true
				}
			}
		}
		if valid {
			if _, e = a.API(ctx, "PUT", "/proxies/"+url.PathEscape(group), M{"name": node}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *App) selectNode(ctx context.Context, group, node string) (M, error) {
	if len(group) > 256 || len(node) > 256 || group == "" || node == "" {
		return nil, E("node.invalid", "Invalid node or group name.")
	}
	var out M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		ps, e := a.API(ctx, "GET", "/proxies", nil)
		if e != nil {
			return e
		}
		p, _ := ps["proxies"].(map[string]any)
		g, _ := p[group].(map[string]any)
		all, _ := g["all"].([]any)
		found := false
		for _, n := range all {
			if n == node {
				found = true
			}
		}
		if !found {
			return E("node.missing", "The requested group member is unavailable.")
		}
		out, e = a.API(ctx, "PUT", "/proxies/"+url.PathEscape(group), M{"name": node})
		if e != nil {
			return e
		}
		selections := map[string]string{}
		if e = ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &selections); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		selections[group] = node
		return WriteJSON(a.Path(".config", "magicnet", "selector-selections.json"), selections)
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return out, e
}

func modeFromConfig(b []byte) string {
	var c M
	if DecodeJSON(b, &c) != nil {
		return "unknown"
	}
	in, _ := c["inbounds"].([]any)
	for _, x := range in {
		m, _ := x.(map[string]any)
		if m["type"] == "ebpf" {
			return "ebpf"
		}
		if m["type"] == "tun" {
			return "tun"
		}
	}
	return "unknown"
}
func (a *App) ClearMaterialization() { a.RuntimeCheckpoint = nil; a.PlatformOwned = nil }
func (a *App) commitMaterialization() error {
	if e := a.CommitRuntimeCheckpoint(); e != nil {
		return e
	}
	if a.PlatformOwned != nil {
		if e := WriteJSON(a.Path(".state", "platform-owned.json"), a.PlatformOwned); e != nil {
			return e
		}
	}
	a.ClearMaterialization()
	return nil
}
