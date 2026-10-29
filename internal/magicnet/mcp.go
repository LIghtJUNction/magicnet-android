package magicnet

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed mcp_catalog.json
var catalogJSON []byte

type MCPConfig struct {
	Enabled bool   `json:"enabled"`
	Bind    string `json:"bind"`
	Port    int    `json:"port"`
	Secret  string `json:"secret"`
}

func (a *App) mcpConfig() (MCPConfig, error) {
	c := MCPConfig{Bind: "127.0.0.1", Port: 9095}
	e := ReadJSON(a.Path(".config", "magicnet", "mcp.json"), 4096, &c)
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	return c, e
}
func (a *App) mcpStatus() (M, error) {
	c, e := a.mcpConfig()
	if e != nil {
		return nil, E("mcp.config_invalid", "Cannot read MCP configuration.")
	}
	_, s, _ := observeOwner(a.Path(".state", "owners", "mcp.json"))
	var running any = s == "active"
	if s == "unknown" {
		running = nil
	}
	return M{"enabled": c.Enabled, "running": running, "owner": s, "authenticated": true, "loopback_only": true, "port": c.Port}, nil
}
func (a *App) mcpControl(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return a.mcpStatus()
	}
	act := args[0]
	if act == "status" {
		return a.mcpStatus()
	}
	if act == "logs" {
		n := 100
		if len(args) > 1 {
			n, _ = strconv.Atoi(args[1])
		}
		return a.readLog("mcp", n, false)
	}
	c, e := a.mcpConfig()
	if e != nil {
		return nil, e
	}
	p := a.Path(".config", "magicnet", "mcp.json")
	if act == "secret" {
		if c.Secret == "" {
			return nil, E("mcp.secret_missing", "Enable MCP to generate a secret.")
		}
		return M{"text": c.Secret + "\n"}, nil
	}
	if act == "set" || act == "enable" {
		if len(args) > 3 {
			return nil, E("mcp.arguments", "Invalid MCP endpoint.")
		}
		if len(args) > 1 {
			c.Bind = args[1]
		}
		if len(args) > 2 {
			c.Port, e = strconv.Atoi(args[2])
		}
		if e != nil || !stringIn(c.Bind, "127.0.0.1", "::1") || c.Port < 1024 || c.Port > 65535 {
			return nil, E("mcp.bind_invalid", "MCP requires an unprivileged loopback port.")
		}
		if c.Secret == "" {
			c.Secret = token() + token()
		}
		if act == "enable" {
			c.Enabled = true
		}
		if e = WriteJSON(p, c); e != nil {
			return nil, e
		}
		if act == "set" {
			return a.mcpStatus()
		}
		act = "start"
	}
	if act == "rotate-secret" {
		c.Secret = token() + token()
		if e = WriteJSON(p, c); e != nil {
			return nil, e
		}
		act = "restart"
	}
	if act == "disable" {
		c.Enabled = false
		if e = WriteJSON(p, c); e != nil {
			return nil, e
		}
		act = "stop"
	}
	if !stringIn(act, "start", "stop", "restart") {
		return nil, E("mcp.arguments", "Unknown MCP action.")
	}
	e = a.withLock(ctx, "mcp", 2*time.Second, func() error {
		ownerPath := a.Path(".state", "owners", "mcp.json")
		if act == "stop" || act == "restart" {
			if e = stopOwner(ctx, ownerPath); e != nil {
				return e
			}
		}
		if act == "start" || act == "restart" {
			if !c.Enabled || c.Secret == "" {
				return E("mcp.disabled", "MCP is disabled.")
			}
			_, s, er := observeOwner(ownerPath)
			if er != nil || s == "unknown" {
				return E("mcp.ownership_unknown", "MCP process ownership is unknown.")
			}
			if s != "active" {
				exe, e := os.Executable()
				if e != nil {
					return e
				}
				_, e = a.spawnOwned("mcp", exe, []string{"__mcp"}, "", "")
				return e
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	a.Publish(ctx)
	return a.mcpStatus()
}
func checkSchema(s M, v any) error {
	fail := func() error { return E("mcp.invalid_arguments", "Arguments do not match the advertised schema.") }
	switch s["type"] {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return fail()
		}
		props, _ := s["properties"].(map[string]any)
		if rs, ok := s["required"].([]any); ok {
			for _, k := range rs {
				if _, ok = m[asString(k)]; !ok {
					return fail()
				}
			}
		}
		for k, x := range m {
			spec, ok := props[k].(map[string]any)
			if !ok {
				return fail()
			}
			if e := checkSchema(spec, x); e != nil {
				return e
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return fail()
		}
		if n, ok := s["maxItems"]; ok && len(a) > asInt(n) {
			return fail()
		}
		if n, ok := s["minItems"]; ok && len(a) < asInt(n) {
			return fail()
		}
		spec, _ := s["items"].(map[string]any)
		for _, x := range a {
			if e := checkSchema(spec, x); e != nil {
				return e
			}
		}
	case "string":
		x, ok := v.(string)
		if !ok || len(x) > 8<<20 {
			return fail()
		}
		if n, ok := s["maxLength"]; ok && len([]rune(x)) > asInt(n) {
			return fail()
		}
		if n, ok := s["minLength"]; ok && len([]rune(x)) < asInt(n) {
			return fail()
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return fail()
		}
		f, e := n.Float64()
		if e != nil || math.Trunc(f) != f || math.Abs(f) > 9007199254740991 {
			return fail()
		}
		if x, ok := s["maximum"]; ok && f > float64(asInt(x)) {
			return fail()
		}
		if x, ok := s["minimum"]; ok && f < float64(asInt(x)) {
			return fail()
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fail()
		}
	}
	if values, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range values {
			if fmt.Sprint(x) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			return fail()
		}
	}
	return nil
}
func genericAllowed(args []string) bool {
	clean, _, e := parseArgs(args)
	if e != nil || len(clean) == 0 {
		return false
	}
	for i, x := range clean {
		if i < 2 && strings.HasPrefix(x, "__") {
			return false
		}
	}
	f := clean[0]
	act := ""
	if len(clean) > 1 {
		act = clean[1]
	}
	switch f {
	case "diagnose", "serve", "module-update", "network-access":
		return false
	case "mcp":
		return !stringIn(act, "secret", "rotate-secret", "logs")
	case "sub":
		if stringIn(act, "", "inspect", "list", "get", "status", "file") {
			return false
		}
		if act == "user-agent" || act == "filter" {
			return len(clean) > 2 && !stringIn(clean[2], "get", "list")
		}
	case "wifi":
		return !stringIn(act, "", "inspect", "status", "list", "check", "watch")
	case "override":
		return act != "inspect"
	case "app":
		return act != "inspect"
	case "config-editor":
		return !stringIn(act, "", "get", "path", "repo")
	case "backup":
		return !stringIn(act, "", "export", "export-payload")
	case "service":
		return act != "logs"
	}
	return true
}
func (a *App) mcpTool(ctx context.Context, name string, v M) (M, error) {
	str := func(k, def string) string {
		if x, ok := v[k].(string); ok {
			return x
		}
		return def
	}
	num := func(k string, d int) string {
		if x, ok := v[k]; ok {
			return fmt.Sprint(asInt(x))
		}
		return strconv.Itoa(d)
	}
	truth := func(k string) bool { x, _ := v[k].(bool); return x }
	b64 := func(k string) string { return base64.StdEncoding.EncodeToString([]byte(str(k, ""))) }
	var args []string
	switch name {
	case "magicnet_cli":
		xs, _ := v["args"].([]any)
		for _, x := range xs {
			args = append(args, asString(x))
		}
		if !genericAllowed(args) {
			return nil, E("mcp.private_boundary", "Use the explicit named tool for this operation.")
		}
	case "magicnet_status":
		args = []string{"--json", "service", "status"}
	case "magicnet_capabilities":
		args = []string{"--json", "capabilities"}
	case "magicnet_service_control":
		args = []string{"service", str("action", "status")}
		if x := str("target", ""); x != "" {
			args = append(args, x)
		}
		if args[1] == "logs" {
			return a.readLog(str("target", "sing-box"), 100, true)
		}
	case "magicnet_core_select":
		args = []string{"core", "select", str("core", "")}
	case "magicnet_config_apply":
		args = []string{"config", "apply"}
	case "magicnet_config_get":
		args = []string{"config-editor", "get", str("target", "")}
	case "magicnet_config_validate":
		args = []string{"config-editor", "validate", str("target", "sing-box")}
	case "magicnet_config_sync_template":
		args = []string{"config-editor", "sync-template", str("target", "")}
	case "magicnet_config_save_base64":
		args = []string{"config-editor", "save", str("target", ""), str("content_base64", "")}
	case "magicnet_transparent_set":
		args = []string{"transparent", "set", str("mode", "")}
	case "magicnet_transparent_apply":
		args = []string{"transparent", "apply"}
	case "magicnet_health":
		args = []string{"health"}
	case "magicnet_pingtest":
		args = []string{"pingtest"}
	case "magicnet_speedtest":
		args = []string{"speedtest"}
	case "magicnet_topology":
		args = []string{"topology"}
	case "magicnet_sysroute_snapshot":
		args = []string{"sysroute", "snapshot"}
	case "magicnet_support_bundle":
		args = []string{"support", "bundle"}
	case "magicnet_block_list":
		args = []string{"block", "list"}
	case "magicnet_block_set_enabled":
		act := "disable"
		if truth("enabled") {
			act = "enable"
		}
		args = []string{"block", act}
	case "magicnet_block_set_community":
		act := "off"
		if truth("enabled") {
			act = "on"
		}
		args = []string{"block", "community", act}
	case "magicnet_block_update":
		args = []string{"block", "update"}
	case "magicnet_block_add_domain":
		args = []string{"block", "add-domain", str("suffix", "")}
	case "magicnet_block_remove_domain":
		args = []string{"block", "remove-domain", str("suffix", "")}
	case "magicnet_block_allow_rule":
		args = []string{"block", "allow-rule", str("rule", "")}
	case "magicnet_block_unallow_rule":
		args = []string{"block", "unallow-rule", str("rule", "")}
	case "magicnet_block_diff":
		args = []string{"block", "diff"}
	case "magicnet_block_apply":
		args = []string{"block", "apply"}
	case "magicnet_subscription_list":
		args = []string{"--json", "sub", "inspect"}
	case "magicnet_subscription_set":
		args = []string{"sub", "set", str("target", "sing-box"), str("url", "")}
	case "magicnet_subscription_set_singbox_lines":
		args = []string{"sub", "set-file", "sing-box", b64("content")}
	case "magicnet_subscription_update":
		args = []string{"sub", "update", str("target", "sing-box")}
	case "magicnet_subscription_update_all":
		args = []string{"sub", "update-all"}
	case "magicnet_subscription_schedule":
		args = []string{"sub", "schedule", "set", str("hours", "")}
	case "magicnet_backup_export":
		args = []string{"backup", "export", str("password", "")}
	case "magicnet_backup_restore_base64":
		args = []string{"backup", "restore", str("password", "-"), str("content_base64", "")}
	case "magicnet_ecapture_status":
		args = []string{"ecapture", "status"}
	case "magicnet_ecapture_help":
		args = []string{"ecapture", "help", str("command", "tls")}
	case "magicnet_ecapture_tls", "magicnet_ecapture_gotls":
		args = []string{"ecapture", strings.TrimPrefix(name, "magicnet_ecapture_"), num("duration_seconds", 10), str("pid", "all"), str("uid", "all")}
	case "magicnet_ecapture_pcap":
		args = []string{"ecapture", "pcap", num("duration_seconds", 10), str("ifname", "")}
		if x := str("filter", ""); x != "" {
			args = append(args, strings.Fields(x)...)
		}
	case "magicnet_app_list":
		args = []string{"app", "list"}
	case "magicnet_app_inspect":
		args = []string{"--json", "app", "inspect"}
	case "magicnet_app_packages":
		args = []string{"app", "packages", str("query", "")}
	case "magicnet_app_mode":
		args = []string{"app", "mode", str("mode", "")}
	case "magicnet_app_add", "magicnet_app_remove":
		args = []string{"app", strings.TrimPrefix(name, "magicnet_app_"), str("package", ""), str("target", "")}
	case "magicnet_app_add_many":
		args = []string{"app", "add-many", str("target", "")}
		xs, _ := v["packages"].([]any)
		for _, x := range xs {
			args = append(args, asString(x))
		}
	case "magicnet_app_apply":
		args = []string{"app", "apply"}
	case "magicnet_mcp_control":
		if str("action", "status") == "logs" {
			return a.readLog("mcp", 100, true)
		}
		args = []string{"mcp", str("action", "status")}
	case "magicnet_api":
		args = []string{"api", str("action", "groups")}
	case "magicnet_webui_status":
		args = []string{"webui", "status"}
	case "magicnet_webui_verify":
		args = []string{"webui", "verify"}
	case "magicnet_webui_install_local":
		args = []string{"webui", "install-local", str("url", ""), str("sha256", ""), str("name", "")}
	case "magicnet_log_list":
		return a.logList()
	case "magicnet_log_read":
		return a.readLog(str("source", "sing-box"), asInt(v["lines"]), true)
	case "magicnet_debug_snapshot":
		return a.debugSnapshot(ctx)
	case "magicnet_file_list", "magicnet_file_read":
		return a.publicFile(str("path", "."), name == "magicnet_file_read")
	case "magicnet_module_update_status":
		args = []string{"--json", "module-update", "status"}
	case "magicnet_transparent_status":
		args = []string{"--json", "transparent", "status"}
	case "magicnet_dns_status":
		args = []string{"--json", "dns", "status"}
	case "magicnet_network_status":
		args = []string{"--json", "network", "status"}
	case "magicnet_network_preflight":
		args = []string{"--json", "network", "preflight"}
	case "magicnet_subscription_status":
		args = []string{"--json", "sub", "status"}
	case "magicnet_wifi_status":
		args = []string{"--json", "wifi", "status"}
	case "magicnet_hotspot_status":
		args = []string{"--json", "hotspot", "status"}
	case "magicnet_network_access_status":
		args = []string{"--json", "network-access", "status"}
	case "magicnet_network_access_inspect":
		args = []string{"--json", "network-access", "inspect"}
	case "magicnet_override_status", "magicnet_override_inspect":
		args = []string{"--json", "override", strings.TrimPrefix(name, "magicnet_override_")}
	case "magicnet_override_preview", "magicnet_override_set", "magicnet_override_reset", "magicnet_override_apply":
		op := strings.TrimPrefix(name, "magicnet_override_")
		p, e := a.payloadPath("tmp", "mcp-"+token()+".json")
		if e != nil {
			return nil, e
		}
		if e = WriteJSON(p, v); e != nil {
			return nil, e
		}
		defer os.Remove(p)
		args = []string{"--json", "override", op + "-file", p}
	case "magicnet_network_set":
		args = []string{"network", "set", str("ipv6_mode", ""), num("mtu", 1400), str("udp_timeout", "")}
	case "magicnet_dns_set":
		args = []string{"dns", "set", str("profile", "")}
	case "magicnet_dns_test":
		args = []string{"dns", "test", str("domain", "")}
	case "magicnet_node_list":
		args = []string{"node", "list"}
	case "magicnet_node_current":
		args = []string{"node", "current"}
	case "magicnet_node_test":
		args = []string{"node", "test", str("name", "")}
	case "magicnet_selector_select":
		args = []string{"api", "select", str("group", ""), str("node", "")}
	case "magicnet_connection_close":
		args = []string{"api", "close", str("id", "")}
	case "magicnet_route_domain":
		args = []string{"route", str("action", ""), str("target", ""), str("domain", "")}
	case "magicnet_supervisor_control":
		args = []string{"supervisor", str("action", "status"), str("target", "all")}
	}
	_ = b64
	if len(args) == 0 {
		return nil, E("mcp.tool_unknown", "Unknown tool.")
	}
	m, e, _, command := a.Execute(ctx, args)
	if e != nil {
		return M{"schema": 1, "ok": false, "command": command, "error": PublicError(e), "receipt": m}, e
	}
	return M{"schema": 1, "ok": true, "command": command, "data": m}, nil
}
func (a *App) publicFile(path string, read bool) (M, error) {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, E("mcp.file_denied", "File is outside the public module view.")
	}
	if strings.HasPrefix(clean, ".") && clean != "." && !strings.HasPrefix(clean, ".state/machines/") && clean != ".state/machines" {
		return nil, E("mcp.file_denied", "Private state and configuration are excluded.")
	}
	for _, part := range strings.Split(strings.ToLower(clean), "/") {
		if strings.Contains(part, "secret") || strings.Contains(part, "backup") || strings.Contains(part, "payload") || strings.Contains(part, "identity") {
			return nil, E("mcp.file_denied", "Private aliases are excluded.")
		}
	}
	p := a.Path(clean)
	if e := safeAncestors(p); e != nil {
		return nil, e
	}
	st, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, E("mcp.file_denied", "Symbolic links are excluded.")
	}
	if read {
		b, e := ReadRegular(p, 256<<10)
		if e != nil {
			return nil, e
		}
		return M{"content": string(b)}, nil
	}
	entries, e := os.ReadDir(p)
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, f := range entries {
		if strings.HasPrefix(f.Name(), ".") || f.Type()&os.ModeSymlink != 0 {
			continue
		}
		names = append(names, f.Name())
		if len(names) > 4096 {
			return nil, E("mcp.file_limit", "Too many entries.")
		}
	}
	return M{"entries": names}, nil
}
func (a *App) serveMCP(ctx context.Context) error {
	c, e := a.mcpConfig()
	if e != nil || !c.Enabled || c.Secret == "" {
		return E("mcp.disabled", "MCP is disabled.")
	}
	if !stringIn(c.Bind, "127.0.0.1", "::1") {
		return E("mcp.bind_invalid", "Only loopback is permitted.")
	}
	catalog := []M{}
	if e = DecodeJSON(catalogJSON, &catalog); e != nil {
		return e
	}
	schemas := map[string]M{}
	for _, t := range catalog {
		schemas[asString(t["name"])] = t
	}
	resourceDomains := map[string]string{"service": "service", "transparent": "transparent", "dns": "dns", "network": "network", "subscription": "subscription", "wifi": "wifi", "overrides": "overrides"}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.Secret)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
		if e != nil || len(b) > 4<<20 {
			http.Error(w, "input_limit", 413)
			return
		}
		var q M
		if DecodeJSON(b, &q) != nil {
			http.Error(w, "invalid_json", 400)
			return
		}
		id, hasID := q["id"]
		respond := func(result any, code int, msg string) {
			w.Header().Set("Content-Type", "application/json")
			v := M{"jsonrpc": "2.0", "id": id}
			if code != 0 {
				v["error"] = M{"code": code, "message": msg}
			} else {
				v["result"] = result
			}
			json.NewEncoder(w).Encode(v)
		}
		for k := range q {
			if !stringIn(k, "jsonrpc", "id", "method", "params") {
				respond(nil, -32600, "invalid_request")
				return
			}
		}
		if q["jsonrpc"] != "2.0" {
			respond(nil, -32600, "invalid_request")
			return
		}
		method := asString(q["method"])
		if !hasID {
			w.WriteHeader(202)
			return
		}
		params, _ := q["params"].(map[string]any)
		switch method {
		case "initialize":
			version := asString(params["protocolVersion"])
			if !stringIn(version, "2025-03-26", "2025-06-18") {
				respond(nil, -32602, "unsupported_protocol")
				return
			}
			respond(M{"protocolVersion": version, "capabilities": M{"tools": M{}, "resources": M{}, "prompts": M{}}, "serverInfo": M{"name": "MagicNet", "version": Version}}, 0, "")
		case "ping":
			respond(M{}, 0, "")
		case "tools/list":
			respond(M{"tools": catalog}, 0, "")
		case "tools/call":
			if len(params) != 2 {
				respond(nil, -32602, "invalid_arguments")
				return
			}
			name := asString(params["name"])
			schema, ok := schemas[name]
			if !ok {
				respond(nil, -32602, "unknown_tool")
				return
			}
			v, ok := params["arguments"].(map[string]any)
			if !ok {
				respond(nil, -32602, "invalid_arguments")
				return
			}
			if e = checkSchema(schema["inputSchema"].(map[string]any), v); e != nil {
				respond(nil, -32602, "invalid_arguments")
				return
			}
			m, e := a.mcpTool(ctx, name, v)
			if e != nil && m == nil {
				fault := PublicError(e)
				m = M{"schema": 1, "ok": false, "command": name, "error": fault}
			}
			if m != nil && m["schema"] == nil {
				if e == nil {
					m = M{"schema": 1, "ok": true, "command": name, "data": m}
				} else {
					m = M{"schema": 1, "ok": false, "command": name, "error": PublicError(e), "receipt": m}
				}
			}
			tb, _ := json.Marshal(m)
			respond(M{"structuredContent": m, "content": []any{M{"type": "text", "text": string(tb)}}, "isError": e != nil}, 0, "")
		case "resources/list":
			rs := []any{}
			for _, n := range []string{"service", "transparent", "dns", "network", "subscription", "wifi", "overrides"} {
				rs = append(rs, M{"uri": "magicnet://status/" + n, "name": n, "mimeType": "application/json"})
			}
			respond(M{"resources": rs}, 0, "")
		case "resources/read":
			uri := asString(params["uri"])
			d, ok := resourceDomains[strings.TrimPrefix(uri, "magicnet://status/")]
			if !ok || !strings.HasPrefix(uri, "magicnet://status/") {
				respond(nil, -32602, "resource_unknown")
				return
			}
			var m M
			if d == "network" {
				m, e, _ = a.HandleRuntime(ctx, []string{"network", "status"}, true)
			} else {
				m, e = a.publicDomain(ctx, d)
			}
			if e != nil {
				respond(nil, -32603, ErrorCode(e))
				return
			}
			command := d + ".status"
			if d == "overrides" {
				command = "override.status"
			}
			if d == "subscription" {
				command = "sub.status"
			}
			tb, _ := json.Marshal(Envelope{Schema: 1, OK: true, Command: command, Data: m})
			respond(M{"contents": []any{M{"uri": uri, "mimeType": "application/json", "text": string(tb)}}}, 0, "")
		case "prompts/list":
			respond(M{"prompts": []any{M{"name": "diagnose-network", "description": "Read public status before proposing a change."}, M{"name": "edit-config-overrides", "description": "Preview private edits, review revision, then apply explicitly."}}}, 0, "")
		case "prompts/get":
			name := asString(params["name"])
			if !stringIn(name, "diagnose-network", "edit-config-overrides") {
				respond(nil, -32602, "prompt_unknown")
				return
			}
			text := "Inspect separate process, API and dataplane evidence. Keep unknown observations unknown. Ask before mutating device intent."
			if name == "edit-config-overrides" {
				text = "Explicitly inspect private override intent. Preview and review expected_revision. Save does not activate. Preserve private values and user drafts on conflict."
			}
			respond(M{"messages": []any{M{"role": "user", "content": M{"type": "text", "text": text}}}}, 0, "")
		default:
			respond(nil, -32601, "method_not_found")
		}
	})
	srv := &http.Server{Addr: net.JoinHostPort(c.Bind, strconv.Itoa(c.Port)), Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() { <-ctx.Done(); srv.Close() }()
	e = srv.ListenAndServe()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
