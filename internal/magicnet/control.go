package magicnet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Envelope struct {
	Schema  int    `json:"schema"`
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Data    M      `json:"data,omitempty"`
	Error   *Fault `json:"error,omitempty"`
}

var machineCommands = []string{"app.inspect", "service.status", "core.status", "supervisor.status", "transparent.status", "dns.status", "network.status", "network.preflight", "network-access.status", "network-access.inspect", "network-access.check", "network-access.repair", "network-access.reapply", "network-access.rollback", "sub.status", "sub.inspect", "wifi.status", "wifi.inspect", "hotspot.status", "machine.capabilities", "tailscale.status", "override.status", "override.inspect", "override.preview", "override.set", "override.reset", "override.apply", "module-update.status", "module-update.check", "module-update.install"}

func capabilities() M {
	return M{"commands": machineCommands, "features": []string{"versioned_envelope", "structured_errors", "redacted_status", "configured_effective_split", "privacy_safe_network_identifiers", "readiness_signals", "transparent_plane_readiness", "dns_capture_preflight", "additive_routing_overlay", "subscription_batch_v1", "backup_payload_v1"}, "json_flag_positions": []string{"prefix", "suffix"}, "machine_schema": 1, "module_update_install": "detached-worker-staged-reboot-required", "module_update_source": "official-stable-github-release", "mutation_commands": []string{"override.preview", "override.set", "override.reset", "override.apply", "network-access.repair", "network-access.reapply", "network-access.rollback", "module-update.check", "module-update.install"}, "network_access_confirmation": "candidate-and-confirm-flag", "override_input": "private-payload-file", "override_patch_format": "json-merge-patch", "private_commands": []string{"sub.inspect", "wifi.inspect", "override.inspect", "network-access.inspect", "app.inspect"}, "read_only": false, "routing_overlay_key": "$magicnet_routing", "routing_overlay_schema": 1, "version": Version}
}
func commandName(args []string) string {
	if len(args) == 0 {
		return "unknown"
	}
	if args[0] == "capabilities" {
		return "machine.capabilities"
	}
	if len(args) == 1 {
		return args[0]
	}
	action := strings.TrimSuffix(args[1], "-file")
	return args[0] + "." + action
}
func parseArgs(args []string) ([]string, bool, error) {
	jsonCount := 0
	out := []string{}
	for _, a := range args {
		if a == "--json" {
			jsonCount++
		} else {
			out = append(out, a)
		}
	}
	if jsonCount > 1 {
		return out, true, E("machine.invalid_arguments", "Exactly one --json flag is allowed.")
	}
	return out, jsonCount == 1, nil
}
func (a *App) Execute(ctx context.Context, args []string) (M, error, bool, string) {
	op := &App{Root: a.Root, Platform: a.Platform}
	return op.execute(ctx, args)
}
func (a *App) execute(ctx context.Context, args []string) (M, error, bool, string) {
	clean, machine, e := parseArgs(args)
	command := commandName(clean)
	if e != nil {
		return nil, e, machine, command
	}
	if machine {
		if !stringIn(command, machineCommands...) {
			return nil, E("machine.command_unsupported", "This command has no machine interface."), true, command
		}
		if strings.HasSuffix(command, ".status") || strings.HasSuffix(command, ".inspect") || command == "network.preflight" {
			if len(clean) != 2 {
				return nil, E("machine.invalid_arguments", "Unexpected trailing arguments."), true, command
			}
		}
		if command == "machine.capabilities" && len(clean) != 1 && !(len(clean) == 2 && clean[0] == "machine") {
			return nil, E("machine.invalid_arguments", "Unexpected trailing arguments."), true, command
		}
	}
	if command == "machine.capabilities" {
		return capabilities(), nil, machine, command
	}
	if len(clean) == 0 || stringIn(clean[0], "help", "--help", "-h") {
		return M{"text": HelpText}, nil, machine, "help"
	}
	if len(clean) == 1 && clean[0] == "version" {
		return M{"version": Version, "version_code": VersionCode, "channel": ReleaseChannel, "commit": Commit, "recipe": "magicnet@" + RecipeVersion, "recipe_version": RecipeVersion, "input_sha256": "502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a"}, nil, machine, "version"
	}
	if m, e, h := a.HandleRuntime(ctx, clean, machine); h {
		return m, e, machine, command
	}
	if m, e, h := a.handlePlatform(ctx, clean, machine); h {
		return m, e, machine, command
	}
	m, e := a.dispatch(ctx, clean, machine)
	return m, e, machine, command
}
func (a *App) dispatch(ctx context.Context, args []string, machine bool) (M, error) {
	f := args[0]
	act := ""
	if len(args) > 1 {
		act = args[1]
	}
	switch f {
	case "service":
		if act == "status" {
			return a.ServiceStatus(ctx)
		}
		if act == "logs" {
			name := "sing-box"
			n := 100
			if len(args) > 2 {
				name = args[2]
			}
			if len(args) > 3 {
				n, _ = strconv.Atoi(args[3])
			}
			return a.readLog(name, n, false)
		}
		if stringIn(act, "start", "ensure", "stop", "restart", "toggle") {
			if len(args) > 3 || len(args) == 3 && !stringIn(args[2], "current", "sing-box") {
				return nil, E("command.arguments", "Invalid service target.")
			}
			return a.serviceAction(ctx, act)
		}
	case "supervisor":
		target := "all"
		if len(args) > 2 {
			target = args[2]
		}
		return a.supervisorControl(ctx, act, target)
	case "state":
		if act == "reconcile" && len(args) == 2 {
			e := a.Publish(ctx)
			return M{"published": e == nil}, e
		}
	case "core":
		if stringIn(act, "status", "selected") {
			r, e := a.IsRunning(ctx)
			return M{"selected": "sing-box", "running": r, "version": Version}, e
		}
		if act == "select" && len(args) == 3 && args[2] == "sing-box" {
			return M{"selected": "sing-box"}, nil
		}
	case "api":
		switch act {
		case "endpoint":
			ep, _, e := a.apiEndpoint()
			return M{"text": ep + "\n"}, e
		case "ui":
			return M{"text": "http://127.0.0.1:9090/ui/\n"}, nil
		case "groups", "proxies":
			return a.API(ctx, "GET", "/proxies", nil)
		case "conns", "stats":
			return a.API(ctx, "GET", "/connections", nil)
		case "select":
			if len(args) == 4 {
				return a.selectNode(ctx, args[2], args[3])
			}
		case "close":
			if len(args) == 3 {
				return a.API(ctx, "DELETE", "/connections/"+url.PathEscape(args[2]), nil)
			}
		case "close-all":
			return a.API(ctx, "DELETE", "/connections", nil)
		case "close-top", "close-matching":
			return a.closeConnections(ctx, args[1:])
		}
	case "node":
		switch act {
		case "list":
			return a.API(ctx, "GET", "/proxies", nil)
		case "current":
			return a.API(ctx, "GET", "/proxies/proxy", nil)
		case "use":
			if len(args) == 3 {
				return a.selectNode(ctx, "proxy", args[2])
			}
		case "test":
			if len(args) == 3 {
				return a.API(ctx, "GET", "/proxies/"+url.PathEscape(args[2])+"/delay?timeout=5000&url="+url.QueryEscape("https://www.gstatic.com/generate_204"), nil)
			}
		case "test-all":
			return a.testAllNodes(ctx, args[2:])
		}
	case "mcp":
		return a.mcpControl(ctx, args[1:])
	case "webui":
		return a.webuiControl(ctx, args[1:])
	case "module-update":
		return a.moduleUpdate(ctx, args[1:])
	case "backup":
		return a.backup(ctx, args[1:])
	case "support":
		if act == "bundle" {
			return a.supportBundle(ctx)
		}
	case "health", "diagnose":
		if len(args) != 1 {
			return nil, E("command.arguments", "No trailing arguments are accepted.")
		}
		return a.health(ctx)
	case "topology":
		return a.topology(ctx)
	case "sysroute":
		return a.sysroute(ctx, args[1:])
	case "pingtest":
		return a.pingTest(ctx)
	case "speedtest":
		return a.speedTest(ctx)
	case "ecapture":
		return a.ecapture(ctx, args[1:])
	case "repair":
		e := a.WithLifecycleLock(ctx, 10*time.Second, func() error {
			if e := a.recoverBackup(ctx); e != nil {
				return e
			}
			if e := a.RecoverRuntime(ctx); e != nil {
				return e
			}
			return a.recoverLifecycle(ctx)
		})
		if e != nil {
			return nil, e
		}
		return a.platformApply(ctx)
	case "menu":
		return a.menu(ctx)
	}
	return nil, E("command.unknown", "Unknown command or invalid arguments.")
}
func Main(args []string) int {
	a, e := NewApp()
	if e != nil {
		fmt.Fprintln(os.Stderr, PublicError(e).Error())
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	if len(args) > 0 && strings.HasPrefix(args[0], "__") {
		switch args[0] {
		case "__supervisor":
			if len(args) == 2 {
				e = a.runSupervisor(ctx, args[1])
			}
		case "__mcp":
			e = a.serveMCP(ctx)
		case "__http":
			bind := "127.0.0.1:17890"
			if len(args) == 2 {
				bind = args[1]
			}
			e = a.serveHTTP(ctx, bind)
		case "__update-worker":
			e = a.updateWorker(ctx)
		case "__install":
			e = a.installModule(ctx)
		case "__uninstall":
			_, e = a.serviceAction(ctx, "stop")
			if e == nil {
				_, e = a.supervisorControl(ctx, "stop", "all")
			}
			if e == nil {
				_, e = a.mcpControl(ctx, []string{"stop"})
			}
		default:
			e = E("command.unknown", "Unknown internal operation.")
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, PublicError(e).Error())
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "serve" {
		e = a.serveHTTP(ctx, "127.0.0.1:17890")
		if e != nil {
			fmt.Fprintln(os.Stderr, PublicError(e).Error())
			return 1
		}
		return 0
	}
	return a.RunCLI(ctx, args, os.Stdout, os.Stderr)
}
func (a *App) RunCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	m, e, machine, command := a.Execute(ctx, args)
	if machine {
		env := Envelope{Schema: 1, OK: e == nil, Command: command, Data: m}
		if e != nil {
			env.Data = nil
			env.Error = PublicError(e)
		}
		json.NewEncoder(stdout).Encode(env)
	} else if e != nil {
		if m != nil && m["accepted"] == true {
			json.NewEncoder(stdout).Encode(m)
		}
		fmt.Fprintln(stderr, PublicError(e).Error())
	} else if t, ok := m["text"].(string); ok {
		fmt.Fprint(stdout, t)
	} else {
		b, _ := json.MarshalIndent(m, "", "  ")
		fmt.Fprintln(stdout, string(b))
	}
	if e != nil {
		return 1
	}
	if warning := asString(m["warning_code"]); warning != "" && warning != "none" {
		fmt.Fprintln(stderr, warning+": committed configuration requires follow-up observation.")
	}
	return 0
}

const HelpText = `MagicNet — Android root network control
Usage: cli [--json] COMMAND ACTION [ARGUMENTS]

Run: service status|start|ensure|stop|restart; transparent status|set tun|set ebpf|apply
Observe: health; topology; network status|preflight; dns status|test; support bundle
Sources: sub status|inspect|set|set-file|apply-file|update|update-all|clear|list|get
         sub schedule status|set off|12|24|48|72; sub user-agent get|set|clear; sub filter list|set|clear
Route: app list|packages|mode|add|add-many|remove|apply; route list|add-domain|remove-domain|apply
       node list|current|use|test|test-all; mode rule|global|direct; chain; block; warp; tailscale
Network: wifi status|enable|disable|mode|interval|add-ssid|remove-ssid|add-bssid|remove-bssid|check
         hotspot status|enable|disable|reconcile; network set; dns set
Edit: config apply; config-editor get|validate|save|save-file|sync-template|repo
      --json override status|inspect|preview-file|set-file|reset-file|apply-file|apply
Recover: network-access status|inspect|check|repair|reapply|rollback; backup export|restore|restore-file
Tools: api; ecapture; pingtest; speedtest; sysroute; supervisor; mcp; webui; module-update; menu

--json fully owns dispatch. Unsupported machine mutations are rejected.
Private inspect, configuration, backup, node and connection data are sensitive.
No Android VPN slot is used. Only explicit tun or ebpf modes are supported.
`

var _ = time.Second
