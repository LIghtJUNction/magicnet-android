#!/usr/bin/env python3
"""Compare two CLI executables against the same isolated module and local API.

Usage: python3 compare-cli.py OLD_BINARY NEW_BINARY [--output report.json]
The host's network tools and lifecycle shell functions are fixture doubles;
Android kernel attachments and a real sing-box process need device acceptance.
"""

import argparse
import base64
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import threading
import urllib.parse


CONFIG = {
    "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "magicnet0", "mtu": 1400,
                  "address": ["172.19.0.1/30"], "auto_route": True}],
    "outbounds": [
        {"type": "selector", "tag": "proxy", "outbounds": ["Node A", "Node B", "chain"], "default": "Node A"},
        {"type": "vless", "tag": "Node A", "server": "node.invalid", "server_port": 443},
        {"type": "socks", "tag": "Node B", "server": "other.invalid", "server_port": 443},
        {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"},
        {"type": "socks", "tag": "magicnet-chain-exit::Node B", "detour": "chain-hop1"},
    ],
    "route": {"final": "proxy", "rules": []},
    "dns": {"servers": [{"tag": "dns-direct", "type": "local"}]},
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
}

API = {
    "proxies": {
        "proxy": {"type": "Selector", "now": "Node A", "all": ["Node A", "Node B", "chain"]},
        "Node A": {"type": "VLESS", "history": [{"delay": 42}]},
        "Node B": {"type": "Socks5", "history": [{"delay": 42}]},
        "chain": {"type": "Selector", "now": "chain-exit", "all": ["chain-exit"]},
        "chain-hop1": {"type": "Selector", "now": "Node A", "all": ["Node A"]},
        "chain-exit": {"type": "Selector", "now": "magicnet-chain-exit::Node B", "all": ["magicnet-chain-exit::Node B"]},
    },
    "configs": {"mode": "rule"},
    "connections": {"uploadTotal": 128, "downloadTotal": 1024, "connections": [
        {"id": "c-one", "upload": 32, "download": 512, "metadata": {"host": "alpha.invalid", "process": "app.one"}, "chains": ["proxy", "Node A"]},
        {"id": "c-two", "upload": 64, "download": 128, "metadata": {"host": "beta.invalid", "process": "app.two"}, "chains": ["proxy", "Node B"]},
    ]},
}


class ApiServer(http.server.ThreadingHTTPServer):
    def reset(self):
        self.state = copy.deepcopy(API)
        self.writes = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.respond()

    def do_PUT(self):
        self.respond()

    def do_PATCH(self):
        self.respond()

    def do_DELETE(self):
        self.respond()

    def respond(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if path == "/native-large-response":
            body = b"x" * (8 * 1024 * 1024)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        raw = self.rfile.read(int(self.headers.get("content-length", "0")))
        payload = json.loads(raw) if raw else None
        if self.command != "GET":
            self.server.writes.append([self.command, path, payload])
        state = self.server.state
        status, result = 200, {}
        if path == "/proxies":
            result = {"proxies": state["proxies"]}
        elif path.startswith("/proxies/"):
            name = path.removeprefix("/proxies/")
            if name.endswith("/delay"):
                result = {"delay": 42}
            elif name not in state["proxies"]:
                status, result = 404, {"message": "proxy not found"}
            elif self.command == "PUT":
                state["proxies"][name]["now"] = payload["name"]
            else:
                result = state["proxies"][name]
        elif path == "/configs":
            if self.command == "PATCH":
                state["configs"].update(payload)
            result = state["configs"]
        elif path.startswith("/connections"):
            if self.command == "DELETE":
                ident = path.removeprefix("/connections").lstrip("/")
                state["connections"]["connections"] = [
                    conn for conn in state["connections"]["connections"] if ident and conn["id"] != ident
                ]
            else:
                result = state["connections"]
        elif path == "/traffic":
            result = {"up": 64, "down": 128}
        elif path == "/memory":
            result = {"inuse": 1048576}
        elif path == "/version":
            result = {"version": "fixture"}
        else:
            status, result = 404, {"message": "unknown fixture path"}
        body = (json.dumps(result, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def write(root, relative, text, executable=False):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


def fixture(root, failing_apply=False):
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    write(root, "module.prop", "id=MagicNet\nname=MagicNet\nversion=fixture\nversionCode=1\n")
    write(root, ".config/sing-box/config.json", json.dumps(CONFIG) + "\n")
    write(root, ".config/magicnet/mcp.conf", "MAGICNET_MCP_ENABLED=0\nMAGICNET_MCP_BIND=127.0.0.1\nMAGICNET_MCP_PORT=8766\nMAGICNET_MCP_SECRET=fixture-secret\n")
    write(root, "lib/kamfw/.kamfwrc", "import() { :; }\n")
    names = [
        "start_kernel", "ensure_kernel", "supervisors_start", "supervisors_start_detached",
        "supervisors_stop", "lifecycle_before_stop", "lifecycle_after_stop", "dns_cleanup",
        "dns_apply", "route_apply", "app_policy_apply", "transparent_apply", "wifi_policy_start",
        "wifi_policy_stop", "fswatch_start", "fswatch_stop", "restore_network_after_failed_stop",
        "recover_interrupted_transparent_transaction", "action_diagnose",
        "prepare_network_for_core_stop", "after_kernel_start_unlocked",
    ]
    script = "trace() { printf '%s\\n' \"$1\" >> \"$MODDIR/fixture-calls.txt\"; }\n"
    for name in names:
        script += f"magicnet_{name}() {{ trace {name}; }}\n"
    script += "magicnet_dns_capture_capabilities() { printf 'ipv4_nat=supported\\nipv6_nat=supported\\nkernel_capture_required=1\\n'; }\n"
    script += "magicnet_apply_runtime_config() { trace apply_runtime_config; " + ("return 9;" if failing_apply else ":;") + " }\n"
    write(root, "lib/magicnet.sh", script)
    write(root, "lib/magicnet_singbox_subscribe.sh", "magicnet_singbox_update_lock_active() { return 1; }\n"
          + "magicnet_singbox_update_subscription() { trace update_subscription; " + ("return 9;" if failing_apply else ":;") + " }\n")
    for name in ["pidof", "pkill", "ip", "iptables", "ip6tables", "iptables-save", "ip6tables-save", "dumpsys", "getprop"]:
        write(root, f"bin/{name}", "#!/bin/sh\nexit 1\n", True)
    write(root, "bin/pm", "#!/bin/sh\nprintf 'package:com.example.beta\\npackage:com.example.alpha\\npackage:com.example.beta\\n'\n", True)
    write(root, "bin/cmd", "#!/bin/sh\ncase \"$1 $2\" in\n'package query-services') printf 'com.example.vpn/.Service\\n';;\n'wifi status') printf 'WifiInfo: SSID: \"Cafe Wireless\", BSSID: aa:bb:cc:dd:ee:01\\n';;\n*) exit 1;;\nesac\n", True)


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes().hex()
            for path in sorted(root.rglob("*")) if path.is_file()}


def encoded(text):
    return base64.b64encode(text.encode()).decode()


def scenarios():
    cases = []

    def add(name, *commands, fail=False):
        cases.append((name, commands, fail))

    for name, args in [("default-help", []), ("help", ["help"]), ("short-help", ["-h"]),
                       ("long-help", ["--help"]), ("unknown", ["unknown-command"]),
                       ("capabilities", ["--json", "capabilities"]),
                       ("double-json", ["--json", "capabilities", "--json"])]:
        add(name, args)
    for command in ["service", "core", "supervisor", "transparent", "dns", "network", "connectivity",
                    "network-access", "sub", "wifi", "hotspot", "tailscale", "override", "module-update"]:
        add(f"machine-{command}", ["--json", command, "status"])
    for command in ["sub", "wifi", "network-access", "override", "app"]:
        add(f"machine-inspect-{command}", [command, "inspect", "--json"])
    for command in ["service", "core", "supervisor", "transparent", "dns", "network", "connectivity",
                    "wifi", "hotspot", "warp", "chain", "sub", "mcp"]:
        add(f"status-{command}", [command, "status"])
    for command in ["service", "supervisor", "transparent", "network", "core", "node", "chain", "wifi",
                    "hotspot", "route", "dns", "warp", "sub", "block", "mcp", "webui", "backup", "api", "app"]:
        add(f"invalid-{command}", [command, "invalid-operation"])
        add(f"machine-reject-{command}", ["--json", command, "invalid-operation"])
    add("machine-reject-control", ["service", "start", "--json"], ["--json", "sub", "clear"])
    add("paths", ["sub", "file"], ["sub", "copy-path", "sing-box"], ["api", "endpoint"], ["core", "selected"])
    add("metadata", ["sub", "user-agent", "set", encoded("MagicNet fixture/1.0")],
        ["sub", "user-agent", "get"], ["sub", "filter", "set", encoded(" Tokyo \nUS\ntokyo\n香港\n")],
        ["sub", "filter", "list"], ["sub", "schedule", "set", "24"], ["sub", "schedule", "status"],
        ["sub", "filter", "clear"], ["sub", "user-agent", "clear"])
    add("metadata-invalid", ["sub", "user-agent", "set", "%%%"], ["sub", "filter", "set", encoded("x" * 65)],
        ["sub", "schedule", "set", "17"], ["sub", "user-agent", "set", encoded("line\nbreak")])
    add("subscription-sources", ["sub", "set", "sing-box", "https://example.invalid/sub"],
        ["sub", "get", "sing-box"], ["sub", "list"], ["--json", "sub", "inspect"], ["sub", "clear"])
    add("subscription-rollback", ["sub", "set", "sing-box", "https://example.invalid/sub"], ["sub", "get", "sing-box"], fail=True)
    add("dns-profiles", *[["dns", "set", value] for value in ["default", "doh", "dot", "udp"]], ["dns", "status"])
    add("dns-invalid", ["dns", "set", "bogus"], ["dns", "test", "https://invalid.example"], ["dns", "test", "a;b"])
    add("network-policy", ["network", "set", "ipv4_only", "1280", "1m"], ["network", "set", "prefer_ipv4", "1400", "5m"],
        ["network", "set", "prefer_ipv6", "1500", "30m"], ["network", "status"], ["--json", "network", "preflight"])
    add("network-invalid", ["network", "set", "auto", "1400", "5m"], ["network", "set", "ipv4_only", "1600", "5m"])
    add("wifi-lists", ["wifi", "mode", "whitelist"], ["wifi", "interval", "30"],
        ["wifi", "add-ssid", "Cafe", "Wireless"], ["wifi", "add-ssid", "Cafe Wireless"],
        ["wifi", "add-bssid", "AA:BB:CC:DD:EE:01"], ["wifi", "add-bssid", "aa:bb:cc:dd:ee:02"],
        ["wifi", "remove-bssid", "AA:BB:CC:DD:EE:01"], ["wifi", "remove-ssid", "Cafe Wireless"], ["wifi", "status"])
    add("wifi-control", ["wifi", "add-ssid", "Cafe Wireless"], ["wifi", "enable"], ["wifi", "check"],
        ["--json", "wifi", "status"], ["wifi", "disable"], ["mode"])
    add("wifi-invalid", ["wifi", "interval", "2"], ["wifi", "mode", "auto"], ["wifi", "add-bssid", "bad-address"])
    add("routes", ["route", "add-domain", "proxy", "example.invalid"], ["route", "add-domain", "direct", "local.invalid"],
        ["route", "list"], ["route", "remove-domain", "proxy", "example.invalid"])
    add("app-lists", ["app", "add", "com.example.alpha", "proxy"], ["app", "add", "com.example.alpha", "direct"],
        ["app", "add-many", "bypass", "com.example.beta", "com.example.gamma", "com.example.beta"],
        ["app", "list"], ["app", "remove", "com.example.beta"], ["app", "mode", "whitelist"],
        ["app", "packages", "example"], ["app", "recommendations"])
    add("app-batch-order", ["app", "add-many", "proxy", "com.example.a", "com.example.b", "com.example.c"],
        ["app", "add-many", "direct", "com.example.b", "com.example.a", "com.example.b"], ["app", "list"],
        ["app", "add-many", "direct", "com.example.a", "com.example.d", "com.example.a"], ["app", "list"])
    add("app-large-batch", ["app", "add-many", "proxy", *[f"com.fixture.app{i}" for i in range(1200)]],
        ["app", "add-many", "bypass", *[f"com.fixture.app{i}" for i in range(1000, -1, -1)]], ["app", "list"])
    add("app-invalid", ["app", "add", "invalid"], ["app", "add-many", "direct", "com.example.good", "bad;package"])
    add("chain-policy", ["chain", "set-upstream", "Node A"], ["chain", "set-exit", "Node B"], ["chain", "mode", "auto"],
        ["chain", "enable"], ["chain", "status"], ["chain", "clear-upstream"], ["chain", "select-upstream", "Node A"],
        ["chain", "select-exit", "Node B"], ["chain", "disable"], ["chain", "clear-upstream"], ["chain", "clear-exit"])
    add("chain-rollback", ["chain", "set-upstream", "Node A"], ["chain", "set-exit", "Node B"], ["chain", "enable"],
        ["chain", "status"], fail=True)
    add("chain-invalid", ["chain", "enable"], ["chain", "mode", "bogus"], ["chain", "set-exit", "missing"],
        ["chain", "set-upstream", "magicnet-chain-exit::Node B"])
    add("api-read", ["api", "groups"], ["api", "proxies"], ["api", "conns"], ["api", "stats"], ["node", "list"], ["node", "current"])
    add("api-write", ["api", "select", "proxy", "Node B"], ["node", "current"], ["node", "use", "Node A"],
        ["node", "test", "Node A"], ["node", "test-all", "Node A", "Node B"], ["mode", "global"], ["mode"],
        ["api", "close", "c-one"], ["api", "conns"], ["api", "close-all"])
    add("connection-filters", ["api", "close-matching", "alpha"], ["api", "close-top", "1"], ["api", "conns"])
    add("mcp-settings", ["mcp", "set", "127.0.0.1", "18866"], ["mcp", "status"], ["mcp", "secret"], ["mcp", "disable"])
    add("mcp-invalid", ["mcp", "set", "0.0.0.0", "0"], ["mcp", "set", "not-an-ip", "8766"])
    add("reconcile", ["state", "reconcile"], ["--json", "service", "status"], ["--json", "transparent", "status"])
    return cases


def run_case(binary, root, server, commands, fail):
    fixture(root, fail)
    server.reset()
    env = dict(os.environ, MODDIR=str(root), MAGICNET_API=f"http://127.0.0.1:{server.server_port}",
               PATH=f"{root}/bin:/usr/bin:/bin", MAGICNET_TEST_PATH="/usr/bin:/bin", LC_ALL="C")
    results = []
    for command in commands:
        output = subprocess.run([binary, *command], env=env, capture_output=True, timeout=30)
        results.append({"command": command, "exit": output.returncode,
                        "stdout": output.stdout.decode(errors="backslashreplace"),
                        "stderr": output.stderr.decode(errors="backslashreplace"),
                        "files": snapshot(root), "api": copy.deepcopy(server.state),
                        "api_writes": copy.deepcopy(server.writes)})
    return results


def differences(old, new):
    result = []
    for a, b in zip(old, new):
        fields = [name for name in a if a[name] != b[name]]
        if fields:
            detail = {"command": a["command"], "fields": fields}
            for name in fields:
                if name == "files":
                    detail[name] = [path for path in sorted(a[name].keys() | b[name].keys())
                                    if a[name].get(path) != b[name].get(path)]
                else:
                    detail[name] = {"old": a[name], "new": b[name]}
            result.append(detail)
    return result


def build_meter(directory):
    meter = directory / "measure-cli"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", str(meter),
                    str(Path(__file__).with_name("measure-cli.c"))], check=True, capture_output=True)
    return meter


def measure_pairs(commands, env, meter, rounds, prepare=lambda: None):
    samples = {label: [] for label in commands}
    # Alternate pairs to distribute host-load and cache effects; omit warm-up.
    for index in range(rounds + 1):
        order = list(commands) if index % 2 else list(reversed(commands))
        for label in order:
            prepare()
            output = subprocess.run([str(meter), *commands[label]], env=env,
                                    capture_output=True, timeout=35)
            if output.returncode != 0:
                raise RuntimeError(f"benchmark command failed: {commands[label][:4]}: {output.stderr!r}")
            if index:
                samples[label].append(json.loads(output.stdout))
    return {label: {
        "median_ms": round(statistics.median(row["ms"] for row in rows), 3),
        "min_ms": round(min(row["ms"] for row in rows), 3),
        "median_peak_rss_kib": statistics.median(row["peak_rss_kib"] for row in rows),
        "rounds": rounds,
    } for label, rows in samples.items()}


def benchmark(binaries, root, server, rounds):
    fixture(root)
    server.reset()
    meter = build_meter(root.parent)
    env = dict(os.environ, MODDIR=str(root), MAGICNET_API=f"http://127.0.0.1:{server.server_port}",
               PATH=f"{root}/bin:/usr/bin:/bin", MAGICNET_TEST_PATH="/usr/bin:/bin", LC_ALL="C")
    result = {label: {} for label in binaries}
    commands = [["help"], ["--json", "capabilities"], ["node", "list"],
                ["--json", "service", "status"], ["api", "proxies"]]
    for command in commands:
        rows = measure_pairs({label: [binary, *command] for label, binary in binaries.items()}, env, meter, rounds)
        for label, values in rows.items():
            result[label][" ".join(command)] = values
    batch = ["app", "add-many", "proxy", *[f"com.fixture.app{i}" for i in range(5000)]]
    rows = measure_pairs({label: [binary, *batch] for label, binary in binaries.items()}, env, meter, rounds,
                         prepare=lambda: fixture(root))
    for label, values in rows.items():
        result[label]["app add-many (5000 packages)"] = values
    return result


def benchmark_native_http(sources, root, server, rounds):
    commands = {}
    meter = build_meter(root.parent)
    for label, path in zip(["old", "new"], sources):
        driver = root.parent / f"http-{label}.rs"
        binary = root.parent / f"http-{label}"
        # Compile the actual transport module from each checkout, with no copy
        # of its implementation. cfg(test) exposes the shared request wrapper.
        driver.write_text(f'#[path = {json.dumps(str(path.resolve()))}] mod transport;\n' + r'''
fn main() {
    let api = std::env::args().nth(1).unwrap();
    let body = transport::request(&api, "GET", "/native-large-response", "").unwrap();
    assert_eq!(body.len(), 8 * 1024 * 1024);
    assert!(body.iter().all(|byte| *byte == b'x'));
}
''')
        subprocess.run(["rustc", "--edition", "2021", "--cfg", "test", "-O", "-Awarnings",
                        str(driver), "-o", str(binary)], check=True, capture_output=True)
        commands[label] = [str(binary), f"http://127.0.0.1:{server.server_port}"]
    return measure_pairs(commands, os.environ, meter, rounds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("new", type=lambda path: str(Path(path).resolve()))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--benchmark-rounds", type=int, default=0)
    parser.add_argument("--native-http-sources", nargs=2, type=Path, metavar=("OLD_RS", "NEW_RS"))
    args = parser.parse_args()
    server = ApiServer(("127.0.0.1", 0), Handler)
    server.reset()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = {"binaries": {label: {"path": path, "bytes": Path(path).stat().st_size,
                "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                for label, path in [("old", args.old), ("new", args.new)]},
              "scenarios": [], "commands": 0,
              "comparison": "Exact exit, stdout, stderr, every file byte, local API state and write effects; no ignored fields."}
    try:
        with tempfile.TemporaryDirectory(prefix="magicnet-cli-parity-") as temp:
            root = Path(temp) / "module"
            for name, commands, fail in scenarios():
                old = run_case(args.old, root, server, commands, fail)
                new = run_case(args.new, root, server, commands, fail)
                delta = differences(old, new)
                report["commands"] += len(commands)
                report["scenarios"].append({"name": name, "commands": len(commands), "exit_codes": [r["exit"] for r in old], "passed": not delta, "differences": delta})
                print(f"{'PASS' if not delta else 'FAIL'} {name} ({len(commands)} commands)", flush=True)
            if args.benchmark_rounds:
                report["benchmarks"] = benchmark({"old": args.old, "new": args.new}, root, server, args.benchmark_rounds)
                if args.native_http_sources:
                    report["native_http_8mib"] = benchmark_native_http(args.native_http_sources, root, server, args.benchmark_rounds)
    finally:
        server.shutdown()
        server.server_close()
    report["passed"] = all(case["passed"] for case in report["scenarios"])
    report["passed_scenarios"] = sum(case["passed"] for case in report["scenarios"])
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(f"{report['passed_scenarios']}/{len(report['scenarios'])} scenarios; {report['commands']} commands; passed={report['passed']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
