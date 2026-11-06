#!/usr/bin/env python3
"""Compare the live MCP HTTP protocol and CLI argument bridge of two binaries.

The delegated CLI is a literal argv recorder. It cannot execute device actions.
Usage: python3 compare-mcp.py OLD_BINARY NEW_BINARY --output report.json
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


TOOLS = {
    "network_set": {"ipv6_mode": "prefer_ipv4", "mtu": 1400, "udp_timeout": "5m"},
    "dns_set": {"profile": "cloudflare-doh"},
    "dns_test": {"domain": "example.invalid"},
    "node_test": {"name": "Node with spaces;$(literal)"},
    "selector_select": {"group": "proxy", "node": "Node with spaces"},
    "connection_close": {"id": "fixture-id"},
    "subscription_schedule": {"hours": "24"},
    "route_domain": {"action": "add-domain", "target": "proxy", "domain": "example.invalid"},
    "supervisor_control": {"action": "start", "target": "fswatch"},
    "core_select": {"core": "sing-box"},
    "config_get": {"target": "sing-box"},
    "config_sync_template": {"target": "sing-box"},
    "config_save_base64": {"target": "sing-box", "content_base64": "e30="},
    "transparent_set": {"mode": "tun"},
    "subscription_update": {},
    "backup_restore_base64": {"content_base64": "e30="},
    "ecapture_help": {},
    "app_packages": {"query": "two words"},
    "app_mode": {"mode": "whitelist"},
    "api": {},
    "webui_install_local": {"url": "https://example.invalid/ui.zip", "sha256": "a" * 64},
    "block_add_domain": {"suffix": "example.invalid"},
    "block_remove_domain": {"suffix": "example.invalid"},
    "block_allow_rule": {"rule": "domain:example.invalid"},
    "block_unallow_rule": {"rule": "domain:example.invalid"},
}


def request(port, payload, secret="fixture-secret"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", "/mcp", json.dumps(payload), {
            "Content-Type": "application/json", "X-MagicNet-MCP-Secret": secret,
        })
        response = connection.getresponse()
        return response.status, response.read().decode()
    finally:
        connection.close()


def run(binary, root, port):
    shutil.rmtree(root, ignore_errors=True)
    (root / ".config/magicnet").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / ".config/magicnet/mcp.conf").write_text(
        f"MAGICNET_MCP_ENABLED=1\nMAGICNET_MCP_BIND=127.0.0.1\nMAGICNET_MCP_PORT={port}\nMAGICNET_MCP_SECRET=fixture-secret\n"
    )
    # One line per argument makes whitespace, quoting and argument boundaries
    # observable. printf receives user strings only as data, never shell code.
    recorder = root / "bin/magicnet-cli"
    recorder.write_text("#!/bin/sh\nprintf '<%s>\\n' \"$@\"\n")
    recorder.chmod(0o700)
    results = []
    with tempfile.TemporaryFile() as errors:
        child = subprocess.Popen([binary, "mcp", "serve"], env=dict(os.environ, MODDIR=str(root)),
                                 stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    request(port, {"jsonrpc": "2.0", "id": 0, "method": "ping"})
                    break
                except OSError:
                    if child.poll() is not None or time.monotonic() >= deadline:
                        errors.seek(0)
                        raise RuntimeError(f"MCP did not start: {errors.read()!r}")
                    time.sleep(0.01)
            for method in ["initialize", "tools/list", "resources/list", "prompts/list", "missing-method"]:
                payload = {"jsonrpc": "2.0", "id": 1, "method": method}
                results.append({"name": method, "response": request(port, payload)})
            for name, args in TOOLS.items():
                payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "magicnet_" + name, "arguments": args}}
                response = request(port, payload)
                parsed = json.loads(response[1])
                if response[0] != 200 or parsed.get("result", {}).get("isError"):
                    raise AssertionError(f"valid tool fixture rejected: {name}: {response}")
                results.append({"name": name, "response": response})
                payload["params"]["arguments"] = {"unexpected": True}
                results.append({"name": name + "-rejected", "response": request(port, payload)})
            notification = {"jsonrpc": "2.0", "method": "tools/call",
                            "params": {"name": "magicnet_network_set", "arguments": TOOLS["network_set"]}}
            results.append({"name": "notification", "response": request(port, notification)})
            results.append({"name": "authentication", "response": request(port, {"jsonrpc": "2.0", "id": 3, "method": "ping"}, "wrong")})
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("new", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="magicnet-mcp-parity-") as temp:
        root = Path(temp) / "module"
        old, new = [run(binary, root, port) for binary in [args.old, args.new]]
    differences = [{"name": a["name"], "old": a["response"], "new": b["response"]}
                   for a, b in zip(old, new) if a != b]
    report = {"requests": len(old), "passed": not differences, "differences": differences,
              "comparison": "Exact HTTP status and body, including delegated argv; no ignored fields."}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return bool(differences)


if __name__ == "__main__":
    raise SystemExit(main())
