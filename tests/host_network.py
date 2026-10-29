#!/usr/bin/env python3
"""Controlled loopback communication through the pinned real protocol engine.

No Android/TUN/eBPF/OEM claims are derived from these socket tests. All keys,
credentials and traffic are synthetic and remain inside the temporary fixture.
"""
from pathlib import Path
import contextlib, http.server, json, os, socket, subprocess, tempfile, threading, time

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "assets/bin/linux-amd64/sing-box"
MARKER = b"magicnet-independent-rebuild-loopback-verified"

class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)
    def log_message(self, *_): pass

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def main():
    results = []
    with tempfile.TemporaryDirectory(prefix="magicnet-protocol-") as td:
        work = Path(td)
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        thread = threading.Thread(target=target.serve_forever, daemon=True)
        thread.start()
        server_tls = {"enabled": True, "server_name": "localhost", "certificate_path": str(cert), "key_path": str(key)}
        client_tls = {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}
        uuid = "b7b9861c-31e6-4676-a735-3c63ed4128bf"
        password = "synthetic-loopback-password"
        variants = [
            ("socks", {"type": "socks", "users": [{"username": "synthetic", "password": password}]}, {"type": "socks", "username": "synthetic", "password": password}),
            ("vless-none", {"type": "vless", "users": [{"uuid": uuid}]}, {"type": "vless", "uuid": uuid, "encryption": "none"}),
            ("vless-tls", {"type": "vless", "users": [{"uuid": uuid}], "tls": server_tls}, {"type": "vless", "uuid": uuid, "tls": client_tls}),
            ("vmess", {"type": "vmess", "users": [{"uuid": uuid, "alterId": 0}]}, {"type": "vmess", "uuid": uuid, "security": "auto"}),
            ("shadowsocks", {"type": "shadowsocks", "method": "aes-128-gcm", "password": password}, {"type": "shadowsocks", "method": "aes-128-gcm", "password": password}),
            ("trojan-tls", {"type": "trojan", "users": [{"password": password}], "tls": server_tls}, {"type": "trojan", "password": password, "tls": client_tls}),
            ("anytls", {"type": "anytls", "users": [{"password": password}], "tls": server_tls}, {"type": "anytls", "password": password, "tls": client_tls}),
            ("hysteria2", {"type": "hysteria2", "users": [{"password": password}], "tls": server_tls}, {"type": "hysteria2", "password": password, "tls": client_tls}),
            ("tuic", {"type": "tuic", "users": [{"uuid": uuid, "password": password}], "congestion_control": "cubic", "tls": dict(server_tls, alpn=["h3"])}, {"type": "tuic", "uuid": uuid, "password": password, "congestion_control": "cubic", "tls": dict(client_tls, alpn=["h3"])}),
        ]
        try:
            for name, inbound, outbound in variants:
                started = time.monotonic()
                processes = []
                handles = []
                row = {"case": name, "layer": "host_loopback_real_core", "result": "FAIL"}
                try:
                    server_port, proxy_port = port(), port()
                    inbound = dict(inbound, tag="server", listen="127.0.0.1", listen_port=server_port)
                    outbound = dict(outbound, tag="test-protocol", server="127.0.0.1", server_port=server_port)
                    server = {"log": {"level": "error"}, "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
                    client = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "tag": "client", "listen": "127.0.0.1", "listen_port": proxy_port}], "outbounds": [outbound], "route": {"final": "test-protocol"}}
                    for role, config in (("server", server), ("client", client)):
                        path = work / f"{name}-{role}.json"
                        path.write_text(json.dumps(config))
                        check = subprocess.run([str(CORE), "check", "-c", str(path)], capture_output=True, timeout=20)
                        if check.returncode:
                            row["stage"] = f"{role}_check"
                            row["diagnostic"] = check.stderr.decode(errors="replace")[-2000:]
                            raise RuntimeError("core_check_failed")
                        log = open(work / f"{name}-{role}.log", "wb")
                        handles.append(log)
                        processes.append(subprocess.Popen([str(CORE), "run", "-c", str(path)], stdout=log, stderr=log))
                    deadline = time.monotonic() + 8
                    connected = None
                    while time.monotonic() < deadline:
                        try:
                            connected = socket.create_connection(("127.0.0.1", proxy_port), timeout=0.2)
                            break
                        except OSError: time.sleep(0.05)
                    if connected is None: raise RuntimeError("client_start_timeout")
                    with connected as sock:
                        sock.settimeout(15)
                        sock.sendall(f"GET http://127.0.0.1:{target.server_port}/verified HTTP/1.1\r\nHost: 127.0.0.1:{target.server_port}\r\nConnection: close\r\n\r\n".encode())
                        data = bytearray()
                        while len(data) < 65536:
                            part = sock.recv(4096)
                            if not part: break
                            data.extend(part)
                    if MARKER not in data or not bytes(data).startswith(b"HTTP/1.1 200"):
                        raise RuntimeError("response_mismatch")
                    row.update(result="PASS", stage="response_verified", bytes=len(data))
                except Exception as exc:
                    row["error"] = str(exc)
                finally:
                    for p in reversed(processes):
                        p.terminate()
                        try: p.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            p.kill(); p.wait(timeout=5)
                    for h in handles: h.close()
                    if row["result"] != "PASS":
                        row["core_logs"] = {p.name: p.read_text(errors="replace")[-2000:] for p in work.glob(f"{name}-*.log")}
                    row["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    results.append(row)
                    print(json.dumps(row), flush=True)
        finally:
            target.shutdown(); target.server_close()
    out = ROOT / "test-results/host-network.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"scope": "Synthetic loopback sockets, not Android or public providers", "results": results}, indent=2) + "\n")
    return 0 if all(r["result"] == "PASS" for r in results) else 1

if __name__ == "__main__": raise SystemExit(main())
