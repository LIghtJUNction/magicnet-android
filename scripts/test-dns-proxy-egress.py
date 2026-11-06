#!/usr/bin/env python3
"""Check managed DNS materialization and exercise its real proxy egress.

The packet fixture uses loopback DoH servers and an HTTP CONNECT proxy, without
public DNS, a subscription, root, TUN, or firewall changes. Only resolver
addresses, ports and TLS trust are localized after the production materializer;
the resolver graph, rules, final resolver and detours remain its actual output.
Use --require in CI so a missing core or unavailable runtime cannot pass.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
NODE_NAME = "proxy.fixture.invalid"
DIRECT_NAME = "direct.fixture.invalid"
TLS_NAME = "dns.fixture.invalid"
PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
              "http_proxy", "https_proxy", "all_proxy", "no_proxy")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def clean_environment():
    return {key: value for key, value in os.environ.items() if key not in PROXY_KEYS}


def fixture_config(port, proxy_port):
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "direct", "tag": "magicnet-dns-in",
                      "listen": "127.0.0.1", "listen_port": port}],
        "dns": {
            "servers": [
                {"type": "https", "tag": "bootstrap-local-dns", "server": "223.6.6.6"},
                {"type": "https", "tag": "doh-cloudflare", "server": "1.1.1.1", "detour": "proxy"},
            ],
            "final": "bootstrap-local-dns", "strategy": "prefer_ipv4",
            "disable_cache": True, "timeout": "2s",
            "rules": [{"domain": [DIRECT_NAME], "server": "bootstrap-local-dns"}],
        },
        "outbounds": [
            {"type": "http", "tag": "proxy", "server": NODE_NAME, "server_port": proxy_port},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"rules": [{"inbound": ["magicnet-dns-in"], "action": "hijack-dns"}],
                  "final": "proxy"},
    }


def materialize(directory, source, port, proxy_port):
    module = directory / "module"
    config_path = module / ".config/sing-box/config.json"
    config_path.parent.mkdir(parents=True)
    (module / "bin").mkdir()
    (module / "bin/jq").symlink_to(shutil.which("jq"))
    original = fixture_config(port, proxy_port)
    config_path.write_text(json.dumps(original))
    environment = dict(clean_environment(), ROOT=str(ROOT), MODDIR=str(module),
                       DNS_SOURCE=str(source), MAGICNET_SUB_CONFIG_FILE=str(config_path),
                       MAGICNET_DNS_PROFILE="default", MAGICNET_IPV6_MODE="prefer_ipv4")
    script = '''set -eu
. "$ROOT/src/MagicNet/lib/magicnet/primitives.sh"
. "$ROOT/src/MagicNet/lib/magicnet/singbox_subscribe/bootstrap.sh"
. "$DNS_SOURCE"
magicnet_dns_apply_singbox
'''
    subprocess.run(["sh", "-c", script], env=environment, check=True, timeout=15)
    first = config_path.read_bytes()
    config = json.loads(first)
    servers = [server for server in config["dns"]["servers"]
               if server["tag"] == config["dns"]["final"]]
    check(len(servers) == 1 and servers[0].get("detour") == "proxy",
          "managed default DNS fallback leaves the proxy through a direct resolver")
    check(config["route"].get("default_domain_resolver") == "bootstrap-local-dns",
          "proxy endpoint bootstrap must resolve without depending on the proxy itself")
    check(config["dns"]["rules"][:1] == original["dns"]["rules"],
          "explicit direct DNS policy changed")
    check(config["dns"]["rules"][-2:] == [
        {"action": "evaluate", "server": config["dns"]["final"], "tag": "magicnet-final-dns"},
        {"match_response": "magicnet-final-dns", "action": "respond"},
    ], "response pipeline does not use the protected final resolver")
    subprocess.run(["sh", "-c", script], env=environment, check=True, timeout=15)
    check(config_path.read_bytes() == first, "DNS materialization is not idempotent")
    print("PASS production DNS materialization: proxy fallback, direct bootstrap, explicit rule, idempotence")
    return config


def question(name, qtype):
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return struct.pack("!6H", 0x1953, 0x100, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!2H", qtype, 1)


def decode_question(query):
    offset, labels = 12, []
    while query[offset]:
        size = query[offset]
        check(size <= 63, "fixture received a compressed or invalid question")
        labels.append(query[offset + 1:offset + 1 + size].decode("ascii"))
        offset += size + 1
    qtype, qclass = struct.unpack("!2H", query[offset + 1:offset + 5])
    check(qclass == 1 and qtype in (1, 28), "unexpected fixture question type")
    return ".".join(labels), qtype, query[12:offset + 5]


def dns_answer(query, remote):
    name, qtype, wire_question = decode_question(query)
    if name == NODE_NAME:
        address = "127.0.0.1" if qtype == 1 else None
    elif qtype == 1:
        address = "198.18.0.42" if remote else "192.0.2.42"
    else:
        address = "2001:db8::42" if remote else "2001:db8::24"
    count = int(address is not None)
    reply = query[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + wire_question
    if address:
        packed = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, address)
        reply += b"\xc0\x0c" + struct.pack("!2HIH", qtype, 1, 0, len(packed)) + packed
    return name, qtype, reply


class DoHHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        check(self.path == "/dns-query", "unexpected DoH path")
        query = self.rfile.read(int(self.headers["Content-Length"]))
        name, qtype, reply = dns_answer(query, self.server.remote)
        self.server.queries.append((name, qtype))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        # Close each tunnel so the proxy-refusal test cannot reuse an earlier
        # successful DoH connection and hide a fail-open resolver fallback.
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)
        self.close_connection = True

    def log_message(self, *_):
        pass


class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        self.server.attempts.append(self.path)
        if self.path != self.server.destination or self.server.refuse:
            self.send_error(502)
            return
        with socket.create_connection(self.server.target, timeout=3) as upstream:
            self.send_response(200)
            self.end_headers()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                readable, _, _ = select.select([self.connection, upstream], [], [], .1)
                for reader in readable:
                    data = reader.recv(65536)
                    if not data:
                        return
                    (upstream if reader is self.connection else self.connection).sendall(data)

    def log_message(self, *_):
        pass


@contextmanager
def http_server(handler, context=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def tls_context(directory):
    certificate, key = directory / "dns.crt", directory / "dns.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
        "-subj", f"/CN={TLS_NAME}", "-addext", f"subjectAltName=DNS:{TLS_NAME}",
        "-keyout", str(key), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
    key.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    context.set_alpn_protocols(["http/1.1"])
    return context, certificate


def localized_config(config, direct, sentinel_port, certificate):
    localized = copy.deepcopy(config)
    for server in localized["dns"]["servers"]:
        check(server["type"] == "https", "runtime fixture requires DoH resolvers")
        proxied = bool(server.get("detour"))
        server["server"] = "127.0.0.2" if proxied else "127.0.0.1"
        server["server_port"] = sentinel_port if proxied else direct.server_port
        server["path"] = "/dns-query"
        server["headers"] = {"Host": TLS_NAME}
        server["tls"] = {"server_name": TLS_NAME, "certificate_path": str(certificate)}
    return localized


class RuntimeUnavailable(RuntimeError):
    pass


@contextmanager
def running_core(core, config, directory):
    path = directory / "runtime.json"
    path.write_text(json.dumps(config))
    result = subprocess.run([str(core), "check", "-c", str(path)], env=clean_environment(),
                            capture_output=True, text=True, timeout=15)
    check(result.returncode == 0, f"core rejected localized production DNS: {result.stderr.strip()}")
    print("PASS real core configuration check for localized production DNS", flush=True)
    with (directory / "core.log").open("w+") as log:
        process = subprocess.Popen([str(core), "run", "-c", str(path)],
                                   env=clean_environment(), stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    message = log.read(8192)
                    if "create netlink socket: operation not permitted" in message:
                        raise RuntimeUnavailable("host denies AF_NETLINK; real core exited before DNS listener startup")
                    raise AssertionError(f"core exited before DNS listener startup: {message.strip()}")
                try:
                    with socket.create_connection(("127.0.0.1", config["inbounds"][0]["listen_port"]), .1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError("core DNS listener startup timed out")
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def read_exact(connection, count):
    data = b""
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ConnectionError("DNS TCP connection ended before its response")
        data += part
    return data


def query_dns(port, name, qtype, tcp=False):
    query = question(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect(("127.0.0.1", port))
        if tcp:
            client.sendall(struct.pack("!H", len(query)) + query)
            return read_exact(client, struct.unpack("!H", read_exact(client, 2))[0])
        client.send(query)
        return client.recv(4096)


def check_response(reply, qtype, remote):
    check(reply[:2] == b"\x19\x53" and reply[3] & 15 == 0 and reply[6:8] == b"\0\x01",
          "DNS query did not receive a successful answer")
    address = ("198.18.0.42" if remote else "192.0.2.42") if qtype == 1 else (
        "2001:db8::42" if remote else "2001:db8::24")
    check(reply.endswith(socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, address)),
          "DNS answer came from the wrong egress resolver")


def exercise(core, source, directory):
    context, certificate = tls_context(directory)
    with ExitStack() as stack:
        direct = stack.enter_context(http_server(DoHHandler, context))
        remote = stack.enter_context(http_server(DoHHandler, context))
        proxy = stack.enter_context(http_server(ProxyHandler))
        direct.remote, direct.queries = False, []
        remote.remote, remote.queries = True, []
        proxy.attempts, proxy.refuse = [], False
        proxy.target = remote.server_address
        # Reserve a loopback port without listening. Only the fixture proxy
        # maps this destination to the remote DoH server; a direct dial fails.
        sentinel = stack.enter_context(socket.socket())
        sentinel.bind(("127.0.0.2", 0))
        sentinel_port = sentinel.getsockname()[1]
        proxy.destination = f"127.0.0.2:{sentinel_port}"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = materialize(directory, source, port, proxy.server_port)
        config = localized_config(config, direct, sentinel_port, certificate)
        with running_core(core, config, directory):
            for tcp in (False, True):
                for qtype in (1, 28):
                    name = f"unclassified-{int(tcp)}-{qtype}.fixture.invalid"
                    attempts = len(proxy.attempts)
                    check_response(query_dns(port, name, qtype, tcp), qtype, remote=True)
                    check((name, qtype) in remote.queries and len(proxy.attempts) > attempts,
                          "unclassified DNS did not traverse the proxy")
                    check(all(domain == NODE_NAME for domain, _ in direct.queries),
                          "unclassified DNS leaked to the direct bootstrap resolver")
            check(any(domain == NODE_NAME for domain, _ in direct.queries),
                  "proxy hostname did not use the direct bootstrap resolver")
            print("PASS real core: unclassified A/AAAA over UDP/TCP use proxy; node bootstrap stays direct")
            check_response(query_dns(port, DIRECT_NAME, 1), 1, remote=False)
            check((DIRECT_NAME, 1) in direct.queries, "explicit direct DNS rule was lost")
            print("PASS real core: explicit direct domain still resolves locally")
            proxy.refuse = True
            for qtype in (1, 28):
                name = f"blocked-{qtype}.fixture.invalid"
                attempts, remote_count = len(proxy.attempts), len(remote.queries)
                try:
                    reply = query_dns(port, name, qtype)
                except (TimeoutError, ConnectionError):
                    pass
                else:
                    check(reply[3] & 15 != 0, "unavailable proxy produced a successful DNS answer")
                check(len(proxy.attempts) > attempts, "failure case did not reach the proxy")
                check(len(remote.queries) == remote_count, "refused proxy still reached the remote DNS fixture")
                check(not any(domain == name for domain, _ in direct.queries),
                      "proxy failure fell back to the direct resolver")
            print("PASS real core: proxy refusal fails closed for A/AAAA with zero direct fallback queries")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", default=os.environ.get("MAGICNET_TEST_REAL_CORE") or shutil.which("sing-box"))
    parser.add_argument("--dns-source", type=Path, default=ROOT / "src/MagicNet/lib/magicnet/dns.sh",
                        help="production dns.sh to exercise, including a pre-fix revision")
    parser.add_argument("--require", action="store_true", help="fail if real-core runtime is unavailable")
    args = parser.parse_args()
    if shutil.which("jq") is None:
        parser.error("jq is required for the production DNS materializer")
    with tempfile.TemporaryDirectory(prefix="magicnet-dns-egress-") as temporary:
        directory = Path(temporary)
        if not args.core or shutil.which("openssl") is None:
            materialize(directory, args.dns_source.resolve(), 1053, 7890)
            reason = "real sing-box core or openssl is unavailable"
            if args.require:
                raise RuntimeUnavailable(reason)
            print(f"SKIP packet fixture: {reason}; materialization only")
            return
        core = Path(args.core).resolve()
        try:
            exercise(core, args.dns_source.resolve(), directory)
        except RuntimeUnavailable as error:
            if args.require:
                raise
            print(f"SKIP packet fixture: {error}; materialization only")
            return
    print("PASS DNS proxy-egress fixture; public requests=0; Android interception is outside this fixture")


if __name__ == "__main__":
    main()
