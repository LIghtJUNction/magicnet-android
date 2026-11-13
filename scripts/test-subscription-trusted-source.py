#!/usr/bin/env python3
"""Trusted subscription policy through the production CLI, shell and real curl.

The only servers are isolated HTTP/TLS fixtures. DNS resolution, origin checks,
CIDR matching and curl address pinning are production code, not test overrides.
"""
import base64
import collections
import http.server
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
FETCH = ROOT / "src/MagicNet/lib/magicnet/singbox_subscribe/fetch.sh"
BODY = b"proxies:\n  - {name: fixture, type: trojan, server: node.invalid, port: 443, password: fixture}\n"
SECRET = "PRIVATE_TRUST_FIXTURE"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        self.server.counts[path] += 1
        status, body, headers = 200, BODY, {}
        if path.startswith("/redirect-"):
            status, body = 302, b""
            headers["Location"] = {
                "/redirect-relative": f"/ok?token={SECRET}",
                "/redirect-host": f"http://localhost:{self.server.server_port}/ok?token={SECRET}",
                "/redirect-port": f"http://127.0.0.1:{self.server.other_port}/ok?token={SECRET}",
                "/redirect-scheme": f"https://127.0.0.1:{self.server.server_port}/ok?token={SECRET}",
                "/redirect-public": f"https://example.invalid/ok?token={SECRET}",
                "/redirect-metadata": f"http://169.254.169.254/latest?token={SECRET}",
                "/redirect-userinfo": f"http://user:{SECRET}@127.0.0.1:{self.server.server_port}/ok",
                "/redirect-loop": f"/redirect-loop?token={SECRET}",
            }[path]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Subscription-Userinfo", "upload=1; download=2; total=100")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, _request, _address):
        pass


class SocksHandler(socketserver.BaseRequestHandler):
    def exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.request.recv(size - len(data))
            if not chunk:
                raise ConnectionError("incomplete fixture SOCKS request")
            data += chunk
        return data

    def handle(self):
        self.request.settimeout(5)
        version, methods = self.exact(2)
        if version != 5 or 0 not in self.exact(methods):
            return
        self.request.sendall(b"\x05\x00")
        version, command, reserved, kind = self.exact(4)
        if (version, command, reserved) != (5, 1, 0):
            return
        if kind == 1:
            address = socket.inet_ntop(socket.AF_INET, self.exact(4))
        elif kind == 4:
            address = socket.inet_ntop(socket.AF_INET6, self.exact(16))
        elif kind == 3:
            address = self.exact(self.exact(1)[0]).decode("ascii")
        else:
            return
        port = int.from_bytes(self.exact(2), "big")
        self.server.connects.append((kind, address, port))
        # A userspace Tailnet proxy owns the route; no host route is installed.
        with socket.create_connection(("127.0.0.1", self.server.http_port), timeout=5) as upstream:
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 5)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (upstream if source is self.request else self.request).sendall(data)


class SocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def handle_error(self, _request, _address):
        pass


class TrustedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for command in ("cargo", "curl", "openssl", "bash"):
            if not shutil.which(command):
                raise RuntimeError(f"required test dependency missing: {command}")
        env = dict(os.environ)
        env.pop("CARGO_BUILD_TARGET", None)
        build = subprocess.run(
            ["cargo", "build", "--locked", "-p", "magicnet-cli", "--message-format=json"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=180,
        )
        if build.returncode:
            raise RuntimeError(build.stderr + build.stdout)
        cls.binary = next(
            Path(item["executable"])
            for line in build.stdout.splitlines()
            if (item := json.loads(line)).get("executable")
            and item.get("target", {}).get("name") == "magicnet-cli"
        )
        cls.tmp = tempfile.TemporaryDirectory(prefix="magicnet-trusted-source-")
        cls.root = Path(cls.tmp.name)
        cls.cert = cls.root / "cert.pem"
        key = cls.root / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cls.cert), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ], check=True, capture_output=True)
        cls.servers = []
        for encrypted in (False, False, True):
            server = QuietServer(("127.0.0.1", 0), Handler)
            server.counts = collections.Counter()
            if encrypted:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(cls.cert, key)
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        cls.http, cls.other, cls.https = cls.servers
        for server in cls.servers:
            server.other_port = cls.other.server_port
        cls.socks = SocksServer(("127.0.0.1", 0), SocksHandler)
        cls.socks.http_port = cls.http.server_port
        cls.socks.connects = []
        threading.Thread(target=cls.socks.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.socks.shutdown()
        cls.socks.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.case.cleanup)
        self.module = Path(self.case.name)
        self.config = self.module / ".config/sing-box"
        self.config.mkdir(parents=True)
        self.policy = self.config / "subscription-trust.list"
        self.resolutions = self.module / "resolutions"
        self.resolutions.write_text("")
        wrapper = self.module / "cli"
        wrapper.write_text(
            "#!/bin/sh\n"
            'case "$1:$2" in sub:resolve-source|sub:resolve-host|sub:check-source) '
            f"printf '%s\\n' \"$*\" >>{shlex.quote(str(self.resolutions))} ;; esac\n"
            f"exec {shlex.quote(str(self.binary))} \"$@\"\n"
        )
        wrapper.chmod(0o755)
        # -q must isolate trusted fetches from the user's curl configuration too.
        (self.module / ".curlrc").write_text(
            f'insecure\nurl = "http://127.0.0.1:{self.other.server_port}/UNEXPECTED"\n'
        )
        self.env = {
            **os.environ, "MODDIR": str(self.module), "CURL_HOME": str(self.module),
            "http_proxy": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1", "MAGICNET_SUB_REQUIRE_FRESH": "1",
        }
        for server in self.servers:
            server.counts.clear()
        self.socks.connects.clear()

    def cli(self, *args, success=True):
        result = subprocess.run([str(self.binary), *args], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        return result

    def allow(self, lines):
        self.cli("sub", "trust", "set", base64.b64encode(lines.encode()).decode())
        self.assertEqual(self.policy.stat().st_mode & 0o777, 0o600)

    def origin(self, scheme="http", host="127.0.0.1", server=None):
        server = server or (self.https if scheme == "https" else self.http)
        return f"{scheme}://{host}:{server.server_port}"

    def fetch(self, path="/ok", *, origin=None, success=True, tls_trust=True, shell="bash"):
        target = self.module / "download"
        url = f"{origin or self.origin()}{path}?token={SECRET}"
        code = f'''set -eu
. {shlex.quote(str(FETCH))}
warn() {{ printf '%s\\n' "$*" >&2; }}
magicnet_singbox_try_fetch_subscription {shlex.quote(url)} {shlex.quote(str(target))} 2 6
'''
        env = dict(self.env)
        if tls_trust:
            env["CURL_CA_BUNDLE"] = str(self.cert)
        else:
            env.pop("CURL_CA_BUNDLE", None)
        result = subprocess.run([shell, "-c", code], env=env,
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr + self.resolutions.read_text())
        self.assertEqual(target.exists(), success)
        self.assertEqual(set(self.module.glob("download.*")),
                         {self.module / "download.usage.json"} if success else set())
        if success:
            self.assertEqual(target.read_bytes(), BODY)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_default_policy_rejects_http_and_private_https_before_connecting(self):
        self.fetch(success=False)
        self.fetch(origin=self.origin("https"), success=False)
        self.assertTrue(all(not server.counts for server in self.servers))

    def test_explicit_http_source_uses_real_resolver_and_ignores_proxies(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        for shell in ("bash", "sh"):
            with self.subTest(shell=shell):
                self.fetch(shell=shell)
        self.assertEqual(self.http.counts["/ok"], 2)
        self.assertFalse(self.other.counts)
        self.assertEqual(self.resolutions.read_text().count("resolve-source"), 2)

    def test_https_source_still_verifies_its_certificate(self):
        self.allow(f"{self.origin('https')} 127.0.0.1/32\n")
        self.fetch(origin=self.origin("https"))
        self.https.counts.clear()
        self.fetch(origin=self.origin("https"), tls_trust=False, success=False)
        self.assertFalse(self.https.counts)

    def test_userspace_tailnet_uses_only_the_explicit_local_socks_route(self):
        origin = "http://100.100.1.2:25500"
        route = f"socks5://127.0.0.1:{self.socks.server_address[1]}"
        self.allow(f"{origin} 100.100.1.2/32 {route}\n{self.origin()} 127.0.0.1/32\n")
        self.fetch("/redirect-relative", origin=origin)
        self.assertEqual(self.socks.connects, [(1, "100.100.1.2", 25500)] * 2)
        self.assertEqual(self.http.counts, {"/redirect-relative": 1, "/ok": 1})
        self.fetch()
        self.assertEqual(len(self.socks.connects), 2)
        public = self.cli("sub", "resolve-source", "https", "1.1.1.1", "443",
                          "https", "1.1.1.1", "443")
        self.assertEqual(public.stdout.strip(), "1.1.1.1|direct")

    def test_authority_and_address_must_both_match(self):
        for line in (
            f"{self.origin(host='localhost')} 127.0.0.1/32",
            f"{self.origin('https', server=self.http)} 127.0.0.1/32",
            f"{self.origin(server=self.other)} 127.0.0.1/32",
        ):
            with self.subTest(policy=line):
                self.allow(line + "\n")
                self.fetch(success=False)
        self.allow(f"{self.origin(host='localhost')} 127.0.0.2/32\n")
        self.fetch(origin=self.origin(host="localhost"), success=False)
        self.assertFalse(self.http.counts)

    def test_relative_redirect_revalidates_same_origin(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        self.fetch("/redirect-relative")
        self.assertEqual(self.http.counts, {"/redirect-relative": 1, "/ok": 1})
        self.assertEqual(self.resolutions.read_text().count("resolve-source"), 2)

    def test_source_collector_normalizes_http_without_changing_its_identity(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        url = f"{self.origin()}/ok?token={SECRET}"
        (self.config / "subscription.url").write_text(url.replace("http:", "HTTP:") + "\n" + url + "\n")
        manifest = self.module / "generation/sources.txt"
        code = f'''set -eu
. {shlex.quote(str(FETCH))}
warn() {{ printf '%s\\n' "$*" >&2; }}
error() {{ printf '%s\\n' "$*" >&2; }}
magicnet_singbox_subscription_url_file() {{ printf '%s\\n' "$MODDIR/.config/sing-box/subscription.url"; }}
magicnet_singbox_subscription_user_agent_file() {{ printf '%s\\n' "$MODDIR/.config/sing-box/subscription.user-agent"; }}
magicnet_singbox_subscription_cache_dir() {{ printf '%s\\n' "$MODDIR/cache"; }}
magicnet_singbox_subscription_fingerprint() {{ printf '%s' "$1" | sha256sum | cut -d ' ' -f1; }}
magicnet_singbox_fetch_subscription {shlex.quote(str(manifest))}
[ "$MAGICNET_SUB_CONFIGURED_COUNT:$MAGICNET_SUB_SOURCE_COUNT" = 1:1 ]
'''
        result = subprocess.run(["bash", "-c", code], env=self.env,
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        sources = manifest.read_text().splitlines()
        self.assertEqual(len(sources), 1)
        self.assertEqual(Path(sources[0]).read_bytes(), BODY)
        self.assertEqual(self.http.counts, {"/ok": 1})
        self.assertFalse(list(manifest.parent.glob("urls.*")))

    def test_installer_onboarding_checks_the_production_source_policy(self):
        run = self.module / "onboarding"
        run.mkdir()
        busybox = shutil.which("busybox")
        if not busybox:
            # The CGI handler only needs standard file utilities here. Source
            # authorization still runs the production Rust CLI on every request.
            applets = self.module / "host-applets"
            applets.write_text('#!/bin/sh\nexec "$@"\n')
            applets.chmod(0o700)
            busybox = str(applets)
        token = "a" * 48
        env = {
            **self.env, "MN_SETUP_BB": busybox, "MN_SETUP_RUN": str(run),
            "MN_SETUP_ROOT": str(self.module), "MN_SETUP_TOKEN": token,
            "MN_SETUP_ORIGIN": "http://127.0.0.1:23456", "HTTP_HOST": "127.0.0.1:23456",
            "HTTP_ORIGIN": "http://127.0.0.1:23456", "HTTP_X_SETUP_TOKEN": token,
            "HTTP_SEC_FETCH_SITE": "same-origin", "REQUEST_METHOD": "POST",
            "PATH_INFO": "/save", "CONTENT_TYPE": "text/plain;charset=UTF-8",
        }

        def submit(url, status, code):
            request_env = {**env, "CONTENT_LENGTH": str(len(url.encode()))}
            response = subprocess.run(
                ["sh", str(ROOT / "src/MagicNet/lib/magicnet/onboarding/handler.sh")],
                input=url, env=request_env, capture_output=True, text=True, timeout=12,
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertTrue(response.stdout.startswith(f"Status: {status} "), response.stdout)
            self.assertEqual(json.loads(response.stdout.splitlines()[-1]), {"code": code})
            self.assertNotIn(SECRET, response.stdout + response.stderr + self.resolutions.read_text())
            self.assertFalse(list(run.glob("request.*")))
            self.assertFalse((run / "submit.lock").exists())
            self.assertFalse(list(self.config.glob(".install-subscription.*")))

        url = f"{self.origin()}/subscribe?token={SECRET}"
        output = self.config / "subscription.url"
        submit(url, 400, "invalid")
        self.assertFalse(output.exists())
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        submit(url.replace(str(self.http.server_port), str(self.other.server_port)), 400, "invalid")
        self.assertFalse(output.exists())
        submit(url, 200, "saved")
        self.assertEqual(output.read_text(), url + "\n")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual((run / "result").read_text(), "saved\n")

    def test_trusted_redirect_cannot_change_origin_even_with_other_grants(self):
        self.allow("\n".join((
            f"{self.origin()} 127.0.0.1/32",
            f"{self.origin(host='localhost')} 127.0.0.1/32",
            f"{self.origin(host='localhost')} ::1/128",
            f"{self.origin(server=self.other)} 127.0.0.1/32",
            f"{self.origin('https', server=self.http)} 127.0.0.1/32",
        )) + "\n")
        for kind in ("host", "port", "scheme", "public", "metadata", "userinfo"):
            with self.subTest(kind=kind):
                self.http.counts.clear()
                self.fetch("/redirect-" + kind, success=False)
                self.assertEqual(sum(self.http.counts.values()), 1)
                self.assertFalse(self.other.counts)

    def test_public_chain_cannot_enter_an_authorized_private_origin(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        self.cli("sub", "resolve-source", "http", "127.0.0.1", str(self.http.server_port),
                 "https", "example.invalid", "443", success=False)
        self.assertFalse(self.http.counts)

    def test_redirect_limit_and_secret_cleanup(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        self.fetch("/redirect-loop", success=False)
        self.assertEqual(self.http.counts["/redirect-loop"], 6)

    def test_every_dns_answer_requires_a_matching_cidr(self):
        addresses = {entry[4][0] for entry in socket.getaddrinfo("localhost", 0,
                                                               type=socket.SOCK_STREAM)}
        if not {"127.0.0.1", "::1"} <= addresses:
            self.skipTest("localhost does not expose both address families on this host")
        origin = self.origin(host="localhost")
        self.allow(f"{origin} 127.0.0.1/32\n")
        self.fetch(origin=origin, success=False)
        self.assertFalse(self.http.counts)
        self.allow(f"{origin} 127.0.0.1/32\n{origin} ::1/128\n")
        self.fetch(origin=origin)

    def test_local_address_families_and_tailscale_are_supported(self):
        for host, cidr in (
            ("192.168.1.2", "192.168.1.0/24"),
            ("10.0.0.2", "10.0.0.0/8"),
            ("172.31.255.254", "172.16.0.0/12"),
            ("100.100.1.2", "100.64.0.0/10"),
            ("fd7a:115c:a1e0::2", "fd7a:115c:a1e0::/48"),
        ):
            with self.subTest(host=host):
                authority = f"[{host}]" if ":" in host else host
                self.allow(f"http://{authority}:25500 {cidr}\n")
                self.cli("sub", "check-source", "http", host, "25500")
                self.cli("sub", "resolve-source", "http", host, "25500", "http", host, "25500")

    def test_invalid_grants_are_rejected_without_replacing_the_previous_policy(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        before = self.policy.read_bytes()
        for line in (
            "http://*.example.invalid 10.0.0.0/8",
            f"{self.origin()}/path 127.0.0.1/32",
            f"{self.origin()}?token={SECRET} 127.0.0.1/32",
            f"http://user:{SECRET}@127.0.0.1 127.0.0.1/32",
            "http://nas.invalid 0.0.0.0/0",
            "http://nas.invalid 100.0.0.0/8",
            "http://nas.invalid 100.64.0.1/10",
            "http://nas.invalid 169.254.0.0/16",
            "http://nas.invalid 224.0.0.0/4",
            "http://nas.invalid 8.8.8.8/32",
            "http://nas.invalid ::/0",
            "http://nas.invalid fe80::/10",
            "http://nas.invalid ff00::/8",
            "http://nas.invalid 2001:4860::/32",
            f"{self.origin()} 127.0.0.1/32 socks5h://127.0.0.1:7892",
            f"{self.origin()} 127.0.0.1/32 http://127.0.0.1:7892",
            f"{self.origin()} 127.0.0.1/32 socks5://192.168.1.1:7892",
            f"{self.origin()} 127.0.0.1/32 socks5://localhost:7892",
            f"{self.origin()} 127.0.0.1/32 socks5://127.0.0.1",
            f"{self.origin()} 127.0.0.1/32 socks5://127.0.0.1:7892/path",
            f"{self.origin()} 127.0.0.1/32 socks5://user:{SECRET}@127.0.0.1:7892",
            f"{self.origin()} 127.0.0.1/32\n{self.origin()} ::1/128 socks5://127.0.0.1:7892",
        ):
            with self.subTest(policy=line):
                self.cli("sub", "trust", "set", base64.b64encode(line.encode()).decode(),
                         success=False)
                self.assertEqual(self.policy.read_bytes(), before)
        self.fetch()

    def test_clear_revokes_access_and_malformed_on_disk_policy_fails_closed(self):
        self.allow(f"{self.origin()} 127.0.0.1/32\n")
        self.fetch()
        self.cli("sub", "trust", "clear")
        self.http.counts.clear()
        self.fetch(success=False)
        self.policy.write_text(f"{self.origin()} 127.0.0.1/32\ninvalid policy\n")
        self.policy.chmod(0o600)
        self.fetch(success=False)
        self.assertFalse(self.http.counts)


if __name__ == "__main__":
    unittest.main()
