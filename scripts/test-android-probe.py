#!/usr/bin/env python3
"""Execute the APK's exact Java request engine against local TLS/error fixtures."""
from __future__ import annotations

import http.server
from pathlib import Path
import queue
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'tests/android-probe/src/best/lmm/magicnet/probe/ProbeClient.java'


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            if self.path == '/slow':
                time.sleep(3)
            if self.path in ('/redirect204', '/unsafe'):
                self.send_response(302)
                scheme = 'http' if self.path == '/unsafe' else 'https'
                self.send_header('Location', f'{scheme}://localhost:{self.server.server_port}/204')
                self.end_headers()
                return
            if self.path == '/204':
                self.send_response(204)
                self.end_headers()
                return
            if self.path == '/403':
                self.send_response(403)
                self.end_headers()
                return
            status = 200
            self.send_response(status)
            if self.path == '/short':
                declared = 1000
                self.send_header('Content-Length', str(declared))
                body = b'short'
            elif self.path == '/large':
                self.send_header('Content-Length', str(16 * 1024 * 1024))
                body = b'x' * 16384
            elif self.path == '/unknown':
                body = b'x' * 16384
            else:
                body = b'hello'
                self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            count = 1024 if self.path == '/large' else (130 if self.path == '/unknown' else 1)
            sent = 0
            for _ in range(count):
                sent += self.wfile.write(body)
            if self.path == '/short':
                self.wfile.flush()
                self.server.short_responses.put(dict(path=self.path, status=status,
                                                     declared=declared, sent=sent))
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class AndroidJavaProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('javac', 'java', 'keytool', 'openssl'):
            if not shutil.which(tool):
                raise RuntimeError(f'{tool} is required; do not silently skip the request-engine tests')
        cls.tmp = tempfile.TemporaryDirectory(prefix='magicnet-java-probe-')
        cls.root = Path(cls.tmp.name)
        runner = cls.root / 'Runner.java'
        runner.write_text('''import best.lmm.magicnet.probe.ProbeClient;
public class Runner {
    public static void main(String[] args) {
        ProbeClient.Result result = new ProbeClient().https(args[0], Integer.parseInt(args[1]),
            Integer.parseInt(args[2]), Integer.parseInt(args[3]));
        System.out.println(result.ok + "|" + result.complete + "|" + result.reason + "|" + result.http
            + "|" + result.bytes + "|" + result.elapsedMs);
    }
}
''')
        udp_runner = cls.root / 'UdpRunner.java'
        udp_runner.write_text(r'''package best.lmm.magicnet.probe;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public class UdpRunner {
    static int workers() {
        return (int) Thread.getAllStackTraces().keySet().stream().filter(thread ->
            thread.isAlive() && thread.getName().equals("magicnet-network-probe")).count();
    }
    static final class FixtureSocket extends DatagramSocket {
        final boolean receiver;
        final String mode;
        final int destination;
        final AtomicInteger requests;
        final CountDownLatch release;
        FixtureSocket(boolean receiver, String mode, int destination, AtomicInteger requests,
                      CountDownLatch release) throws IOException {
            super((java.net.SocketAddress) null);
            this.receiver = receiver;
            this.mode = mode;
            this.destination = destination;
            this.requests = requests;
            this.release = release;
        }
        @Override public void send(DatagramPacket packet) throws IOException {
            byte[] payload = Arrays.copyOfRange(packet.getData(), packet.getOffset(),
                                               packet.getOffset() + packet.getLength());
            if (!receiver) {
                if (!packet.getAddress().getHostAddress().equals("198.18.0.42")
                        || !Arrays.equals(payload, "magicnet-udp-sentinel-v1\n".getBytes(StandardCharsets.US_ASCII))) {
                    throw new IllegalStateException("unexpected destination or marker-bearing request");
                }
                requests.incrementAndGet();
                if (mode.equals("worker_error")) throw new IllegalStateException("fixture worker failure");
                if (mode.equals("bad_request")) payload[0] = 'x';
                // Production still addresses the reserved sentinel. Only this
                // package-private host adapter maps its real datagram to loopback.
                packet = new DatagramPacket(payload, payload.length,
                        InetAddress.getByName("127.0.0.1"), destination);
            } else if (mode.equals("mismatch")) {
                payload[0] = 'x';
                packet = new DatagramPacket(payload, payload.length, packet.getSocketAddress());
            }
            super.send(packet);
        }
        @Override public void receive(DatagramPacket packet) throws IOException {
            super.receive(packet);
            if (receiver && mode.equals("worker_stall")) {
                boolean done = false;
                while (!done) {
                    try { release.await(); done = true; }
                    catch (InterruptedException ignored) { }
                }
            }
        }
        @Override public void close() {
            if (!(receiver && mode.equals("cleanup_error"))) super.close();
        }
        void releaseSocket() { super.close(); }
    }
    public static void main(String[] args) throws Exception {
        String mode = args[0];
        int timeout = Integer.parseInt(args[1]);
        AtomicInteger requests = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        List<FixtureSocket> sockets = new ArrayList<>();
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        ProbeClient.Result result;
        int live;
        boolean reusable;
        int accepted;
        try (DatagramSocket reserved = new DatagramSocket(0, loopback);
             DatagramSocket sink = new DatagramSocket(0, loopback)) {
            int port = reserved.getLocalPort();
            if (!mode.equals("bind_error")) reserved.close();
            ProbeClient probe = new ProbeClient(() -> {
                FixtureSocket value = new FixtureSocket(sockets.isEmpty(), mode,
                    mode.equals("drop") ? sink.getLocalPort() : port, requests, release);
                sockets.add(value);
                return value;
            });
            try {
                result = probe.udpSentinel(mode.equals("invalid_port") ? 0 : port,
                    mode.equals("invalid_marker") ? "not-a-marker" : "a".repeat(32), timeout);
                accepted = result.accepted;
                live = workers();
                try (DatagramSocket check = new DatagramSocket(null)) {
                    check.bind(new InetSocketAddress(loopback, port));
                    reusable = true;
                } catch (IOException error) { reusable = false; }
                if (mode.equals("drop")) {
                    sink.setSoTimeout(500);
                    DatagramPacket request = new DatagramPacket(new byte[64], 64);
                    sink.receive(request); // The negative control really sent a UDP packet.
                }
            } finally {
                release.countDown();
                for (FixtureSocket value : sockets) value.releaseSocket();
                long deadline = System.nanoTime() + 1000000000L;
                while (workers() > 0 && System.nanoTime() < deadline) Thread.sleep(5);
                if (workers() != 0) throw new IllegalStateException("host fixture leaked a worker");
            }
        }
        System.out.println(result.ok + "|" + result.complete + "|" + result.reason + "|" + result.bytes
            + "|" + result.elapsedMs + "|" + result.transport + "|" + result.receiverBound
            + "|" + result.receiverClosed + "|" + result.requestAttempted + "|" + result.accepted
            + "|" + requests.get() + "|" + live + "|" + reusable + "|" + (accepted == result.accepted));
    }
}
''')
        subprocess.run(['javac', '-d', str(cls.root), str(CLIENT), str(runner), str(udp_runner)],
                       check=True, capture_output=True, timeout=30)
        cert, key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=10)
        cls.trust = cls.root / 'trust.p12'
        subprocess.run(['keytool', '-importcert', '-noprompt', '-storetype', 'PKCS12',
                        '-alias', 'fixture', '-file', str(cert), '-keystore', str(cls.trust),
                        '-storepass', 'fixture-only'], check=True, capture_output=True, timeout=10)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.short_responses = queue.Queue()
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tmp.cleanup()

    def probe(self, path, expected=200, prefix=0, timeout=3000, trusted=True):
        args = ['java']
        if trusted:
            args += [f'-Djavax.net.ssl.trustStore={self.trust}', '-Djavax.net.ssl.trustStorePassword=fixture-only']
        args += ['-cp', str(self.root), 'Runner',
                 f'https://localhost:{self.server.server_port}{path}', str(expected), str(prefix), str(timeout)]
        cp = subprocess.run(args, check=True, capture_output=True, text=True, timeout=8)
        ok, complete, reason, status, size, elapsed = cp.stdout.strip().split('|')
        return dict(ok=ok == 'true', complete=complete == 'true', reason=reason,
                    status=int(status), size=int(size), elapsed=int(elapsed))

    def udp(self, mode, timeout=300):
        cp = subprocess.run(['java', '-cp', str(self.root),
            'best.lmm.magicnet.probe.UdpRunner', mode, str(timeout)],
            check=True, capture_output=True, text=True, timeout=8)
        values = cp.stdout.strip().split('|')
        fields = ('ok', 'complete', 'reason', 'received_bytes', 'elapsed_ms', 'transport',
                  'receiver_bound', 'receiver_closed', 'request_attempted', 'accepted',
                  'requests', 'workers', 'port_reusable', 'frozen')
        result = dict(zip(fields, values, strict=True))
        for key in ('ok', 'complete', 'receiver_bound', 'receiver_closed', 'request_attempted',
                    'port_reusable', 'frozen'):
            result[key] = result[key] == 'true'
        for key in ('received_bytes', 'elapsed_ms', 'accepted', 'requests', 'workers'):
            result[key] = int(result[key])
        return result

    def assert_udp_closed(self, result):
        self.assertEqual(result['transport'], 'udp')
        self.assertTrue(result['receiver_closed'], result)
        self.assertTrue(result['port_reusable'], result)
        self.assertEqual(result['workers'], 0, result)
        self.assertTrue(result['frozen'])

    def test_udp_real_loopback_roundtrip_uses_one_fixed_request_and_closes_receiver(self):
        result = self.udp('positive', timeout=1000)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['complete'])
        self.assertEqual(result['reason'], 'sentinel')
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(result['requests'], 1)
        self.assertEqual(result['received_bytes'], 33)
        self.assertTrue(result['receiver_bound'])
        self.assertTrue(result['request_attempted'])
        self.assertGreater(result['elapsed_ms'], 0)
        self.assert_udp_closed(result)

    def test_udp_real_packet_on_wrong_path_is_a_complete_zero_receive_timeout(self):
        result = self.udp('drop')
        self.assertFalse(result['ok'], result)
        self.assertTrue(result['complete'])
        self.assertEqual(result['reason'], 'timeout')
        self.assertEqual(result['accepted'], 0)
        self.assertEqual(result['requests'], 1)
        self.assertEqual(result['received_bytes'], 0)
        self.assertTrue(result['receiver_bound'])
        self.assertTrue(result['request_attempted'])
        self.assertLess(result['elapsed_ms'], 1800)
        self.assert_udp_closed(result)

    def test_udp_wrong_request_or_marker_cannot_be_a_valid_negative(self):
        for mode in ('bad_request', 'mismatch'):
            with self.subTest(mode=mode):
                result = self.udp(mode)
                self.assertFalse(result['ok'], result)
                self.assertFalse(result['complete'])
                self.assertEqual(result['reason'], 'sentinel_mismatch')
                self.assertEqual(result['accepted'], 1)
                self.assert_udp_closed(result)

    def test_udp_bind_failure_never_becomes_a_network_negative(self):
        result = self.udp('bind_error')
        self.assertFalse(result['complete'], result)
        self.assertEqual(result['reason'], 'udp_setup_failed')
        self.assertFalse(result['receiver_bound'])
        self.assertTrue(result['receiver_closed'])
        self.assertFalse(result['request_attempted'])
        self.assertEqual(result['accepted'], 0)
        self.assertEqual(result['requests'], 0)
        self.assertEqual(result['workers'], 0)

    def test_udp_invalid_inputs_do_not_open_a_receiver(self):
        for mode, timeout in (('invalid_port', 300), ('invalid_marker', 300), ('positive', 50)):
            with self.subTest(mode=mode, timeout=timeout):
                result = self.udp(mode, timeout)
                self.assertFalse(result['complete'], result)
                self.assertEqual(result['reason'], 'invalid_input')
                self.assertFalse(result['receiver_bound'])
                self.assertFalse(result['request_attempted'])
                self.assertEqual(result['accepted'], 0)
                self.assertEqual(result['requests'], 0)
                self.assertEqual(result['workers'], 0)

    def test_udp_worker_exception_keeps_real_metadata_and_remains_incomplete(self):
        result = self.udp('worker_error')
        self.assertFalse(result['complete'], result)
        self.assertEqual(result['reason'], 'udp_worker_failed')
        self.assertTrue(result['receiver_bound'])
        self.assertTrue(result['request_attempted'])
        self.assertEqual(result['accepted'], 0)
        self.assert_udp_closed(result)

    def test_udp_unclosed_receiver_cannot_publish_a_success(self):
        result = self.udp('cleanup_error')
        self.assertFalse(result['ok'], result)
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'], 'udp_cleanup_failed')
        self.assertFalse(result['receiver_closed'])
        self.assertFalse(result['port_reusable'])
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(result['workers'], 0)

    def test_udp_unfinished_worker_cannot_publish_a_timeout_negative_or_late_count(self):
        result = self.udp('worker_stall', timeout=200)
        self.assertFalse(result['ok'], result)
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'], 'udp_cleanup_failed')
        self.assertTrue(result['receiver_closed'])
        self.assertTrue(result['port_reusable'])
        self.assertGreater(result['workers'], 0)
        self.assertEqual(result['accepted'], 0)
        self.assertTrue(result['frozen'])
        self.assertLess(result['elapsed_ms'], 1700)

    def test_exact_200_and_empty_204(self):
        self.assertTrue(self.probe('/200')['ok'])
        self.assertTrue(self.probe('/204', expected=204)['ok'])
        self.assertFalse(self.probe('/200', expected=204)['ok'])
        self.assertFalse(self.probe('/204', expected=200)['ok'])

    def test_errors_redirected_204_and_downgrade_never_pass(self):
        for path, status in (('/403', 200), ('/redirect204', 204), ('/unsafe', 200)):
            with self.subTest(path=path):
                self.assertFalse(self.probe(path, expected=status)['ok'])

    def test_untrusted_certificate_is_not_bypassed(self):
        result = self.probe('/200', trusted=False)
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'tls')

    def test_premature_eof_fails_even_after_http_200(self):
        def assert_positive():
            response = self.probe('/200')
            self.assertTrue(response['ok'], response)
            self.assertTrue(response['complete'], response)
            self.assertEqual((response['reason'], response['status'], response['size']),
                             ('https_response', 200, 5))

        self.assertTrue(self.server.short_responses.empty())
        assert_positive()
        result = self.probe('/short')
        sent = self.server.short_responses.get(timeout=2)
        assert_positive()
        self.assertEqual(sent, dict(path='/short', status=200, declared=1000, sent=5))
        self.assertFalse(result['ok'], result)
        self.assertTrue(result['complete'], result)
        self.assertIn(result['reason'], ('short_body', 'transport'), result)
        if result['reason'] == 'short_body':
            self.assertEqual((result['status'], result['size']), (200, 5), result)

    def test_known_and_unknown_length_body_limits(self):
        for path in ('/large', '/unknown'):
            with self.subTest(path=path):
                result = self.probe(path)
                self.assertFalse(result['ok'])
                self.assertFalse(result['complete'])
                self.assertLessEqual(result['size'], 2 * 1024 * 1024 + 1)

    def test_speed_requires_exact_bounded_prefix(self):
        result = self.probe('/large', prefix=8 * 1024 * 1024, timeout=5000)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['size'], 8 * 1024 * 1024)
        self.assertFalse(self.probe('/200', prefix=100)['ok'])
        self.assertFalse(self.probe('/403', prefix=100)['ok'])

    def test_outer_deadline_covers_response_stalls(self):
        started = time.monotonic()
        result = self.probe('/slow', timeout=300)
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'timeout')
        self.assertLess(time.monotonic() - started, 2.5)


if __name__ == '__main__':
    unittest.main()
