package best.lmm.magicnet.probe;

import java.io.InputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.PortUnreachableException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;

/** The same request implementation is exercised by host TLS fixtures and Android. */
public final class ProbeClient {
    public static final String SENTINEL = "198.18.0.42";
    public static final int BODY_LIMIT = 2 * 1024 * 1024;
    public static final int SPEED_LIMIT = 8 * 1024 * 1024;

    public static final class Result {
        public boolean ok;
        public boolean complete = true;
        public int http;
        public int redirects;
        public long bytes;
        public long elapsedMs;
        public String reason = "transport";
        public String transport;
        public boolean receiverBound;
        public boolean receiverClosed;
        public boolean requestAttempted;
        public int accepted;
    }

    interface DatagramFactory { DatagramSocket open() throws IOException; }
    private final DatagramFactory datagrams;
    private volatile HttpURLConnection connection;
    private volatile Socket socket;

    public ProbeClient() { this(() -> new DatagramSocket(null)); }
    ProbeClient(DatagramFactory datagrams) { this.datagrams = datagrams; }

    private static final class UdpExchange {
        volatile DatagramSocket receiver;
        volatile DatagramSocket client;
        volatile boolean receiverBound;
        volatile boolean requestAttempted;
        volatile boolean requestSent;
        volatile int accepted;
        boolean closing;
        boolean cleanupComplete;
        volatile boolean cleanupFailed;

        synchronized DatagramSocket track(DatagramSocket value, boolean receiving) {
            if (closing) {
                value.close();
                throw new IllegalStateException("probe closed");
            }
            if (receiving) receiver = value;
            else client = value;
            return value;
        }

        void close() {
            DatagramSocket receiving;
            DatagramSocket sending;
            synchronized (this) {
                closing = true;
                receiving = receiver;
                sending = client;
            }
            try {
                if (sending != null) sending.close();
            } finally {
                if (receiving != null) receiving.close();
            }
        }

        void finish(ExecutorService executor) {
            try {
                Thread cleanup = new Thread(() -> {
                    try { close(); }
                    catch (RuntimeException error) { cleanupFailed = true; }
                }, "magicnet-probe-cleanup");
                cleanup.setDaemon(true);
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
                cleanup.start();
                if (executor != null) executor.shutdownNow();
                cleanup.join(1000);
                boolean stopped = executor == null || executor.awaitTermination(
                        Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
                cleanupComplete = !cleanup.isAlive() && !cleanupFailed && stopped
                        && (receiver == null || receiver.isClosed())
                        && (client == null || client.isClosed());
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException error) {
                cleanupFailed = true;
            }
        }
    }

    private void close() {
        HttpURLConnection current = connection;
        if (current != null) current.disconnect();
        Socket currentSocket = socket;
        if (currentSocket != null) {
            try { currentSocket.close(); } catch (IOException ignored) { }
        }
    }

    private Result bounded(int timeoutMs, Callable<Result> task) {
        return bounded(timeoutMs, task, null);
    }

    private Result bounded(int timeoutMs, Callable<Result> task, UdpExchange udp) {
        if (timeoutMs < 100 || timeoutMs > 60000) {
            Result invalid = new Result();
            invalid.complete = false;
            invalid.reason = "invalid_input";
            return invalid;
        }
        long started = System.nanoTime();
        ExecutorService executor = null;
        Future<Result> future = null;
        Result result;
        try {
            executor = Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "magicnet-network-probe");
                thread.setDaemon(true);
                return thread;
            });
            future = executor.submit(task);
            result = future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException error) {
            result = new Result();
            result.reason = "timeout";
        } catch (ExecutionException error) {
            Throwable cause = error.getCause();
            result = new Result();
            if (cause instanceof UnknownHostException) result.reason = "dns";
            else if (cause instanceof SSLException) result.reason = "tls";
            else if (cause instanceof SocketTimeoutException) result.reason = "timeout";
            else if (cause instanceof ConnectException || udp != null
                    && (cause instanceof PortUnreachableException || cause instanceof NoRouteToHostException)) {
                result.reason = "connect";
            }
            else if (cause instanceof IllegalArgumentException) {
                result.reason = "invalid_input";
                result.complete = false;
            } else if (udp != null) {
                result.complete = false;
                result.reason = udp.requestAttempted ? "udp_worker_failed" : "udp_setup_failed";
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            result = new Result();
            result.complete = false;
            result.reason = "interrupted";
        } catch (RuntimeException error) {
            if (udp == null) throw error;
            result = new Result();
            result.complete = false;
            result.reason = "udp_worker_failed";
        } finally {
            if (future != null) future.cancel(true);
            if (udp != null) {
                udp.finish(executor);
            } else {
                // Closing a URLConnection may wait on its blocked DNS/TLS worker.
                // Never turn the outer deadline into another unbounded wait. Android
                // finish() tears down this test process; the host also force-stops it
                // if the instrumentation response is lost.
                Thread cleanup = new Thread(this::close, "magicnet-probe-cleanup");
                cleanup.setDaemon(true);
                cleanup.start();
                if (executor != null) executor.shutdownNow();
            }
        }
        result.elapsedMs = Math.max(1L, (System.nanoTime() - started) / 1000000L);
        return result;
    }

    private static URL httpsUrl(String value) throws IOException {
        URL url = new URL(value);
        if (!"https".equals(url.getProtocol()) || url.getUserInfo() != null
                || url.getHost().isEmpty() || value.length() > 2048
                || value.matches(".*[\\s\\p{Cntrl}].*")) {
            throw new IllegalArgumentException("invalid HTTPS target");
        }
        return url;
    }

    public Result https(String address, int expected, int prefixBytes, int timeoutMs) {
        return bounded(timeoutMs, () -> {
            if ((expected != 200 && expected != 204) || prefixBytes < 0
                    || prefixBytes > SPEED_LIMIT || (prefixBytes > 0 && expected != 200)) {
                throw new IllegalArgumentException("invalid probe options");
            }
            URL url = httpsUrl(address);
            Result result = new Result();
            int limit = prefixBytes > 0 ? prefixBytes : BODY_LIMIT;
            for (int redirects = 0; redirects <= 5; redirects++) {
                // No HTTP proxy or account cookies: this app's ordinary OS path
                // is used. Transparent capture is proven separately, not assumed.
                connection = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
                connection.setConnectTimeout(timeoutMs);
                connection.setReadTimeout(timeoutMs);
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("Connection", "close");
                connection.setRequestProperty("User-Agent", "MagicNet-Network-Test/1");
                result.http = connection.getResponseCode();
                result.redirects = redirects;
                if (result.http == 301 || result.http == 302 || result.http == 303
                        || result.http == 307 || result.http == 308) {
                    String location = connection.getHeaderField("Location");
                    if (expected == 204 || location == null || redirects == 5) {
                        result.reason = "unexpected_redirect";
                        return result;
                    }
                    URL next = new URL(url, location);
                    if (!"https".equals(next.getProtocol()) || next.getUserInfo() != null) {
                        result.reason = "unsafe_redirect";
                        return result;
                    }
                    url = httpsUrl(next.toString());
                    close();
                    continue;
                }
                if (result.http != expected) {
                    result.reason = "unexpected_http_status";
                    return result;
                }
                long length = connection.getContentLengthLong();
                if (expected == 204 && length > 0) {
                    result.reason = "unexpected_body";
                    return result;
                }
                if (prefixBytes == 0 && length > limit) {
                    result.complete = false;
                    result.reason = "body_limit";
                    return result;
                }
                try (InputStream input = connection.getInputStream()) {
                    byte[] buffer = new byte[16384];
                    while (true) {
                        int remaining = limit - (int) result.bytes;
                        int count = input.read(buffer, 0, Math.min(buffer.length, remaining + (prefixBytes > 0 ? 0 : 1)));
                        if (count == -1) break;
                        result.bytes += count;
                        if (expected == 204 && result.bytes != 0) {
                            result.reason = "unexpected_body";
                            return result;
                        }
                        if (result.bytes > limit) {
                            result.complete = false;
                            result.reason = "body_limit";
                            return result;
                        }
                        // A throughput sample measures exactly a bounded prefix;
                        // it is not a checksum or whole-file integrity assertion.
                        if (prefixBytes > 0 && result.bytes == prefixBytes) break;
                    }
                }
                if (prefixBytes > 0 && result.bytes != prefixBytes) {
                    result.reason = "short_body";
                    return result;
                }
                // HttpURLConnection does not consistently throw on early EOF.
                if (prefixBytes == 0 && length >= 0 && result.bytes != length) {
                    result.reason = "short_body";
                    return result;
                }
                result.ok = true;
                result.reason = prefixBytes > 0 ? "https_prefix" : "https_response";
                return result;
            }
            result.reason = "unexpected_redirect";
            return result;
        });
    }

    /** Test-only public benchmarking address; never accepts arbitrary cleartext targets. */
    public Result sentinel(int port, String marker, int timeoutMs) {
        return bounded(timeoutMs, () -> {
            if (port < 1024 || port > 65535 || !marker.matches("[a-f0-9]{32}")) {
                throw new IllegalArgumentException("invalid sentinel options");
            }
            Result result = new Result();
            socket = new Socket();
            socket.connect(new InetSocketAddress(SENTINEL, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            byte[] expected = (marker + "\n").getBytes(StandardCharsets.US_ASCII);
            try (InputStream input = socket.getInputStream()) {
                for (byte value : expected) {
                    if (input.read() != (value & 255)) {
                        result.reason = "sentinel_mismatch";
                        return result;
                    }
                    result.bytes++;
                }
            }
            result.ok = true;
            result.reason = "sentinel";
            return result;
        });
    }

    /** One app-owned UDP request; only the loopback receiver knows the marker. */
    public Result udpSentinel(int port, String marker, int timeoutMs) {
        UdpExchange udp = new UdpExchange();
        Result result = bounded(timeoutMs, () -> {
            if (port < 1024 || port > 65535 || marker == null || !marker.matches("[a-f0-9]{32}")) {
                throw new IllegalArgumentException("invalid sentinel options");
            }
            DatagramSocket receiver = udp.track(datagrams.open(), true);
            receiver.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
            udp.receiverBound = true;
            receiver.setSoTimeout(timeoutMs);
            DatagramSocket client = udp.track(datagrams.open(), false);
            client.setSoTimeout(timeoutMs);
            byte[] request = "magicnet-udp-sentinel-v1\n".getBytes(StandardCharsets.US_ASCII);
            udp.requestAttempted = true;
            client.send(new DatagramPacket(request, request.length, InetAddress.getByName(SENTINEL), port));
            udp.requestSent = true;
            DatagramPacket incoming = new DatagramPacket(new byte[request.length + 1], request.length + 1);
            receiver.receive(incoming);
            udp.accepted++;
            Result answer = new Result();
            if (!Arrays.equals(request, Arrays.copyOf(incoming.getData(), incoming.getLength()))) {
                answer.complete = false;
                answer.reason = "sentinel_mismatch";
                return answer;
            }
            byte[] expected = (marker + "\n").getBytes(StandardCharsets.US_ASCII);
            receiver.send(new DatagramPacket(expected, expected.length, incoming.getSocketAddress()));
            DatagramPacket response = new DatagramPacket(new byte[expected.length + 1], expected.length + 1);
            client.receive(response);
            answer.bytes = response.getLength();
            answer.ok = Arrays.equals(expected, Arrays.copyOf(response.getData(), response.getLength()));
            answer.complete = answer.ok;
            answer.reason = answer.ok ? "sentinel" : "sentinel_mismatch";
            return answer;
        }, udp);
        // Complete evidence requires closed sockets and a stopped worker.
        result.transport = "udp";
        result.receiverBound = udp.receiverBound;
        result.receiverClosed = udp.receiver != null && udp.receiver.isClosed();
        result.requestAttempted = udp.requestAttempted;
        result.accepted = udp.accepted;
        if (!udp.cleanupComplete && !"invalid_input".equals(result.reason)) {
            result.ok = false;
            result.complete = false;
            result.reason = "udp_cleanup_failed";
        } else if (!result.ok && (!udp.receiverBound || !udp.requestAttempted
                || udp.accepted != 0 || !("connect".equals(result.reason)
                    || "timeout".equals(result.reason) && udp.requestSent))) {
            result.complete = false;
        }
        return result;
    }
}
