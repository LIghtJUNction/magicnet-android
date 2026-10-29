package magicnet

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubscriptionURLIdentity(t *testing.T) {
	cases := map[string]string{
		"HTTPS://A.example.invalid:443#one":               "https://a.example.invalid/",
		"https://A.example.invalid?token=a%23b&x=1&x=2+3": "https://a.example.invalid/?token=a%23b&x=1&x=2+3",
		"https://a.example.invalid/P%2fA?q=汉字&x=%2F":      "https://a.example.invalid/P%2fA?q=%E6%B1%89%E5%AD%97&x=%2F",
		"https://例子.测试/订阅":                                "https://xn--fsqu00a.xn--0zwm56d/%E8%AE%A2%E9%98%85",
	}
	for input, want := range cases {
		got, e := NormalizeSubscriptionURL(input)
		if e != nil || got != want {
			t.Fatalf("normalization failed: %v got %q want %q", e, got, want)
		}
	}
	list, requested, e := NormalizeSubscriptionList([]byte("HTTPS://A.example.invalid:443#one\r\nhttps://a.example.invalid/#two\rhttps://a.example.invalid/sub?x=1&x=2\nhttps://a.example.invalid/sub?x=2&x=1\n"))
	if e != nil || requested != 4 || len(list) != 3 {
		t.Fatal(e, requested, list)
	}
	for _, input := range []string{"http://example.com/", "https://user:password@example.com/", "https://example.com:0/", "https://example.com:65536/", "https://example.com/a b", "https://example.com/%ZZ", "https://example.com/\x00"} {
		if _, e := NormalizeSubscriptionURL(input); e == nil {
			t.Fatal("accepted invalid URL")
		}
	}
	var six []string
	for _, x := range []string{"a", "b", "c", "d", "e", "f"} {
		six = append(six, "https://example.com/"+x)
	}
	if _, _, e := NormalizeSubscriptionList([]byte(strings.Join(six, "\n"))); ErrorCode(e) != "subscription.source_limit" {
		t.Fatal(e)
	}
}

func TestSubscriptionAddressPolicy(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "0.1.2.3", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "::ffff:127.0.0.1", "fd00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::"} {
		if PublicSubscriptionAddress(netip.MustParseAddr(s)) {
			t.Fatal("accepted reserved address", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !PublicSubscriptionAddress(netip.MustParseAddr(s)) {
			t.Fatal("rejected public address", s)
		}
	}
	if validateResolvedAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}) == nil {
		t.Fatal("mixed public/private answer accepted")
	}
}

func encryptionFixtures(t *testing.T) []string {
	t.Helper()
	x, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	k, e := mlkem.GenerateKey768()
	if e != nil {
		t.Fatal(e)
	}
	keys := []string{base64.RawURLEncoding.EncodeToString(x.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(k.EncapsulationKey().Bytes())}
	var values []string
	for _, appearance := range []string{"native", "xorpub", "random"} {
		for _, rtt := range []string{"0rtt", "1rtt"} {
			for _, key := range keys {
				values = append(values, "mlkem768x25519plus."+appearance+"."+rtt+"."+key)
			}
		}
	}
	return values
}

func TestVLESSEncryptionAcrossNativeInputs(t *testing.T) {
	for _, encryption := range append([]string{"", "none"}, encryptionFixtures(t)...) {
		n := M{"type": "vless", "tag": "Synthetic", "server": "node.example.invalid", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001", "encryption": encryption, "tls": M{"enabled": true, "server_name": "tls.example.invalid"}, "transport": M{"type": "ws", "path": "/route", "headers": M{"Host": "http.example.invalid"}}}
		link := "vless://00000000-0000-0000-0000-000000000001@node.example.invalid:443?security=tls&sni=tls.example.invalid&type=ws&host=http.example.invalid&path=%2Froute&encryption=" + url.QueryEscape(encryption) + "#Synthetic"
		yaml := []byte("proxies:\n  - {name: Synthetic, type: vless, server: node.example.invalid, port: 443, uuid: 00000000-0000-0000-0000-000000000001, tls: true, servername: tls.example.invalid, network: ws, encryption: " + strconvQuote(encryption) + ", ws-opts: {path: /route, headers: {Host: http.example.invalid}}}\n")
		inputs := [][]byte{rtJSON(M{"outbounds": []any{n}}), []byte(link), []byte(base64.StdEncoding.EncodeToString([]byte(link))), yaml}
		for _, data := range inputs {
			p, e := ParseSubscription(data)
			if e != nil || len(p.Nodes) != 1 {
				t.Fatal(e)
			}
			got := p.Nodes[0]
			if got["encryption"] != encryption || got["server"] != "node.example.invalid" || rtMap(got["tls"])["server_name"] != "tls.example.invalid" || rtMap(rtMap(got["transport"])["headers"])["Host"] != "http.example.invalid" {
				t.Fatal("VLESS semantics changed")
			}
		}
	}
	for _, v := range []any{true, 1, "NONE", "mlkem768x25519plus.native.0rtt", "mlkem768x25519plus.bad.0rtt.x", "mlkem768x25519plus.native.0rtt..abc", "mlkem768x25519plus.native.0rtt.AAAAAA=="} {
		if ValidateVLESSEncryption(v) == nil {
			t.Fatal("invalid encryption accepted")
		}
	}
}
func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestYAMLAnchorsAndVMessFields(t *testing.T) {
	yaml := []byte("base: &base\n  type: trojan\n  server: a.example.invalid\n  port: 443\n  password: synthetic\n  network: grpc\n  grpc-opts: {grpc-service-name: svc}\nproxies:\n  - <<: *base\n    name: one\n  - <<: *base\n    name: two\n    server: b.example.invalid\n")
	p, e := ParseSubscription(yaml)
	if e != nil || len(p.Nodes) != 2 || rtMap(p.Nodes[1]["transport"])["service_name"] != "svc" {
		t.Fatal(e)
	}
	vm := M{"v": "2", "ps": "Synthetic", "add": "server.example.invalid", "port": "443", "id": "00000000-0000-0000-0000-000000000001", "aid": "0", "net": "ws", "type": "none", "host": "host.example.invalid", "path": "/ws", "tls": "tls", "sni": "sni.example.invalid"}
	v, _ := json.Marshal(vm)
	n, e := ParseShareLink("vmess://" + base64.StdEncoding.EncodeToString(v))
	if e != nil || n["server"] != "server.example.invalid" || rtMap(n["tls"])["server_name"] != "sni.example.invalid" || rtMap(n["transport"])["path"] != "/ws" || rtMap(rtMap(n["transport"])["headers"])["Host"] != "host.example.invalid" {
		t.Fatal(e, n)
	}
	if _, e := ParseShareLink("socks5://user@node.example.invalid:1080"); e == nil {
		t.Fatal("missing SOCKS password accepted")
	}
	if _, e := ParseSubscription([]byte("proxies: [{name: x, type: trojan, server: a.example.invalid, port: 443, password: synthetic, unimplemented-security: true}]")); ErrorCode(e) != "subscription.semantic_incomplete" {
		t.Fatal(e)
	}
}

func testTrojan(name, server string) M {
	return M{"type": "trojan", "tag": name, "server": server, "server_port": 443, "password": "synthetic-password", "tls": M{"enabled": true}, "transport": M{"type": "grpc", "service_name": "svc"}}
}

func TestStableSemanticIdentityAndReferences(t *testing.T) {
	a := SubscriptionSourceInput{"source-a", &ParsedSubscription{Nodes: []M{testTrojan("shared-name", "a.example.invalid")}, ParsedCount: 1}}
	b := SubscriptionSourceInput{"source-b", &ParsedSubscription{Nodes: []M{testTrojan("shared-name", "b.example.invalid")}, ParsedCount: 1}}
	nodes, counts, e := MergeSubscriptionNodes([]SubscriptionSourceInput{a, b}, nil, nil)
	if e != nil || len(nodes) != 2 || counts[0].Imported != 1 || counts[1].Imported != 1 {
		t.Fatal(e, nodes, counts)
	}
	old := map[string]string{}
	for _, n := range nodes {
		old[n.Identity] = n.Tag
	}
	reordered, _, e := MergeSubscriptionNodes([]SubscriptionSourceInput{b, a}, nil, nodes)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range reordered {
		if n.Tag != old[n.Identity] {
			t.Fatal("selection identity drifted on reorder")
		}
	}
	c := a
	c.ID = "source-c"
	c.Parsed = &ParsedSubscription{Nodes: []M{testTrojan("other-display-name", "a.example.invalid")}, ParsedCount: 1}
	merged, cnt, e := MergeSubscriptionNodes([]SubscriptionSourceInput{a, c}, nil, nil)
	if e != nil || len(merged) != 1 || len(merged[0].Sources) != 2 || cnt[1].Duplicate != 1 {
		t.Fatal(e, cnt)
	}
	up := testTrojan("proxy", "up.example.invalid")
	exit := testTrojan("exit", "exit.example.invalid")
	exit["detour"] = "proxy"
	x := SubscriptionSourceInput{"references", &ParsedSubscription{Nodes: []M{up, exit}, Groups: []M{{"type": "selector", "tag": "my group", "outbounds": []any{"exit", "proxy"}, "default": "exit"}}, ParsedCount: 2}}
	remapped, _, e := MergeSubscriptionNodes([]SubscriptionSourceInput{x}, nil, nil)
	if e != nil || len(remapped) != 3 {
		t.Fatal(e)
	}
	if remapped[0].Tag == "proxy" || remapped[1].Config["detour"] != remapped[0].Tag || remapped[2].Config["default"] != remapped[1].Tag {
		t.Fatal("source-local references were not remapped")
	}
	x.Parsed.Nodes = append(x.Parsed.Nodes, testTrojan("proxy", "ambiguous.example.invalid"))
	x.Parsed.ParsedCount++
	if _, _, e = MergeSubscriptionNodes([]SubscriptionSourceInput{x}, nil, nil); e == nil {
		t.Fatal("ambiguous source-local reference accepted")
	}
}

func TestSubscriptionUsageAndBounds(t *testing.T) {
	u := ParseSubscriptionUsage([]string{"upload=10; download=-1; total=1e9; expire=0; upload=20"}, time.Unix(100, 0))
	if u.Upload != nil || u.Download != nil || u.Total != nil || u.Expire != nil {
		t.Fatal(u)
	}
	u = ParseSubscriptionUsage([]string{"UPLOAD=9007199254740991; download=123; total=1000; expire=253402300799"}, time.Unix(100, 0))
	if u.Upload == nil || u.Expire == nil || *u.Download != 123 {
		t.Fatal(u)
	}
	if _, e := ValidateUserAgent(strings.Repeat("a", 256)); e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateUserAgent(strings.Repeat("a", 257)); e == nil {
		t.Fatal("UA limit bypass")
	}
	f, e := NormalizeSubscriptionFilters([]byte("ONE\r\none\r.*\n"))
	if e != nil || len(f) != 2 {
		t.Fatal(e, f)
	}
	filtered, _ := subscriptionFiltered("ordinary", []string{".*"})
	if filtered {
		t.Fatal("filter interpreted as regex")
	}
	data := bytes.Repeat([]byte("x"), int(SubscriptionDocumentLimit))
	b, e := ValidateSubscriptionDocument(data)
	if e != nil || int64(len(b)) > SubscriptionDocumentLimit {
		t.Fatal(e)
	}
	if _, e = ValidateSubscriptionDocument(append(data, 'x')); e == nil {
		t.Fatal("local size limit bypass")
	}
}

func realCoreFixture(t *testing.T) *App {
	t.Helper()
	repo, e := filepath.Abs(filepath.Join("..", ".."))
	if e != nil {
		t.Fatal(e)
	}
	core := filepath.Join(repo, "assets", "bin", "linux-amd64", "sing-box")
	if _, e = os.Stat(core); e != nil {
		t.Skip("fixed real Linux core not present; core validation was not run")
	}
	a := &App{Root: t.TempDir(), Platform: "linux"}
	if e = os.MkdirAll(a.Path("bin"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(core, a.corePath()); e != nil {
		t.Fatal(e)
	}
	assets := filepath.Join(repo, "assets", "rules")
	entries, e := os.ReadDir(assets)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, e := os.ReadFile(filepath.Join(assets, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = AtomicWrite(a.Path(".config", "sing-box", "rules", entry.Name()), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return a
}

func checkRealCore(t *testing.T, a *App, data []byte) {
	t.Helper()
	if e := a.CheckConfig(context.Background(), data); e != nil {
		p := a.Path("test-invalid.json")
		os.WriteFile(p, data, 0600)
		cmd := exec.Command(a.corePath(), "check", "-c", p)
		cmd.Env = cleanEnv(a.Root)
		out, _ := cmd.CombinedOutput()
		t.Fatalf("real core rejected synthetic candidate: %v\n%s", e, out)
	}
}

func TestRealCoreDefaultAndLocalImport(t *testing.T) {
	a := realCoreFixture(t)
	c, e := a.DefaultPolicy()
	if e != nil {
		t.Fatal(e)
	}
	checkRealCore(t, a, rtJSON(c))
	if e = a.EnsureDefaultConfig(context.Background()); e != nil {
		t.Fatal(e)
	}
	data := rtJSON(M{"outbounds": []any{testTrojan("synthetic-node", "node.example.invalid")}})
	receipt, e := a.ApplyLocalSubscription(context.Background(), data)
	if e != nil {
		t.Fatal(e)
	}
	if receipt["outcome"] != "committed" || receipt["saved_pending_start"] != true {
		t.Fatal(receipt)
	}
	status, e := a.SubscriptionStatus(context.Background(), false)
	if e != nil || rtMap(status["source"])["configured_count"] != 1 {
		t.Fatal(e, status)
	}
	raw, _ := json.Marshal(status)
	if bytes.Contains(raw, []byte("node.example.invalid")) || bytes.Contains(raw, []byte("synthetic-node")) || bytes.Contains(raw, []byte("synthetic-password")) {
		t.Fatal("private subscription values leaked")
	}
	old, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e = a.ApplyLocalSubscription(context.Background(), []byte("proxies: [{type: unsupported, name: private-canary, server: x.example.invalid, port: 443}]"))
	if e == nil {
		t.Fatal("invalid local source accepted")
	}
	after, _ := ReadRegular(a.ConfigPath(), 4<<20)
	if !bytes.Equal(old, after) {
		t.Fatal("failed parse changed the active configuration")
	}
	if _, e = a.ClearSubscriptions(context.Background()); e != nil {
		t.Fatal(e)
	}
	after, _ = ReadRegular(a.ConfigPath(), 4<<20)
	if !bytes.Equal(old, after) {
		t.Fatal("clear changed effective configuration")
	}
	status, e = a.SubscriptionStatus(context.Background(), false)
	if e != nil || rtMap(status["source"])["configured_count"] != 0 {
		t.Fatal(e, status)
	}
}

func controlledFetcher(t *testing.T, handler http.HandlerFunc) (*SubscriptionFetcher, func()) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := strings.TrimPrefix(server.URL, "https://")
	f := &SubscriptionFetcher{Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, DialAddress: func(ctx context.Context, network, ignored string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}, TLSConfig: &tls.Config{RootCAs: roots}}
	return f, server.Close
}

func TestRealCoreMultiSourceAtomicityAndCache(t *testing.T) {
	a := realCoreFixture(t)
	var failB, badB atomic.Bool
	f, close := controlledFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		source := r.URL.Query().Get("source")
		if source == "missing" || source == "b" && failB.Load() {
			w.WriteHeader(400)
			return
		}
		if source == "a" {
			w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1000; expire=2000000000")
		}
		if source == "b" && badB.Load() {
			io.WriteString(w, "proxies: [{type: unsupported}]")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(rtJSON(M{"outbounds": []any{testTrojan("shared-name", source+".example.invalid")}}))
	})
	defer close()
	ctx := context.Background()
	aURL := "https://example.com/?source=a"
	bURL := "https://example.com/?source=b"
	r, e := a.applySubscriptions(ctx, "remote_url", []string{aURL}, nil, 1, false, f)
	if e != nil {
		t.Fatal(e, r)
	}
	old, _ := ReadRegular(a.ConfigPath(), 4<<20)
	r, e = a.applySubscriptions(ctx, "remote_url", []string{aURL, "https://example.com/?source=missing"}, nil, 2, false, f)
	if e == nil || r["outcome"] != "rolled_back" {
		t.Fatal(e, r)
	}
	after, _ := ReadRegular(a.ConfigPath(), 4<<20)
	if !bytes.Equal(old, after) {
		t.Fatal("partial fetch was committed")
	}
	status, e := a.SubscriptionStatus(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	last := status["last"].(SubscriptionLast)
	if rtMap(status["source"])["configured_count"] != 1 || last.Batch.UniqueCount != 2 || last.Batch.Sources[1].FetchResult != "failed" {
		t.Fatal(status)
	}
	r, e = a.applySubscriptions(ctx, "remote_url", []string{aURL, bURL}, nil, 2, false, f)
	if e != nil {
		t.Fatal(e, r)
	}
	snapshot, e := a.subscriptionSnapshot()
	if e != nil || len(snapshot.Nodes) != 2 {
		t.Fatal(e, len(snapshot.Nodes))
	}
	tags := map[string]string{}
	for _, n := range snapshot.Nodes {
		tags[n.Identity] = n.Tag
	}
	r, e = a.applySubscriptions(ctx, "remote_url", []string{bURL, aURL}, nil, 2, false, f)
	if e != nil {
		t.Fatal(e, r)
	}
	snapshot, e = a.subscriptionSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range snapshot.Nodes {
		if tags[n.Identity] != n.Tag {
			t.Fatal("reorder moved node identity")
		}
	}
	failB.Store(true)
	r, e = a.applySubscriptions(ctx, "remote_url", []string{bURL, aURL}, nil, 2, false, f)
	if e != nil {
		t.Fatal(e, r)
	}
	status, e = a.SubscriptionStatus(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	last = status["last"].(SubscriptionLast)
	if last.Batch.Sources[0].FetchResult != "cached" {
		t.Fatal("cache freshness not exposed")
	}
	rows := rtArray(status["source_usage"])
	if len(rows) != 2 {
		t.Fatal("missing usage row removed a source")
	}
	r, e = a.applySubscriptions(ctx, "remote_url", []string{bURL, aURL}, nil, 2, true, f)
	if e == nil {
		t.Fatal("require-fresh fell back to a cache")
	}
	failB.Store(false)
	badB.Store(true)
	old, _ = ReadRegular(a.ConfigPath(), 4<<20)
	r, e = a.applySubscriptions(ctx, "remote_url", []string{aURL, bURL}, nil, 2, false, f)
	if e == nil {
		t.Fatal("parse failure silently used old cache")
	}
	after, _ = ReadRegular(a.ConfigPath(), 4<<20)
	if !bytes.Equal(old, after) {
		t.Fatal("invalid source changed effective config")
	}
}

func TestSafeFetchRedirectAndTLS(t *testing.T) {
	var requests atomic.Int64
	f, close := controlledFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/private" {
			http.Redirect(w, r, "https://127.0.0.1/", 302)
			return
		}
		if r.URL.Path == "/http" {
			http.Redirect(w, r, "http://example.com/", 302)
			return
		}
		if r.URL.Path == "/loop" {
			http.Redirect(w, r, "/loop", 302)
			return
		}
		io.WriteString(w, "ok")
	})
	defer close()
	for _, path := range []string{"private", "http", "loop"} {
		if _, e := f.Fetch(context.Background(), "https://example.com/"+path, ""); ErrorCode(e) != "subscription.url_policy" {
			t.Fatal(path, e)
		}
	}
	before := requests.Load()
	f.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, e := f.Fetch(context.Background(), "https://example.com/", ""); e == nil || requests.Load() != before {
		t.Fatal("dangerous target received a request")
	}
}

func TestSafeFetchGzipHeaderRetryAndCancellation(t *testing.T) {
	var attempts atomic.Int64
	entered := make(chan struct{}, 1)
	f, closeServer := controlledFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/compressed":
			w.Header().Set("Content-Encoding", "gzip")
			g := gzip.NewWriter(w)
			_, _ = g.Write(bytes.Repeat([]byte("x"), int(SubscriptionDocumentLimit)+1))
			_ = g.Close()
		case "/headers":
			w.Header().Set("X-Synthetic-Limit", strings.Repeat("x", 70<<10))
			_, _ = io.WriteString(w, "ok")
		case "/retry":
			if attempts.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			_, _ = io.WriteString(w, "ok")
		case "/wait":
			select {
			case entered <- struct{}{}:
			default:
			}
			<-r.Context().Done()
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})
	defer closeServer()
	for _, path := range []string{"compressed", "headers"} {
		if _, e := f.Fetch(context.Background(), "https://example.com/"+path, ""); ErrorCode(e) != "subscription.response_too_large" {
			t.Fatal(path, e)
		}
	}
	if _, e := f.Fetch(context.Background(), "https://example.com/retry", ""); e != nil || attempts.Load() != 3 {
		t.Fatal("bounded transient retry", e, attempts.Load())
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:9")
	if _, e := f.Fetch(context.Background(), "https://example.com/ok", ""); e != nil {
		t.Fatal("environment proxy changed direct transport", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := f.Fetch(ctx, "https://example.com/wait", ""); done <- e }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("controlled request did not start")
	}
	cancel()
	select {
	case e := <-done:
		if ErrorCode(e) != "subscription.interrupted" {
			t.Fatal("cancel classification", e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled network read did not stop")
	}
}

func TestSafeFetchSharesConnectBudgetAcrossAddresses(t *testing.T) {
	var firstDeadline atomic.Int64
	var invalid atomic.Bool
	f := &SubscriptionFetcher{Resolver: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}, DialAddress: func(ctx context.Context, network, target string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 110*time.Millisecond {
			invalid.Store(true)
		}
		value := deadline.UnixNano()
		if !firstDeadline.CompareAndSwap(0, value) && firstDeadline.Load() != value {
			invalid.Store(true)
		}
		return nil, context.DeadlineExceeded
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, _, e := f.fetchAttempt(ctx, "https://example.com/", "", 100*time.Millisecond)
	if e == nil || invalid.Load() || firstDeadline.Load() == 0 {
		t.Fatal("resolved addresses did not share one connect deadline", e)
	}
}
