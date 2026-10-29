package magicnet

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRealCoreVLESSEncryptionMatrix(t *testing.T) {
	a := realCoreFixture(t)
	fixtures := encryptionFixtures(t)
	fixtures = append(fixtures, "none", "")
	first := strings.Split(fixtures[0], ".")[3]
	second := strings.Split(fixtures[1], ".")[3]
	fixtures = append(fixtures, "mlkem768x25519plus.native.1rtt.100-111-1111.75-0-111."+first+"."+second)
	fixtures = append(fixtures, "mlkem768x25519plus.random.0rtt."+strings.TrimSuffix(strings.Repeat(second+".", 16), "."))
	nodes := []any{}
	for i, value := range fixtures {
		n := M{"type": "vless", "tag": "encryption-" + fmtInt(i), "server": "synthetic.example.invalid", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001", "encryption": value, "tls": M{"enabled": true, "server_name": "tls.example.invalid"}, "transport": M{"type": "ws", "path": "/independent", "headers": M{"Host": "http.example.invalid"}}}
		p, e := ParseSubscription(rtJSON(M{"outbounds": []any{n}}))
		if e != nil || p.Nodes[0]["encryption"] != value {
			t.Fatal("encrypted semantics changed", e)
		}
		nodes = append(nodes, p.Nodes[0])
	}
	config := M{"outbounds": append([]any{M{"type": "direct", "tag": "direct"}}, nodes...), "route": M{"final": "direct"}}
	checkRealCore(t, a, rtJSON(config))
	invalid := rtClone(config).(map[string]any)
	rtMap(rtArray(invalid["outbounds"])[1])["encryption"] = "mlkem768x25519plus.native.0rtt.100-1-2." + first
	if e := a.CheckConfig(context.Background(), rtJSON(invalid)); e == nil {
		t.Fatal("actual core accepted invalid padding")
	}
}

func TestRealCoreMigrationRegeneratesPolicyAndRetainsNodes(t *testing.T) {
	a := realCoreFixture(t)
	old, e := a.DefaultPolicy()
	if e != nil {
		t.Fatal(e)
	}
	value := encryptionFixtures(t)[1]
	node := M{"type": "vless", "tag": "retained-encrypted-node", "server": "private.example.invalid", "server_port": 443, "uuid": "00000000-0000-0000-0000-000000000001", "encryption": value}
	old["outbounds"] = append(rtArray(old["outbounds"]), node, M{"type": "selector", "tag": "Retained group", "outbounds": []any{"retained-encrypted-node", "direct"}, "default": "retained-encrypted-node"})
	for _, v := range rtArray(old["outbounds"]) {
		m := rtMap(v)
		if m["tag"] == "proxy" {
			m["outbounds"] = []any{"retained-encrypted-node", "block"}
			m["default"] = "retained-encrypted-node"
		}
	}
	rtMap(old["route"])["rules"] = append(rtArray(rtMap(old["route"])["rules"]), M{"domain_suffix": []any{"old-policy-canary.example.invalid"}, "outbound": "direct"})
	raw := rtJSON(old)
	if e = AtomicWrite(a.Path(".migration-backup", ".config", "sing-box", "config.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.EnsureDefaultConfig(context.Background()); e != nil {
		t.Fatal(e)
	}
	active, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(active, []byte("old-policy-canary")) || !bytes.Contains(active, []byte(value)) {
		t.Fatal("migration did not preserve endpoint or regenerate policy")
	}
	var config M
	if DecodeJSON(active, &config) != nil {
		t.Fatal("invalid migrated config")
	}
	if findOutbound(config, "proxy")["default"] != "retained-encrypted-node" || findOutbound(config, "Retained group") == nil {
		t.Fatal("migration discarded a selector intention")
	}
	backup, _ := ReadRegular(a.Path(".migration-backup", ".config", "sing-box", "config.json"), 4<<20)
	if !bytes.Equal(raw, backup) {
		t.Fatal("migration altered original private backup")
	}
	checkRealCore(t, a, active)
	if _, e = a.ApplyLocalSubscription(context.Background(), rtJSON(M{"outbounds": []any{testTrojan("later-source", "later.example.invalid")}})); e != nil {
		t.Fatal(e)
	}
	active, _ = ReadRegular(a.ConfigPath(), 4<<20)
	_ = DecodeJSON(active, &config)
	if findOutbound(config, "retained-encrypted-node") == nil {
		t.Fatal("later subscription removed migrated user node")
	}
	members, _ := rtStringList(findOutbound(config, "proxy")["outbounds"])
	if !stringIn("retained-encrypted-node", members...) {
		t.Fatal("later subscription made retained node unselectable")
	}
}

func findOutbound(config M, tag string) M {
	for _, v := range rtArray(config["outbounds"]) {
		m := rtMap(v)
		if m["tag"] == tag {
			return m
		}
	}
	return nil
}

func TestRealCoreChainUndoDNSAndTemplate(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	if _, e := a.ApplyLocalSubscription(ctx, rtJSON(M{"outbounds": []any{testTrojan("entry", "entry.example.invalid"), testTrojan("exit", "exit.example.invalid")}})); e != nil {
		t.Fatal(e)
	}
	if _, e := a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error { s.Chain = RuntimeChain{true, "manual", "entry", "exit"}; return nil }); e != nil {
		t.Fatal(e)
	}
	first, _ := ReadRegular(a.ConfigPath(), 4<<20)
	candidate, e := a.MaterializeConfig(ctx, first)
	if e != nil || !bytes.Equal(first, candidate) {
		t.Fatal("chain repeat drift", e)
	}
	a.ClearMaterialization()
	if _, e = a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error {
		s.Chain.Enabled = false
		s.Block.Enabled = false
		s.DNSProfile = "cloudflare-udp"
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	after, _ := ReadRegular(a.ConfigPath(), 4<<20)
	if bytes.Contains(after, []byte("magicnet-chain")) {
		t.Fatal("disabled chain retained a dangling reference")
	}
	if _, e = a.changeRuntimeSettings(ctx, func(s *RuntimeSettings) error { s.Block.Enabled = true; s.DNSProfile = "default"; return nil }); e != nil {
		t.Fatal(e)
	}
	after, _ = ReadRegular(a.ConfigPath(), 4<<20)
	var config M
	_ = DecodeJSON(after, &config)
	if findOutbound(config, "ad-block")["default"] != "block" {
		t.Fatal("block re-enable did not restore owned default")
	}
	for _, v := range rtArray(rtMap(config["dns"])["servers"]) {
		m := rtMap(v)
		if m["tag"] == "magicnet-dns-icloud" && m["server"] != "1.1.1.1" {
			t.Fatal("direct policy DNS reset to remote template")
		}
	}
	patch := M{"$magicnet_routing": M{"schema": 1, "rules": []any{M{"kind": "domain", "value": "retained-rule.example.invalid", "outbound": "direct"}}}}
	if _, e = a.OverrideOperation(ctx, "set", M{"patch": patch, "expected_revision": 0}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.OverrideOperation(ctx, "apply", M{"expected_revision": 1}); e != nil {
		t.Fatal(e)
	}
	if _, e = a.syncTemplate(ctx); e != nil {
		t.Fatal(e)
	}
	after, _ = ReadRegular(a.ConfigPath(), 4<<20)
	if !bytes.Contains(after, []byte("retained-rule.example.invalid")) || !bytes.Contains(after, []byte("entry.example.invalid")) {
		t.Fatal("template sync dropped active runtime intent or sources")
	}
	checkRealCore(t, a, after)
}

func TestOverridePreviewDoesNotInitializeConfiguration(t *testing.T) {
	a := realCoreFixture(t)
	if _, e := a.OverrideOperation(context.Background(), "preview", M{"patch": M{"inbounds": []any{}}}); e == nil {
		t.Fatal("invalid override preview accepted")
	}
	if _, e := os.Lstat(a.ConfigPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("invalid preview wrote active config", e)
	}
	if _, e := a.OverrideOperation(context.Background(), "preview", M{"patch": M{"log": M{"level": "info"}}}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(a.ConfigPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("valid preview wrote active config", e)
	}
	if _, e := os.Lstat(a.Path(".config", "magicnet", "selector-selections.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("preview persisted migration intentions", e)
	}
}

func TestSubscriptionScheduleOwnerAndBoundedCancellation(t *testing.T) {
	a := &App{Root: t.TempDir(), Platform: "linux"}
	ctx := context.Background()
	owner, e := newSubscriptionOwner("schedule-test")
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteJSON(a.Path(".state", "owners", "fswatch.json"), owner); e != nil {
		t.Fatal(e)
	}
	if e = WriteJSON(a.Path(".config", "magicnet", "subscription-schedule.json"), SubscriptionSchedule{"12", time.Now().Add(time.Hour).Unix()}); e != nil {
		t.Fatal(e)
	}
	status, e := a.SubscriptionScheduleStatus(ctx)
	if e != nil || status["owner"] != "active" || status["running"] != true || status["refreshing"] != false {
		t.Fatal("waiting scheduler was not observed", e, status)
	}
	if e = WriteJSON(a.Path(".config", "magicnet", "subscription-schedule.json"), SubscriptionSchedule{"12", 0}); e != nil {
		t.Fatal(e)
	}
	entered := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- a.tickSubscriptionSchedule(ctx, func(c context.Context) error { close(entered); <-c.Done(); return c.Err() })
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("scheduled task did not start")
	}
	start := time.Now()
	status, e = a.SetSubscriptionSchedule(ctx, "off")
	if e != nil || status["enabled"] != false || time.Since(start) > 9*time.Second {
		t.Fatal("off did not complete with bounded owned cancellation", e, status)
	}
	select {
	case e := <-finished:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("cancelled task result", e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled task did not exit")
	}
	schedule, e := a.subscriptionSchedule()
	if e != nil || schedule.IntervalHours != "off" || schedule.NextDueEpoch != 0 {
		t.Fatal("completion resurrected schedule", e, schedule)
	}
	if _, state, e := observeOwner(a.Path(".state", "owners", "fswatch.json")); e != nil || state != "active" {
		t.Fatal("turning off refresh killed independent supervisor", e, state)
	}
	if e = AtomicWrite(a.Path(".state", "private", "subscription-refresh-owner.json"), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = a.SetSubscriptionSchedule(ctx, "off"); ErrorCode(e) != "subscription.owner_unknown" {
		t.Fatal("unknown refresh owner was ignored", e)
	}
}

func TestRuntimeStatusReadsDoNotCreateState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-created")
	a := &App{Root: root, Platform: "linux"}
	for _, domain := range []string{"subscription", "subscription-refresh", "dns", "tailscale", "overrides"} {
		if _, e := a.RuntimeStatus(context.Background(), domain); e != nil {
			t.Fatal(domain, e)
		}
	}
	if _, e := os.Lstat(root); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("read-only runtime status initialized storage", e)
	}
}

func TestRealCoreWireGuardImportAndTailscaleUserspace(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	peer, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	wireguard := "[Interface]\nPrivateKey=" + base64.StdEncoding.EncodeToString(private.Bytes()) + "\nAddress=172.16.0.2/32,2606:4700:110:8765::2/128\nMTU=1280\n[Peer]\nPublicKey=" + base64.StdEncoding.EncodeToString(peer.PublicKey().Bytes()) + "\nEndpoint=198.51.100.1:2408\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\nReserved=1,2,3\n"
	payload := a.Path(".state", "private", "payload", "tmp", "wireguard.conf")
	if e = AtomicWrite(payload, []byte(wireguard), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = a.warpAction(ctx, []string{"import-file", payload}); e != nil {
		t.Fatal(e)
	}
	status, e := a.WarpStatus()
	if e != nil || status["enabled"] != false || status["configured"] != true {
		t.Fatal("disabled WireGuard import state", e, status)
	}
	if _, e = a.warpAction(ctx, []string{"enable"}); e != nil {
		t.Fatal(e)
	}
	raw, _ := ReadRegular(a.ConfigPath(), 4<<20)
	checkRealCore(t, a, raw)
	if _, e = a.warpAction(ctx, []string{"disable"}); e != nil {
		t.Fatal(e)
	}
	raw, _ = ReadRegular(a.ConfigPath(), 4<<20)
	var config M
	_ = DecodeJSON(raw, &config)
	key := "tskey-auth-synthetic-private-canary"
	config["endpoints"] = append(rtArray(config["endpoints"]), M{"type": "tailscale", "tag": "tailscale", "hostname": "synthetic", "auth_key": key, "system_interface": false})
	if _, e = a.saveEditedConfig(ctx, rtJSON(config)); e != nil {
		t.Fatal(e)
	}
	active, _ := ReadRegular(a.ConfigPath(), 4<<20)
	if bytes.Contains(active, []byte(key)) {
		t.Fatal("Tailscale auth leaked into active configuration")
	}
	checkRealCore(t, a, active)
	runtime, e := a.CoreConfigWithSecrets(active)
	if e != nil || !bytes.Contains(runtime, []byte(key)) {
		t.Fatal("private Tailscale credential was not injected at core boundary", e)
	}
	_ = DecodeJSON(active, &config)
	routes := rtArray(rtMap(config["route"])["rules"])
	preferred, lan := -1, -1
	for i, v := range routes {
		m := rtMap(v)
		if m["preferred_by"] != nil {
			preferred = i
		}
		if m["ip_is_private"] == true {
			lan = i
		}
	}
	if preferred < 0 || lan < 0 || preferred >= lan {
		t.Fatal("actual Tailnet route does not precede LAN classification")
	}
	ts, e := a.TailscaleStatus(ctx)
	if e != nil || rtMap(ts["effective"])["online"] != nil {
		t.Fatal("Tailscale status fabricated online connectivity", e)
	}
	for _, v := range rtArray(config["endpoints"]) {
		m := rtMap(v)
		if m["type"] == "tailscale" {
			m["system_interface"] = true
		}
	}
	if _, e = a.saveEditedConfig(ctx, rtJSON(config)); ErrorCode(e) != "tailscale.system_interface_forbidden" {
		t.Fatal("system TUN Tailscale was accepted", e)
	}
}

func TestSubscriptionPublicTokensRejectPrivateCanary(t *testing.T) {
	a := &App{Root: t.TempDir(), Platform: "linux"}
	last, e := a.subscriptionLast()
	if e != nil {
		t.Fatal(e)
	}
	last.NativeParser = "private-canary.example.invalid"
	if e = WriteJSON(a.subscriptionPrivate("last.json"), last); e != nil {
		t.Fatal(e)
	}
	if _, e = a.SubscriptionStatus(context.Background(), false); ErrorCode(e) != "machine.subscription_observation_failed" || strings.Contains(e.Error(), "private-canary") {
		t.Fatal("malformed public token escaped its whitelist", e)
	}
}

func TestRealCoreInterruptedInitializationRecoversForward(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	data, changes, e := a.initialConfigCandidate(ctx)
	if e != nil {
		t.Fatal(e)
	}
	changes = append(changes, RuntimeFileChange{Path: ".state/private/runtime-checkpoint.json", Data: rtJSON(a.RuntimeCheckpoint)}, RuntimeFileChange{Path: ".state/platform-owned.json", Data: rtJSON(a.PlatformOwned)}, RuntimeFileChange{Path: ".state/lifecycle/last-known-good.json", Data: data}, RuntimeFileChange{Path: ".config/sing-box/config.json", Data: data})
	before, e := a.snapshotFiles(changes)
	if e != nil {
		t.Fatal(e)
	}
	if e = WriteJSON(a.Path(".state", "private", "runtime-initialization.json"), RuntimeInitialization{1, data, changes, before}); e != nil {
		t.Fatal(e)
	}
	if e = AtomicWrite(a.Path(changes[0].Path), changes[0].Data, 0600); e != nil {
		t.Fatal(e)
	}
	a.ClearMaterialization()
	if e = a.RecoverRuntime(ctx); e != nil {
		t.Fatal(e)
	}
	active, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil || !bytes.Equal(active, data) {
		t.Fatal("initial generation was not recovered completely", e)
	}
	if e = a.RecoverRuntime(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(a.Path(".state", "private", "runtime-initialization.json")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("initialization evidence was not cleared after success", e)
	}
	checkRealCore(t, a, active)
}
