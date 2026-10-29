package magicnet

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/netlink"
)

func TestRealCorePlatformTransactionsStayStopped(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	if e := a.EnsureDefaultConfig(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e, handled := a.HandleRuntime(ctx, []string{"network", "set", "ipv4_only", "1300", "3m"}, false); e != nil || !handled {
		t.Fatal(e)
	}
	for _, mode := range []string{"ebpf", "tun", "tun"} {
		m, e, handled := a.handlePlatform(ctx, []string{"transparent", "set", mode}, false)
		if e != nil || !handled || m["applied"] != true {
			t.Fatalf("%s %v %v", mode, m, e)
		}
		if mode2, e := a.transparentMode(); e != nil || mode2 != mode {
			t.Fatal(mode2, e)
		}
		if e := a.CheckConfig(ctx, mustRead(t, a.ConfigPath())); e != nil {
			t.Fatal(e)
		}
		var conf M
		DecodeJSON(mustRead(t, a.ConfigPath()), &conf)
		for _, v := range rtArray(conf["inbounds"]) {
			in := rtMap(v)
			if in["tag"] != "tun-in" {
				continue
			}
			if mode == "ebpf" {
				if rtMap(in["local"])["ipv6"] != false || rtMap(in["shared"])["ipv6"] != false {
					t.Fatal("IPv6-only intent lost in eBPF")
				}
			} else if asInt(in["mtu"]) != 1300 || len(rtArray(in["address"])) != 1 {
				t.Fatal("network intent lost after TUN switch", in)
			}
		}
	}
	before := mustRead(t, a.ConfigPath())
	modeBefore := mustRead(t, a.Path(".config", "magicnet", "transparent.conf"))
	if _, e, _ := a.handlePlatform(ctx, []string{"transparent", "set", "redirect"}, false); e == nil {
		t.Fatal("invalid mode accepted")
	}
	if !bytes.Equal(before, mustRead(t, a.ConfigPath())) || !bytes.Equal(modeBefore, mustRead(t, a.Path(".config", "magicnet", "transparent.conf"))) {
		t.Fatal("invalid mode changed intent")
	}
	for _, args := range [][]string{{"app", "mode", "whitelist"}, {"app", "mode", "blacklist"}, {"hotspot", "enable"}, {"hotspot", "disable"}} {
		if _, e, _ := a.handlePlatform(ctx, args, false); e != nil {
			t.Fatal(args, e)
		}
	}
	if _, state, _ := observeOwner(a.Path(".state", "owners", "core.json")); state != "none" {
		t.Fatal("platform mutation started core", state)
	}
}
func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, e := ReadRegular(p, 64<<20)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestRealCoreBackupRecoveryAndConflict(t *testing.T) {
	for _, phase := range []string{"prepared", "partial", "written", "committed", "external"} {
		t.Run(phase, func(t *testing.T) {
			a := realCoreFixture(t)
			ctx := context.Background()
			if e := a.EnsureDefaultConfig(ctx); e != nil {
				t.Fatal(e)
			}
			old, e := a.backupCurrent()
			if e != nil {
				t.Fatal(e)
			}
			next := map[string][]byte{}
			for p, b := range old {
				next[p] = append([]byte{}, b...)
			}
			var config M
			DecodeJSON(next[".config/sing-box/config.json"], &config)
			config["log"] = M{"level": "warn"}
			next[".config/sing-box/config.json"] = rtJSON(config)
			p := ".config/magicnet/synthetic-private"
			old[p] = nil
			next[p] = []byte("private-synthetic")
			j := backupJournal{Old: old, Next: next, Phase: "writing"}
			if phase == "committed" {
				j.Phase = "committed"
			}
			if phase != "prepared" {
				AtomicWrite(a.Path(p), next[p], 0600)
			}
			if phase == "written" || phase == "committed" {
				AtomicWrite(a.ConfigPath(), next[".config/sing-box/config.json"], 0600)
			}
			if phase == "external" {
				AtomicWrite(a.Path(p), []byte("newer-external-intent"), 0600)
			}
			if e := WriteJSON(a.Path(".state", "backup", "restore-journal.json"), j); e != nil {
				t.Fatal(e)
			}
			e = a.WithLifecycleLock(ctx, time.Second, func() error { return a.recoverBackup(ctx) })
			if phase == "external" {
				if ErrorCode(e) != "backup.rollback_conflict" || string(mustRead(t, a.Path(p))) != "newer-external-intent" {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			want := old[".config/sing-box/config.json"]
			if phase == "committed" {
				want = next[".config/sing-box/config.json"]
			}
			if !bytes.Equal(want, mustRead(t, a.ConfigPath())) {
				t.Fatal("wrong recovery baseline")
			}
			if _, e := os.Stat(a.Path(".state", "backup", "restore-journal.json")); !os.IsNotExist(e) {
				t.Fatal("journal remained", e)
			}
		})
	}
}

func TestHotspotIdentityDoesNotAdoptForeignRules(t *testing.T) {
	r := hotspotResource{Kind: "rule", Family: netlink.FAMILY_V4, Interface: "wlan99", Phase: "installed"}
	good := *r.rule()
	if !sameHotspotRule(good, *r.rule()) {
		t.Fatal("exact rule rejected")
	}
	good.Mark = 1
	if sameHotspotRule(good, *r.rule()) {
		t.Fatal("foreign mark adopted")
	}
	q := hotspotResource{Kind: "route", Family: netlink.FAMILY_V6, Interface: "magicnet0", Index: 55, Prefix: "::/0", Phase: "installed"}
	route := *q.route()
	if !sameHotspotRoute(route, *q.route()) {
		t.Fatal("exact route rejected")
	}
	route.Protocol = 99
	if sameHotspotRoute(route, *q.route()) {
		t.Fatal("foreign protocol adopted")
	}
	route = *q.route()
	route.LinkIndex = 56
	if sameHotspotRoute(route, *q.route()) {
		t.Fatal("reused name adopted")
	}
}

func TestInheritedWorkerLockRetainsOwnership(t *testing.T) {
	a := &App{Root: t.TempDir()}
	ctx := context.Background()
	e := a.withLockFD(ctx, "inherited", time.Second, func(f *os.File) error {
		_, e := a.spawnOwnedFiles("lock-child", "/usr/bin/sleep", []string{"10"}, "fixture", "", []*os.File{f})
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	defer stopOwner(ctx, a.Path(".state", "owners", "lock-child.json"))
	if e := a.withLock(ctx, "inherited", 0, func() error { return nil }); ErrorCode(e) != "operation.busy" {
		t.Fatal("inherited lock was released", e)
	}
	if e := stopOwner(ctx, a.Path(".state", "owners", "lock-child.json")); e != nil {
		t.Fatal(e)
	}
	if e := a.withLock(ctx, "inherited", time.Second, func() error { return nil }); e != nil {
		t.Fatal("reaped child retained lock", e)
	}
}

func TestRealCoreFiveOwnedProcessStopCycles(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	path := a.Path("synthetic-core.json")
	if e := WriteJSON(path, M{"log": M{"level": "error"}, "outbounds": []any{M{"type": "direct", "tag": "direct"}}}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		o, e := a.spawnOwned("core", a.corePath(), []string{"run", "-c", path}, "cycle-"+strconv.Itoa(i), "")
		if e != nil {
			t.Fatal(e)
		}
		time.Sleep(80 * time.Millisecond)
		if _, state, e := observeOwner(a.Path(".state", "owners", "core.json")); e != nil || state != "active" {
			t.Fatal(state, e)
		}
		if e = a.stopCore(ctx); e != nil {
			t.Fatal(e)
		}
		if _, e = procStart(o.PID); !os.IsNotExist(e) {
			t.Fatal("owned core remains", e)
		}
	}
}

func TestUpdateReplayAndDurableRecord(t *testing.T) {
	a := &App{Root: t.TempDir(), Platform: "linux"}
	l := UpdateLedger{Used: map[string]string{"abcdefgh": "fixed-intent"}, Results: map[string]UpdateIntent{}, Order: []string{}}
	i := UpdateIntent{ID: "abcdefgh", Action: "check", Phase: "available", Baseline: "v0.3.1", Release: OfficialRelease{Tag: "v0.3.2"}, Error: "none"}
	if e := a.recordUpdateWithLedger(i, l); e != nil {
		t.Fatal(e)
	}
	actual, e := a.readLedger()
	if e != nil {
		t.Fatal(e)
	}
	if m, e, found := updateReplay(actual, i.ID, "fixed-intent"); e != nil || !found || m["replayed"] != true {
		t.Fatal(m, e)
	}
	if _, e, found := updateReplay(actual, i.ID, "different-intent"); !found || ErrorCode(e) != "module-update.conflict" {
		t.Fatal(e)
	}
	delete(actual.Results, i.ID)
	if _, e, found := updateReplay(actual, i.ID, "fixed-intent"); !found || ErrorCode(e) != "module-update.receipt_expired" {
		t.Fatal(e)
	}
	private := a.Path(".config", "magicnet", "module-update.conf")
	var intent UpdateIntent
	if e := ReadJSON(private, 128<<10, &intent); e != nil || intent.Release.Tag != "v0.3.2" {
		t.Fatal(e, intent)
	}
	if _, e := os.Stat(a.Path(".state", "module-update", "record-journal.json")); !os.IsNotExist(e) {
		t.Fatal("record not cleared", e)
	}
}

func TestCaptureHelperFailureIsNotSuccess(t *testing.T) {
	a := &App{Root: t.TempDir()}
	script := []byte("#!/bin/sh\nprintf '%s\\n' 'synthetic capture failure' >&2\nexit 7\n")
	if e := AtomicWrite(a.Path("bin", "ecapture"), script, 0700); e != nil {
		t.Fatal(e)
	}
	m, e := a.ecapture(context.Background(), []string{"tls", "1", "all", "all"})
	if ErrorCode(e) != "ecapture.capture_failed" || m["capture_success"] != nil {
		t.Fatal(m, e)
	}
	paths, e := goTLSExecutables(strconv.Itoa(os.Getpid()), strconv.Itoa(os.Geteuid()))
	if e != nil || len(paths) != 1 {
		t.Fatal(paths, e)
	}
	if !filepath.IsAbs(paths[0]) {
		t.Fatal(paths)
	}
}

func TestMCPBackupPayloadPrivacyAndCanonicalShape(t *testing.T) {
	if genericAllowed([]string{"backup", "export-payload", "synthetic"}) {
		t.Fatal("private alias accepted")
	}
	a := &App{Root: t.TempDir()}
	if e := AtomicWrite(a.Path(".log", "core.log"), []byte("INFO password=PRIVATE_TEST_CANARY\n"), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := a.readLog("sing-box", 10, true)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(m)
	if bytes.Contains(b, []byte("PRIVATE_TEST_CANARY")) {
		t.Fatal("private log leaked")
	}
}

func TestSysrouteDeletionUsesExactOwnedIdentity(t *testing.T) {
	a := &App{Root: t.TempDir()}
	ctx := context.Background()
	if e := AtomicWrite(a.Path("bin", "ip"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$MAGICNET_MODULE_ROOT/ip-argv.log\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"add-rule", "17101", "27101"}, {"del-rule", "17101"}, {"add-route", "27101", "198.51.100.0/24", "synthetic0"}, {"del-route", "27101", "198.51.100.0/24"}} {
		if _, e := a.sysroute(ctx, args); e != nil {
			t.Fatal(args, e)
		}
	}
	b := mustRead(t, a.Path("ip-argv.log"))
	if !bytes.Contains(b, []byte("rule del priority 17101 lookup 27101")) || !bytes.Contains(b, []byte("route del table 27101 198.51.100.0/24 dev synthetic0 proto 186")) {
		t.Fatal("delete lost ownership fields", string(b))
	}
	if _, e := a.sysroute(ctx, []string{"del-rule", "17101"}); ErrorCode(e) != "route.not_owned" {
		t.Fatal(e)
	}
	if !bytes.Equal(b, mustRead(t, a.Path("ip-argv.log"))) {
		t.Fatal("unowned deletion reached helper")
	}
}
func TestChangedCommandOwnerIsNeverKilled(t *testing.T) {
	a := &App{Root: t.TempDir()}
	ctx := context.Background()
	o, e := a.spawnOwned("command-test", "/usr/bin/sleep", []string{"10"}, "fixture", "")
	if e != nil {
		t.Fatal(e)
	}
	p := a.Path(".state", "owners", "command-test.json")
	defer func() { WriteJSON(p, o); stopOwner(ctx, p) }()
	wrong := *o
	wrong.CommandHash = digest([]byte("different command"))
	if e = WriteJSON(p, wrong); e != nil {
		t.Fatal(e)
	}
	if e = stopOwner(ctx, p); ErrorCode(e) != "process.ownership_unknown" {
		t.Fatal(e)
	}
	if _, e = procStart(o.PID); e != nil {
		t.Fatal("wrong-command process was killed", e)
	}
}
