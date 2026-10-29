package magicnet

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMachineDispatchRejectsMutation(t *testing.T) {
	a := &App{Root: t.TempDir(), Platform: "linux"}
	for _, args := range [][]string{{"--json", "service", "stop"}, {"service", "stop", "--json"}, {"--json", "--json", "capabilities"}, {"--json", "service", "status", "trailing"}, {"--json", "nonsense"}} {
		var out, errout bytes.Buffer
		if code := a.RunCLI(context.Background(), args, &out, &errout); code == 0 {
			t.Fatalf("accepted %v", args)
		}
		var env Envelope
		if e := json.Unmarshal(out.Bytes(), &env); e != nil || env.Schema != 1 || env.OK || env.Error == nil {
			t.Fatalf("bad envelope %v %s", e, out.String())
		}
		entries, _ := os.ReadDir(a.Root)
		if len(entries) != 0 {
			t.Fatal("rejected machine mutation wrote files")
		}
	}
	for _, args := range [][]string{{"--json", "capabilities"}, {"capabilities", "--json"}} {
		m, e, _, _ := a.Execute(context.Background(), args)
		if e != nil || m["machine_schema"] != 1 {
			t.Fatal(e, m)
		}
	}
}
func TestPrivateFilesAreBoundedAndNoLinks(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "data")
	if e := AtomicWrite(p, []byte("canary"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadRegular(p, 3); e == nil {
		t.Fatal("over limit accepted")
	}
	os.Symlink(p, filepath.Join(d, "link"))
	if _, e := ReadRegular(filepath.Join(d, "link"), 64); e == nil {
		t.Fatal("symlink read")
	}
	os.Link(p, filepath.Join(d, "hard"))
	if _, e := ReadRegular(p, 64); e == nil {
		t.Fatal("hard link read")
	}
}
func TestJSONDuplicateAndTrailing(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `{} {}`, `[1,]`} {
		var m any
		if DecodeJSON([]byte(s), &m) == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestGenericMCPPrivacy(t *testing.T) {
	for _, a := range [][]string{{"sub", "inspect"}, {"--json", "app", "inspect"}, {"diagnose", "anything"}, {"wifi", "check"}, {"mcp", "secret"}, {"config-editor", "get", "sing-box"}, {"backup", "export"}, {"__worker"}, {"sub", "user-agent", "get"}} {
		if genericAllowed(a) {
			t.Fatalf("private bypass %v", a)
		}
	}
	for _, a := range [][]string{{"node", "test", "__example"}, {"wifi", "add-ssid", "__network"}, {"--json", "service", "status"}} {
		if !genericAllowed(a) {
			t.Fatalf("ordinary argument rejected %v", a)
		}
	}
}
func TestMCPCatalogSchema(t *testing.T) {
	var tools []M
	if e := DecodeJSON(catalogJSON, &tools); e != nil {
		t.Fatal(e)
	}
	if len(tools) != 85 {
		t.Fatal(len(tools))
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		n := asString(tool["name"])
		if n == "" || seen[n] {
			t.Fatal(n)
		}
		seen[n] = true
		s, _ := tool["inputSchema"].(map[string]any)
		if s["additionalProperties"] != false {
			t.Fatal("open schema", n)
		}
		if checkSchema(s, M{"unexpected": "value"}) == nil {
			t.Fatal("unknown property", n)
		}
	}
}
func TestBackupAuthentication(t *testing.T) {
	b, e := sealBackup([]byte("private-test-config"), "synthetic-password")
	if e != nil {
		t.Fatal(e)
	}
	plain, e := openBackup(b, "synthetic-password")
	if e != nil || string(plain) != "private-test-config" {
		t.Fatal(e)
	}
	if _, e = openBackup(b, "wrong-password"); e == nil {
		t.Fatal("wrong password accepted")
	}
	b[len(b)-1] ^= 1
	if _, e = openBackup(b, "synthetic-password"); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestZipPathAndDuplicate(t *testing.T) {
	for _, names := range [][]string{{"../escape"}, {"/escape"}, {"a", "a"}, {"dir/../../escape"}} {
		var b bytes.Buffer
		z := zip.NewWriter(&b)
		for _, n := range names {
			w, _ := z.Create(n)
			w.Write([]byte("x"))
		}
		z.Close()
		if _, e := secureZip(b.Bytes(), 1<<20); e == nil {
			t.Fatal("unsafe zip accepted", names)
		}
	}
}
func TestRunnerLimitsAndTimeout(t *testing.T) {
	a := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e := Run(ctx, a, "/bin/sh", []string{"-c", "sleep 5"}, nil, 1000)
	if e == nil || time.Since(start) > time.Second {
		t.Fatal("timeout not bounded", e, time.Since(start))
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, e = Run(ctx2, a, "/bin/sh", []string{"-c", "printf '%02000d' 0; printf '%02000d' 0 >&2"}, nil, 100)
	if ErrorCode(e) != "command.output_limit" {
		t.Fatal("output limit", e)
	}
}
func TestModeFileStrict(t *testing.T) {
	a := &App{Root: t.TempDir()}
	if m, e := a.transparentMode(); m != "tun" || e != nil {
		t.Fatal(m, e)
	}
	p := a.Path(".config", "magicnet", "transparent.conf")
	for _, v := range []string{"", "auto", "tun\nebpf", "mode=tun\nmode=tun", "tun\x00"} {
		AtomicWrite(p, []byte(v), 0600)
		if _, e := a.transparentMode(); e == nil {
			t.Fatal("accepted invalid", v)
		}
	}
	for _, v := range []string{"ebpf", "mode=tun\r\n"} {
		AtomicWrite(p, []byte(v), 0600)
		if _, e := a.transparentMode(); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPublicProjectionDoesNotReadPrivateValues(t *testing.T) {
	a := &App{Root: t.TempDir(), Platform: "linux"}
	canary := "UNIQUE_PRIVATE_CANARY"
	p := PlatformSettings{AppMode: "blacklist", Apps: map[string]string{"com." + canary: "proxy"}, WiFi: WiFiSettings{Mode: "blacklist", Interval: 10, SSIDs: []string{canary}, BSSIDs: []string{}}}
	a.savePlatform(p)
	for _, domain := range []string{"service", "transparent", "wifi", "app-policy", "hotspot"} {
		m, e := a.publicDomain(context.Background(), domain)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), canary) || strings.Contains(string(canonicalTokens(domain, m)), canary) {
			t.Fatal("private projection leak", domain)
		}
	}
}
