package magicnet

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) health(ctx context.Context) (M, error) {
	s, e := a.ServiceStatus(ctx)
	if e != nil {
		return nil, e
	}
	m := M{"service": s, "application_network": "unknown", "vpn_slot": "not_used", "diagnostic_scope": "control_and_kernel_observation"}
	for _, d := range []string{"subscription", "dns", "wifi", "hotspot", "tailscale", "transactions"} {
		v, er := a.publicDomain(ctx, d)
		if er != nil {
			v = M{"state": "unknown", "error_code": ErrorCode(er)}
		}
		m[d] = v
	}
	return m, nil
}
func (a *App) logList() (M, error) {
	entries, e := os.ReadDir(a.Path(".log"))
	if errors.Is(e, os.ErrNotExist) {
		return M{"files": []any{}}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []any{}
	for _, f := range entries {
		if f.Type().IsRegular() && safeToken(f.Name()) {
			st, e := f.Info()
			if e != nil {
				return nil, e
			}
			out = append(out, M{"name": f.Name(), "bytes": st.Size()})
		}
	}
	return M{"files": out}, nil
}
func (a *App) readLog(name string, lines int, redact bool) (M, error) {
	aliases := map[string]string{"sing-box": "core.log", "mcp": "mcp.log", "fswatch": "fswatch.log", "supervisors": "wifi-policy.log", "service": "service.log", "webui": "webui.log"}
	if x, ok := aliases[name]; ok {
		name = x
	}
	if !safeToken(name) {
		return nil, E("log.name_invalid", "Invalid log name.")
	}
	if lines <= 0 {
		lines = 100
	}
	if lines > 1000 {
		return nil, E("log.limit", "At most 1000 lines may be read.")
	}
	p := a.Path(".log", name)
	b, e := ReadRegular(p, 8<<20)
	if e != nil {
		return nil, E("log.unavailable", "The requested log is unavailable.")
	}
	ls := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(ls) > lines {
		ls = ls[len(ls)-lines:]
	}
	if redact {
		for i, line := range ls {
			level := "event"
			for _, l := range []string{"ERROR", "WARN", "INFO", "DEBUG", "TRACE"} {
				if strings.Contains(strings.ToUpper(line), l) {
					level = strings.ToLower(l)
					break
				}
			}
			ls[i] = level + ": private diagnostic content withheld"
		}
	}
	return M{"text": strings.Join(ls, "\n") + "\n", "redacted": redact, "line_count": len(ls)}, nil
}
func (a *App) supportBundle(ctx context.Context) (M, error) {
	m, e := a.health(ctx)
	if e != nil {
		return nil, e
	}
	data, e := json.MarshalIndent(M{"schema": 1, "version": Version, "observations": m, "private_data": "excluded", "created_epoch": time.Now().Unix()}, "", "  ")
	if e != nil {
		return nil, e
	}
	p := a.Path(".state", "support", "support-"+token()+".json")
	if e = AtomicWrite(p, data, 0600); e != nil {
		return nil, e
	}
	return M{"path": p, "bytes": len(data), "redacted": true}, nil
}
func (a *App) topology(ctx context.Context) (M, error) {
	ifs, e := net.Interfaces()
	if e != nil {
		return nil, E("topology.observation_failed", "Cannot enumerate network interfaces.")
	}
	items := []any{}
	for _, in := range ifs {
		addrs, e := in.Addrs()
		if e != nil {
			return nil, e
		}
		addresses := []string{}
		for _, ad := range addrs {
			addresses = append(addresses, ad.String())
		}
		items = append(items, M{"name": in.Name, "index": in.Index, "mtu": in.MTU, "flags": in.Flags.String(), "addresses": addresses})
	}
	r, e := a.sysroute(ctx, []string{"snapshot"})
	if e != nil {
		r = M{"state": "unknown"}
	}
	return M{"interfaces": items, "routing": r, "private_network_metadata": true}, nil
}
func (a *App) sysroute(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "A route action is required.")
	}
	act := args[0]
	tool := a.findTool("ip")
	if act == "snapshot" || act == "list" {
		m := M{}
		for _, family := range []string{"-4", "-6"} {
			for _, kind := range []string{"rule", "route"} {
				r, e := Run(ctx, a.Root, tool, []string{family, kind, "show", "table", "all"}, nil, 256<<10)
				if e != nil {
					return nil, E("route.observation_failed", "Cannot read route and rule tables.")
				}
				m[family+kind] = string(r.Stdout)
			}
		}
		return m, nil
	}
	cmd := []string{}
	switch act {
	case "add-rule":
		if len(args) != 3 {
			return nil, E("route.arguments", "Priority and table are required.")
		}
		for _, x := range args[1:] {
			n, e := strconv.Atoi(x)
			if e != nil || n < 1 {
				return nil, E("route.arguments", "Numeric route identity is required.")
			}
		}
		cmd = []string{"rule", "add", "priority", args[1], "lookup", args[2]}
	case "del-rule":
		if len(args) != 2 {
			return nil, E("route.arguments", "Priority is required.")
		}
		cmd = []string{"rule", "del", "priority", args[1]}
	case "add-route":
		if len(args) < 4 || len(args) > 5 {
			return nil, E("route.arguments", "Table, destination and device are required.")
		}
		cmd = []string{"route", "add", "table", args[1], args[2], "dev", args[3], "proto", "186"}
		if len(args) == 5 {
			cmd = append(cmd, "via", args[4])
		}
	case "del-route":
		if len(args) != 3 {
			return nil, E("route.arguments", "Table and destination are required.")
		}
		cmd = []string{"route", "del", "table", args[1], args[2], "proto", "186"}
	default:
		return nil, E("route.arguments", "Unknown route operation.")
	}
	for _, x := range args[1:] {
		if strings.HasPrefix(x, "-") || strings.ContainsAny(x, "\x00\r\n\t ") {
			return nil, E("route.arguments", "Invalid route argument.")
		}
	}
	var journal [][]string
	jp := a.Path(".state", "sysroute", "owned.json")
	e := ReadJSON(jp, 64<<10, &journal)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if strings.HasPrefix(act, "del") {
		match := -1
		for i, old := range journal {
			matches := act == "del-rule" && len(old) == 6 && old[0] == "rule" && old[1] == "add" && old[2] == "priority" && old[3] == args[1]
			matches = matches || act == "del-route" && len(old) >= 9 && old[0] == "route" && old[1] == "add" && old[2] == "table" && old[3] == args[1] && old[4] == args[2]
			if matches {
				if match >= 0 {
					return nil, E("route.identity_ambiguous", "More than one owned route matches; select a unique identity.")
				}
				match = i
				cmd = append([]string{}, old...)
				cmd[1] = "del"
			}
		}
		if match < 0 {
			return nil, E("route.not_owned", "This rule or route is not owned by MagicNet.")
		}
		if _, e = Run(ctx, a.Root, tool, cmd, nil, 64<<10); e != nil {
			return nil, e
		}
		journal = append(journal[:match], journal[match+1:]...)
	} else {
		if _, e = Run(ctx, a.Root, tool, cmd, nil, 64<<10); e != nil {
			return nil, e
		}
		journal = append(journal, cmd)
	}
	if e = WriteJSON(jp, journal); e != nil {
		return nil, e
	}
	return M{"changed": true}, nil
}
func (a *App) closeConnections(ctx context.Context, args []string) (M, error) {
	m, e := a.API(ctx, "GET", "/connections", nil)
	if e != nil {
		return nil, e
	}
	xs, _ := m["connections"].([]any)
	limit := 10
	if args[0] == "close-top" && len(args) > 1 {
		limit, e = strconv.Atoi(args[1])
		if e != nil || limit < 1 || limit > 1000 {
			return nil, E("connection.limit", "Count must be 1–1000.")
		}
	}
	sort.SliceStable(xs, func(i, j int) bool {
		mi, _ := xs[i].(map[string]any)
		mj, _ := xs[j].(map[string]any)
		return asInt(mi["upload"])+asInt(mi["download"]) > asInt(mj["upload"])+asInt(mj["download"])
	})
	closed := 0
	for _, x := range xs {
		m, _ := x.(map[string]any)
		if args[0] == "close-matching" {
			if len(args) != 2 {
				return nil, E("connection.arguments", "A text query is required.")
			}
			b, _ := json.Marshal(m["metadata"])
			if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(args[1])) {
				continue
			}
		} else if closed >= limit {
			break
		}
		if _, e = a.API(ctx, "DELETE", "/connections/"+url.PathEscape(asString(m["id"])), nil); e != nil {
			return nil, e
		}
		closed++
	}
	return M{"closed_count": closed}, nil
}
func (a *App) testAllNodes(ctx context.Context, names []string) (M, error) {
	if len(names) == 0 {
		m, e := a.API(ctx, "GET", "/proxies", nil)
		if e != nil {
			return nil, e
		}
		ps, _ := m["proxies"].(map[string]any)
		for n, v := range ps {
			m, _ := v.(map[string]any)
			if !stringIn(strings.ToLower(asString(m["type"])), "selector", "urltest", "direct", "reject") {
				names = append(names, n)
			}
		}
		sort.Strings(names)
	}
	if len(names) > 2048 {
		return nil, E("node.limit", "Too many nodes in one test.")
	}
	results := []any{}
	for _, n := range names {
		m, e := a.API(ctx, "GET", "/proxies/"+url.PathEscape(n)+"/delay?timeout=5000&url="+url.QueryEscape("https://www.gstatic.com/generate_204"), nil)
		r := M{"name": n, "ok": e == nil}
		if e == nil {
			r["result"] = m
		} else {
			r["error_code"] = ErrorCode(e)
		}
		results = append(results, r)
		if ctx.Err() != nil {
			break
		}
	}
	return M{"results": results}, nil
}
func (a *App) httpProbe(ctx context.Context, target string, proxy bool, max int64) (M, error) {
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: nil}
	if proxy {
		u, _ := url.Parse("http://127.0.0.1:7892")
		tr.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(c, "GET", target, nil)
	if e != nil {
		return nil, e
	}
	start := time.Now()
	resp, e := client.Do(req)
	if e != nil {
		return nil, E("probe.transport_failed", "The network probe failed.")
	}
	defer resp.Body.Close()
	n, e := io.Copy(io.Discard, io.LimitReader(resp.Body, max))
	if e != nil {
		return nil, E("probe.read_failed", "The network response was incomplete.")
	}
	return M{"http_status": resp.StatusCode, "bytes": n, "elapsed_ms": float64(time.Since(start).Microseconds()) / 1000, "transport_success": true, "application_success": resp.StatusCode >= 200 && resp.StatusCode < 300}, nil
}
func (a *App) pingTest(ctx context.Context) (M, error) {
	results := []any{}
	for _, p := range []struct {
		name, url string
		proxy     bool
	}{{"domestic", "https://connect.rom.miui.com/generate_204", false}, {"global", "https://www.gstatic.com/generate_204", true}} {
		m, e := a.httpProbe(ctx, p.url, p.proxy, 64<<10)
		if e != nil {
			m = M{"ok": false, "error_code": ErrorCode(e)}
		}
		m["kind"] = p.name
		results = append(results, m)
	}
	return M{"method": "http_delay", "results": results, "real_app_traffic": "not_measured"}, nil
}
func (a *App) speedTest(ctx context.Context) (M, error) {
	results := []any{}
	for _, proxy := range []bool{false, true} {
		m, e := a.httpProbe(ctx, "https://speed.cloudflare.com/__down?bytes=5242880", proxy, 5<<20)
		if e != nil {
			m = M{"ok": false, "error_code": ErrorCode(e)}
		}
		m["proxy"] = proxy
		results = append(results, m)
	}
	return M{"maximum_download_bytes": 10 << 20, "results": results}, nil
}
func secureZip(data []byte, limit int64) (map[string][]byte, error) {
	r, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return nil, E("archive.invalid", "Invalid ZIP archive.")
	}
	if len(r.File) > 10000 {
		return nil, E("archive.limit", "Too many archive entries.")
	}
	out := map[string][]byte{}
	seen := map[string]bool{}
	var total int64
	for _, f := range r.File {
		name := f.Name
		if name == "" || strings.HasPrefix(name, "../") || name == ".." || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || filepath.Clean(name) != strings.TrimSuffix(name, "/") || strings.Contains(name, "\x00") || f.Mode()&os.ModeSymlink != 0 || f.Mode()&07000 != 0 {
			return nil, E("archive.unsafe", "Unsafe archive entry.")
		}
		if seen[name] {
			return nil, E("archive.duplicate", "Duplicate archive entry.")
		}
		seen[name] = true
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() {
			return nil, E("archive.unsafe", "Only regular files are allowed.")
		}
		total += int64(f.UncompressedSize64)
		if total > limit {
			return nil, E("archive.limit", "Archive exceeds its extraction limit.")
		}
		rc, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(rc, limit+1))
		rc.Close()
		if e != nil || int64(len(b)) != int64(f.UncompressedSize64) {
			return nil, E("archive.invalid", "Archive entry integrity failed.")
		}
		out[name] = b
	}
	return out, nil
}
func sealBackup(data []byte, password string) ([]byte, error) {
	if password == "" {
		return append([]byte("MNBACKUP1\x00"), data...), nil
	}
	salt := make([]byte, 32)
	rand.Read(salt)
	key, e := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	head := append([]byte("MNBACKUP1\x01"), salt...)
	head = append(head, nonce...)
	return append(head, gcm.Seal(nil, nonce, data, head)...), nil
}
func openBackup(data []byte, password string) ([]byte, error) {
	if len(data) < 10 || string(data[:9]) != "MNBACKUP1" {
		return nil, E("backup.invalid", "Invalid backup format.")
	}
	if data[9] == 0 {
		return data[10:], nil
	}
	if data[9] != 1 || len(data) < 54 {
		return nil, E("backup.invalid", "Invalid encrypted backup.")
	}
	key, e := pbkdf2.Key(sha256.New, password, data[10:42], 600000, 32)
	if e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, e := gcm.Open(nil, data[42:54], data[54:], data[:54])
	if e != nil {
		return nil, E("backup.authentication_failed", "Backup password or authentication is invalid.")
	}
	return plain, nil
}
func (a *App) backup(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "A backup action is required.")
	}
	if stringIn(args[0], "export-payload", "restore-payload") {
		if len(args) != 2 {
			return nil, E("backup.arguments", "A private payload path is required.")
		}
		b, e := a.consumePayload(args[1], 8<<20)
		if e != nil {
			return nil, e
		}
		var payload M
		if DecodeJSON(b, &payload) != nil {
			return nil, E("backup.invalid", "Invalid backup payload.")
		}
		password, ok := payload["password"].(string)
		if !ok {
			return nil, E("backup.invalid", "Backup password must be a string.")
		}
		if args[0] == "export-payload" {
			if len(payload) != 1 {
				return nil, E("backup.invalid", "Unknown backup payload field.")
			}
			return a.backup(ctx, []string{"export", password})
		}
		archive, ok := payload["archive_base64"].(string)
		if !ok || len(payload) != 2 {
			return nil, E("backup.invalid", "Invalid backup archive payload.")
		}
		return a.backup(ctx, []string{"restore", password, archive})
	}
	password := ""
	if len(args) > 1 && args[1] != "-" {
		password = args[1]
	}
	if args[0] == "export" {
		return a.exportBackup(ctx, password)
	}

	if !stringIn(args[0], "restore", "restore-file") || len(args) != 3 {
		return nil, E("backup.arguments", "Password and backup input are required.")
	}
	var b []byte
	var e error
	if args[0] == "restore" {
		b, e = base64.StdEncoding.Strict().DecodeString(args[2])
	} else {
		b, e = ReadRegular(args[2], 48<<20)
	}
	if e != nil || len(b) > 48<<20 {
		return nil, E("backup.invalid", "Backup input is invalid.")
	}
	b, e = openBackup(b, password)
	if e != nil {
		return nil, e
	}
	files, e := secureZip(b, 64<<20)
	if e != nil {
		return nil, e
	}
	for p := range files {
		if !backupAllowed(p) {
			return nil, E("backup.unsafe", "Backup contains an unapproved path.")
		}
	}
	return a.restoreBackup(ctx, files)
}

func (a *App) installModule(ctx context.Context) error {
	if e := a.WithLifecycleLock(ctx, 10*time.Second, func() error {
		if e := a.RecoverRuntime(ctx); e != nil {
			return e
		}
		return a.EnsureDefaultConfig(ctx)
	}); e != nil {
		return e
	}
	return a.Publish(ctx)
}

var _ = binary.BigEndian
var _ = regexp.MustCompile

func backupAllowed(p string) bool {
	return strings.HasPrefix(p, ".config/") && !strings.HasPrefix(p, ".config/sing-box/rules/") || strings.HasPrefix(p, ".state/private/subscription/generations/") || strings.HasPrefix(p, ".state/private/tailscale/") || stringIn(p, ".state/private/runtime-checkpoint.json", ".state/platform-owned.json", ".state/lifecycle/last-known-good.json", ".state/private/subscription/last.json")
}
func (a *App) exportBackup(ctx context.Context, password string) (M, error) {
	var result M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		for _, p := range []string{".state/private/runtime-transaction.json", ".state/private/runtime-initialization.json", ".state/private/runtime-path-relocation.json", ".state/private/subscription/journal.json", ".state/lifecycle/journal.json", ".state/backup/restore-journal.json"} {
			if _, e := os.Stat(a.Path(p)); e == nil {
				return E("backup.recovery_pending", "Complete pending recovery before exporting a backup.")
			}
		}
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		files, e := a.backupCurrent()
		if e != nil {
			return e
		}
		paths := make([]string, 0, len(files))
		for p := range files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			w, e := zw.Create(p)
			if e != nil {
				return e
			}
			if _, e = w.Write(files[p]); e != nil {
				return e
			}
		}
		if e := zw.Close(); e != nil {
			return e
		}
		b, e := sealBackup(buf.Bytes(), password)
		if e != nil {
			return e
		}
		result = M{"text": base64.StdEncoding.EncodeToString(b) + "\n", "encrypted": password != ""}
		return nil
	})
	return result, e
}
