package magicnet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const officialAPI = "https://api.github.com/repos/LIghtJUNction/MagicNet"

type ReleaseAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
type OfficialRelease struct {
	Tag        string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []ReleaseAsset `json:"assets"`
}
type UpdateIntent struct {
	ID                string          `json:"request_id"`
	Action            string          `json:"action"`
	ExpectedInstalled string          `json:"expected_installed"`
	ExpectedLatest    string          `json:"expected_latest"`
	Accepted          int64           `json:"accepted_epoch"`
	Boot              string          `json:"boot"`
	Baseline          string          `json:"baseline"`
	Release           OfficialRelease `json:"release"`
	Phase             string          `json:"phase"`
	Error             string          `json:"error_code"`
	Recovery          bool            `json:"recovery_required"`
	StagedCLI         string          `json:"staged_cli_hash"`
}
type UpdateLedger struct {
	Used    map[string]string       `json:"used"`
	Results map[string]UpdateIntent `json:"results"`
	Order   []string                `json:"order"`
}

var semver = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (a *App) downloadPublic(ctx context.Context, raw, accept string, limit int64, official bool) (string, http.Header, error) {
	normalized, e := NormalizeSubscriptionURL(raw)
	if e != nil {
		return "", nil, E("download.url_policy", "The download URL was rejected.")
	}
	c, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	for hop := 0; hop <= 5; hop++ {
		u, e := url.Parse(normalized)
		if e != nil {
			return "", nil, e
		}
		if official && !stringIn(u.Hostname(), "api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com") {
			return "", nil, E("download.host_denied", "The release redirect host is not allowed.")
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		portNumber, pe := strconv.Atoi(port)
		if pe != nil {
			return "", nil, E("download.url_policy", "Invalid target port.")
		}
		ips, e := ResolveSubscriptionHost(c, u.Hostname(), portNumber)
		if e != nil || len(ips) == 0 {
			return "", nil, E("download.dns_failed", "The target could not be validated.")
		}
		tr := &http.Transport{Proxy: nil, MaxResponseHeaderBytes: 64 << 10, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			var last error
			for _, ip := range ips {
				conn, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if e == nil {
					return conn, nil
				}
				last = e
			}
			return nil, last
		}}
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(c, "GET", normalized, nil)
		if e != nil {
			return "", nil, e
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", "MagicNet/"+Version)
		resp, e := client.Do(req)
		if e != nil {
			return "", nil, E("download.failed", "HTTPS download failed.")
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc, e := resp.Location()
			resp.Body.Close()
			tr.CloseIdleConnections()
			if e != nil || hop == 5 {
				return "", nil, E("download.redirect_failed", "Invalid or excessive redirects.")
			}
			normalized, e = NormalizeSubscriptionURL(loc.String())
			if e != nil {
				return "", nil, E("download.url_policy", "The redirect target was rejected.")
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return "", nil, E("download.http_failed", "The download server rejected the request.")
		}
		dir := a.Path(".state", "private", "downloads")
		if e = os.MkdirAll(dir, 0700); e != nil {
			resp.Body.Close()
			return "", nil, e
		}
		f, e := os.CreateTemp(dir, "asset-")
		if e != nil {
			resp.Body.Close()
			return "", nil, e
		}
		p := f.Name()
		n, e := io.Copy(f, io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		tr.CloseIdleConnections()
		if e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil || n > limit || n == 0 {
			os.Remove(p)
			return "", nil, E("download.size_or_io", "Download size or I/O validation failed.")
		}
		return p, resp.Header, nil
	}
	return "", nil, E("download.redirect_failed", "Too many redirects.")
}
func (a *App) installedVersion() string {
	b, e := ReadRegular(a.Path("module.prop"), 64<<10)
	if e != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "version=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "version="))
		}
	}
	return "unknown"
}
func (a *App) moduleUpdateStatus() (M, error) {
	var i UpdateIntent
	e := ReadJSON(a.Path(".config", "magicnet", "module-update.conf"), 128<<10, &i)
	if errors.Is(e, os.ErrNotExist) {
		return M{"phase": "idle", "running": false, "effective_version": a.installedVersion(), "reboot_required": false, "recovery_required": false}, nil
	}
	if e != nil {
		return nil, E("module-update.observation_failed", "Update intent cannot be read.")
	}
	_, owner, oe := observeOwner(a.Path(".state", "owners", "module-update.json"))
	running := owner == "active"
	phase := i.Phase
	if stringIn(phase, "checking", "downloading", "verifying", "installing") && !running && owner != "unknown" {
		phase = "failed"
	}
	reboot := phase == "reboot_required"
	effective := a.installedVersion()
	if i.Boot == bootID() && reboot {
		effective = i.Baseline
	}
	if i.Boot != bootID() && reboot {
		b, be := ReadRegular(a.Path("bin", "magicnet-cli"), 64<<20)
		_, se := os.Stat("/data/adb/modules_update/MagicNet")
		if be == nil && digest(b) == i.StagedCLI && effective == i.ExpectedLatest && errors.Is(se, os.ErrNotExist) {
			phase = "up_to_date"
			reboot = false
		} else {
			effective = "unknown"
		}
	}
	var run any = running
	if oe != nil || owner == "unknown" {
		run = nil
	}
	return M{"phase": phase, "running": run, "owner": owner, "effective_version": effective, "latest_version": func() string {
		if semver.MatchString(i.Release.Tag) {
			return i.Release.Tag
		}
		return "unknown"
	}(), "reboot_required": reboot, "recovery_required": i.Recovery, "error_code": i.Error, "request_id": i.ID}, nil
}
func (a *App) readLedger() (UpdateLedger, error) {
	l := UpdateLedger{Used: map[string]string{}, Results: map[string]UpdateIntent{}, Order: []string{}}
	e := ReadJSON(a.Path(".state", "module-update", "ledger.json"), 512<<10, &l)
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	if e == nil && (l.Used == nil || l.Results == nil || len(l.Used) > 4096 || len(l.Results) > 128 || len(l.Order) > 128) {
		return l, E("module-update.ledger_invalid", "Replay ledger is invalid.")
	}
	return l, e
}
func (a *App) recordUpdate(i UpdateIntent) error {
	l, e := a.readLedger()
	if e != nil {
		return e
	}
	return a.recordUpdateWithLedger(i, l)
}
func (a *App) recordUpdateWithLedger(i UpdateIntent, l UpdateLedger) error {
	receipt := i
	receipt.Release = OfficialRelease{Tag: i.Release.Tag}
	l.Results[i.ID] = receipt
	found := false
	for _, x := range l.Order {
		if x == i.ID {
			found = true
		}
	}
	if !found {
		l.Order = append(l.Order, i.ID)
	}
	for len(l.Order) > 128 {
		delete(l.Results, l.Order[0])
		l.Order = l.Order[1:]
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	if len(b) > 512<<10 {
		return E("module-update.ledger_limit", "Update replay ledger reached its limit.")
	}
	return a.publishUpdateRecord(i, l)
}
func (a *App) moduleUpdate(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("module-update.arguments", "An action is required.")
	}
	if args[0] == "status" && len(args) == 1 {
		return a.moduleUpdateStatus()
	}
	action := args[0]
	if !stringIn(action, "check", "install") {
		return nil, E("module-update.arguments", "Only status, check and install are supported.")
	}
	values := map[string]string{}
	for n := 1; n < len(args); n += 2 {
		if n+1 >= len(args) || !stringIn(args[n], "--request-id", "--expected-installed", "--expected-latest") {
			return nil, E("module-update.arguments", "Unknown update argument.")
		}
		if _, ok := values[args[n]]; ok {
			return nil, E("module-update.arguments", "Duplicate update argument.")
		}
		values[args[n]] = args[n+1]
	}
	id := values["--request-id"]
	if !requestID.MatchString(id) {
		return nil, E("module-update.request_id_invalid", "request-id must contain 8–64 ASCII letters, digits, underscore or hyphen.")
	}
	i := UpdateIntent{ID: id, Action: action, ExpectedInstalled: values["--expected-installed"], ExpectedLatest: values["--expected-latest"], Accepted: time.Now().Unix(), Boot: bootID(), Baseline: a.installedVersion(), Phase: "checking", Error: "none"}
	if action == "install" && (!semver.MatchString(i.ExpectedInstalled) || !semver.MatchString(i.ExpectedLatest)) {
		return nil, E("module-update.version_invalid", "Install requires exact expected installed and latest versions.")
	}
	intentBytes, _ := json.Marshal(M{"action": action, "expected_installed": i.ExpectedInstalled, "expected_latest": i.ExpectedLatest})
	ih := sha256.Sum256(intentBytes)
	intentHash := base64.RawURLEncoding.EncodeToString(ih[:16])
	var out M
	e := a.withLockFD(ctx, "module-update", 2*time.Second, func(lockFile *os.File) error {
		// A receipt is historical evidence, not permission to ignore today's
		// manager/recovery state. Check before recovery as well so a blocked
		// request cannot publish a pending ledger over retained evidence.
		if e := a.updateAcceptanceGate(); e != nil {
			return e
		}
		if e := a.recoverUpdateRecord(); e != nil {
			return e
		}
		if e := a.updateAcceptanceGate(); e != nil {
			return e
		}
		l, e := a.readLedger()
		if e != nil {
			return e
		}
		if replay, replayErr, found := updateReplay(l, id, intentHash); found {
			out = replay
			return replayErr
		}
		if len(l.Used) >= 4096 {
			return E("module-update.id_budget_exhausted", "Update request ID history is full.")
		}
		l.Used[id] = intentHash
		if e = a.recordUpdateWithLedger(i, l); e != nil {
			return e
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		if _, e = a.spawnOwnedFiles("module-update", exe, []string{"__update-worker"}, id, "", []*os.File{lockFile}); e != nil {
			return e
		}
		out = M{"request_id": id, "accepted": true, "phase": "checking", "effective_version": i.Baseline}
		return nil
	})
	if e != nil {
		if ErrorCode(e) == "operation.busy" {
			return nil, E("module-update.busy", "An update operation is still running.")
		}
		return nil, e
	}
	if out["replayed"] == true {
		return out, nil
	}
	if e = a.Publish(ctx); e != nil {
		return nil, e
	}
	return out, nil
}

// updateAcceptanceGate is called only while the update lock is held. It is
// read-only: blocked retries retain intent, ledger, journal and owner bytes.
func (a *App) updateAcceptanceGate() error {
	_, owner, oe := observeOwner(a.Path(".state", "owners", "module-update.json"))
	if oe != nil || owner == "unknown" || owner == "pending" {
		return E("module-update.ownership_unknown", "Update owner is unknown.")
	}
	if owner == "active" {
		return E("module-update.busy", "An update operation is still running.")
	}
	staging := "/data/adb/modules_update/MagicNet"
	if filepath.Base(a.Root) == "MagicNet" && stringIn(filepath.Base(filepath.Dir(a.Root)), "modules", "modules_update") {
		staging = filepath.Join(filepath.Dir(filepath.Dir(a.Root)), "modules_update", "MagicNet")
	}
	for _, p := range []string{staging, a.Path("update"), a.Path("disable"), a.Path("remove")} {
		if _, e := os.Lstat(p); e == nil {
			return E("module-update.pending", "Pending manager state prevents another install or success replay.")
		} else if !errors.Is(e, os.ErrNotExist) {
			return E("module-update.observation_failed", "Pending manager state cannot be safely observed.")
		}
	}
	var current UpdateIntent
	if e := ReadJSON(a.Path(".config", "magicnet", "module-update.conf"), 128<<10, &current); e == nil {
		if current.Recovery || current.Phase == "recovery_required" || current.Phase == "installing" {
			return E("module-update.recovery_required", "Current manager recovery must finish before another request or receipt replay.")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return E("module-update.observation_failed", "Current update intent cannot be safely observed.")
	}
	return nil
}
func (a *App) updateWorker(ctx context.Context) error {
	lock := os.NewFile(3, "update-lock")
	defer lock.Close()
	path, e := os.Readlink("/proc/self/fd/3")
	if e != nil || path != a.Path(".state", "locks", "module-update.lock") {
		return E("module-update.lock_missing", "The accepted update lock was not inherited.")
	}
	return func() error {
		var i UpdateIntent
		if e := ReadJSON(a.Path(".config", "magicnet", "module-update.conf"), 128<<10, &i); e != nil {
			return e
		}
		finish := func(e error) error {
			if e != nil {
				i.Error = ErrorCode(e)
				i.Phase = "failed"
			}
			if we := a.recordUpdate(i); we != nil {
				return we
			}
			a.Publish(ctx)
			return e
		}
		p, _, e := a.downloadPublic(ctx, officialAPI+"/releases/latest", "application/vnd.github+json", 2<<20, true)
		if e != nil {
			return finish(e)
		}
		b, e := ReadRegular(p, 2<<20)
		os.Remove(p)
		if e != nil {
			return finish(e)
		}
		var release OfficialRelease
		if e = DecodeJSON(b, &release); e != nil || release.Draft || release.Prerelease || !semver.MatchString(release.Tag) {
			return finish(E("module-update.release_invalid", "No valid official stable release was returned."))
		}
		i.Release = release
		if i.Action == "check" {
			i.Phase = "available"
			if i.Baseline == release.Tag {
				i.Phase = "up_to_date"
			}
			return finish(nil)
		}
		if i.Baseline != i.ExpectedInstalled || release.Tag != i.ExpectedLatest {
			return finish(E("module-update.version_conflict", "Installed or latest release changed."))
		}
		var core, sums ReleaseAsset
		for _, as := range release.Assets {
			if as.Name == "MagicNet-core.zip" {
				core = as
			}
			if as.Name == "SHA256SUMS" {
				sums = as
			}
		}
		if core.ID <= 0 || sums.ID <= 0 || core.Size <= 0 || core.Size > 512<<20 || !strings.HasPrefix(core.Digest, "sha256:") {
			return finish(E("module-update.assets_invalid", "Required official release assets are missing."))
		}
		i.Phase = "downloading"
		if e = a.recordUpdate(i); e != nil {
			return e
		}
		a.Publish(ctx)
		archive, _, e := a.downloadPublic(ctx, officialAPI+"/releases/assets/"+strconv.FormatInt(core.ID, 10), "application/octet-stream", 512<<20, true)
		if e != nil {
			return finish(e)
		}
		defer os.Remove(archive)
		sumsPath, _, e := a.downloadPublic(ctx, officialAPI+"/releases/assets/"+strconv.FormatInt(sums.ID, 10), "application/octet-stream", 1<<20, true)
		if e != nil {
			return finish(e)
		}
		defer os.Remove(sumsPath)
		i.Phase = "verifying"
		if e = a.recordUpdate(i); e != nil {
			return e
		}
		a.Publish(ctx)
		if st, se := os.Stat(archive); se != nil || st.Size() != core.Size {
			return finish(E("module-update.size_mismatch", "Published asset size does not match downloaded bytes."))
		}
		f, e := os.Open(archive)
		if e != nil {
			return finish(e)
		}
		h := sha256.New()
		io.Copy(h, f)
		f.Close()
		sum := hex.EncodeToString(h.Sum(nil))
		sb, e := ReadRegular(sumsPath, 1<<20)
		if e != nil {
			return finish(e)
		}
		matches := 0
		for _, line := range strings.Split(string(sb), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == "MagicNet-core.zip" && fields[0] == sum {
				matches++
			}
		}
		if core.Digest != "sha256:"+sum || matches != 1 {
			return finish(E("module-update.hash_mismatch", "Release SHA-256 verification failed."))
		}
		data, e := ReadRegular(archive, 512<<20)
		if e != nil {
			return finish(e)
		}
		files, e := secureZip(data, 1<<30)
		if e != nil {
			return finish(e)
		}
		prop := string(files["module.prop"])
		if !strings.Contains("\n"+prop, "\nid=MagicNet\n") || !strings.Contains("\n"+prop, "\nversion="+release.Tag+"\n") {
			return finish(E("module-update.identity_invalid", "The module ID or version does not match."))
		}
		cli := files["bin/magicnet-cli"]
		if len(cli) < 20 || string(cli[:4]) != "\x7fELF" || cli[18] != 183 || cli[19] != 0 {
			return finish(E("module-update.architecture_invalid", "The package CLI is not Android arm64."))
		}
		if _, ok := files["components.json"]; !ok {
			return finish(E("module-update.manifest_missing", "Component manifest is missing."))
		}
		if _, e = Run(ctx, a.Root, a.Path("bin", "magicnet-installer"), []string{"verify", archive}, nil, 1<<20); e != nil {
			return finish(E("module-update.archive_invalid", "The installed verifier rejected the module archive."))
		}
		i.StagedCLI = digest(cli)
		manager, managerArgs, e := a.managerCommand(ctx, archive)
		if e != nil {
			return finish(e)
		}
		i.Phase = "installing"
		i.Recovery = true
		if e = a.recordUpdate(i); e != nil {
			return e
		}
		a.Publish(ctx)
		managerCtx, managerCancel := context.WithTimeout(ctx, 10*time.Minute)
		_, e = Run(managerCtx, a.Root, manager, managerArgs, nil, 2<<20)
		managerCancel()
		if e != nil {
			return finish(E("module-update.recovery_required", "The manager failed after installation began."))
		}
		staged, e := ReadRegular("/data/adb/modules_update/MagicNet/module.prop", 64<<10)
		if e != nil || !strings.Contains("\n"+string(staged), "\nid=MagicNet\n") || !strings.Contains("\n"+string(staged), "\nversion="+release.Tag+"\n") {
			return finish(E("module-update.staging_unverified", "Manager success did not prove the expected staged module."))
		}
		if _, e = os.Stat("/data/adb/modules_update/MagicNet/update"); e != nil {
			if _, e = os.Stat(a.Path("update")); e != nil {
				return finish(E("module-update.staging_unverified", "The manager update marker is missing."))
			}
		}
		if _, e = Run(ctx, a.Root, a.Path("bin", "magicnet-installer"), []string{"verify-installed", "/data/adb/modules_update/MagicNet"}, nil, 1<<20); e != nil {
			return finish(E("module-update.staging_unverified", "Staged component bytes or permissions did not verify."))
		}
		i.Phase = "reboot_required"
		i.Recovery = false
		return finish(nil)
	}()
}
func (a *App) managerCommand(ctx context.Context, archive string) (string, []string, error) {
	if a.Platform != "android" {
		return "", nil, E("module-update.manager_unavailable", "A real Android root manager is required.")
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, e := os.Stat("/data/adb/ksud"); e == nil {
		r, e := Run(c, a.Root, "/data/adb/ksud", []string{"debug", "get-version"}, nil, 4096)
		if e == nil && len(r.Stdout) > 0 {
			return "/data/adb/ksud", []string{"module", "install", archive}, nil
		}
	}
	if _, e := os.Stat("/data/adb/apd"); e == nil {
		r, e := Run(c, a.Root, "/data/adb/apd", []string{"-V"}, nil, 4096)
		if e == nil && len(r.Stdout) > 0 {
			return "/data/adb/apd", []string{"module", "install", archive}, nil
		}
	}
	for _, p := range []string{"/data/adb/magisk/magisk", "/sbin/magisk", "/debug_ramdisk/magisk"} {
		if _, e := os.Stat(p); e == nil {
			if _, e = Run(c, a.Root, p, []string{"-V"}, nil, 4096); e == nil {
				return p, []string{"--install-module", archive}, nil
			}
		}
	}
	return "", nil, E("module-update.manager_unavailable", "No verified root manager capability is available.")
}
func (a *App) installPanel(ctx context.Context, raw, expected string) (M, error) {
	if len(expected) != 64 {
		return nil, E("webui.hash_invalid", "A SHA-256 digest is required.")
	}
	if _, e := hex.DecodeString(expected); e != nil {
		return nil, E("webui.hash_invalid", "Invalid SHA-256.")
	}
	p, _, e := a.downloadPublic(ctx, raw, "application/octet-stream", 32<<20, false)
	if e != nil {
		return nil, e
	}
	defer os.Remove(p)
	b, e := ReadRegular(p, 32<<20)
	if e != nil {
		return nil, e
	}
	if digest(b) != strings.ToLower(expected) {
		return nil, E("webui.hash_mismatch", "Panel SHA-256 mismatch.")
	}
	files, e := secureZip(b, 128<<20)
	if e != nil {
		return nil, e
	}
	if _, ok := files["index.html"]; !ok {
		return nil, E("webui.panel_invalid", "Panel index.html is missing.")
	}
	stage := a.Path(".state", "panel-stage-"+token())
	defer os.RemoveAll(stage)
	for name, data := range files {
		if e = AtomicWrite(filepath.Join(stage, name), data, 0644); e != nil {
			return nil, e
		}
	}
	dest := a.Path("ui")
	old := a.Path(".state", "panel-previous")
	if _, e = os.Stat(old); e == nil {
		return nil, E("webui.recovery_pending", "A previous panel installation needs recovery.")
	}
	hadOld := false
	if _, e = os.Stat(dest); e == nil {
		if e = os.Rename(dest, old); e != nil {
			return nil, e
		}
		hadOld = true
	}
	if e = os.Rename(stage, dest); e != nil {
		if hadOld {
			os.Rename(old, dest)
		}
		return nil, e
	}
	if hadOld {
		os.RemoveAll(old)
	}
	return M{"installed": true, "verified": true, "sha256": expected}, nil
}

var _ = fmt.Sprint
