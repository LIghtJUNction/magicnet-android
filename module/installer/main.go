// MagicNet's module installer is independent of Android's Python/shell tooling.
// It accepts only the manifest bundled in the current module archive.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxArchive = 512 << 20
const maxExpanded = 1 << 30
const maxFile = 160 << 20

type File struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Component struct {
	ID       string `json:"id"`
	Identity string `json:"identity"`
	Archive  string `json:"archive"`
	SHA256   string `json:"sha256"`
	Files    []File `json:"files"`
}
type Manifest struct {
	Schema           int            `json:"schema"`
	ModuleID         string         `json:"module_id"`
	Arch             string         `json:"arch"`
	Version          string         `json:"version"`
	VersionCode      int64          `json:"version_code,omitempty"`
	RecipeVersion    string         `json:"recipe_version,omitempty"`
	Channel          string         `json:"channel,omitempty"`
	SourceMode       string         `json:"source_mode,omitempty"`
	SourceProvenance map[string]any `json:"source_provenance,omitempty"`
	ReleaseTag       string         `json:"release_tag"`
	Components       []Component    `json:"components"`
}
type Migration struct {
	Schema     int             `json:"schema"`
	Paths      []MigrationPath `json:"paths"`
	Exclusions []MigrationPath `json:"exclusions"`
}
type MigrationPath struct {
	Path   string `json:"path"`
	Action string `json:"action"`
}
type Change struct {
	File    File   `json:"file"`
	Remove  bool   `json:"remove,omitempty"`
	HadOld  bool   `json:"had_old"`
	OldHash string `json:"old_hash"`
	OldMode uint32 `json:"old_mode"`
}
type Journal struct {
	Schema  int      `json:"schema"`
	Phase   string   `json:"phase"`
	Changes []Change `json:"changes"`
}

func fail(code string) error { return errors.New(code) }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func safeName(s string) bool {
	return s != "" && len(s) <= 240 && !strings.HasPrefix(s, "/") && !strings.Contains(s, "\\") && !strings.ContainsRune(s, 0) && path.Clean(s) == s && s != "." && s != ".." && !strings.HasPrefix(s, "../")
}
func token(s string) bool {
	if len(s) == 0 || len(s) > 100 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}
func safeAncestors(p string) error {
	for d := filepath.Clean(p); d != "/" && d != "."; d = filepath.Dir(d) {
		st, e := os.Lstat(d)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return fail("filesystem.observation_failed")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fail("filesystem.link_rejected")
		}
	}
	return nil
}
func readRegular(p string, limit int64) ([]byte, error) {
	if e := safeAncestors(p); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > limit || st.Mode().Perm()&0022 != 0 && strings.Contains(p, ".components-install") {
		return nil, fail("filesystem.unsafe_file")
	}
	if v, ok := st.Sys().(*syscall.Stat_t); ok && v.Nlink != 1 {
		return nil, fail("filesystem.hardlink_rejected")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, fail("filesystem.size_limit")
	}
	after, e := f.Stat()
	if e != nil || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) || int64(len(b)) != st.Size() {
		return nil, fail("filesystem.changed_during_read")
	}
	return b, nil
}
func atomic(p string, b []byte, mode os.FileMode) error {
	if e := safeAncestors(p); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".new-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(tmp, p)
	}
	if e == nil {
		d, de := os.Open(filepath.Dir(p))
		if de != nil {
			return de
		}
		e = d.Sync()
		d.Close()
	}
	return e
}
func writeJSON(p string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomic(p, append(b, '\n'), 0600)
}
func decode(b []byte, v any) error {
	// encoding/json otherwise accepts duplicate keys and case-folded struct
	// members. A current-archive identity document has one unambiguous meaning.
	scan := json.NewDecoder(bytes.NewReader(b))
	if e := uniqueJSON(scan, 0); e != nil {
		return e
	}
	if _, e := scan.Token(); e != io.EOF {
		return fail("manifest.trailing_data")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fail("manifest.invalid")
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return fail("manifest.trailing_data")
	}
	return nil
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fail("manifest.depth_limit")
	}
	t, e := d.Token()
	if e != nil {
		return fail("manifest.invalid")
	}
	mark, container := t.(json.Delim)
	if !container {
		return nil
	}
	if mark != '{' && mark != '[' {
		return fail("manifest.invalid")
	}
	seen := map[string]bool{}
	for d.More() {
		if mark == '{' {
			key, e := d.Token()
			name, ok := key.(string)
			if e != nil || !ok || name != strings.ToLower(name) || seen[name] {
				return fail("manifest.ambiguous_key")
			}
			seen[name] = true
		}
		if e := uniqueJSON(d, depth+1); e != nil {
			return e
		}
	}
	end, e := d.Token()
	if e != nil || (mark == '{' && end != json.Delim('}')) || (mark == '[' && end != json.Delim(']')) {
		return fail("manifest.invalid")
	}
	return nil
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil && strings.ToLower(s) == s
}
func identity(files []File) string {
	copyFiles := append([]File(nil), files...)
	sort.Slice(copyFiles, func(i, j int) bool { return copyFiles[i].Path < copyFiles[j].Path })
	var b strings.Builder
	for _, f := range copyFiles {
		fmt.Fprintf(&b, "%s\x00%d\x00%d\x00%s\n", f.Path, f.Mode, f.Size, f.SHA256)
	}
	return digest([]byte(b.String()))
}
func validateManifest(m *Manifest) error {
	if m.Schema != 1 || m.ModuleID != "MagicNet" || m.Arch != "android-arm64" || !token(m.Version) || !token(m.ReleaseTag) || len(m.Components) < 3 || len(m.Components) > 32 {
		return fail("manifest.identity_invalid")
	}
	if m.SourceMode != "" || len(m.SourceProvenance) != 0 {
		if (m.SourceMode != "git" && m.SourceMode != "archive") || len(m.SourceProvenance) == 0 {
			return fail("manifest.source_metadata_invalid")
		}
	}
	if m.VersionCode != 0 || m.RecipeVersion != "" || m.Channel != "" {
		if m.VersionCode < 1 || !token(m.RecipeVersion) || (m.Channel != "candidate" && m.Channel != "stable") {
			return fail("manifest.product_metadata_invalid")
		}
	}
	names := map[string]bool{}
	ids := map[string]bool{}
	total := int64(0)
	for _, c := range m.Components {
		if !token(c.ID) || ids[c.ID] || !validHash(c.Identity) || !validHash(c.SHA256) || c.Archive != "MagicNet-component-"+c.ID+"-"+c.Identity+".zip" || len(c.Files) == 0 || len(c.Files) > 4096 || identity(c.Files) != c.Identity {
			return fail("manifest.component_invalid")
		}
		ids[c.ID] = true
		for _, f := range c.Files {
			if !safeName(f.Path) || names[f.Path] || f.Path == "components.json" || f.Path == "module.prop" || strings.HasPrefix(f.Path, ".state/") || strings.HasPrefix(f.Path, ".log/") || strings.HasPrefix(f.Path, ".components-install/") || !validHash(f.SHA256) || f.Size < 1 || f.Size > maxFile || !(f.Mode == 0644 || f.Mode == 0755 || f.Mode == 0600) {
				return fail("manifest.file_invalid")
			}
			names[f.Path] = true
			total += f.Size
			if total > maxExpanded {
				return fail("manifest.size_limit")
			}
		}
	}
	if !names["bin/magicnet-cli"] || !names["bin/sing-box"] || !names["webroot/index.html"] || !names[".config/sing-box/rules/manifest.json"] {
		return fail("manifest.required_file_missing")
	}
	return nil
}
func zipFiles(data []byte) (map[string][]byte, map[string]os.FileMode, error) {
	if len(data) == 0 || len(data) > maxArchive {
		return nil, nil, fail("archive.size_limit")
	}
	r, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return nil, nil, fail("archive.invalid")
	}
	if len(r.File) > 6000 {
		return nil, nil, fail("archive.entry_limit")
	}
	if e := verifyLocalHeaders(data, r.File); e != nil {
		return nil, nil, e
	}
	out := map[string][]byte{}
	modes := map[string]os.FileMode{}
	total := uint64(0)
	for _, f := range r.File {
		name := strings.TrimSuffix(f.Name, "/")
		if !safeName(name) {
			return nil, nil, fail("archive.path_invalid")
		}
		if _, ok := modes[name]; ok {
			return nil, nil, fail("archive.duplicate_entry")
		}
		modes[name] = f.Mode()
		if f.Flags&1 != 0 {
			return nil, nil, fail("archive.encrypted")
		}
		if f.FileInfo().IsDir() {
			if f.UncompressedSize64 != 0 {
				return nil, nil, fail("archive.directory_payload")
			}
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 {
			if name != "cli" {
				return nil, nil, fail("archive.link_rejected")
			}
		} else if !f.Mode().IsRegular() || f.Mode().Perm()&0022 != 0 || f.Mode()&os.ModeSetuid != 0 || f.Mode()&os.ModeSetgid != 0 {
			return nil, nil, fail("archive.mode_invalid")
		}
		total += f.UncompressedSize64
		if f.UncompressedSize64 > maxFile || total > maxExpanded {
			return nil, nil, fail("archive.expansion_limit")
		}
		rd, e := f.Open()
		if e != nil {
			return nil, nil, fail("archive.entry_invalid")
		}
		b, e := io.ReadAll(io.LimitReader(rd, maxFile+1))
		rd.Close()
		if e != nil || uint64(len(b)) != f.UncompressedSize64 {
			return nil, nil, fail("archive.crc_or_size")
		}
		if name == "cli" && f.Mode()&os.ModeSymlink != 0 && string(b) != "bin/magicnet-cli" {
			return nil, nil, fail("archive.cli_link_invalid")
		}
		out[name] = b
	}
	return out, modes, nil
}

// Archive readers differ in their handling of local/central filename conflicts.
// Our release archives need no prepended executables, ZIP64, encryption or gaps.
func verifyLocalHeaders(data []byte, files []*zip.File) error {
	byName := map[string]*zip.File{}
	for _, f := range files {
		if _, ok := byName[f.Name]; ok {
			return fail("archive.duplicate_entry")
		}
		byName[f.Name] = f
	}
	pos := 0
	seen := map[string]bool{}
	for pos+4 <= len(data) && binary.LittleEndian.Uint32(data[pos:]) == 0x04034b50 {
		if pos+30 > len(data) {
			return fail("archive.local_header_invalid")
		}
		flags := binary.LittleEndian.Uint16(data[pos+6:])
		method := binary.LittleEndian.Uint16(data[pos+8:])
		nl := int(binary.LittleEndian.Uint16(data[pos+26:]))
		xl := int(binary.LittleEndian.Uint16(data[pos+28:]))
		start := pos + 30 + nl + xl
		if start > len(data) || flags&1 != 0 {
			return fail("archive.local_header_invalid")
		}
		name := string(data[pos+30 : pos+30+nl])
		f, ok := byName[name]
		if !ok || seen[name] || f.Flags != flags || f.Method != method {
			return fail("archive.header_ambiguity")
		}
		seen[name] = true
		offset, e := f.DataOffset()
		if e != nil || offset != int64(start) {
			return fail("archive.header_ambiguity")
		}
		for p := pos + 30 + nl; p < start; {
			if p+4 > start {
				return fail("archive.extra_invalid")
			}
			kind := binary.LittleEndian.Uint16(data[p:])
			size := int(binary.LittleEndian.Uint16(data[p+2:]))
			p += 4
			if p+size > start || kind == 0x0001 || kind == 0x7075 {
				return fail("archive.extra_ambiguous")
			}
			p += size
		}
		if flags&8 == 0 && (binary.LittleEndian.Uint32(data[pos+14:]) != f.CRC32 || uint64(binary.LittleEndian.Uint32(data[pos+18:])) != f.CompressedSize64 || uint64(binary.LittleEndian.Uint32(data[pos+22:])) != f.UncompressedSize64) {
			return fail("archive.header_ambiguity")
		}
		next := uint64(start) + f.CompressedSize64
		if next > uint64(len(data)) {
			return fail("archive.local_header_invalid")
		}
		pos = int(next)
		if flags&8 != 0 {
			if pos+4 <= len(data) && binary.LittleEndian.Uint32(data[pos:]) == 0x08074b50 {
				pos += 4
			}
			if pos+12 > len(data) || binary.LittleEndian.Uint32(data[pos:]) != f.CRC32 || uint64(binary.LittleEndian.Uint32(data[pos+4:])) != f.CompressedSize64 || uint64(binary.LittleEndian.Uint32(data[pos+8:])) != f.UncompressedSize64 {
				return fail("archive.descriptor_invalid")
			}
			pos += 12
		}
	}
	if len(seen) != len(files) || pos+4 > len(data) || binary.LittleEndian.Uint32(data[pos:]) != 0x02014b50 {
		return fail("archive.header_ambiguity")
	}
	return nil
}
func verifyELF(b []byte) error {
	f, e := elf.NewFile(bytes.NewReader(b))
	if e != nil {
		return fail("binary.invalid_elf")
	}
	defer f.Close()
	if f.Machine != elf.EM_AARCH64 || f.Class != elf.ELFCLASS64 {
		return fail("binary.architecture_invalid")
	}
	return nil
}
func verifyArchive(p string) (*Manifest, map[string][]byte, error) {
	b, e := readRegular(p, maxArchive)
	if e != nil {
		return nil, nil, fail("archive.unreadable")
	}
	files, modes, e := zipFiles(b)
	if e != nil {
		return nil, nil, e
	}
	prop, e := moduleProperties(files["module.prop"])
	if e != nil || prop["id"] != "MagicNet" {
		return nil, nil, fail("module.identity_invalid")
	}
	var m Manifest
	if e = decode(files["components.json"], &m); e != nil {
		return nil, nil, e
	}
	if e = validateManifest(&m); e != nil {
		return nil, nil, e
	}
	if e = validateProductProperties(&m, prop); e != nil {
		return nil, nil, e
	}
	if e = verifyELF(files["bin/magicnet-cli"]); e != nil {
		return nil, nil, e
	}
	if e = verifyELF(files["bin/magicnet-installer"]); e != nil {
		return nil, nil, e
	}
	allowed := map[string]bool{"components.json": true, "module.prop": true, "cli": true}
	for _, c := range m.Components {
		for _, f := range c.Files {
			allowed[f.Path] = true
			if data, ok := files[f.Path]; ok {
				if digest(data) != f.SHA256 || int64(len(data)) != f.Size || uint32(modes[f.Path].Perm()) != f.Mode {
					return nil, nil, fail("component.payload_mismatch")
				}
			}
		}
	}
	for name := range files {
		if !allowed[name] {
			return nil, nil, fail("archive.unmanifested_file")
		}
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if _, collision := files[dir]; collision {
				return nil, nil, fail("archive.path_collision")
			}
		}
	}
	for _, name := range []string{"bin/sing-box", "bin/ecapture"} {
		if data, ok := files[name]; ok {
			if e = verifyELF(data); e != nil {
				return nil, nil, e
			}
		}
	}
	return &m, files, nil
}
func moduleProperties(b []byte) (map[string]string, error) {
	if len(b) == 0 || len(b) > 65536 || bytes.IndexByte(b, 0) >= 0 {
		return nil, fail("module.properties_invalid")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || !token(pair[0]) {
			return nil, fail("module.properties_invalid")
		}
		if _, exists := values[pair[0]]; exists {
			return nil, fail("module.properties_ambiguous")
		}
		values[pair[0]] = pair[1]
	}
	return values, nil
}
func validateProductProperties(m *Manifest, prop map[string]string) error {
	if prop["version"] != m.Version {
		return fail("module.version_invalid")
	}
	if m.VersionCode != 0 || m.RecipeVersion != "" || m.Channel != "" || prop["recipeVersion"] != "" || prop["releaseChannel"] != "" {
		if prop["versionCode"] != strconv.FormatInt(m.VersionCode, 10) || prop["recipeVersion"] != m.RecipeVersion || prop["releaseChannel"] != m.Channel {
			return fail("module.product_metadata_invalid")
		}
	}
	return nil
}
func verifyInstalled(root string) error {
	b, e := readRegular(filepath.Join(root, "components.json"), 4<<20)
	if e != nil {
		return fail("manifest.unreadable")
	}
	var m Manifest
	if e = decode(b, &m); e != nil {
		return e
	}
	if e = validateManifest(&m); e != nil {
		return e
	}
	propBytes, e := readRegular(filepath.Join(root, "module.prop"), 65536)
	if e != nil {
		return fail("module.properties_invalid")
	}
	prop, e := moduleProperties(propBytes)
	if e != nil || prop["id"] != m.ModuleID {
		return fail("module.identity_invalid")
	}
	if e = validateProductProperties(&m, prop); e != nil {
		return e
	}
	for _, c := range m.Components {
		for _, f := range c.Files {
			if e = verifyFile(root, f); e != nil {
				return e
			}
		}
	}
	return nil
}
func verifyFile(root string, f File) error {
	b, e := readRegular(filepath.Join(root, f.Path), f.Size)
	if e != nil || int64(len(b)) != f.Size || digest(b) != f.SHA256 {
		return fail("component.file_mismatch")
	}
	st, e := os.Stat(filepath.Join(root, f.Path))
	if e != nil || uint32(st.Mode().Perm()) != f.Mode {
		return fail("component.mode_mismatch")
	}
	if f.Path == "bin/magicnet-cli" || f.Path == "bin/magicnet-installer" || f.Path == "bin/sing-box" || f.Path == "bin/ecapture" {
		return verifyELF(b)
	}
	return nil
}
func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "2001:db8::/32", "fc00::/7", "fe80::/10"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}
func download(raw string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	for n := 0; n < 6; n++ {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
			return nil, fail("download.url_policy")
		}
		host := strings.ToLower(u.Hostname())
		allowed := false
		for _, h := range []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com"} {
			if host == h {
				allowed = true
			}
		}
		if !allowed {
			return nil, fail("download.host_policy")
		}
		ips, e := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, fail("download.dns_failed")
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, fail("download.address_policy")
			}
		}
		tr := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: 15 * time.Second, MaxResponseHeaderBytes: 65536, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var last error
			for _, ip := range ips {
				d := net.Dialer{Timeout: 10 * time.Second}
				c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
				if e == nil {
					return c, nil
				}
				last = e
			}
			return nil, last
		}}
		client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
		req.Header.Set("User-Agent", "MagicNet-installer/1.8.1 (recipe 0.3.1; candidate)")
		res, e := client.Do(req)
		if e != nil {
			return nil, fail("download.https_failed")
		}
		if res.StatusCode == 302 || res.StatusCode == 301 || res.StatusCode == 307 || res.StatusCode == 308 {
			loc, e := res.Location()
			res.Body.Close()
			tr.CloseIdleConnections()
			if e != nil {
				return nil, fail("download.redirect_invalid")
			}
			raw = loc.String()
			continue
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			tr.CloseIdleConnections()
			return nil, fail("download.http_failed")
		}
		b, e := io.ReadAll(io.LimitReader(res.Body, maxArchive+1))
		res.Body.Close()
		tr.CloseIdleConnections()
		if e != nil || len(b) == 0 || len(b) > maxArchive {
			return nil, fail("download.size_limit")
		}
		return b, nil
	}
	return nil, fail("download.redirect_limit")
}
func recoverInstall(root string) error {
	base := filepath.Join(root, ".components-install")
	b, e := readRegular(filepath.Join(base, "journal.json"), 8<<20)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return fail("install.recovery_required")
	}
	var j Journal
	if decode(b, &j) != nil || j.Schema != 1 {
		return fail("install.recovery_required")
	}
	if j.Phase == "committed" {
		return os.RemoveAll(base)
	}
	for i := len(j.Changes) - 1; i >= 0; i-- {
		c := j.Changes[i]
		if !safeName(c.File.Path) {
			return fail("install.recovery_required")
		}
		dst := filepath.Join(root, c.File.Path)
		backup := filepath.Join(base, "backup", c.File.Path)
		old, e := readRegular(backup, maxFile)
		if e == nil {
			if !c.HadOld || digest(old) != c.OldHash {
				return fail("install.recovery_conflict")
			}
			current, ce := readRegular(dst, maxFile)
			if ce == nil && (c.Remove || digest(current) != c.File.SHA256) {
				return fail("install.recovery_conflict")
			}
			if ce != nil && !errors.Is(ce, os.ErrNotExist) {
				return fail("install.recovery_required")
			}
			if ce == nil {
				if e = os.Remove(dst); e != nil {
					return e
				}
			}
			if e = os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
				return e
			}
			if e = os.Rename(backup, dst); e != nil {
				return e
			}
			if e = os.Chmod(dst, os.FileMode(c.OldMode)); e != nil {
				return e
			}
			continue
		}
		if !errors.Is(e, os.ErrNotExist) {
			return fail("install.recovery_required")
		}
		current, ce := readRegular(dst, maxFile)
		if c.HadOld {
			if ce != nil || digest(current) != c.OldHash {
				return fail("install.recovery_conflict")
			}
		} else if ce == nil {
			if digest(current) != c.File.SHA256 {
				return fail("install.recovery_conflict")
			}
			if e = os.Remove(dst); e != nil {
				return e
			}
		} else if !errors.Is(ce, os.ErrNotExist) {
			return fail("install.recovery_required")
		}
	}
	if e = atomic(filepath.Join(root, ".install-recovery-receipt"), []byte("schema=1\nresult=recovered\n"), 0600); e != nil {
		return e
	}
	return os.RemoveAll(base)
}
func obsoleteFiles(root string, next Manifest) ([]Change, error) {
	b, e := readRegular(filepath.Join(root, ".components-manifest.json"), 8<<20)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, fail("component.ownership_unreadable")
	}
	var old Manifest
	if decode(b, &old) != nil || validateManifest(&old) != nil {
		return nil, fail("component.ownership_invalid")
	}
	retained := map[string]bool{}
	for _, c := range next.Components {
		for _, f := range c.Files {
			retained[f.Path] = true
		}
	}
	changes := []Change{}
	for _, c := range old.Components {
		for _, f := range c.Files {
			if retained[f.Path] {
				continue
			}
			p := filepath.Join(root, f.Path)
			current, e := readRegular(p, maxFile)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return nil, fail("component.obsolete_unsafe")
			}
			st, e := os.Stat(p)
			if e != nil {
				return nil, fail("component.obsolete_unsafe")
			}
			// A user or another writer changed the file: its former manifest no
			// longer proves ownership. Keep it, including its exact mode.
			if int64(len(current)) != f.Size || digest(current) != f.SHA256 || uint32(st.Mode().Perm()) != f.Mode {
				fmt.Println("component obsolete_modified_preserved")
				continue
			}
			changes = append(changes, Change{File: f, Remove: true, HadOld: true, OldHash: f.SHA256, OldMode: f.Mode})
		}
	}
	return changes, nil
}
func migrationFiles(old string, m Migration) (map[string][]byte, error) {
	if m.Schema != 1 || len(m.Paths) == 0 || len(m.Paths) > 64 || len(m.Exclusions) > 64 {
		return nil, fail("migration.invalid")
	}
	for i, item := range m.Paths {
		if !safeName(item.Path) || item.Action != "restore" {
			return nil, fail("migration.invalid")
		}
		for _, other := range m.Paths[:i] {
			if item.Path == other.Path || strings.HasPrefix(item.Path, other.Path+"/") || strings.HasPrefix(other.Path, item.Path+"/") {
				return nil, fail("migration.overlapping_paths")
			}
		}
	}
	seenExclusions := map[string]bool{}
	for _, item := range m.Exclusions {
		if !safeName(item.Path) || seenExclusions[item.Path] || !(item.Action == "replace" || item.Action == "backup_only") {
			return nil, fail("migration.invalid")
		}
		seenExclusions[item.Path] = true
	}
	result := map[string][]byte{}
	total := int64(0)
	excluded := func(p string) string {
		for _, x := range m.Exclusions {
			if p == x.Path || strings.HasPrefix(p, x.Path+"/") {
				return x.Action
			}
		}
		return ""
	}
	for _, entry := range m.Paths {
		if !safeName(entry.Path) || entry.Action != "restore" {
			return nil, fail("migration.invalid")
		}
		start := filepath.Join(old, entry.Path)
		if _, e := os.Lstat(start); errors.Is(e, os.ErrNotExist) {
			continue
		}
		e := filepath.WalkDir(start, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(old, p)
			if e != nil || !safeName(filepath.ToSlash(rel)) {
				return fail("migration.path_invalid")
			}
			rel = filepath.ToSlash(rel)
			action := excluded(rel)
			if action == "replace" {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fail("migration.link_rejected")
			}
			if d.IsDir() {
				return nil
			}
			b, e := readRegular(p, 16<<20)
			if e != nil {
				return fail("migration.copy_failed")
			}
			total += int64(len(b))
			if len(result) > 4096 || total > 128<<20 {
				return fail("migration.size_limit")
			}
			if action == "backup_only" {
				result[".migration-backup/"+rel] = b
			} else {
				result[rel] = b
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	return result, nil
}
func install(root, old, archive, cache string) error {
	if e := safeAncestors(root); e != nil {
		return e
	}
	if runtime.GOOS == "android" {
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		actual := filepath.Dir(filepath.Dir(exe))
		if actual != root || !(root == "/data/adb/modules/MagicNet" || root == "/data/adb/modules_update/MagicNet") {
			return fail("install.untrusted_root")
		}
		if old != "" && old != "/data/adb/modules/MagicNet" {
			return fail("install.untrusted_previous_root")
		}
	}
	if old == root {
		for _, name := range []string{".components-manifest.json", ".install-receipt", ".config/sing-box/config.json", "bin/sing-box"} {
			if _, observed := os.Lstat(filepath.Join(root, name)); !errors.Is(observed, os.ErrNotExist) {
				// Whole-module rollback across a failed config migration requires
				// the manager's separate staging root. Never modify a live old
				// root and subsequently claim the migration was atomic.
				return fail("install.in_place_upgrade_requires_staging")
			}
		}
	}
	lockPath := filepath.Join(root, ".components-install.lock")
	fd, e := syscall.Open(lockPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail("install.busy")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	if e = recoverInstall(root); e != nil {
		return e
	}
	m, bundled, e := verifyArchive(archive)
	if e != nil {
		return e
	}
	var stat syscall.Statfs_t
	if e = syscall.Statfs(root, &stat); e != nil {
		return fail("install.space_unknown")
	}
	required := int64(128 << 20)
	for _, c := range m.Components {
		for _, f := range c.Files {
			required += f.Size * 3
		}
	}
	if uint64(required) > stat.Bavail*uint64(stat.Bsize) {
		return fail("install.space_insufficient")
	}
	base := filepath.Join(root, ".components-install")
	stage := filepath.Join(base, "stage")
	if e = os.MkdirAll(stage, 0700); e != nil {
		return e
	}
	if e = os.Chmod(base, 0700); e != nil {
		return e
	}
	journalWritten := false
	defer func() {
		if !journalWritten {
			_ = os.RemoveAll(base)
		}
	}()
	changes := []File{}
	for _, c := range m.Components {
		componentData := map[string][]byte{}
		needDownload := false
		for _, f := range c.Files {
			found := false
			// Prefer proven installed bytes before bundled or external input. No network is used for complete reuse/full installs.
			for _, source := range []string{root, old} {
				if source == "" {
					continue
				}
				b, e := readRegular(filepath.Join(source, f.Path), f.Size)
				if e == nil && int64(len(b)) == f.Size && digest(b) == f.SHA256 {
					componentData[f.Path] = b
					found = true
					break
				}
			}
			if !found {
				if b, ok := bundled[f.Path]; ok && digest(b) == f.SHA256 {
					componentData[f.Path] = b
					found = true
				}
			}
			if !found {
				needDownload = true
			}
		}
		if needDownload {
			var data []byte
			if cache != "" {
				data, e = readRegular(filepath.Join(cache, c.Archive), maxArchive)
				if e != nil && !errors.Is(e, os.ErrNotExist) {
					return fail("component.offline_source_invalid")
				}
			}
			if len(data) == 0 {
				fmt.Printf("component %s download\n", c.ID)
				data, e = download("https://github.com/LIghtJUNction/MagicNet/releases/download/" + url.PathEscape(m.ReleaseTag) + "/" + url.PathEscape(c.Archive))
				if e != nil {
					return e
				}
			}
			if digest(data) != c.SHA256 {
				return fail("component.archive_hash_mismatch")
			}
			downloadDir := filepath.Join(base, ".downloads")
			if e = os.MkdirAll(downloadDir, 0700); e != nil {
				return e
			}
			downloadPath := filepath.Join(downloadDir, c.Archive)
			if e = atomic(downloadPath, data, 0600); e != nil {
				return e
			}
			files, modes, e := zipFiles(data)
			if e != nil {
				return e
			}
			if len(files) != len(c.Files) {
				return fail("component.extra_files")
			}
			for _, f := range c.Files {
				b, ok := files[f.Path]
				if !ok || digest(b) != f.SHA256 || int64(len(b)) != f.Size || uint32(modes[f.Path].Perm()) != f.Mode {
					return fail("component.contents_mismatch")
				}
				componentData[f.Path] = b
			}
			if e = os.Remove(downloadPath); e != nil {
				return e
			}
		}
		for _, f := range c.Files {
			b := componentData[f.Path]
			if e = atomic(filepath.Join(stage, f.Path), b, os.FileMode(f.Mode)); e != nil {
				return fail("component.stage_failed")
			}
			changes = append(changes, f)
		}
	}
	// These identity documents are trusted from this verified core ZIP and are
	// included in the same replacement journal, without a circular self-hash.
	for _, name := range []string{"components.json", "module.prop"} {
		data := bundled[name]
		if len(data) == 0 {
			return fail("install.identity_missing")
		}
		if e = atomic(filepath.Join(stage, name), data, 0644); e != nil {
			return e
		}
		changes = append(changes, File{Path: name, Mode: 0644, Size: int64(len(data)), SHA256: digest(data)})
	}
	var migration Migration
	if e = decode(bundled["migration.json"], &migration); e != nil || migration.Schema != 1 {
		return fail("migration.manifest_invalid")
	}
	if old != "" && old != root {
		saved, e := migrationFiles(old, migration)
		if e != nil {
			return e
		}
		for name, data := range saved {
			if e = atomic(filepath.Join(stage, name), data, 0600); e != nil {
				return fail("migration.copy_failed")
			}
			changes = append(changes, File{Path: name, Mode: 0600, Size: int64(len(data)), SHA256: digest(data)})
		}
	}
	ownership, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return fail("install.identity_encode_failed")
	}
	for name, data := range map[string][]byte{
		".components-manifest.json": append(ownership, '\n'),
		".install-receipt":          []byte("schema=1\nmodule=MagicNet\ncomponents=verified\nmigration=complete\n"),
	} {
		if e = atomic(filepath.Join(stage, name), data, 0600); e != nil {
			return e
		}
		changes = append(changes, File{Path: name, Mode: 0600, Size: int64(len(data)), SHA256: digest(data)})
	}
	j := Journal{Schema: 1, Phase: "prepared"}
	seen := map[string]bool{}
	for _, f := range changes {
		if seen[f.Path] {
			return fail("install.conflicting_file")
		}
		seen[f.Path] = true
		c := Change{File: f}
		b, e := readRegular(filepath.Join(root, f.Path), maxFile)
		if e == nil {
			c.HadOld = true
			c.OldHash = digest(b)
			st, _ := os.Stat(filepath.Join(root, f.Path))
			c.OldMode = uint32(st.Mode().Perm())
		} else if !errors.Is(e, os.ErrNotExist) {
			return fail("install.destination_unsafe")
		}
		j.Changes = append(j.Changes, c)
	}
	obsolete, e := obsoleteFiles(root, *m)
	if e != nil {
		return e
	}
	j.Changes = append(j.Changes, obsolete...)
	link := filepath.Join(root, "cli")
	needLink := false
	if st, se := os.Lstat(link); errors.Is(se, os.ErrNotExist) {
		needLink = true
	} else if se != nil || st.Mode()&os.ModeSymlink == 0 {
		return fail("install.cli_link_invalid")
	} else if target, le := os.Readlink(link); le != nil || target != "bin/magicnet-cli" {
		return fail("install.cli_link_invalid")
	}
	if e = writeJSON(filepath.Join(base, "journal.json"), j); e != nil {
		return e
	}
	journalWritten = true
	rollback := func(code string) error {
		if re := recoverInstall(root); re != nil {
			return re
		}
		return fail(code)
	}
	for _, c := range j.Changes {
		dest := filepath.Join(root, c.File.Path)
		current, ce := readRegular(dest, maxFile)
		if (c.HadOld && (ce != nil || digest(current) != c.OldHash)) || (!c.HadOld && !errors.Is(ce, os.ErrNotExist)) {
			return rollback("install.destination_changed")
		}
		if c.HadOld {
			back := filepath.Join(base, "backup", c.File.Path)
			if e = os.MkdirAll(filepath.Dir(back), 0700); e == nil {
				e = os.Rename(dest, back)
			}
			if e != nil {
				if re := recoverInstall(root); re != nil {
					return re
				}
				return fail("install.backup_failed")
			}
		}
		if c.Remove {
			continue
		}
		if e = os.MkdirAll(filepath.Dir(dest), 0700); e == nil {
			e = os.Rename(filepath.Join(stage, c.File.Path), dest)
		}
		if e != nil {
			if re := recoverInstall(root); re != nil {
				return re
			}
			return fail("install.replace_failed")
		}
	}
	if e = verifyInstalled(root); e != nil {
		if re := recoverInstall(root); re != nil {
			return re
		}
		return e
	}
	for _, f := range changes {
		if e = verifyFile(root, f); e != nil {
			return rollback("migration.readback_failed")
		}
	}
	for _, c := range obsolete {
		if _, e = os.Lstat(filepath.Join(root, c.File.Path)); !errors.Is(e, os.ErrNotExist) {
			return rollback("component.obsolete_readback_failed")
		}
	}
	for _, dir := range []string{"bin", "webroot", "ui", "META-INF", "META-INF/com", "META-INF/com/google", "META-INF/com/google/android"} {
		if st, se := os.Stat(filepath.Join(root, dir)); se == nil && st.IsDir() {
			if e = os.Chmod(filepath.Join(root, dir), 0755); e != nil {
				return rollback("install.permissions_failed")
			}
		}
	}
	if needLink {
		if e = os.Symlink("bin/magicnet-cli", link); e != nil {
			return rollback("install.cli_link_failed")
		}
	}
	j.Phase = "committed"
	if e = writeJSON(filepath.Join(base, "journal.json"), j); e != nil {
		if needLink {
			_ = os.Remove(link)
		}
		return rollback("install.commit_failed")
	}
	return os.RemoveAll(base)
}
func main() {
	args := os.Args[1:]
	var e error
	if len(args) == 2 && args[0] == "verify" {
		_, _, e = verifyArchive(args[1])
	} else if len(args) == 2 && args[0] == "verify-installed" {
		e = verifyInstalled(args[1])
	} else if len(args) >= 1 && args[0] == "install" {
		values := map[string]string{}
		for i := 1; i < len(args); i += 2 {
			if i+1 >= len(args) || !(args[i] == "--root" || args[i] == "--old" || args[i] == "--archive" || args[i] == "--cache-dir") {
				e = fail("install.arguments")
				break
			}
			if _, ok := values[args[i]]; ok {
				e = fail("install.arguments")
				break
			}
			values[args[i]] = args[i+1]
		}
		if e == nil {
			root, err := filepath.Abs(values["--root"])
			if err != nil || values["--root"] == "" || values["--archive"] == "" {
				e = fail("install.arguments")
			} else {
				e = install(root, values["--old"], values["--archive"], values["--cache-dir"])
			}
		}
	} else {
		e = fail("install.arguments")
	}
	if e != nil {
		code := e.Error()
		if !token(code) || !strings.Contains(code, ".") || code != strings.ToLower(code) {
			code = "filesystem.io_failure"
		}
		fmt.Fprintln(os.Stderr, "MagicNet:", code)
		os.Exit(1)
	}
	fmt.Println("MagicNet: verified")
}
