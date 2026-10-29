package main

import (
	"archive/zip"
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityIgnoresZipOrderAndTimestamp(t *testing.T) {
	a := File{Path: "a", Mode: 0644, Size: 1, SHA256: digest([]byte("a"))}
	b := File{Path: "b", Mode: 0755, Size: 1, SHA256: digest([]byte("b"))}
	if identity([]File{a, b}) != identity([]File{b, a}) {
		t.Fatal("content identity depends on archive order")
	}
	b.Mode = 0644
	if identity([]File{a, b}) == identity([]File{a, {Path: "b", Mode: 0755, Size: 1, SHA256: digest([]byte("b"))}}) {
		t.Fatal("mode does not affect identity")
	}
}
func makeZip(t *testing.T, names []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range names {
		h := &zip.FileHeader{Name: n, Method: zip.Store}
		h.SetMode(0644)
		f, e := w.CreateHeader(h)
		if e != nil {
			t.Fatal(e)
		}
		f.Write([]byte("synthetic"))
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}
func TestZipTraversalDuplicateAndLocalHeaderAmbiguity(t *testing.T) {
	for _, names := range [][]string{{"../escape"}, {"a", "a"}, {"/absolute"}, {"a\\b"}} {
		if _, _, e := zipFiles(makeZip(t, names)); e == nil {
			t.Fatalf("accepted unsafe archive %v", names)
		}
	}
	data := makeZip(t, []string{"good"})
	data[30] = 'x'
	if _, _, e := zipFiles(data); e == nil {
		t.Fatal("accepted divergent local/central names")
	}
	if _, _, e := zipFiles(makeZip(t, []string{"good"})); e != nil {
		t.Fatal(e)
	}
}
func TestInterruptedReplacementRestoresOnlyOwnedBytes(t *testing.T) {
	root := t.TempDir()
	name := "bin/file"
	old := []byte("old generation")
	next := []byte("new generation")
	file := File{Path: name, Mode: 0600, Size: int64(len(next)), SHA256: digest(next)}
	if e := atomic(filepath.Join(root, name), next, 0600); e != nil {
		t.Fatal(e)
	}
	if e := atomic(filepath.Join(root, ".components-install/backup", name), old, 0600); e != nil {
		t.Fatal(e)
	}
	j := Journal{Schema: 1, Phase: "prepared", Changes: []Change{{File: file, HadOld: true, OldHash: digest(old), OldMode: 0600}}}
	if e := writeJSON(filepath.Join(root, ".components-install/journal.json"), j); e != nil {
		t.Fatal(e)
	}
	if e := recoverInstall(root); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(root, name))
	if !bytes.Equal(got, old) {
		t.Fatal("did not restore previous bytes")
	}
	if e := atomic(filepath.Join(root, name), []byte("external writer"), 0600); e != nil {
		t.Fatal(e)
	}
	atomic(filepath.Join(root, ".components-install/backup", name), old, 0600)
	writeJSON(filepath.Join(root, ".components-install/journal.json"), j)
	if e := recoverInstall(root); e == nil {
		t.Fatal("overwrote an external writer")
	}
	got, _ = os.ReadFile(filepath.Join(root, name))
	if string(got) != "external writer" {
		t.Fatal("external bytes lost")
	}
}
func TestMigrationOneManifestAndLinksFailClosed(t *testing.T) {
	old := t.TempDir()
	atomic(filepath.Join(old, ".config/magicnet/settings.json"), []byte("private setting"), 0600)
	atomic(filepath.Join(old, ".config/sing-box/config.json"), []byte("old template"), 0600)
	atomic(filepath.Join(old, ".config/sing-box/rules/old.srs"), []byte("old rule"), 0600)
	m := Migration{Schema: 1, Paths: []MigrationPath{{Path: ".config", Action: "restore"}}, Exclusions: []MigrationPath{{Path: ".config/sing-box/config.json", Action: "backup_only"}, {Path: ".config/sing-box/rules", Action: "replace"}}}
	files, e := migrationFiles(old, m)
	if e != nil {
		t.Fatal(e)
	}
	if string(files[".config/magicnet/settings.json"]) != "private setting" || string(files[".migration-backup/.config/sing-box/config.json"]) != "old template" {
		t.Fatal("migration dropped declared state")
	}
	if len(files) != 2 {
		t.Fatal("immutable rules leaked into migration")
	}
	os.Symlink("/tmp", filepath.Join(old, ".config/unsafe"))
	if _, e = migrationFiles(old, m); e == nil {
		t.Fatal("followed migration symlink")
	}
}
func TestPublicDestinationPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "::1", "fc00::1"} {
		if publicIP(net.ParseIP(raw)) {
			t.Fatal("accepted private destination")
		}
	}
}

func TestIdentityJSONRejectsAmbiguousKeys(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"schema":2}`, `{"schema":1,"Schema":1}`, `{"schema":1} {"schema":2}`, `{"paths":[{"path":"a","path":"b"}]}`} {
		var value map[string]any
		if e := decode([]byte(raw), &value); e == nil {
			t.Fatal("accepted ambiguous identity document")
		}
	}
}

func TestProductVersionRecipeAndChannelStaySeparate(t *testing.T) {
	m := Manifest{Version: "v1.8.1", VersionCode: 10609, RecipeVersion: "0.3.1", Channel: "candidate"}
	prop := map[string]string{"version": "v1.8.1", "versionCode": "10609", "recipeVersion": "0.3.1", "releaseChannel": "candidate"}
	if e := validateProductProperties(&m, prop); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"version", "versionCode", "recipeVersion", "releaseChannel"} {
		original := prop[field]
		prop[field] = "different"
		if e := validateProductProperties(&m, prop); e == nil {
			t.Fatalf("accepted divergent %s", field)
		}
		prop[field] = original
	}
	// Old ownership manifests remain readable for component reuse and removal.
	legacy := Manifest{Version: "v0.3.1"}
	if e := validateProductProperties(&legacy, map[string]string{"version": "v0.3.1", "versionCode": "30001"}); e != nil {
		t.Fatal("legacy version-only manifest became unreadable", e)
	}
	stripped := Manifest{Version: "v1.8.1"}
	if e := validateProductProperties(&stripped, prop); e == nil {
		t.Fatal("accepted stripped metadata for a module declaring recipe/channel")
	}
}

func TestObsoleteRemovalNeedsUnchangedSuccessfulOwnership(t *testing.T) {
	root := t.TempDir()
	data := []byte("owned previous component")
	file := File{Path: "webroot/obsolete.js", Mode: 0644, Size: int64(len(data)), SHA256: digest(data)}
	groups := [][]File{{
		{Path: "bin/magicnet-cli", Mode: 0755, Size: 1, SHA256: digest([]byte("x"))},
		{Path: "bin/sing-box", Mode: 0755, Size: 1, SHA256: digest([]byte("x"))},
	}, {{Path: "webroot/index.html", Mode: 0644, Size: 1, SHA256: digest([]byte("x"))}, file}, {{Path: ".config/sing-box/rules/manifest.json", Mode: 0644, Size: 1, SHA256: digest([]byte("x"))}}}
	old := Manifest{Schema: 1, ModuleID: "MagicNet", Arch: "android-arm64", Version: "v0.3.1", ReleaseTag: "v0.3.1"}
	for i, files := range groups {
		id := []string{"engine", "webui", "rules"}[i]
		ident := identity(files)
		old.Components = append(old.Components, Component{ID: id, Identity: ident, Archive: "MagicNet-component-" + id + "-" + ident + ".zip", SHA256: digest([]byte("archive")), Files: files})
	}
	if e := validateManifest(&old); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(root, ".components-manifest.json"), old); e != nil {
		t.Fatal(e)
	}
	atomic(filepath.Join(root, file.Path), data, 0644)
	next := old
	next.Components = append([]Component(nil), old.Components...)
	next.Components[1].Files = next.Components[1].Files[:1]
	changes, e := obsoleteFiles(root, next)
	if e != nil || len(changes) != 1 || !changes[0].Remove {
		t.Fatal("owned obsolete file was not identified", e)
	}
	atomic(filepath.Join(root, file.Path), []byte("external modification"), 0644)
	changes, e = obsoleteFiles(root, next)
	if e != nil || len(changes) != 0 {
		t.Fatal("modified obsolete file was marked for removal", e)
	}
	atomic(filepath.Join(root, ".components-install/backup", file.Path), data, 0644)
	os.Remove(filepath.Join(root, file.Path))
	journal := Journal{Schema: 1, Phase: "prepared", Changes: []Change{{File: file, Remove: true, HadOld: true, OldHash: file.SHA256, OldMode: file.Mode}}}
	writeJSON(filepath.Join(root, ".components-install/journal.json"), journal)
	if e := recoverInstall(root); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(root, file.Path))
	if !bytes.Equal(got, data) {
		t.Fatal("removed file was not restored on interrupted update")
	}
}

func TestInPlaceUpgradeIsRejectedBeforeAnyPublication(t *testing.T) {
	root := t.TempDir()
	active := []byte("synthetic active configuration")
	if e := atomic(filepath.Join(root, ".config/sing-box/config.json"), active, 0600); e != nil {
		t.Fatal(e)
	}
	if e := install(root, root, "/nonexistent/not-read.zip", ""); e == nil || e.Error() != "install.in_place_upgrade_requires_staging" {
		t.Fatal("in-place upgrade was not rejected before archive/staging work", e)
	}
	got, _ := os.ReadFile(filepath.Join(root, ".config/sing-box/config.json"))
	if !bytes.Equal(got, active) {
		t.Fatal("active data changed")
	}
	for _, name := range []string{".components-install", ".components-install.lock", ".migration-backup", "bin"} {
		if _, e := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(e) {
			t.Fatal("rejected install created runtime state", name)
		}
	}
}
