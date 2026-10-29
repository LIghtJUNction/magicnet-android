package magicnet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyAbsolutePaths(value any, root string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if text, ok := child.(string); ok && (key == "path" || key == "state_directory") && (strings.HasPrefix(text, ".config/sing-box/rules/") || text == ".state/private/core-cache.db" || text == ownedTailscaleRelative) {
				v[key] = filepath.Join(root, text)
			} else {
				legacyAbsolutePaths(child, root)
			}
		}
	case []any:
		for _, child := range v {
			legacyAbsolutePaths(child, root)
		}
	}
}

func legacyRuntimePathFixture(t *testing.T) (*App, runtimePathRelocation) {
	t.Helper()
	a := realCoreFixture(t)
	if e := a.EnsureDefaultConfig(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := a.setIntent(false); e != nil {
		t.Fatal(e)
	}
	for _, path := range runtimePathFiles {
		b, e := ReadRegular(a.Path(path), 16<<20)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		var value M
		if DecodeJSON(b, &value) != nil {
			t.Fatal(path)
		}
		legacyAbsolutePaths(value, a.Root)
		if path == ".state/private/runtime-checkpoint.json" {
			value["fingerprint"] = digest(rtJSON(value["effective"]))
		}
		if e := AtomicWrite(a.Path(path), rtJSON(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	j, e := a.planOwnedRuntimePaths()
	if e != nil || len(j.Files) != 3 {
		t.Fatal("legacy fixture should relocate active config, LKG and checkpoint", len(j.Files), e)
	}
	return a, j
}

func TestRealCoreOwnedPathRelocationRecovery(t *testing.T) {
	for _, phase := range []string{"prepared", "committed", "rollback", "external_conflict"} {
		t.Run(phase, func(t *testing.T) {
			a, j := legacyRuntimePathFixture(t)
			j.Phase = phase
			if phase == "external_conflict" {
				j.Phase = "prepared"
			}
			if e := WriteJSON(a.Path(runtimePathJournal), j); e != nil {
				t.Fatal(e)
			}
			if e := AtomicWrite(a.Path(j.Files[0].Path), j.Files[0].After, 0600); e != nil {
				t.Fatal(e)
			}
			if phase == "external_conflict" {
				var changed M
				DecodeJSON(j.Files[0].After, &changed)
				changed["log"] = M{"level": "info"}
				AtomicWrite(a.Path(j.Files[0].Path), rtJSON(changed), 0600)
				before := mustRead(t, a.Path(runtimePathJournal))
				if e := a.ensureOwnedRuntimePaths(context.Background()); ErrorCode(e) != "runtime.paths_conflict" {
					t.Fatal(e)
				}
				if !bytes.Equal(before, mustRead(t, a.Path(runtimePathJournal))) || !bytes.Equal(j.Files[1].Before, mustRead(t, a.Path(j.Files[1].Path))) {
					t.Fatal("conflict changed journal or another file")
				}
				return
			}
			if e := a.recoverOwnedRuntimePaths(context.Background()); e != nil {
				t.Fatal(e)
			}
			for _, file := range j.Files {
				expected := file.After
				if phase == "rollback" {
					expected = file.Before
				}
				if !bytes.Equal(expected, mustRead(t, a.Path(file.Path))) {
					t.Fatal("recovery direction or full baseline mismatch", file.Path, phase)
				}
			}
			if _, e := os.Lstat(a.Path(runtimePathJournal)); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("completed recovery retained journal", e)
			}
			if e := a.EnsureDefaultConfig(context.Background()); e != nil {
				t.Fatal(e)
			}
			for _, file := range j.Files {
				if !bytes.Equal(file.After, mustRead(t, a.Path(file.Path))) {
					t.Fatal("stopped retry did not finish relocation", file.Path)
				}
			}
			if intent, e := a.ReadServiceIntent(); e != nil || intent {
				t.Fatal("relocation changed stopped intent", e)
			}
			checkRealCore(t, a, mustRead(t, a.ConfigPath()))
		})
	}
}

func TestUpdatePublicationRetainsConflictAndCanonicalRecovery(t *testing.T) {
	for _, scenario := range []string{"external", "canonical_failure"} {
		t.Run(scenario, func(t *testing.T) {
			a := &App{Root: t.TempDir(), Platform: "linux"}
			i := UpdateIntent{ID: "recovery-123", Action: "check", Phase: "available", Error: "none"}
			l := UpdateLedger{Used: map[string]string{i.ID: "confirmed-intent"}, Results: map[string]UpdateIntent{i.ID: i}, Order: []string{i.ID}}
			j := updateRecordJournal{Schema: 1, Files: []updateRecordFile{{Path: ".state/module-update/ledger.json", Before: digest(nil), After: rtJSON(l)}, {Path: ".config/magicnet/module-update.conf", Before: digest(nil), After: rtJSON(i)}}}
			jp := a.Path(".state", "module-update", "record-journal.json")
			if e := WriteJSON(jp, j); e != nil {
				t.Fatal(e)
			}
			if scenario == "external" {
				external := []byte("external-owner-evidence")
				if e := AtomicWrite(a.Path(j.Files[0].Path), external, 0600); e != nil {
					t.Fatal(e)
				}
				if e := a.recoverUpdateRecord(); ErrorCode(e) != "module-update.record_conflict" {
					t.Fatal(e)
				}
				if !bytes.Equal(external, mustRead(t, a.Path(j.Files[0].Path))) {
					t.Fatal("external ledger was overwritten")
				}
				if _, e := os.Lstat(jp); e != nil {
					t.Fatal("conflict evidence lost", e)
				}
				return
			}
			if e := AtomicWrite(a.Path(".state", "machines"), []byte("block-directory-publication"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := a.recoverUpdateRecord(); ErrorCode(e) != "module-update.record_pending" {
				t.Fatal(e)
			}
			if _, e := os.Lstat(jp); e != nil {
				t.Fatal("canonical failure discarded recovery", e)
			}
			if e := os.Remove(a.Path(".state", "machines")); e != nil {
				t.Fatal(e)
			}
			if e := a.recoverUpdateRecord(); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Lstat(jp); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("recovered record still pending", e)
			}
			if !bytes.Contains(mustRead(t, a.Path(".state", "machines", "module-update.state")), []byte("phase=available")) {
				t.Fatal("canonical receipt was not published")
			}
		})
	}
}
