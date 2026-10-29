package magicnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RuntimeFileChange struct {
	Path           string `json:"path"`
	Data           []byte `json:"data,omitempty"`
	Remove         bool   `json:"remove,omitempty"`
	BeforeActivate bool   `json:"before_activate,omitempty"`
}
type RuntimeFileSnapshot struct {
	Path     string `json:"path"`
	Data     []byte `json:"data,omitempty"`
	Exists   bool   `json:"exists"`
	Expected string `json:"expected,omitempty"`
}
type RuntimeTransaction struct {
	Schema        int                   `json:"schema"`
	Generation    string                `json:"generation_id"`
	Phase         string                `json:"phase"`
	Running       bool                  `json:"running"`
	OldConfig     []byte                `json:"old_config"`
	CandidateHash string                `json:"candidate_hash"`
	Files         []RuntimeFileSnapshot `json:"files"`
	Created       int64                 `json:"created_epoch"`
}

func (a *App) snapshotFiles(changes []RuntimeFileChange) ([]RuntimeFileSnapshot, error) {
	paths := map[string]RuntimeFileChange{}
	for _, c := range changes {
		if !safeRuntimeTransactionPath(c.Path) {
			return nil, E("transaction.path_invalid", "Invalid transaction path")
		}
		paths[c.Path] = c
	}
	for _, p := range []string{".state/private/runtime-checkpoint.json", ".state/platform-owned.json", ".state/lifecycle/last-known-good.json"} {
		if _, ok := paths[p]; !ok {
			change := RuntimeFileChange{Path: p}
			if p == ".state/private/runtime-checkpoint.json" && a.RuntimeCheckpoint != nil {
				change.Data = rtJSON(a.RuntimeCheckpoint)
			}
			if p == ".state/platform-owned.json" && a.PlatformOwned != nil {
				change.Data = rtJSON(a.PlatformOwned)
			}
			paths[p] = change
		}
	}
	snapshots := []RuntimeFileSnapshot{}
	for path, c := range paths {
		b, e := ReadRegular(a.Path(path), 16<<20)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		expected := ""
		if c.Data != nil {
			expected = digest(c.Data)
		}
		if c.Remove {
			expected = "absent"
		}
		snapshots = append(snapshots, RuntimeFileSnapshot{path, b, e == nil, expected})
	}
	return snapshots, nil
}

func safeRuntimeTransactionPath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.HasPrefix(path, "../") && (strings.HasPrefix(path, ".config/magicnet/") || strings.HasPrefix(path, ".config/sing-box/") || path == ".state/private/runtime-checkpoint.json" || path == ".state/private/tailscale/.magicnet-owned" || path == ".state/platform-owned.json" || path == ".state/lifecycle/last-known-good.json")
}

func (a *App) validatedBaseline(ctx context.Context) ([]byte, error) {
	old, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e == nil && a.CheckConfig(ctx, old) == nil {
		return old, nil
	}
	for _, path := range []string{a.Path(".state", "lifecycle", "last-known-good.json"), a.Path(".state", "private", "last-known-good.json")} {
		b, e := ReadRegular(path, 4<<20)
		if e == nil && a.CheckConfig(ctx, b) == nil {
			return b, nil
		}
	}
	return nil, E("config.recovery_unavailable", "No independently validated recovery configuration is available")
}

func (a *App) performRuntimeChange(ctx context.Context, candidate []byte, changes []RuntimeFileChange, generation string) error {
	if e := a.CheckConfig(ctx, candidate); e != nil {
		return e
	}
	old, e := a.validatedBaseline(ctx)
	if e != nil {
		return e
	}
	running, e := a.IsRunning(ctx)
	if e != nil {
		return e
	}
	files, e := a.snapshotFiles(changes)
	if e != nil {
		return e
	}
	j := RuntimeTransaction{1, generation, "prepared", running, old, digest(candidate), files, time.Now().Unix()}
	if jsonSize(j) > 32<<20 {
		return E("config.limit", "Runtime transaction evidence exceeds its recovery limit")
	}
	jp := a.Path(".state", "private", "runtime-transaction.json")
	if e = WriteJSON(jp, j); e != nil {
		return e
	}
	apply := func(before bool) error {
		for _, c := range changes {
			if c.BeforeActivate != before {
				continue
			}
			if c.Remove {
				if e := removeRuntimeFile(a.Path(c.Path)); e != nil {
					return e
				}
			} else if e := AtomicWrite(a.Path(c.Path), c.Data, 0600); e != nil {
				return e
			}
		}
		return nil
	}
	if e = apply(true); e == nil {
		j.Phase = "activate"
		e = WriteJSON(jp, j)
	}
	if e == nil {
		e = a.ActivateConfig(ctx, candidate, generation, running)
	}
	if e == nil {
		j.Phase = "commit"
		e = WriteJSON(jp, j)
	}
	if e == nil {
		e = apply(false)
	}
	committed := false
	if e == nil {
		j.Phase = "committed"
		e = WriteJSON(jp, j)
		committed = e == nil
	}
	if e == nil {
		e = removeRuntimeFile(jp)
	}
	if e != nil {
		if committed {
			// A durable commit decision is recovered forward. Cleanup failure
			// must not roll back files while leaving a committed journal behind.
			return E("config.recovery_pending", "Committed runtime configuration has pending journal cleanup")
		}
		// Activation failure and bookkeeping failure share the same baseline.
		// The independent recovery context survives caller cancellation.
		rctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		j.Phase = "recovering"
		if re := WriteJSON(jp, j); re != nil {
			return E("config.recovery_pending", "Runtime rollback decision could not be recorded")
		}
		if re := a.restoreRuntimeTransaction(rctx, j); re != nil {
			return E("config.recovery_pending", "Runtime recovery remains pending")
		}
		if re := removeRuntimeFile(jp); re != nil {
			return E("config.recovery_pending", "Runtime recovery journal could not be cleared")
		}
		return e
	}
	return nil
}

func (a *App) restoreRuntimeTransaction(ctx context.Context, j RuntimeTransaction) error {
	if j.Schema != 1 || len(j.OldConfig) == 0 || a.CheckConfig(ctx, j.OldConfig) != nil {
		return E("config.recovery_pending", "The recovery baseline is invalid")
	}
	current, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e == nil && digest(current) != j.CandidateHash && digest(current) != digest(j.OldConfig) {
		return E("override.rollback_conflict", "Configuration changed outside this transaction")
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for _, file := range j.Files {
		if !safeRuntimeTransactionPath(file.Path) {
			return E("config.recovery_pending", "Recovery paths are invalid")
		}
		now, e := ReadRegular(a.Path(file.Path), 16<<20)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if file.Expected != "" {
			oldMatch := (file.Exists && e == nil && digest(now) == digest(file.Data)) || (!file.Exists && errors.Is(e, os.ErrNotExist))
			newMatch := (file.Expected == "absent" && errors.Is(e, os.ErrNotExist)) || (e == nil && digest(now) == file.Expected)
			if !oldMatch && !newMatch {
				return E("override.rollback_conflict", "A transaction-owned file changed externally")
			}
		}
	}
	a.ClearMaterialization()
	for _, file := range j.Files {
		if file.Exists {
			if e = AtomicWrite(a.Path(file.Path), file.Data, 0600); e != nil {
				return e
			}
		} else if e = removeRuntimeFile(a.Path(file.Path)); e != nil {
			return e
		}
	}
	if e = a.ActivateConfig(ctx, j.OldConfig, "recovery-"+j.Generation, j.Running); e != nil {
		return e
	}
	// Lifecycle activation may maintain its own LKG; restore checkpoint bytes
	// again so ownership corresponds exactly to the recovered source generation.
	for _, file := range j.Files {
		if file.Path == ".state/private/runtime-checkpoint.json" || file.Path == ".state/platform-owned.json" {
			if file.Exists {
				if e = AtomicWrite(a.Path(file.Path), file.Data, 0600); e != nil {
					return e
				}
			} else if e = removeRuntimeFile(a.Path(file.Path)); e != nil {
				return e
			}
		}
	}
	return nil
}

func removeRuntimeFile(path string) error {
	if e := safeAncestors(path); e != nil {
		return e
	}
	st, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return E("file.unsafe", "Only an owned regular file can be removed")
	}
	if e = os.Remove(path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func (a *App) RecoverRuntime(ctx context.Context) error {
	if e := a.ensureOwnedRuntimePaths(ctx); e != nil {
		return e
	}
	if e := a.recoverRuntimeInitialization(ctx); e != nil {
		return e
	}
	var j RuntimeTransaction
	jp := a.Path(".state", "private", "runtime-transaction.json")
	e := ReadJSON(jp, 32<<20, &j)
	if e == nil {
		if j.Phase == "committed" {
			if e = a.verifyRuntimeCommit(ctx, j); e != nil {
				return e
			}
			if e = removeRuntimeFile(jp); e != nil {
				return e
			}
		} else {
			if e = a.restoreRuntimeTransaction(ctx, j); e != nil {
				return e
			}
			if e = removeRuntimeFile(jp); e != nil {
				return e
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return E("config.recovery_pending", "Runtime recovery journal is unreadable")
	}
	return a.recoverSubscription(ctx)
}

func (a *App) verifyRuntimeCommit(ctx context.Context, j RuntimeTransaction) error {
	if j.Schema != 1 || !safeToken(j.Generation) {
		return E("config.recovery_pending", "Runtime commit evidence is invalid")
	}
	current, e := ReadRegular(a.ConfigPath(), 4<<20)
	if e != nil || digest(current) != j.CandidateHash || a.CheckConfig(ctx, current) != nil {
		return E("config.recovery_pending", "Committed runtime generation cannot be verified")
	}
	for _, file := range j.Files {
		if !safeRuntimeTransactionPath(file.Path) {
			return E("config.recovery_pending", "Committed runtime path is invalid")
		}
		if file.Expected == "" {
			continue
		}
		data, re := ReadRegular(a.Path(file.Path), 16<<20)
		if file.Expected == "absent" && errors.Is(re, os.ErrNotExist) {
			continue
		}
		if re != nil || digest(data) != file.Expected {
			return E("config.recovery_pending", "Committed runtime metadata does not match its generation")
		}
	}
	return nil
}
