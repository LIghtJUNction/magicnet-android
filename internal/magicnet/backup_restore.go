package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type backupJournal struct {
	Old     map[string][]byte `json:"old"`
	Next    map[string][]byte `json:"next"`
	Running bool              `json:"running"`
	Phase   string            `json:"phase"`
}

var backupRoots = []string{".config", ".state/private/subscription/generations", ".state/private/tailscale", ".state/private/runtime-checkpoint.json", ".state/platform-owned.json", ".state/lifecycle/last-known-good.json", ".state/private/subscription/last.json"}

func (a *App) backupCurrent() (map[string][]byte, error) {
	out := map[string][]byte{}
	var total int64
	for _, root := range backupRoots {
		if _, e := os.Lstat(a.Path(root)); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if root == ".state/private/tailscale" {
			b, e := ReadRegular(a.Path(root, ".magicnet-owned"), 64)
			if e != nil || string(b) != "MagicNet\n" {
				return nil, E("backup.tailscale_ownership_unknown", "Tailscale directory ownership is not proved.")
			}
		}
		e := filepath.WalkDir(a.Path(root), func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(a.Root, p)
			if e != nil {
				return e
			}
			if d.Type()&os.ModeSymlink != 0 {
				return E("backup.unsafe", "Backup excludes links.")
			}
			if strings.HasPrefix(rel, ".config/sing-box/rules") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !backupAllowed(rel) {
				return E("backup.unsafe", "Unapproved backup path.")
			}
			b, e := ReadRegular(p, 8<<20)
			if e != nil {
				return e
			}
			total += int64(len(b))
			if total > 64<<20 {
				return E("backup.limit", "Backup exceeds 64 MiB.")
			}
			out[rel] = b
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}

func (a *App) checkBackupConfig(ctx context.Context, files map[string][]byte) error {
	b, ok := files[".config/sing-box/config.json"]
	if !ok {
		return E("backup.config_missing", "Backup has no active configuration.")
	}
	var config M
	if len(b) > 4<<20 || DecodeJSON(b, &config) != nil || config == nil {
		return E("backup.invalid", "Backup configuration is invalid.")
	}
	keys := map[string]string{}
	if b := files[".config/magicnet/tailscale-auth.json"]; b != nil {
		if len(b) > 64<<10 || DecodeJSON(b, &keys) != nil {
			return E("backup.invalid", "Backup private credentials are invalid.")
		}
	}
	endpoints, _ := config["endpoints"].([]any)
	for _, v := range endpoints {
		m, _ := v.(map[string]any)
		if m["type"] != "tailscale" {
			continue
		}
		if m["system_interface"] == true {
			return E("tailscale.system_interface_forbidden", "Tailscale must use userspace networking.")
		}
		if m["auth_key"] == nil || m["auth_key"] == "" {
			m["auth_key"] = keys[asString(m["tag"])]
		}
	}
	prepared, e := json.Marshal(config)
	if e != nil {
		return e
	}
	return a.checkPreparedConfig(ctx, prepared)
}

func backupPaths(j backupJournal) []string {
	out := make([]string, 0, len(j.Old))
	for p := range j.Old {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func (a *App) writeBackupFile(p string, b []byte) error {
	if !backupAllowed(p) || filepath.Clean(p) != p || strings.Contains(p, "\\") {
		return E("backup.unsafe", "Unapproved recovery path.")
	}
	if b != nil {
		return AtomicWrite(a.Path(p), b, 0600)
	}
	if e := safeAncestors(a.Path(p)); e != nil {
		return e
	}
	if e := os.Remove(a.Path(p)); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if d, e := os.Open(filepath.Dir(a.Path(p))); e == nil {
		defer d.Close()
		return d.Sync()
	}
	return nil
}

func (a *App) restoreBackup(ctx context.Context, files map[string][]byte) (M, error) {
	if e := a.checkBackupConfig(ctx, files); e != nil {
		return nil, e
	}
	for p := range files {
		if strings.HasPrefix(p, ".state/private/tailscale/") && string(files[".state/private/tailscale/.magicnet-owned"]) != "MagicNet\n" {
			return nil, E("backup.tailscale_ownership_unknown", "Backup Tailscale state has no ownership marker.")
		}
	}
	e := a.WithLifecycleLock(ctx, 10*time.Second, func() error {
		if e := a.recoverBackup(ctx); e != nil {
			return e
		}
		for _, p := range []string{".state/private/runtime-transaction.json", ".state/private/runtime-initialization.json", ".state/private/subscription/journal.json", ".state/lifecycle/journal.json"} {
			if _, e := os.Stat(a.Path(p)); e == nil {
				return E("backup.recovery_pending", "Complete pending recovery before restoring a backup.")
			}
		}
		old, e := a.backupCurrent()
		if e != nil {
			return e
		}
		running, e := a.IsRunning(ctx)
		if e != nil {
			return e
		}
		if running {
			if e = a.checkBackupConfig(ctx, old); e != nil {
				return E("backup.recovery_unavailable", "The running configuration cannot be validated for rollback.")
			}
		}
		for p := range files {
			if _, ok := old[p]; !ok {
				old[p] = nil
			}
		}
		j := backupJournal{Old: old, Next: files, Running: running, Phase: "prepared"}
		jp := a.Path(".state", "backup", "restore-journal.json")
		if e = WriteJSON(jp, j); e != nil {
			return e
		}
		if running {
			if e = a.stopCore(ctx); e != nil {
				return e
			}
		}
		j.Phase = "writing"
		if e = WriteJSON(jp, j); e != nil {
			return e
		}
		for _, p := range backupPaths(j) {
			if e = a.writeBackupFile(p, files[p]); e != nil {
				break
			}
		}
		if e == nil {
			e = a.CheckConfig(ctx, files[".config/sing-box/config.json"])
		}
		if e == nil && running {
			e = a.startCore(ctx, "backup-"+token())
		}
		if e != nil {
			if re := a.rollbackBackup(ctx, j); re != nil {
				return re
			}
			return e
		}
		j.Phase = "committed"
		if e = WriteJSON(jp, j); e != nil {
			return E("backup.recovery_pending", "Backup commit bookkeeping is incomplete.")
		}
		return os.Remove(jp)
	})
	if e != nil {
		return nil, e
	}
	if e = a.Publish(ctx); e != nil {
		return nil, e
	}
	return M{"restored": true}, nil
}

func (a *App) rollbackBackup(ctx context.Context, j backupJournal) error {
	if len(j.Old) > 10000 || len(j.Next) > 10000 {
		return E("backup.recovery_pending", "Recovery manifest exceeds its limit.")
	}
	for _, p := range backupPaths(j) {
		if !backupAllowed(p) {
			return E("backup.recovery_pending", "Invalid recovery path.")
		}
		b, e := ReadRegular(a.Path(p), 8<<20)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return E("backup.recovery_pending", "Cannot observe recovery ownership.")
		}
		if digest(b) != digest(j.Old[p]) && digest(b) != digest(j.Next[p]) {
			return E("backup.rollback_conflict", "A file changed outside the backup transaction.")
		}
	}
	if e := a.stopCore(ctx); e != nil {
		return e
	}
	for _, p := range backupPaths(j) {
		if e := a.writeBackupFile(p, j.Old[p]); e != nil {
			return E("backup.recovery_pending", "Backup rollback write is incomplete.")
		}
	}
	if j.Running {
		if e := a.checkBackupConfig(ctx, j.Old); e != nil {
			return E("backup.recovery_pending", "Restored baseline failed validation.")
		}
		if e := a.startCore(ctx, "backup-recovery-"+token()); e != nil {
			return E("backup.recovery_pending", "Backup rollback startup failed.")
		}
	}
	return os.Remove(a.Path(".state", "backup", "restore-journal.json"))
}
func (a *App) recoverBackup(ctx context.Context) error {
	jp := a.Path(".state", "backup", "restore-journal.json")
	var j backupJournal
	e := ReadJSON(jp, 192<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || j.Old == nil || j.Next == nil {
		return E("backup.recovery_pending", "Backup recovery journal is unreadable.")
	}
	if j.Phase == "committed" {
		return os.Remove(jp)
	}
	return a.rollbackBackup(ctx, j)
}
