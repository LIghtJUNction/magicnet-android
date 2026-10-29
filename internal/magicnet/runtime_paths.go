package magicnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const ownedTailscaleRelative = ".state/private/tailscale"
const runtimePathJournal = ".state/private/runtime-path-relocation.json"

var runtimePathFiles = []string{
	".config/sing-box/config.json",
	".state/lifecycle/last-known-good.json",
	".state/private/last-known-good.json",
	".state/private/runtime-checkpoint.json",
	".config/magicnet/runtime-settings.json",
}

type runtimePathFile struct {
	Path   string `json:"path"`
	Before []byte `json:"before"`
	After  []byte `json:"after"`
}

type runtimePathRelocation struct {
	Schema int               `json:"schema"`
	Phase  string            `json:"phase"`
	Files  []runtimePathFile `json:"files"`
}

// Managed paths are relative to the working directory used by both core check
// and core run. Only the current root and the manager's paired stage/live roots
// are accepted as historical absolute roots; arbitrary user prefixes are not.
func (a *App) isManagedPath(value, relative string) bool {
	if value == relative {
		return true
	}
	for _, root := range a.historicalRuntimeRoots() {
		if value == filepath.Join(root, relative) {
			return true
		}
	}
	return false
}

func (a *App) historicalRuntimeRoots() []string {
	roots := []string{a.Root}
	if filepath.Base(a.Root) == "MagicNet" && stringIn(filepath.Base(filepath.Dir(a.Root)), "modules", "modules_update") {
		base := filepath.Dir(filepath.Dir(a.Root))
		roots = append(roots, filepath.Join(base, "modules", "MagicNet"), filepath.Join(base, "modules_update", "MagicNet"))
	}
	return roots
}

func (a *App) isCurrentOwnedTailscalePath(value string) bool {
	return value == ownedTailscaleRelative || value == a.Path(ownedTailscaleRelative)
}

func (a *App) ownedTailscaleMarker() bool {
	b, e := ReadRegular(a.Path(ownedTailscaleRelative, ".magicnet-owned"), 128)
	return e == nil && strings.TrimSpace(string(b)) == "MagicNet"
}

func (a *App) normalizeOwnedConfigPaths(config M, assets map[string]RuleAsset, tailscaleTag string) bool {
	changed := false
	for _, item := range rtArray(rtMap(config["route"])["rule_set"]) {
		r := rtMap(item)
		asset, known := assets[rtString(r["tag"])]
		relative := filepath.Join(".config", "sing-box", "rules", asset.Path)
		path := rtString(r["path"])
		if known && r["type"] == "local" && r["format"] == asset.Format && path != relative && a.isManagedPath(path, relative) {
			r["path"] = relative
			changed = true
		}
	}
	cache := rtMap(rtMap(config["experimental"])["cache_file"])
	if path := rtString(cache["path"]); path != ".state/private/core-cache.db" && a.isManagedPath(path, ".state/private/core-cache.db") {
		cache["path"] = ".state/private/core-cache.db"
		changed = true
	}
	for _, item := range rtArray(config["endpoints"]) {
		if a.normalizeOwnedTailscale(rtMap(item), tailscaleTag) {
			changed = true
		}
	}
	return changed
}

func (a *App) normalizeOwnedTailscale(endpoint M, tag string) bool {
	if tag == "" || endpoint["type"] != "tailscale" || endpoint["tag"] != tag {
		return false
	}
	path := rtString(endpoint["state_directory"])
	if path != ownedTailscaleRelative && a.isManagedPath(path, ownedTailscaleRelative) {
		endpoint["state_directory"] = ownedTailscaleRelative
		return true
	}
	return false
}

func (a *App) planOwnedRuntimePaths() (runtimePathRelocation, error) {
	j := runtimePathRelocation{Schema: 1, Phase: "prepared"}
	contents := map[string][]byte{}
	mayRelocate := false
	for _, path := range runtimePathFiles {
		b, e := ReadRegular(a.Path(path), 16<<20)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return j, e
		}
		contents[path] = b
		for _, root := range a.historicalRuntimeRoots() {
			for _, relative := range []string{".config/sing-box/rules/", ".state/private/core-cache.db", ownedTailscaleRelative} {
				value, _ := json.Marshal(filepath.Join(root, relative))
				if bytes.Contains(b, value[:len(value)-1]) {
					mayRelocate = true
				}
			}
		}
	}
	if !mayRelocate {
		// Ordinary relative-path generations and unrelated invalid configs
		// stay under their existing validation/recovery contracts.
		return j, nil
	}
	var manifest RuleManifest
	if e := ReadJSON(a.Path(".config", "sing-box", "rules", "manifest.json"), 256<<10, &manifest); errors.Is(e, os.ErrNotExist) {
		return j, nil
	} else if e != nil || manifest.Schema != 1 || manifest.Revision != PolicyRevision {
		return j, E("runtime.paths_invalid", "The owned path asset manifest is invalid.")
	}
	assets := map[string]RuleAsset{}
	for _, asset := range manifest.Files {
		if stringIn(asset.Tag, PolicyRuleTags...) && !filepath.IsAbs(asset.Path) && filepath.Clean(asset.Path) == asset.Path && !strings.HasPrefix(asset.Path, "../") {
			assets[asset.Tag] = asset
		}
	}
	var settings RuntimeSettings
	settingsData := contents[".config/magicnet/runtime-settings.json"]
	tailscaleTag := ""
	if settingsData != nil {
		if DecodeJSON(settingsData, &settings) != nil {
			return j, E("runtime.paths_invalid", "Runtime settings cannot be observed before path relocation.")
		}
		if settings.Tailscale.OwnedDirectory && a.ownedTailscaleMarker() && a.isManagedPath(rtString(settings.Tailscale.Endpoint["state_directory"]), ownedTailscaleRelative) {
			tailscaleTag = rtString(settings.Tailscale.Endpoint["tag"])
		}
	}
	for _, path := range runtimePathFiles {
		before := contents[path]
		if before == nil {
			continue
		}
		var after []byte
		changed := false
		switch path {
		case ".state/private/runtime-checkpoint.json":
			var cp RuntimeCheckpoint
			if DecodeJSON(before, &cp) != nil || cp.Schema != 1 || cp.Base == nil || cp.Effective == nil {
				return j, E("runtime.paths_invalid", "Runtime checkpoint cannot be safely relocated.")
			}
			changed = a.normalizeOwnedConfigPaths(cp.Base, assets, tailscaleTag)
			changed = a.normalizeOwnedConfigPaths(cp.Effective, assets, tailscaleTag) || changed
			for _, endpoint := range cp.RuntimeOwned.Endpoints {
				changed = a.normalizeOwnedTailscale(endpoint, tailscaleTag) || changed
			}
			if changed {
				cp.Fingerprint = digest(rtJSON(cp.Effective))
				after = rtJSON(cp)
			}
		case ".config/magicnet/runtime-settings.json":
			changed = a.normalizeOwnedTailscale(settings.Tailscale.Endpoint, tailscaleTag)
			if changed {
				after = runtimeSettingsBytes(settings)
			}
		default:
			var config M
			if DecodeJSON(before, &config) != nil || config == nil {
				return j, E("runtime.paths_invalid", "An owned configuration cannot be safely relocated.")
			}
			changed = a.normalizeOwnedConfigPaths(config, assets, tailscaleTag)
			if changed {
				after = rtJSON(config)
			}
		}
		if changed && !bytes.Equal(before, after) {
			j.Files = append(j.Files, runtimePathFile{path, before, after})
		}
	}
	return j, nil
}

func (a *App) checkRuntimePathCandidates(ctx context.Context, j runtimePathRelocation) error {
	for _, f := range j.Files {
		if stringIn(f.Path, ".config/sing-box/config.json", ".state/lifecycle/last-known-good.json", ".state/private/last-known-good.json") {
			if e := a.CheckConfig(ctx, f.After); e != nil {
				return E("runtime.paths_invalid", "The pinned core rejected a relocated owned configuration; original bytes were retained.")
			}
		}
	}
	return nil
}

// Caller holds the lifecycle lock. The install entry, runtime transactions and
// service startup share this path; observation-only commands never migrate.
func (a *App) ensureOwnedRuntimePaths(ctx context.Context) error {
	if e := a.recoverOwnedRuntimePaths(ctx); e != nil {
		return e
	}
	j, e := a.planOwnedRuntimePaths()
	if e != nil || len(j.Files) == 0 {
		return e
	}
	if running, e := a.IsRunning(ctx); e != nil {
		return E("runtime.paths_pending", "Core ownership is unknown before owned path relocation.")
	} else if running {
		// Do not turn a harmless same-root normalization into a blocker for
		// service stop. The next stopped activation performs it under lock.
		return nil
	}
	for _, path := range []string{".state/private/runtime-transaction.json", ".state/private/runtime-initialization.json", ".state/private/subscription/journal.json", ".state/lifecycle/journal.json", ".state/backup/restore-journal.json"} {
		if _, e := os.Lstat(a.Path(path)); e == nil || !errors.Is(e, os.ErrNotExist) {
			return E("runtime.paths_pending", "An earlier transaction must recover before owned path relocation.")
		}
	}
	if _, e := a.PolicyAssets(); e != nil {
		return e
	}
	if e := a.checkRuntimePathCandidates(ctx, j); e != nil {
		return e
	}
	if jsonSize(j) > 64<<20 {
		return E("runtime.paths_limit", "Owned path recovery evidence exceeds its limit.")
	}
	if e = WriteJSON(a.Path(runtimePathJournal), j); e != nil {
		return e
	}
	if e = a.recoverOwnedRuntimePaths(ctx); e != nil {
		// A failed publication records a rollback decision before attempting
		// restoration. Abrupt exit retains prepared evidence for safe retry.
		j.Phase = "rollback"
		if re := WriteJSON(a.Path(runtimePathJournal), j); re != nil {
			return E("runtime.paths_pending", "Owned path rollback could not be recorded.")
		}
		if re := a.recoverOwnedRuntimePaths(ctx); re != nil {
			return re
		}
		return e
	}
	return nil
}

func (a *App) recoverOwnedRuntimePaths(ctx context.Context) error {
	var j runtimePathRelocation
	e := ReadJSON(a.Path(runtimePathJournal), 64<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || j.Schema != 1 || !stringIn(j.Phase, "prepared", "committed", "rollback") || len(j.Files) == 0 || len(j.Files) > len(runtimePathFiles) {
		return E("runtime.paths_pending", "Owned path recovery evidence is unreadable.")
	}
	seen := map[string]bool{}
	for _, f := range j.Files {
		if !stringIn(f.Path, runtimePathFiles...) || seen[f.Path] || len(f.Before) == 0 || len(f.After) == 0 || len(f.Before) > 16<<20 || len(f.After) > 16<<20 {
			return E("runtime.paths_pending", "Owned path recovery entries are invalid.")
		}
		seen[f.Path] = true
		current, e := ReadRegular(a.Path(f.Path), 16<<20)
		if e != nil || !bytes.Equal(current, f.Before) && !bytes.Equal(current, f.After) {
			return E("runtime.paths_conflict", "An owned relocation file changed externally; recovery evidence was retained.")
		}
	}
	if running, e := a.IsRunning(ctx); e != nil || running {
		return E("runtime.paths_pending", "Core ownership must be stopped before path recovery.")
	}
	if j.Phase != "rollback" {
		if e := a.checkRuntimePathCandidates(ctx, j); e != nil {
			return e
		}
	}
	for _, f := range j.Files {
		data := f.After
		if j.Phase == "rollback" {
			data = f.Before
		}
		if e := AtomicWrite(a.Path(f.Path), data, 0600); e != nil {
			return E("runtime.paths_pending", "Owned path publication has pending writes.")
		}
	}
	if j.Phase != "rollback" {
		j.Phase = "committed"
		if e := WriteJSON(a.Path(runtimePathJournal), j); e != nil {
			return E("runtime.paths_pending", "Owned path commit requires recovery.")
		}
	}
	return removeRuntimeFile(a.Path(runtimePathJournal))
}
