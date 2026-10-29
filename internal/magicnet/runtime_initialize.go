package magicnet

import (
	"context"
	"errors"
	"os"
	"strings"
)

// Initial configuration generation also serves package migration. Only user
// endpoints and selector choices are extracted from the private old config;
// the fixed policy recipe is always regenerated from the installed assets.
func (a *App) initialConfigCandidate(ctx context.Context) ([]byte, []RuntimeFileChange, error) {
	return a.initialConfigCandidateWithPatch(ctx, nil)
}

func (a *App) initialConfigCandidateWithPatch(ctx context.Context, replacement *M) ([]byte, []RuntimeFileChange, error) {
	for _, path := range []string{a.subscriptionPrivate("journal.json"), a.Path(".state", "private", "runtime-transaction.json"), a.Path(".state", "lifecycle", "journal.json")} {
		if _, e := os.Lstat(path); e == nil {
			return nil, nil, E("config.recovery_pending", "An earlier configuration transaction must recover before initialization")
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, nil, e
		}
	}
	base, e := a.DefaultPolicy()
	if e != nil {
		return nil, nil, e
	}
	snapshot, e := a.subscriptionSnapshot()
	if e != nil {
		return nil, nil, e
	}
	settings, e := a.runtimeSettings()
	if e != nil {
		return nil, nil, e
	}
	beforeSettings := runtimeSettingsBytes(settings)
	selections := map[string]string{}
	if e = ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &selections); e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, nil, E("config.migration_invalid", "Selector intent cannot be read")
	}
	changes := []RuntimeFileChange{}
	nodes := append([]SubscriptionNode{}, snapshot.Nodes...)
	known := map[string]M{}
	for _, n := range nodes {
		known[n.Tag] = n.Config
	}
	generated := map[string]bool{}
	var oldCheckpoint RuntimeCheckpoint
	if ce := ReadJSON(a.Path(".state", "private", "runtime-checkpoint.json"), 16<<20, &oldCheckpoint); ce != nil && !errors.Is(ce, os.ErrNotExist) {
		return nil, nil, E("config.migration_invalid", "Existing runtime ownership cannot be read")
	}
	for _, list := range [][]M{oldCheckpoint.RuntimeOwned.Outbounds, oldCheckpoint.RoutingOwned.Outbounds, oldCheckpoint.RuntimeOwned.Endpoints, oldCheckpoint.RoutingOwned.Endpoints} {
		for _, n := range list {
			generated[rtString(n["tag"])] = true
		}
	}
	raw, e := ReadRegular(a.Path(".migration-backup", ".config", "sing-box", "config.json"), 4<<20)
	hasBackup := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, nil, E("config.migration_invalid", "Private migration configuration cannot be read")
	}
	if hasBackup {
		var old M
		if DecodeJSON(raw, &old) != nil || old == nil {
			return nil, nil, E("config.migration_invalid", "Private migration configuration is invalid; its bytes were retained")
		}
		for _, v := range rtArray(old["outbounds"]) {
			n := rtMap(v)
			tag := rtString(n["tag"])
			typ := rtString(n["type"])
			if !validNodeTag(tag) {
				return nil, nil, E("config.migration_invalid", "A retained outbound has an invalid tag")
			}
			system := tag == "direct" || tag == "block"
			for _, def := range SystemSelectorDefaults {
				if tag == def.Tag {
					system = true
					if selections[tag] == "" && rtString(n["default"]) != "" {
						selections[tag] = rtString(n["default"])
					}
					break
				}
			}
			if system || generated[tag] {
				continue
			}
			if current, ok := known[tag]; ok {
				if !rtEqual(current, n) {
					return nil, nil, E("config.migration_conflict", "Committed node ownership differs from the private migration configuration")
				}
				continue
			}
			if ValidateProxyNode(n) == nil {
				cloned := rtClone(n).(map[string]any)
				nodes = append(nodes, SubscriptionNode{Identity: semanticDigest(cloned), Tag: tag, DisplayName: tag, Config: cloned})
				known[tag] = cloned
			} else {
				// Other core-valid endpoint/group definitions remain private user data.
				// Actual check below decides whether the fixed core can preserve them.
				if typ == "selector" || typ == "urltest" {
					if selections[tag] == "" {
						selections[tag] = rtString(n["default"])
					}
				}
				base["outbounds"] = append(rtArray(base["outbounds"]), rtClone(n))
			}
		}
		keys := map[string]string{}
		if ke := ReadJSON(a.Path(".config", "magicnet", "tailscale-auth.json"), 64<<10, &keys); ke != nil && !errors.Is(ke, os.ErrNotExist) {
			return nil, nil, E("tailscale.key_unavailable", "Private Tailscale credentials cannot be read")
		}
		keysChanged := false
		for _, v := range rtArray(old["endpoints"]) {
			ep := rtMap(v)
			tag := rtString(ep["tag"])
			if generated[tag] {
				continue
			}
			if rtString(ep["type"]) == "tailscale" {
				if settings.Tailscale.Endpoint != nil {
					continue
				}
				if rtBool(ep["system_interface"]) {
					return nil, nil, E("tailscale.system_interface_forbidden", "A migrated Tailscale endpoint must use userspace networking")
				}
				ep = rtClone(ep).(map[string]any)
				if key := rtString(ep["auth_key"]); key != "" {
					keys[tag] = key
					keysChanged = true
				}
				delete(ep, "auth_key")
				ep["system_interface"] = false
				if rtString(ep["state_directory"]) == "" {
					ep["state_directory"] = ownedTailscaleRelative
				}
				owned := false
				if a.isManagedPath(rtString(ep["state_directory"]), ownedTailscaleRelative) {
					if marker, me := ReadRegular(a.Path(".state", "private", "tailscale", ".magicnet-owned"), 128); me == nil && strings.TrimSpace(string(marker)) == "MagicNet" {
						owned = true
						ep["state_directory"] = ownedTailscaleRelative
					}
				}
				settings.Tailscale = RuntimeTunnel{Enabled: true, Revision: settings.Tailscale.Revision + 1, Endpoint: ep, OwnedDirectory: owned}
			} else {
				if settings.Warp.Endpoint != nil && tag == "warp" {
					continue
				}
				base["endpoints"] = append(rtArray(base["endpoints"]), rtClone(ep))
			}
		}
		if keysChanged {
			changes = append(changes, RuntimeFileChange{Path: ".config/magicnet/tailscale-auth.json", Data: rtJSON(keys)})
		}
	}
	if len(nodes) == 0 && snapshot.Mode == "local_file" && len(snapshot.LocalDocument) > 0 {
		parsed, pe := ParseSubscription(snapshot.LocalDocument)
		if pe != nil {
			return nil, nil, pe
		}
		nodes, _, e = MergeSubscriptionNodes([]SubscriptionSourceInput{{ID: "local", Parsed: parsed}}, nil, nil)
		if e != nil {
			return nil, nil, e
		}
	}
	if len(nodes) > 0 {
		if _, e = UpdatePolicySelectors(base, nodes, nil, selections); e != nil {
			return nil, nil, e
		}
	} else {
		applyAvailableSelectorChoices(base, selections)
	}
	patch := M{}
	if replacement != nil {
		patch = *replacement
	} else {
		override, oe := a.readOverride(true)
		if oe != nil {
			return nil, nil, oe
		}
		patch = override.Patch
	}
	candidate, e := a.materializeFromBase(ctx, base, settings, patch)
	if e != nil {
		return nil, nil, e
	}
	if e = a.CheckConfig(ctx, candidate); e != nil {
		return nil, nil, E("config.migration_invalid", "The pinned core rejected the regenerated configuration; private migration data was retained")
	}
	if string(beforeSettings) != string(runtimeSettingsBytes(settings)) {
		changes = append(changes, RuntimeFileChange{Path: ".config/magicnet/runtime-settings.json", Data: runtimeSettingsBytes(settings)})
	}
	changes = append(changes, RuntimeFileChange{Path: ".config/magicnet/selector-selections.json", Data: rtJSON(selections)})
	if hasBackup {
		changes = append(changes, RuntimeFileChange{Path: ".config/magicnet/migration-report.json", Data: rtJSON(M{"schema": 1, "policy_regenerated": true, "backup_retained": true, "retained_nodes": len(nodes), "unmanaged_policy_requires_review": true})})
	}
	return candidate, changes, nil
}

func applyAvailableSelectorChoices(base M, selections map[string]string) {
	for _, v := range rtArray(base["outbounds"]) {
		m := rtMap(v)
		if rtString(m["type"]) != "selector" {
			continue
		}
		members, _ := rtStringList(m["outbounds"])
		if choice := selections[rtString(m["tag"])]; stringIn(choice, members...) {
			m["default"] = choice
		}
	}
}

type RuntimeInitialization struct {
	Schema    int                   `json:"schema"`
	Candidate []byte                `json:"candidate"`
	Files     []RuntimeFileChange   `json:"files"`
	Before    []RuntimeFileSnapshot `json:"before"`
}

func (a *App) beginRuntimeInitialization(ctx context.Context, data []byte, changes []RuntimeFileChange) error {
	cp, ok := a.RuntimeCheckpoint.(*RuntimeCheckpoint)
	if !ok || cp == nil || cp.Fingerprint != digest(data) {
		return E("config.recovery_pending", "Initialization ownership checkpoint is unavailable")
	}
	changes = append(changes, RuntimeFileChange{Path: ".state/private/runtime-checkpoint.json", Data: rtJSON(cp)})
	if a.PlatformOwned != nil {
		changes = append(changes, RuntimeFileChange{Path: ".state/platform-owned.json", Data: rtJSON(a.PlatformOwned)})
	}
	changes = append(changes, RuntimeFileChange{Path: ".state/lifecycle/last-known-good.json", Data: data}, RuntimeFileChange{Path: ".config/sing-box/config.json", Data: data})
	before, e := a.snapshotFiles(changes)
	if e != nil {
		return e
	}
	journal := RuntimeInitialization{1, data, changes, before}
	if jsonSize(journal) > 32<<20 {
		return E("config.limit", "Initialization evidence exceeds its recovery limit")
	}
	if e = WriteJSON(a.Path(".state", "private", "runtime-initialization.json"), journal); e != nil {
		return e
	}
	a.ClearMaterialization()
	return a.recoverRuntimeInitialization(ctx)
}

func (a *App) recoverRuntimeInitialization(ctx context.Context) error {
	path := a.Path(".state", "private", "runtime-initialization.json")
	var journal RuntimeInitialization
	e := ReadJSON(path, 32<<20, &journal)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || journal.Schema != 1 || len(journal.Candidate) == 0 {
		return E("config.recovery_pending", "Initialization recovery evidence is invalid")
	}
	if e = a.CheckConfig(ctx, journal.Candidate); e != nil {
		return E("config.recovery_pending", "Initialization candidate failed the pinned core check")
	}
	previous := map[string]RuntimeFileSnapshot{}
	for _, s := range journal.Before {
		previous[s.Path] = s
	}
	for _, change := range journal.Files {
		if !safeRuntimeTransactionPath(change.Path) || change.Remove {
			return E("config.recovery_pending", "Initialization recovery paths are invalid")
		}
		old, ok := previous[change.Path]
		if !ok {
			return E("config.recovery_pending", "Initialization baseline is incomplete")
		}
		now, re := ReadRegular(a.Path(change.Path), 16<<20)
		oldMatch := (old.Exists && re == nil && digest(now) == digest(old.Data)) || (!old.Exists && errors.Is(re, os.ErrNotExist))
		newMatch := re == nil && digest(now) == digest(change.Data)
		if !oldMatch && !newMatch {
			return E("config.rollback_conflict", "Initialization found an externally changed owned file")
		}
	}
	for _, change := range journal.Files {
		if e = AtomicWrite(a.Path(change.Path), change.Data, 0600); e != nil {
			return E("config.recovery_pending", "Initialization has pending private configuration writes")
		}
	}
	return removeRuntimeFile(path)
}
