package magicnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type OverrideDocument struct {
	Schema   int   `json:"schema"`
	Revision int64 `json:"revision"`
	Patch    M     `json:"patch"`
}

func (a *App) readOverride(active bool) (OverrideDocument, error) {
	doc := OverrideDocument{1, 0, M{}}
	name := "config-override.json"
	if active {
		name = "config-override-active.json"
	}
	b, e := ReadRegular(a.Path(".config", "magicnet", name), 4<<20)
	if errors.Is(e, os.ErrNotExist) {
		return doc, nil
	}
	if e != nil {
		return doc, E("override.observation_failed", "Override intent cannot be read")
	}
	v, e := rtDecodeJSON(b)
	if e != nil || rtMap(v) == nil {
		return doc, E("override.invalid", "Invalid persisted override")
	}
	m := rtMap(v)
	if _, hasPatch := m["patch"]; hasPatch && m["schema"] != nil {
		if e = DecodeJSON(b, &doc); e != nil || doc.Schema != 1 || doc.Revision < 0 || doc.Patch == nil {
			return doc, E("override.invalid", "Invalid persisted override revision")
		}
	} else {
		doc.Patch = m
	}
	return doc, nil
}

func (a *App) OverrideStatus(private bool) (M, error) {
	saved, e := a.readOverride(false)
	if e != nil {
		return nil, e
	}
	active, e := a.readOverride(true)
	if e != nil {
		return nil, e
	}
	m := M{"revision": saved.Revision, "active_revision": active.Revision, "pending": !rtEqual(saved.Patch, active.Patch), "configured": len(saved.Patch) > 0, "state": "ready"}
	if m["pending"] == true {
		m["state"] = "pending"
	}
	if _, e = os.Stat(a.Path(".state", "private", "runtime-transaction.json")); e == nil {
		m["state"] = "recovery_pending"
	}
	if private {
		m["patch"] = saved.Patch
		targets := []any{}
		b, e := ReadRegular(a.ConfigPath(), 4<<20)
		if e == nil {
			var c M
			if DecodeJSON(b, &c) == nil {
				for _, key := range []string{"outbounds", "endpoints"} {
					for _, v := range rtArray(c[key]) {
						n := rtMap(v)
						targets = append(targets, M{"tag": n["tag"], "type": n["type"]})
					}
				}
			}
		}
		m["routing_targets"] = targets
	}
	return m, nil
}

func (a *App) privatePayload(path string, limit int64) ([]byte, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, E("payload.invalid", "Invalid private payload path")
	}
	rel, e := filepath.Rel(a.Root, abs)
	if e != nil || strings.HasPrefix(rel, "../") || !(strings.HasPrefix(rel, ".state/private/payload/tmp/") || strings.HasPrefix(rel, ".state/private/payload/subscription/") || strings.HasPrefix(rel, ".state/payloads/") || strings.HasPrefix(rel, ".state/webui-payload/") || strings.HasPrefix(rel, ".state/webui/") || strings.HasPrefix(rel, ".tmp/") || strings.HasPrefix(rel, ".config/magicnet/payloads/")) {
		return nil, E("payload.unsafe", "Payload must be in a controlled private directory")
	}
	return ReadRegular(abs, limit)
}

func (a *App) OverrideOperation(ctx context.Context, action string, payload M) (M, error) {
	defer a.ClearMaterialization()
	if payload == nil {
		payload = M{}
	}
	var result M
	e := a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		if action == "apply" {
			if e := a.RecoverRuntime(ctx); e != nil {
				return e
			}
		} else {
			for _, path := range []string{a.Path(".state", "private", "runtime-initialization.json"), a.Path(".state", "private", "runtime-transaction.json"), a.subscriptionPrivate("journal.json"), a.Path(".state", "lifecycle", "journal.json")} {
				if _, e := os.Lstat(path); e == nil {
					return E("config.recovery_pending", "Configuration recovery must complete before this preview")
				} else if !errors.Is(e, os.ErrNotExist) {
					return e
				}
			}
		}
		saved, e := a.readOverride(false)
		if e != nil {
			return e
		}
		patch := M{}
		if action != "reset" && action != "apply" {
			var ok bool
			patch, ok = payload["patch"].(map[string]any)
			if !ok {
				return E("override.invalid", "A complete patch object is required")
			}
		}
		if !rtAllowedKeys(payload, "patch expected_revision") {
			return E("override.invalid", "Unexpected override payload field")
		}
		if action != "preview" {
			expected, ok := rtInt(payload["expected_revision"])
			if !ok || expected < 0 {
				return E("override.invalid", "expected_revision is required")
			}
			if expected != saved.Revision && !(action != "apply" && rtEqual(saved.Patch, patch)) {
				return E("override.conflict", "Override revision changed; inspect before retrying")
			}
		}
		if action == "apply" {
			patch = saved.Patch
		}
		if action == "apply" {
			if e = a.EnsureDefaultConfig(ctx); e != nil {
				return e
			}
		}
		data, e := ReadRegular(a.ConfigPath(), 4<<20)
		var candidate []byte
		if errors.Is(e, os.ErrNotExist) {
			candidate, _, e = a.initialConfigCandidateWithPatch(ctx, &patch)
		} else if e == nil {
			var settings RuntimeSettings
			settings, e = a.runtimeSettings()
			if e == nil {
				candidate, e = a.materializeWith(ctx, data, settings, patch)
			}
		}
		if e != nil {
			return e
		}
		if e = a.CheckConfig(ctx, candidate); e != nil {
			return E("override.config_invalid", "The pinned core rejected the override candidate")
		}
		routing := rtMap(patch["$magicnet_routing"])
		summary := M{"changed": digest(data) != digest(candidate), "rule_count": len(rtArray(routing["rules"])), "outbound_count": len(rtArray(routing["outbounds"]))}
		if action == "preview" {
			a.RuntimeCheckpoint = nil
			result = M{"valid": true, "revision": saved.Revision, "summary": summary}
			return nil
		}
		if action == "set" || action == "reset" {
			a.RuntimeCheckpoint = nil
			if rtEqual(saved.Patch, patch) {
				result = M{"saved": true, "changed": false, "revision": saved.Revision}
				return nil
			}
			saved.Revision++
			saved.Patch = patch
			saved.Schema = 1
			if e = WriteJSON(a.Path(".config", "magicnet", "config-override.json"), saved); e != nil {
				return e
			}
			result = M{"saved": true, "changed": true, "revision": saved.Revision, "pending": true}
			return nil
		}
		if action != "apply" {
			return E("command.arguments", "Invalid override operation")
		}
		generation := token()
		changes := []RuntimeFileChange{{Path: ".config/magicnet/config-override-active.json", Data: rtJSON(saved)}}
		if e = a.performRuntimeChange(ctx, candidate, changes, generation); e != nil {
			return e
		}
		result = M{"applied": true, "revision": saved.Revision, "pending": false, "generation_id": generation}
		return nil
	})
	if e != nil {
		if ErrorCode(e) == "operation.busy" {
			return nil, E("override.busy", "Another lifecycle operation is still running")
		}
		return nil, e
	}
	if action != "preview" {
		if e = a.Publish(ctx); e != nil {
			return nil, e
		}
	}
	return result, nil
}
