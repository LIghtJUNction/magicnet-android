package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"
)

type networkAccessRecord struct {
	UID      int      `json:"uid"`
	User     int      `json:"user"`
	Policy   int      `json:"policy"`
	Packages []string `json:"packages"`
	Progress string   `json:"progress,omitempty"`
}

type networkAccessJournal struct {
	Schema    int                   `json:"schema"`
	Phase     string                `json:"phase"`
	Records   []networkAccessRecord `json:"records"`
	Candidate string                `json:"candidate"`
	Created   int64                 `json:"created"`
}

func validNetworkIdentity(r *networkAccessRecord) bool {
	if r.UID < 0 || r.User < 0 || r.UID/100000 != r.User || r.Policy < 0 || r.Policy > 2147483647 || len(r.Packages) == 0 || len(r.Packages) > 256 {
		return false
	}
	sort.Strings(r.Packages)
	for n, p := range r.Packages {
		if len(p) == 0 || len(p) > 255 || n > 0 && r.Packages[n-1] == p {
			return false
		}
	}
	return true
}

func networkRecords(m M) ([]networkAccessRecord, error) {
	b, e := json.Marshal(m["records"])
	var records []networkAccessRecord
	if e != nil || DecodeJSON(b, &records) != nil || len(records) > 128 {
		return nil, E("network-access.limit", "Invalid or excessive policy identities.")
	}
	seen := map[int]bool{}
	for n := range records {
		if !validNetworkIdentity(&records[n]) || seen[records[n].UID] || records[n].Policy&1 == 0 {
			return nil, E("network-access.provider_invalid", "The provider returned an invalid restricted identity.")
		}
		seen[records[n].UID] = true
		records[n].Progress = "prepared"
	}
	return records, nil
}

func (a *App) readNetworkJournal() (networkAccessJournal, bool, error) {
	var j networkAccessJournal
	e := ReadJSON(a.Path(".state", "network-access", "journal.json"), 512<<10, &j)
	if errors.Is(e, os.ErrNotExist) {
		return j, false, nil
	}
	if e != nil || !stringIn(j.Phase, "prepared", "applied", "rollback_prepared", "rolled_back") || len(j.Records) == 0 || len(j.Records) > 128 || !stringIn(fmtInt(j.Schema), "0", "2") {
		return j, true, E("network-access.recovery_pending", "Recovery evidence is unreadable or invalid.")
	}
	seen := map[int]bool{}
	for n := range j.Records {
		r := &j.Records[n]
		if !validNetworkIdentity(r) || seen[r.UID] || r.Policy&1 == 0 {
			return j, true, E("network-access.recovery_pending", "Recovery identities are invalid.")
		}
		seen[r.UID] = true
		if j.Schema == 0 {
			// Legacy prepared journals could have completed any prefix before
			// losing their setter response. Retain every original identity.
			r.Progress = "apply_pending"
			if j.Phase == "rollback_prepared" {
				r.Progress = "rollback_pending"
			} else if j.Phase == "rolled_back" {
				r.Progress = "restored"
			}
		}
		if !stringIn(r.Progress, "prepared", "apply_pending", "applied", "rollback_pending", "restored") {
			return j, true, E("network-access.recovery_pending", "Recovery progress is invalid.")
		}
	}
	j.Schema = 2
	return j, true, nil
}

func (a *App) networkIdentity(ctx context.Context, expected networkAccessRecord) (networkAccessRecord, error) {
	m, e := a.bridge(ctx, "network-get", fmtInt(expected.UID))
	if e != nil {
		return networkAccessRecord{}, e
	}
	b, _ := json.Marshal(m)
	var current networkAccessRecord
	if DecodeJSON(b, &current) != nil || !validNetworkIdentity(&current) || current.UID != expected.UID || current.User != expected.User || !rtEqual(current.Packages, expected.Packages) {
		return current, E("network-access.conflict", "Shared package identity changed.")
	}
	if current.Policy != expected.Policy && current.Policy != expected.Policy&^1 {
		return current, E("network-access.conflict", "A policy was modified outside this operation.")
	}
	return current, nil
}

func (a *App) networkAccess(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "An action is required.")
	}
	act := args[0]
	m, e := a.bridge(ctx, "network-inspect")
	if e != nil {
		if act == "status" {
			return M{"supported": false, "state": "unsupported", "provider": "unknown", "configured_verified": false}, nil
		}
		return nil, E("network-access.unsupported", "No verified Android network-policy provider is available.")
	}
	if act == "status" {
		records, _ := m["records"].([]any)
		j, exists, je := a.readNetworkJournal()
		phase := "none"
		if exists {
			phase = j.Phase
		}
		if je != nil {
			phase = "unknown"
		}
		return M{"supported": true, "provider": "aosp", "restriction_count": len(records), "configured_verified": false, "journal_phase": phase, "recovery_pending": exists && !stringIn(phase, "applied", "rolled_back"), "effective_application_dns": "unknown"}, nil
	}
	raw, _ := json.Marshal(m)
	candidate := digest(raw)
	m["candidate"] = candidate
	if act == "inspect" {
		return m, nil
	}
	if len(args) < 2 || args[1] != candidate {
		return nil, E("network-access.conflict", "Network policy changed; inspect a fresh candidate.")
	}
	if act == "check" {
		return M{"candidate": candidate, "valid": true, "writes": 0}, nil
	}
	if len(args) != 3 || args[2] != "--confirm" || !stringIn(act, "repair", "reapply", "rollback") {
		return nil, E("network-access.confirmation_required", "The reviewed candidate and --confirm are required.")
	}
	var result M
	e = a.WithLifecycleLock(ctx, 2*time.Second, func() error {
		now, e := a.bridge(ctx, "network-inspect")
		if e != nil {
			return e
		}
		b, _ := json.Marshal(now)
		if digest(b) != candidate {
			return E("network-access.conflict", "The reviewed identities or policies changed.")
		}
		restricted, e := networkRecords(now)
		if e != nil {
			return e
		}
		j, exists, e := a.readNetworkJournal()
		if e != nil {
			return e
		}
		if act == "rollback" {
			if !exists {
				return E("network-access.no_journal", "No owned changes are available to roll back.")
			}
		} else if exists && j.Phase != "rolled_back" {
			if j.Phase == "rollback_prepared" {
				return E("network-access.recovery_pending", "Finish the owned rollback before beginning another repair.")
			}
			if j.Phase == "applied" && act == "repair" {
				return E("network-access.reapply_required", "Restrictions need a new explicit reapply operation.")
			}
			owned := map[int]bool{}
			for _, r := range j.Records {
				owned[r.UID] = true
			}
			for _, r := range restricted {
				if !owned[r.UID] {
					return E("network-access.recovery_pending", "Roll back the existing identity set before adding a new one.")
				}
			}
			// Keep the immutable original policies, including identities which
			// no longer appear in the provider's restricted-only inspection.
		} else {
			if len(restricted) == 0 {
				result = M{"configured_verified": true, "phase": "unchanged", "identity_count": 0, "effective_application_dns": "unknown"}
				return nil
			}
			j = networkAccessJournal{Schema: 2, Phase: "prepared", Records: restricted, Candidate: candidate, Created: time.Now().Unix()}
		}
		for _, r := range j.Records {
			current, e := a.networkIdentity(ctx, r)
			if e != nil {
				return e
			}
			if r.Progress == "prepared" && current.Policy != r.Policy {
				return E("network-access.conflict", "An unmodified identity changed outside this operation.")
			}
			if act == "rollback" && j.Phase == "rolled_back" && current.Policy != r.Policy {
				return E("network-access.conflict", "A completed rollback no longer owns later policy changes.")
			}
		}
		if act == "rollback" {
			j.Phase = "rollback_prepared"
		} else {
			j.Phase = "prepared"
		}
		jp := a.Path(".state", "network-access", "journal.json")
		if e = WriteJSON(jp, j); e != nil {
			return e
		}
		for n := range j.Records {
			r := &j.Records[n]
			current, e := a.networkIdentity(ctx, *r)
			if e != nil {
				return e
			}
			if r.Progress == "prepared" && current.Policy != r.Policy {
				return E("network-access.conflict", "An unmodified identity changed before its setter.")
			}
			desired, pending, done := r.Policy&^1, "apply_pending", "applied"
			if act == "rollback" {
				desired, pending, done = r.Policy, "rollback_pending", "restored"
			}
			if current.Policy != desired {
				r.Progress = pending
				if e = WriteJSON(jp, j); e != nil {
					return e
				}
				if _, e = a.bridge(ctx, "network-set", fmtInt(r.UID), fmtInt(desired)); e != nil {
					return E("network-access.write_failed", "Provider write failed; the complete original baseline and pending progress are retained.")
				}
				read, re := a.networkIdentity(ctx, *r)
				if re != nil || read.Policy != desired {
					return E("network-access.readback_failed", "Policy or identity readback did not match; recovery evidence is retained.")
				}
			}
			r.Progress = done
			if e = WriteJSON(jp, j); e != nil {
				return e
			}
		}
		// Recheck the entire original identity set before declaring a terminal
		// phase, including a prefix restored during an earlier interrupted try.
		for _, r := range j.Records {
			read, e := a.networkIdentity(ctx, r)
			desired := r.Policy &^ 1
			if act == "rollback" {
				desired = r.Policy
			}
			if e != nil || read.Policy != desired {
				return E("network-access.readback_failed", "The complete identity set did not verify.")
			}
		}
		j.Phase = "applied"
		if act == "rollback" {
			j.Phase = "rolled_back"
		}
		if e = WriteJSON(jp, j); e != nil {
			return e
		}
		result = M{"configured_verified": true, "phase": j.Phase, "identity_count": len(j.Records), "effective_application_dns": "unknown"}
		return nil
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return result, e
}
