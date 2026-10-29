package magicnet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRealCoreSubscriptionRecoveryAtTransactionBoundaries(t *testing.T) {
	for _, stage := range []string{"prepared", "activated", "source_partial", "committed", "external_conflict"} {
		t.Run(stage, func(t *testing.T) {
			a := realCoreFixture(t)
			ctx := context.Background()
			if _, e := a.ApplyLocalSubscription(ctx, rtJSON(M{"outbounds": []any{testTrojan("old-node", "old.example.invalid")}})); e != nil {
				t.Fatal(e)
			}
			oldConfig, _ := ReadRegular(a.ConfigPath(), 4<<20)
			oldCheckpoint, _ := ReadRegular(a.Path(".state", "private", "runtime-checkpoint.json"), 16<<20)
			previous, e := a.subscriptionSnapshot()
			if e != nil {
				t.Fatal(e)
			}
			prior, e := a.subscriptionLast()
			if e != nil {
				t.Fatal(e)
			}
			local := rtJSON(M{"outbounds": []any{testTrojan("new-node", "new.example.invalid")}})
			parsed, e := ParseSubscription(local)
			if e != nil {
				t.Fatal(e)
			}
			nodes, _, e := MergeSubscriptionNodes([]SubscriptionSourceInput{{"local", parsed}}, nil, previous.Nodes)
			if e != nil {
				t.Fatal(e)
			}
			var base M
			_ = DecodeJSON(oldConfig, &base)
			base, e = a.runtimeBase(base)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = UpdatePolicySelectors(base, nodes, previous.Nodes, map[string]string{}); e != nil {
				t.Fatal(e)
			}
			settings, e := a.runtimeSettings()
			if e != nil {
				t.Fatal(e)
			}
			candidate, e := a.materializeFromBase(ctx, base, settings, M{})
			if e != nil {
				t.Fatal(e)
			}
			checkRealCore(t, a, candidate)
			generation := token()
			next := SubscriptionSnapshot{Schema: 1, GenerationID: generation, Mode: "local_file", URLs: []string{}, Nodes: nodes, Sources: []SubscriptionSourceCache{}, ConfigSHA256: digest(candidate), LocalDocument: local}
			if e = a.stageSubscriptionSnapshot(next, nil); e != nil {
				t.Fatal(e)
			}
			changes := []RuntimeFileChange{{Path: ".config/magicnet/subscription-current.json", Data: rtJSON(SubscriptionPointer{1, generation})}, {Path: ".config/sing-box/subscription.local", Data: local}}
			files, e := a.snapshotFiles(changes)
			if e != nil {
				t.Fatal(e)
			}
			batch := &SubscriptionBatch{Schema: 1, GenerationID: generation, RequestedCount: 1, UniqueCount: 1, Outcome: "running", ErrorCode: "none", WarningCode: "none", Sources: []SubscriptionBatchSource{{Index: 1, Stage: "activate", FetchResult: "not_attempted", ConvertResult: "not_needed", ParsedCount: intPointer(1), ImportedCount: intPointer(1), FilteredCount: intPointer(0), DuplicateCount: intPointer(0), ErrorCode: "none"}}}
			last := prior
			last.GenerationID = generation
			last.OperationID = token()
			last.Result = "running"
			last.Phase = "activate"
			last.Batch = batch
			journal := SubscriptionJournal{Runtime: RuntimeTransaction{Schema: 1, Generation: generation, Phase: "prepared", OldConfig: oldConfig, CandidateHash: digest(candidate), Files: files, Created: time.Now().Unix()}, OldGeneration: previous.GenerationID, NewGeneration: generation, Last: last}
			path := a.subscriptionPrivate("journal.json")
			if e = WriteJSON(path, journal); e != nil {
				t.Fatal(e)
			}
			if stage != "prepared" {
				journal.Runtime.Phase = "activate"
				if e = WriteJSON(path, journal); e != nil {
					t.Fatal(e)
				}
				if e = a.ActivateConfig(ctx, candidate, generation, false); e != nil {
					t.Fatal(e)
				}
			}
			if stage == "source_partial" || stage == "committed" {
				journal.Runtime.Phase = "commit"
				if e = WriteJSON(path, journal); e != nil {
					t.Fatal(e)
				}
				if e = AtomicWrite(a.Path(changes[0].Path), changes[0].Data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if stage == "committed" {
				if e = AtomicWrite(a.Path(changes[1].Path), changes[1].Data, 0600); e != nil {
					t.Fatal(e)
				}
				journal.Runtime.Phase = "committed"
				if e = WriteJSON(path, journal); e != nil {
					t.Fatal(e)
				}
			}
			a.ClearMaterialization()
			if stage == "external_conflict" {
				var external M
				_ = DecodeJSON(candidate, &external)
				external["log"] = M{"level": "info"}
				if e = AtomicWrite(a.ConfigPath(), rtJSON(external), 0600); e != nil {
					t.Fatal(e)
				}
				if e = a.RecoverRuntime(ctx); ErrorCode(e) != "subscription.rollback_failed" {
					t.Fatal("external conflict not retained", e)
				}
				if _, e = os.Lstat(path); e != nil {
					t.Fatal("recovery deleted conflict evidence", e)
				}
				if e = AtomicWrite(a.ConfigPath(), candidate, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = a.RecoverRuntime(ctx); e != nil {
				t.Fatal(e)
			}
			if e = a.RecoverRuntime(ctx); e != nil {
				t.Fatal("recovery repeat was not idempotent", e)
			}
			current, e := a.subscriptionSnapshot()
			if e != nil {
				t.Fatal(e)
			}
			active, _ := ReadRegular(a.ConfigPath(), 4<<20)
			history, e := a.subscriptionLast()
			if e != nil {
				t.Fatal(e)
			}
			if stage == "committed" {
				if current.GenerationID != generation || !bytes.Equal(active, candidate) || history.Batch.Outcome != "committed" || history.Result != "success" {
					t.Fatal("committed generation did not recover forward")
				}
			} else {
				checkpoint, _ := ReadRegular(a.Path(".state", "private", "runtime-checkpoint.json"), 16<<20)
				if current.GenerationID != previous.GenerationID || !bytes.Equal(active, oldConfig) || !bytes.Equal(checkpoint, oldCheckpoint) || history.SuccessEpoch != prior.SuccessEpoch || history.Batch.Outcome != "rolled_back" {
					t.Fatal("rollback did not restore complete prior generation", history.Batch.Outcome)
				}
			}
			if _, e = os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("completed recovery retained journal", e)
			}
			checkRealCore(t, a, active)
		})
	}
}

func TestRealCoreRejectsInvalidIndependentRecoveryBaseline(t *testing.T) {
	a := realCoreFixture(t)
	ctx := context.Background()
	if _, e := a.ApplyLocalSubscription(ctx, rtJSON(M{"outbounds": []any{testTrojan("baseline", "baseline.example.invalid")}})); e != nil {
		t.Fatal(e)
	}
	oldPointer, _ := ReadRegular(a.subscriptionPointerPath(), 1024)
	// An empty object can be a valid standalone core configuration; invalid JSON
	// gives an unambiguous invalid baseline rather than relying on a policy guess.
	for _, path := range []string{a.ConfigPath(), a.Path(".state", "lifecycle", "last-known-good.json"), a.Path(".state", "private", "last-known-good.json")} {
		if e := AtomicWrite(path, []byte("{"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := a.RefreshSubscriptions(ctx); ErrorCode(e) != "config.recovery_unavailable" {
		t.Fatal("invalid independent baseline was accepted", e)
	}
	pointer, _ := ReadRegular(a.subscriptionPointerPath(), 1024)
	if !bytes.Equal(pointer, oldPointer) {
		t.Fatal("baseline failure changed sources")
	}
}
