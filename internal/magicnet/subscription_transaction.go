package magicnet

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type SubscriptionJournal struct {
	Runtime       RuntimeTransaction `json:"runtime"`
	OldGeneration string             `json:"old_generation"`
	NewGeneration string             `json:"new_generation"`
	Last          SubscriptionLast   `json:"last"`
}

func (a *App) ApplySubscriptionURLs(ctx context.Context, data []byte) (M, error) {
	urls, requested, e := NormalizeSubscriptionList(data)
	if e != nil {
		return nil, e
	}
	return a.applySubscriptions(ctx, "remote_url", urls, nil, requested, false, &SubscriptionFetcher{})
}
func (a *App) ApplyLocalSubscription(ctx context.Context, data []byte) (M, error) {
	normalized, e := ValidateSubscriptionDocument(data)
	if e != nil {
		return nil, e
	}
	return a.applySubscriptions(ctx, "local_file", nil, normalized, 1, false, &SubscriptionFetcher{})
}
func (a *App) RefreshSubscriptions(ctx context.Context) (M, error) {
	s, e := a.subscriptionSnapshot()
	if e != nil {
		return nil, e
	}
	if s.Mode == "local_file" {
		return a.applySubscriptions(ctx, s.Mode, nil, s.LocalDocument, 1, false, &SubscriptionFetcher{})
	}
	if len(s.URLs) == 0 {
		return nil, E("subscription.not_configured", "No subscription sources are configured")
	}
	return a.applySubscriptions(ctx, s.Mode, s.URLs, nil, len(s.URLs), false, &SubscriptionFetcher{})
}

func (a *App) applySubscriptions(ctx context.Context, mode string, urls []string, local []byte, requested int, requireFresh bool, fetcher *SubscriptionFetcher) (M, error) {
	var receipt M
	// Five serial 45-second sources plus validation, activation and recovery fit
	// inside this explicit eight-minute device-side batch budget. UI timeouts do
	// not cancel detached device workers or release their owner.
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	e := a.withLock(ctx, "subscription", 2*time.Second, func() error {
		return a.WithLifecycleLock(ctx, 2*time.Second, func() error {
			_, owner, oe := a.subscriptionOwner()
			if oe != nil || owner == "unknown" || owner == "pending" {
				return E("subscription.owner_unknown", "Updater ownership cannot be established")
			}
			if owner == "active" {
				return E("subscription.busy", "A subscription update is still running")
			}
			if e := a.recoverSubscription(ctx); e != nil {
				return e
			}
			if e := a.recoverRuntimeOnly(ctx); e != nil {
				return e
			}
			if _, se := os.Lstat(a.ConfigPath()); errors.Is(se, os.ErrNotExist) {
				if e := a.EnsureDefaultConfig(ctx); e != nil {
					return e
				}
			}
			old, e := a.validatedBaseline(ctx)
			if e != nil {
				return e
			}
			previous, e := a.subscriptionSnapshot()
			if e != nil {
				return e
			}
			ua, filters, e := a.subscriptionPreferences()
			if e != nil {
				return e
			}
			prior, e := a.subscriptionLast()
			if e != nil {
				return e
			}
			generation := token()
			task, e := newSubscriptionOwner(generation)
			if e != nil {
				return e
			}
			if e = WriteJSON(a.subscriptionPrivate("owner.json"), task); e != nil {
				return e
			}
			defer a.releaseSubscriptionOwner(task.Task)
			unique := len(urls)
			if mode == "local_file" {
				unique = 1
			}
			batch := &SubscriptionBatch{Schema: 1, GenerationID: generation, RequestedCount: requested, UniqueCount: unique, Outcome: "running", Sources: make([]SubscriptionBatchSource, unique), ErrorCode: "none", WarningCode: "none"}
			for i := range batch.Sources {
				batch.Sources[i] = SubscriptionBatchSource{Index: i + 1, Stage: "validate", FetchResult: "not_attempted", ConvertResult: "not_attempted", ErrorCode: "none"}
			}
			last := SubscriptionLast{Phase: "prepare", Result: "running", GenerationID: generation, OperationID: task.Task, AttemptEpoch: time.Now().Unix(), SuccessEpoch: prior.SuccessEpoch, ConfiguredCount: unique, SourceCount: unique, SourceMode: "url", NativeParser: "unknown", ConverterEnabled: "0", ConverterAvailable: "native", ConverterAttempted: "0", ConverterFormat: "unknown", ConverterResult: "not_attempted", Batch: batch}
			if mode == "local_file" {
				last.SourceMode = "local"
			}
			receipt = M{"accepted": true, "operation_id": task.Task, "generation_id": generation, "outcome": "running"}
			if e = a.publishSubscriptionLast(ctx, last); e != nil {
				return e
			}
			fail := func(err error, stage string, index int) error {
				code := subscriptionFailureCode(err)
				if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
					code = "interrupted"
				}
				last.Phase = stage
				last.Result = "failed"
				last.HasReason = true
				batch.Outcome = "rolled_back"
				batch.ErrorCode = code
				if code == "interrupted" {
					last.Result = "interrupted"
					batch.Outcome = "interrupted"
				}
				if index >= 0 {
					batch.Sources[index].ErrorCode = code
				}
				receipt["outcome"] = batch.Outcome
				receipt["error_code"] = code
				pctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if pe := a.publishSubscriptionLast(pctx, last); pe != nil {
					return E("subscription.rollback_failed", "Failure state could not be published")
				}
				return err
			}
			inputs := make([]SubscriptionSourceInput, 0, unique)
			caches := make([]SubscriptionSourceCache, 0, len(urls))
			bodies := make(map[string][]byte)
			formats := map[string]bool{}
			for i := 0; i < unique; i++ {
				if e := ctx.Err(); e != nil {
					return fail(E("subscription.interrupted", "Subscription update was cancelled"), "fetch", i)
				}
				source := &batch.Sources[i]
				source.Stage = "fetch"
				last.Phase = "fetch"
				if e = a.publishSubscriptionLast(ctx, last); e != nil {
					return fail(e, "fetch", i)
				}
				id := "local"
				data := local
				if mode == "remote_url" {
					id = SubscriptionSourceID(urls[i])
					f, fetchErr := fetcher.Fetch(ctx, urls[i], ua)
					state := "fresh"
					if fetchErr != nil {
						if ctx.Err() != nil {
							source.FetchResult = "failed"
							return fail(fetchErr, "fetch", i)
						}
						if requireFresh {
							source.FetchResult = "failed"
							return fail(fetchErr, "fetch", i)
						}
						cached, found := findSubscriptionCache(previous, urls[i])
						if !found {
							source.FetchResult = "failed"
							return fail(fetchErr, "fetch", i)
						}
						body, ce := ReadRegular(a.subscriptionPrivate("generations", previous.GenerationID, "source-"+id+".bin"), SubscriptionDocumentLimit)
						if ce != nil || digest(body) != cached.BodySHA256 {
							source.FetchResult = "failed"
							return fail(E("subscription.cache_untrusted", "Same-source cache could not be verified"), "fetch", i)
						}
						f = FetchedSubscription{body, cached.Usage}
						state = "cached"
					}
					data = f.Body
					source.FetchResult = state
					bodies[id] = data
					caches = append(caches, SubscriptionSourceCache{ID: id, URL: urls[i], BodySHA256: digest(data), State: state, Usage: f.Usage})
				} else {
					source.FetchResult = "not_applicable"
				}
				source.Stage = "parse"
				last.Phase = "convert"
				if e = a.publishSubscriptionLast(ctx, last); e != nil {
					return fail(e, "convert", i)
				}
				parsed, parseErr := ParseSubscription(data)
				if parseErr != nil {
					source.ConvertResult = "failed"
					return fail(parseErr, "convert", i)
				}
				source.ConvertResult = "not_needed"
				source.ParsedCount = intPointer(parsed.ParsedCount)
				source.Stage = "merge"
				formats[parsed.Format] = true
				last.NativeNodeCount += parsed.ParsedCount
				inputs = append(inputs, SubscriptionSourceInput{id, parsed})
			}
			last.NativeParser = "mixed"
			last.ConverterFormat = "mixed"
			if len(formats) == 1 {
				for format := range formats {
					last.NativeParser = format
					last.ConverterFormat = format
				}
			}
			nodes, counts, e := MergeSubscriptionNodes(inputs, filters, previous.Nodes)
			for i, c := range counts {
				source := &batch.Sources[i]
				source.ImportedCount = intPointer(c.Imported)
				source.FilteredCount = intPointer(c.Filtered)
				source.DuplicateCount = intPointer(c.Duplicate)
				source.Stage = "check"
				last.ImportedCount += c.Imported
				last.SkippedCount += c.Filtered + c.Duplicate
			}
			if e != nil {
				return fail(e, "merge", -1)
			}
			var base M
			if e = DecodeJSON(old, &base); e != nil {
				return fail(E("subscription.config_invalid", "Invalid active recovery configuration"), "validate", -1)
			}
			base, e = a.runtimeBase(base)
			if e != nil {
				return fail(E("subscription.merge_failed", "Existing user intent cannot be reconstructed safely"), "merge", -1)
			}
			selections := map[string]string{}
			e = ReadJSON(a.Path(".config", "magicnet", "selector-selections.json"), 4<<20, &selections)
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return fail(E("subscription.merge_failed", "Saved selections cannot be read"), "merge", -1)
			}
			fallbacks, e := UpdatePolicySelectors(base, nodes, previous.Nodes, selections)
			if e != nil {
				return fail(e, "merge", -1)
			}
			for _, tag := range fallbacks {
				for _, v := range rtArray(base["outbounds"]) {
					m := rtMap(v)
					if rtString(m["tag"]) == tag {
						selections[tag] = rtString(m["default"])
					}
				}
			}
			settings, e := a.runtimeSettings()
			if e != nil {
				return fail(e, "validate", -1)
			}
			override, e := a.readOverride(true)
			if e != nil {
				return fail(e, "validate", -1)
			}
			candidate, e := a.materializeFromBase(ctx, base, settings, override.Patch)
			if e != nil {
				return fail(E("subscription.merge_failed", "Candidate policy materialization failed"), "merge", -1)
			}
			last.Phase = "validate"
			if e = a.publishSubscriptionLast(ctx, last); e != nil {
				return fail(e, "validate", -1)
			}
			if e = a.CheckConfig(ctx, candidate); e != nil {
				return fail(E("subscription.config_invalid", "The pinned core rejected the subscription candidate"), "validate", -1)
			}
			newSnapshot := SubscriptionSnapshot{Schema: 1, GenerationID: generation, Mode: mode, URLs: urls, Nodes: nodes, Sources: caches, ConfigSHA256: digest(candidate), LocalDocument: local}
			if newSnapshot.URLs == nil {
				newSnapshot.URLs = []string{}
			}
			if e = a.stageSubscriptionSnapshot(newSnapshot, bodies); e != nil {
				return fail(e, "validate", -1)
			}
			changes := []RuntimeFileChange{{Path: ".config/magicnet/subscription-current.json", Data: rtJSON(SubscriptionPointer{1, generation})}, {Path: ".config/magicnet/selector-selections.json", Data: rtJSON(selections)}}
			if mode == "local_file" {
				changes = append(changes, RuntimeFileChange{Path: ".config/sing-box/subscription.local", Data: local}, RuntimeFileChange{Path: ".config/sing-box/subscription.url", Remove: true})
			} else {
				changes = append(changes, RuntimeFileChange{Path: ".config/sing-box/subscription.url", Data: []byte(strings.Join(urls, "\n") + "\n")}, RuntimeFileChange{Path: ".config/sing-box/subscription.local", Remove: true})
			}
			files, e := a.snapshotFiles(changes)
			if e != nil {
				return fail(e, "validate", -1)
			}
			running, e := a.IsRunning(ctx)
			if e != nil {
				return fail(E("subscription.activation_failed", "Original core ownership is unknown"), "activate", -1)
			}
			journal := SubscriptionJournal{Runtime: RuntimeTransaction{1, generation, "prepared", running, old, digest(candidate), files, time.Now().Unix()}, OldGeneration: previous.GenerationID, NewGeneration: generation, Last: last}
			if jsonSize(journal) > 32<<20 {
				return fail(E("subscription.config_invalid", "Subscription recovery evidence exceeds its bounded limit"), "validate", -1)
			}
			jp := a.subscriptionPrivate("journal.json")
			if e = WriteJSON(jp, journal); e != nil {
				return fail(e, "validate", -1)
			}
			last.Phase = "activate"
			for i := range batch.Sources {
				batch.Sources[i].Stage = "activate"
			}
			journal.Last = last
			journal.Runtime.Phase = "activate"
			if e = WriteJSON(jp, journal); e == nil {
				e = a.publishSubscriptionLast(ctx, last)
			}
			if e == nil {
				e = a.ActivateConfig(ctx, candidate, generation, running)
			}
			if e == nil {
				last.Phase = "commit"
				journal.Last = last
				journal.Runtime.Phase = "commit"
				e = WriteJSON(jp, journal)
			}
			if e == nil {
				for _, c := range changes {
					if c.Remove {
						e = removeRuntimeFile(a.Path(c.Path))
					} else {
						e = AtomicWrite(a.Path(c.Path), c.Data, 0600)
					}
					if e != nil {
						break
					}
				}
			}
			if e == nil {
				journal.Runtime.Phase = "committed"
				e = WriteJSON(jp, journal)
			}
			if e != nil {
				rctx, rcancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer rcancel()
				journal.Runtime.Phase = "recovering"
				if re := WriteJSON(jp, journal); re != nil {
					receipt["outcome"] = "recovery_pending"
					receipt["error_code"] = "rollback_failed"
					return E("subscription.rollback_failed", "Subscription rollback decision could not be recorded")
				}
				if re := a.restoreRuntimeTransaction(rctx, journal.Runtime); re != nil {
					last.Result = "failed"
					last.Phase = "activate"
					last.HasReason = true
					batch.Outcome = "recovery_pending"
					batch.ErrorCode = "rollback_failed"
					journal.Last = last
					_ = WriteJSON(jp, journal)
					_ = a.publishSubscriptionLast(rctx, last)
					receipt["outcome"] = "recovery_pending"
					return E("subscription.rollback_failed", "Subscription recovery remains pending")
				}
				if re := removeRuntimeFile(jp); re != nil {
					return fail(E("subscription.rollback_failed", "Subscription recovery journal could not be cleared"), "activate", -1)
				}
				return fail(E("subscription.activation_failed", "The new subscription generation could not be committed"), "activate", -1)
			}
			last.Phase = "complete"
			last.Result = "success"
			last.SuccessEpoch = time.Now().Unix()
			batch.Outcome = "committed"
			batch.ErrorCode = "none"
			for i := range batch.Sources {
				batch.Sources[i].Stage = "complete"
			}
			if running {
				if e = a.ReplaySelectors(ctx); e != nil {
					batch.WarningCode = "selector_replay_failed"
				}
			}
			journal.Last = last
			receipt["outcome"] = "recovery_pending"
			receipt["error_code"] = "rollback_failed"
			if e = WriteJSON(jp, journal); e != nil {
				return E("subscription.rollback_failed", "Committed subscription has pending completion bookkeeping")
			}
			if e = a.publishSubscriptionLast(ctx, last); e != nil {
				return E("subscription.rollback_failed", "Committed subscription status remains pending")
			}
			if e = removeRuntimeFile(jp); e != nil {
				return E("subscription.rollback_failed", "Committed subscription has pending journal cleanup")
			}
			receipt["outcome"] = "committed"
			delete(receipt, "error_code")
			receipt["warning_code"] = batch.WarningCode
			receipt["selection_fallback_count"] = len(fallbacks)
			receipt["saved_pending_start"] = !running
			receipt["network_verified"] = false
			receipt["exit_code"] = 0
			return nil
		})
	})
	publishErr := a.Publish(context.Background())
	if e != nil {
		return receipt, e
	}
	if publishErr != nil {
		return receipt, publishErr
	}
	return receipt, nil
}

func findSubscriptionCache(snapshot SubscriptionSnapshot, normalized string) (SubscriptionSourceCache, bool) {
	id := SubscriptionSourceID(normalized)
	for _, c := range snapshot.Sources {
		if c.ID == id && c.URL == normalized && snapshot.GenerationID != "" {
			return c, true
		}
	}
	return SubscriptionSourceCache{}, false
}

func (a *App) stageSubscriptionSnapshot(s SubscriptionSnapshot, bodies map[string][]byte) error {
	if !safeToken(s.GenerationID) || jsonSize(s) > 8<<20 {
		return E("subscription.merge_failed", "Subscription generation exceeds its metadata limit")
	}
	for id, body := range bodies {
		if len(id) != 64 {
			return E("subscription.cache_untrusted", "Invalid cache identity")
		}
		if e := AtomicWrite(a.subscriptionPrivate("generations", s.GenerationID, "source-"+id+".bin"), body, 0600); e != nil {
			return e
		}
	}
	for _, c := range s.Sources {
		if e := WriteJSON(a.subscriptionPrivate("generations", s.GenerationID, "usage-"+c.ID+".json"), sanitizeUsage(c.Usage)); e != nil {
			return e
		}
	}
	if s.Mode == "local_file" {
		if e := AtomicWrite(a.subscriptionPrivate("generations", s.GenerationID, "local.txt"), s.LocalDocument, 0600); e != nil {
			return e
		}
	}
	return WriteJSON(a.subscriptionPrivate("generations", s.GenerationID, "manifest.json"), s)
}

func (a *App) recoverSubscription(ctx context.Context) error {
	jp := a.subscriptionPrivate("journal.json")
	var j SubscriptionJournal
	e := ReadJSON(jp, 32<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return E("subscription.rollback_failed", "Subscription recovery journal is unreadable")
	}
	_, owner, oe := a.subscriptionOwner()
	if oe != nil || owner == "unknown" || owner == "pending" {
		return E("subscription.owner_unknown", "Recovery cannot establish updater ownership")
	}
	if owner == "active" {
		return E("subscription.busy", "An updater still owns the subscription transaction")
	}
	if j.Runtime.Phase == "committed" {
		if e = a.verifyRuntimeCommit(ctx, j.Runtime); e != nil {
			return E("subscription.rollback_failed", "Committed subscription metadata cannot be verified")
		}
		current, e := a.subscriptionSnapshot()
		config, ce := ReadRegular(a.ConfigPath(), 4<<20)
		if e != nil || ce != nil || current.GenerationID != j.NewGeneration || digest(config) != j.Runtime.CandidateHash || a.CheckConfig(ctx, config) != nil {
			return E("subscription.rollback_failed", "Committed subscription generation cannot be verified")
		}
		if j.Last.Result != "success" || j.Last.Phase != "complete" || j.Last.SuccessEpoch == 0 {
			j.Last.SuccessEpoch = time.Now().Unix()
		}
		j.Last.Result = "success"
		j.Last.Phase = "complete"
		if j.Last.Batch != nil {
			j.Last.Batch.Outcome = "committed"
			j.Last.Batch.ErrorCode = "none"
			for i := range j.Last.Batch.Sources {
				j.Last.Batch.Sources[i].Stage = "complete"
			}
		}
	} else {
		if e = a.restoreRuntimeTransaction(ctx, j.Runtime); e != nil {
			j.Last.Result = "failed"
			if j.Last.Batch != nil {
				j.Last.Batch.Outcome = "recovery_pending"
				j.Last.Batch.ErrorCode = "rollback_failed"
			}
			_ = a.publishSubscriptionLast(ctx, j.Last)
			return E("subscription.rollback_failed", "Subscription recovery remains pending")
		}
		j.Last.Result = "interrupted"
		j.Last.HasReason = true
		if j.Last.Batch != nil {
			j.Last.Batch.Outcome = "rolled_back"
			j.Last.Batch.ErrorCode = "interrupted"
		}
	}
	if e = a.publishSubscriptionLast(ctx, j.Last); e != nil {
		return e
	}
	if e = removeRuntimeFile(jp); e != nil {
		return e
	}
	if owner == "stale" {
		_ = removeRuntimeFile(a.subscriptionPrivate("owner.json"))
	}
	return nil
}

func (a *App) recoverRuntimeOnly(ctx context.Context) error {
	jp := a.Path(".state", "private", "runtime-transaction.json")
	var j RuntimeTransaction
	e := ReadJSON(jp, 32<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return E("config.recovery_pending", "Runtime journal cannot be read")
	}
	if j.Phase != "committed" {
		if e = a.restoreRuntimeTransaction(ctx, j); e != nil {
			return e
		}
	} else if e = a.verifyRuntimeCommit(ctx, j); e != nil {
		return e
	}
	return removeRuntimeFile(jp)
}

func (a *App) ClearSubscriptions(ctx context.Context) (M, error) {
	var result M
	e := a.withLock(ctx, "subscription", 2*time.Second, func() error {
		return a.WithLifecycleLock(ctx, 2*time.Second, func() error {
			_, owner, oe := a.subscriptionOwner()
			if oe != nil || owner == "unknown" || owner == "pending" {
				return E("subscription.owner_unknown", "Subscription owner is unknown")
			}
			if owner == "active" {
				return E("subscription.busy", "A subscription update is active")
			}
			if _, e := os.Stat(a.subscriptionPrivate("journal.json")); e == nil {
				return E("subscription.recovery_pending", "Recover the pending subscription transaction before clearing sources")
			}
			s, e := a.subscriptionSnapshot()
			if e != nil {
				return e
			}
			candidate, e := a.validatedBaseline(ctx)
			if e != nil {
				return e
			}
			s.Mode = "remote_url"
			s.URLs = []string{}
			s.Sources = []SubscriptionSourceCache{}
			s.GenerationID = token()
			s.LocalDocument = nil
			s.ConfigSHA256 = digest(candidate)
			if e = a.stageSubscriptionSnapshot(s, nil); e != nil {
				return e
			}
			changes := []RuntimeFileChange{{Path: ".config/magicnet/subscription-current.json", Data: rtJSON(SubscriptionPointer{1, s.GenerationID})}, {Path: ".config/sing-box/subscription.url", Remove: true}, {Path: ".config/sing-box/subscription.local", Remove: true}}
			if e = a.performRuntimeChange(ctx, candidate, changes, s.GenerationID); e != nil {
				return e
			}
			result = M{"cleared": true, "configured_count": 0, "configuration_preserved": true, "generation_id": s.GenerationID}
			return nil
		})
	})
	if e == nil {
		e = a.Publish(ctx)
	}
	return result, e
}

type SubscriptionRefreshCancellation struct {
	Task  string `json:"task"`
	PID   int    `json:"pid"`
	Start string `json:"start"`
	Boot  string `json:"boot"`
}

func refreshCancellation(o *Owner) SubscriptionRefreshCancellation {
	return SubscriptionRefreshCancellation{o.Task, o.PID, o.Start, o.Boot}
}

func (a *App) SetSubscriptionSchedule(ctx context.Context, hours string) (M, error) {
	if !stringIn(hours, "off", "12", "24", "48", "72") {
		return nil, E("subscription.schedule_invalid", "Refresh interval must be off, 12, 24, 48 or 72")
	}
	var cancelling *Owner
	e := a.withLock(ctx, "subscription-schedule", 2*time.Second, func() error {
		s, e := a.subscriptionSchedule()
		if e != nil {
			return e
		}
		if s.IntervalHours != hours {
			s.IntervalHours, s.NextDueEpoch = hours, 0
			if hours != "off" {
				n, _ := strconv.Atoi(hours)
				s.NextDueEpoch = time.Now().Add(time.Duration(n) * time.Hour).Unix()
			}
			if e = WriteJSON(a.Path(".config", "magicnet", "subscription-schedule.json"), s); e != nil {
				return e
			}
		}
		o, state, oe := observeOwner(a.Path(".state", "private", "subscription-refresh-owner.json"))
		if oe != nil || state == "unknown" || state == "pending" {
			return E("subscription.owner_unknown", "Refresh ownership cannot be proved; no process was stopped")
		}
		if hours == "off" && state == "active" {
			cancelling = o
			return WriteJSON(a.Path(".state", "private", "subscription-refresh-cancel.json"), refreshCancellation(o))
		}
		return nil
	})
	if e == nil && hours != "off" {
		if _, de := os.Lstat(a.Path("disable")); de == nil {
			e = E("module.disabled", "The refresh interval was saved but the module is disabled")
		} else if !errors.Is(de, os.ErrNotExist) {
			e = de
		} else {
			// Repeating the same value repairs a provably absent/stale scheduler.
			_, e = a.supervisorControl(ctx, "start", "fswatch")
		}
	}
	if e == nil && cancelling != nil {
		wait, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		for {
			o, state, oe := observeOwner(a.Path(".state", "private", "subscription-refresh-owner.json"))
			if oe != nil || state == "unknown" || state == "pending" {
				e = E("subscription.owner_unknown", "The refresh cancellation result is uncertain")
				break
			}
			if state == "none" || state == "stale" {
				break
			}
			if o == nil || o.Task != cancelling.Task || o.PID != cancelling.PID || o.Start != cancelling.Start || o.Boot != cancelling.Boot {
				e = E("subscription.owner_changed", "Refresh ownership changed while cancellation was pending")
				break
			}
			select {
			case <-wait.Done():
				e = E("subscription.cancellation_pending", "The schedule is off; its owned refresh is still stopping or recovering")
			case <-time.After(50 * time.Millisecond):
			}
			if e != nil {
				break
			}
		}
	}
	pctx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pcancel()
	pe := a.Publish(pctx)
	if e == nil {
		e = pe
	}
	status, se := a.SubscriptionScheduleStatus(pctx)
	if e == nil {
		e = se
	}
	return status, e
}

func (a *App) TickSubscriptionSchedule(ctx context.Context) error {
	return a.tickSubscriptionSchedule(ctx, func(c context.Context) error {
		_, e := a.RefreshSubscriptions(c)
		return e
	})
}

func (a *App) tickSubscriptionSchedule(ctx context.Context, refresh func(context.Context) error) error {
	s, e := a.subscriptionSchedule()
	if e != nil || s.IntervalHours == "off" || s.NextDueEpoch > time.Now().Unix() {
		return e
	}
	e = a.withLock(ctx, "subscription-refresh", 0, func() error {
		var o *Owner
		path := a.Path(".state", "private", "subscription-refresh-owner.json")
		cancelPath := a.Path(".state", "private", "subscription-refresh-cancel.json")
		e := a.withLock(ctx, "subscription-schedule", 2*time.Second, func() error {
			if _, e := os.Lstat(a.Path("disable")); e == nil {
				return nil
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
			_, state, oe := observeOwner(path)
			if oe != nil || state == "unknown" || state == "pending" {
				return E("subscription.owner_unknown", "Refresh owner cannot be proved")
			}
			if state == "active" {
				return nil
			}
			var e error
			s, e = a.subscriptionSchedule()
			if e != nil || s.IntervalHours == "off" || s.NextDueEpoch > time.Now().Unix() {
				return e
			}
			o, e = newSubscriptionOwner(token())
			if e != nil {
				return e
			}
			return WriteJSON(path, o)
		})
		if e != nil || o == nil {
			return e
		}
		defer func() {
			var current Owner
			if ReadJSON(path, 4096, &current) == nil && current.Task == o.Task && current.PID == o.PID && current.Start == o.Start && current.Boot == o.Boot {
				_ = removeRuntimeFile(path)
			}
			var request SubscriptionRefreshCancellation
			if ReadJSON(cancelPath, 4096, &request) == nil && request == refreshCancellation(o) {
				_ = removeRuntimeFile(cancelPath)
			}
			pctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.Publish(pctx)
		}()
		work, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-work.Done():
					return
				case <-tick.C:
					var request SubscriptionRefreshCancellation
					if ReadJSON(cancelPath, 4096, &request) == nil && request == refreshCancellation(o) {
						cancel()
						return
					}
					if _, e := os.Lstat(a.Path("disable")); e == nil {
						cancel()
						return
					}
				}
			}
		}()
		updateErr := refresh(work)
		cancel()
		<-done
		if logErr := a.recordSubscriptionRefresh(updateErr); logErr != nil && updateErr == nil {
			updateErr = logErr
		}
		commit, commitCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer commitCancel()
		if e = a.withLock(commit, "subscription-schedule", 2*time.Second, func() error {
			current, e := a.subscriptionSchedule()
			if e != nil {
				return e
			}
			// A concurrent off/interval change is authoritative. Completion must
			// never resurrect the old schedule or advance its replacement.
			if current.IntervalHours != s.IntervalHours || current.NextDueEpoch != s.NextDueEpoch {
				return nil
			}
			hours, _ := strconv.Atoi(current.IntervalHours)
			current.NextDueEpoch = time.Now().Add(time.Duration(hours) * time.Hour).Unix()
			return WriteJSON(a.Path(".config", "magicnet", "subscription-schedule.json"), current)
		}); e != nil {
			return e
		}
		return updateErr
	})
	if ErrorCode(e) == "operation.busy" {
		return nil
	}
	return e
}
