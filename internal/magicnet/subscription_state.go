package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SubscriptionBatchSource struct {
	Index          int    `json:"index"`
	Stage          string `json:"stage"`
	FetchResult    string `json:"fetch_result"`
	ConvertResult  string `json:"convert_result"`
	ParsedCount    *int   `json:"parsed_count"`
	ImportedCount  *int   `json:"imported_count"`
	FilteredCount  *int   `json:"filtered_count"`
	DuplicateCount *int   `json:"duplicate_count"`
	ErrorCode      string `json:"error_code"`
}
type SubscriptionBatch struct {
	Schema         int                       `json:"schema"`
	GenerationID   string                    `json:"generation_id"`
	RequestedCount int                       `json:"requested_count"`
	UniqueCount    int                       `json:"unique_count"`
	Outcome        string                    `json:"outcome"`
	Sources        []SubscriptionBatchSource `json:"sources"`
	ErrorCode      string                    `json:"error_code"`
	WarningCode    string                    `json:"warning_code"`
}
type SubscriptionLast struct {
	Phase              string             `json:"phase"`
	Result             string             `json:"result"`
	GenerationID       string             `json:"generation_id"`
	OperationID        string             `json:"operation_id,omitempty"`
	AttemptEpoch       int64              `json:"attempt_epoch"`
	SuccessEpoch       int64              `json:"success_epoch"`
	ConfiguredCount    int                `json:"configured_count"`
	SourceCount        int                `json:"source_count"`
	ImportedCount      int                `json:"imported_count"`
	SkippedCount       int                `json:"skipped_count"`
	HasReason          bool               `json:"has_reason"`
	SourceMode         string             `json:"source_mode"`
	NativeParser       string             `json:"native_parser"`
	NativeNodeCount    int                `json:"native_node_count"`
	ConverterEnabled   string             `json:"converter_enabled"`
	ConverterAvailable string             `json:"converter_available"`
	ConverterAttempted string             `json:"converter_attempted"`
	ConverterFormat    string             `json:"converter_format"`
	ConverterResult    string             `json:"converter_result"`
	Batch              *SubscriptionBatch `json:"batch"`
}
type SubscriptionSourceCache struct {
	ID         string            `json:"id"`
	URL        string            `json:"url"`
	BodySHA256 string            `json:"body_sha256"`
	State      string            `json:"state"`
	Usage      SubscriptionUsage `json:"-"`
}
type SubscriptionSnapshot struct {
	Schema        int                       `json:"schema"`
	GenerationID  string                    `json:"generation_id"`
	Mode          string                    `json:"mode"`
	URLs          []string                  `json:"urls"`
	Nodes         []SubscriptionNode        `json:"nodes"`
	Sources       []SubscriptionSourceCache `json:"sources"`
	ConfigSHA256  string                    `json:"config_sha256"`
	LocalDocument []byte                    `json:"-"`
}
type SubscriptionPointer struct {
	Schema       int    `json:"schema"`
	GenerationID string `json:"generation_id"`
}

func (a *App) subscriptionPrivate(parts ...string) string {
	return a.Path(append([]string{".state", "private", "subscription"}, parts...)...)
}
func (a *App) subscriptionPointerPath() string {
	return a.Path(".config", "magicnet", "subscription-current.json")
}
func (a *App) subscriptionLast() (SubscriptionLast, error) {
	l := SubscriptionLast{Phase: "idle", Result: "idle", SourceMode: "url", NativeParser: "unknown", ConverterEnabled: "0", ConverterAvailable: "native", ConverterAttempted: "0", ConverterFormat: "unknown", ConverterResult: "not_attempted"}
	e := ReadJSON(a.subscriptionPrivate("last.json"), 64<<10, &l)
	if errors.Is(e, os.ErrNotExist) {
		return l, nil
	}
	if e != nil {
		return l, E("machine.subscription_observation_failed", "Subscription progress cannot be read")
	}
	validFormat := func(s string) bool {
		return stringIn(s, "unknown", "mixed", "sing_box_json", "sing_box_yaml", "clash_yaml", "share_links", "base64_sing_box_json", "base64_sing_box_yaml", "base64_clash_yaml", "base64_share_links", "json", "yaml", "links", "base64", "native", "none")
	}
	if !stringIn(l.Phase, "idle", "prepare", "fetch", "parse", "convert", "merge", "validate", "check", "activate", "commit", "complete", "unknown") || !stringIn(l.Result, "idle", "running", "success", "failed", "interrupted", "unknown") || (l.GenerationID != "" && !safeToken(l.GenerationID)) || (l.OperationID != "" && !safeToken(l.OperationID)) || !stringIn(l.SourceMode, "url", "local", "unknown", "none") || !validFormat(l.NativeParser) || !validFormat(l.ConverterFormat) || !stringIn(l.ConverterEnabled, "0", "1", "unknown") || !stringIn(l.ConverterAvailable, "0", "1", "unknown", "native") || !stringIn(l.ConverterAttempted, "0", "1", "unknown") || !stringIn(l.ConverterResult, "not_attempted", "not_needed", "success", "failed", "unknown") || l.AttemptEpoch < 0 || l.SuccessEpoch < 0 || l.AttemptEpoch > 253402300799 || l.SuccessEpoch > 253402300799 || l.ConfiguredCount < 0 || l.ConfiguredCount > 5 || l.SourceCount < 0 || l.SourceCount > 5 || l.NativeNodeCount < 0 || l.ImportedCount < 0 || l.SkippedCount < 0 {
		return l, E("machine.subscription_observation_failed", "Subscription progress contains invalid public tokens")
	}
	if l.Batch != nil {
		b := l.Batch
		if b.Schema != 1 || b.GenerationID == "" || b.GenerationID != l.GenerationID || b.UniqueCount < 1 || b.UniqueCount > 5 || b.RequestedCount < b.UniqueCount || b.RequestedCount > int(SubscriptionListLimit) || len(b.Sources) != b.UniqueCount || !safeToken(b.GenerationID) || !stringIn(b.Outcome, "running", "committed", "rolled_back", "recovery_pending", "interrupted", "unknown") || !validSubscriptionErrorCode(b.ErrorCode) || !stringIn(b.WarningCode, "none", "selector_replay_failed") {
			return l, E("machine.subscription_observation_failed", "Invalid subscription batch state")
		}
		for i, s := range b.Sources {
			if s.Index != i+1 || !stringIn(s.Stage, "validate", "fetch", "parse", "convert", "merge", "check", "activate", "complete", "unknown") || !stringIn(s.FetchResult, "fresh", "cached", "failed", "not_attempted", "not_applicable") || !stringIn(s.ConvertResult, "success", "not_needed", "failed", "not_attempted", "unknown") || !validSubscriptionErrorCode(s.ErrorCode) {
				return l, E("machine.subscription_observation_failed", "Invalid subscription source indices")
			}
			for _, n := range []*int{s.ParsedCount, s.ImportedCount, s.FilteredCount, s.DuplicateCount} {
				if n != nil && (*n < 0 || *n > 1000000) {
					return l, E("machine.subscription_observation_failed", "Invalid subscription source count")
				}
			}
		}
	}
	return l, nil
}

func (a *App) subscriptionSnapshot() (SubscriptionSnapshot, error) {
	s := SubscriptionSnapshot{Schema: 1, Mode: "remote_url", URLs: []string{}, Nodes: []SubscriptionNode{}, Sources: []SubscriptionSourceCache{}}
	b, e := ReadRegular(a.subscriptionPointerPath(), 1024)
	if errors.Is(e, os.ErrNotExist) {
		return a.legacySubscriptionSnapshot(s)
	}
	if e != nil {
		return s, E("machine.subscription_observation_failed", "Subscription generation cannot be read")
	}
	var p SubscriptionPointer
	if DecodeJSON(b, &p) != nil || p.Schema != 1 || !safeToken(p.GenerationID) {
		return s, E("machine.subscription_observation_failed", "Invalid subscription generation")
	}
	if e = ReadJSON(a.subscriptionPrivate("generations", p.GenerationID, "manifest.json"), 8<<20, &s); e != nil || s.Schema != 1 || s.GenerationID != p.GenerationID || !stringIn(s.Mode, "remote_url", "local_file") {
		return s, E("machine.subscription_observation_failed", "Subscription manifest cannot be read")
	}
	for i := range s.Sources {
		cache := &s.Sources[i]
		var usage SubscriptionUsage
		if len(cache.ID) != 64 || cache.ID != SubscriptionSourceID(cache.URL) {
			cache.State = "unknown"
			continue
		}
		if e := ReadJSON(a.subscriptionPrivate("generations", s.GenerationID, "usage-"+cache.ID+".json"), 2<<10, &usage); e != nil {
			cache.State = "unknown"
		} else {
			cache.Usage = sanitizeUsage(usage)
		}
	}
	if s.Mode == "remote_url" {
		if len(s.URLs) > 5 {
			return s, E("machine.subscription_observation_failed", "Invalid committed source count")
		}
		if len(s.URLs) > 0 {
			normalized, _, e := NormalizeSubscriptionList([]byte(strings.Join(s.URLs, "\n")))
			if e != nil || !rtEqual(normalized, s.URLs) {
				return s, E("machine.subscription_observation_failed", "Invalid committed source identity")
			}
		}
	} else {
		if len(s.URLs) != 0 {
			return s, E("machine.subscription_observation_failed", "Conflicting subscription source modes")
		}
		local, e := ReadRegular(a.subscriptionPrivate("generations", s.GenerationID, "local.txt"), SubscriptionDocumentLimit)
		if e != nil {
			return s, E("machine.subscription_observation_failed", "Local subscription source cannot be read")
		}
		if _, e = ValidateSubscriptionDocument(local); e != nil {
			return s, E("machine.subscription_observation_failed", "Local subscription source is invalid")
		}
		s.LocalDocument = local
	}
	b2, e := ReadRegular(a.subscriptionPointerPath(), 1024)
	if e != nil || string(b) != string(b2) {
		return s, E("machine.snapshot_changed", "Subscription generation changed during observation")
	}
	return s, nil
}

func (a *App) legacySubscriptionSnapshot(s SubscriptionSnapshot) (SubscriptionSnapshot, error) {
	u, ue := ReadRegular(a.Path(".config", "sing-box", "subscription.url"), SubscriptionListLimit)
	l, le := ReadRegular(a.Path(".config", "sing-box", "subscription.local"), SubscriptionDocumentLimit)
	if ue != nil && !errors.Is(ue, os.ErrNotExist) || le != nil && !errors.Is(le, os.ErrNotExist) {
		return s, E("machine.subscription_observation_failed", "Legacy subscription configuration cannot be read")
	}
	if ue == nil && le == nil {
		return s, E("machine.subscription_observation_failed", "Both legacy subscription source modes are configured")
	}
	if ue == nil {
		urls, _, e := NormalizeSubscriptionList(u)
		if e != nil {
			return s, E("machine.subscription_observation_failed", "Legacy URL configuration is invalid")
		}
		s.URLs = urls
	}
	if le == nil {
		if _, e := ValidateSubscriptionDocument(l); e != nil {
			return s, E("machine.subscription_observation_failed", "Legacy local configuration is invalid")
		}
		s.Mode = "local_file"
		s.LocalDocument = l
	}
	return s, nil
}

func (a *App) subscriptionPreferences() (string, []string, error) {
	ua := ""
	b, e := ReadRegular(a.Path(".config", "sing-box", "subscription.user-agent"), 1<<10)
	if e == nil {
		ua, e = ValidateUserAgent(string(b))
		if e != nil {
			return "", nil, E("machine.subscription_observation_failed", "Stored User-Agent is invalid")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", nil, E("machine.subscription_observation_failed", "User-Agent cannot be read")
	}
	filters := []string{}
	b, e = ReadRegular(a.Path(".config", "sing-box", "subscription-filter.list"), 8<<10)
	if e == nil {
		filters, e = NormalizeSubscriptionFilters(b)
		if e != nil {
			return "", nil, E("machine.subscription_observation_failed", "Stored filters are invalid")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", nil, E("machine.subscription_observation_failed", "Filters cannot be read")
	}
	return ua, filters, nil
}

func (a *App) subscriptionOwner() (*Owner, string, error) {
	path := a.subscriptionPrivate("owner.json")
	o, state, e := observeOwner(path)
	if state == "unknown" {
		if st, se := os.Stat(path); se == nil && time.Since(st.ModTime()) < 5*time.Second {
			return o, "pending", nil
		}
	}
	return o, state, e
}

func (a *App) SubscriptionStatus(ctx context.Context, private bool) (M, error) {
	s, e := a.subscriptionSnapshot()
	if e != nil {
		return nil, e
	}
	ua, filters, e := a.subscriptionPreferences()
	if e != nil {
		return nil, e
	}
	last, e := a.subscriptionLast()
	if e != nil {
		return nil, e
	}
	_, owner, _ := a.subscriptionOwner()
	_, pe := os.Lstat(a.subscriptionPrivate("journal.json"))
	pending := pe == nil
	if pe != nil && !errors.Is(pe, os.ErrNotExist) {
		return nil, E("machine.subscription_observation_failed", "Subscription transaction cannot be observed")
	}
	var running any = false
	if owner == "active" {
		running = true
	} else if owner == "unknown" || owner == "pending" {
		running = nil
	}
	if last.Result == "running" && (owner == "none" || owner == "stale") {
		last.Result = "interrupted"
		if last.Batch != nil {
			last.Batch.Outcome = "interrupted"
			if pending {
				last.Batch.Outcome = "recovery_pending"
			}
		}
	}
	state := last.Result
	switch {
	case owner == "active":
		state = "running"
	case owner == "pending":
		state = "pending"
	case owner == "unknown":
		state = "unknown"
	case pending:
		state = "recovery_pending"
	}
	count := len(s.URLs)
	if s.Mode == "local_file" {
		count = 1
	}
	entries := 0
	if s.GenerationID != "" {
		files, re := os.ReadDir(a.subscriptionPrivate("generations", s.GenerationID))
		if re != nil {
			return nil, E("machine.subscription_observation_failed", "Subscription cache inventory cannot be read")
		}
		for _, file := range files {
			if file.Type().IsRegular() {
				entries++
			}
		}
	}
	sourceEntries := 0
	provenance := 0
	for _, c := range s.Sources {
		if c.ID != SubscriptionSourceID(c.URL) || !stringIn(c.URL, s.URLs...) {
			continue
		}
		if b, e := ReadRegular(a.subscriptionPrivate("generations", s.GenerationID, "source-"+c.ID+".bin"), SubscriptionDocumentLimit); e == nil && digest(b) == c.BodySHA256 {
			sourceEntries++
			provenance++
		}
	}
	schedule, e := a.SubscriptionScheduleStatus(ctx)
	if e != nil {
		return nil, e
	}
	refresh, e := a.subscriptionRefreshCounts()
	if e != nil {
		return nil, e
	}
	data := M{"source": M{"mode": s.Mode, "configured_count": count}, "update": M{"lock_present": owner != "none", "transaction_pending": pending, "owner": owner, "running": running}, "last": last, "cache": M{"entries": entries, "source_entries": sourceEntries, "provenance_entries": provenance, "identity": "url_sha256_identity"}, "refresh": refresh, "schedule": schedule, "state": state, "schema": 1}
	if private {
		data["configuration"] = M{"sing_box_urls": s.URLs, "user_agent": ua, "filters": filters}
		rows := []any{}
		for i, u := range s.URLs {
			id := SubscriptionSourceID(u)
			parsed, _ := url.Parse(u)
			row := M{"id": id, "index": i + 1, "hostname": parsed.Hostname(), "state": "unknown", "upload_bytes": nil, "download_bytes": nil, "total_bytes": nil, "expire_epoch": nil, "updated_epoch": nil}
			for _, source := range s.Sources {
				if source.ID == id && source.URL == u {
					usage := sanitizeUsage(source.Usage)
					state := source.State
					if !stringIn(state, "fresh", "cached") {
						state = "unknown"
					}
					if pending || last.Result != "success" {
						if state == "fresh" {
							state = "cached"
						}
					}
					if state != "unknown" {
						row["state"] = state
						row["upload_bytes"] = usage.Upload
						row["download_bytes"] = usage.Download
						row["total_bytes"] = usage.Total
						row["expire_epoch"] = usage.Expire
						row["updated_epoch"] = usage.Updated
					}
					break
				}
			}
			rows = append(rows, row)
		}
		data["source_usage"] = rows
	}
	if current, e := a.subscriptionSnapshot(); e != nil || current.GenerationID != s.GenerationID || !rtEqual(current.URLs, s.URLs) || current.Mode != s.Mode {
		return nil, E("machine.snapshot_changed", "Subscription generation changed during observation")
	}
	return data, nil
}

type SubscriptionSchedule struct {
	IntervalHours string `json:"interval_hours"`
	NextDueEpoch  int64  `json:"next_due_epoch"`
}

func (a *App) subscriptionSchedule() (SubscriptionSchedule, error) {
	s := SubscriptionSchedule{IntervalHours: "off"}
	e := ReadJSON(a.Path(".config", "magicnet", "subscription-schedule.json"), 1024, &s)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil || !stringIn(s.IntervalHours, "off", "12", "24", "48", "72") || s.NextDueEpoch < 0 {
		return s, E("machine.subscription_observation_failed", "Refresh schedule is invalid")
	}
	return s, nil
}
func (a *App) SubscriptionScheduleStatus(ctx context.Context) (M, error) {
	s, e := a.subscriptionSchedule()
	if e != nil {
		return nil, e
	}
	_, taskOwner, _ := observeOwner(a.Path(".state", "private", "subscription-refresh-owner.json"))
	owner := taskOwner
	// The fswatch supervisor owns the waiting schedule. A refresh owner only
	// exists while one due batch is running; its absence is not a dead loop.
	if s.IntervalHours != "off" && (owner == "none" || owner == "stale") {
		_, owner, _ = observeOwner(a.Path(".state", "owners", "fswatch.json"))
	}
	var running any = owner == "active"
	var valid any = owner == "active"
	if owner == "unknown" || owner == "pending" {
		running = nil
		valid = nil
	}
	var refreshing any = taskOwner == "active"
	if taskOwner == "unknown" || taskOwner == "pending" {
		refreshing = nil
	}
	return M{"interval_hours": s.IntervalHours, "enabled": s.IntervalHours != "off", "owner": owner, "running": running, "owner_valid": valid, "next_due_epoch": s.NextDueEpoch, "refreshing": refreshing}, nil
}

func (a *App) publishSubscriptionLast(ctx context.Context, last SubscriptionLast) error {
	if e := WriteJSON(a.subscriptionPrivate("last.json"), last); e != nil {
		return e
	}
	return a.Publish(ctx)
}
func intPointer(n int) *int { return &n }
func newSubscriptionOwner(generation string) (*Owner, error) {
	start, e := procStart(os.Getpid())
	if e != nil {
		return nil, E("subscription.owner_unknown", "Cannot establish updater process identity")
	}
	exe, e := os.Readlink(filepath.Join("/proc", fmtInt(os.Getpid()), "exe"))
	if e != nil {
		return nil, e
	}
	commandHash, e := procCommandHash(os.Getpid())
	if e != nil {
		return nil, e
	}
	return &Owner{PID: os.Getpid(), Start: start, Boot: bootID(), Exe: exe, Task: token(), Generation: generation, Created: time.Now().Unix(), CommandHash: commandHash}, nil
}
func (a *App) releaseSubscriptionOwner(task string) error {
	var o Owner
	if e := ReadJSON(a.subscriptionPrivate("owner.json"), 4096, &o); e != nil {
		return e
	}
	if o.Task != task {
		return E("subscription.owner_changed", "Updater ownership changed")
	}
	return removeRuntimeFile(a.subscriptionPrivate("owner.json"))
}
func subscriptionFailureCode(err error) string {
	code := ErrorCode(err)
	code = strings.TrimPrefix(code, "subscription.")
	if validSubscriptionErrorCode(code) && code != "none" {
		return code
	}
	return "unknown"
}

func validSubscriptionErrorCode(code string) bool {
	return stringIn(code, "none", "input_invalid", "source_limit", "url_policy", "dns_failed", "tls_failed", "download_timeout", "download_failed", "response_too_large", "cache_untrusted", "format_unsupported", "converter_unavailable", "conversion_failed", "semantic_incomplete", "node_invalid", "empty_result", "merge_failed", "config_invalid", "activation_failed", "rollback_failed", "interrupted", "unknown")
}

func (a *App) subscriptionRefreshCounts() (M, error) {
	b, e := ReadRegular(a.Path(".log", "subscription-refresh.log"), 64<<10)
	if errors.Is(e, os.ErrNotExist) {
		return M{"event_count": 0, "error_count": 0}, nil
	}
	if e != nil {
		return nil, E("machine.subscription_observation_failed", "Refresh event window cannot be read")
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	events, failures := 0, 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, E("machine.subscription_observation_failed", "Refresh event window is invalid")
		}
		if _, e := strconv.ParseInt(fields[0], 10, 64); e != nil || !stringIn(fields[1], "success", "failed", "interrupted") {
			return nil, E("machine.subscription_observation_failed", "Refresh event window is invalid")
		}
		events++
		if fields[1] != "success" {
			failures++
		}
	}
	return M{"event_count": events, "error_count": failures}, nil
}

func (a *App) recordSubscriptionRefresh(result error) error {
	path := a.Path(".log", "subscription-refresh.log")
	b, e := ReadRegular(path, 64<<10)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	lines := []string{}
	if len(b) > 0 {
		lines = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	if len(lines) > 199 {
		lines = lines[len(lines)-199:]
	}
	state := "success"
	if result != nil {
		state = "failed"
	}
	if errors.Is(result, context.Canceled) || ErrorCode(result) == "subscription.interrupted" {
		state = "interrupted"
	}
	lines = append(lines, strconv.FormatInt(time.Now().Unix(), 10)+" "+state)
	return AtomicWrite(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}
func jsonSize(v any) int { b, _ := json.Marshal(v); return len(b) }
