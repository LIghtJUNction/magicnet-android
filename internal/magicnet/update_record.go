package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"
)

type updateRecordFile struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  []byte `json:"after"`
}
type updateRecordJournal struct {
	Schema int                `json:"schema"`
	Files  []updateRecordFile `json:"files"`
}

func updateReplay(l UpdateLedger, id, intent string) (M, error, bool) {
	h, used := l.Used[id]
	if !used {
		return nil, nil, false
	}
	if h != intent {
		return nil, E("module-update.conflict", "The request ID was used for another intent."), true
	}
	i, ok := l.Results[id]
	if !ok {
		return nil, E("module-update.receipt_expired", "This request ID has expired and cannot execute again."), true
	}
	if i.Recovery {
		return nil, E("module-update.recovery_required", "Manager recovery is required."), true
	}
	return M{"request_id": id, "replayed": true, "phase": i.Phase, "effective_version": i.Baseline, "error_code": i.Error}, nil, true
}
func (a *App) publishUpdateRecord(i UpdateIntent, l UpdateLedger) error {
	intent, e := json.Marshal(i)
	if e != nil || len(intent) > 128<<10 {
		return E("module-update.intent_limit", "Update intent exceeds its limit.")
	}
	ledger, e := json.Marshal(l)
	if e != nil || len(ledger) > 512<<10 {
		return E("module-update.ledger_limit", "Update ledger exceeds its limit.")
	}
	j := updateRecordJournal{Schema: 1}
	for _, f := range []updateRecordFile{{Path: ".state/module-update/ledger.json", After: ledger}, {Path: ".config/magicnet/module-update.conf", After: intent}} {
		old, e := ReadRegular(a.Path(f.Path), 512<<10)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		f.Before = digest(old)
		j.Files = append(j.Files, f)
	}
	if e = WriteJSON(a.Path(".state", "module-update", "record-journal.json"), j); e != nil {
		return e
	}
	return a.recoverUpdateRecord()
}
func (a *App) recoverUpdateRecord() error {
	jp := a.Path(".state", "module-update", "record-journal.json")
	var j updateRecordJournal
	e := ReadJSON(jp, 1<<20, &j)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil || j.Schema != 1 || len(j.Files) != 2 {
		return E("module-update.record_pending", "Update record recovery is unreadable.")
	}
	var nextLedger UpdateLedger
	var nextIntent UpdateIntent
	if DecodeJSON(j.Files[0].After, &nextLedger) != nil || nextLedger.Used == nil || nextLedger.Results == nil || len(nextLedger.Used) > 4096 || len(nextLedger.Results) > 128 || len(nextLedger.Order) > 128 || DecodeJSON(j.Files[1].After, &nextIntent) != nil || !requestID.MatchString(nextIntent.ID) || !stringIn(nextIntent.Action, "check", "install") || !stringIn(nextIntent.Phase, "checking", "available", "up_to_date", "downloading", "verifying", "installing", "reboot_required", "failed") {
		return E("module-update.record_pending", "Update recovery candidates are invalid; original records were retained.")
	}
	if receipt, ok := nextLedger.Results[nextIntent.ID]; !ok || receipt.ID != nextIntent.ID || receipt.Action != nextIntent.Action || receipt.Phase != nextIntent.Phase || receipt.Recovery != nextIntent.Recovery || receipt.Error != nextIntent.Error || nextLedger.Used[nextIntent.ID] == "" {
		return E("module-update.record_pending", "Update recovery intent and receipt do not agree.")
	}
	for n, f := range j.Files {
		expected := ".state/module-update/ledger.json"
		if n == 1 {
			expected = ".config/magicnet/module-update.conf"
		}
		if f.Path != expected {
			return E("module-update.record_pending", "Invalid update recovery path.")
		}
		current, e := ReadRegular(a.Path(f.Path), 512<<10)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return E("module-update.record_pending", "Update record cannot be observed.")
		}
		if digest(current) != f.Before && digest(current) != digest(f.After) {
			return E("module-update.record_conflict", "Update records changed outside this transaction.")
		}
	}
	for _, f := range j.Files {
		if e = AtomicWrite(a.Path(f.Path), f.After, 0600); e != nil {
			return E("module-update.record_pending", "Update record publication is incomplete.")
		}
	}
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e = a.Publish(c); e != nil {
		return E("module-update.record_pending", "Public update state requires publication recovery.")
	}
	if e = os.Remove(jp); e != nil {
		return E("module-update.record_pending", "Update publication cleanup is incomplete.")
	}
	return nil
}
