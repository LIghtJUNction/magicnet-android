package magicnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

type stopResources struct {
	Owner       Owner            `json:"owner"`
	TunIndex    int              `json:"tun_index"`
	Programs    []ebpf.ProgramID `json:"programs"`
	Observation string           `json:"observation"`
}

func coreResources(o *Owner) (stopResources, error) {
	r := stopResources{Owner: *o, Programs: []ebpf.ProgramID{}, Observation: "verified"}
	files, e := os.ReadDir(fmt.Sprintf("/proc/%d/fdinfo", o.PID))
	if e != nil {
		r.Observation = "unknown"
		return r, e
	}
	seen := map[ebpf.ProgramID]bool{}
	for _, f := range files {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", o.PID, f.Name()))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			r.Observation = "unknown"
			return r, e
		}
		for _, line := range strings.Split(string(b), "\n") {
			v := strings.Fields(line)
			if len(v) != 2 {
				continue
			}
			if v[0] == "iff:" && v[1] == "magicnet0" {
				in, e := net.InterfaceByName("magicnet0")
				if e == nil {
					r.TunIndex = in.Index
				} else {
					r.Observation = "unknown"
					return r, e
				}
			}
			if v[0] == "prog_id:" {
				n, e := strconv.ParseUint(v[1], 10, 32)
				if e == nil && n > 0 {
					seen[ebpf.ProgramID(n)] = true
				}
			}
		}
	}
	for id := range seen {
		r.Programs = append(r.Programs, id)
	}
	start, e := procStart(o.PID)
	if e != nil || start != o.Start {
		r.Observation = "unknown"
		return r, E("process.ownership_unknown", "Process identity changed during resource observation.")
	}
	return r, nil
}
func (a *App) observeTUN(o *Owner) M {
	m := M{"mode": "tun", "ready": nil, "local_ready": nil, "shared_ready": nil, "shared_tc": "not_applicable", "evidence": "ownership_unknown"}
	if o == nil {
		return m
	}
	r, e := coreResources(o)
	if e != nil {
		return m
	}
	ready := r.TunIndex > 0
	m["ready"] = ready
	m["local_ready"] = ready
	m["evidence"] = "owned_tun_descriptor"
	if !ready {
		m["evidence"] = "owned_tun_missing"
	}
	return m
}
func (a *App) stopCoreWithEvidence(ctx context.Context) error {
	jp := a.Path(".state", "lifecycle", "stop-resources.json")
	var resources stopResources
	readErr := ReadJSON(jp, 64<<10, &resources)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return E("service.cleanup_pending", "Cannot read the previous cleanup evidence.")
	}
	o, state, e := observeOwner(a.Path(".state", "owners", "core.json"))
	if e != nil || state == "unknown" {
		return E("process.ownership_unknown", "Core ownership cannot be proved.")
	}
	if state == "active" {
		if readErr == nil && resources.Owner.Task != o.Task {
			return E("service.cleanup_conflict", "Cleanup evidence belongs to a different core task.")
		}
		var observationErr error
		resources, observationErr = coreResources(o)
		if observationErr != nil {
			resources.Observation = "unknown"
		}
		if e = WriteJSON(jp, resources); e != nil {
			return e
		}
	} else if state == "stale" && errors.Is(readErr, os.ErrNotExist) && o.Boot == bootID() {
		if e := ReadJSON(a.Path(".state", "lifecycle", "core-resources.json"), 64<<10, &resources); e != nil || resources.Owner.Task != o.Task {
			resources = stopResources{Owner: *o, Observation: "unknown"}
		}
		if e = WriteJSON(jp, resources); e != nil {
			return e
		}
		readErr = nil
	}
	if e = stopOwner(ctx, a.Path(".state", "owners", "core.json")); e != nil {
		return e
	}
	if e = a.releaseHotspot(ctx); e != nil {
		return e
	}
	if readErr != nil && state != "active" {
		return nil
	}
	if resources.Observation != "verified" && resources.Owner.Boot == bootID() {
		return E("service.cleanup_unknown", "The core stopped, but its resource cleanup cannot be proved.")
	}
	if resources.Owner.Boot == bootID() {
		if resources.TunIndex > 0 {
			if in, e := net.InterfaceByIndex(resources.TunIndex); e == nil && in.Name == "magicnet0" {
				return E("service.cleanup_pending", "The owned TUN interface still exists.")
			}
		}
		for _, id := range resources.Programs {
			p, e := ebpf.NewProgramFromID(id)
			if e == nil {
				p.Close()
				return E("service.cleanup_pending", "An owned eBPF program is still referenced.")
			}
			if !errors.Is(e, os.ErrNotExist) {
				return E("service.cleanup_unknown", "eBPF cleanup observation is unavailable.")
			}
		}
	}
	if e = os.Remove(jp); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e = os.Remove(a.Path(".state", "lifecycle", "core-resources.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
