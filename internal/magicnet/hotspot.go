package magicnet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/netlink"
)

const hotspotTable = 17892
const hotspotPriority = 17892

type hotspotResource struct {
	Kind      string `json:"kind"`
	Family    int    `json:"family"`
	Interface string `json:"interface"`
	Index     int    `json:"index,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Phase     string `json:"phase"`
}
type HotspotJournal struct {
	Schema         int               `json:"schema"`
	Boot           string            `json:"boot"`
	Offload        string            `json:"offload"`
	OffloadChanged bool              `json:"offload_changed"`
	Resources      []hotspotResource `json:"resources"`
}

func (r hotspotResource) key() string {
	b, _ := json.Marshal([]any{r.Kind, r.Family, r.Interface, r.Index, r.Prefix})
	return string(b)
}
func (r hotspotResource) rule() *netlink.Rule {
	v := netlink.NewRule()
	v.Family = r.Family
	v.Priority = hotspotPriority
	v.Table = hotspotTable
	v.IifName = r.Interface
	return v
}
func (r hotspotResource) route() *netlink.Route {
	_, prefix, _ := net.ParseCIDR(r.Prefix)
	scope := netlink.SCOPE_LINK
	if r.Prefix == "0.0.0.0/0" || r.Prefix == "::/0" {
		scope = netlink.SCOPE_UNIVERSE
	}
	return &netlink.Route{Family: r.Family, Table: hotspotTable, LinkIndex: r.Index, Dst: prefix, Protocol: 186, Scope: scope, Type: 1}
}
func sameHotspotRule(a, b netlink.Rule) bool { a.Type = 0; b.Type = 0; return reflect.DeepEqual(a, b) }
func prefixString(n *net.IPNet, family int) string {
	if n == nil {
		if family == netlink.FAMILY_V6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	return n.String()
}
func sameHotspotRoute(a, b netlink.Route) bool {
	return a.Family == b.Family && a.Table == b.Table && a.LinkIndex == b.LinkIndex && prefixString(a.Dst, a.Family) == prefixString(b.Dst, b.Family) && a.Protocol == b.Protocol && a.Scope == b.Scope && a.Type == b.Type && len(a.Gw) == 0 && len(a.MultiPath) == 0 && a.Src == nil && a.Priority == 0 && a.Encap == nil && a.NewDst == nil && a.Via == nil
}
func (r hotspotResource) observe(h *netlink.Handle) (string, error) {
	if r.Kind == "rule" {
		xs, e := h.RuleList(r.Family)
		if e != nil {
			return "unknown", e
		}
		n := 0
		for _, x := range xs {
			if x.Priority == hotspotPriority && x.IifName == r.Interface {
				if !sameHotspotRule(x, *r.rule()) {
					return "conflict", nil
				}
				n++
			}
		}
		if n > 1 {
			return "conflict", nil
		}
		if n == 1 {
			return "present", nil
		}
		return "absent", nil
	}
	xs, e := h.RouteListFiltered(r.Family, &netlink.Route{Table: hotspotTable}, netlink.RT_FILTER_TABLE)
	if e != nil {
		return "unknown", e
	}
	n := 0
	for _, x := range xs {
		if prefixString(x.Dst, r.Family) == r.Prefix {
			if !sameHotspotRoute(x, *r.route()) {
				return "conflict", nil
			}
			n++
		}
	}
	if n > 1 {
		return "conflict", nil
	}
	if n == 1 {
		return "present", nil
	}
	return "absent", nil
}
func (r hotspotResource) mutate(h *netlink.Handle, add bool) error {
	if r.Kind == "rule" {
		if add {
			return h.RuleAdd(r.rule())
		}
		return h.RuleDel(r.rule())
	}
	if add {
		return h.RouteAdd(r.route())
	}
	return h.RouteDel(r.route())
}
func hotspotHandle() (*netlink.Handle, error) {
	h, e := netlink.NewHandle()
	if e != nil {
		return nil, E("hotspot.observation_failed", "Kernel routing observation is unavailable.")
	}
	_ = h.SetSocketTimeout(2 * time.Second)
	return h, nil
}
func (a *App) readHotspotJournal() (HotspotJournal, error) {
	j := HotspotJournal{Schema: 1, Boot: bootID(), Resources: []hotspotResource{}}
	e := ReadJSON(a.Path(".state", "hotspot", "journal.json"), 128<<10, &j)
	if errors.Is(e, os.ErrNotExist) {
		return j, nil
	}
	if e != nil || j.Schema != 1 || len(j.Resources) > 512 {
		return j, E("hotspot.recovery_pending", "Hotspot ownership journal is unreadable.")
	}
	for _, r := range j.Resources {
		if !stringIn(r.Kind, "rule", "route") || !stringIn(r.Phase, "prepared", "installed") || !stringIn(r.Interface, strings.Fields(r.Interface)...) {
			return j, E("hotspot.recovery_pending", "Invalid hotspot ownership record.")
		}
	}
	return j, nil
}
func (a *App) writeHotspotJournal(j HotspotJournal) error {
	return WriteJSON(a.Path(".state", "hotspot", "journal.json"), j)
}
func (a *App) offloadValue(ctx context.Context) (string, error) {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, e := Run(c, a.Root, a.findTool("settings"), []string{"get", "global", "tether_offload_disabled"}, nil, 1024)
	if e != nil {
		return "", E("hotspot.offload_failed", "Cannot observe tether offload.")
	}
	v := strings.TrimSpace(string(r.Stdout))
	if !stringIn(v, "0", "1", "null") {
		return "", E("hotspot.offload_failed", "Unexpected tether offload state.")
	}
	return v, nil
}
func (a *App) setOffload(ctx context.Context, value string) error {
	args := []string{"put", "global", "tether_offload_disabled", value}
	if value == "null" {
		args = []string{"delete", "global", "tether_offload_disabled"}
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, e := Run(c, a.Root, a.findTool("settings"), args, nil, 1024); e != nil {
		return E("hotspot.offload_failed", "Cannot update tether offload.")
	}
	actual, e := a.offloadValue(ctx)
	if e != nil || actual != value {
		return E("hotspot.offload_failed", "Tether offload readback did not match.")
	}
	return nil
}
func (a *App) ensureOffload(ctx context.Context, j *HotspotJournal) error {
	current, e := a.offloadValue(ctx)
	if e != nil {
		return e
	}
	if j.OffloadChanged {
		if current != "1" && current != j.Offload {
			return E("hotspot.offload_conflict", "Tether offload changed outside this transaction.")
		}
	} else {
		j.Offload = current
		if current == "1" {
			return nil
		}
		j.OffloadChanged = true
		if e = a.writeHotspotJournal(*j); e != nil {
			return e
		}
	}
	if current != "1" {
		return a.setOffload(ctx, "1")
	}
	return nil
}

func (a *App) hotspotDesired(ds []string) ([]hotspotResource, error) {
	tun, e := net.InterfaceByName("magicnet0")
	if e != nil {
		return nil, E("hotspot.pending", "The managed TUN interface is unavailable.")
	}
	var conf M
	if ReadJSON(a.ConfigPath(), 4<<20, &conf) != nil {
		return nil, E("hotspot.observation_failed", "Cannot read active network configuration.")
	}
	v6 := false
	for _, v := range rtArray(conf["inbounds"]) {
		m := rtMap(v)
		if m["tag"] == "tun-in" {
			for _, ad := range rtArray(m["address"]) {
				if strings.Contains(asString(ad), ":") {
					v6 = true
				}
			}
		}
	}
	resources := []hotspotResource{}
	families := map[int]bool{}
	for _, name := range ds {
		in, e := net.InterfaceByName(name)
		if e != nil {
			return nil, E("hotspot.observation_failed", "A confirmed downstream disappeared.")
		}
		ads, e := in.Addrs()
		if e != nil {
			return nil, e
		}
		ownFamilies := map[int]bool{}
		for _, ad := range ads {
			ip, prefix, e := net.ParseCIDR(ad.String())
			if e != nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				continue
			}
			family := netlink.FAMILY_V4
			if ip.To4() == nil {
				family = netlink.FAMILY_V6
				if !v6 {
					continue
				}
			}
			families[family] = true
			ownFamilies[family] = true
			resources = append(resources, hotspotResource{"route", family, name, in.Index, prefix.String(), "prepared"})
		}
		for family := range ownFamilies {
			resources = append(resources, hotspotResource{"rule", family, name, in.Index, "", "prepared"})
		}
	}
	for family := range families {
		prefix := "0.0.0.0/0"
		if family == netlink.FAMILY_V6 {
			prefix = "::/0"
		}
		resources = append(resources, hotspotResource{"route", family, tun.Name, tun.Index, prefix, "prepared"})
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Kind != resources[j].Kind {
			return resources[i].Kind == "route"
		}
		return resources[i].key() < resources[j].key()
	})
	return resources, nil
}

func (a *App) cleanupHotspotResources(h *netlink.Handle, j *HotspotJournal, keep map[string]bool) error {
	for i := len(j.Resources) - 1; i >= 0; i-- {
		r := j.Resources[i]
		if keep[r.key()] {
			continue
		}
		state, e := r.observe(h)
		if e != nil || state == "unknown" {
			return E("hotspot.cleanup_pending", "Cannot observe owned network resources.")
		}
		if state == "conflict" {
			return E("hotspot.ownership_conflict", "Network resource identity changed outside this transaction.")
		}
		if state == "present" {
			if e = r.mutate(h, false); e != nil {
				return E("hotspot.cleanup_pending", "Owned network cleanup is incomplete.")
			}
			state, e = r.observe(h)
			if e != nil || state != "absent" {
				return E("hotspot.cleanup_pending", "Network deletion could not be verified.")
			}
		}
		j.Resources = append(j.Resources[:i], j.Resources[i+1:]...)
		if e = a.writeHotspotJournal(*j); e != nil {
			return e
		}
	}
	return nil
}
func (a *App) releaseHotspot(ctx context.Context) error {
	jp := a.Path(".state", "hotspot", "journal.json")
	if _, e := os.Lstat(jp); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	j, e := a.readHotspotJournal()
	if e != nil {
		return e
	}
	if len(j.Resources) > 0 {
		h, e := hotspotHandle()
		if e != nil {
			return e
		}
		defer h.Close()
		if e = a.cleanupHotspotResources(h, &j, nil); e != nil {
			return e
		}
	}
	if j.OffloadChanged {
		current, e := a.offloadValue(ctx)
		if e != nil {
			return e
		}
		if current == "1" {
			if e = a.setOffload(ctx, j.Offload); e != nil {
				return e
			}
		} else if current != j.Offload {
			return E("hotspot.offload_conflict", "Refusing to overwrite a newer tether offload setting.")
		}
		j.OffloadChanged = false
		if e = a.writeHotspotJournal(j); e != nil {
			return e
		}
	}
	return os.Remove(jp)
}

func (a *App) hotspotReconcile(ctx context.Context) (M, error) {
	var result M
	attempted := false
	e := a.WithLifecycleLock(ctx, 0, func() error {
		attempted = true
		p, e := a.platformSettings()
		if e != nil {
			return e
		}
		running, e := a.IsRunning(ctx)
		if e != nil {
			return e
		}
		if !p.Hotspot || !running {
			if e = a.releaseHotspot(ctx); e != nil {
				return e
			}
			result = M{"state": "disabled", "client_return_path": "unknown"}
			return nil
		}
		ds, e := a.downstreams(ctx)
		if e != nil {
			return e
		}
		if len(ds) == 0 {
			if e = a.releaseHotspot(ctx); e != nil {
				return e
			}
			result = M{"state": "pending", "downstream_count": 0, "client_return_path": "unknown"}
			return nil
		}
		mode, e := a.transparentMode()
		if e != nil {
			return e
		}
		if _, e = a.platformApplyUnlocked(ctx); e != nil {
			return e
		}
		j, e := a.readHotspotJournal()
		if e != nil {
			return e
		}
		if e = a.ensureOffload(ctx, &j); e != nil {
			return e
		}
		if mode == "ebpf" {
			if len(j.Resources) > 0 {
				h, e := hotspotHandle()
				if e != nil {
					return e
				}
				defer h.Close()
				if e = a.cleanupHotspotResources(h, &j, nil); e != nil {
					return e
				}
			}
			result, e = a.hotspotStatus(ctx)
			return e
		}
		desired, e := a.hotspotDesired(ds)
		if e != nil {
			return e
		}
		keep := map[string]bool{}
		for _, r := range desired {
			keep[r.key()] = true
		}
		h, e := hotspotHandle()
		if e != nil {
			return e
		}
		defer h.Close()
		if e = a.cleanupHotspotResources(h, &j, keep); e != nil {
			return e
		}
		if e = hotspotTableOwnership(h, j); e != nil {
			return e
		}
		for _, r := range desired {
			at := -1
			for i, old := range j.Resources {
				if old.key() == r.key() {
					at = i
					break
				}
			}
			state, e := r.observe(h)
			if e != nil {
				return E("hotspot.observation_failed", "Cannot observe target route identity.")
			}
			if state == "conflict" || state == "present" && at < 0 {
				return E("hotspot.ownership_conflict", "Target route identity is already in use.")
			}
			if state == "absent" {
				if at < 0 {
					j.Resources = append(j.Resources, r)
					at = len(j.Resources) - 1
				}
				j.Resources[at].Phase = "prepared"
				if e = a.writeHotspotJournal(j); e != nil {
					return e
				}
				if e = r.mutate(h, true); e != nil {
					if errors.Is(e, syscall.EEXIST) {
						j.Resources = append(j.Resources[:at], j.Resources[at+1:]...)
						if we := a.writeHotspotJournal(j); we != nil {
							return we
						}
					}
					return E("hotspot.route_failed", "Cannot install the owned downstream route.")
				}
				state, e = r.observe(h)
				if e != nil || state != "present" {
					return E("hotspot.route_failed", "Installed route readback failed.")
				}
			}
			j.Resources[at].Phase = "installed"
			if e = a.writeHotspotJournal(j); e != nil {
				return e
			}
		}
		result, e = a.hotspotStatus(ctx)
		return e
	})
	if !attempted && ErrorCode(e) == "operation.busy" {
		return M{"state": "skipped_busy"}, nil
	}
	if attempted {
		if pe := a.Publish(ctx); e == nil {
			e = pe
		}
	}
	return result, e
}

func (a *App) hotspotStatus(ctx context.Context) (M, error) {
	p, e := a.platformSettings()
	if e != nil {
		return nil, e
	}
	m := M{"enabled": p.Hotspot, "state": "disabled", "downstream_count": nil, "route_status": "unknown", "shared_dataplane_ready": nil, "client_return_path": "unknown"}
	ds, e := a.downstreams(ctx)
	if e != nil {
		m["state"] = "unknown"
		return m, nil
	}
	m["downstream_count"] = len(ds)
	if !p.Hotspot {
		return m, nil
	}
	m["state"] = "pending"
	if len(ds) == 0 {
		return m, nil
	}
	o, ownership, _ := observeOwner(a.Path(".state", "owners", "core.json"))
	if ownership != "active" {
		return m, nil
	}
	if offload, err := a.offloadValue(ctx); err != nil || offload != "1" {
		m["offload"] = "unknown"
		return m, nil
	} else {
		m["offload"] = "disabled"
	}
	mode, e := a.transparentMode()
	if e != nil {
		return m, nil
	}
	if mode == "ebpf" {
		observed := a.observeEBPF(ctx, o)
		m["shared_dataplane_ready"] = observed["shared_ready"]
		m["route_status"] = "not_required"
		if observed["shared_ready"] == true {
			m["state"] = "attached"
		}
		return m, nil
	}
	desired, e := a.hotspotDesired(ds)
	if e != nil || len(desired) == 0 {
		return m, nil
	}
	j, e := a.readHotspotJournal()
	if e != nil {
		return m, nil
	}
	owned := map[string]bool{}
	for _, r := range j.Resources {
		owned[r.key()] = true
	}
	h, e := hotspotHandle()
	if e != nil {
		return m, nil
	}
	defer h.Close()
	for _, r := range desired {
		state, e := r.observe(h)
		if e != nil || state != "present" || !owned[r.key()] {
			m["route_status"] = "pending"
			return m, nil
		}
	}
	m["route_status"] = "verified"
	m["state"] = "configured"
	m["shared_dataplane_ready"] = true
	return m, nil
}

func hotspotTableOwnership(h *netlink.Handle, j HotspotJournal) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rs, e := h.RouteListFiltered(family, &netlink.Route{Table: hotspotTable}, netlink.RT_FILTER_TABLE)
		if e != nil {
			return E("hotspot.observation_failed", "Cannot inspect reserved routing table.")
		}
		for _, actual := range rs {
			owned := false
			for _, r := range j.Resources {
				if r.Kind == "route" && r.Family == family && sameHotspotRoute(actual, *r.route()) {
					owned = true
					break
				}
			}
			if !owned {
				return E("hotspot.ownership_conflict", "The reserved routing table contains an unowned route.")
			}
		}
		rules, e := h.RuleList(family)
		if e != nil {
			return E("hotspot.observation_failed", "Cannot inspect routing rule ownership.")
		}
		for _, actual := range rules {
			if actual.Table != hotspotTable {
				continue
			}
			owned := false
			for _, r := range j.Resources {
				if r.Kind == "rule" && r.Family == family && sameHotspotRule(actual, *r.rule()) {
					owned = true
					break
				}
			}
			if !owned {
				return E("hotspot.ownership_conflict", "An unowned rule uses the reserved routing table.")
			}
		}
	}
	return nil
}
