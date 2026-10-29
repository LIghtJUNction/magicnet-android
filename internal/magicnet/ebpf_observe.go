package magicnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
)

// Match actual attached program IDs to descriptors held by the owned core.
// Names and a successful capability probe are insufficient ownership evidence.
func (a *App) observeEBPF(ctx context.Context, o *Owner) M {
	m := M{"mode": "ebpf", "ready": nil, "local_ready": nil, "shared_ready": nil, "shared_tc": "unknown", "evidence": "attachment_unknown"}
	if o == nil {
		return m
	}
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fdinfo", o.PID))
	if e != nil {
		return m
	}
	owned := map[ebpf.ProgramID]bool{}
	for _, f := range fds {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", o.PID, f.Name()))
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "prog_id:" {
				n, e := strconv.ParseUint(fields[1], 10, 32)
				if e == nil {
					owned[ebpf.ProgramID(n)] = true
				}
			}
		}
	}
	if len(owned) == 0 {
		return m
	}
	var conf M
	if ReadJSON(a.ConfigPath(), 4<<20, &conf) != nil {
		return m
	}
	inbounds, _ := conf["inbounds"].([]any)
	var inbound M
	for _, x := range inbounds {
		v, _ := x.(map[string]any)
		if v["type"] == "ebpf" {
			inbound = v
			break
		}
	}
	if inbound == nil {
		return m
	}
	mode := asString(inbound["mode"])
	if mode == "" {
		mode = "local"
	}
	local, _ := inbound["local"].(map[string]any)
	cg := asString(local["cgroup_path"])
	if cg == "" {
		cg = "/sys/fs/cgroup"
	}
	if !filepath.IsAbs(cg) {
		return m
	}
	localReady := mode == "shared"
	if mode != "shared" {
		fd, e := os.Open(cg)
		if e != nil {
			return m
		}
		defer fd.Close()
		attachments := []ebpf.AttachType{ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP4Recvmsg}
		if local["ipv6"] != false {
			attachments = append(attachments, ebpf.AttachCGroupInet6Connect, ebpf.AttachCGroupUDP6Sendmsg, ebpf.AttachCGroupUDP6Recvmsg)
		}
		localReady = true
		for _, attach := range attachments {
			r, e := link.QueryPrograms(link.QueryOptions{Target: int(fd.Fd()), Attach: attach})
			if e != nil {
				return m
			}
			found := false
			for _, p := range r.Programs {
				if owned[p.ID] {
					found = true
				}
			}
			if !found {
				localReady = false
			}
		}
	}
	m["local_ready"] = localReady
	if mode == "local" {
		m["shared_ready"] = false
		m["shared_tc"] = "not_applicable"
		m["ready"] = localReady
		m["evidence"] = "owned_cgroup_program_ids"
		return m
	}
	ds, e := a.downstreams(ctx)
	if e != nil {
		return m
	}
	if len(ds) == 0 {
		m["shared_tc"] = "pending"
		m["shared_ready"] = false
		m["ready"] = mode == "hybrid" && localReady
		m["evidence"] = "owned_cgroup_shared_pending"
		return m
	}
	sharedReady := true
	for _, name := range ds {
		in, e := net.InterfaceByName(name)
		if e != nil {
			sharedReady = false
			continue
		}
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			found := false
			if r, e := link.QueryPrograms(link.QueryOptions{Target: in.Index, Attach: attach}); e == nil {
				for _, p := range r.Programs {
					if owned[p.ID] {
						found = true
					}
				}
			}
			if !found {
				dev, e := netlink.LinkByName(name)
				if e != nil {
					sharedReady = false
					continue
				}
				parent := uint32(netlink.HANDLE_MIN_INGRESS)
				if attach == ebpf.AttachTCXEgress {
					parent = netlink.HANDLE_MIN_EGRESS
				}
				filters, e := netlink.FilterList(dev, parent)
				if e != nil {
					return m
				}
				for _, f := range filters {
					if bpf, ok := f.(*netlink.BpfFilter); ok && owned[ebpf.ProgramID(bpf.Id)] {
						found = true
					}
				}
			}
			if !found {
				sharedReady = false
			}
		}
	}
	m["shared_ready"] = sharedReady
	m["shared_tc"] = "missing"
	if sharedReady {
		m["shared_tc"] = "attached"
	}
	m["ready"] = localReady && sharedReady
	m["evidence"] = "owned_cgroup_tc_program_ids"
	return m
}

var _ = json.Marshal
