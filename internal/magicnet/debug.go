package magicnet

import (
	"context"
	"github.com/sagernet/netlink"
	"os"
	"strings"
	"time"
)

func (a *App) debugSnapshot(ctx context.Context) (M, error) {
	h, e := a.health(ctx)
	if e != nil {
		return nil, e
	}
	logs := M{}
	for _, name := range []string{"sing-box", "service", "fswatch", "mcp"} {
		m, e := a.readLog(name, 50, true)
		if e != nil {
			m = M{"state": "unavailable", "error_code": ErrorCode(e)}
		}
		logs[name] = m
	}
	listeners := M{}
	for _, family := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, e := os.ReadFile("/proc/net/" + family)
		if e != nil {
			listeners[family] = M{"state": "unknown"}
			continue
		}
		n := 0
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if len(strings.Fields(line)) >= 4 {
				n++
			}
		}
		listeners[family] = M{"socket_count": n, "addresses": "withheld"}
	}
	routes := M{"state": "unknown"}
	if handle, e := netlink.NewHandle(); e == nil {
		defer handle.Close()
		_ = handle.SetSocketTimeout(time.Second)
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			key := "ipv4"
			if family == netlink.FAMILY_V6 {
				key = "ipv6"
			}
			r, e1 := handle.RouteList(nil, family)
			rules, e2 := handle.RuleList(family)
			if e1 == nil && e2 == nil {
				routes[key] = M{"route_count": len(r), "rule_count": len(rules), "destinations": "withheld"}
			} else {
				routes[key] = M{"state": "unknown"}
			}
		}
	}
	return M{"health": h, "logs": logs, "listeners": listeners, "routing": routes, "redacted": true, "private_identifiers": "excluded"}, nil
}
