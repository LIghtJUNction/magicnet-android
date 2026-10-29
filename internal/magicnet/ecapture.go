package magicnet

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fixed eCapture v2.5.2 uses `tls -m pcap`, a positional BPF filter, and
// requires an ELF path for GoTLS. Public PID/UID filters stay separate argv.
func (a *App) ecapture(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("ecapture.arguments", "A capture action is required.")
	}
	path := a.Path("bin", "ecapture")
	if args[0] == "status" {
		st, e := os.Stat(path)
		return M{"available": e == nil && st.Mode()&0111 != 0, "kernel_capability": "unknown", "requires_explicit_capture": true}, nil
	}
	if args[0] == "help" || args[0] == "version" {
		argv := []string{"--version"}
		if args[0] == "help" {
			argv = []string{"--help"}
			if len(args) > 1 {
				sub := args[1]
				if sub == "pcap" {
					sub = "tls"
				}
				if !stringIn(sub, "tls", "gotls", "nspr") {
					return nil, E("ecapture.arguments", "Unknown capture command.")
				}
				argv = []string{sub, "--help"}
			}
		}
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		r, e := Run(c, a.Root, path, argv, nil, 256<<10)
		return M{"text": string(r.Stdout)}, e
	}
	if !stringIn(args[0], "tls", "gotls", "nspr", "pcap") {
		return nil, E("ecapture.arguments", "Unknown capture command.")
	}
	duration := 10
	if len(args) > 1 {
		n, e := strconv.Atoi(args[1])
		if e != nil || n < 1 || n > 60 {
			return nil, E("ecapture.duration", "Duration must be 1–60 seconds.")
		}
		duration = n
	}
	dir := a.Path(".log", "capture-"+token())
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	base := []string{args[0]}
	pid, uid := "all", "all"
	if len(args) > 2 {
		pid = args[2]
	}
	if len(args) > 3 {
		uid = args[3]
	}
	commands := [][]string{}
	pcapPath := ""
	if args[0] == "pcap" {
		if len(args) < 3 {
			return nil, E("ecapture.interface", "An interface is required.")
		}
		in, e := net.InterfaceByName(args[2])
		if e != nil || in.Flags&net.FlagUp == 0 {
			return nil, E("ecapture.interface", "Capture interface is unavailable.")
		}
		pcapPath = filepath.Join(dir, "capture.pcapng")
		base = []string{"tls", "-m", "pcap", "-i", args[2], "-w", pcapPath, "--"}
		for _, arg := range args[3:] {
			if strings.ContainsAny(arg, "\x00\r\n") || len(arg) > 4096 {
				return nil, E("ecapture.filter", "Invalid capture filter.")
			}
		}
		commands = append(commands, append(base, args[3:]...))
	} else {
		if len(args) > 4 {
			return nil, E("ecapture.arguments", "Unexpected capture arguments.")
		}
		if pid != "all" {
			n, e := strconv.Atoi(pid)
			if e != nil || n < 1 {
				return nil, E("ecapture.pid", "Invalid process identity.")
			}
			base = append(base, "--pid", pid)
		}
		if uid != "all" {
			n, e := strconv.Atoi(uid)
			if e != nil || n < 0 {
				return nil, E("ecapture.uid", "Invalid user identity.")
			}
			base = append(base, "--uid", uid)
		}
		if args[0] == "gotls" {
			paths, e := goTLSExecutables(pid, uid)
			if e != nil {
				return nil, e
			}
			for _, exe := range paths {
				commands = append(commands, append(append([]string{}, base...), "--elfpath", exe))
			}
		} else {
			commands = append(commands, base)
		}
	}
	c, cancel := context.WithTimeout(ctx, time.Duration(duration)*time.Second)
	defer cancel()
	results := make([]M, len(commands))
	errs := make([]error, len(commands))
	var wg sync.WaitGroup
	for i, argv := range commands {
		wg.Add(1)
		go func(i int, argv []string) {
			defer wg.Done()
			r, e := runWithGrace(c, a.Root, path, argv, nil, 4<<20, 1500*time.Millisecond)
			logpath := filepath.Join(dir, fmt.Sprintf("capture-%02d.log", i+1))
			if we := AtomicWrite(logpath, append(r.Stdout, r.Stderr...), 0600); we != nil {
				errs[i] = we
				return
			}
			deadline := c.Err() != nil && ErrorCode(e) == "command.timeout"
			if e != nil && !deadline {
				errs[i] = e
			}
			results[i] = M{"path": logpath, "process_exit": r.ExitCode, "deadline_reached": deadline, "error_code": ErrorCode(e), "capture_success": nil}
		}(i, argv)
	}
	wg.Wait()
	output := filepath.Join(dir, "capture-01.log")
	if pcapPath != "" {
		output = pcapPath
		_ = os.Chmod(output, 0600)
	}
	st, se := os.Stat(output)
	m := M{"path": output, "file_nonempty": se == nil && st.Size() > 0, "duration_seconds": duration, "target_count": len(commands), "results": results, "capture_success": nil, "deadline_reached": c.Err() != nil}
	for _, e := range errs {
		if e != nil {
			return m, E("ecapture.capture_failed", "The capture helper failed; inspect the private diagnostic log.")
		}
	}
	return m, nil
}

// `all` observes a bounded snapshot of current executable identities, never
// follows arbitrary caller paths, and does not pretend to cover future PIDs.
func goTLSExecutables(pid, uid string) ([]string, error) {
	ids := []string{pid}
	if pid == "all" {
		ds, e := os.ReadDir("/proc")
		if e != nil {
			return nil, E("ecapture.discovery_failed", "Process discovery is unavailable.")
		}
		ids = nil
		for _, d := range ds {
			if _, e := strconv.Atoi(d.Name()); e == nil {
				ids = append(ids, d.Name())
			}
		}
		if len(ids) > 4096 {
			return nil, E("ecapture.discovery_limit", "Too many process identities; select a PID.")
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if id == strconv.Itoa(os.Getpid()) && pid == "all" {
			continue
		}
		if uid != "all" {
			b, e := os.ReadFile("/proc/" + id + "/status")
			if e != nil {
				continue
			}
			matched := false
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) > 1 && f[0] == "Uid:" && f[1] == uid {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		exe, e := os.Readlink("/proc/" + id + "/exe")
		if e != nil || !filepath.IsAbs(exe) || strings.HasSuffix(exe, " (deleted)") || seen[exe] {
			continue
		}
		if _, e = buildinfo.ReadFile(exe); e != nil {
			continue
		}
		seen[exe] = true
		out = append(out, exe)
		if len(out) > 16 {
			return nil, E("ecapture.discovery_limit", "More than 16 Go executables are active; select a PID.")
		}
	}
	if len(out) == 0 {
		return nil, E("ecapture.target_unavailable", "No matching live Go executable is available.")
	}
	return out, nil
}
