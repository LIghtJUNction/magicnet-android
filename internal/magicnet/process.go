package magicnet

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// One shared reaper retains a slot until a child is actually reaped, even when
// its caller times out. It never turns a stuck kernel task into a free slot.
type child struct {
	p       *os.Process
	done    chan syscall.WaitStatus
	started string
}

var children = struct {
	sync.Mutex
	m     map[int]*child
	once  sync.Once
	slots chan struct{}
}{m: map[int]*child{}, slots: make(chan struct{}, 64)}

func reapLoop() {
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		children.Lock()
		for pid, c := range children.m {
			var st syscall.WaitStatus
			n, e := syscall.Wait4(pid, &st, syscall.WNOHANG, nil)
			if n == pid || e == syscall.ECHILD {
				delete(children.m, pid)
				c.done <- st
				close(c.done)
				c.p.Release()
				<-children.slots
			}
		}
		children.Unlock()
	}
}

type RunResult struct {
	Stdout, Stderr []byte
	ExitCode       int
	Truncated      bool
}
type capture struct {
	data     []byte
	overflow bool
	mu       sync.Mutex
	limit    int
}

func (c *capture) read(r *os.File, done chan struct{}) {
	defer close(done)
	defer r.Close()
	buf := make([]byte, 8192)
	for {
		n, e := r.Read(buf)
		if n > 0 {
			c.mu.Lock()
			if len(c.data)+n > c.limit {
				c.overflow = true
				c.data = nil
			} else if !c.overflow {
				c.data = append(c.data, buf[:n]...)
			}
			c.mu.Unlock()
		}
		if e != nil {
			return
		}
	}
}
func cleanEnv(root string) []string {
	out := []string{"PATH=/system/bin:/system/xbin:/usr/bin:/bin", "LANG=C.UTF-8", "MAGICNET_MODULE_ROOT=" + root, "TMPDIR=" + filepath.Join(root, ".state", "tmp")}
	if runtimePlatform() != "android" {
		out = append(out, "MAGICNET_ROOT="+root)
	}
	return out
}
func runtimePlatform() string {
	if _, e := os.Stat("/system/bin/app_process"); e == nil {
		return "android"
	}
	return "host"
}
func Run(ctx context.Context, root, path string, args []string, stdin []byte, limit int) (RunResult, error) {
	return runWithGrace(ctx, root, path, args, stdin, limit, 0)
}
func runWithGrace(ctx context.Context, root, path string, args []string, stdin []byte, limit int, grace time.Duration) (RunResult, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	if limit <= 0 {
		limit = 1 << 20
	}
	select {
	case children.slots <- struct{}{}:
	default:
		return RunResult{}, E("resource.saturated", "All command slots are occupied.")
	}
	release := true
	defer func() {
		if release {
			<-children.slots
		}
	}()
	ro, wo, e := os.Pipe()
	if e != nil {
		return RunResult{}, e
	}
	defer ro.Close()
	defer wo.Close()
	re, we, e := os.Pipe()
	if e != nil {
		return RunResult{}, e
	}
	defer re.Close()
	defer we.Close()
	var input *os.File
	if stdin != nil {
		if len(stdin) > 4<<20 {
			return RunResult{}, E("input.limit", "Command input exceeds limit.")
		}
		if e = os.MkdirAll(filepath.Join(root, ".state", "tmp"), 0700); e != nil {
			return RunResult{}, e
		}
		input, e = os.CreateTemp(filepath.Join(root, ".state", "tmp"), "stdin-")
		if e != nil {
			return RunResult{}, e
		}
		defer input.Close()
		os.Remove(input.Name())
		if _, e = input.Write(stdin); e != nil {
			return RunResult{}, e
		}
		input.Seek(0, 0)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = cleanEnv(root)
	cmd.Dir = root
	cmd.Stdin = input
	cmd.Stdout = wo
	cmd.Stderr = we
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e = cmd.Start(); e != nil {
		return RunResult{}, E("command.spawn_failed", "Cannot start required helper.")
	}
	release = false
	wo.Close()
	we.Close()
	start, _ := procStart(cmd.Process.Pid)
	c := &child{cmd.Process, make(chan syscall.WaitStatus, 1), start}
	children.Lock()
	children.m[cmd.Process.Pid] = c
	children.Unlock()
	children.once.Do(func() { go reapLoop() })
	co, ce := &capture{limit: limit}, &capture{limit: limit}
	do, de := make(chan struct{}), make(chan struct{})
	go co.read(ro, do)
	go ce.read(re, de)
	var st syscall.WaitStatus
	var err error
	select {
	case st = <-c.done:
	case <-ctx.Done():
		if grace > 0 {
			if now, x := procStart(c.p.Pid); x == nil && now == c.started {
				syscall.Kill(-c.p.Pid, syscall.SIGTERM)
			}
			select {
			case st = <-c.done:
			case <-time.After(grace):
			}
		}
		if now, x := procStart(c.p.Pid); x == nil && now == c.started {
			syscall.Kill(-c.p.Pid, syscall.SIGKILL)
		}
		err = E("command.timeout", "Command exceeded its deadline.")
	}
	// Descendants that retain the inherited pipe cannot keep callers waiting.
	wait := func(ch chan struct{}) {
		select {
		case <-ch:
		case <-time.After(200 * time.Millisecond):
			ro.Close()
			re.Close()
		case <-ctx.Done():
			ro.Close()
			re.Close()
		}
	}
	wait(do)
	wait(de)
	ro.Close()
	re.Close()
	co.mu.Lock()
	ce.mu.Lock()
	r := RunResult{append([]byte{}, co.data...), append([]byte{}, ce.data...), st.ExitStatus(), co.overflow || ce.overflow}
	if st.Signaled() {
		r.ExitCode = 128 + int(st.Signal())
	}
	if err != nil && r.ExitCode == 0 {
		r.ExitCode = 124
	}
	ce.mu.Unlock()
	co.mu.Unlock()
	if r.Truncated {
		return r, E("command.output_limit", "Command output exceeded its limit.")
	}
	if err != nil {
		return r, err
	}
	if st.Signaled() {
		r.ExitCode = 128 + int(st.Signal())
	}
	if r.ExitCode != 0 {
		return r, E("command.failed", "The helper returned a failure.")
	}
	return r, nil
}
func procStart(pid int) (string, error) {
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil {
		return "", e
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", E("process.identity_invalid", "Cannot parse process identity.")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", E("process.identity_invalid", "Cannot parse process identity.")
	}
	if f[0] == "Z" || f[0] == "X" {
		return "", os.ErrNotExist
	}
	return f[19], nil
}

type Owner struct {
	PID         int    `json:"pid"`
	Start       string `json:"start"`
	Boot        string `json:"boot"`
	Exe         string `json:"exe"`
	Task        string `json:"task"`
	Generation  string `json:"generation"`
	Fingerprint string `json:"fingerprint"`
	Created     int64  `json:"created"`
	CommandHash string `json:"command_hash"`
}

func procCommandHash(pid int) (string, error) {
	f, e := os.Open("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if e != nil || len(b) == 0 || len(b) > 2<<20 {
		return "", E("process.identity_invalid", "Cannot read bounded process command identity.")
	}
	return digest(b), nil
}

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
func observeOwner(path string) (*Owner, string, error) {
	var o Owner
	e := ReadJSON(path, 4096, &o)
	if errors.Is(e, os.ErrNotExist) {
		return nil, "none", nil
	}
	if e != nil {
		return nil, "unknown", e
	}
	if o.PID < 1 || o.Start == "" || o.Exe == "" || o.Boot == "" || o.CommandHash == "" {
		return &o, "unknown", E("process.owner_invalid", "Owner record is invalid.")
	}
	if o.Boot != bootID() {
		return &o, "stale", nil
	}
	st, e := procStart(o.PID)
	if errors.Is(e, os.ErrNotExist) {
		return &o, "stale", nil
	}
	if e != nil {
		return &o, "unknown", e
	}
	if st != o.Start {
		return &o, "stale", nil
	}
	exe, e := os.Readlink("/proc/" + strconv.Itoa(o.PID) + "/exe")
	if e != nil {
		return &o, "unknown", e
	}
	if exe != o.Exe {
		return &o, "stale", nil
	}
	commandHash, e := procCommandHash(o.PID)
	if e != nil {
		return &o, "unknown", e
	}
	if commandHash != o.CommandHash {
		return &o, "unknown", E("process.command_changed", "The process command identity changed.")
	}
	return &o, "active", nil
}
func stopOwner(ctx context.Context, path string) error {
	o, state, e := observeOwner(path)
	if e != nil || state == "unknown" {
		return E("process.ownership_unknown", "Process ownership cannot be proved.")
	}
	if state == "none" {
		return nil
	}
	if state == "stale" {
		return os.Remove(path)
	}
	if e = syscall.Kill(o.PID, syscall.SIGTERM); e != nil && e != syscall.ESRCH {
		return e
	}
	end := time.Now().Add(8 * time.Second)
	for time.Now().Before(end) {
		_, s, _ := observeOwner(path)
		if s == "stale" || s == "none" {
			return os.Remove(path)
		}
		select {
		case <-ctx.Done():
			return E("process.stop_pending", "Stop remains incomplete.")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, s, _ := observeOwner(path); s != "active" {
		return E("process.ownership_unknown", "Process ownership changed during stop.")
	}
	if e = syscall.Kill(o.PID, syscall.SIGKILL); e != nil && e != syscall.ESRCH {
		return e
	}
	end = time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		_, s, _ := observeOwner(path)
		if s == "stale" || s == "none" {
			return os.Remove(path)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return E("process.stop_pending", "The owned process has not exited.")
}
func (a *App) spawnOwned(name, path string, args []string, gen, fp string) (*Owner, error) {
	return a.spawnOwnedFiles(name, path, args, gen, fp, nil)
}
func (a *App) spawnOwnedFiles(name, path string, args []string, gen, fp string, extra []*os.File) (*Owner, error) {
	if e := os.MkdirAll(a.Path(".log"), 0700); e != nil {
		return nil, e
	}
	logpath := a.Path(".log", name+".log")
	if f, e := os.Stat(logpath); e == nil && f.Size() > 4<<20 {
		if e = os.Rename(logpath, logpath+".previous"); e != nil {
			return nil, e
		}
	}
	log, e := os.OpenFile(logpath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	defer log.Close()
	cmd := exec.Command(path, args...)
	cmd.Dir = a.Root
	cmd.Env = cleanEnv(a.Root)
	cmd.ExtraFiles = extra
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e = cmd.Start(); e != nil {
		return nil, E("process.start_failed", "Cannot start the managed process.")
	}
	st, e := procStart(cmd.Process.Pid)
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, e
	}
	exe, e := os.Readlink("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe")
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, e
	}
	commandHash, e := procCommandHash(cmd.Process.Pid)
	if e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, e
	}
	o := &Owner{PID: cmd.Process.Pid, Start: st, Boot: bootID(), Exe: exe, Task: token(), Generation: gen, Fingerprint: fp, Created: time.Now().Unix(), CommandHash: commandHash}
	if e = WriteJSON(a.Path(".state", "owners", name+".json"), o); e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, e
	}
	go cmd.Wait()
	return o, nil
}
func limitedCopy(dst io.Writer, src io.Reader, n int64) error {
	x, e := io.Copy(dst, io.LimitReader(src, n+1))
	if e != nil {
		return e
	}
	if x > n {
		return E("input.limit", "Input exceeds the size limit.")
	}
	return nil
}
