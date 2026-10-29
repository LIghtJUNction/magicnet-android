// Package magicnet contains the shared control plane. CLI, WebUI and MCP call
// the same transactions; none of the transports owns networking policy.
package magicnet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type M = map[string]any
type Fault struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (f *Fault) Error() string { return f.Code + ": " + f.Message }
func E(code, msg string) error { return &Fault{code, msg} }
func ErrorCode(err error) string {
	if err == nil {
		return "none"
	}
	var f *Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return "operation.failed"
}
func PublicError(err error) *Fault {
	var f *Fault
	if errors.As(err, &f) {
		return f
	}
	return &Fault{"operation.failed", "The operation failed; private details were withheld."}
}

type App struct {
	Root              string
	Platform          string
	RuntimeCheckpoint any
	PlatformOwned     M
	PlatformOverride  *PlatformSettings
	ModeOverride      string
}

var Version = "1.8.1"
var Commit = "uncommitted"

const VersionCode = 10609
const RecipeVersion = "0.3.1"
const ReleaseChannel = "candidate"

func NewApp() (*App, error) {
	exe, e := os.Executable()
	if e != nil {
		return nil, E("environment.executable", "Cannot identify the executable.")
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil {
		return nil, e
	}
	root := filepath.Dir(filepath.Dir(exe))
	if runtime.GOOS != "android" {
		if x := os.Getenv("MAGICNET_ROOT"); x != "" {
			root = x
		} else if x = os.Getenv("MODDIR"); x != "" {
			root = x
		}
	}
	root, e = filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	if runtime.GOOS == "android" && root != "/data/adb/modules/MagicNet" && root != "/data/adb/modules_update/MagicNet" {
		return nil, E("environment.module_root", "Untrusted Android module location.")
	}
	return &App{Root: root, Platform: runtime.GOOS}, nil
}
func (a *App) Path(parts ...string) string {
	return filepath.Join(append([]string{a.Root}, parts...)...)
}
func (a *App) ConfigPath() string { return a.Path(".config", "sing-box", "config.json") }
func token() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func safeAncestors(path string) error {
	p := filepath.Clean(filepath.Dir(path))
	for {
		f, e := os.Lstat(p)
		if e == nil && f.Mode()&os.ModeSymlink != 0 {
			return E("file.unsafe", "Symbolic links are not permitted.")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		n := filepath.Dir(p)
		if p == n {
			break
		}
		p = n
	}
	return nil
}
func ReadRegular(path string, limit int64) ([]byte, error) {
	if e := safeAncestors(path); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, E("file.unsafe", "A regular file is required.")
	}
	if x, ok := st.Sys().(*syscall.Stat_t); ok && (x.Nlink != 1 || (int(x.Uid) != os.Geteuid() && x.Uid != 0)) {
		return nil, E("file.ownership", "Untrusted file ownership.")
	}
	if st.Size() > limit {
		return nil, E("file.limit", "File exceeds the size limit.")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, E("file.limit", "File exceeds the size limit.")
	}
	return b, nil
}
func AtomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := safeAncestors(path); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0) {
		return E("file.unsafe", "Unsafe destination.")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := os.OpenFile(filepath.Join(filepath.Dir(path), ".write-"+token()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func DecodeJSON(b []byte, v any) error {
	if e := validateJSONUnique(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := d.Decode(v); e != nil {
		return E("input.json_invalid", "Invalid JSON.")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return E("input.json_invalid", "Exactly one JSON document is required.")
	}
	return nil
}
func validateJSONUnique(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 128 {
			return E("input.json_limit", "JSON nesting exceeds the limit.")
		}
		t, e := d.Token()
		if e != nil {
			return E("input.json_invalid", "Invalid JSON.")
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return E("input.json_duplicate", "Duplicate JSON property.")
					}
					seen[s] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return E("input.json_invalid", "Invalid JSON.")
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return E("input.json_invalid", "Exactly one JSON document is required.")
	}
	return nil
}
func ReadJSON(path string, limit int64, v any) error {
	b, e := ReadRegular(path, limit)
	if e != nil {
		return e
	}
	return DecodeJSON(b, v)
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(path, append(b, '\n'), 0600)
}
func (a *App) WithLifecycleLock(ctx context.Context, timeout time.Duration, fn func() error) error {
	return a.withLock(ctx, "lifecycle", timeout, fn)
}
func (a *App) withLock(ctx context.Context, name string, timeout time.Duration, fn func() error) error {
	return a.withLockFD(ctx, name, timeout, func(_ *os.File) error { return fn() })
}
func (a *App) withLockFD(ctx context.Context, name string, timeout time.Duration, fn func(*os.File) error) error {
	p := a.Path(".state", "locks", name+".lock")
	if e := safeAncestors(p); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	file := os.NewFile(uintptr(fd), p)
	defer file.Close()
	st, se := file.Stat()
	if se != nil {
		return se
	}
	if !st.Mode().IsRegular() {
		return E("lock.unsafe", "The lock is not a regular file.")
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); ok && (stat.Nlink != 1 || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid())) {
		return E("lock.unsafe", "Lock ownership is invalid.")
	}
	until := time.Now().Add(timeout)
	for {
		e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			// Closing the final open-file description releases flock. A detached
			// update worker can inherit it without an acceptance-to-spawn gap.
			return fn(file)
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return E("lock.failed", "Cannot acquire operation lock.")
		}
		if timeout == 0 || time.Now().After(until) {
			return E("operation.busy", "A conflicting operation is still running.")
		}
		select {
		case <-ctx.Done():
			return E("operation.cancelled", "The operation was cancelled.")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func asString(v any) string { s, _ := v.(string); return s }
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case json.Number:
		x, _ := n.Int64()
		return int(x)
	}
	return 0
}
func needArgs(args []string, min, max int) error {
	if len(args) < min || len(args) > max {
		return E("command.arguments", "Invalid argument count.")
	}
	return nil
}
func stringIn(s string, vs ...string) bool {
	for _, v := range vs {
		if s == v {
			return true
		}
	}
	return false
}
func safeToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}
func (a *App) ReadServiceIntent() (bool, error) {
	b, e := ReadRegular(a.Path(".config", "magicnet", "service-intent"), 64)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	switch strings.TrimSpace(string(b)) {
	case "running":
		return true, nil
	case "stopped":
		return false, nil
	}
	return false, E("service.intent_invalid", "Invalid persisted service intent.")
}
func (a *App) setIntent(v bool) error {
	s := "stopped\n"
	if v {
		s = "running\n"
	}
	return AtomicWrite(a.Path(".config", "magicnet", "service-intent"), []byte(s), 0600)
}
func statusMap(name, state string) M { return M{"schema": 1, "domain": name, "state": state} }
func fmtInt(v int) string            { return fmt.Sprint(v) }
