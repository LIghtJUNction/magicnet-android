package magicnet

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

var payloadName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

func (a *App) payloadPath(ns, name string) (string, error) {
	if !stringIn(ns, "tmp", "subscription") || !payloadName.MatchString(name) {
		return "", E("payload.name_invalid", "Invalid private payload name.")
	}
	return a.Path(".state", "private", "payload", ns, name), nil
}
func (a *App) webuiControl(ctx context.Context, args []string) (M, error) {
	if len(args) == 0 {
		return nil, E("command.arguments", "A WebUI action is required.")
	}
	act := args[0]
	if act == "status" || act == "verify" {
		b, e := ReadRegular(a.Path("webroot", "index.html"), 4<<20)
		if e != nil {
			return M{"installed": false, "verified": false}, nil
		}
		m := M{"installed": true, "bytes": len(b), "verified": true}
		return m, nil
	}
	if act == "install-local" {
		if len(args) < 3 || len(args) > 4 {
			return nil, E("command.arguments", "URL and SHA-256 are required.")
		}
		return a.installPanel(ctx, args[1], args[2])
	}
	if act != "payload" || len(args) < 3 {
		return nil, E("command.arguments", "Invalid payload command.")
	}
	op := args[1]
	if stringIn(op, "apply-subscription", "apply-subscription-source") {
		if len(args) != 3 {
			return nil, E("command.arguments", "A payload name is required.")
		}
		p, e := a.payloadPath("subscription", args[2])
		if e != nil {
			return nil, e
		}
		b, e := a.consumePayload(p, 8<<20)
		if e != nil {
			return nil, e
		}
		if op == "apply-subscription" {
			return a.ApplySubscriptionURLs(ctx, b)
		}
		return a.ApplyLocalSubscription(ctx, b)
	}
	if len(args) < 4 {
		return nil, E("command.arguments", "A namespace and payload name are required.")
	}
	p, e := a.payloadPath(args[2], args[3])
	if e != nil {
		return nil, e
	}
	switch op {
	case "create":
		if len(args) != 4 {
			return nil, E("command.arguments", "Invalid create arguments.")
		}
		if e = safeAncestors(p); e != nil {
			return nil, e
		}
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return nil, e
		}
		fd, e := syscall.Open(p, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, E("payload.create_failed", "Cannot create private payload.")
		}
		syscall.Close(fd)
		return M{"text": p + "\n"}, nil
	case "append":
		if len(args) != 5 {
			return nil, E("command.arguments", "A base64 chunk is required.")
		}
		chunk, e := base64.StdEncoding.Strict().DecodeString(args[4])
		if e != nil || len(chunk) > 256<<10 {
			return nil, E("payload.chunk_invalid", "Invalid payload chunk.")
		}
		if _, e = ReadRegular(p, 8<<20); e != nil {
			return nil, E("payload.unsafe", "Private payload is unavailable.")
		}
		fd, e := syscall.Open(p, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, e
		}
		f := os.NewFile(uintptr(fd), p)
		defer f.Close()
		st, e := f.Stat()
		if e != nil {
			return nil, e
		}
		if !st.Mode().IsRegular() || st.Size()+int64(len(chunk)) > 8<<20 {
			return nil, E("payload.limit", "Private payload exceeds 8 MiB.")
		}
		if st.Mode().Perm()&0077 != 0 {
			return nil, E("payload.unsafe", "Private payload permissions are unsafe.")
		}
		if identity, ok := st.Sys().(*syscall.Stat_t); !ok || identity.Nlink != 1 || int(identity.Uid) != os.Geteuid() {
			return nil, E("payload.unsafe", "Private payload ownership is unsafe.")
		}
		if _, e = f.Write(chunk); e != nil {
			return nil, e
		}
		if e = f.Sync(); e != nil {
			return nil, e
		}
		return M{"appended": len(chunk)}, nil
	case "remove":
		if len(args) != 4 {
			return nil, E("command.arguments", "Invalid remove arguments.")
		}
		if _, e = ReadRegular(p, 8<<20); errors.Is(e, os.ErrNotExist) {
			return M{"removed": true}, nil
		} else if e != nil {
			return nil, E("payload.unsafe", "Private payload is unsafe.")
		}
		e = os.Remove(p)
		return M{"removed": e == nil}, e
	}
	return nil, E("command.unknown", "Unknown private payload operation.")
}
func (a *App) consumePayload(p string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(filepath.Clean(p), a.Path(".state", "private", "payload")+string(os.PathSeparator)) {
		return nil, E("payload.path_invalid", "Only controlled private payload paths are allowed.")
	}
	if e := safeAncestors(p); e != nil {
		return nil, e
	}
	claim := p + ".consumed-" + token()
	if e := os.Rename(p, claim); e != nil {
		return nil, E("payload.unavailable", "Cannot claim the private payload.")
	}
	defer os.Remove(claim)
	if st, e := os.Lstat(claim); e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, E("payload.unsafe", "Private payload permissions are unsafe.")
	}
	b, e := ReadRegular(claim, limit)
	if e != nil {
		return nil, E("payload.unsafe", "Private payload cannot be read safely.")
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, E("payload.encoding_invalid", "Private payload must be valid UTF-8 without NUL.")
	}
	return b, nil
}

type httpOperation struct {
	ID       string    `json:"operation_id"`
	Running  bool      `json:"running"`
	ExitCode *int      `json:"exit_code"`
	Stdout   string    `json:"stdout"`
	Stderr   string    `json:"stderr"`
	Created  time.Time `json:"-"`
	Intent   string    `json:"-"`
}

func (a *App) serveHTTP(ctx context.Context, bind string) error {
	host, _, e := net.SplitHostPort(bind)
	if e != nil || !stringIn(host, "127.0.0.1", "::1") {
		return E("http.bind_invalid", "The console must bind to loopback.")
	}
	secret := token() + token()
	ops := map[string]*httpOperation{}
	var mu sync.Mutex
	slots := make(chan struct{}, 64)
	mux := http.NewServeMux()
	origin := "http://" + bind
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin {
			http.Error(w, "origin_denied", 403)
			return false
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-MagicNet-Token")), []byte(secret)) != 1 {
			http.Error(w, "unauthorized", 401)
			return false
		}
		return true
	}
	encode := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "denied", 403)
			return
		}
		if r.URL.Query().Get("key") != secret {
			http.Error(w, "unauthorized", 401)
			return
		}
		encode(w, M{"token": secret})
	})
	mux.HandleFunc("/api/operation", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		op := ops[r.URL.Query().Get("id")]
		if op == nil {
			http.Error(w, "unknown_operation", 404)
			return
		}
		encode(w, op)
	})
	mux.HandleFunc("/api/command", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 12<<20+1))
		if e != nil || len(b) > 12<<20 {
			http.Error(w, "input_limit", 413)
			return
		}
		var v struct {
			Args        []string `json:"args"`
			OperationID string   `json:"operation_id"`
		}
		if DecodeJSON(b, &v) != nil || len(v.Args) == 0 || len(v.Args) > 220 {
			http.Error(w, "input_invalid", 400)
			return
		}
		if strings.HasPrefix(v.Args[0], "__") || v.Args[0] == "serve" {
			http.Error(w, "denied", 403)
			return
		}
		id := v.OperationID
		if id == "" {
			id = token()
		}
		if !safeToken(id) {
			http.Error(w, "input_invalid", 400)
			return
		}
		mu.Lock()
		intentBytes, _ := json.Marshal(v.Args)
		intent := digest(intentBytes)
		if existing := ops[id]; existing != nil {
			if existing.Intent != intent {
				mu.Unlock()
				http.Error(w, "operation_conflict", 409)
				return
			}
			encode(w, existing)
			mu.Unlock()
			return
		}
		for k, o := range ops {
			if !o.Running && time.Since(o.Created) > 5*time.Minute {
				delete(ops, k)
			}
		}
		if len(ops) >= 128 {
			mu.Unlock()
			http.Error(w, "operation_limit", 429)
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			mu.Unlock()
			http.Error(w, "busy", 429)
			return
		}
		op := &httpOperation{ID: id, Running: true, Created: time.Now(), Intent: intent}
		ops[id] = op
		mu.Unlock()
		done := make(chan struct{})
		go func() {
			defer func() { <-slots; close(done) }()
			var out, errout bytes.Buffer
			code := a.RunCLI(ctx, v.Args, &out, &errout)
			mu.Lock()
			op.ExitCode = &code
			op.Running = false
			op.Stdout = out.String()
			op.Stderr = errout.String()
			mu.Unlock()
		}()
		select {
		case <-done:
			mu.Lock()
			encode(w, op)
			mu.Unlock()
		case <-r.Context().Done():
			return
		case <-time.After(25 * time.Second):
			mu.Lock()
			encode(w, op)
			mu.Unlock()
		}
	})
	mux.HandleFunc("/api/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			encode(w, Envelope{Schema: 1, OK: true, Command: "machine.capabilities", Data: capabilities()})
		}
	})
	files := http.FileServer(http.Dir(a.Path("webroot")))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:9090; frame-src http://127.0.0.1:9090; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		files.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: bind, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	fmt.Fprintf(os.Stderr, "Open %s/#session=%s\n", origin, secret)
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	e = srv.ListenAndServe()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}

var _ = url.QueryEscape
