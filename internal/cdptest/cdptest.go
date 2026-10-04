// Package cdptest drives a headless Chromium for tests, over the Chrome
// DevTools Protocol on a pipe (--remote-debugging-pipe): commands go to
// the browser on its file descriptor 3, and answers and events come back
// on 4, each a JSON message ended by a NUL byte. No port is opened, and
// nothing but the standard library is used.
//
// A Browser runs in a profile of its own (--user-data-dir) with HOME and
// the XDG directories the caller gives it, so it never reads or writes the
// person's own profiles. It is told to keep away from the network, the
// system keyring and the session bus.
package cdptest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Find is the Chromium-family browser to test with, or "" when there is
// none: $SECRETVAULT_TEST_CHROMIUM, else chromium on the PATH. A Snap or
// Flatpak wrapper is not taken: it would keep files of its own in the
// person's home, whatever HOME says.
func Find() string {
	if p := os.Getenv("SECRETVAULT_TEST_CHROMIUM"); p != "" {
		return p
	}
	for _, name := range []string{"chromium", "chromium-browser"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil || strings.HasPrefix(p, "/snap/") || strings.HasPrefix(real, "/snap/") || filepath.Base(real) == "snap" || strings.Contains(real, "flatpak") {
			continue
		}
		// A script in front of the browser (Ubuntu's chromium-browser
		// starts the snap) is not taken either.
		if head, err := readHead(real); err != nil || bytes.HasPrefix(head, []byte("#!")) {
			continue
		}
		return p
	}
	return ""
}

func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, 2)
	n, err := io.ReadFull(f, b)
	return b[:n], err
}

// Options say how to start the browser.
type Options struct {
	Binary      string   // the browser
	UserDataDir string   // its profile: a temporary directory
	Extensions  []string // unpacked extensions to load
	Env         []string // its whole environment (HOME, XDG_*, PATH, ...)
	Args        []string // more switches
	Stderr      io.Writer
}

// Browser is a running browser.
type Browser struct {
	cmd  *exec.Cmd
	in   *os.File // to the browser's fd 3
	out  *os.File // from its fd 4
	done chan struct{}

	mu      sync.Mutex
	seq     int64
	waiting map[int64]chan reply
	subs    []*sub
	err     error
}

type reply struct {
	Result json.RawMessage
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
}

// Event is something the browser said unasked.
type Event struct {
	Method    string
	SessionID string
	Params    json.RawMessage
}

type sub struct {
	match func(Event) bool
	ch    chan Event
}

// Launch starts the browser, headless.
func Launch(o Options) (*Browser, error) {
	if o.Binary == "" {
		return nil, errors.New("cdptest: no browser")
	}
	// Without these the browser would use the person's own profile, and
	// inherit the test's environment (their HOME, session bus, ...).
	if o.UserDataDir == "" || len(o.Env) == 0 {
		return nil, errors.New("cdptest: a profile directory and a whole environment are required")
	}
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	evR, evW, err := os.Pipe()
	if err != nil {
		cmdR.Close()
		cmdW.Close()
		return nil, err
	}
	args := []string{
		"--headless=new",
		"--remote-debugging-pipe",
		"--user-data-dir=" + o.UserDataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-default-apps",
		"--disable-sync",
		"--disable-features=MediaRouter,OptimizationHints,Translate",
		"--password-store=basic", // never the system keyring
		"--use-mock-keychain",
		"--metrics-recording-only",
		"--no-pings",
		"--enable-unsafe-extension-debugging",
	}
	if len(o.Extensions) > 0 {
		args = append(args, "--load-extension="+strings.Join(o.Extensions, ","),
			"--disable-extensions-except="+strings.Join(o.Extensions, ","))
	}
	args = append(args, o.Args...)
	args = append(args, "about:blank")
	cmd := exec.Command(o.Binary, args...)
	cmd.Env = o.Env
	cmd.Stdout = o.Stderr
	cmd.Stderr = o.Stderr
	cmd.ExtraFiles = []*os.File{cmdR, evW} // fds 3 and 4
	if err := cmd.Start(); err != nil {
		cmdR.Close()
		cmdW.Close()
		evR.Close()
		evW.Close()
		return nil, err
	}
	cmdR.Close()
	evW.Close()
	b := &Browser{cmd: cmd, in: cmdW, out: evR, done: make(chan struct{}), waiting: map[int64]chan reply{}}
	go b.read()
	go func() {
		cmd.Wait()
		b.fail(errors.New("cdptest: the browser exited"))
	}()
	return b, nil
}

func (b *Browser) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return
	}
	b.err = err
	for id, ch := range b.waiting {
		close(ch)
		delete(b.waiting, id)
	}
	close(b.done)
}

func (b *Browser) read() {
	r := bufio.NewReaderSize(b.out, 1<<20)
	for {
		msg, err := r.ReadBytes(0)
		if err != nil {
			b.fail(fmt.Errorf("cdptest: reading from the browser: %w", err))
			return
		}
		msg = msg[:len(msg)-1]
		var m struct {
			ID        int64           `json:"id"`
			Method    string          `json:"method"`
			SessionID string          `json:"sessionId"`
			Params    json.RawMessage `json:"params"`
			Result    json.RawMessage `json:"result"`
			Error     *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(msg, &m) != nil {
			continue
		}
		if m.Method != "" {
			ev := Event{Method: m.Method, SessionID: m.SessionID, Params: m.Params}
			b.mu.Lock()
			subs := append([]*sub(nil), b.subs...)
			b.mu.Unlock()
			for _, s := range subs {
				if s.match(ev) {
					select {
					case s.ch <- ev:
					default: // a listener that does not keep up misses it
					}
				}
			}
			continue
		}
		b.mu.Lock()
		ch := b.waiting[m.ID]
		delete(b.waiting, m.ID)
		b.mu.Unlock()
		if ch != nil {
			ch <- reply{Result: m.Result, Error: m.Error}
		}
	}
}

// Call sends a command (to a session, unless session is "") and waits for
// its answer, decoded into out when out is not nil.
func (b *Browser) Call(ctx context.Context, session, method string, params, out any) error {
	b.mu.Lock()
	if b.err != nil {
		b.mu.Unlock()
		return b.err
	}
	b.seq++
	id := b.seq
	ch := make(chan reply, 1)
	b.waiting[id] = ch
	b.mu.Unlock()
	m := map[string]any{"id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	if session != "" {
		m["sessionId"] = session
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b.mu.Lock()
	_, err = b.in.Write(append(data, 0))
	b.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return b.err
		}
		if r.Error != nil {
			return fmt.Errorf("%s: %s (%d)", method, r.Error.Message, r.Error.Code)
		}
		if out != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.waiting, id)
		b.mu.Unlock()
		return fmt.Errorf("%s: %w", method, ctx.Err())
	}
}

// Subscribe returns the events that match, from now on, until cancel.
func (b *Browser) Subscribe(match func(Event) bool) (<-chan Event, func()) {
	s := &sub{match: match, ch: make(chan Event, 256)}
	b.mu.Lock()
	b.subs = append(b.subs, s)
	b.mu.Unlock()
	return s.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, x := range b.subs {
			if x == s {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				return
			}
		}
	}
}

// Close ends the browser and waits for it to exit.
func (b *Browser) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = b.Call(ctx, "", "Browser.close", nil, nil)
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
		b.cmd.Process.Kill()
		<-b.done
	}
	b.in.Close()
	b.out.Close()
}

// Target is a page, a frame or a worker the browser has.
type Target struct {
	TargetID string `json:"targetId"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	Title    string `json:"title"`
}

// Targets are the browser's targets now.
func (b *Browser) Targets(ctx context.Context) ([]Target, error) {
	var r struct {
		TargetInfos []Target `json:"targetInfos"`
	}
	err := b.Call(ctx, "", "Target.getTargets", nil, &r)
	return r.TargetInfos, err
}

// WaitTarget waits for a target that match accepts.
func (b *Browser) WaitTarget(ctx context.Context, match func(Target) bool) (Target, error) {
	for {
		ts, err := b.Targets(ctx)
		if err != nil {
			return Target{}, err
		}
		for _, t := range ts {
			if match(t) {
				return t, nil
			}
		}
		select {
		case <-ctx.Done():
			return Target{}, fmt.Errorf("waiting for a target: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Attach opens a session on a target, flat.
func (b *Browser) Attach(ctx context.Context, targetID string) (string, error) {
	var r struct {
		SessionID string `json:"sessionId"`
	}
	err := b.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true}, &r)
	return r.SessionID, err
}

// NewPage opens a tab at url and returns its target and a session on it.
func (b *Browser) NewPage(ctx context.Context, url string) (string, string, error) {
	var r struct {
		TargetID string `json:"targetId"`
	}
	if err := b.Call(ctx, "", "Target.createTarget", map[string]any{"url": url}, &r); err != nil {
		return "", "", err
	}
	s, err := b.Attach(ctx, r.TargetID)
	return r.TargetID, s, err
}

// ExtensionWorld is the execution context of an extension's content
// script in a session's top frame: its isolated world, named for the
// extension.
func (b *Browser) ExtensionWorld(ctx context.Context, session, name string) (int, error) {
	events, cancel := b.Subscribe(func(e Event) bool {
		return e.SessionID == session && e.Method == "Runtime.executionContextCreated"
	})
	defer cancel()
	if err := b.Call(ctx, session, "Runtime.enable", nil, nil); err != nil {
		return 0, err
	}
	defer b.Call(ctx, session, "Runtime.disable", nil, nil)
	for {
		select {
		case e := <-events:
			var p struct {
				Context struct {
					ID      int    `json:"id"`
					Name    string `json:"name"`
					AuxData struct {
						Type string `json:"type"`
					} `json:"auxData"`
				} `json:"context"`
			}
			if json.Unmarshal(e.Params, &p) == nil && p.Context.AuxData.Type == "isolated" && p.Context.Name == name {
				return p.Context.ID, nil
			}
		case <-ctx.Done():
			return 0, fmt.Errorf("no isolated world %q: %w", name, ctx.Err())
		}
	}
}

// EvalIn is Eval in an execution context of the session's (0: the page's
// own).
func (b *Browser) EvalIn(ctx context.Context, session string, context int, expr string, out any) error {
	return b.eval(ctx, session, context, expr, out)
}

// Eval evaluates JavaScript in a session's page (awaiting a promise) and
// decodes its value into out, when out is not nil.
func (b *Browser) Eval(ctx context.Context, session, expr string, out any) error {
	return b.eval(ctx, session, 0, expr, out)
}

func (b *Browser) eval(ctx context.Context, session string, context int, expr string, out any) error {
	var r struct {
		Result struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	params := map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true}
	if context != 0 {
		params["contextId"] = context
	}
	err := b.Call(ctx, session, "Runtime.evaluate", params, &r)
	if err != nil {
		return err
	}
	if r.ExceptionDetails != nil {
		msg := r.ExceptionDetails.Text
		if r.ExceptionDetails.Exception != nil {
			msg = r.ExceptionDetails.Exception.Description
		}
		return fmt.Errorf("evaluating %q: %s", short(expr), msg)
	}
	if out != nil && len(r.Result.Value) > 0 {
		return json.Unmarshal(r.Result.Value, out)
	}
	return nil
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// Until evaluates expr every 100 ms until it is true, or ctx ends.
func (b *Browser) Until(ctx context.Context, session, expr string) error {
	var last error
	for {
		var ok bool
		last = b.Eval(ctx, session, expr, &ok)
		if last == nil && ok {
			return nil
		}
		select {
		case <-ctx.Done():
			if last != nil {
				return fmt.Errorf("waiting for %q: %w (last: %v)", short(expr), ctx.Err(), last)
			}
			return fmt.Errorf("waiting for %q: %w", short(expr), ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Click clicks at a point of a session's page, as a person's mouse does:
// the browser makes the events, which the page sees as trusted.
func (b *Browser) Click(ctx context.Context, session string, x, y float64) error {
	for _, typ := range []string{"mouseMoved", "mousePressed", "mouseReleased"} {
		p := map[string]any{"type": typ, "x": x, "y": y}
		if typ != "mouseMoved" {
			p["button"], p["clickCount"] = "left", 1
		}
		if err := b.Call(ctx, session, "Input.dispatchMouseEvent", p, nil); err != nil {
			return err
		}
	}
	return nil
}

// Type types text into whatever has the focus, as a keyboard would.
func (b *Browser) Type(ctx context.Context, session, text string) error {
	return b.Call(ctx, session, "Input.insertText", map[string]any{"text": text}, nil)
}

// Point is where something is on a page, in CSS pixels.
type Point struct{ X, Y float64 }

// Center is the middle of the element expr evaluates to.
func (b *Browser) Center(ctx context.Context, session, expr string) (Point, error) {
	var p Point
	err := b.Eval(ctx, session, "(() => { const r = ("+expr+").getBoundingClientRect(); return {X: r.left + r.width / 2, Y: r.top + r.height / 2}; })()", &p)
	return p, err
}

// Log is a browser's stderr, kept to show when a test fails.
type Log struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *Log) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
