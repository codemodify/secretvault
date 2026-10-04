package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/internal/cdptest"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// secretvault's extension in a real browser: a headless Chromium, in a
// profile of its own under the test's temporary directory, with the
// extension as `secretvault browser extension --target chromium --dir`
// writes it, and the native-messaging host's manifest as
// `secretvault browser install` writes it, in that profile. The host the
// browser starts is this test binary (TestMain), speaking to a daemon in
// this process, whose consent prompts the test answers. Pages are served
// by httptest. The test drives the browser over the DevTools protocol on
// a pipe (internal/cdptest), clicking as a mouse would.
//
// Nothing reaches the person's own browsers, profiles, native-messaging
// folders, vaults or daemon: HOME, the XDG folders and the profile are
// temporary, and the browser is kept off the session bus and the system
// keyring. It runs when chromium is installed (or
// SECRETVAULT_TEST_CHROMIUM names a browser), and not with -short.

// e2eHostEnv names the daemon's socket for the test binary started as the
// browser's host.
const e2eHostEnv = "SECRETVAULT_TEST_BROWSER_HOST"

// e2eHost is the native-messaging host, as the browser started it.
func e2eHost(sock string) int {
	c := &cli{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		connect: func(o secretvault.Options) (*secretvault.Client, error) {
			o.Socket, o.NoStart = sock, true
			return secretvault.Connect(o)
		}}
	code := c.run(append([]string{"browser-host"}, os.Args[1:]...))
	if c.client != nil {
		c.client.Close()
	}
	return code
}

// chromium is a headless browser with the extension, for one test.
type chromium struct {
	t   *testing.T
	b   *cdptest.Browser
	log *cdptest.Log
	ctx context.Context
}

// startChromium starts a browser whose host speaks to h's daemon.
func startChromium(t *testing.T, h *harness) *chromium {
	t.Helper()
	bin := cdptest.Find()
	if bin == "" {
		t.Skip("no chromium here (SECRETVAULT_TEST_CHROMIUM may name one): the extension was not tried in a browser")
	}
	if testing.Short() {
		t.Skip("-short: the extension was not tried in a browser")
	}
	if runtime.GOOS != "linux" {
		// Elsewhere, browser install writes where no temporary home
		// reaches (Windows' registry), and the pipe needs fds 3 and 4.
		t.Skip("the extension is tried in a browser on Linux only")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ext := filepath.Join(dir, "extension")
	if err := svops.WriteExtensionDir(ext, svops.TargetChromium); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	run := filepath.Join(dir, "run")
	for _, d := range []string{home, run} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// This test's own home, for the browser and for the install below.
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("SECRETVAULT_HOME", filepath.Join(home, "secretvault"))

	// The host's manifest, as `secretvault browser install --browser NAME`
	// writes it, naming this test binary, in that home: the browser's own
	// folder, which is also its profile's (the profile is the browser's
	// default one, in that home).
	name := "chromium"
	switch base := strings.ToLower(filepath.Base(bin)); {
	case strings.Contains(base, "brave"):
		name = "brave"
	case strings.Contains(base, "chrome"):
		name = "chrome"
	case strings.Contains(base, "edge"):
		name = "edge"
	case strings.Contains(base, "vivaldi"):
		name = "vivaldi"
	}
	plan, err := svops.PlanBrowserInstall(svops.ExtensionHost, []string{name}, exe)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Hosts) != 1 || plan.Hosts[0].Skip != "" || !strings.HasPrefix(plan.Hosts[0].Spot.Manifest, home) {
		t.Fatalf("the install would do %+v", plan.Hosts)
	}
	if _, err := plan.Apply(plan.Hosts[0]); err != nil {
		t.Fatal(err)
	}
	spot := plan.Hosts[0].Spot
	manifest, err := os.ReadFile(spot.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var nm svops.NativeManifest
	if err := json.Unmarshal(manifest, &nm); err != nil || len(nm.AllowedOrigins) != 1 || nm.AllowedOrigins[0] != svext.ChromeOrigin || len(nm.AllowedExtensions) != 0 || nm.Path != exe {
		t.Fatalf("the host's manifest for Chromium (%v):\n%s", err, manifest)
	}
	profile := filepath.Dir(filepath.Dir(spot.Manifest))
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local", "share"),
		"XDG_RUNTIME_DIR=" + run,
		"SECRETVAULT_HOME=" + filepath.Join(home, "secretvault"),
		"DBUS_SESSION_BUS_ADDRESS=disabled:",
		"TMPDIR=" + dir,
		e2eHostEnv + "=" + h.sock,
	}
	log := &cdptest.Log{}
	b, err := cdptest.Launch(cdptest.Options{Binary: bin, UserDataDir: profile, Extensions: []string{ext}, Env: env, Stderr: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	c := &chromium{t: t, b: b, log: log, ctx: ctx}
	t.Cleanup(func() {
		cancel()
		b.Close()
		if t.Failed() {
			t.Logf("the browser said:\n%s", log.String())
		}
	})
	if _, err := b.WaitTarget(ctx, func(x cdptest.Target) bool {
		return x.Type == "service_worker" && strings.HasPrefix(x.URL, svext.ChromeOrigin)
	}); err != nil {
		t.Fatalf("the extension did not start: %v", err)
	}
	return c
}

func (c *chromium) fatal(format string, args ...any) {
	c.t.Helper()
	c.t.Fatalf(format, args...)
}

// open opens url in a new tab and returns a session on it.
func (c *chromium) open(url string) string {
	c.t.Helper()
	_, s, err := c.b.NewPage(c.ctx, url)
	if err != nil {
		c.fatal("opening %s: %v", url, err)
	}
	if err := c.b.Call(c.ctx, s, "Page.enable", nil, nil); err != nil {
		c.fatal("%v", err)
	}
	// Not the about:blank a new tab starts with: the page asked for.
	c.until(s, fmt.Sprintf(`location.href === %q && document.readyState === "complete"`, url))
	return s
}

func (c *chromium) eval(s, expr string, out any) {
	c.t.Helper()
	if err := c.b.Eval(c.ctx, s, expr, out); err != nil {
		c.fatal("%v", err)
	}
}

func (c *chromium) until(s, expr string) {
	c.t.Helper()
	if err := c.b.Until(c.ctx, s, expr); err != nil {
		c.fatal("%v", err)
	}
}

// untilSaid is until, saying what said evaluates to when it fails.
func (c *chromium) untilSaid(s, expr, said string) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
	defer cancel()
	if err := c.b.Until(ctx, s, expr); err != nil {
		var what any
		c.b.Eval(c.ctx, s, said, &what)
		c.fatal("%v; it says: %v", err, what)
	}
}

func (c *chromium) click(s string, p cdptest.Point) {
	c.t.Helper()
	if err := c.b.Click(c.ctx, s, p.X, p.Y); err != nil {
		c.fatal("clicking: %v", err)
	}
}

// frame waits for a frame or page of the browser's whose URL match
// accepts, and returns a session on it.
func (c *chromium) frame(what string, match func(url string) bool) string {
	c.t.Helper()
	x, err := c.b.WaitTarget(c.ctx, func(x cdptest.Target) bool { return (x.Type == "iframe" || x.Type == "page") && match(x.URL) })
	if err != nil {
		c.fatal("%s: %v", what, err)
	}
	s, err := c.b.Attach(c.ctx, x.TargetID)
	if err != nil {
		c.fatal("%s: %v", what, err)
	}
	return s
}

// frameAgain waits for another frame at the URL of the frame of session
// first, and returns a session on it.
func (c *chromium) frameAgain(first string) string {
	c.t.Helper()
	var info struct {
		TargetInfo cdptest.Target `json:"targetInfo"`
	}
	if err := c.b.Call(c.ctx, first, "Target.getTargetInfo", nil, &info); err != nil {
		c.fatal("%v", err)
	}
	url := info.TargetInfo.URL
	for {
		ts, err := c.b.Targets(c.ctx)
		if err != nil {
			c.fatal("%v", err)
		}
		for _, x := range ts {
			if x.Type == "iframe" && x.URL == url && x.TargetID != info.TargetInfo.TargetID {
				s, err := c.b.Attach(c.ctx, x.TargetID)
				if err != nil {
					c.fatal("%v", err)
				}
				return s
			}
		}
		select {
		case <-c.ctx.Done():
			c.fatal("no second frame at %s", url)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// stopWorkers stops the extension's service worker, as Chromium does when
// it has been idle, and waits until it is gone.
func (c *chromium) stopWorkers(s string) {
	c.t.Helper()
	if err := c.b.Call(c.ctx, s, "ServiceWorker.enable", nil, nil); err != nil {
		c.fatal("%v", err)
	}
	if err := c.b.Call(c.ctx, s, "ServiceWorker.stopAllWorkers", nil, nil); err != nil {
		c.fatal("%v", err)
	}
	for {
		ts, err := c.b.Targets(c.ctx)
		if err != nil {
			c.fatal("%v", err)
		}
		running := false
		for _, x := range ts {
			running = running || x.Type == "service_worker" && strings.HasPrefix(x.URL, svext.ChromeOrigin)
		}
		if !running {
			return
		}
		select {
		case <-c.ctx.Done():
			c.fatal("the service worker did not stop")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ourHosts is how a page script finds the extension's elements: children
// of <html> it cannot look into (their shadow roots are closed).
const ourHosts = `[...document.documentElement.children].filter((e) => e.tagName === "SPAN" && e.hasAttribute("popover"))`

// markFor is where the extension's mark for the field sel is.
func (c *chromium) markFor(s, sel string) cdptest.Point {
	c.t.Helper()
	expr := fmt.Sprintf(`(() => {
		const f = document.querySelector(%q).getBoundingClientRect();
		const m = %s.filter((e) => e.style.width === "20px" && e.matches(":popover-open")).map((e) => e.getBoundingClientRect())
			.find((r) => r.top >= f.top - 1 && r.bottom <= f.bottom + 1 && r.left >= f.left && r.right <= f.right + 1);
		return m ? {X: m.left + m.width / 2, Y: m.top + m.height / 2} : null;
	})()`, sel, ourHosts)
	var p *cdptest.Point
	for {
		c.eval(s, expr, &p)
		if p != nil {
			return *p
		}
		select {
		case <-c.ctx.Done():
			c.fatal("no mark by %s", sel)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

const loginPage = `<!doctype html><title>Sign in</title>
<style>body { font: 16px sans-serif; margin: 40px } input { display: block; width: 260px; height: 28px; margin: 6px 0 16px }</style>
<form id="f" action="/done" method="post">
<label for="u">Email</label><input id="u" name="username" autocomplete="username">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<button>Sign in</button>
</form>
%s`

func TestTheExtensionFillsInChromium(t *testing.T) {
	h := newHarness(t)
	h.init()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginPage, "")
	}))
	defer other.Close()
	// The other server, by another name: another origin, and another site.
	framed := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginPage, `<iframe id="x" src="`+framed+`/" width="420" height="260"></iframe>`)
	}))
	defer site.Close()
	h.ok("s3cret", h.with("set", "web/site", "--kind", "login", "--field", "username=ada@example.org", "--field", "url="+site.URL)...)
	h.ok("framed", h.with("set", "web/framed", "--kind", "login", "--field", "username=eve", "--field", "url="+framed)...)
	// The consent stand-in: every question secretvault asks is answered
	// "allow, this once".
	h.desk.answer(svrpc.ChoiceOnce, "")

	c := startChromium(t, h)
	s := c.open(site.URL + "/")

	// The marks come, on the page's own fields.
	mark := c.markFor(s, "#p")
	c.markFor(s, "#u")
	// A mark takes a click only once it has stood still a moment.
	time.Sleep(700 * time.Millisecond)
	c.click(s, mark)

	// The panel, an extension page in the page, lists the login.
	panel := c.frame("the panel", func(u string) bool {
		return strings.HasPrefix(u, svext.ChromeOrigin+"panel.html#")
	})
	c.untilSaid(panel, `document.querySelectorAll("#logins button.login").length === 1`, `document.body.innerText`)
	var title string
	c.eval(panel, `document.querySelector("#logins button.login .title").textContent`, &title)
	if title != "web/site" && title != site.URL {
		t.Errorf("the panel lists %q", title)
	}
	// Where the panel's login button is, in the page.
	var at cdptest.Point
	c.eval(s, ourHosts+`.filter((e) => e.style.width === "320px").map((e) => { const r = e.getBoundingClientRect(); return {X: r.left, Y: r.top}; })[0]`, &at)
	in, err := c.b.Center(c.ctx, panel, `document.querySelector("#logins button.login")`)
	if err != nil {
		t.Fatal(err)
	}
	// Chromium stops an idle extension's service worker: what the panel
	// relies on (its token, what it was shown) outlives it.
	c.stopWorkers(s)
	// And the token stays bound to the panel's own frame: another frame
	// of the tab with it, which only the content script could make, is
	// refused.
	var token string
	c.eval(panel, `location.hash.slice(1)`, &token)
	world, err := c.b.ExtensionWorld(c.ctx, s, "secretvault")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.b.EvalIn(c.ctx, s, world, fmt.Sprintf(`(() => { const f = document.createElement("iframe"); f.id = "again";
		f.src = chrome.runtime.getURL("panel.html") + "#" + %q; document.body.append(f); return 1; })()`, token), nil); err != nil {
		t.Fatal(err)
	}
	again := c.frameAgain(panel)
	c.untilSaid(again, `/said no/.test(document.body.innerText) && document.querySelectorAll("#logins button.login").length === 0`, `document.body.innerText`)
	c.eval(s, `document.getElementById("again").remove()`, nil)
	time.Sleep(700 * time.Millisecond) // the panel takes no click for a moment after it shows
	c.click(s, cdptest.Point{X: at.X + in.X, Y: at.Y + in.Y})

	// Filled, once the consent stand-in said yes.
	c.until(s, `document.querySelector("#p").value === "s3cret" && document.querySelector("#u").value === "ada@example.org"`)
	asked := strings.Join(h.desk.questions(), "\n")
	if !strings.Contains(asked, `wants the login "web/site" for `+site.URL) {
		t.Errorf("secretvault was asked:\n%s", asked)
	}

	// The frame of another origin got no marks, and nothing was filled
	// there.
	inner := c.frame("the other origin's frame", func(u string) bool { return strings.HasPrefix(u, framed) })
	c.until(inner, `document.readyState === "complete"`)
	time.Sleep(time.Second)
	var marks int
	var value string
	c.eval(inner, ourHosts+`.length`, &marks)
	c.eval(inner, `document.querySelector("#p").value`, &value)
	if marks != 0 || value != "" {
		t.Errorf("the cross-origin frame has %d marks, and its password field %q", marks, value)
	}
	if strings.Contains(asked, "web/framed") {
		t.Errorf("secretvault was asked about the framed origin's login:\n%s", asked)
	}
}
