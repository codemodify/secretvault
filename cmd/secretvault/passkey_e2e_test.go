package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/cdptest"
	"github.com/codemodify/secretvault/internal/webauthntest"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svrpc"
)

// Passkeys in a real browser (see browser_e2e_test.go for how it runs): a
// relying party made with the standard library (internal/webauthntest)
// registers a passkey and signs in with it, through secretvault's window,
// and checks both as a server does. Then the person chooses "another
// device", and the browser's own authenticator (here, the DevTools
// protocol's virtual one) makes the credential instead. And a frame of
// another origin that the page's permissions policy does not let use
// WebAuthn is left to the browser.

// window waits for a passkey window the test has not seen, and returns a
// session on it.
func (c *chromium) window(seen map[string]bool) string {
	c.t.Helper()
	x, err := c.b.WaitTarget(c.ctx, func(x cdptest.Target) bool {
		return x.Type == "page" && strings.HasPrefix(x.URL, svext.ChromeOrigin+"passkey.html#") && !seen[x.TargetID]
	})
	if err != nil {
		c.fatal("no passkey window: %v", err)
	}
	seen[x.TargetID] = true
	s, err := c.b.Attach(c.ctx, x.TargetID)
	if err != nil {
		c.fatal("%v", err)
	}
	return s
}

func (c *chromium) center(s, sel string) cdptest.Point {
	c.t.Helper()
	p, err := c.b.Center(c.ctx, s, fmt.Sprintf("document.querySelector(%q)", sel))
	if err != nil {
		c.fatal("%v", err)
	}
	return p
}

// press clicks the button sel of a passkey window, once it may be clicked.
func (c *chromium) press(win, sel string) {
	c.t.Helper()
	c.untilSaid(win, fmt.Sprintf(`(() => { const b = document.querySelector(%q); return !!b && b.offsetParent !== null; })()`, sel), `document.body.innerText`)
	time.Sleep(800 * time.Millisecond) // the window takes no click for a moment after it shows
	c.click(win, c.center(win, sel))
}

const result = `document.body.dataset.result || ""`

func TestPasskeysInChromium(t *testing.T) {
	h := newHarness(t)
	h.init()
	rp := &webauthntest.Handler{RP: &webauthntest.RP{ID: "localhost"}}
	srv := httptest.NewServer(rp)
	defer srv.Close()
	origin := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) // http on localhost: a secure context
	rp.RP.Origin = origin
	h.desk.answer(svrpc.ChoiceOnce, "")

	c := startChromium(t, h)
	s := c.open(origin + "/")
	seen := map[string]bool{}
	ours := hex.EncodeToString(svext.AAGUID[:])

	// Register: the person presses the page's button; secretvault's window
	// asks; the person saves; the consent stand-in allows; the RP checks.
	c.click(s, c.center(s, "#register"))
	win := c.window(seen)
	c.untilSaid(win, `document.getElementById("title").textContent === "Save a passkey for localhost?"`, `document.body.innerText`)
	c.press(win, "#save-button")
	c.untilSaid(s, `(`+result+`).startsWith("registered")`, result)
	var got string
	c.eval(s, result, &got)
	if !strings.Contains(got, "alg -7 aaguid "+ours) {
		t.Errorf("the RP registered: %s", got)
	}
	asked := strings.Join(h.desk.questions(), "\n")
	if !strings.Contains(asked, `wants to save a new passkey "localhost" for localhost (account "ada@example.com"), for `+origin) {
		t.Errorf("secretvault was asked:\n%s", asked)
	}

	// Sign in with it, the same way.
	c.click(s, c.center(s, "#signin"))
	win = c.window(seen)
	c.untilSaid(win, `document.querySelectorAll("#passkeys button.login").length === 1`, `document.body.innerText`)
	c.press(win, "#passkeys button.login")
	c.untilSaid(s, `(`+result+`).startsWith("signed in")`, result)
	c.eval(s, result, &got)
	if !strings.HasSuffix(got, " as user-ada") {
		t.Errorf("the RP said: %s", got)
	}
	asked = strings.Join(h.desk.questions(), "\n")
	if !strings.Contains(asked, `wants to sign in to localhost as "ada@example.com" with the passkey "localhost"`) {
		t.Errorf("secretvault was asked:\n%s", asked)
	}

	// Autofill (conditional mediation): the page waits for a passkey as it
	// loads; nothing shows, and secretvault is not asked, until the person
	// opens the panel from the user name field's mark.
	asking := h.desk.count()
	cs := c.open(origin + "/conditional")
	mark := c.markFor(cs, "#u")
	time.Sleep(700 * time.Millisecond)
	if h.desk.count() != asking {
		t.Errorf("secretvault was asked before the person did anything: %q", h.desk.questions()[asking:])
	}
	c.click(cs, mark)
	panel := c.frame("the panel", func(u string) bool { return strings.HasPrefix(u, svext.ChromeOrigin+"panel.html#") })
	c.untilSaid(panel, `document.querySelectorAll("#pk-list button.login").length === 1`, `document.body.innerText`)
	var pat cdptest.Point
	c.eval(cs, ourHosts+`.filter((e) => e.style.width === "320px").map((e) => { const r = e.getBoundingClientRect(); return {X: r.left, Y: r.top}; })[0]`, &pat)
	pin, err := c.b.Center(c.ctx, panel, `document.querySelector("#pk-list button.login")`)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	c.click(cs, cdptest.Point{X: pat.X + pin.X, Y: pat.Y + pin.Y})
	c.untilSaid(cs, `(`+result+`).startsWith("signed in")`, result)

	// Another device: the browser's own authenticator (a virtual one), in
	// the first tab, brought to the front again.
	if err := c.b.Call(c.ctx, s, "Page.bringToFront", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.b.Call(c.ctx, s, "WebAuthn.enable", map[string]any{"enableUI": false}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.b.Call(c.ctx, s, "WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "usb", "hasResidentKey": true, "hasUserVerification": true, "isUserVerified": true,
		"automaticPresenceSimulation": true}}, nil); err != nil {
		t.Fatal(err)
	}
	c.click(s, c.center(s, "#register"))
	win = c.window(seen)
	c.press(win, "#other")
	c.untilSaid(s, `(`+result+`).startsWith("registered") && !(`+result+`).includes("`+ours+`")`, result)

	// A frame of another origin, which the page does not let use WebAuthn:
	// secretvault stays out of it, and the browser refuses it.
	framer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><iframe id="f" src="%s/" width="600" height="400"></iframe>`, origin)
	}))
	defer framer.Close()
	top := c.open(framer.URL + "/") // another site: the frame is a target of its own
	x, err := c.b.WaitTarget(c.ctx, func(x cdptest.Target) bool { return x.Type == "iframe" && x.URL == origin+"/" })
	if err != nil {
		t.Fatal(err)
	}
	frame, err := c.b.Attach(c.ctx, x.TargetID)
	if err != nil {
		t.Fatal(err)
	}
	c.until(frame, `document.readyState === "complete"`)
	var at cdptest.Point
	c.eval(top, `(() => { const r = document.getElementById("f").getBoundingClientRect(); return {X: r.left, Y: r.top}; })()`, &at)
	in := c.center(frame, "#signin")
	c.click(top, cdptest.Point{X: at.X + in.X, Y: at.Y + in.Y})
	c.untilSaid(frame, `(`+result+`) !== ""`, result)
	c.eval(frame, result, &got)
	if !strings.HasPrefix(got, "error: NotAllowedError") {
		t.Errorf("in a frame WebAuthn is not allowed in, the page got: %s", got)
	}
	ts, _ := c.b.Targets(c.ctx)
	for _, x := range ts {
		if strings.HasPrefix(x.URL, svext.ChromeOrigin+"passkey.html#") && !seen[x.TargetID] {
			t.Error("secretvault's window came up for a frame not allowed WebAuthn")
		}
	}
	// A sandboxed document at the RP's own URL has an opaque origin:
	// secretvault stays out of it, whatever the URL says.
	sb := c.open(origin + "/sandboxed")
	c.click(sb, c.center(sb, "#signin"))
	c.untilSaid(sb, `(`+result+`) !== ""`, result)
	c.eval(sb, result, &got)
	if !strings.HasPrefix(got, "error: ") {
		t.Errorf("a sandboxed document got: %s", got)
	}
	ts, _ = c.b.Targets(c.ctx)
	for _, x := range ts {
		if strings.HasPrefix(x.URL, svext.ChromeOrigin+"passkey.html#") && !seen[x.TargetID] {
			t.Error("secretvault's window came up for a sandboxed document")
		}
	}

	if n := len(rp.Results()); n != 4 {
		t.Errorf("the RP saw %d results: %q", n, rp.Results())
	}
}
