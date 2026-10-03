package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// secretvault's own extension end to end: the test plays the extension
// (its background script's requests, as lib/protocol.js builds them)
// through the host's stdin and stdout, to a real daemon in this process,
// which is told the host's parent is Firefox. Nothing reaches a real
// browser or profile.

// ownExtension is the secretvault extension, talking to a running host.
type ownExtension struct {
	t       *testing.T
	in      *io.PipeWriter
	replies chan map[string]any
	events  chan map[string]any
	exited  chan int
	stderr  *lockedBuffer
	seq     int
}

const extManifest = "/home/u/.mozilla/native-messaging-hosts/" + svext.HostName + ".json"

// startOwnExtension runs the host as Firefox would for the extension
// named id.
func startOwnExtension(t *testing.T, h *harness, args ...string) *ownExtension {
	t.Helper()
	if len(args) == 0 {
		args = []string{extManifest, svext.FirefoxID}
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	x := &ownExtension{t: t, in: inW, replies: make(chan map[string]any, 64), events: make(chan map[string]any, 16),
		exited: make(chan int, 1), stderr: &lockedBuffer{}}
	c := &cli{
		stdin: inR, stdout: outW, stderr: x.stderr,
		connect: func(o secretvault.Options) (*secretvault.Client, error) {
			o.Socket, o.NoStart = h.sock, true
			return secretvault.Connect(o)
		},
	}
	go func() {
		code := c.run(append([]string{"browser-host"}, args...))
		if c.client != nil {
			c.client.Close()
		}
		outW.Close()
		inR.Close()
		x.exited <- code
	}()
	go func() {
		defer close(x.replies)
		for {
			f, err := svbrowser.ReadFrame(outR)
			if err != nil {
				return
			}
			var m map[string]any
			if err := json.Unmarshal(f, &m); err != nil {
				t.Errorf("the host wrote %q", f)
				continue
			}
			if m["v"] != float64(1) {
				t.Errorf("a message without the protocol's version: %v", m)
			}
			if m["event"] != nil {
				x.events <- m
				continue
			}
			x.replies <- m
		}
	}()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-x.exited:
		case <-time.After(10 * time.Second):
			t.Error("the host did not stop when the browser went away")
		}
		outR.Close()
	})
	return x
}

func (x *ownExtension) frame(b []byte) {
	x.t.Helper()
	var head [4]byte
	binary.NativeEndian.PutUint32(head[:], uint32(len(b)))
	if _, err := x.in.Write(append(head[:], b...)); err != nil {
		x.t.Fatalf("writing to the host: %v", err)
	}
}

func (x *ownExtension) reply() map[string]any {
	x.t.Helper()
	select {
	case r, ok := <-x.replies:
		if !ok {
			x.t.Fatalf("the host stopped; it said: %s", x.stderr.String())
		}
		return r
	case <-time.After(10 * time.Second):
		x.t.Fatalf("no answer; the host said: %s", x.stderr.String())
	}
	return nil
}

func (x *ownExtension) event() map[string]any {
	x.t.Helper()
	select {
	case e := <-x.events:
		return e
	case <-time.After(10 * time.Second):
		x.t.Fatal("no event came")
	}
	return nil
}

// ask sends a request and returns its answer.
func (x *ownExtension) ask(op string, params map[string]any) map[string]any {
	x.t.Helper()
	x.seq++
	id := fmt.Sprintf("r%d", x.seq)
	m := map[string]any{"v": 1, "id": id, "op": op}
	for k, v := range params {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	x.frame(b)
	r := x.reply()
	if r["id"] != id {
		x.t.Fatalf("%s: the answer is to %v: %v", op, r["id"], r)
	}
	return r
}

func refused(r map[string]any) string {
	if r["ok"] == true {
		return ""
	}
	s, _ := r["error"].(string)
	return s
}

func loginsOf(r map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := r["logins"].([]any)
	for _, l := range list {
		out = append(out, l.(map[string]any))
	}
	return out
}

func TestTheExtensionIsAskedAboutTheLoginsOfAPage(t *testing.T) {
	h, _ := browserHarness(t)
	h.ok("hunter2", h.with("set", "web/github.com", "--kind", "login", "--field", "username=ada", "--field", "url=https://github.com")...)
	h.ok("g1st", h.with("set", "web/gist", "--kind", "login", "--field", "username=gisty", "--field", "url=https://gist.github.com")...)
	h.ok("plain", h.with("set", "web/plain", "--kind", "login", "--field", "url=http://github.com")...)
	h.ok("evil", h.with("set", "web/evil", "--kind", "login", "--field", "url=https://evilgithub.com")...)
	h.ok("alice", h.with("set", "web/alice", "--kind", "login", "--field", "url=https://alice.github.io")...)
	h.ok("uk", h.with("set", "web/uk", "--kind", "login", "--field", "url=https://co.uk")...)
	h.ok("shop", h.with("set", "web/shop", "--kind", "login", "--field", "url=https://login.shop.co.uk")...)
	h.ok("note", h.with("set", "notes/github", "--kind", "note", "--field", "url=https://github.com")...)

	x := startOwnExtension(t, h)
	if r := x.ask("hello", map[string]any{"extension": "0.1.0"}); r["protocol"] != float64(1) || r["browser"] != "firefox (/usr/lib/firefox/firefox)" {
		t.Fatalf("hello: %v", r)
	}
	r := x.ask("state", nil)
	vaults, _ := r["vaults"].([]any)
	if len(vaults) != 1 || vaults[0].(map[string]any)["name"] != "default" || vaults[0].(map[string]any)["locked"] != false {
		t.Fatalf("state: %v", r)
	}

	// Listing a page's logins is listing the vault: asked once, here
	// remembered. Names and user names come back, never a password.
	asked := h.desk.count()
	h.desk.answer(svrpc.ChoiceAlways, "")
	r = x.ask("logins", map[string]any{"origin": "https://github.com"})
	ls := loginsOf(r)
	if len(ls) != 3 || ls[0]["title"] != "web/github.com" || ls[0]["username"] != "ada" || ls[0]["match"] != "host" ||
		ls[1]["title"] != "web/plain" || ls[1]["match"] != "host" || ls[2]["title"] != "web/gist" || ls[2]["match"] != "site" {
		t.Fatalf("the logins of github.com: %v", r)
	}
	if b, _ := json.Marshal(r); bytes.Contains(b, []byte("hunter2")) || bytes.Contains(b, []byte("password")) {
		t.Fatalf("logins handed out a password: %s", b)
	}
	if n := h.desk.count() - asked; n != 1 {
		t.Fatalf("%d prompts to list", n)
	}
	if q := h.desk.questions()[asked]; !strings.Contains(q, "firefox (/usr/lib/firefox/firefox) wants to see which logins in vault \"default\" are for https://github.com") {
		t.Fatalf("the list prompt: %q", q)
	}
	ids := map[string]string{}
	for _, l := range ls {
		ids[l["title"].(string)] = l["id"].(string)
	}

	// The scheme, the port, and the Public Suffix List.
	for origin, want := range map[string][]string{
		"http://github.com":           {"web/plain"},
		"https://github.com:8443":     nil,
		"https://evilgithub.com":      {"web/evil"},
		"https://github.com.evil.io":  nil,
		"https://bob.github.io":       nil,
		"https://www.alice.github.io": {"web/alice"},
		"https://example.co.uk":       nil,
		"https://www.shop.co.uk":      {"web/shop"},
	} {
		got := []string{}
		for _, l := range loginsOf(x.ask("logins", map[string]any{"origin": origin})) {
			got = append(got, l["title"].(string))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("the logins of %s: %v, want %v", origin, got, want)
		}
	}

	// Filling is a read of that login, asked about like any program's.
	asked = h.desk.count()
	h.desk.answer(svrpc.ChoiceOnce, "")
	r = x.ask("fill", map[string]any{"origin": "https://github.com", "login": ids["web/github.com"]})
	if r["username"] != "ada" || r["password"] != "hunter2" || h.desk.count() != asked+1 {
		t.Fatalf("fill: %v", r)
	}
	if q := h.desk.questions()[asked]; !strings.Contains(q, `firefox (/usr/lib/firefox/firefox) wants the login "web/github.com" for https://github.com, through the secretvault extension.`) || !strings.Contains(q, "Process: 31337") {
		t.Fatalf("the fill prompt: %q", q)
	}
	h.desk.answer(svrpc.ChoiceDeny, "")
	if r := x.ask("fill", map[string]any{"origin": "https://github.com", "login": ids["web/github.com"]}); refused(r) != svext.CodeDenied || r["password"] != nil {
		t.Fatalf("a refused fill: %v", r)
	}
	// A login is filled only into a page it fits: not asked, not found.
	asked = h.desk.count()
	for _, c := range []struct{ origin, login string }{
		{"https://evilgithub.com", ids["web/github.com"]},
		{"http://github.com", ids["web/github.com"]},
		{"https://bob.github.io", ids["web/gist"]},
		{"https://github.com", strings.Repeat("0", 32)},
	} {
		if r := x.ask("fill", map[string]any{"origin": c.origin, "login": c.login}); refused(r) != svext.CodeNotFound {
			t.Errorf("fill %s on %s: %v", c.login, c.origin, r)
		}
	}
	if h.desk.count() != asked {
		t.Fatal("a fill into a page the login does not fit was asked about")
	}

	// Remembered for its own host, a login is not asked about there again;
	// on another host of its site, it is asked about every time.
	gh := map[string]any{"origin": "https://github.com", "login": ids["web/github.com"]}
	h.desk.answer(svrpc.ChoiceAlways, "")
	x.ask("fill", gh)
	asked = h.desk.count()
	if r := x.ask("fill", gh); r["password"] != "hunter2" || h.desk.count() != asked {
		t.Fatalf("a remembered fill: %v (%d prompts)", r, h.desk.count()-asked)
	}
	// Chosen in a panel inside the page, which the extension cannot vouch
	// for, it is asked about every time, remembered or not.
	h.desk.answer(svrpc.ChoiceOnce, "")
	if r := x.ask("fill", map[string]any{"origin": "https://github.com", "login": ids["web/github.com"], "confirm": true}); r["password"] != "hunter2" ||
		h.desk.count() != asked+1 || !strings.Contains(h.desk.questions()[asked], "It was chosen in a panel inside the page, so this is asked every time") {
		t.Fatalf("a fill to confirm: %v (%d prompts) %q", r, h.desk.count()-asked, h.desk.questions()[asked:])
	}
	asked = h.desk.count()
	sibling := map[string]any{"origin": "https://gist.github.com", "login": ids["web/github.com"]}
	for range 2 {
		if r := x.ask("fill", sibling); r["password"] != "hunter2" {
			t.Fatalf("a fill on another host of the site: %v", r)
		}
	}
	if n := h.desk.count() - asked; n != 2 || !strings.Contains(h.desk.questions()[asked], "saved for another host of this site, so this is asked every time") {
		t.Fatalf("%d prompts on another host of the site: %q", n, h.desk.questions()[asked:])
	}
	// Nor can another host of the site change it.
	if r := x.ask("check", map[string]any{"origin": "https://gist.github.com", "username": "ada", "password": "0ther"}); r["status"] != svext.StatusNew {
		t.Fatalf("check on another host of the site: %v", r)
	}
	if r := x.ask("check", map[string]any{"origin": "https://github.com", "username": "ada", "password": "0ther"}); r["status"] != svext.StatusChanged || r["login"] != ids["web/github.com"] {
		t.Fatalf("check on its own host: %v", r)
	}
	if r := x.ask("save", map[string]any{"origin": "https://gist.github.com", "username": "ada", "password": "0ther", "login": ids["web/github.com"]}); refused(r) != svext.CodeNotFound {
		t.Fatalf("an update from another host of the site: %v", r)
	}
	if got := h.ok("", h.with("get", "web/github.com")...); got != "hunter2\n" {
		t.Fatalf("the password became %q", got)
	}
	// A remembered no holds there too: nobody is asked.
	h.ok("", h.with("grant", "deny", "/usr/lib/firefox/firefox", "--item", "web/github.com", "--ops", "read")...)
	asked = h.desk.count()
	if r := x.ask("fill", sibling); refused(r) != svext.CodeDenied || h.desk.count() != asked {
		t.Fatalf("a fill denied ahead of time, on another host of the site: %v (%d prompts)", r, h.desk.count()-asked)
	}

	audit := h.ok("", h.with("audit", "--limit", "0")...)
	for _, want := range []string{`allowed\s+read web/github.com\s+firefox \(/usr/lib/firefox/firefox\)`, `denied\s+read web/github.com\s+firefox`, `allowed\s+list\s+.*firefox`} {
		if !regexp.MustCompile(want).MatchString(audit) {
			t.Errorf("the audit log lacks %q:\n%s", want, audit)
		}
	}
}

func TestTheExtensionUnlocksSavesAndFillsCodes(t *testing.T) {
	h, _ := browserHarness(t)
	h.ok("pw", h.with("set", "web/2fa", "--kind", "login", "--field", "username=tess", "--field", "url=https://2fa.example",
		"--field", "otp=otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")...)
	x := startOwnExtension(t, h, "chrome-extension://"+svext.ChromeID+"/")
	x.ask("hello", nil)

	// Locked: the extension hears so, gets nothing, and asks secretvault
	// to unlock, which asks the person on the desktop.
	h.ok("", "lock")
	if e := x.event(); e["event"] != "vault" || e["vault"] != "default" || e["locked"] != true {
		t.Fatalf("the lock event: %v", e)
	}
	if r := x.ask("logins", map[string]any{"origin": "https://2fa.example"}); refused(r) != svext.CodeLocked {
		t.Fatalf("logins while locked: %v", r)
	}
	h.desk.answer("", "correct horse battery staple")
	r := x.ask("unlock", map[string]any{"vault": "default"})
	if vs, _ := r["vaults"].([]any); r["ok"] != true || len(vs) != 1 || vs[0].(map[string]any)["locked"] != false {
		t.Fatalf("unlock: %v", r)
	}
	q := h.desk.questions()
	if !strings.Contains(q[len(q)-1], `asks to unlock vault "default" for the secretvault extension`) {
		t.Fatalf("the unlock prompt: %q", q[len(q)-1])
	}
	if e := x.event(); e["locked"] != false {
		t.Fatalf("the unlock event: %v", e)
	}
	if r := x.ask("logins", map[string]any{"vault": "nope", "origin": "https://2fa.example"}); refused(r) != svext.CodeNoVault {
		t.Fatalf("another vault: %v", r)
	}

	// The one-time code is a read of the login.
	h.desk.answer(svrpc.ChoiceAlways, "")
	ls := loginsOf(x.ask("logins", map[string]any{"origin": "https://2fa.example"}))
	if len(ls) != 1 || ls[0]["totp"] != true {
		t.Fatalf("a login with a code: %v", ls)
	}
	key, _ := svotp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
	codes := map[string]bool{}
	for _, at := range []time.Time{time.Now().Add(-30 * time.Second), time.Now(), time.Now().Add(30 * time.Second)} {
		c, _ := key.Code(at)
		codes[c] = true
	}
	if r := x.ask("totp", map[string]any{"origin": "https://2fa.example", "login": ls[0]["id"]}); !codes[fmt.Sprint(r["code"])] {
		t.Fatalf("totp: %v", r)
	}
	if r := x.ask("fill", map[string]any{"origin": "https://2fa.example", "login": ls[0]["id"]}); r["password"] != "pw" || !codes[fmt.Sprint(r["totp"])] {
		t.Fatalf("fill with a code: %v", r)
	}

	// Saving: a login is new, then known, then changed.
	check := func(user, pw string) map[string]any {
		return x.ask("check", map[string]any{"origin": "https://shop.example", "username": user, "password": pw})
	}
	if r := check("bob", "s3cr\"et"); r["status"] != svext.StatusNew {
		t.Fatalf("check a new login: %v", r)
	}
	asked := h.desk.count()
	h.desk.answer(svrpc.ChoiceOnce, "")
	r = x.ask("save", map[string]any{"origin": "https://shop.example", "username": "bob", "password": "s3cr\"et", "title": "Shop"})
	if r["created"] != true || h.desk.count() != asked+1 || !strings.Contains(h.desk.questions()[asked], `wants to save a new login "web/shop.example" for https://shop.example`) {
		t.Fatalf("save: %v (%d prompts)", r, h.desk.count()-asked)
	}
	if got := h.ok("", h.with("get", "web/shop.example")...); got != "s3cr\"et\n" {
		t.Fatalf("stored %q", got)
	}
	if got := h.ok("", h.with("get", "web/shop.example", "--field", "url")...); got != "https://shop.example\n" {
		t.Fatalf("its URL: %q", got)
	}
	id := r["login"]
	if r := check("bob", "s3cr\"et"); r["status"] != svext.StatusKnown || r["login"] != id {
		t.Fatalf("check a known login: %v", r)
	}
	if r := check("bob", "n3w"); r["status"] != svext.StatusChanged || r["login"] != id {
		t.Fatalf("check a changed login: %v", r)
	}
	// The browser made it, so it may read and change it without asking.
	asked = h.desk.count()
	if r := x.ask("save", map[string]any{"origin": "https://shop.example", "username": "bob", "password": "n3w", "login": id}); r["created"] != false || r["login"] != id {
		t.Fatalf("update: %v", r)
	}
	if r := x.ask("fill", map[string]any{"origin": "https://shop.example", "login": id}); r["password"] != "n3w" || h.desk.count() != asked {
		t.Fatalf("the saved login, read back: %v (%d prompts)", r, h.desk.count()-asked)
	}
	// Not into a login of another site.
	if r := x.ask("save", map[string]any{"origin": "https://evil.example", "password": "x", "login": id}); refused(r) != svext.CodeNotFound {
		t.Fatalf("an update from another site: %v", r)
	}

	// New passwords are the host's, with the managers' generator.
	if r := x.ask("generate", nil); len(fmt.Sprint(r["password"])) != 24 {
		t.Fatalf("generate: %v", r)
	}
	if r := x.ask("generate", map[string]any{"length": 40, "symbols": false}); !regexp.MustCompile(`^[A-Za-z0-9]{40}$`).MatchString(fmt.Sprint(r["password"])) {
		t.Fatalf("generate 40, no symbols: %v", r)
	}

	if r := x.ask("lock", nil); r["ok"] != true {
		t.Fatalf("lock: %v", r)
	}
	if e := x.event(); e["locked"] != true {
		t.Fatalf("after lock: %v", e)
	}
}

func TestTheExtensionsHostChecksEveryMessage(t *testing.T) {
	h, _ := browserHarness(t)
	x := startOwnExtension(t, h)
	for _, c := range []struct {
		frame string
		code  string
		id    string
	}{
		{`not json`, svext.CodeBadRequest, ""},
		{`[1,2]`, svext.CodeBadRequest, ""},
		{`{"v":1,"op":"state"}`, svext.CodeBadRequest, ""},
		{`{"v":2,"id":"a","op":"state"}`, svext.CodeBadRequest, "a"},
		{`{"v":1,"id":"b","op":"dump"}`, svext.CodeUnknownOp, "b"},
		{`{"v":1,"id":"c","op":"state","evil":1}`, svext.CodeBadRequest, "c"},
		{`{"v":1,"id":"d","op":"logins","origin":"https://github.com/login"}`, svext.CodeBadRequest, "d"},
		{`{"v":1,"id":"e","op":"logins","origin":"file:///etc"}`, svext.CodeBadRequest, "e"},
		{`{"v":1,"id":"f","op":"fill","origin":"https://a.example","login":"../../x"}`, svext.CodeBadRequest, "f"},
		{`{"v":1,"id":"g","op":"save","origin":"https://a.example","password":"` + strings.Repeat("p", svext.MaxPassword+1) + `"}`, svext.CodeBadRequest, "g"},
		{`{"v":1,"id":"h","op":"logins","origin":"https://a.example","pad":"` + strings.Repeat("x", svext.MaxRequest) + `"}`, svext.CodeTooLarge, ""},
	} {
		x.frame([]byte(c.frame))
		r := x.reply()
		if refused(r) != c.code || r["id"] != c.id {
			t.Errorf("%.60s: %v", c.frame, r)
		}
	}
	// Still talking.
	if r := x.ask("state", nil); r["ok"] != true {
		t.Fatalf("after the bad messages: %v", r)
	}
	// A length the browser never sends ends the host.
	x.in.Write([]byte{0xff, 0xff, 0xff, 0x7f})
	select {
	case code := <-x.exited:
		if code != 1 || !strings.Contains(x.stderr.String(), "larger than 1 MiB") {
			t.Fatalf("exit %d: %s", code, x.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the host read on past a message over the limit")
	}
	x.exited <- 1 // for the cleanup
}

func TestTheExtensionsHostServesTheExtensionAlone(t *testing.T) {
	h, _ := browserHarness(t)
	// Started by its own manifest for another extension, or by Chromium
	// (which names no manifest) for an extension that is neither: it
	// refuses.
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{extManifest, "keepassxc-browser@keepassxc.org"}, "serves the secretvault extension only"},
		{[]string{extManifest, "evil@example.com"}, "serves the secretvault extension only"},
		{[]string{"chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh/"}, "serves the secretvault extension and KeePassXC-Browser only"},
		{[]string{"/home/u/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json", "evil@example.com"}, "and KeePassXC-Browser only"},
	} {
		x := startOwnExtension(t, h, c.args...)
		select {
		case code := <-x.exited:
			if code != 1 || !strings.Contains(x.stderr.String(), c.says) {
				t.Fatalf("%s: exit %d: %s", c.args, code, x.stderr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("the host served %s", c.args)
		}
		x.exited <- 1
	}
	// Started for KeePassXC-Browser, the host is the legacy relay, which
	// does not speak the extension's protocol.
	y := startExtension(t, h, "/home/u/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json", "keepassxc-browser@keepassxc.org")
	y.send(map[string]any{"v": 1, "id": "a", "op": "state", "clientID": "c"})
	if r := y.reply(); r["errorCode"] == nil {
		t.Fatalf("the legacy relay answered the extension's protocol: %v", r)
	}
}

func TestTheExtensionHearsWhenSecretvaultCannotBeReached(t *testing.T) {
	outR, outW := io.Pipe()
	stderr := &lockedBuffer{}
	c := &cli{stdin: strings.NewReader(""), stdout: outW, stderr: stderr,
		connect: func(secretvault.Options) (*secretvault.Client, error) { return nil, secretvault.ErrNoDaemon }}
	exited := make(chan int, 1)
	go func() {
		code := c.run([]string{"browser-host", extManifest, svext.FirefoxID})
		outW.Close()
		exited <- code
	}()
	f, err := svbrowser.ReadFrame(outR)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	if json.Unmarshal(f, &e) != nil || e["v"] != float64(1) || e["event"] != "down" || e["error"] != svext.CodeNotRunning || e["message"] == "" {
		t.Fatalf("the down event: %s", f)
	}
	if code := <-exited; code != 1 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}
