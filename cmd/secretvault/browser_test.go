package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The browser path end to end: the test plays KeePassXC-Browser (its keys,
// crypto_box, nonces and messages, as keepassxc-browser's keepass.js and
// client.js send them) through the relay's stdin and stdout, to a real
// daemon in this process. The daemon is told the relay's parent is
// Firefox.

var firefox = svpeer.Process{PID: 31337, Exe: "/usr/lib/firefox/firefox", SystemOwned: true}

// launcher is the program the daemon is told started the relay.
type launcher struct {
	mu sync.Mutex
	p  svpeer.Process
}

func (l *launcher) set(p svpeer.Process) {
	l.mu.Lock()
	l.p = p
	l.mu.Unlock()
}

func (l *launcher) of(relay *svpeer.Process) (*svpeer.Process, error) {
	if relay.PID != os.Getpid() {
		return nil, fmt.Errorf("the relay is process %d, not this test", relay.PID)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.p
	return &p, nil
}

func browserHarness(t *testing.T) (*harness, *launcher) {
	t.Helper()
	l := &launcher{p: firefox}
	h := newHarness(t, func(o *svd.Options) { o.Launcher = l.of })
	h.init()
	return h, l
}

func (d *fakeDesk) answer(choice, passphrase string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.choice, d.passphrase = choice, passphrase
}

func (d *fakeDesk) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.asked)
}

// lockedBuffer is stderr, written by the relay while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// extension is KeePassXC-Browser, talking to a running relay.
type extension struct {
	t        *testing.T
	in       *io.PipeWriter
	replies  chan map[string]any
	pushed   chan string
	exited   chan int
	stderr   *lockedBuffer
	pub, sec *[32]byte
	host     *[32]byte
	clientID string
	idKey    string
	id       string
	last     []byte // the last frame sent
}

// startExtension runs the relay as a browser would, with args.
func startExtension(t *testing.T, h *harness, args ...string) *extension {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	x := &extension{t: t, in: inW, replies: make(chan map[string]any, 64), pushed: make(chan string, 16),
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
				t.Errorf("the relay wrote %q", f)
				continue
			}
			if a := m["action"]; a == svbrowser.ActionDatabaseLocked || a == svbrowser.ActionDatabaseUnlocked {
				if len(m) != 1 {
					t.Errorf("a notice with more than its action: %v", m)
				}
				x.pushed <- a.(string)
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
			t.Error("the relay did not stop when the browser went away")
		}
		outR.Close()
	})
	return x
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func newNonce() (string, [24]byte) {
	var n [24]byte
	rand.Read(n[:])
	return b64(n[:]), n
}

// incremented is the extension's keepassClient.incrementedNonce.
func incremented(n [24]byte) string {
	c := 1
	for i := range n {
		c += int(n[i])
		n[i] = byte(c)
		c >>= 8
	}
	return b64(n[:])
}

func (x *extension) sendFrame(frame []byte) {
	x.t.Helper()
	x.last = frame
	var head [4]byte
	binary.NativeEndian.PutUint32(head[:], uint32(len(frame)))
	if _, err := x.in.Write(append(head[:], frame...)); err != nil {
		x.t.Fatalf("writing to the relay: %v", err)
	}
}

func (x *extension) send(m map[string]any) {
	x.t.Helper()
	b, _ := json.Marshal(m)
	x.sendFrame(b)
}

func (x *extension) reply() map[string]any {
	x.t.Helper()
	select {
	case r, ok := <-x.replies:
		if !ok {
			x.t.Fatalf("the relay stopped; it said: %s", x.stderr.String())
		}
		return r
	case <-time.After(10 * time.Second):
		x.t.Fatalf("no answer; the relay said: %s", x.stderr.String())
	}
	return nil
}

func (x *extension) notice() string {
	x.t.Helper()
	select {
	case a := <-x.pushed:
		return a
	case <-time.After(10 * time.Second):
		x.t.Fatal("no notice came")
	}
	return ""
}

// changeKeys is keepass.changePublicKeys.
func (x *extension) changeKeys() {
	x.t.Helper()
	x.pub, x.sec, _ = box.GenerateKey(rand.Reader)
	cid := make([]byte, 24)
	rand.Read(cid)
	x.clientID = b64(cid)
	nonce, n := newNonce()
	x.send(map[string]any{"action": svbrowser.ActionChangePublicKeys, "publicKey": b64(x.pub[:]), "nonce": nonce, "clientID": x.clientID})
	r := x.reply()
	if r["success"] != "true" || r["nonce"] != incremented(n) || r["action"] != svbrowser.ActionChangePublicKeys {
		x.t.Fatalf("change-public-keys: %v", r)
	}
	k, _ := base64.StdEncoding.DecodeString(r["publicKey"].(string))
	x.host = new([32]byte)
	copy(x.host[:], k)
}

// call is keepassClient.sendMessage: the message sealed, then the answer
// opened and checked (or the error, as sent).
func (x *extension) call(action string, msg map[string]any, extra ...string) map[string]any {
	x.t.Helper()
	msg["action"] = action
	plain, _ := json.Marshal(msg)
	nonce, n := newNonce()
	req := map[string]any{"action": action, "message": b64(box.Seal(nil, plain, &n, x.host, x.sec)), "nonce": nonce, "clientID": x.clientID}
	for i := 0; i+1 < len(extra); i += 2 {
		req[extra[i]] = extra[i+1]
	}
	x.send(req)
	r := x.reply()
	if r["message"] == nil {
		return r
	}
	want := incremented(n)
	if r["nonce"] != want || r["action"] != action {
		x.t.Fatalf("%s: answered %v", action, r)
	}
	sealed, _ := base64.StdEncoding.DecodeString(r["message"].(string))
	var rn [24]byte
	b, _ := base64.StdEncoding.DecodeString(want)
	copy(rn[:], b)
	out, ok := box.Open(nil, sealed, &rn, x.host, x.sec)
	if !ok {
		x.t.Fatalf("%s: the answer does not open", action)
	}
	var m map[string]any
	json.Unmarshal(out, &m)
	if m["success"] != "true" || m["nonce"] != want || m["version"] != svbrowser.Version {
		x.t.Fatalf("%s: the answer's envelope: %v", action, m)
	}
	return m
}

// associate is keepass.associate, with the person's answer given.
func (x *extension) associate(h *harness, answer string) map[string]any {
	x.t.Helper()
	idPub, _, _ := box.GenerateKey(rand.Reader)
	x.idKey = b64(idPub[:])
	h.desk.answer(answer, "")
	r := x.call(svbrowser.ActionAssociate, map[string]any{"key": b64(x.pub[:]), "idKey": x.idKey}, "triggerUnlock", "true")
	if id, ok := r["id"].(string); ok {
		x.id = id
	}
	return r
}

func (x *extension) keys() []map[string]string {
	return []map[string]string{{"id": x.id, "key": x.idKey}}
}

func (x *extension) logins(url string) (map[string]any, []map[string]any) {
	x.t.Helper()
	r := x.call(svbrowser.ActionGetLogins, map[string]any{"id": x.id, "url": url, "keys": x.keys()})
	var out []map[string]any
	if list, ok := r["entries"].([]any); ok {
		for _, e := range list {
			out = append(out, e.(map[string]any))
		}
	}
	return r, out
}

func errCode(r map[string]any) string {
	c, _ := r["errorCode"].(string)
	return c
}

func TestAnExtensionConnectsOnceAndIsAskedAboutEachLogin(t *testing.T) {
	h, _ := browserHarness(t)
	h.ok("hunter2", h.with("set", "web/github.com", "--kind", "login", "--field", "username=ada", "--field", "url=https://github.com")...)
	h.ok("g1st", h.with("set", "web/gist", "--kind", "login", "--field", "username=gisty", "--field", "url=https://gist.github.com")...)
	h.ok("evil", h.with("set", "web/evil", "--kind", "login", "--field", "url=https://evilgithub.com")...)
	h.ok("tld", h.with("set", "web/tld", "--kind", "login", "--field", "url=https://com")...)
	h.ok("plain", h.with("set", "web/plain", "--kind", "login", "--field", "url=http://github.com")...)
	h.ok("port", h.with("set", "web/port", "--kind", "login", "--field", "url=https://github.com:8443")...)
	h.ok("note", h.with("set", "notes/github", "--kind", "note", "--field", "url=https://github.com")...)

	x := startExtension(t, h, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/")
	x.changeKeys()
	r := x.call(svbrowser.ActionGetDatabaseHash, map[string]any{"connectedKeys": []string{}})
	hash, _ := r["hash"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(hash) {
		t.Fatalf("get-databasehash: %v", r)
	}
	if again := x.call(svbrowser.ActionGetDatabaseHash, map[string]any{}); again["hash"] != hash {
		t.Fatalf("the hash changed: %v", again)
	}

	// Nothing of the vault's before the person agrees.
	if r := x.call(svbrowser.ActionGetLogins, map[string]any{"url": "https://github.com/"}); errCode(r) != "8" {
		t.Fatalf("get-logins before associating: %v", r)
	}
	if r := x.associate(h, svrpc.ChoiceDeny); errCode(r) != "6" {
		t.Fatalf("an association refused: %v", r)
	}
	q := h.desk.questions()
	if len(q) != 1 || !strings.Contains(q[0], "firefox (/usr/lib/firefox/firefox) wants to connect its KeePassXC-Browser extension (chrome-extension://oboonakemofpalcgghocfoadofidjkkk/)") {
		t.Fatalf("the association prompt: %q", q)
	}
	r = x.associate(h, svrpc.ChoiceAlways)
	if !regexp.MustCompile(`^firefox-[0-9a-f]{4}$`).MatchString(x.id) || r["hash"] != hash {
		t.Fatalf("associate: %v", r)
	}
	if ls := h.ok("", h.with("browser", "ls")...); !strings.Contains(ls, x.id) || !strings.Contains(ls, "/usr/lib/firefox/firefox") || !strings.Contains(ls, "chrome-extension://") {
		t.Fatalf("browser ls:\n%s", ls)
	}

	// Each login is asked about: once...
	asked := h.desk.count()
	h.desk.answer(svrpc.ChoiceOnce, "")
	r, entries := x.logins("https://gist.github.com/login")
	if r["count"] != float64(2) || len(entries) != 2 {
		t.Fatalf("get-logins: %v", r)
	}
	if entries[0]["login"] != "gisty" || entries[0]["password"] != "g1st" || entries[1]["login"] != "ada" || entries[1]["password"] != "hunter2" {
		t.Fatalf("the logins, best first: %v", entries)
	}
	if entries[1]["group"] != "web" || entries[1]["name"] != "web/github.com" || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(entries[1]["uuid"].(string)) {
		t.Fatalf("an entry: %v", entries[1])
	}
	if n := h.desk.count() - asked; n != 2 {
		t.Fatalf("%d prompts for two logins", n)
	}
	last := h.desk.questions()[h.desk.count()-1]
	if !strings.Contains(last, `firefox (/usr/lib/firefox/firefox) wants the login "web/github.com" for gist.github.com`) || !strings.Contains(last, "Process: 31337") {
		t.Fatalf("the consent prompt: %q", last)
	}
	// ... once means once ...
	asked = h.desk.count()
	if _, entries := x.logins("https://github.com/"); len(entries) != 1 || entries[0]["password"] != "hunter2" || h.desk.count() != asked+1 {
		t.Fatalf("again: %v, %d prompts", entries, h.desk.count()-asked)
	}
	// ... refused, the extension learns only that there is nothing ...
	h.desk.answer(svrpc.ChoiceDeny, "")
	if r, _ := x.logins("https://github.com/"); errCode(r) != "15" {
		t.Fatalf("refused: %v", r)
	}
	// ... and remembered, it is not asked again.
	h.desk.answer(svrpc.ChoiceAlways, "")
	x.logins("https://github.com/")
	asked = h.desk.count()
	if _, entries := x.logins("https://github.com/"); len(entries) != 1 || h.desk.count() != asked {
		t.Fatalf("remembered: %v, %d prompts", entries, h.desk.count()-asked)
	}
	if grants := h.ok("", h.with("grant", "list")...); !strings.Contains(grants, "firefox") || !strings.Contains(grants, "web/github.com") {
		t.Fatalf("the remembered decision is not a grant:\n%s", grants)
	}

	// A look-alike domain gets only its own login; nothing is offered where
	// only a bare top-level name, or nothing at all, was stored.
	h.desk.answer(svrpc.ChoiceOnce, "")
	if _, entries := x.logins("https://evilgithub.com/"); len(entries) != 1 || entries[0]["password"] != "evil" {
		t.Errorf("evilgithub.com: %v", entries)
	}
	for _, u := range []string{"https://github.com.evil.example/", "https://example.com/"} {
		asked := h.desk.count()
		if r, _ := x.logins(u); errCode(r) != "15" || h.desk.count() != asked {
			t.Errorf("%s: %v", u, r)
		}
	}
	// The scheme counts; a port only when one was stored.
	if _, entries := x.logins("http://github.com/"); len(entries) != 1 || entries[0]["password"] != "plain" {
		t.Errorf("http: %v", entries)
	}
	if _, entries := x.logins("https://github.com:8443/"); len(entries) != 2 {
		t.Errorf("port 8443: %v", entries)
	}

	// Every login handed out, and every refusal, is in the audit log under
	// the browser's name.
	audit := h.ok("", h.with("audit", "--limit", "0")...)
	for _, want := range []string{`allowed\s+read web/gist\s+firefox \(/usr/lib/firefox/firefox\)`, `denied\s+read web/github.com\s+firefox`,
		`connected KeePassXC-Browser as ` + x.id} {
		if !regexp.MustCompile(want).MatchString(audit) {
			t.Errorf("the audit log lacks %q:\n%s", want, audit)
		}
	}

	// Removing the association ends it, even for the session that made it.
	h.ok("", h.with("browser", "rm", x.id)...)
	if r := x.call(svbrowser.ActionGetDatabaseGroups, map[string]any{}); errCode(r) != "8" {
		t.Fatalf("after browser rm: %v", r)
	}
	if r := x.call(svbrowser.ActionTestAssociate, map[string]any{"id": x.id, "key": x.idKey}); errCode(r) != "8" {
		t.Fatalf("test-associate after browser rm: %v", r)
	}
}

// connected is an extension associated with the vault.
func connected(t *testing.T, h *harness) *extension {
	t.Helper()
	x := startExtension(t, h, "/home/u/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json", "keepassxc-browser@keepassxc.org")
	x.changeKeys()
	if r := x.associate(h, svrpc.ChoiceAlways); x.id == "" {
		t.Fatalf("associate: %v", r)
	}
	return x
}

func TestANewSessionProvesItsAssociation(t *testing.T) {
	h, browser := browserHarness(t)
	x := connected(t, h)
	y := startExtension(t, h, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/")
	y.changeKeys()
	if r := y.call(svbrowser.ActionTestAssociate, map[string]any{"id": x.id, "key": "AAAA"}); errCode(r) != "8" {
		t.Fatalf("a wrong key: %v", r)
	}
	if r := y.call(svbrowser.ActionTestAssociate, map[string]any{"id": x.id, "key": x.idKey}); r["id"] != x.id {
		t.Fatalf("test-associate: %v", r)
	}
	y.id, y.idKey = x.id, x.idKey
	if r := y.call(svbrowser.ActionGetDatabaseGroups, map[string]any{}); errCode(r) != "" {
		t.Fatalf("an associated session: %v", r)
	}
	// The same key from another browser is not the association.
	browser.set(svpeer.Process{PID: 999, Exe: "/usr/bin/chromium", SystemOwned: true})
	z := startExtension(t, h, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/")
	z.changeKeys()
	if r := z.call(svbrowser.ActionTestAssociate, map[string]any{"id": x.id, "key": x.idKey}); errCode(r) != "8" {
		t.Fatalf("another browser with the key: %v", r)
	}
}

func TestTheExtensionSavesLoginsAndGetsCodes(t *testing.T) {
	h, _ := browserHarness(t)
	x := connected(t, h)

	// A new login is a write, asked about; then the browser may use it.
	h.desk.answer(svrpc.ChoiceOnce, "")
	asked := h.desk.count()
	r := x.call(svbrowser.ActionSetLogin, map[string]any{"id": x.id, "url": "https://example.org/login", "submitUrl": "https://example.org/login",
		"login": "bob", "password": "s3cr\"et"})
	if r["error"] != "success" || h.desk.count() != asked+1 {
		t.Fatalf("set-login: %v (%d prompts)", r, h.desk.count()-asked)
	}
	if !strings.Contains(h.desk.questions()[asked], `wants to save a new login "web/example.org" for example.org`) {
		t.Fatalf("the prompt: %q", h.desk.questions()[asked])
	}
	if got := h.ok("", h.with("get", "web/example.org")...); got != "s3cr\"et\n" {
		t.Fatalf("stored %q", got)
	}
	asked = h.desk.count()
	_, entries := x.logins("https://example.org/")
	if len(entries) != 1 || entries[0]["login"] != "bob" || h.desk.count() != asked {
		t.Fatalf("the saved login, read back without asking: %v", entries)
	}
	uuid := entries[0]["uuid"].(string)

	// Changing it needs no question either: the browser made it.
	if r := x.call(svbrowser.ActionSetLogin, map[string]any{"url": "https://example.org/", "login": "bob", "password": "n3w", "uuid": uuid}); r["error"] != "success" {
		t.Fatalf("updating: %v", r)
	}
	if got := h.ok("", h.with("get", "web/example.org")...); got != "n3w\n" || h.desk.count() != asked {
		t.Fatalf("after the update: %q", got)
	}
	// A second account for the site gets its own name.
	x.call(svbrowser.ActionSetLogin, map[string]any{"url": "https://example.org/", "login": "carol", "password": "c"})
	if got := h.ok("", h.with("get", "web/example.org (carol)", "--field", "username")...); got != "carol\n" {
		t.Fatalf("a second account: %q", got)
	}

	// Groups are the vault's folders; seeing them is listing the vault.
	h.desk.answer(svrpc.ChoiceOnce, "")
	asked = h.desk.count()
	r = x.call(svbrowser.ActionGetDatabaseGroups, map[string]any{})
	groups := r["groups"].(map[string]any)["groups"].([]any)
	root := groups[0].(map[string]any)
	children := root["children"].([]any)
	if root["name"] != "default" || len(children) != 1 || children[0].(map[string]any)["name"] != "web" || h.desk.count() != asked+1 {
		t.Fatalf("get-database-groups: %v", r)
	}
	if !strings.Contains(h.desk.questions()[asked], "wants to see the folders of vault") {
		t.Fatalf("the prompt: %q", h.desk.questions()[asked])
	}
	g := x.call(svbrowser.ActionCreateNewGroup, map[string]any{"groupName": "Work/Sites"})
	if g["name"] != "Sites" || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(g["uuid"].(string)) {
		t.Fatalf("create-new-group: %v", g)
	}
	if again := x.call(svbrowser.ActionCreateNewGroup, map[string]any{"groupName": "/Work/Sites/"}); again["uuid"] != g["uuid"] {
		t.Fatalf("the same folder, another ID: %v", again)
	}
	if bad := x.call(svbrowser.ActionCreateNewGroup, map[string]any{"groupName": "a/../b"}); errCode(bad) != "17" {
		t.Fatalf("a bad folder: %v", bad)
	}
	x.call(svbrowser.ActionSetLogin, map[string]any{"url": "https://shop.example/", "login": "dave", "password": "d", "group": "Sites", "groupUuid": g["uuid"]})
	x.call(svbrowser.ActionSetLogin, map[string]any{"url": "https://top.example/", "login": "erin", "password": "e", "group": "default", "groupUuid": root["uuid"]})
	list := h.ok("", h.with("ls")...)
	if !strings.Contains(list, "Work/Sites/shop.example\n") || !strings.Contains(list, "\ntop.example\n") {
		t.Fatalf("saved into groups:\n%s", list)
	}

	// The one-time code is a read of the item.
	h.ok("pw", h.with("set", "web/2fa", "--kind", "login", "--field", "url=https://2fa.example",
		"--field", "otp=otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")...)
	h.desk.answer(svrpc.ChoiceAlways, "")
	_, entries = x.logins("https://2fa.example/")
	key, _ := svotp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
	now := time.Now()
	codes := map[string]bool{}
	for _, at := range []time.Time{now.Add(-30 * time.Second), now, now.Add(30 * time.Second)} {
		c, _ := key.Code(at)
		codes[c] = true
	}
	if len(entries) != 1 || !codes[entries[0]["totp"].(string)] {
		t.Fatalf("a login with a code: %v", entries)
	}
	if r := x.call(svbrowser.ActionGetTOTP, map[string]any{"uuid": entries[0]["uuid"]}); !codes[r["totp"].(string)] {
		t.Fatalf("get-totp: %v", r)
	}
	if r := x.call(svbrowser.ActionGetTOTP, map[string]any{"uuid": "nope"}); errCode(r) != "18" {
		t.Fatalf("get-totp of a bad ID: %v", r)
	}

	// Deleting is asked about, unless the browser made the item.
	if r := x.call(svbrowser.ActionDeleteEntry, map[string]any{"uuid": uuid}); r["success"] != "true" {
		t.Fatalf("delete-entry: %v", r)
	}
	if _, _, code := h.run("", h.with("get", "web/example.org")...); code == 0 {
		t.Fatal("the deleted login is still there")
	}

	if r := x.call(svbrowser.ActionGeneratePassword, map[string]any{"requestID": "4f3a2b1c"}, "requestID", "4f3a2b1c"); len(r["password"].(string)) != 24 {
		t.Fatalf("generate-password: %v", r)
	}
	// Not served: the extension falls back on its own.
	for _, a := range []string{svbrowser.ActionPasskeysGet, svbrowser.ActionPasskeysRegister, svbrowser.ActionRequestAutotype} {
		if r := x.call(a, map[string]any{"origin": "https://example.org", "keys": x.keys()}); errCode(r) != "12" {
			t.Errorf("%s: %v", a, r)
		}
	}
}

func TestTheExtensionHearsTheVaultLockAndUnlock(t *testing.T) {
	h, _ := browserHarness(t)
	h.ok("hunter2", h.with("set", "web/github.com", "--kind", "login", "--field", "url=https://github.com")...)
	x := connected(t, h)

	h.ok("", "lock")
	if a := x.notice(); a != svbrowser.ActionDatabaseLocked {
		t.Fatalf("after lock: %s", a)
	}
	if r := x.call(svbrowser.ActionGetDatabaseHash, map[string]any{}); errCode(r) != "1" {
		t.Fatalf("get-databasehash while locked: %v", r)
	}
	if r, _ := x.logins("https://github.com/"); errCode(r) != "1" {
		t.Fatalf("get-logins while locked: %v", r)
	}
	// triggerUnlock asks the person for the passphrase, on the desktop.
	h.desk.answer("", "correct horse battery staple")
	r := x.call(svbrowser.ActionGetDatabaseHash, map[string]any{}, "triggerUnlock", "true")
	if r["hash"] == nil {
		t.Fatalf("get-databasehash with triggerUnlock: %v", r)
	}
	if a := x.notice(); a != svbrowser.ActionDatabaseUnlocked {
		t.Fatalf("after the unlock: %s", a)
	}
	q := h.desk.questions()
	if !strings.Contains(q[len(q)-1], "asks to unlock vault \"default\" for its KeePassXC-Browser extension") {
		t.Fatalf("the unlock prompt: %q", q[len(q)-1])
	}
	// The association outlives the lock.
	h.desk.answer(svrpc.ChoiceOnce, "")
	if _, entries := x.logins("https://github.com/"); len(entries) != 1 {
		t.Fatalf("after unlocking: %v", entries)
	}

	if r := x.call(svbrowser.ActionLockDatabase, map[string]any{}); errCode(r) != "" {
		t.Fatalf("lock-database: %v", r)
	}
	if a := x.notice(); a != svbrowser.ActionDatabaseLocked {
		t.Fatalf("after lock-database: %s", a)
	}
	if out := h.ok("", "status"); !regexp.MustCompile(`default \*\s+locked`).MatchString(out) {
		t.Fatalf("status after lock-database:\n%s", out)
	}
	h.ok("", h.with("unlock")...)
	if a := x.notice(); a != svbrowser.ActionDatabaseUnlocked {
		t.Fatalf("after unlock: %s", a)
	}
}

func TestTheRelayPassesOnlyWellSealedMessages(t *testing.T) {
	h, _ := browserHarness(t)
	x := connected(t, h)

	x.call(svbrowser.ActionGetDatabaseHash, map[string]any{})
	replay := x.last
	x.sendFrame(replay)
	if r := x.reply(); errCode(r) != "4" {
		t.Fatalf("a replay: %v", r)
	}
	// A nonce too short.
	nonce, n := newNonce()
	plain := []byte(`{"action":"get-databasehash"}`)
	sealed := b64(box.Seal(nil, plain, &n, x.host, x.sec))
	x.send(map[string]any{"action": "get-databasehash", "message": sealed, "nonce": nonce[:28] + "AA==", "clientID": x.clientID})
	if r := x.reply(); errCode(r) != "4" {
		t.Fatalf("a bad nonce: %v", r)
	}
	// Sealed under another nonce than the one sent.
	other, _ := newNonce()
	x.send(map[string]any{"action": "get-databasehash", "message": sealed, "nonce": other, "clientID": x.clientID})
	if r := x.reply(); errCode(r) != "4" {
		t.Fatalf("a wrong nonce: %v", r)
	}
	// Frames that are no message.
	for _, f := range []string{"not json", "[1,2,3]", "{}"} {
		x.sendFrame([]byte(f))
		if r := x.reply(); errCode(r) != "13" {
			t.Fatalf("frame %q: %v", f, r)
		}
	}
	// Still talking.
	if r := x.call(svbrowser.ActionGetDatabaseHash, map[string]any{}); r["hash"] == nil {
		t.Fatalf("after the bad frames: %v", r)
	}

	// A length the browser never sends ends the relay: the stream cannot
	// be read past it.
	x.in.Write([]byte{0xff, 0xff, 0xff, 0x7f})
	select {
	case code := <-x.exited:
		if code != 1 || !strings.Contains(x.stderr.String(), "larger than 1 MiB") {
			t.Fatalf("exit %d: %s", code, x.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the relay read on past a message over the limit")
	}
	x.exited <- 1 // for the cleanup

	// So does a message cut short.
	y := startExtension(t, h, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/")
	y.changeKeys()
	var head [4]byte
	binary.NativeEndian.PutUint32(head[:], 100)
	y.in.Write(append(head[:], `{"action":`...))
	y.in.Close()
	select {
	case code := <-y.exited:
		if code != 1 || !strings.Contains(y.stderr.String(), "unexpected EOF") {
			t.Fatalf("exit %d: %s", code, y.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the relay did not stop at a cut message")
	}
	y.exited <- 1
}

func TestTheRelayIsFoundByItsNameOrItsArguments(t *testing.T) {
	for argv0, want := range map[string]string{
		"/usr/bin/secretvault-browser":    "browser-host",
		"/opt/sv/secretvault-browser.exe": "browser-host",
		"/usr/bin/secretvault":            "",
	} {
		if got := helperName(argv0); got != want {
			t.Errorf("helperName(%s) = %q", argv0, got)
		}
	}
	for _, c := range []struct {
		args   []string
		origin string
		ok     bool
	}{
		{[]string{"chrome-extension://oboonakemofpalcgghocfoadofidjkkk/"}, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", true},
		{[]string{"chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", "--parent-window=0"}, "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", true},
		{[]string{"/home/u/.mozilla/native-messaging-hosts/org.keepassxc.keepassxc_browser.json", "keepassxc-browser@keepassxc.org"}, "keepassxc-browser@keepassxc.org", true},
		{[]string{"export", "backup.json"}, "", false},
		{[]string{"import", "auto", "x.json"}, "", false},
		{[]string{"x.json"}, "", false},
		{nil, "", false},
	} {
		if o, ok := browserOrigin(c.args); o != c.origin || ok != c.ok {
			t.Errorf("browserOrigin(%q) = %q, %v", c.args, o, ok)
		}
	}
}
