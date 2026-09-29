package svbrowser

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/nacl/box"
)

func TestFramesAreALengthThenJSON(t *testing.T) {
	var buf bytes.Buffer
	for _, m := range []string{`{"action":"a"}`, ``, `{"x":"` + strings.Repeat("y", 70000) + `"}`} {
		if err := WriteFrame(&buf, []byte(m)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{`{"action":"a"}`, ``} {
		got, err := ReadFrame(&buf)
		if err != nil || string(got) != want {
			t.Fatalf("ReadFrame = %q, %v; want %q", got, err, want)
		}
	}
	if got, err := ReadFrame(&buf); err != nil || len(got) != 70008 {
		t.Fatalf("a long frame: %d bytes, %v", len(got), err)
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("at the end: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{5, 0})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut length: %v", err)
	}
	WriteFrame(&buf, []byte(`{"a":1}`))
	if _, err := ReadFrame(bytes.NewReader(buf.Bytes()[:6])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a cut message: %v", err)
	}
	huge := []byte{0xff, 0xff, 0xff, 0x7f}
	if _, err := ReadFrame(bytes.NewReader(huge)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a length over the limit: %v", err)
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writing over the limit: %v", err)
	}
}

func TestNoncesIncrementLikeLibsodium(t *testing.T) {
	var n [24]byte
	n[0], n[1] = 0xff, 0xff
	if got := increment(n); got[0] != 0 || got[1] != 0 || got[2] != 1 {
		t.Fatalf("carry: %x", got)
	}
	for i := range n {
		n[i] = 0xff
	}
	if got := increment(n); got != ([24]byte{}) {
		t.Fatalf("wrap: %x", got)
	}
}

func TestSecretsSurviveJSONBothWays(t *testing.T) {
	for _, s := range []string{
		"hunter2", `quo"te\back/slash`, "tab\tnew\nline\x01\x1f", "ünïcödé ✓", "😀 emoji", "",
		"<script>&amp;</script>", "  ",
	} {
		// Ours out, encoding/json in.
		enc := appendSecret(nil, []byte(s))
		var back string
		if err := json.Unmarshal(enc, &back); err != nil || back != s {
			t.Errorf("appendSecret(%q) = %s, read back %q, %v", s, enc, back, err)
		}
		// encoding/json out, ours in.
		j, _ := json.Marshal(s)
		got, err := decodeSecret(j)
		if err != nil || string(got) != s {
			t.Errorf("decodeSecret(%s) = %q, %v", j, got, err)
		}
	}
	if got, _ := decodeSecret([]byte(`"😀 and é and \ud800 alone"`)); string(got) != "😀 and é and � alone" {
		t.Errorf("escapes: %q", got)
	}
	if enc := appendSecret(nil, []byte{'a', 0xff, 'b'}); !utf8.Valid(enc) || !bytes.Contains(enc, []byte(`�`)) {
		t.Errorf("invalid UTF-8 went out as %q", enc)
	}
	for _, bad := range []string{`hunter2`, `"unterminated`, `"bad \x escape"`, `"raw ` + "\n" + ` newline"`, `"\u12"`, `12`, `null`} {
		if _, err := decodeSecret([]byte(bad)); err == nil {
			t.Errorf("decodeSecret(%q) was accepted", bad)
		}
	}
}

func TestStoredURLsFitOnlyTheirSites(t *testing.T) {
	for _, c := range []struct {
		stored, site string
		want         int // 0: no match; -1: any match
	}{
		{"https://github.com", "https://github.com/login", 85},
		{"https://github.com/login", "https://github.com/login", 100},
		{"https://github.com/login", "https://github.com/login?next=/x", 90},
		{"github.com", "https://github.com/", 100},
		{"github.com", "https://gist.github.com/", 60},
		{"https://GitHub.com.", "https://github.com/", 100},
		{"https://gist.github.com", "https://github.com/", 0},
		{"https://github.com", "https://evilgithub.com/", 0},
		{"https://github.com", "https://github.com.evil.com/", 0},
		{"com", "https://github.com/", 0},
		{"https://com", "https://github.com/", 0},
		{"https://com", "https://com/", -1},
		{"http://github.com", "https://github.com/", 0},
		{"https://github.com", "http://github.com/", 0},
		{"github.com", "http://github.com/", 0},
		{"https://github.com:8443", "https://github.com/", 0},
		{"https://github.com:443", "https://github.com/", -1},
		{"https://github.com", "https://github.com:8443/", -1},
		{"https://github.com:8443", "https://github.com:8443/", -1},
		{"http://192.168.1.1", "http://192.168.1.1/admin", -1},
		{"http://1.1", "http://192.168.1.1/", 0},
		{"http://168.1.1", "http://192.168.1.1/", 0},
		{"http://localhost:3000", "http://localhost:3000/", -1},
		{"http://localhost", "http://app.localhost/", 0},
		{"https://[::1]", "https://[::1]/", -1},
		{"https://*.github.com", "https://gist.github.com/", 0},
		{`"https://github.com"`, "https://github.com", 0},
		{"https://git<hub.com", "https://git<hub.com", 0},
		{"https://user:pw@github.com/", "https://github.com/", 100},
		{"", "https://github.com/", 0},
		{"https://github.com", "not a url", 0},
		{"https://github.com", "file:///etc/passwd", 0},
	} {
		got := Priority(c.stored, c.site, "")
		if (c.want == -1 && got == 0) || (c.want != -1 && got != c.want) {
			t.Errorf("Priority(%q, %q) = %d, want %d", c.stored, c.site, got, c.want)
		}
	}
	// Whether a URL fits is the page's to say; the form's URL only ranks.
	if p := Priority("https://example.com/login", "https://example.com/", "https://example.com/login"); p != 100 {
		t.Errorf("the form's own URL: %d", p)
	}
	if p := Priority("https://login.example.com", "https://example.com/", "https://login.example.com/post"); p != 0 {
		t.Errorf("a host only the form posts to: %d", p)
	}
	if h := Host("https://Gist.GitHub.com:8443/x"); h != "gist.github.com" {
		t.Errorf("Host = %q", h)
	}
}

func TestFoldersBecomeGroups(t *testing.T) {
	folders := Folders([]string{"web/github.com", "web/shops/amazon", "top", "mail/work/imap", "web/shops/ebay"})
	if strings.Join(folders, ",") != "mail,mail/work,web,web/shops" {
		t.Fatalf("Folders = %v", folders)
	}
	root := Tree("personal", folders, func(p string) string { return "id:" + p })
	j, _ := json.Marshal(root)
	want := `{"name":"personal","uuid":"id:","children":[` +
		`{"name":"mail","uuid":"id:mail","children":[{"name":"work","uuid":"id:mail/work","children":[]}]},` +
		`{"name":"web","uuid":"id:web","children":[{"name":"shops","uuid":"id:web/shops","children":[]}]}]}`
	if string(j) != want {
		t.Fatalf("Tree =\n%s\nwant\n%s", j, want)
	}
	for in, want := range map[string]string{"Work/Sites": "Work/Sites", "/Work//Sites/ ": "Work/Sites", "": "", "/": ""} {
		if got, ok := CleanFolder(in); !ok || got != want {
			t.Errorf("CleanFolder(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"a/../b", "./x", "tab\there"} {
		if _, ok := CleanFolder(bad); ok {
			t.Errorf("CleanFolder(%q) was accepted", bad)
		}
	}
}

// fakeBackend answers from memory.
type fakeBackend struct {
	mu       sync.Mutex
	locked   bool
	assocs   map[string]string
	allow    bool
	opened   []bool
	saved    []SaveLogin
	password string
}

func (f *fakeBackend) Open(_ context.Context, unlock bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, unlock)
	if f.locked && !unlock {
		return &Error{Code: CodeDatabaseNotOpened}
	}
	f.locked = false
	return nil
}
func (f *fakeBackend) Hash(context.Context) (string, error) { return "hash1", nil }
func (f *fakeBackend) Associate(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.allow {
		return "", &Error{Code: CodeActionCancelledOrDenied}
	}
	f.assocs["browser-1"] = key
	return "browser-1", nil
}
func (f *fakeBackend) Associated(_ context.Context, name, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assocs[name] == key && key != "", nil
}
func (f *fakeBackend) Logins(_ context.Context, q LoginQuery) ([]Login, error) {
	if Priority("https://example.com", q.URL, q.SubmitURL) == 0 {
		return nil, &Error{Code: CodeNoLoginsFound}
	}
	return []Login{{Login: "ada", Name: "example", Password: []byte(f.password), UUID: strings.Repeat("ab", 16), Group: "web"}}, nil
}
func (f *fakeBackend) SaveLogin(_ context.Context, s SaveLogin) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.Password = bytes.Clone(s.Password)
	f.saved = append(f.saved, s)
	return nil
}
func (f *fakeBackend) Groups(context.Context) (Group, error) {
	return Tree("root", []string{"web"}, func(p string) string { return p }), nil
}
func (f *fakeBackend) CreateGroup(_ context.Context, p string) (Group, error) {
	return Group{Name: p, UUID: "u"}, nil
}
func (f *fakeBackend) TOTP(context.Context, string) (string, error) { return "123456", nil }
func (f *fakeBackend) Delete(context.Context, string) (bool, error) { return true, nil }
func (f *fakeBackend) Lock(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked = true
	return nil
}
func (f *fakeBackend) GeneratePassword(context.Context) ([]byte, error) { return []byte("gen"), nil }

// extension plays KeePassXC-Browser's side.
type extension struct {
	t        *testing.T
	s        *Session
	pub, sec *[32]byte
	host     *[32]byte
	clientID string
	idKey    string
	last     []byte // the last frame sent
}

func newExtension(t *testing.T, s *Session) *extension {
	pub, sec, _ := box.GenerateKey(rand.Reader)
	x := &extension{t: t, s: s, pub: pub, sec: sec, clientID: randomB64(24)}
	idPub, _, _ := box.GenerateKey(rand.Reader)
	x.idKey = base64.StdEncoding.EncodeToString(idPub[:])
	nonce := randomB64(24)
	r := x.send(map[string]any{"action": ActionChangePublicKeys, "publicKey": base64.StdEncoding.EncodeToString(pub[:]), "nonce": nonce, "clientID": x.clientID})
	if r["success"] != "true" || r["nonce"] != inc(nonce) {
		t.Fatalf("change-public-keys: %v", r)
	}
	k, _ := base64.StdEncoding.DecodeString(r["publicKey"].(string))
	x.host = new([32]byte)
	copy(x.host[:], k)
	return x
}

func randomB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func inc(nonce string) string {
	n, _ := decodeNonce(nonce)
	return encodeNonce(increment(n))
}

func (x *extension) send(m map[string]any) map[string]any {
	x.t.Helper()
	x.last, _ = json.Marshal(m)
	return x.raw(x.last)
}

func (x *extension) raw(frame []byte) map[string]any {
	x.t.Helper()
	out := x.s.Handle(context.Background(), frame)
	if out == nil {
		return nil
	}
	var r map[string]any
	if err := json.Unmarshal(out, &r); err != nil {
		x.t.Fatalf("the host sent %q: %v", out, err)
	}
	return r
}

// call sends an encrypted action and returns the decrypted answer, or the
// clear error reply.
func (x *extension) call(action string, msg map[string]any, extra ...string) map[string]any {
	x.t.Helper()
	msg["action"] = action
	plain, _ := json.Marshal(msg)
	nonce := randomB64(24)
	n, _ := decodeNonce(nonce)
	sealed := box.Seal(nil, plain, &n, x.host, x.sec)
	req := map[string]any{"action": action, "message": base64.StdEncoding.EncodeToString(sealed), "nonce": nonce, "clientID": x.clientID}
	for i := 0; i+1 < len(extra); i += 2 {
		req[extra[i]] = extra[i+1]
	}
	r := x.send(req)
	return x.open(r, inc(nonce))
}

func (x *extension) open(r map[string]any, wantNonce string) map[string]any {
	x.t.Helper()
	if r["message"] == nil {
		return r
	}
	if r["nonce"] != wantNonce {
		x.t.Fatalf("the answer's nonce is %v, want %s", r["nonce"], wantNonce)
	}
	sealed, _ := base64.StdEncoding.DecodeString(r["message"].(string))
	n, _ := decodeNonce(wantNonce)
	plain, ok := box.Open(nil, sealed, &n, x.host, x.sec)
	if !ok {
		x.t.Fatal("the answer does not open")
	}
	var m map[string]any
	json.Unmarshal(plain, &m)
	if m["nonce"] != wantNonce || m["success"] != "true" || m["version"] != Version {
		x.t.Fatalf("the answer's envelope: %v", m)
	}
	return m
}

func code(r map[string]any) string {
	c, _ := r["errorCode"].(string)
	return c
}

func TestTheSessionAssociatesThenServes(t *testing.T) {
	b := &fakeBackend{assocs: map[string]string{}, password: `pa"ss`}
	s := NewSession(b)
	defer s.Close()
	x := newExtension(t, s)

	if r := x.call(ActionGetDatabaseHash, map[string]any{}); r["hash"] != "hash1" {
		t.Fatalf("get-databasehash: %v", r)
	}
	// Before association, nothing of the vault's.
	if r := x.call(ActionGetLogins, map[string]any{"url": "https://example.com/"}); code(r) != "8" {
		t.Fatalf("get-logins unassociated: %v", r)
	}
	// Associating with a key other than the session's is refused.
	if r := x.call(ActionAssociate, map[string]any{"key": x.idKey, "idKey": x.idKey}); code(r) != "8" {
		t.Fatalf("associate with a foreign key: %v", r)
	}
	key := base64.StdEncoding.EncodeToString(x.pub[:])
	if r := x.call(ActionAssociate, map[string]any{"key": key, "idKey": x.idKey}); code(r) != "6" {
		t.Fatalf("a refused association: %v", r)
	}
	b.allow = true
	r := x.call(ActionAssociate, map[string]any{"key": key, "idKey": x.idKey})
	if r["id"] != "browser-1" || r["hash"] != "hash1" {
		t.Fatalf("associate: %v", r)
	}
	r = x.call(ActionGetLogins, map[string]any{"url": "https://example.com/", "keys": []map[string]string{{"id": "browser-1", "key": x.idKey}}})
	entries, _ := r["entries"].([]any)
	if r["count"] != float64(1) || len(entries) != 1 || entries[0].(map[string]any)["password"] != `pa"ss` {
		t.Fatalf("get-logins: %v", r)
	}
	if r := x.call(ActionGetLogins, map[string]any{"url": "https://example.com/", "keys": []map[string]string{{"id": "other", "key": x.idKey}}}); code(r) != "8" {
		t.Fatalf("get-logins with another database's keys: %v", r)
	}
	if r := x.call(ActionGetLogins, map[string]any{}); code(r) != "14" {
		t.Fatalf("get-logins without a URL: %v", r)
	}
	if r := x.call(ActionSetLogin, map[string]any{"url": "https://new.example/", "login": "bob", "password": "sécret\n"}); r["error"] != "success" {
		t.Fatalf("set-login: %v", r)
	}
	if len(b.saved) != 1 || string(b.saved[0].Password) != "sécret\n" || b.saved[0].Login != "bob" {
		t.Fatalf("saved %+v", b.saved)
	}
	if r := x.call(ActionSetLogin, map[string]any{"url": "https://new.example/", "uuid": "not-a-uuid"}); code(r) != "18" {
		t.Fatalf("set-login with a bad uuid: %v", r)
	}
	if r := x.call(ActionGetTOTP, map[string]any{"uuid": strings.Repeat("ab", 16)}); r["totp"] != "123456" {
		t.Fatalf("get-totp: %v", r)
	}
	if r := x.call(ActionGetDatabaseGroups, map[string]any{}); r["groups"].(map[string]any)["groups"].([]any)[0].(map[string]any)["name"] != "root" {
		t.Fatalf("get-database-groups: %v", r)
	}
	if r := x.call(ActionGeneratePassword, map[string]any{"requestID": "abcd1234"}, "requestID", "abcd1234"); r["password"] != "gen" {
		t.Fatalf("generate-password: %v", r)
	}
	for _, a := range []string{ActionRequestAutotype, ActionPasskeysGet, ActionPasskeysRegister, "no-such-action"} {
		if r := x.call(a, map[string]any{}); code(r) != "12" || r["action"] != a {
			t.Errorf("%s: %v", a, r)
		}
	}
	if r := x.call(ActionGetDatabaseEntries, map[string]any{}); code(r) != "19" {
		t.Errorf("get-database-entries: %v", r)
	}

	// A new session must prove its association again.
	y := newExtension(t, s)
	if r := y.call(ActionGetTOTP, map[string]any{"uuid": strings.Repeat("ab", 16)}); code(r) != "8" {
		t.Fatalf("a new session unassociated: %v", r)
	}
	if r := y.call(ActionTestAssociate, map[string]any{"id": "browser-1", "key": "wrong"}); code(r) != "8" {
		t.Fatalf("test-associate with a wrong key: %v", r)
	}
	if r := y.call(ActionTestAssociate, map[string]any{"id": "browser-1", "key": x.idKey}); r["id"] != "browser-1" {
		t.Fatalf("test-associate: %v", r)
	}
	// An association removed meanwhile ends the session's.
	b.mu.Lock()
	delete(b.assocs, "browser-1")
	b.mu.Unlock()
	if r := y.call(ActionGetTOTP, map[string]any{"uuid": strings.Repeat("ab", 16)}); code(r) != "8" {
		t.Fatalf("after the association was removed: %v", r)
	}
}

func TestTheSessionRefusesWhatIsNotSealedRight(t *testing.T) {
	b := &fakeBackend{assocs: map[string]string{}}
	s := NewSession(b)
	x := newExtension(t, s)

	x.call(ActionGetDatabaseHash, map[string]any{})
	good := x.last
	// A replay.
	if r := x.raw(good); code(r) != "4" {
		t.Fatalf("a replayed message: %v", r)
	}
	// A new message under a nonce already used.
	plain := []byte(`{"action":"get-databasehash"}`)
	var req map[string]string
	json.Unmarshal(good, &req)
	n, _ := decodeNonce(req["nonce"])
	again := s.Handle(context.Background(), mustJSON(map[string]any{"action": ActionGetDatabaseHash,
		"message": base64.StdEncoding.EncodeToString(box.Seal(nil, []byte(`{"action":"get-databasehash","x":1}`), &n, x.host, x.sec)),
		"nonce":   req["nonce"], "clientID": x.clientID}))
	if code(decode(again)) != "4" {
		t.Fatalf("a nonce used before: %s", again)
	}
	// One whose answer would reuse a nonce: the one just before a used one.
	var prev [24]byte
	copy(prev[:], n[:])
	for i := range prev {
		if prev[i] > 0 {
			prev[i]--
			break
		}
		prev[i] = 0xff
	}
	if increment(prev) != n {
		t.Fatal("test: prev is not n - 1")
	}
	before := s.Handle(context.Background(), mustJSON(map[string]any{"action": ActionGetDatabaseHash,
		"message": base64.StdEncoding.EncodeToString(box.Seal(nil, plain, &prev, x.host, x.sec)),
		"nonce":   encodeNonce(prev), "clientID": x.clientID}))
	if code(decode(before)) != "4" {
		t.Fatalf("a message whose answer reuses a nonce: %s", before)
	}
	// The host's own answer sent back: crypto_box's key is the same both
	// ways, so it would open.
	fresh := randomB64(24)
	n, _ = decodeNonce(fresh)
	sealed := box.Seal(nil, plain, &n, x.host, x.sec)
	out := s.Handle(context.Background(), mustJSON(map[string]any{"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(sealed), "nonce": fresh, "clientID": x.clientID}))
	var ans map[string]string
	json.Unmarshal(out, &ans)
	reflected := mustJSON(map[string]any{"action": ActionGetDatabaseHash, "message": ans["message"], "nonce": ans["nonce"], "clientID": x.clientID})
	if r := x.raw(reflected); code(r) != "4" {
		t.Fatalf("the host's answer sent back as a request: %v", r)
	}

	for name, req := range map[string]map[string]any{
		"a short nonce":   {"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(sealed), "nonce": randomB64(23), "clientID": x.clientID},
		"no nonce":        {"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(sealed), "clientID": x.clientID},
		"a wrong nonce":   {"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(sealed), "nonce": randomB64(24), "clientID": x.clientID},
		"not base64":      {"action": ActionGetDatabaseHash, "message": "!!!", "nonce": randomB64(24), "clientID": x.clientID},
		"a short message": {"action": ActionGetDatabaseHash, "message": "AAAA", "nonce": randomB64(24), "clientID": x.clientID},
		"another key":     {"action": ActionGetDatabaseHash, "message": sealWith(x.host, plain), "nonce": fresh, "clientID": x.clientID},
		"flipped bit":     {"action": ActionGetDatabaseHash, "message": flip(sealed), "nonce": fresh, "clientID": x.clientID},
	} {
		if r := x.send(req); code(r) != "4" {
			t.Errorf("%s: %v", name, r)
		}
	}
	// Another client ID has no keys here.
	if r := x.send(map[string]any{"action": ActionGetDatabaseHash, "message": "x", "nonce": randomB64(24), "clientID": "someone else"}); code(r) != "3" {
		t.Errorf("an unknown client: %v", r)
	}
	// The sealed action must be the one named outside.
	if r := x.call(ActionGetDatabaseHash, map[string]any{}); r["hash"] == nil {
		t.Fatalf("hash: %v", r)
	}
	plain = []byte(`{"action":"lock-database"}`)
	fresh = randomB64(24)
	n, _ = decodeNonce(fresh)
	if r := x.send(map[string]any{"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(box.Seal(nil, plain, &n, x.host, x.sec)), "nonce": fresh, "clientID": x.clientID}); code(r) != "12" {
		t.Errorf("a mismatched action: %v", r)
	}
	// Sealed nonsense.
	for _, p := range []string{`[1,2]`, `null`, `not json`} {
		fresh = randomB64(24)
		n, _ = decodeNonce(fresh)
		if r := x.send(map[string]any{"action": ActionGetDatabaseHash, "message": base64.StdEncoding.EncodeToString(box.Seal(nil, []byte(p), &n, x.host, x.sec)), "nonce": fresh, "clientID": x.clientID}); code(r) != "4" {
			t.Errorf("sealed %s: %v", p, r)
		}
	}
	// Frames that are not messages.
	for _, f := range []string{`not json`, `[]`, `null`, `{}`, `"x"`} {
		if r := x.raw([]byte(f)); code(r) != "13" {
			t.Errorf("frame %s: %v", f, r)
		}
	}
	if r := x.raw([]byte(`{"action":"get-databasehash"}`)); r != nil {
		t.Errorf("a message from no client was answered: %v", r)
	}
	if r := x.send(map[string]any{"action": ActionChangePublicKeys, "publicKey": "short", "nonce": randomB64(24), "clientID": "c"}); code(r) != "3" {
		t.Errorf("change-public-keys with a bad key: %v", r)
	}

	// A locked vault answers nothing but change-public-keys; triggerUnlock
	// may open it.
	b.locked = true
	if r := x.call(ActionGetDatabaseHash, map[string]any{}); code(r) != "1" {
		t.Fatalf("locked: %v", r)
	}
	if r := x.call(ActionGetDatabaseHash, map[string]any{}, "triggerUnlock", "true"); r["hash"] != "hash1" {
		t.Fatalf("triggerUnlock: %v", r)
	}

	// New keys end the old ones, and the association with them.
	s.Close()
	if r := x.call(ActionGetDatabaseHash, map[string]any{}); code(r) != "3" {
		t.Fatalf("after Close: %v", r)
	}
}

func TestNoticesAreInTheClear(t *testing.T) {
	if string(Notice(ActionDatabaseLocked)) != `{"action":"database-locked"}` {
		t.Fatalf("%s", Notice(ActionDatabaseLocked))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func decode(b []byte) map[string]any {
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func sealWith(host *[32]byte, plain []byte) string {
	_, other, _ := box.GenerateKey(rand.Reader)
	var n [24]byte
	return base64.StdEncoding.EncodeToString(box.Seal(nil, plain, &n, host, other))
}

func flip(sealed []byte) string {
	c := bytes.Clone(sealed)
	c[len(c)-1] ^= 1
	return base64.StdEncoding.EncodeToString(c)
}
