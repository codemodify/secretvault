package svext

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestHostsComeInTheirASCIIForm(t *testing.T) {
	// What node's url.domainToASCII (and so the browsers) make of them.
	for in, want := range map[string]string{
		"bücher.example":   "xn--bcher-kva.example",
		"münchen.de":       "xn--mnchen-3ya.de",
		"食狮.公司.cn":         "xn--85x722f.xn--55qx5d.cn",
		"www.食狮.公司.cn":     "www.xn--85x722f.xn--55qx5d.cn",
		"ПРИМЕР.рф":        "xn--e1afmkfd.xn--p1ai",
		"例え.テスト":           "xn--r8jz45g.xn--zckzah",
		"ü":                "xn--tda",
		"GitHub.COM.":      "github.com",
		"xn--bcher-kva.de": "xn--bcher-kva.de",
	} {
		if got, ok := asciiHost(in); !ok || got != want {
			t.Errorf("asciiHost(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", ".", "a..b", "a b.com", "exa\x00mple.com", strings.Repeat("a", 64) + ".com", "a/b.com", "a%2e.com"} {
		if got, ok := asciiHost(bad); ok {
			t.Errorf("asciiHost(%q) = %q, not refused", bad, got)
		}
	}
}

func TestThePublicSuffixListDecides(t *testing.T) {
	l := Suffixes()
	if l.Len() < 5000 {
		t.Fatalf("the bundled list has %d rules", l.Len())
	}
	// The list's own test vectors (publicsuffix.org's tests.txt), and its
	// private section.
	for host, want := range map[string]string{
		"com":                           "",
		"example.com":                   "example.com",
		"b.example.com":                 "example.com",
		"a.b.example.com":               "example.com",
		"uk.com":                        "",
		"example.uk.com":                "example.uk.com",
		"b.example.uk.com":              "example.uk.com",
		"test.ac":                       "test.ac",
		"jp":                            "",
		"test.jp":                       "test.jp",
		"www.test.jp":                   "test.jp",
		"ac.jp":                         "",
		"test.ac.jp":                    "test.ac.jp",
		"kyoto.jp":                      "",
		"test.kyoto.jp":                 "test.kyoto.jp",
		"ide.kyoto.jp":                  "",
		"b.ide.kyoto.jp":                "b.ide.kyoto.jp",
		"a.b.ide.kyoto.jp":              "b.ide.kyoto.jp",
		"c.kobe.jp":                     "",
		"b.c.kobe.jp":                   "b.c.kobe.jp",
		"a.b.c.kobe.jp":                 "b.c.kobe.jp",
		"city.kobe.jp":                  "city.kobe.jp",
		"www.city.kobe.jp":              "city.kobe.jp",
		"ck":                            "",
		"test.ck":                       "",
		"b.test.ck":                     "b.test.ck",
		"a.b.test.ck":                   "b.test.ck",
		"www.ck":                        "www.ck",
		"www.www.ck":                    "www.ck",
		"us":                            "",
		"test.us":                       "test.us",
		"www.test.us":                   "test.us",
		"ak.us":                         "",
		"test.ak.us":                    "test.ak.us",
		"k12.ak.us":                     "",
		"test.k12.ak.us":                "test.k12.ak.us",
		"xn--85x722f.com.cn":            "xn--85x722f.com.cn",
		"xn--55qx5d.cn":                 "",
		"xn--85x722f.xn--55qx5d.cn":     "xn--85x722f.xn--55qx5d.cn",
		"www.xn--85x722f.xn--55qx5d.cn": "xn--85x722f.xn--55qx5d.cn",
		"shishi.xn--55qx5d.cn":          "shishi.xn--55qx5d.cn",
		"co.uk":                         "",
		"example.co.uk":                 "example.co.uk",
		"www.example.co.uk":             "example.co.uk",
		"github.io":                     "",
		"alice.github.io":               "alice.github.io",
		"www.alice.github.io":           "alice.github.io",
		"example.notarealtld":           "example.notarealtld",
		"localhost":                     "",
		"127.0.0.1":                     "",
		"::1":                           "",
	} {
		if got := l.RegistrableDomain(host); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

func origin(t *testing.T, s string) Origin {
	t.Helper()
	o, err := ParseOrigin(s)
	if err != nil {
		t.Fatalf("ParseOrigin(%q): %v", s, err)
	}
	return o
}

func TestOriginsHaveOneSpelling(t *testing.T) {
	for _, ok := range []string{"https://github.com", "http://localhost:8080", "https://xn--bcher-kva.example", "http://[::1]:3000", "https://10.0.0.1", "https://a.b.c.example:8443"} {
		if o, err := ParseOrigin(ok); err != nil || o.String() != ok {
			t.Errorf("ParseOrigin(%q) = %v, %v", ok, o, err)
		}
	}
	for _, bad := range []string{
		"", "github.com", "https://github.com/", "https://github.com/login", "https://github.com?x", "https://github.com#x",
		"https://GitHub.com", "https://github.com:443", "http://github.com:80", "https://user@github.com", "ftp://github.com",
		"file:///etc/passwd", "javascript:alert(1)", "moz-extension://abc", "chrome-extension://abc", "data:text/html,x",
		"https://bücher.example", "https://github.com:0", "https://github.com:70000", "https://", "https://a b.com",
		"https://" + strings.Repeat("a.", 600) + "com",
	} {
		if o, err := ParseOrigin(bad); err == nil {
			t.Errorf("ParseOrigin(%q) = %v, not refused", bad, o)
		}
	}
}

func TestLoginsMatchByOrigin(t *testing.T) {
	l := Suffixes()
	for _, c := range []struct {
		stored, page string
		want         Match
	}{
		{"https://github.com", "https://github.com", MatchHost},
		{"github.com", "https://github.com", MatchHost},
		{"https://github.com/login?next=/", "https://github.com", MatchHost},
		{"https://GitHub.com./", "https://github.com", MatchHost},
		{"https://github.com", "https://gist.github.com", MatchSite},
		{"https://login.example.co.uk", "https://www.example.co.uk", MatchSite},
		{"https://co.uk", "https://example.co.uk", MatchNone},
		{"https://example.co.uk", "https://other.co.uk", MatchNone},
		{"https://alice.github.io", "https://bob.github.io", MatchNone},
		{"https://alice.github.io", "https://www.alice.github.io", MatchSite},
		{"https://github.com", "https://evilgithub.com", MatchNone},
		{"https://github.com", "https://github.com.evil.example", MatchNone},
		// The scheme: never https to http; http upgraded to https.
		{"https://github.com", "http://github.com", MatchNone},
		{"http://github.com", "https://github.com", MatchHost},
		{"http://github.com", "http://github.com", MatchHost},
		{"http://github.com:8080", "https://github.com:8080", MatchNone},
		// The port.
		{"https://github.com:8443", "https://github.com:8443", MatchHost},
		{"https://github.com:8443", "https://github.com", MatchNone},
		{"https://github.com", "https://github.com:8443", MatchNone},
		{"http://localhost:3000", "http://localhost:3000", MatchHost},
		{"http://localhost", "http://localhost:3000", MatchNone},
		// Addresses and one-label names only fit themselves.
		{"https://10.0.0.1", "https://10.0.0.1", MatchHost},
		{"https://10.0.0.2", "https://10.0.0.1", MatchNone},
		{"http://intranet", "http://wiki.intranet", MatchNone},
		{"http://[::1]:3000", "http://[::1]:3000", MatchHost},
		// Names stored as people read them.
		{"https://bücher.example/", "https://xn--bcher-kva.example", MatchHost},
		{"https://shop.食狮.公司.cn", "https://www.xn--85x722f.xn--55qx5d.cn", MatchSite},
		// What is no URL fits nothing.
		{"", "https://github.com", MatchNone},
		{"*.github.com", "https://github.com", MatchNone},
		{"ftp://github.com", "https://github.com", MatchNone},
		{"javascript:alert(1)//github.com", "https://github.com", MatchNone},
		{"https://user:pw@github.com", "https://github.com", MatchHost},
	} {
		if got := MatchURL(l, c.stored, origin(t, c.page)); got != c.want {
			t.Errorf("MatchURL(%q, %s) = %v, want %v", c.stored, c.page, got, c.want)
		}
	}
}

func frame(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	return b
}

func TestRequestsAreCheckedWhole(t *testing.T) {
	good := map[string]any{"v": 1, "id": "r1", "op": "save", "vault": "personal", "origin": "https://github.com",
		"username": "ada", "password": "hunter2 \"\\ é", "login": strings.Repeat("ab", 16), "title": "GitHub"}
	r, err := ParseRequest(frame(good))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "r1" || r.Op != OpSave || r.Vault != "personal" || r.Origin.Host != "github.com" || r.Username != "ada" ||
		string(r.Password) != "hunter2 \"\\ é" || r.Title != "GitHub" || r.Login != strings.Repeat("ab", 16) {
		t.Fatalf("parsed %+v", r)
	}
	g, err := ParseRequest(frame(map[string]any{"v": 1, "id": "g", "op": "generate"}))
	if err != nil || g.Length != DefaultGenerate || !g.Symbols {
		t.Fatalf("generate's defaults: %+v %v", g, err)
	}

	with := func(k string, v any) []byte {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return frame(m)
	}
	for name, c := range map[string]struct {
		frame []byte
		code  string
	}{
		"not JSON":             {[]byte("not json"), CodeBadRequest},
		"an array":             {[]byte(`[1]`), CodeBadRequest},
		"null":                 {[]byte(`null`), CodeBadRequest},
		"two objects":          {[]byte(`{"v":1,"id":"a","op":"state"}{}`), CodeBadRequest},
		"a stray brace after":  {[]byte(`{"v":1,"id":"a","op":"state"}}`), CodeBadRequest},
		"a stray bracket":      {[]byte(`{"v":1,"id":"a","op":"state"}]`), CodeBadRequest},
		"a lone surrogate":     {[]byte(`{"v":1,"id":"a","op":"check","origin":"https://a.example","password":"x\ud800"}`), CodeBadRequest},
		"too large":            {bytes.Repeat([]byte(" "), MaxRequest+1), CodeTooLarge},
		"no version":           {with("v", nil), CodeBadRequest},
		"version 2":            {with("v", 2), CodeBadRequest},
		"version as a string":  {with("v", "1"), CodeBadRequest},
		"no id":                {with("id", nil), CodeBadRequest},
		"an id with a space":   {with("id", "a b"), CodeBadRequest},
		"a long id":            {with("id", strings.Repeat("a", MaxID+1)), CodeBadRequest},
		"an unknown op":        {with("op", "dump"), CodeUnknownOp},
		"an unknown member":    {with("evil", true), CodeBadRequest},
		"no origin":            {with("origin", nil), CodeBadRequest},
		"a page URL":           {with("origin", "https://github.com/login"), CodeBadRequest},
		"a file origin":        {with("origin", "file:///"), CodeBadRequest},
		"an extension origin":  {with("origin", "moz-extension://x"), CodeBadRequest},
		"origin a number":      {with("origin", 7), CodeBadRequest},
		"no password":          {with("password", nil), CodeBadRequest},
		"an empty password":    {with("password", ""), CodeBadRequest},
		"a long password":      {with("password", strings.Repeat("p", MaxPassword+1)), CodeBadRequest},
		"password a number":    {with("password", 7), CodeBadRequest},
		"a long username":      {with("username", strings.Repeat("u", MaxUsername+1)), CodeBadRequest},
		"a username with NUL":  {with("username", "a\x00b"), CodeBadRequest},
		"a title with newline": {with("title", "a\nb"), CodeBadRequest},
		"a long vault":         {with("vault", strings.Repeat("v", MaxVault+1)), CodeBadRequest},
		"a bad login":          {with("login", "../../etc"), CodeBadRequest},
		"an upper-case login":  {with("login", strings.Repeat("AB", 16)), CodeBadRequest},
		"a member of another":  {frame(map[string]any{"v": 1, "id": "x", "op": "state", "origin": "https://a.example"}), CodeBadRequest},
		"fill without login":   {frame(map[string]any{"v": 1, "id": "x", "op": "fill", "origin": "https://a.example"}), CodeBadRequest},
		"a short generate":     {frame(map[string]any{"v": 1, "id": "x", "op": "generate", "length": 4}), CodeBadRequest},
		"a fractional length":  {[]byte(`{"v":1,"id":"x","op":"generate","length":24.5}`), CodeBadRequest},
		"a null length":        {[]byte(`{"v":1,"id":"x","op":"generate","length":null}`), CodeBadRequest},
		"symbols as a string":  {frame(map[string]any{"v": 1, "id": "x", "op": "generate", "symbols": "yes"}), CodeBadRequest},
		"confirm as a string":  {frame(map[string]any{"v": 1, "id": "x", "op": "fill", "origin": "https://a.example", "login": strings.Repeat("ab", 16), "confirm": "yes"}), CodeBadRequest},
		"confirm on a save":    {with("confirm", true), CodeBadRequest},
	} {
		_, err := ParseRequest(c.frame)
		if !IsCode(err, c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	// A refusal answers the request's id when it had one.
	r, err = ParseRequest(with("origin", "https://x.example/"))
	if r == nil || r.ID != "r1" || err == nil {
		t.Fatalf("the id of a refused request: %+v %v", r, err)
	}
	var ans map[string]any
	json.Unmarshal(Refusal(r.ID, err), &ans)
	if ans["id"] != "r1" || ans["ok"] != false || ans["error"] != CodeBadRequest || ans["v"] != float64(1) {
		t.Fatalf("the refusal: %v", ans)
	}
}

// backend is a Backend of the test's own.
type backend struct {
	locked  bool
	asked   []string
	refuse  bool
	vaultOf string
}

func (b *backend) Hello(context.Context) (Hello, error) {
	return Hello{Browser: "firefox (/usr/lib/firefox/firefox)", Version: "test"}, nil
}

func (b *backend) Vaults(context.Context) ([]Vault, error) {
	return []Vault{{Name: "b"}, {Name: "work", Locked: b.locked}, {Name: "personal", Default: true}}, nil
}

func (b *backend) Unlock(_ context.Context, vault string) error {
	b.locked = false
	return nil
}

func (b *backend) Lock(_ context.Context, vault string) error {
	b.locked = true
	return nil
}

func (b *backend) Logins(_ context.Context, vault string, o Origin) ([]Login, error) {
	b.vaultOf = vault
	if b.locked {
		return nil, Errorf(CodeLocked, "vault %q is locked", vault)
	}
	return []Login{{ID: strings.Repeat("0", 32), Title: "GitHub", Username: "ada", URL: "https://github.com", Match: "host"}}, nil
}

func (b *backend) Fill(_ context.Context, vault string, o Origin, login string, confirm bool) (Credentials, error) {
	if b.refuse {
		return Credentials{}, Errorf(CodeDenied, "the person said no")
	}
	return Credentials{Username: "ada", Password: []byte(`hun"ter2`), TOTP: "123456"}, nil
}

func (b *backend) TOTP(context.Context, string, Origin, string, bool) (string, error) { return "", nil }

func (b *backend) Check(_ context.Context, vault string, o Origin, username string, password []byte) (CheckResult, error) {
	if string(password) == "hunter2" {
		return CheckResult{Status: StatusKnown, Login: strings.Repeat("0", 32)}, nil
	}
	return CheckResult{Status: StatusNew}, nil
}

func (b *backend) Save(_ context.Context, vault string, o Origin, s SaveLogin) (string, bool, error) {
	return strings.Repeat("1", 32), s.Login == "", nil
}

func ask(t *testing.T, s *Session, m map[string]any) map[string]any {
	t.Helper()
	m["v"] = 1
	if m["id"] == nil {
		m["id"] = "t"
	}
	var out map[string]any
	if err := json.Unmarshal(s.Handle(context.Background(), frame(m)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestASessionAnswersFromItsBackend(t *testing.T) {
	b := &backend{}
	s := NewSession(b)
	if r := ask(t, s, map[string]any{"op": "hello", "extension": "0.1.0"}); r["ok"] != true || r["protocol"] != float64(1) || r["browser"] == "" {
		t.Fatalf("hello: %v", r)
	}
	r := ask(t, s, map[string]any{"op": "state"})
	vs, _ := r["vaults"].([]any)
	if len(vs) != 3 || vs[0].(map[string]any)["name"] != "personal" || vs[1].(map[string]any)["name"] != "b" {
		t.Fatalf("the default vault first: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "lock", "vault": "work"}); r["ok"] != true || !b.locked {
		t.Fatalf("lock: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "logins", "vault": "work", "origin": "https://github.com"}); r["ok"] != false || r["error"] != CodeLocked || r["id"] != "t" {
		t.Fatalf("logins while locked: %v", r)
	}
	ask(t, s, map[string]any{"op": "unlock", "vault": "work"})
	r = ask(t, s, map[string]any{"op": "logins", "vault": "work", "origin": "https://github.com"})
	if ls, _ := r["logins"].([]any); r["ok"] != true || len(ls) != 1 || r["origin"] != "https://github.com" || b.vaultOf != "work" {
		t.Fatalf("logins: %v", r)
	}
	if _, has := r["logins"].([]any)[0].(map[string]any)["password"]; has {
		t.Fatal("logins handed out a password")
	}
	r = ask(t, s, map[string]any{"op": "fill", "origin": "https://github.com", "login": strings.Repeat("0", 32), "id": "f1"})
	if r["id"] != "f1" || r["username"] != "ada" || r["password"] != `hun"ter2` || r["totp"] != "123456" {
		t.Fatalf("fill: %v", r)
	}
	b.refuse = true
	if r := ask(t, s, map[string]any{"op": "fill", "origin": "https://github.com", "login": strings.Repeat("0", 32)}); r["error"] != CodeDenied || r["password"] != nil {
		t.Fatalf("a refused fill: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "totp", "origin": "https://github.com", "login": strings.Repeat("0", 32)}); r["error"] != CodeNotFound {
		t.Fatalf("totp without a key: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "check", "origin": "https://github.com", "username": "ada", "password": "hunter2"}); r["status"] != StatusKnown || r["login"] == nil {
		t.Fatalf("check: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "save", "origin": "https://github.com", "username": "ada", "password": "x"}); r["created"] != true || r["login"] != strings.Repeat("1", 32) {
		t.Fatalf("save: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "generate"}); r["error"] != CodeUnknownOp {
		t.Fatalf("generate in the daemon: %v", r)
	}
	if r := ask(t, s, map[string]any{"op": "logins", "origin": "https://github.com/"}); r["error"] != CodeBadRequest {
		t.Fatalf("a bad request: %v", r)
	}

	g := GenerateReply(&Request{ID: "g", Op: OpGenerate, Length: 30, Symbols: false}, func(n int, sym bool) ([]byte, error) {
		if n != 30 || sym {
			return nil, errors.New("wrong settings")
		}
		return bytes.Repeat([]byte("x"), n), nil
	})
	var gr map[string]any
	json.Unmarshal(g, &gr)
	if gr["password"] != strings.Repeat("x", 30) || gr["id"] != "g" {
		t.Fatalf("generate: %s", g)
	}
}

func TestEventsAreVersioned(t *testing.T) {
	var e map[string]any
	json.Unmarshal(VaultEvent("personal", true), &e)
	if e["v"] != float64(1) || e["event"] != "vault" || e["vault"] != "personal" || e["locked"] != true {
		t.Fatalf("the vault event: %v", e)
	}
	json.Unmarshal(DownEvent("no daemon"), &e)
	if e["event"] != "down" || e["error"] != CodeNotRunning {
		t.Fatalf("the down event: %v", e)
	}
}
