package svd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The secretvault extension's session as the daemon opens it;
// cmd/secretvault's tests play the extension through the host, end to end.

// onlyOnceOrDeny reports whether a prompt asked every time offers nothing
// to remember, and says no by default: its first choice (a plain
// pinentry's OK, Enter) is Deny.
func onlyOnceOrDeny(cs []svrpc.Choice) bool {
	if len(cs) == 0 || cs[0].ID != svrpc.ChoiceDeny {
		return false
	}
	allows := false
	for _, c := range cs {
		switch c.ID {
		case svrpc.ChoiceOnce:
			allows = true
		case svrpc.ChoiceDeny:
		default:
			return false
		}
	}
	return allows
}

func TestTheExtensionsSessionIsForTheExtensionAlone(t *testing.T) {
	h := newHarness(t)
	h.opts.Launcher = func(*svpeer.Process) (*svpeer.Process, error) {
		return &svpeer.Process{PID: 777, Exe: "/usr/bin/firefox", SystemOwned: true}, nil
	}
	h.restart()
	h.setup()

	evil := h.connect("/home/u/evil", nil)
	if err := evil.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.FirefoxID}, nil); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a stranger opened the extension's session: %v", err)
	}
	relay := h.connect("/usr/bin/secretvault", nil)
	var e *svrpc.Error
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: "something/9", Origin: svext.FirefoxID}, nil); !errors.As(err, &e) || e.Code != svrpc.CodeInvalidParams {
		t.Fatalf("a protocol nobody speaks: %v", err)
	}
	// A session names its protocol: there is no other.
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Origin: svext.FirefoxID}, nil); !errors.As(err, &e) || e.Code != svrpc.CodeInvalidParams {
		t.Fatalf("a session naming no protocol: %v", err)
	}
	for _, other := range []string{"evil@example.com", "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", "", "chrome-extension://" + svext.ChromeID} {
		if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: other}, nil); !errors.Is(err, svrpc.ErrDenied) {
			t.Fatalf("the extension's protocol for %q: %v", other, err)
		}
	}
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{"v":1,"id":"a","op":"state"}`)}, nil); !errors.As(err, &e) || e.Code != svrpc.CodeInvalidRequest {
		t.Fatalf("a message with no session: %v", err)
	}
	var opened svrpc.BrowserOpenResult
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.ChromeOrigin}, &opened); err != nil {
		t.Fatal(err)
	}
	if opened.Browser != "firefox (/usr/bin/firefox)" {
		t.Fatalf("opened %+v", opened)
	}
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.ChromeOrigin}, nil); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a second session on one connection: %v", err)
	}
	var reply svrpc.BrowserFrame
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{"v":1,"id":"a","op":"state"}`)}, &reply); err != nil {
		t.Fatal(err)
	}
	var st struct {
		OK     bool          `json:"ok"`
		Vaults []svext.Vault `json:"vaults"`
	}
	if json.Unmarshal(reply.Frame, &st) != nil || !st.OK || len(st.Vaults) != 1 || st.Vaults[0].Name != "personal" || !st.Vaults[0].Default {
		t.Fatalf("state: %s", reply.Frame)
	}
	// Its frames are the extension's protocol, and nothing else.
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{"action":"get-logins"}`)}, &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Frame), `"error":"bad-request"`) {
		t.Fatalf("a message of another protocol: %s", reply.Frame)
	}
}

// A host whose parent cannot be named gets nothing.
func TestAnOrphanedHostOpensNoSession(t *testing.T) {
	h := newHarness(t)
	h.opts.Launcher = func(*svpeer.Process) (*svpeer.Process, error) {
		return nil, errors.New("process 4242 has no parent of its own")
	}
	h.restart()
	h.setup()
	orphan := h.connect("/usr/bin/secretvault", nil)
	if err := orphan.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.FirefoxID}, nil); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("an orphaned host: %v", err)
	}
}

// A vault made when secretvault served another browser extension
// holds its association records: they are only records of a kind nothing
// reads now, and the vault opens and serves the extension as any other.
func TestAVaultWithOldBrowserAssociationsStillOpens(t *testing.T) {
	h := newHarness(t)
	h.opts.Launcher = func(*svpeer.Process) (*svpeer.Process, error) {
		return &svpeer.Process{PID: 777, Exe: "/usr/bin/firefox", SystemOwned: true}, nil
	}
	h.restart()
	h.setup()
	mv, err := h.d.vault("")
	if err != nil {
		t.Fatal(err)
	}
	old := map[string]any{"device": h.d.svOpts.Device, "name": "firefox-3f2a", "key": "AAAA", "identity": "path:/usr/bin/firefox",
		"program": "firefox", "extension": "other-extension@example.org", "created": "2026-09-30T10:00:00Z"}
	if _, err := mv.v.PutRecord("browser-association", svformat.ID{}, old); err != nil {
		t.Fatal(err)
	}
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	if err := cli.Lock(ctx(t), "", true); err != nil {
		t.Fatal(err)
	}
	h.restart()
	cli = h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: "passphrase", Secret: append([]byte(nil), pass...)}); err != nil {
		t.Fatalf("a vault holding old association records: %v", err)
	}
	if _, err := cli.Put(ctx(t), "", login("web/github.com", "pw")); err != nil {
		t.Fatal(err)
	}
	relay := h.connect("/usr/bin/secretvault", nil)
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.FirefoxID}, nil); err != nil {
		t.Fatal(err)
	}
	var reply svrpc.BrowserFrame
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{"v":1,"id":"a","op":"state"}`)}, &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Frame), `"ok":true`) || !strings.Contains(string(reply.Frame), `"locked":false`) {
		t.Fatalf("state: %s", reply.Frame)
	}
}

func TestLoginsAreFoundByTheirURLFieldsAndAttributes(t *testing.T) {
	it := login("web/x", "p")
	it.Fields = append(it.Fields,
		svrpc.Field{Name: "url", Type: "text", Value: []byte("https://a.example")},
		svrpc.Field{Name: "url2", Type: "url", Value: []byte("https://b.example")},
		svrpc.Field{Name: "url (3)", Type: "text", Value: []byte("https://c.example")},
		svrpc.Field{Name: "homepage", Type: "url", Value: []byte("https://d.example")},
		svrpc.Field{Name: "urlish", Type: "text", Value: []byte("https://not.example")},
		svrpc.Field{Name: "notes", Type: "text", Value: []byte("https://not.example")})
	it.Attrs = map[string]string{"origin_url": "https://e.example", "service": "https://not.example"}
	ci := fromItem(it)
	got := map[string]bool{}
	for _, u := range loginURLs(&ci) {
		got[u] = true
	}
	for _, want := range []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example", "https://e.example"} {
		if !got[want] {
			t.Errorf("%s was not taken as a URL", want)
		}
	}
	if got["https://not.example"] || len(got) != 5 {
		t.Errorf("URLs: %v", got)
	}
}
