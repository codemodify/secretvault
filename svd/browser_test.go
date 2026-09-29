package svd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The browser face as the daemon serves it; cmd/secretvault's tests play
// the extension through the relay, end to end.

func TestOnlyTheRelayOpensABrowserSessionForTheBrowserBehindIt(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var launcherErr error
	h.opts.Launcher = func(relay *svpeer.Process) (*svpeer.Process, error) {
		mu.Lock()
		defer mu.Unlock()
		if launcherErr != nil {
			return nil, launcherErr
		}
		return &svpeer.Process{PID: 777, Exe: "/usr/bin/firefox", SystemOwned: true}, nil
	}
	h.restart()
	h.setup()

	// A program that is not secretvault's own cannot be the relay.
	evil := h.connect("/home/u/evil", nil)
	if err := evil.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{}, nil); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a stranger opened a browser session: %v", err)
	}
	var e *svrpc.Error
	if err := evil.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{}`)}, nil); !errors.As(err, &e) || e.Code != svrpc.CodeInvalidRequest {
		t.Fatalf("a message with no session: %v", err)
	}

	// The relay gets a session for the browser that started it, and
	// hears of the vault as the extension does, not as a client.
	frames := make(chan []byte, 8)
	h.procs <- &svpeer.Process{PID: 4242, Exe: "/usr/bin/secretvault", SystemOwned: true}
	relay, err := secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true,
		OnEvent: func(method string, _ svrpc.VaultEvent) { t.Errorf("the relay was sent %s", method) },
		OnNotify: func(method string, params json.RawMessage) {
			var f svrpc.BrowserFrame
			if method == svrpc.EBrowserFrame && json.Unmarshal(params, &f) == nil {
				frames <- f.Frame
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	var opened svrpc.BrowserOpenResult
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Origin: "keepassxc-browser@keepassxc.org"}, &opened); err != nil {
		t.Fatal(err)
	}
	if opened.Browser != "firefox (/usr/bin/firefox)" || opened.Vault != "personal" {
		t.Fatalf("opened %+v", opened)
	}
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{}, nil); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a second session on one connection: %v", err)
	}
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 24))
	msg, _ := json.Marshal(map[string]string{"action": "change-public-keys", "publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"nonce": nonce, "clientID": "c"})
	var reply svrpc.BrowserFrame
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: msg}, &reply); err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	json.Unmarshal(reply.Frame, &keys)
	if keys["success"] != "true" || keys["publicKey"] == "" || keys["version"] != svbrowser.Version {
		t.Fatalf("change-public-keys through the daemon: %s", reply.Frame)
	}

	cli := h.connect("/usr/bin/secretvault", &scripted{})
	cli.Lock(ctx(t), "", true)
	select {
	case f := <-frames:
		if string(f) != `{"action":"database-locked"}` {
			t.Fatalf("the relay was sent %s", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the extension was not told the vault locked")
	}

	// A relay whose parent cannot be named gets nothing.
	mu.Lock()
	launcherErr = errors.New("process 4242 has no parent of its own")
	mu.Unlock()
	orphan := h.connect("/usr/bin/secretvault", nil)
	if err := orphan.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{}, nil); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("an orphaned relay: %v", err)
	}
}

func TestAssociationsAreNamedForTheBrowser(t *testing.T) {
	for p, want := range map[*svpeer.Process]string{
		{Exe: "/usr/lib/firefox/firefox"}:                 `^firefox-[0-9a-f]{4}$`,
		{Exe: `/opt/Google/Chrome/Chrome.exe`}:            `^chrome-[0-9a-f]{4}$`,
		{Flatpak: "org.chromium.Chromium", Exe: "/app/x"}: `^chromium-[0-9a-f]{4}$`,
		{Snap: "firefox"}:                                 `^firefox-[0-9a-f]{4}$`,
		{PID: 3}:                                          `^browser-[0-9a-f]{4}$`,
		{Exe: "/usr/bin/some browser (beta)"}:             `^somebrowserbeta-[0-9a-f]{4}$`,
	} {
		if got := associationName(p, nil); !regexp.MustCompile(want).MatchString(got) {
			t.Errorf("associationName(%+v) = %q", *p, got)
		}
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
