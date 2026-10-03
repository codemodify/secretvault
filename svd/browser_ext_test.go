package svd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svext"
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
	for _, other := range []string{"keepassxc-browser@keepassxc.org", "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", "", "chrome-extension://" + svext.ChromeID} {
		if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: other}, nil); !errors.Is(err, svrpc.ErrDenied) {
			t.Fatalf("the extension's protocol for %q: %v", other, err)
		}
	}
	// Nor does KeePassXC-Browser's protocol serve any other extension.
	for _, other := range []string{"evil@example.com", "chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh/", "", svext.FirefoxID, svext.ChromeOrigin} {
		if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Origin: other}, nil); !errors.Is(err, svrpc.ErrDenied) {
			t.Fatalf("KeePassXC-Browser's protocol for %q: %v", other, err)
		}
	}
	var opened svrpc.BrowserOpenResult
	if err := relay.Call(ctx(t), svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Protocol: svext.Protocol, Origin: svext.ChromeOrigin}, &opened); err != nil {
		t.Fatal(err)
	}
	if opened.Browser != "firefox (/usr/bin/firefox)" {
		t.Fatalf("opened %+v", opened)
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
	// Its frames are the extension's protocol, not KeePassXC's.
	if err := relay.Call(ctx(t), svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: []byte(`{"action":"change-public-keys"}`)}, &reply); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reply.Frame), `"error":"bad-request"`) {
		t.Fatalf("a KeePassXC message: %s", reply.Frame)
	}
}
