//go:build linux

package svd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// askPortal plays xdg-desktop-portal: it asks the backend for an app's
// secret through a pipe, and returns the response and what came down it.
func askPortal(t *testing.T, h *ssHarness, appID string) (uint32, []byte, error) {
	t.Helper()
	caller, err := svdbus.ConnectSession()
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	reply, err := caller.Call(ctx(t), h.bus.UniqueName(), portalPath, ifPortal, "RetrieveSecret",
		svdbus.ObjectPath("/org/freedesktop/portal/desktop/request/1_1/t"), appID, svdbus.UnixFD(w.Fd()), map[string]svdbus.Variant{})
	w.Close()
	if err != nil {
		return 0, nil, err
	}
	var response uint32
	var results map[string]svdbus.Variant
	if err := reply.Decode(&response, &results); err != nil {
		t.Fatal(err)
	}
	secret, _ := io.ReadAll(r)
	return response, secret, nil
}

func TestTheSecretPortalGivesEachFlatpakAppItsOwnKey(t *testing.T) {
	h := newSSHarness(t)
	h.d.opts.IsPortal = func(*svpeer.Process) bool { return true }
	h.d.opts.Log = func(s string) { t.Log(s) }

	h.desk.script("choose:"+svrpc.ChoiceAlways)
	resp, first, err := askPortal(t, h, "org.example.Mail")
	if err != nil || resp != portalOK || len(first) != 64 {
		t.Fatalf("first ask: %d, %d bytes, %v", resp, len(first), err)
	}
	if q := h.desk.asked[len(h.desk.asked)-1]; !bytes.Contains([]byte(q.Description), []byte("org.example.Mail (Flatpak)")) {
		t.Fatalf("the prompt did not name the app: %q", q.Description)
	}
	// The same key every time, without asking again.
	asked := h.desk.count()
	if resp, again, _ := askPortal(t, h, "org.example.Mail"); resp != portalOK || !bytes.Equal(again, first) {
		t.Fatal("the app got a different key the second time")
	}
	if h.desk.count() != asked {
		t.Fatal("a remembered app was asked about again")
	}
	// Another app: its own key, and its own question; saying no gives it
	// nothing.
	h.desk.script("choose:"+svrpc.ChoiceDeny)
	if resp, other, _ := askPortal(t, h, "org.example.Chat"); resp != portalNo || len(other) != 0 {
		t.Fatalf("a refused app: %d, %d bytes", resp, len(other))
	}
	h.desk.script("choose:"+svrpc.ChoiceOnce)
	if resp, other, _ := askPortal(t, h, "org.example.Chat"); resp != portalOK || len(other) != 64 || bytes.Equal(other, first) {
		t.Fatalf("a second app: %d, %d bytes", resp, len(other))
	}
	// A program outside a sandbox has no app ID to ask with.
	if resp, _, _ := askPortal(t, h, ""); resp != portalError {
		t.Fatalf("an empty app ID: %d", resp)
	}
	h.desk.done(t)
}

func TestOnlyThePortalMayAskForAnAppsSecret(t *testing.T) {
	h := newSSHarness(t) // IsPortal is the real check: this test is no portal
	if _, _, err := askPortal(t, h, "org.example.Mail"); !isDBusError(err, svdbus.ErrorAccessDenied) {
		t.Fatalf("a program that is not xdg-desktop-portal: %v", err)
	}
	if h.desk.count() != 0 {
		t.Fatal("refusing asked the desktop anyway")
	}
}
