package svtui

import (
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// passkeyItem is a passkey as the extension saves one.
func passkeyItem(t *testing.T, name string) (svrpc.Item, string) {
	t.Helper()
	kp, err := svext.NewKeyPair(svext.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	r := &svext.PasskeyRecord{RPID: "github.com", UserName: "ada@example.com", DisplayName: "Ada", CredentialID: []byte("cred-1"),
		UserHandle: []byte("u-1"), Alg: svext.AlgES256, PrivateKey: kp.Private, Created: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	it := svrpc.Item{Kind: svext.PasskeyKind, Name: name, Label: "GitHub"}
	key := ""
	for _, f := range r.Fields() {
		it.Fields = append(it.Fields, svrpc.Field{Name: f.Name, Type: f.Type, Value: f.Value})
		if f.Name == svext.PasskeyPrivateKey {
			key = string(f.Value)
		}
	}
	return it, key
}

// A passkey shows its site, its account and when it was made; its key is
// not shown, revealed or copied, and it is not edited.
func TestAPasskeyShowsItsSiteAndAccountButNeverItsKey(t *testing.T) {
	h := newHarness(t)
	h.unlockAdmin("")
	it, key := passkeyItem(t, "passkeys/github.com")
	if _, err := h.admin.Put(h.ctx(), "", it); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, key)
	h.unlock()
	h.open("passkeys/github.com")
	h.waitFor("Passkey")
	screen := h.text()
	for _, want := range []string{"site", "github.com", "user name", "ada@example.com", "created", "2026-09-01", "never shown or copied"} {
		if !strings.Contains(screen, want) {
			t.Errorf("the passkey's view lacks %q:\n%s", want, screen)
		}
	}
	if strings.Contains(screen, "private_key") || strings.Contains(screen, key[:16]) {
		t.Fatalf("the key shows:\n%s", screen)
	}
	h.typeText("r")
	time.Sleep(100 * time.Millisecond)
	if s := h.text(); strings.Contains(s, key[:16]) || strings.Contains(s, "private_key") {
		t.Fatalf("the key shows once revealed:\n%s", s)
	}
	h.typeText("c")
	h.waitFor("has no secret to copy")
	if len(h.copies()) != 0 || h.leaked.Load() {
		t.Fatalf("copied %q", h.copies())
	}
	h.typeText("e")
	h.waitFor(svops.PasskeyEditNote[:40])
}
