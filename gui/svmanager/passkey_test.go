package svmanager

import (
	"strings"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// A passkey shows its site, its account and when it was made; its key is
// never shown, revealed or copied, and it is renamed or deleted, not
// edited.
func TestAPasskeyShowsItsSiteAndAccountButNeverItsKey(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()

	kp, err := svext.NewKeyPair(svext.AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	r := &svext.PasskeyRecord{RPID: "github.com", UserName: "ada@example.com", DisplayName: "Ada", CredentialID: []byte("cred-1"),
		UserHandle: []byte("u-1"), Alg: svext.AlgES256, PrivateKey: kp.Private, Created: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	it := svrpc.Item{Kind: svext.PasskeyKind, Name: "passkeys/github.com", Label: "GitHub"}
	key := ""
	for _, f := range r.Fields() {
		it.Fields = append(it.Fields, svrpc.Field{Name: f.Name, Type: f.Type, Value: f.Value})
		if f.Name == svext.PasskeyPrivateKey {
			key = string(f.Value)
		}
	}
	h.prove()
	if _, err := h.admin.Put(h.ctx(), "", it); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the passkey", func() bool { return h.m.entry("passkeys/github.com") != nil })
	h.open("passkeys/github.com")
	screen := h.text()
	for _, want := range []string{"PASSKEY", "Site", "github.com", "User name", "ada@example.com", "Created", "2026-09-01", "never shown or copied"} {
		if !strings.Contains(screen, want) {
			t.Errorf("the passkey's view lacks %q:\n%s", want, screen)
		}
	}
	if strings.Contains(screen, "private_key") || len(h.m.ui.view.secrets) != 0 {
		t.Fatalf("the key is in the view:\n%s", screen)
	}
	if find(h.m.ui.pane, func(b *widgets.Button) bool {
		return b.Text == "Copy password" || b.Text == "Edit" || b.Text == "Copy reference…"
	}) != nil {
		t.Error("a passkey offers to copy a password, or to be edited")
	}
	h.win().Press(platform.KeyR, platform.ModCtrl)
	h.pump()
	if shaped(h, key[:12]) {
		t.Fatal("the key shows")
	}
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.pump()
	if h.m.editor != nil {
		t.Fatal("the editor opened on a passkey")
	}
	h.said(svops.PasskeyEditNote[:30])
}
