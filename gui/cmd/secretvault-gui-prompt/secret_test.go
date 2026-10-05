package main

import (
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/a11y/a11ytest"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// A new vault's recovery key, which secretvaultd shows once when a
// program asked for the vault (SETSECRET, then CHOOSE): set apart from
// what is said about it, drawn from the bytes the protocol holds and in
// no label, read to no screen reader, let go of as the dialog closes,
// and wiped by the protocol as the session moves on.
func TestASecretToWriteDownIsShownFromItsBytes(t *testing.T) {
	const key = "SVRK1-ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567-ABCD-EFGH-IJKL-MNOP-QRST"
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETTITLE Recovery key for vault mail",
		"SETDESC Write this recovery key down and keep it somewhere safe.",
		"SETSECRET "+key,
		"ADDCHOICE no-recovery Don't keep a recovery key",
		"ADDCHOICE written I have written it down")
	h.send("CHOOSE")
	d := h.dialog()
	if d.shown == nil || string(d.req.Secret) != key {
		t.Fatal("the secret is not shown")
	}
	widget.Walk(d.win.Content(), func(c widget.Component) {
		if l, ok := c.(*widgets.Label); ok && strings.Contains(l.Text, "SVRK1") {
			t.Errorf("a label holds the secret: %q", l.Text)
		}
	})
	// It is all on screen, broken to the dialog's width, not cut.
	if b, w := d.shown.Bounds(), d.win.Content().Bounds(); b.Dx() <= 0 || b.Max.X > w.Max.X || b.Dy() < d.win.Look().MonoFont().Height() {
		t.Fatalf("the secret's box: %v, in %v", b, w)
	}
	tree := a11ytest.Audit(t, "secret", d.win.AccessibleTree())
	tree.Walk(func(n *a11y.Node) bool {
		if strings.Contains(n.Name+n.Value+n.Description, "SVRK1") {
			t.Errorf("a screen reader hears the secret: %+v", n)
		}
		return true
	})
	// "I have written it down" is the default: Enter answers it.
	if !d.buttons["written"].Primary || d.win.Focus() != d.buttons["written"] {
		t.Fatalf("the default is not the last answer: focus %v", d.win.Focus())
	}
	secret := d.req.Secret
	d.win.Press(platform.KeyReturn)
	h.expect("D written")
	h.expect("OK")
	if d.shown.Showing() {
		t.Fatal("the closed dialog still holds the secret")
	}
	h.do("RESET")
	if strings.Trim(string(secret), "\x00") != "" {
		t.Fatalf("the secret was left as %q", secret)
	}

	// Escape is a dismissal, which secretvaultd takes as keeping the key.
	h.do("SETSECRET "+key, "ADDCHOICE no-recovery Don't keep a recovery key", "ADDCHOICE written I have written it down")
	h.send("CHOOSE")
	d = h.dialog()
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}
