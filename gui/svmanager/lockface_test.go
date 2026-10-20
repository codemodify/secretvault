package svmanager

import (
	"testing"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
)

// A locked vault is its face, the logo, over the whole of the Vault part,
// what the vault holds out of sight; Enter on it (or a click) asks for the
// passphrase, and once the vault is open the face is gone, the items
// behind it. Locked again, the face is back.
func TestALockedVaultIsTheLogo(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	f := h.m.face
	if f == nil || f.vault != "personal" || len(h.m.ui.vaultHost.Children()) != 2 || h.m.ui.vaultHost.base().Visible() {
		t.Fatalf("a locked vault has no face over the Vault part, or shows what is under it: %v", f)
	}
	// The logo alone: no words, no buttons, no tip; under the pointer it
	// lifts, which says a click does something, and settles off it.
	if _, tip := any(f).(widget.Tipper); len(f.Children()) != 0 || tip || f.says() == "" {
		t.Fatalf("the face holds %d things, has a tip %v, says %q", len(f.Children()), tip, f.says())
	}
	// One size, whatever the window's: it shrinks only where it would not
	// fit.
	before := f.Bounds()
	f.Arrange(paintengine2d.XYWH(0, 0, 900, 700))
	_, small := f.dial()
	f.Arrange(paintengine2d.XYWH(0, 0, 1800, 1200))
	_, large := f.dial()
	f.Arrange(before)
	if small != large {
		t.Fatalf("the logo is %v in a small part and %v in a large one", small, large)
	}
	c, _ := f.dial()
	f.MouseMove(widget.MouseEvent{Pos: c})
	if f.lift() != 1 {
		t.Fatalf("on the logo, it is lifted %v", f.lift())
	}
	f.MouseMove(widget.MouseEvent{Pos: paintengine2d.Pt(2, 2)})
	if f.lift() != 0 {
		t.Fatalf("off the logo, it is lifted %v", f.lift())
	}
	h.win().FocusOn(f)
	h.win().Press(platform.KeyReturn)
	p := h.asking()
	p.win.Type(pass)
	p.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
	if h.m.face != nil || len(h.m.ui.vaultHost.Children()) != 1 || !h.m.ui.vaultHost.base().Visible() {
		t.Fatal("the face is still up over an open vault")
	}
	h.pressTool("Lock personal")
	h.waitFor("the face", func() bool { return h.m.face != nil })
}

// Animated, the logo turns half round, as a vault's dial does, grows and
// fades, the items showing behind it as it goes, and is gone at its end;
// locked, it comes back the same way and stays.
func TestTheLogoTurnsAndFades(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	t0 := time.Now()
	now := t0
	h.m.clock = func() time.Time { return now }
	h.m.flipAnyway = true
	h.unlock()
	f := h.m.face
	if f == nil || f.anim == nil || !f.anim.opening {
		t.Fatalf("unlocked, the logo does not go: %v", f)
	}
	if f.anim.quick {
		t.Skip("the desktop asks for less motion here: the logo only fades")
	}
	if !h.m.ui.vaultHost.base().Visible() {
		t.Fatal("as the logo goes, the items are not behind it")
	}
	var lastTurn float32
	for _, at := range []time.Duration{0, 200, 450, 700, 950, 1090} {
		now = t0.Add(at * time.Millisecond)
		turn, grow, left := f.at()
		if turn < lastTurn || turn > 1 || grow < 1 || left < 0 || left > 1 {
			t.Fatalf("at %v the logo is turned %v, grown %v, %v of it left", at, turn, grow, left)
		}
		lastTurn = turn
		if h.main().Capture() == nil {
			t.Fatalf("at %v the window could not be drawn", at)
		}
	}
	now = t0.Add(faceTime + time.Millisecond)
	f.next()
	if h.m.face != nil {
		t.Fatal("gone, the logo is still up")
	}
	h.pressTool("Lock personal")
	h.waitFor("the face", func() bool { return h.m.face != nil })
	f = h.m.face
	if f.anim == nil || f.anim.opening {
		t.Fatalf("locked, the logo does not come back: %+v", f.anim)
	}
	now = now.Add(faceTime + time.Millisecond)
	f.next()
	if h.m.face != f || f.anim != nil || h.m.ui.vaultHost.base().Visible() {
		t.Fatal("back, the logo is not up over the Vault part")
	}
}
