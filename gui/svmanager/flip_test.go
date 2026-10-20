package svmanager

import (
	"slices"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
)

// The mark at the top left turns the window over to Settings, on its
// back, which has no rail; it turns back to the part the front showed,
// as Escape does. On the back, Ctrl+Page Down and Up step through
// Settings' tabs; anything that shows a part of the front turns the window
// back to it.
func TestTheMarkTurnsTheWindowOver(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.showSection(secDisks)
	h.idle()
	h.pressTool("Settings")
	h.idle()
	if !h.m.onBack() || h.m.ui.rail.Visible() || !slices.Equal(h.crumbTexts(), []string{"Settings", "Appearance"}) {
		t.Fatalf("Settings: on the back %v, the rail shown %v, the breadcrumbs %q", h.m.onBack(), h.m.ui.rail.Visible(), h.crumbTexts())
	}
	h.win().Press(platform.KeyPageDown, platform.ModCtrl)
	h.pump()
	if h.m.spage.selected() != tabSetShortcuts {
		t.Fatalf("Ctrl+Page Down on the back shows Settings' tab %d", h.m.spage.selected())
	}
	h.win().Press(platform.Key1, platform.ModCtrl)
	h.pump()
	if h.m.spage.selected() != 0 || !h.m.onBack() {
		t.Fatalf("Ctrl+1 on the back shows Settings' tab %d, on the back %v", h.m.spage.selected(), h.m.onBack())
	}
	h.pressTool("Settings")
	h.idle()
	if h.m.onBack() || h.m.section() != secDisks || !h.m.ui.rail.Visible() {
		t.Fatalf("turned back, the window shows part %d, the rail shown %v", h.m.section(), h.m.ui.rail.Visible())
	}
	h.m.showAbout()
	h.idle()
	if !h.m.onBack() || h.m.spage.selected() != tabSetAbout {
		t.Fatalf("About secretvault: on the back %v, tab %d", h.m.onBack(), h.m.spage.selected())
	}
	h.win().Press(platform.KeyEscape)
	h.pump()
	if h.m.onBack() || h.m.section() != secDisks {
		t.Fatalf("Escape on the back shows part %d", h.m.section())
	}
	// On the front, Ctrl+1, 2, 3 pick Vault, Disk and Tools.
	for _, c := range []struct {
		key  platform.Key
		part int
	}{{platform.Key3, secTools}, {platform.Key2, secDisks}, {platform.Key1, secVaults}} {
		h.win().Press(c.key, platform.ModCtrl)
		h.pump()
		if h.m.section() != c.part {
			t.Fatalf("Ctrl+%v shows part %d, not %d", c.key, h.m.section(), c.part)
		}
	}
	h.m.showSettings(-1)
	h.win().Press(platform.KeyF, platform.ModCtrl)
	h.pump()
	if h.m.onBack() || h.m.section() != secVaults {
		t.Fatalf("Find from the back shows part %d", h.m.section())
	}
}

// Animated, the whole window turns over, frame and all: uitoolkit's own
// turn of a framed window, the window taking the card's outline as it
// turns. It turns where the person's settings ask for less motion too.
// Once it has turned, the window's content is on the face that is up and
// the other is blank.
func TestTheWindowTurnsOverWithItsFrame(t *testing.T) {
	t.Setenv("UITK_DECORATIONS", "toolkit") // the frame it turns with (offscreen windows have none)
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	h.m.flipAnyway = true
	was := style.ReduceMotion()
	style.SetReduceMotion(true) // the person's setting: it turns all the same
	t.Cleanup(func() { style.SetReduceMotion(was) })

	// The turn's clock held, and stepped a frame at a time: a frame is
	// drawn because the test asks for one, not because the machine was
	// quick enough (under the race detector one frame outlasts a turn).
	p := h.main().FlipPanel()
	now := time.Now()
	p.SetClock(func() time.Time { return now })
	t.Cleanup(func() { p.SetClock(nil) })

	h.m.turnOver()
	if !h.main().Turning() || !h.m.onBack() {
		t.Fatalf("the window did not turn: turning %v, Settings %v", h.main().Turning(), h.m.onBack())
	}
	if p.Back() != widget.Component(h.m.ui.root) || p.Front() != nil {
		t.Fatalf("turning: the content on the back %v, the front blank %v", p.Back() == widget.Component(h.m.ui.root), p.Front() == nil)
	}
	shaped := false
	for n := 0; h.main().Turning(); n++ {
		if n > 100 {
			t.Fatal("the turn never ended")
		}
		if h.main().Capture() == nil {
			t.Fatal("the window could not be drawn")
		}
		shaped = shaped || h.main().Shape() != nil && h.main().Turning()
		now = now.Add(30 * time.Millisecond)
	}
	p.SetClock(nil) // the rest on the real clock
	if !shaped {
		t.Error("the window never took the card's outline")
	}
	if !slices.Equal(h.crumbTexts(), []string{"Settings", "Appearance"}) {
		t.Fatalf("turned over, the breadcrumbs are %q", h.crumbTexts())
	}

	// Asked again while it turns, it changes at once under the turn, and
	// ends where it was last asked to.
	h.m.turnOver()
	h.m.turnOver()
	h.waitFor("the turns to end", func() bool { return !h.main().Turning() })
	if !h.m.onBack() || p.Back() != widget.Component(h.m.ui.root) || p.Front() != nil || !p.Showing() {
		t.Fatalf("turned twice more: on the back %v, the content on it %v", h.m.onBack(), p.Back() == widget.Component(h.m.ui.root))
	}
}
