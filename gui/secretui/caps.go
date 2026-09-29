package secretui

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// CapsLock is a line that says Caps Lock is on, shown only while it is.
// Every passphrase question carries one, because a right passphrase
// refused is nearly always Caps Lock.
//
// It learns the lock from the window (uitoolkit's Window.LockKeys and
// OnLockKeys), which has it from the keyboard: telling it from the case of
// the letters typed would mean reading the passphrase to do it.
type CapsLock struct {
	*widgets.Label
	win *uitoolkit.Window
}

// NewCapsLock is the line, hidden until Follow finds Caps Lock on.
func NewCapsLock() *CapsLock {
	c := &CapsLock{Label: widgets.NewLabel("Caps Lock is on")}
	c.Label.Init(c)
	c.SetVisible(false)
	return c
}

// Follow shows the line while Caps Lock is on in w: from now (on X11 and
// Windows a window can tell before the first key) and as it changes,
// whether or not the key reached a field. It takes w's OnLockKeys, of
// which a window has one; Stop gives it back.
func (c *CapsLock) Follow(w *uitoolkit.Window) {
	if w == nil {
		return
	}
	c.win = w
	caps, _ := w.LockKeys()
	c.show(c.asKeyboard(caps))
	w.OnLockKeys(func(caps, _ bool) { c.show(c.asKeyboard(caps)) })
}

// asKeyboard is the keyboard's own answer where the backend has one (X11,
// Windows), and else what the window reported. uitoolkit takes a window
// coming back into focus, whose event carries no modifiers, for the lock
// keys going off (uitoolkit-gaps.md, 12); asked, the keyboard knows
// better.
func (c *CapsLock) asKeyboard(reported bool) bool {
	if s, ok := c.win.Surface().(platform.LockKeysSurface); ok {
		caps, _ := s.LockKeys()
		return caps
	}
	return reported
}

// Stop stops following the window's Caps Lock, and hides the line.
func (c *CapsLock) Stop() {
	if c.win != nil {
		c.win.OnLockKeys(nil)
		c.win = nil
	}
	c.show(false)
}

// On reports whether the line is showing.
func (c *CapsLock) On() bool { return c.Visible() }

func (c *CapsLock) show(on bool) {
	if c.Visible() == on {
		return
	}
	c.SetVisible(on)
	c.RequestLayout()
}

// The line is in the look's warning colour, taken as it is painted, so it
// follows the desktop from light to dark.

func (c *CapsLock) Measure(cs layout.Constraints) paintengine2d.Point {
	c.Color = c.Look().Palette().Warning
	return c.Label.Measure(cs)
}

func (c *CapsLock) Paint(ctx *paintengine2d.Context) {
	c.Color = c.Look().Palette().Warning
	c.Label.Paint(ctx)
}
