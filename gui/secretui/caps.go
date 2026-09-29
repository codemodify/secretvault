package secretui

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// CapsLock is a line that says "Caps Lock is on" while it is, and takes
// no room while it is not. Every passphrase question carries one beside
// its buttons, because a right passphrase refused is nearly always Caps
// Lock. (A focused SecretField marks it too, in the field.)
//
// It learns the lock from the keyboard, through the window it is in, and
// never from what was typed: telling it from the case of the letters
// would mean reading the passphrase to do it. The window tells it of every
// change (it is a widget.LockKeysWatcher); it asks the window once, the
// first time it is laid out, which on X11 and Windows says so before the
// first key.
type CapsLock struct {
	*widgets.Label
	on, known bool
}

const capsLockText = "Caps Lock is on"

// NewCapsLock is the line, empty until its window says Caps Lock is on.
func NewCapsLock() *CapsLock {
	c := &CapsLock{Label: widgets.NewLabel("")}
	c.Label.Init(c)
	return c
}

// On reports whether the line says Caps Lock is on.
func (c *CapsLock) On() bool { return c.on }

// LockKeysChanged is the window saying Caps Lock or Num Lock changed
// (widget.LockKeysWatcher).
func (c *CapsLock) LockKeysChanged(caps, _ bool) {
	c.known = true
	c.show(c.asKeyboard(caps))
}

// lockKeysWindow is what CapsLock needs of the window it is in: the lock
// state as the window has it, and the surface to ask the keyboard.
type lockKeysWindow interface {
	LockKeys() (caps, num bool)
	Surface() platform.Surface
}

// asKeyboard is the keyboard's own answer where the backend has one (X11,
// Windows), and else what the window reported. uitoolkit takes a window
// coming back into focus, whose event carries no modifiers, for the lock
// keys going off (uitoolkit-gaps.md, 12); asked, the keyboard knows
// better.
func (c *CapsLock) asKeyboard(reported bool) bool {
	w, ok := c.Host().(lockKeysWindow)
	if !ok {
		return reported
	}
	if s, ok := w.Surface().(platform.LockKeysSurface); ok {
		caps, _ := s.LockKeys()
		return caps
	}
	return reported
}

func (c *CapsLock) show(on bool) {
	if c.on == on {
		return
	}
	c.on = on
	c.Text = ""
	if on {
		c.Text = capsLockText
	}
	c.RequestLayout()
	c.Invalidate()
}

func (c *CapsLock) Measure(cs layout.Constraints) paintengine2d.Point {
	if !c.known {
		// The state as it is when the line is first laid out in a
		// window: a dialog that opens with Caps Lock on says so at once.
		if w, ok := c.Host().(lockKeysWindow); ok {
			c.known = true
			caps, _ := w.LockKeys()
			c.show(c.asKeyboard(caps))
		}
	}
	if !c.on {
		return cs.Constrain(paintengine2d.Point{})
	}
	c.Color = c.warning()
	return c.Label.Measure(cs)
}

func (c *CapsLock) Paint(ctx *paintengine2d.Context) {
	c.Color = c.warning()
	c.Label.Paint(ctx)
}

// warning is the look's warning colour, readable on its background, taken
// as the line is drawn so it follows the desktop from light to dark.
func (c *CapsLock) warning() paintengine2d.Color {
	p := c.Look().Palette()
	return Ink(p.Warning, p.Background)
}
