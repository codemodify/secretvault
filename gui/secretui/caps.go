package secretui

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
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
// change (it is a widget.LockKeysWatcher), and a window coming back into
// focus is not one; it asks the window once, the first time it is laid
// out, which on X11, Windows and (since uitoolkit v0.23.3) macOS says so
// before the first key. On Wayland that is before the compositor has said
// (uitoolkit-gaps.md, 51), so a new prompt there says so at the first key
// or pointer event.
type CapsLock struct {
	*widgets.Label
	on, known bool
}

const capsLockText = "Caps Lock is on"

// NewCapsLock is the line, empty until its window says Caps Lock is on.
func NewCapsLock() *CapsLock {
	c := &CapsLock{Label: widgets.NewLabel("")}
	c.Label.Init(c)
	c.Tone = widgets.ToneWarning
	return c
}

// On reports whether the line says Caps Lock is on.
func (c *CapsLock) On() bool { return c.on }

// LockKeysChanged is the window saying Caps Lock or Num Lock changed
// (widget.LockKeysWatcher).
func (c *CapsLock) LockKeysChanged(caps, _ bool) {
	c.known = true
	c.show(caps)
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
		if w, ok := c.Host().(widget.LockKeysHost); ok {
			c.known = true
			caps, _ := w.LockKeys()
			c.show(caps)
		}
	}
	if !c.on {
		return cs.Constrain(paintengine2d.Point{})
	}
	return c.Label.Measure(cs)
}
