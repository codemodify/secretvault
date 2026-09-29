package svmanager

import (
	"bytes"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svrpc"
)

// Secrets on the screen, and on the clipboard.
//
// uitoolkit's labels draw Go strings, and a Go string can be neither wiped
// nor told apart from other garbage; worse, a label's text is shaped once
// and kept in the face's shape cache for as long as the face lives. So a
// secret value never goes into a label here. secretText draws it straight
// from the byte slice the open item holds, through the toolkit's
// byte-slice path (style.Font.DrawBytes), which shapes it afresh on every
// paint and caches nothing; when the item is left, or its vault locks, the
// slice is wiped where it lies and the widget let go of.
//
// What remains is what any painted text leaves: the glyph images of the
// characters (not their order) in the face's atlas, and the frame's pixels
// until the next paint covers them.

// mask stands for a hidden value: always the same length, so the screen
// does not say how long the secret is.
const mask = "••••••••"

// secretText shows a secret, masked unless revealed. It holds the bytes it
// was given, not a copy: whoever owns them wipes them, and calls Forget.
type secretText struct {
	widget.Base
	value  []byte
	reveal bool
	mono   bool
}

func newSecretText(value []byte) *secretText {
	s := &secretText{value: value, mono: true}
	s.Init(s)
	return s
}

// SetReveal shows or hides the value.
func (s *secretText) SetReveal(on bool) {
	if s.reveal == on {
		return
	}
	s.reveal = on
	s.RequestLayout()
	s.Invalidate()
}

// Revealed reports whether the value is on the screen.
func (s *secretText) Revealed() bool { return s.reveal }

// SetValue shows other bytes (a new one-time code), still not a copy.
func (s *secretText) SetValue(b []byte) {
	s.value = b
	s.RequestLayout()
	s.Invalidate()
}

// Forget hides the value and drops the widget's hold on its bytes.
func (s *secretText) Forget() {
	s.value, s.reveal = nil, false
	s.RequestLayout()
	s.Invalidate()
}

func (s *secretText) font() *style.Font {
	if s.mono {
		return s.Look().MonoFont()
	}
	return s.Look().Font()
}

// lines are the value's lines, as slices of it: a private key is shown as
// the lines it is written in.
func (s *secretText) lines() [][]byte {
	if !s.reveal || len(s.value) == 0 {
		return nil
	}
	return bytes.Split(bytes.TrimRight(s.value, "\n"), []byte("\n"))
}

func (s *secretText) Measure(c layout.Constraints) paintengine2d.Point {
	f := s.font()
	lines := s.lines()
	if lines == nil {
		return c.Constrain(paintengine2d.Pt(f.Advance(mask)+2, f.Height()))
	}
	var w float32
	for _, l := range lines {
		w = max(w, f.AdvanceBytes(l))
	}
	return c.Constrain(paintengine2d.Pt(w+2, f.Height()*float32(len(lines))))
}

func (s *secretText) Arrange(r paintengine2d.Rect) { s.SetBounds(r) }

func (s *secretText) Paint(ctx *paintengine2d.Context) {
	lk := s.Look()
	f := s.font()
	b := s.LocalBounds()
	col := lk.Palette().Text
	ctx.Save()
	ctx.ClipRect(b)
	lines := s.lines()
	if lines == nil {
		y := b.Min.Y + (b.Dy()-f.Height())*0.5
		f.Draw(ctx, mask, paintengine2d.Pt(b.Min.X, y), lk.Palette().TextMuted)
		ctx.Restore()
		return
	}
	y := b.Min.Y + (b.Dy()-f.Height()*float32(len(lines)))*0.5
	for _, l := range lines {
		f.DrawBytes(ctx, l, paintengine2d.Pt(b.Min.X, y), col)
		y += f.Height()
	}
	ctx.Restore()
}

// Describe tells assistive technology what this is, and nothing of what it
// holds: a screen reader says "password, concealed", revealed or not. The
// accessibility tree is made of strings, and a string outlives the frame.
func (s *secretText) Describe(n *a11y.Node) {
	n.Role = a11y.RoleLabel
	n.Value = mask
	n.Description = "concealed"
	if s.reveal {
		n.Description = "concealed, shown on screen"
	}
}

// codeText is a one-time code: bytes too, so that thirty seconds of codes
// do not pile up in the shape cache. It is always shown.
func newCodeText() *secretText {
	s := newSecretText(nil)
	s.reveal = true
	return s
}

// syncCapture keeps the window out of screenshots and screen sharing
// while it shows a secret: a value revealed, a one-time code, a generated
// password, a secret field showing what was typed. Windows and macOS
// honour it; X11 and Wayland have no such thing (uitoolkit reports so),
// and there it does nothing.
func (m *Manager) syncCapture() {
	if m.ui == nil || m.win.Closed() {
		return
	}
	showing := false
	look := func(c widget.Component) {
		widget.Walk(c, func(c widget.Component) {
			switch x := c.(type) {
			case *secretText:
				showing = showing || (x.reveal && len(x.value) > 0)
			case *widgets.SecretField:
				showing = showing || (x.Reveal && !x.Empty())
			}
		})
	}
	if root := m.win.Content(); root != nil {
		look(root)
	}
	if o := m.win.Overlay(); o != nil {
		look(o)
	}
	if showing != m.excluded {
		m.excluded = showing
		m.win.SetExcludeFromCapture(showing)
	}
}

// wipeItem zeroes the values of an item's fields.
func wipeItem(it *svrpc.Item) {
	for i := range it.Fields {
		clear(it.Fields[i].Value)
	}
}

// wipeEntries zeroes the values of every entry's fields.
func wipeEntries(es []svrpc.Entry) {
	for i := range es {
		wipeItem(&es[i].Item)
	}
}

// Clipboard is where copies go. The real one is the toolkit's secret
// clipboard (uitoolkit.ClipboardSetSecret); tests put a fake in its place,
// so that nothing they copy reaches the desktop.
type Clipboard interface {
	// SetSecret copies data, taking ownership of it, and clears it again
	// after ttl. The copy is wiped when it is cleared.
	SetSecret(data []byte, ttl time.Duration) Copied
}

// Copied is one copy on the clipboard.
type Copied interface {
	// Clear takes the copy off the clipboard, if it is still there, and
	// wipes it. Something copied since, by anyone, is left alone.
	Clear()
}

// desktopClipboard is the desktop's clipboard, through uitoolkit: the
// CLIPBOARD selection only, hinted so clipboard managers do not record it,
// and cleared after the timeout and when the program quits.
type desktopClipboard struct{}

func (desktopClipboard) SetSecret(data []byte, ttl time.Duration) Copied {
	return uitoolkit.ClipboardSetSecret(data, ttl)
}
