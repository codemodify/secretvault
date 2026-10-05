package secretui

import (
	"unicode/utf8"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
)

// Shown is a secret shown in full, once, for the person to write down: a
// new recovery key, in the prompt that shows it (secretvault-gui-prompt,
// SETSECRET).
//
// A label draws a Go string, which can be neither wiped nor told apart
// from other garbage, and keeps it shaped in its face's cache. Shown
// draws the bytes it was given instead, in the monospace face, through
// the toolkit's byte-slice path (style.Font.DrawBytes), which shapes them
// afresh on every paint and keeps nothing; long lines break to fit. It
// holds the caller's bytes, not a copy: whoever owns them wipes them, and
// calls Forget first.
type Shown struct {
	widget.Base
	value []byte
}

// minChars is how narrow Shown may be, in characters: a key breaks onto
// more lines rather than widen its dialog past its buttons.
const minChars = "MMMMMMMMMMMMMMMMMMMMMMMM"

// NewShown shows value.
func NewShown(value []byte) *Shown {
	s := &Shown{value: value}
	s.Init(s)
	return s
}

// Forget drops the widget's hold on its bytes, and draws nothing more.
func (s *Shown) Forget() {
	s.value = nil
	s.RequestLayout()
	s.Invalidate()
}

// Showing reports whether it holds a secret still.
func (s *Shown) Showing() bool { return len(s.value) > 0 }

// lines are the value broken before the character that would pass width
// (none broken for a negative width), as slices of it, not copies.
func (s *Shown) lines(width float32) [][]byte {
	if len(s.value) == 0 {
		return nil
	}
	f := s.Look().MonoFont()
	var out [][]byte
	// brk is where the line may break best: after the last '-' or space
	// (a key's groups stay whole), else before the character that
	// overflows.
	start, brk := 0, -1
	for i := 0; i < len(s.value); {
		_, n := utf8.DecodeRune(s.value[i:])
		if s.value[i] == '\n' {
			out = append(out, s.value[start:i])
			start, brk = i+1, -1
			i++
			continue
		}
		if width >= 0 && i > start && f.AdvanceBytes(s.value[start:i+n]) > width {
			end := i
			if brk > start {
				end = brk
			}
			out = append(out, s.value[start:end])
			start, brk = end, -1
			continue
		}
		if s.value[i] == '-' || s.value[i] == ' ' {
			brk = i + n
		}
		i += n
	}
	return append(out, s.value[start:])
}

func (s *Shown) Measure(c layout.Constraints) paintengine2d.Point {
	f := s.Look().MonoFont()
	width := float32(-1)
	if c.HasMaxW() {
		width = c.MaxW
	}
	lines := s.lines(width)
	var w float32
	for _, l := range lines {
		w = max(w, f.AdvanceBytes(l))
	}
	return c.Constrain(paintengine2d.Pt(w, f.Height()*float32(max(1, len(lines)))))
}

// MinWidth is the narrowest it may be (widget.MinWidther).
func (s *Shown) MinWidth() float32 { return s.Look().MonoFont().Advance(minChars) }

func (s *Shown) Arrange(r paintengine2d.Rect) { s.SetBounds(r) }

func (s *Shown) Paint(ctx *paintengine2d.Context) {
	lk := s.Look()
	f := lk.MonoFont()
	b := s.LocalBounds()
	ctx.Save()
	ctx.ClipRect(b)
	y := b.Min.Y
	for _, l := range s.lines(b.Dx()) {
		f.DrawBytes(ctx, l, paintengine2d.Pt(b.Min.X, y), lk.Palette().Text)
		y += f.Height()
	}
	ctx.Restore()
}

// Describe tells assistive technology that something is shown, and
// nothing of what it holds: the accessibility tree is made of strings,
// and a string outlives the dialog. Its name (SetAccessibleName) says
// what it is.
func (s *Shown) Describe(n *a11y.Node) {
	n.Role = a11y.RoleLabel
	n.Description = "shown on screen, not read aloud"
}
