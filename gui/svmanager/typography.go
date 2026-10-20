package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
)

// displayHeading is the title of what the pane beside a list shows (an
// item, a message): the look's face, light and larger than its text, as
// the big headings of secretvault's look are; what it is, under it, is
// muted and small.
type displayHeading struct {
	widget.Base
	text string
}

func newDisplayHeading(text string) *displayHeading {
	h := &displayHeading{text: text}
	h.Init(h)
	h.SetAccessibleName(text)
	return h
}

// Text is what it says.
func (h *displayHeading) Text() string { return h.text }

// SetText changes what it says.
func (h *displayHeading) SetText(t string) {
	h.text = t
	h.SetAccessibleName(t)
	h.RequestLayout()
	h.Invalidate()
}

// font is the look's face, light, 1.7 times its text.
func (h *displayHeading) font() *style.Font {
	lk := h.Look()
	c, ok := lk.(*style.Classic)
	if !ok {
		return lk.TitleFont()
	}
	return style.BakeFamily(c.UIFamily(), style.Weight(300), c.Metrics().FontSize*1.7, c.Palette().Text)
}

func (h *displayHeading) Measure(c layout.Constraints) paintengine2d.Point {
	f := h.font()
	return c.Constrain(paintengine2d.Pt(f.Advance(h.text), f.Height()+4))
}

func (h *displayHeading) MinWidth() float32 { return min(h.font().Advance(h.text), 240) }

func (h *displayHeading) Arrange(r paintengine2d.Rect) { h.SetBounds(r) }

func (h *displayHeading) Paint(ctx *paintengine2d.Context) {
	f := h.font()
	text := f.Fit(h.text, h.Bounds().Dx())
	f.Draw(ctx, text, paintengine2d.Pt(0, 0), h.Look().Palette().Text)
}

func (h *displayHeading) Describe(n *a11y.Node) { n.Role = a11y.RoleHeading }
