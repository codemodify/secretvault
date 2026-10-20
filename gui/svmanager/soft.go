package svmanager

import (
	"math"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
)

// The look's own pieces that no control of the toolkit's asks for: a pane
// sunk into the window; what is picked in the manager's own lists, marked
// as the toolkit's rows are; and a count in a small tag. The look draws
// the first two (its panel, its list row picked).

// insetBox sets its content in a pane sunk into the window, as the look
// draws a panel.
type insetBox struct{ widget.Base }

func newInset(content widget.Component) *insetBox {
	b := &insetBox{}
	b.Init(b)
	b.Add(content)
	return b
}

// pad is the room round the content inside the pane, and round the pane.
func (b *insetBox) pad() (in, out float32) {
	lk := b.Look()
	return style.Dip(lk, 6), style.Dip(lk, 6)
}

func (b *insetBox) Measure(c layout.Constraints) paintengine2d.Point {
	in, out := b.pad()
	e := 2 * (in + out)
	sz := b.Children()[0].Measure(c.Inset(e, e))
	return c.Constrain(paintengine2d.Pt(sz.X+e, sz.Y+e))
}

func (b *insetBox) MinWidth() float32 {
	in, out := b.pad()
	return widget.MinWidthOf(b.Children()[0]) + 2*(in+out)
}

func (b *insetBox) Arrange(r paintengine2d.Rect) {
	b.SetBounds(r)
	in, out := b.pad()
	e := in + out
	b.Children()[0].Arrange(paintengine2d.XYWH(e, e, max(r.Dx()-2*e, 0), max(r.Dy()-2*e, 0)))
}

func (b *insetBox) Paint(ctx *paintengine2d.Context) {
	_, out := b.pad()
	lk := b.Look()
	lk.DrawPanel(ctx, b.LocalBounds().Inset(out), false)
}

// markPicked marks a row of the manager's own lists picked, as the look
// draws the toolkit's rows picked.
func markPicked(ctx *paintengine2d.Context, b paintengine2d.Rect, lk style.LookAndFeel) {
	lk.DrawListRow(ctx, b, style.RowState(true, false), "")
}

// drawBadge puts a count in a small tag, its box b: square, framed in a
// hairline, as the look's tags are.
func drawBadge(ctx *paintengine2d.Context, b paintengine2d.Rect, lk style.LookAndFeel) {
	p := lk.Palette()
	box := paintengine2d.Rect{
		Min: paintengine2d.Pt(float32(math.Floor(float64(b.Min.X)))+0.5, float32(math.Floor(float64(b.Min.Y)))+0.5),
		Max: paintengine2d.Pt(float32(math.Floor(float64(b.Max.X)))+0.5, float32(math.Floor(float64(b.Max.Y)))+0.5),
	}
	ctx.DrawRect(box, paintengine2d.StrokePaint(p.Border, 1))
}
