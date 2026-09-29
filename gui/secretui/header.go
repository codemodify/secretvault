package secretui

import (
	"math"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
)

// The header's colours are secretvault's own and do not follow the
// theme: whatever look the desktop has, a secretvault dialog opens with
// the same band across its top. It is readable on light and dark desktops
// alike, because it brings its own background.
var (
	Brand       = paintengine2d.RGB(0.09, 0.20, 0.27) // the band
	BrandAccent = paintengine2d.RGB(0.20, 0.64, 0.58) // the rule under it, and the padlock
	BrandText   = paintengine2d.RGB(1, 1, 1)
)

// Name is how the header spells the product.
const Name = "secretvault"

// Header is the band across the top of every secretvault dialog: a
// padlock, the name, and the dialog's title, which names the vault
// ("Unlock vault Personal").
type Header struct {
	widget.Base
	Title string
}

// NewHeader is the band with title under the name.
func NewHeader(title string) *Header {
	h := &Header{Title: title}
	h.Init(h)
	return h
}

// SetTitle changes the title line.
func (h *Header) SetTitle(s string) {
	h.Title = s
	h.Invalidate()
}

// metrics are the header's lengths at the look's scale.
func (h *Header) metrics() (padX, padY, icon, gap, rule float32) {
	lk := h.Look()
	return style.Dip(lk, 16), style.Dip(lk, 12), style.Dip(lk, 30), style.Dip(lk, 2), style.Dip(lk, 3)
}

func (h *Header) Measure(c layout.Constraints) paintengine2d.Point {
	lk := h.Look()
	_, padY, icon, gap, rule := h.metrics()
	text := lk.BoldFont().Height()
	if h.Title != "" {
		text += gap + lk.TitleFont().Height()
	}
	w := float32(0)
	if c.HasMaxW() {
		w = c.MaxW
	}
	return c.Constrain(paintengine2d.Pt(w, padY*2+max(icon, text)+rule))
}

func (h *Header) Arrange(r paintengine2d.Rect) { h.SetBounds(r) }

func (h *Header) Paint(ctx *paintengine2d.Context) {
	lk := h.Look()
	b := h.LocalBounds()
	padX, padY, icon, gap, rule := h.metrics()
	ctx.DrawRect(b, paintengine2d.Fill(Brand))
	ctx.DrawRect(paintengine2d.XYWH(b.Min.X, b.Max.Y-rule, b.Dx(), rule), paintengine2d.Fill(BrandAccent))

	inner := b
	inner.Max.Y -= rule
	lock := paintengine2d.XYWH(b.Min.X+padX, inner.Min.Y+(inner.Dy()-icon)/2, icon, icon)
	paintLock(ctx, lock)

	name, title := lk.BoldFont(), lk.TitleFont()
	x := lock.Max.X + padX*0.75
	textH := name.Height()
	if h.Title != "" {
		textH += gap + title.Height()
	}
	y := inner.Min.Y + max(padY, (inner.Dy()-textH)/2)
	maxW := b.Max.X - padX - x
	name.Draw(ctx, Name, paintengine2d.Pt(x, y), BrandText.WithAlpha(0.72))
	if h.Title != "" {
		title.Draw(ctx, title.Fit(h.Title, maxW), paintengine2d.Pt(x, y+name.Height()+gap), BrandText)
	}
}

// Icon is secretvault's icon, side pixels square: the header's padlock on
// a tile of the header's colour. It is what a secretvault window and its
// tray icon show.
func Icon(side int) *paintengine2d.Image {
	img := paintengine2d.NewImage(side, side)
	ctx := paintengine2d.NewContext(img)
	s := float32(side)
	ctx.DrawRoundRect(paintengine2d.XYWH(0, 0, s, s), s*0.22, s*0.22, paintengine2d.Fill(Brand))
	paintLock(ctx, paintengine2d.XYWH(s*0.18, s*0.14, s*0.64, s*0.64))
	return img
}

// paintLock draws the padlock in box: a shackle over a body with a
// keyhole cut out of it.
func paintLock(ctx *paintengine2d.Context, box paintengine2d.Rect) {
	s := box.Dx()
	stroke := max(1.5, s*0.11)
	body := paintengine2d.XYWH(box.Min.X+s*0.12, box.Min.Y+s*0.44, s*0.76, s*0.54)
	r := s * 0.24
	cx := body.Min.X + body.Dx()/2
	cy := box.Min.Y + r + stroke/2
	ink := paintengine2d.StrokePaint(BrandAccent, stroke)
	ctx.DrawArc(paintengine2d.Pt(cx, cy), r, r, math.Pi, math.Pi, ink)
	ctx.DrawLine(paintengine2d.Pt(cx-r, cy), paintengine2d.Pt(cx-r, body.Min.Y+1), ink)
	ctx.DrawLine(paintengine2d.Pt(cx+r, cy), paintengine2d.Pt(cx+r, body.Min.Y+1), ink)
	ctx.DrawRoundRect(body, s*0.08, s*0.08, paintengine2d.Fill(BrandAccent))
	hole := paintengine2d.Pt(cx, body.Min.Y+body.Dy()*0.42)
	ctx.DrawCircle(hole, s*0.07, paintengine2d.Fill(Brand))
	ctx.DrawRect(paintengine2d.XYWH(cx-s*0.03, hole.Y, s*0.06, body.Dy()*0.32), paintengine2d.Fill(Brand))
}
