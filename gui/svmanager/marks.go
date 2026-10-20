package svmanager

import (
	"math"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
)

// The manager's own mark, where the toolkit's icons have none: its logo,
// alone or with the toolkit's badge (a new vault). A padlock with a plus
// (unlock with something else than the passphrase) is the toolkit's
// padlock and its badge, and a vault joined from a sync server its cloud
// (uitoolkit-gaps.md item 93).

// markInk is the colour a mark is drawn in, for a button in state st.
func (m *Manager) markInk(st style.ControlState) paintengine2d.Color {
	p := m.win.Look().Palette()
	if st&style.StateDisabled != 0 {
		return p.TextMuted
	}
	return p.Text
}

// iconBox is the square a mark of an icon-only button is drawn in: the
// middle of the button.
func iconBox(b paintengine2d.Rect) paintengine2d.Rect {
	s := min(b.Dx(), b.Dy()) * 0.62
	return paintengine2d.XYWH(b.Min.X+(b.Dx()-s)/2, b.Min.Y+(b.Dy()-s)/2, s, s)
}

// plusBadge puts the toolkit's plus on a button's corner, over its icon:
// unlock with something else, a new one.
func (m *Manager) plusBadge() widgets.ButtonContentPainter {
	return func(ctx *paintengine2d.Context, b paintengine2d.Rect, st style.ControlState) {
		style.DrawIconBadge(ctx, b.Inset(2), style.IconBadge{Mark: style.BadgePlus}, m.win.Look())
	}
}

// logoMark is secretvault's logo alone; at is where in the button it
// goes.
func (m *Manager) logoMark(at func(paintengine2d.Rect) paintengine2d.Rect) widgets.ButtonContentPainter {
	var logo *paintengine2d.Image
	return func(ctx *paintengine2d.Context, b paintengine2d.Rect, st style.ControlState) {
		box := at(b)
		side := int(math.Ceil(float64(box.Dx())))
		if logo == nil || logo.Width != side {
			logo = secretui.Icon(side)
		}
		ctx.DrawImageRect(logo, paintengine2d.XYWH(0, 0, float32(logo.Width), float32(logo.Height)), box)
	}
}

// newVaultMark is the logo, small, with a plus: a new vault. at is where
// in the button it goes (iconBox).
func (m *Manager) newVaultMark(at func(paintengine2d.Rect) paintengine2d.Rect) widgets.ButtonContentPainter {
	var logo *paintengine2d.Image
	return func(ctx *paintengine2d.Context, b paintengine2d.Rect, st style.ControlState) {
		box := at(b)
		side := int(math.Ceil(float64(box.Dx())))
		if logo == nil || logo.Width != side {
			logo = secretui.Icon(side)
		}
		ctx.DrawImageRect(logo, paintengine2d.XYWH(0, 0, float32(logo.Width), float32(logo.Height)), box)
		style.DrawIconBadge(ctx, b.Inset(2), style.IconBadge{Mark: style.BadgePlus}, m.win.Look())
	}
}
