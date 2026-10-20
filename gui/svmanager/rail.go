package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The rail down the window's left edge: the window's three parts, Vault,
// Disk and Tools, an icon each in the muted ink, each button the rail's
// whole width, the one shown lit across it with a bar in the accent down
// its left edge; and at its foot what is of none of them: the password
// generator and Quit. Each says what it is in its tip, and to a screen
// reader.

// railWidth is the rail's width.
const railWidth = 60

// rail is the column of the rail's buttons, on the look's sidebar colour.
type rail struct {
	widget.Base
	col   *widgets.FlexBox
	parts []*railItem // Vault, Disk, Tools, as the window's parts
}

func (m *Manager) newRail() *rail {
	r := &rail{}
	r.Init(r)
	box := func(b paintengine2d.Rect) paintengine2d.Rect { return iconBox(b) }
	part := func(name, tip string, mark func(*paintengine2d.Context, paintengine2d.Rect, paintengine2d.Color), i int) *railItem {
		it := newRailItem(nil)
		it.btn = iconButton(name, tip, style.IconNone, m.railInk(it, box, mark), func() { m.showSection(i) })
		it.Add(it.btn)
		r.parts = append(r.parts, it)
		return it
	}
	tool := func(name, tip string, mark func(*paintengine2d.Context, paintengine2d.Rect, paintengine2d.Color), do func()) *railItem {
		it := newRailItem(nil)
		it.btn = iconButton(name, tip, style.IconNone, m.railInk(it, box, mark), do)
		it.Add(it.btn)
		return it
	}
	stock := func(icon style.ToolIcon) func(*paintengine2d.Context, paintengine2d.Rect, paintengine2d.Color) {
		return func(ctx *paintengine2d.Context, b paintengine2d.Rect, ink paintengine2d.Color) {
			set := style.IconSetName("")
			if c, ok := r.Look().(*style.Classic); ok {
				set = c.Icons()
			}
			style.DrawToolIcon(ctx, b, icon, ink, set)
		}
	}
	r.col = widgets.NewColumn(
		part("Vault", "Vault: your vaults, and what each one holds", stock(style.IconSafe), secVaults),
		part("Disk", "Disk: the encrypted disks, whose keys your vaults keep", stock(style.IconDrive), secDisks),
		part("Tools", "Tools: what works outside the vaults", stock(style.IconLayout), secTools),
	).WithGap(6).WithPadding(0, 12, 0, 12)
	spacer := widgets.NewSpacer()
	r.col.Add(spacer)
	r.col.AddFlex(spacer, 1)
	r.col.Add(tool("Password generator…", "Password generator: make a password or a passphrase", stock(style.IconDice), m.openGenerator))
	r.col.Add(tool("Quit", "Quit secretvault (the vaults stay as they are)", stock(style.IconQuit), m.Quit))
	r.Add(r.col)
	r.SetAccessibleName("secretvault")
	return r
}

// railInk paints a rail button's mark in the muted ink, or the text's
// while it is the part shown or under the pointer.
func (m *Manager) railInk(it *railItem, at func(paintengine2d.Rect) paintengine2d.Rect,
	mark func(*paintengine2d.Context, paintengine2d.Rect, paintengine2d.Color)) widgets.ButtonContentPainter {
	return func(ctx *paintengine2d.Context, b paintengine2d.Rect, st style.ControlState) {
		p := m.win.Look().Palette()
		ink := p.TextMuted
		if it.on || st&(style.StateHovered|style.StatePressed) != 0 {
			ink = p.Text
		}
		mark(ctx, at(b), ink)
	}
}

// mark lights part i, the one shown.
func (r *rail) mark(i int) {
	for j, p := range r.parts {
		if p.on != (j == i) {
			p.on = j == i
			p.Invalidate()
		}
	}
}

func (r *rail) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(railWidth, c.MaxH))
}

func (r *rail) MinWidth() float32 { return railWidth }

func (r *rail) Arrange(b paintengine2d.Rect) {
	r.SetBounds(b)
	r.col.Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (r *rail) Paint(ctx *paintengine2d.Context) {
	ctx.DrawRect(r.LocalBounds(), paintengine2d.Fill(railGround(r.Look())))
}

// railGround is the rail's colour: the look's sidebar's.
func railGround(lk style.LookAndFeel) paintengine2d.Color {
	bg := lk.Palette().SurfaceAlt
	if c, ok := lk.(*style.Classic); ok {
		bg = c.X("sidebar", bg)
	}
	return bg
}

func (r *rail) Describe(n *a11y.Node) { n.Role = a11y.RoleToolBar }

// railItem is one of the rail's buttons, the rail's whole width: its
// button fills it, and it is lit across it, a bar down its left edge,
// when it is the part shown.
type railItem struct {
	widget.Base
	btn    *widgets.ToolButton
	on     bool
	ground bool // it paints the rail's colour under itself (the title bar's Settings)
}

// newRailItem is a rail button around b; with b nil, the caller adds one.
func newRailItem(b *widgets.ToolButton) *railItem {
	it := &railItem{btn: b}
	it.Init(it)
	if b != nil {
		it.Add(b)
	}
	return it
}

func (it *railItem) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(railWidth, 52))
}

func (it *railItem) MinWidth() float32 { return railWidth }

// Arrange gives the button the item's whole box: a press anywhere across
// the rail is the button's.
func (it *railItem) Arrange(b paintengine2d.Rect) {
	it.SetBounds(b)
	it.btn.Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (it *railItem) Paint(ctx *paintengine2d.Context) {
	p := it.Look().Palette()
	b := it.LocalBounds()
	if it.ground {
		ctx.DrawRect(b, paintengine2d.Fill(railGround(it.Look())))
	}
	if !it.on {
		return
	}
	ctx.DrawRect(b, paintengine2d.Fill(p.Highlight))
	ctx.DrawRect(paintengine2d.XYWH(0, 0, 3, b.Dy()), paintengine2d.Fill(p.Accent))
}
