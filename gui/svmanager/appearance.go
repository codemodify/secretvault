package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svops"
)

// Settings › Appearance: the look secretvault's windows are in, the
// manager's and the passphrase prompts': one, uitoolkit's Hangar, a dark
// console, whatever the desktop is set to (2026-10-12). The page shows it,
// and says so.

// appearanceAbout heads the tab.
const appearanceAbout = "How secretvault's windows look: this one, and the ones that ask for a passphrase. " +
	"secretvault has one look, Hangar, a dark console, whatever the desktop is set to."

// fillAppearance shows the look, a sample of it beside what it is.
func (m *Manager) fillAppearance(pn *pane) {
	sample := newFixedWidth(m.lookSample(svops.LookDark, "secretvault"), sampleWidth)
	col := widgets.NewColumn(m.paragraph(appearanceAbout), section(m, "Look"), sample).WithGap(gap)
	pn.box.Set(scrolled(col))
}

// sampleWidth is the sample's width.
const sampleWidth = 260

// lookSample is a small picture of the manager in look: a vault's row
// picked, an item, and its button, drawn in that look whatever the window
// is in. It is a picture: nothing in it takes the keyboard or a click.
func (m *Manager) lookSample(look, title string) widget.Component {
	picked := newSampleRow("fastmail")
	btn := widgets.NewButton("Copy password", nil)
	btn.Primary = true
	btn.SetWantsFocus(false)
	col := widgets.NewColumn(heading("github.com"), m.muted("Login · GitHub"), picked, btn).WithGap(6)
	s := &lookSampleBox{}
	s.Init(s)
	s.Add(widgets.NewPad(12, col))
	s.SetAccessibleName("A sample of the look " + title)
	widget.SetTheme(s, secretui.ThemeFor(look, m.app.DesktopColorScheme()))
	return s
}

// lookSampleBox is a sample's ground: the look's own background, in its
// border.
type lookSampleBox struct{ widget.Base }

func (s *lookSampleBox) Measure(c layout.Constraints) paintengine2d.Point {
	p := s.Children()[0].Measure(layout.Constraints{MaxW: sampleWidth, MaxH: c.MaxH})
	return c.Constrain(paintengine2d.Pt(sampleWidth, p.Y))
}

func (s *lookSampleBox) MinWidth() float32 { return sampleWidth }

func (s *lookSampleBox) Arrange(b paintengine2d.Rect) {
	s.SetBounds(b)
	s.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (s *lookSampleBox) Paint(ctx *paintengine2d.Context) {
	p := s.Look().Palette()
	b := s.LocalBounds()
	ctx.DrawRoundRect(b, 6, 6, paintengine2d.Fill(p.Background))
	ctx.DrawRoundRect(b, 6, 6, paintengine2d.StrokePaint(p.Border, 1))
}

func (s *lookSampleBox) Describe(n *a11y.Node) { n.Role = a11y.RoleImage }

// sampleRow is a list's row picked, as the manager marks one.
type sampleRow struct {
	widget.Base
	name *widgets.Label
}

func newSampleRow(text string) *sampleRow {
	r := &sampleRow{name: widgets.NewLabel(text)}
	r.Init(r)
	r.Add(widgets.NewPad(6, r.name))
	return r
}

func (r *sampleRow) Measure(c layout.Constraints) paintengine2d.Point {
	return r.Children()[0].Measure(c)
}

func (r *sampleRow) Arrange(b paintengine2d.Rect) {
	r.SetBounds(b)
	r.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (r *sampleRow) Paint(ctx *paintengine2d.Context) {
	markPicked(ctx, r.LocalBounds(), r.Look())
}
