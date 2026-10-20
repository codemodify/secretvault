package svmanager

import (
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window's content is one ground, the rail's, the title bar's and the
// pages' alike; the rail and the title bar stand off it by a hairline,
// crisp, with no soft shadow (pageFrame). There is no status bar: what
// the window has to say comes as uitoolkit's passing notes
// (widgets.ShowToast), over the pages and out of the pointer's way: a
// message fades after a few seconds (m.say, m.fail), and an emergency
// request, or work that takes a while, stays as long as it is so. Each is
// said to a screen reader as it comes.

// How long a note stays before it fades, and when work that takes a while
// says so.
const (
	noteFor      = 4500 * time.Millisecond
	noteErrorFor = 8 * time.Second
	busyAfter    = 700 * time.Millisecond
)

// pageFrame holds the window's content, and over it the rail's and the
// title bar's edges.
type pageFrame struct {
	widget.Base
	m     *Manager
	shade *frameShade
}

func newPageFrame(m *Manager, content widget.Component) *pageFrame {
	f := &pageFrame{m: m}
	f.Init(f)
	f.shade = &frameShade{m: m}
	f.shade.Init(f.shade)
	f.Add(content)
	f.Add(f.shade)
	return f
}

func (f *pageFrame) Measure(c layout.Constraints) paintengine2d.Point {
	return f.Children()[0].Measure(c)
}

func (f *pageFrame) MinWidth() float32 { return widget.MinWidthOf(f.Children()[0]) }

func (f *pageFrame) Arrange(r paintengine2d.Rect) {
	f.SetBounds(r)
	for _, c := range f.Children() {
		c.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
	}
}

// railEdge is where the rail ends, in the frame: 0 while it is hidden
// (the window's back).
func (m *Manager) railEdge() float32 {
	if m.ui == nil || m.ui.rail == nil || !m.ui.rail.Visible() {
		return 0
	}
	return m.ui.rail.Bounds().Max.X
}

// frameShade draws the rail's and the title bar's edges. The pointer goes
// through it.
type frameShade struct {
	widget.Base
	m *Manager
}

func (s *frameShade) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(c.MaxW, c.MaxH))
}

func (s *frameShade) Arrange(r paintengine2d.Rect) { s.SetBounds(r) }

func (s *frameShade) HitTest(paintengine2d.Point) widget.Component { return nil }

func (s *frameShade) Paint(ctx *paintengine2d.Context) {
	// Crisp: a hairline along each edge, one device pixel, and no soft
	// shadow.
	b := s.LocalBounds()
	edge := s.Look().Palette().Border
	if x := s.m.railEdge(); x > 0 {
		ctx.DrawRect(paintengine2d.XYWH(x-1, 0, 1, b.Dy()), paintengine2d.Fill(edge))
	}
	ctx.DrawRect(paintengine2d.XYWH(0, 0, b.Dx(), 1), paintengine2d.Fill(edge))
}

// notes are the window's notes up: the passing one, and the one that
// stays while something is so.
type notes struct {
	m         *Manager
	passing   *widgets.Toast
	stay      string // what stays, "" for nothing
	staying   *widgets.Toast
	busySince time.Time // when work began that is not done yet
}

// note puts text up for a few seconds, longer for an error, in the place
// of the note before it.
func (n *notes) note(text string, isErr bool) {
	if n.passing != nil {
		n.passing.Dismiss()
		n.passing = nil
	}
	kind, d := widgets.ToastInfo, noteFor
	if isErr {
		kind, d = widgets.ToastError, noteErrorFor
	}
	n.passing = widgets.ShowToast(n.m.win.Content(), text, kind, d)
}

// stays puts up what stays (or takes it away: ""): a warning, or work
// under way.
func (n *notes) stays(text string, warn bool) {
	if text == n.stay {
		return
	}
	n.stay = text
	if n.staying != nil {
		n.staying.Dismiss()
		n.staying = nil
	}
	if text == "" {
		return
	}
	kind := widgets.ToastInfo
	if warn {
		kind = widgets.ToastWarning
	}
	n.staying = widgets.ShowToast(n.m.win.Content(), text, kind, -1)
}
