package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
)

// blocker lies over the manager's window while a dialog is up in a
// window of its own, so that the window takes nothing in: the dialog is
// modal, as a desktop's own are. A click on the window brings the dialog
// forward. It draws nothing: the window under it looks as it did.
type blocker struct {
	widget.Base
	m *Manager
}

func newBlocker(m *Manager) *blocker {
	b := &blocker{m: m}
	b.Init(b)
	return b
}

func (b *blocker) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(c.MaxW, c.MaxH))
}

func (b *blocker) Arrange(r paintengine2d.Rect) { b.SetBounds(r) }

func (b *blocker) Paint(*paintengine2d.Context) {}

func (b *blocker) MousePress(widget.MouseEvent) bool {
	if top := b.m.topDialog(); top != nil {
		top.win.Raise()
	}
	return true
}

func (b *blocker) MouseRelease(widget.MouseEvent) bool { return true }
func (b *blocker) MouseMove(widget.MouseEvent) bool    { return true }
func (b *blocker) MouseWheel(widget.MouseEvent) bool   { return true }
func (b *blocker) KeyPress(widget.KeyEvent) bool       { return true }

// blockWindow puts the blocker over the window, once.
func (m *Manager) blockWindow() {
	if m.blocker == nil {
		m.blocker = newBlocker(m)
		m.win.PushOverlay(m.blocker)
	}
}

// unblockWindow takes it away.
func (m *Manager) unblockWindow() {
	if m.blocker != nil {
		m.win.PopOverlay(m.blocker)
		m.blocker = nil
	}
}
