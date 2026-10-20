package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window's three parts, Vault, Disk and Tools, picked from the rail
// (rail.go).

// The window's parts (ui.sections).
const (
	secVaults = iota
	secDisks
	secTools
	secSettings // the title bar's button's, at its right end (appsettings.go), not the rail's
)

// section is the window's tab shown.
func (m *Manager) section() int {
	if m.ui == nil || m.ui.sections == nil {
		return secVaults
	}
	return m.ui.sections.Selected()
}

// showSection brings the window's part i forward: Settings, or another
// part from Settings, on the window's other face (flip.go).
func (m *Manager) showSection(i int) {
	if m.ui == nil || m.ui.sections == nil || m.ui.sections.Selected() == i {
		return
	}
	switch {
	case i == secSettings:
		m.showSettings(-1)
	case m.onBack():
		m.turn(func() { m.ui.sections.Select(i) })
	default:
		m.ui.sections.Select(i)
	}
}

// sectionShown fills the tab brought forward: the disks are asked for
// again each time, and the tools are made again for another vault.
func (m *Manager) sectionShown(i int) {
	m.ui.rail.mark(i)
	m.ui.rail.SetVisible(i != secSettings) // the front's: the back is Settings alone
	m.keepFocus()
	switch i {
	case secDisks:
		m.disksShown()
	case secTools:
		m.toolsShown()
	case secSettings:
		m.settingsShown()
	}
	m.enableMenus()
	m.restateFloor()
}

// keepFocus keeps the keyboard in sight: off what went out of it (a part
// or a tab no longer shown), it goes to the part's button, on the rail or
// in the title bar, from where Tab goes into the part, and Ctrl+Page Up
// and Down go on to the next.
func (m *Manager) keepFocus() {
	f := m.win.Focus()
	if f != nil && (isUnder(f, m.ui.sections.Page()) || isUnder(f, m.ui.rail) || isUnder(f, m.win.TitleBar()) ||
		m.ui.title != nil && m.ui.title.drop != nil && isUnder(f, m.ui.title.drop)) {
		return
	}
	switch i := m.section(); {
	case i < len(m.ui.rail.parts):
		m.win.FocusOn(m.ui.rail.parts[i].btn)
	case m.ui.title != nil:
		m.win.FocusOn(m.ui.title.settings.btn) // Settings': the title bar's
	}
}

// sectionsBox holds the window's tabs and answers for their floor: the
// tab shown's. A TabView answers for none, and a probe of one sees only
// the Vaults tab's splitter, which measures a fixed 320 unbounded.
type sectionsBox struct {
	widget.Base
	tabs     *widgets.TabView
	contents []widget.Component
}

func newSectionsBox(tabs *widgets.TabView, contents ...widget.Component) *sectionsBox {
	b := &sectionsBox{tabs: tabs, contents: contents}
	b.Init(b)
	b.Add(tabs)
	return b
}

func (b *sectionsBox) Measure(c layout.Constraints) paintengine2d.Point { return b.tabs.Measure(c) }

func (b *sectionsBox) Arrange(r paintengine2d.Rect) {
	b.SetBounds(r)
	b.tabs.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

// MinWidth is the tab shown's floor (widget.MinWidther).
func (b *sectionsBox) MinWidth() float32 {
	i := b.tabs.Selected()
	if i < 0 || i >= len(b.contents) {
		return 0
	}
	return widget.MinWidthOf(b.contents[i])
}
