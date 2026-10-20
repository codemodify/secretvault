package svmanager

// Settings: secretvault's own, on the back of the window, which the mark
// at its title bar's right end turns it over to (flip.go): its look
// (appearance.go), its keyboard shortcuts, About secretvault, and where
// things are kept. Its tabs are picked in the title bar (titlebar.go), as
// every part's are.

// Settings' tabs.
const (
	tabSetAppearance = iota
	tabSetShortcuts
	tabSetAbout
	tabSetWhere
)

// showSettings turns the window over to Settings, on its back (flip.go),
// open at tab (-1 for the one it shows already).
func (m *Manager) showSettings(tab int) {
	open := func() {
		if tab >= 0 && m.spage != nil {
			m.selectTab(m.spage, tab)
		}
	}
	if m.ui == nil || m.ui.sections == nil || m.onBack() {
		open()
		return
	}
	m.turn(func() {
		m.ui.sections.Select(secSettings) // which makes its page, or fills it again (sectionShown)
		open()
	})
}

// settingsShown makes Settings' page if there is none yet.
func (m *Manager) settingsShown() {
	if pg := m.spage; pg != nil {
		// Filled again, the keyboard on what it is filled with: what had
		// it is gone.
		pg.panes[pg.selected()].refresh()
		m.paneShown(pg, pg.selected())
		return
	}
	p := &tabbedPage{kind: pageSettings, title: "Settings"}
	p.panes = []*pane{
		newPane("Appearance", m.fillAppearance),
		newPane("Keyboard shortcuts", m.fillShortcuts),
		newPane("About secretvault", m.fillAbout),
		newPane("Where things are kept", m.fillWhere),
	}
	m.spage = p
	m.standPage(p, m.ui.settingsHost, tabSetAppearance)
}
