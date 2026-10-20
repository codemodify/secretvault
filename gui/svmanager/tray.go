package svmanager

import (
	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/uitoolkit/platform"
)

// The tray icon: open the window, filter the items, lock every vault,
// quit. With one, closing the window hides it there; without one (a
// desktop that shows no tray icons), closing the window quits.

func (m *Manager) startTray() {
	item, err := m.app.NewStatusItem(platform.StatusItemOptions{
		ID:      "secretvault-gui",
		Title:   "secretvault",
		Tooltip: "secretvault",
		// The logo, and no theme name beside it: a name is sent as well
		// as the picture, and which the tray shows is its own choice,
		// while no icon theme has a "secretvault" (uitoolkit 0.23.11).
		Icon:    platform.StatusIcon{Image: secretui.Icon(22)},
		Menu:    m.trayMenu(),
		OnClick: func() { m.post(m.showWindow) },
	})
	if err != nil || item == nil {
		return
	}
	m.tray = item
	// A tray that goes away (an extension switched off, a panel that
	// quit) while the window is hidden in it would take the window with
	// it: the window comes back instead.
	item.SetOnShownChange(func(shown bool) {
		m.post(func() {
			if !shown && m.hidden {
				m.showWindow()
			}
		})
	})
}

func (m *Manager) trayMenu() []platform.StatusMenuItem {
	return []platform.StatusMenuItem{
		{Text: "Open secretvault", OnClick: func() { m.post(m.showWindow) }},
		{Text: "Filter the items…", OnClick: func() { m.post(m.quickFilter) }},
		{Text: "Lock all vaults", OnClick: func() { m.post(func() { m.lockVault(true) }) }},
		{Separator: true},
		{Text: "Quit", OnClick: func() { m.post(m.Quit) }},
	}
}

// hasTray reports whether there is a tray to hide the window in, and to
// bring it back from: somebody shows the icon. uitoolkit's Shown asks the
// desktop (on Linux, whether a StatusNotifierWatcher is on the bus and has
// a host registered: a GNOME without the AppIndicator extension has
// neither, and hiding the window there would lose it).
func (m *Manager) hasTray() bool {
	return m.tray != nil && m.tray.Alive() && m.tray.Backend() != "stub" && m.tray.Shown()
}

// closeRequested is the window's close button: to the tray if there is
// one, else quit.
func (m *Manager) closeRequested() bool {
	if m.hasTray() {
		m.hideWindow()
		return false
	}
	m.shutdown()
	m.app.Quit()
	return true
}

// closeWindow is Ctrl+W: what the close button does.
func (m *Manager) closeWindow() {
	if m.closeRequested() {
		m.win.Close()
	}
}

// hideWindow hides the window in the tray. What was on it goes: an open
// item is closed and wiped, as when it is left.
func (m *Manager) hideWindow() {
	m.closeItem()
	m.wipeHistory()
	if m.showingHistory() {
		m.showSelected()
	}
	if m.editor != nil {
		m.editor.hideSecrets()
	}
	m.win.Hide()
	m.hidden = true
}

// showWindow brings the window back, in front.
func (m *Manager) showWindow() {
	m.win.Show()
	m.win.Activate()
	m.hidden = false
}

// quickFilter is the tray's Filter the items: the window, with the filter
// ready to type into.
func (m *Manager) quickFilter() {
	m.showWindow()
	m.focusFilter()
}
