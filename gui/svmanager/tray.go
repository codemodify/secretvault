package svmanager

import (
	"context"
	"time"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/uitoolkit/platform"
)

// The tray icon: open the window, search, lock every vault, quit. With
// one, closing the window hides it there; without one (a desktop that
// shows no tray icons), closing the window quits.

func (m *Manager) startTray() {
	item, err := m.app.NewStatusItem(platform.StatusItemOptions{
		ID:      "secretvault-gui",
		Title:   "secretvault",
		Tooltip: "secretvault",
		Icon:    platform.StatusIcon{Name: "secretvault", Image: secretui.Icon(22)},
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
		{Text: "Search…", OnClick: func() { m.post(m.quickSearch) }},
		{Text: "Lock all vaults", OnClick: func() { m.post(func() { m.lockVault(true) }) }},
		{Separator: true},
		{Text: "Quit", OnClick: func() { m.post(m.Quit) }},
	}
}

// hasTray reports whether there is a tray to hide the window in, and to
// bring it back from: somebody shows the icon (uitoolkit's Shown).
func (m *Manager) hasTray() bool {
	if m.tray == nil || !m.tray.Alive() || !m.tray.Shown() {
		return false
	}
	switch m.tray.Backend() {
	case "stub":
		return false
	case "sni":
		// uitoolkit reads the StatusNotifierWatcher's host flag, but
		// takes a bus with no watcher at all for one that shows the
		// icon (uitoolkit-gaps.md, 23). A GNOME without the AppIndicator
		// extension is exactly that bus, and hiding the window there
		// would lose it; so no watcher is no tray.
		return sniHostRegistered()
	}
	return true
}

// sniHostRegistered asks the session's StatusNotifierWatcher whether a
// host that shows status items has registered with it, over secretvault's
// own D-Bus code. No watcher is no.
func sniHostRegistered() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	addr, err := svdbus.SessionBusAddress()
	if err != nil {
		return false
	}
	conn, err := svdbus.ConnectContext(ctx, addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	v, err := conn.GetProperty(ctx, "org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
		"org.kde.StatusNotifierWatcher", "IsStatusNotifierHostRegistered")
	if err != nil {
		return false
	}
	on, _ := v.Value.(bool)
	return on
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

// quickSearch is the tray's Search: the window, with the search box
// ready to type into.
func (m *Manager) quickSearch() {
	m.showWindow()
	m.focusSearch()
}
