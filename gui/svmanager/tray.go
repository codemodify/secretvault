package svmanager

import (
	"context"
	"math"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/uitoolkit/platform"
)

// The tray icon: open the window, search, lock every vault, quit. With
// one, closing the window hides it there; without one (a desktop with no
// tray, or macOS, where uitoolkit shows no tray menu yet), closing the
// window quits.

func (m *Manager) startTray() {
	item, err := m.app.NewStatusItem(platform.StatusItemOptions{
		ID:      "secretvault-gui",
		Title:   "secretvault",
		Tooltip: "secretvault",
		Icon:    platform.StatusIcon{Name: "secretvault", Image: padlock(22)},
		Menu:    m.trayMenu(),
		OnClick: func() { m.post(m.showWindow) },
	})
	if err != nil || item == nil {
		return
	}
	m.tray = item
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
// bring it back from.
func (m *Manager) hasTray() bool {
	if m.tray == nil || !m.tray.Alive() {
		return false
	}
	switch m.tray.Backend() {
	case "stub":
		return false
	case "sni":
		// On Linux uitoolkit's status item is alive wherever there is a
		// session bus, which is as true of a GNOME that shows no tray
		// icons as of a KDE that does; there, hiding the window in the
		// tray would lose it. The tray's own registry says whether any
		// host shows the icons.
		return sniHostRegistered()
	}
	return true
}

// sniHostRegistered asks the session's StatusNotifierWatcher whether a
// host that shows status items has registered with it, over secretvault's
// own D-Bus code.
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

// padlock draws the tray's icon: a padlock, side pixels square, in white
// on a dark round tile, which reads on light and dark panels alike.
func padlock(side int) *paintengine2d.Image {
	img := paintengine2d.NewImage(side, side)
	ctx := paintengine2d.NewContext(img)
	s := float32(side)
	ctx.DrawRoundRect(paintengine2d.XYWH(0, 0, s, s), s*0.22, s*0.22, paintengine2d.Fill(paintengine2d.RGB(0.16, 0.30, 0.52)))
	white := paintengine2d.RGB(1, 1, 1)
	// The shackle: a half ring above the body.
	ctx.DrawArc(paintengine2d.Pt(s*0.5, s*0.46), s*0.18, s*0.2, math.Pi, math.Pi, paintengine2d.StrokePaint(white, s*0.09))
	ctx.DrawLine(paintengine2d.Pt(s*0.32, s*0.46), paintengine2d.Pt(s*0.32, s*0.52), paintengine2d.StrokePaint(white, s*0.09))
	ctx.DrawLine(paintengine2d.Pt(s*0.68, s*0.46), paintengine2d.Pt(s*0.68, s*0.52), paintengine2d.StrokePaint(white, s*0.09))
	// The body, and its keyhole.
	ctx.DrawRoundRect(paintengine2d.XYWH(s*0.22, s*0.48, s*0.56, s*0.36), s*0.06, s*0.06, paintengine2d.Fill(white))
	ctx.DrawCircle(paintengine2d.Pt(s*0.5, s*0.63), s*0.06, paintengine2d.Fill(paintengine2d.RGB(0.16, 0.30, 0.52)))
	return img
}
