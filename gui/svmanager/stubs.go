package svmanager

type desktopPage struct{ *tabbedPage }

const (
	tabKeyring = iota
	tabBrowsers
	tabGnuPG
	tabHelpers
	tabHost
)

func (m *Manager) showDesktopPage(int) {}
