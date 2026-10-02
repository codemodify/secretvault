package svmanager

type desktopPage struct{ *tabbedPage }

const (
	tabKeyring = iota
	tabBrowsers
	tabGnuPG
	tabHelpers
	tabHost
)

func (m *Manager) signFile()           {}
func (m *Manager) verifyFile()         {}
func (m *Manager) decryptPGPFile()     {}
func (m *Manager) encryptAgeFile()     {}
func (m *Manager) decryptAgeFile()     {}
func (m *Manager) inspectMessage()     {}
func (m *Manager) composeMessage()     {}
func (m *Manager) resolveReference()   {}
func (m *Manager) checkEnvFile()       {}
func (m *Manager) checkTemplate()      {}
func (m *Manager) showDesktopPage(int) {}
