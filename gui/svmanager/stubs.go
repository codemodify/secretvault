package svmanager

type contactsPage struct{ *tabbedPage }
type desktopPage struct{ *tabbedPage }

const (
	tabPeople = iota
	tabDirectories
)

const (
	tabKeyring = iota
	tabBrowsers
	tabGnuPG
	tabHelpers
	tabHost
)

func (m *Manager) showContactsPage(int) {}
func (m *Manager) addContact()          {}
func (m *Manager) importContacts()      {}
func (m *Manager) lookupContact()       {}
func (m *Manager) showMyQR()            {}
func (m *Manager) checkSigner()         {}
func (m *Manager) recordSeen()          {}
func (m *Manager) contactsVault()       {}
func (m *Manager) signFile()            {}
func (m *Manager) verifyFile()          {}
func (m *Manager) decryptPGPFile()      {}
func (m *Manager) encryptAgeFile()      {}
func (m *Manager) decryptAgeFile()      {}
func (m *Manager) inspectMessage()      {}
func (m *Manager) composeMessage()      {}
func (m *Manager) resolveReference()    {}
func (m *Manager) checkEnvFile()        {}
func (m *Manager) checkTemplate()       {}
func (m *Manager) showDesktopPage(int)  {}
