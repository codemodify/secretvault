package svmanager

import (
	"slices"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The Vault tab beside the vaults. The vault shown opens, in the list of
// vaults, into what it holds: a row for each kind of item, with how many
// it has, then My keys and Contacts, pages with tabs of their own, and
// About this vault, the vault's own pages (the ways it unlocks, sharing,
// devices, sync, grants, audit log and settings) as tabs. The row picked
// shows here, one at a time (stage): for a kind of item, a list of
// its items (content.go) with the item picked beside them, one view for
// every kind. Every item is in one kind's row, or in My keys; one filter
// narrows them all, and the rows' counts follow it. A page stays once
// made, for the vault it was made for, and asks the daemon again each
// time it is shown; another vault's makes it again. A disk's key is in
// Disk keys, each one leading to its disk in the Disk tab, and back.

// What can be picked under a vault (ui.vaultTabs): the kinds of item, in
// the order the list shows them, then the pages.
const (
	vtLogins = iota
	vtPasswords
	vtPasskeys
	vtCodes
	vtCards
	vtDetails
	vtNotes
	vtSSH
	vtAPI
	vtKV
	vtKeyItems
	vtDiskKeys
	vtOther
	vtMyKeys
	vtContacts
	vtVault

	lastItemTab = vtOther // the ones up to it are kinds of item
)

// vaultTabTitles are their names, as the list of vaults shows them, and
// tabKinds the kind of item each kind's row shows (Other shows those of no
// row of their own too): svops.KindRows, as the TUI's.
var vaultTabTitles, tabKinds = func() ([]string, map[int]string) {
	titles, kinds := []string{}, map[int]string{}
	for i, r := range svops.KindRows {
		titles = append(titles, r.Title)
		kinds[i] = r.Kind
	}
	return append(titles, svops.MyKeysRow, svops.ContactsRow, svops.AboutVaultRow), kinds
}()

// stage shows one of its contents at a time, as a TabView without its row
// of tabs: what is picked under the vault shown, picked from the list of
// vaults (vaultlist.go), and the window's parts, picked from the rail
// (rail.go).
type stage struct {
	*slot
	sel      int
	contents []widget.Component
	onChange func(int)
}

func newStage(contents []widget.Component, onChange func(int)) *stage {
	s := &stage{slot: newSlot(), contents: contents, onChange: onChange}
	s.slot.Set(contents[0])
	return s
}

// Selected is what is shown.
func (s *stage) Selected() int { return s.sel }

// Select shows i, as a click on its row does, and tells onChange.
func (s *stage) Select(i int) {
	if i == s.sel || i < 0 || i >= len(s.contents) {
		return
	}
	s.sel = i
	if s.Page() != s.contents[i] {
		s.Set(s.contents[i])
	}
	if s.onChange != nil {
		s.onChange(i)
	}
}

// buildVaultTabs makes what can be picked under a vault, the kinds of item
// sharing items.
func (m *Manager) buildVaultTabs(items widget.Component) widget.Component {
	u := m.ui
	u.itemsView = items
	u.keysHost, u.contactsHost = newSlot(), newSlot()
	u.keysHost.onSet, u.contactsHost.onSet = m.restateFloor, m.restateFloor
	// About this vault: the vault page's tabs, a slot each.
	var sub []widgets.Tab
	u.vaultHosts = nil
	for _, t := range []string{"Ways to unlock", "Sharing", "Devices", "Sync", "Grants", "Audit log", "Settings"} {
		s := newSlot()
		s.onSet = m.restateFloor
		u.vaultHosts = append(u.vaultHosts, s)
		sub = append(sub, widgets.Tab{Title: t, Content: widgets.NewPad(pad, s)})
	}
	subContents := make([]widget.Component, len(sub))
	for i, t := range sub {
		subContents[i] = t.Content
	}
	// Its tabs are picked in the title bar, as every page's.
	u.vaultSub = newStage(subContents, func(k int) {
		if u.vaultTabs.Selected() == vtVault {
			m.vaultPageShown(k)
			m.drawTitle()
		}
	})
	u.vaultSub.SetAccessibleName("About this vault")
	contents := make([]widget.Component, vtVault+1)
	for i := vtLogins; i <= lastItemTab; i++ {
		contents[i] = items
	}
	// The tab shown's floor is the tabs' (a TabView has none).
	contents[vtMyKeys], contents[vtContacts] = newInset(u.keysHost), newInset(u.contactsHost)
	contents[vtVault] = newInset(u.vaultSub.slot)
	u.vaultTabs = newStage(contents, m.vaultTabShown)
	u.vaultTabs.onSet = m.restateFloor
	u.vaultTabs.SetAccessibleName("What the vault holds")
	return newPage("vault tabs", u.vaultTabs.slot, m.vaultTabKey)
}

// inItemTab reports whether e shows in the tab of items shown.
func (m *Manager) inItemTab(e *svrpc.Entry) bool { return tabOf(e) == m.itemTab }

// tabOf is the kind's row e shows in (svops.KindRowOf): -1 for a key
// that is My keys'.
func tabOf(e *svrpc.Entry) int { return svops.KindRowOf(&e.Item) }

// vaultTabKey is a page's own keys (Delete on a grant), and Escape back
// to the items.
func (m *Manager) vaultTabKey(e widget.KeyEvent) bool {
	if !m.showingVaultPage() {
		return false
	}
	if m.page != nil && m.page.keys != nil && m.page.keys(e) {
		return true
	}
	if e.Key == platform.KeyEscape {
		m.closeVaultPage()
		return true
	}
	return false
}

// showVaultTab brings the Vault tab's tab i forward, its page made or
// asked for again.
func (m *Manager) showVaultTab(i int) {
	m.showSection(secVaults)
	if m.ui.vaultTabs.Selected() != i {
		m.ui.vaultTabs.Select(i) // which shows it (vaultTabShown)
		return
	}
	m.vaultTabShown(i)
}

// showVaultPageTab brings the Vault tab forward at the vault page's tab k.
func (m *Manager) showVaultPageTab(k int) {
	m.showSection(secVaults)
	if m.ui.vaultTabs.Selected() != vtVault {
		if m.ui.vaultSub.Selected() != k {
			m.ui.vaultSub.Select(k) // not shown yet: it is when the tab is
		}
		m.ui.vaultTabs.Select(vtVault)
		return
	}
	if m.ui.vaultSub.Selected() != k {
		m.ui.vaultSub.Select(k)
		return
	}
	m.vaultPageShown(k)
}

// vaultTabShown fills the tab brought forward.
func (m *Manager) vaultTabShown(i int) {
	if i > lastItemTab {
		// The item pane is hidden: an item open in it is let go of, its
		// values wiped, rather than kept where nobody sees it; the one
		// picked comes back when the items do. An edit stays.
		m.leaveHistory()
		if m.editor == nil {
			m.closeItem()
		}
	}
	switch {
	case i <= lastItemTab:
		m.page = nil
		m.showItemTab(i)
	case i == vtContacts:
		m.contactsShown()
	case m.vault == "" || m.gone:
		m.page = nil
	case i == vtMyKeys:
		m.keysShown()
	default:
		m.vaultPageShown(m.ui.vaultSub.Selected())
	}
	m.enableMenus()
	m.syncCapture()
}

// showItemTab shows the items of kind i; an item picked that is not one
// of them is let go of.
func (m *Manager) showItemTab(i int) {
	m.itemTab = i
	m.applyFilter()
	if m.listed && m.cursor != "" && !slices.ContainsFunc(m.shown, func(k int) bool { return m.entries[k].Item.Name == m.cursor }) &&
		m.editor == nil && !m.showingHistory() {
		m.cursor = ""
		m.closeItem()
	} else if m.cur == nil && m.editor == nil && !m.showingHistory() {
		m.showSelected()
	}
	m.syncList()
}

// vaultChanged shows the tab up for the vault now shown: its page is made
// again for it.
func (m *Manager) vaultChanged() {
	if i := m.ui.vaultTabs.Selected(); i > lastItemTab && i != vtContacts {
		m.vaultTabShown(i)
	}
}

// keysShown makes the keys' page for the vault shown, or asks again.
func (m *Manager) keysShown() {
	if m.kpage == nil || m.kpage.vault != m.vault {
		m.makeKeysPage()
		m.standPage(m.kpage.tabbedPage, m.ui.keysHost, tabPGP)
	} else {
		m.kpage.panes[m.kpage.selected()].refresh()
	}
	m.page = m.kpage.tabbedPage
}

// contactsShown makes the contacts' page, or asks again.
func (m *Manager) contactsShown() {
	if m.cpage == nil {
		m.makeContactsPage()
		m.standPage(m.cpage.tabbedPage, m.ui.contactsHost, tabPeople)
	} else {
		m.cpage.panes[m.cpage.selected()].refresh()
	}
	m.page = m.cpage.tabbedPage
}

// vaultPageShown shows the vault page's tab k, the page made for the
// vault shown if it is not yet: each of its tabs is one of the Vault
// tab's own.
func (m *Manager) vaultPageShown(k int) {
	if m.vpage == nil || m.vpage.vault != m.vault {
		p := m.makeVaultPage()
		p.pick = m.showVaultPageTab
		for j, pn := range p.panes {
			pn.pg = p.tabbedPage
			pn.filled = false
			pn.box.Set(m.paragraph("Loading…"))
			m.ui.vaultHosts[j].Set(pn.box)
		}
		m.vpage = p
	}
	p := m.vpage
	p.sel = k
	m.page = p.tabbedPage
	p.panes[k].refresh()
}

// closeVaultPage brings the tab of items shown last back, the item
// picked beside the list as it was.
func (m *Manager) closeVaultPage() {
	if m.ui == nil || m.ui.vaultTabs == nil {
		return
	}
	if m.showingVaultPage() {
		m.ui.vaultTabs.Select(m.itemTab)
		m.focus(m.ui.content)
	}
	m.page = nil
	m.syncList()
}
