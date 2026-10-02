package svmanager

import (
	"fmt"
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window: a menu bar; the vaults and their folders down the left; the
// search and the items in the middle; the open item (or its editor, its
// history, or the vault's grants and audit log) on the right; a status bar
// along the bottom.

// gap and pad are the window's spacing, everywhere: between controls, and
// round the inside of a pane.
const (
	gap = 8
	pad = 12
)

// sidebarFloor and listFloor are the least the vaults' sidebar and the
// item list are given, in 1x pixels, as the window narrows.
const (
	sidebarFloor = 160
	listFloor    = 200
)

// ui holds the window's widgets.
type ui struct {
	column    *widgets.FlexBox
	menu      *widgets.MenuBar
	vaultList *widgets.TableView
	folders   *widgets.TreeView
	search    *searchField
	items     *widgets.TableView
	itemsNote *widgets.Label
	browse    *widgets.Splitter // the items, and the item beside them
	main      *slot             // shows browse, or a vault's page
	pane      *slot             // the right-hand pane beside the items
	status    *widgets.StatusBar
	message   string

	vaultMenu map[string]*widgets.MenuItem // menu rows that depend on the vault shown
	itemMenu  map[string]*widgets.MenuItem // and on there being an item

	view *itemView // the item page, when it is up
}

// toned is a label whose text means something: muted, an error, a
// warning. uitoolkit colours it from the look as it paints it (Label.Tone),
// so it keeps meaning the same thing when the desktop goes from light to
// dark, and a status colour is the palette's made readable as text.
func toned(text string, t widgets.LabelTone) *widgets.Label {
	l := widgets.NewLabel(text)
	l.Tone = t
	return l
}

// muted is a label in the look's muted text colour.
func (m *Manager) muted(text string) *widgets.Label { return toned(text, widgets.ToneMuted) }

// heading is a section's title.
func heading(text string) *widgets.Label {
	l := widgets.NewLabel(text)
	l.Title = true
	return l
}

func (m *Manager) build() {
	u := &ui{vaultMenu: map[string]*widgets.MenuItem{}, itemMenu: map[string]*widgets.MenuItem{}}
	m.ui = u
	u.menu = m.buildMenu()

	u.vaultList = widgets.NewTableView([]widgets.TableColumn{
		{Title: "Vault"},
		{Title: "State", Width: 80, Align: style.AlignEnd},
	}, 0, m.vaultCell, func(i int) { m.vaultSelected(i) })
	u.vaultList.CellIcon = m.vaultIcon
	u.vaultList.OnActivate = func(i int) { m.vaultActivated(i) }
	u.vaultList.SetAccessibleName("Vaults")
	u.vaultList.DisableTypeAhead = true

	u.folders = widgets.NewTreeView()
	u.folders.OnSelect = func(n *widgets.TreeNode) { m.folderSelected(n) }
	u.folders.SetAccessibleName("Folders")

	vaultsHead := m.muted("VAULTS")
	foldersHead := m.muted("FOLDERS")
	sidebar := widgets.NewColumn(vaultsHead, u.vaultList, foldersHead, u.folders).WithGap(gap).WithPad(pad)
	sidebar.AddFlex(u.vaultList, 1)
	sidebar.AddFlex(u.folders, 2)

	u.search = newSearchField(m)
	u.itemsNote = m.muted("")
	u.items = widgets.NewTableView([]widgets.TableColumn{
		{Title: "Name"},
		{Title: "Kind", Width: 76},
	}, 0, m.itemCell, func(i int) { m.itemSelected(i) })
	u.items.CellIcon = m.itemIcon
	u.items.OnActivate = func(i int) { m.itemActivated(i) }
	u.items.SetAccessibleName("Items")
	middle := widgets.NewColumn(u.search, u.items, u.itemsNote).WithGap(gap).WithPad(pad)
	middle.AddFlex(u.items, 1)

	u.pane = newSlot()
	right := widgets.NewPad(pad, u.pane)

	// The splitters keep each pane at least as wide as what it holds
	// (uitoolkit's floors): the pane on the right, the page it shows, so
	// the editor's fields and their buttons stay in it. The lists get
	// floors of their own, because a table asks for all its columns and
	// can do with less.
	u.browse = widgets.NewSplitter(widgets.SplitColumns, middle, right)
	u.browse.Ratio = 0.42
	u.browse.MinA = listFloor
	// The vault's own page (grants, audit log) takes the place of both.
	u.main = newSlot()
	u.main.Set(u.browse)
	outer := widgets.NewSplitter(widgets.SplitColumns, sidebar, u.main)
	outer.Ratio = 0.21
	outer.MinA = sidebarFloor

	u.status = widgets.NewStatusBar("", "")
	u.column = widgets.NewColumn(u.menu, outer, u.status).WithGap(0)
	u.column.AddFlex(outer, 1)
	m.win.SetContent(newShortcutRoot(u.column, m.key))
	m.win.SetInitialFocus(u.items)
	m.showEmpty()
	m.drawStatus()
}

func (m *Manager) buildMenu() *widgets.MenuBar {
	u := m.ui
	item := func(set map[string]*widgets.MenuItem, text, accel string, on func()) *widgets.MenuItem {
		it := widgets.ItemAccel(text, accel, on)
		if set != nil {
			set[text] = it
		}
		return it
	}
	vault := func(text string, tab int) *widgets.MenuItem {
		return item(u.vaultMenu, text, "", func() { m.showVaultPage(tab) })
	}
	return widgets.NewMenuBar(
		widgets.NewMenu("&File",
			item(u.vaultMenu, "New item", "Ctrl+N", func() { m.newItem(nil) }),
			item(nil, "New vault…", "", m.newVault),
			item(nil, "Add vault folder…", "", m.addVaultFolder),
			item(nil, "Join a synced vault…", "", m.joinSynced),
			widgets.Sep(),
			item(u.vaultMenu, "Import…", "", m.importItems),
			item(u.vaultMenu, "Export…", "", m.exportItems),
			widgets.Sep(),
			&widgets.MenuItem{Text: "Emergency access", Submenu: []*widgets.MenuItem{
				item(nil, "Accept an invite…", "", m.acceptEmergency),
				item(nil, "Ask for access…", "", m.requestEmergency),
				item(nil, "Open the vault…", "", m.openEmergency),
			}},
			widgets.Sep(),
			item(nil, "Password generator…", "Ctrl+G", m.openGenerator),
			widgets.Sep(),
			item(nil, "Close window", "Ctrl+W", m.closeWindow),
			item(nil, "Quit", "Ctrl+Q", m.Quit),
		),
		widgets.NewMenu("&Edit",
			item(nil, "Find", "Ctrl+F", m.focusSearch),
			widgets.Sep(),
			item(u.itemMenu, "Copy password", "Ctrl+C", m.copySecret),
			item(u.itemMenu, "Copy username", "Ctrl+B", m.copyUsername),
			item(u.itemMenu, "Copy one-time code", "Ctrl+T", m.copyCode),
			item(u.itemMenu, "Copy password and minimise", "Ctrl+Shift+C", m.copyAndMinimise),
			item(u.itemMenu, "Copy reference", "", m.copyReference),
			widgets.Sep(),
			item(u.itemMenu, "Open", "", m.openSelected),
			item(u.itemMenu, "Edit item", "Ctrl+E", m.editItem),
			item(u.itemMenu, "Show or hide concealed values", "Ctrl+R", m.toggleRevealAll),
			item(u.itemMenu, "Rename…", "F2", m.renameItem),
			item(u.itemMenu, "Delete…", "Delete", m.deleteItem),
			item(u.itemMenu, "History", "Ctrl+H", m.showHistory),
			widgets.Sep(),
			item(u.vaultMenu, "Deleted items", "", m.showDeleted),
		),
		widgets.NewMenu("&Vault",
			item(u.vaultMenu, "Unlock", "Ctrl+U", func() { m.unlockVault("") }),
			item(u.vaultMenu, "Unlock with…", "", m.unlockWith),
			item(u.vaultMenu, "Lock", "Ctrl+L", func() { m.lockVault(false) }),
			item(nil, "Lock all vaults", "Ctrl+Shift+L", func() { m.lockVault(true) }),
			widgets.Sep(),
			item(u.vaultMenu, "Make default", "", m.makeDefault),
			widgets.Sep(),
			vault("Keyslots", tabKeyslots),
			vault("Devices", tabDevices),
			vault("Sharing and emergency access", tabSharing),
			vault("Sync", tabSync),
			vault("Containers", tabContainers),
			item(u.vaultMenu, "Grants and audit log", "Ctrl+Shift+G", func() { m.showVaultPage(tabGrants) }),
			vault("Settings", tabSettings),
		),
		widgets.NewMenu("&Keys",
			item(u.vaultMenu, "OpenPGP keys", "", func() { m.showKeysPage(tabPGP) }),
			item(u.vaultMenu, "S/MIME keys", "", func() { m.showKeysPage(tabSMIME) }),
			item(u.vaultMenu, "age identities", "", func() { m.showKeysPage(tabAge) }),
			widgets.Sep(),
			item(nil, "Identity files", "", func() { m.showKeysPage(tabIdentities) }),
			item(nil, "Security keys", "", func() { m.showKeysPage(tabSecurityKeys) }),
		),
		widgets.NewMenu("&Contacts",
			item(nil, "Contacts", "Ctrl+Shift+K", func() { m.showContactsPage(tabPeople) }),
			widgets.Sep(),
			item(nil, "Add…", "", m.addContact),
			item(nil, "Import…", "", m.importContacts),
			item(nil, "Look up…", "", m.lookupContact),
			item(nil, "Show my QR code…", "", m.showMyQR),
			widgets.Sep(),
			item(nil, "Check a signer…", "", m.checkSigner),
			item(nil, "Record a key seen in mail…", "", m.recordSeen),
			widgets.Sep(),
			item(nil, "Keep contacts in…", "", m.contactsVault),
			item(nil, "Directories", "", func() { m.showContactsPage(tabDirectories) }),
		),
		widgets.NewMenu("&Tools",
			item(nil, "Sign a file…", "", m.signFile),
			item(nil, "Check a signature…", "", m.verifyFile),
			item(nil, "Decrypt a file (OpenPGP)…", "", m.decryptPGPFile),
			widgets.Sep(),
			item(nil, "Encrypt a file (age)…", "", m.encryptAgeFile),
			item(nil, "Decrypt a file (age)…", "", m.decryptAgeFile),
			widgets.Sep(),
			item(nil, "Inspect a message…", "", m.inspectMessage),
			item(nil, "Sign and encrypt a message…", "", m.composeMessage),
			widgets.Sep(),
			item(nil, "Resolve a reference…", "", m.resolveReference),
			item(nil, "Check an env file…", "", m.checkEnvFile),
			item(nil, "Check a template…", "", m.checkTemplate),
		),
		widgets.NewMenu("&Desktop",
			item(nil, "System keyring", "", func() { m.showDesktopPage(tabKeyring) }),
			item(nil, "Browsers", "", func() { m.showDesktopPage(tabBrowsers) }),
			item(nil, "GnuPG", "", func() { m.showDesktopPage(tabGnuPG) }),
			item(nil, "Program helpers", "", func() { m.showDesktopPage(tabHelpers) }),
			item(nil, "Host daemon", "", func() { m.showDesktopPage(tabHost) }),
		),
		widgets.NewMenu("&Help",
			item(nil, "Keys", "F1", m.showKeys),
			item(nil, "About secretvault", "", m.showAbout),
		),
	)
}

// enableMenus greys out what cannot be done now.
func (m *Manager) enableMenus() {
	v := m.vaultInfo(m.vault)
	for _, it := range m.ui.vaultMenu {
		it.Disabled = m.gone || v == nil
	}
	if v != nil && !m.gone {
		m.ui.vaultMenu["Unlock"].Disabled = !v.Locked
		m.ui.vaultMenu["Lock"].Disabled = v.Locked
		m.ui.vaultMenu["Make default"].Disabled = v.Default
	}
	// The vault's page covers the items: what acts on an item waits
	// until they are back, rather than act on a pane nobody can see.
	page := m.showingVaultPage()
	m.ui.vaultMenu["New item"].Disabled = m.ui.vaultMenu["New item"].Disabled || page
	none := m.gone || m.targetName() == "" || page
	for _, it := range m.ui.itemMenu {
		it.Disabled = none
	}
	m.ui.menu.Invalidate()
}

// drawStatus fills the status bar: the vault shown and its state, then
// the latest message.
func (m *Manager) drawStatus() {
	if m.ui == nil {
		return
	}
	var b strings.Builder
	switch v := m.vaultInfo(m.vault); {
	case m.gone:
		b.WriteString("secretvaultd is not running")
	case m.vault == "":
		b.WriteString("No vault")
	case v == nil:
		b.WriteString(m.vault)
	default:
		b.WriteString(v.Name)
		switch {
		case v.ID == "":
			b.WriteString(": missing")
		case v.Locked:
			b.WriteString(": locked")
		default:
			b.WriteString(": unlocked")
			if m.listed {
				fmt.Fprintf(&b, ", %s", plural(len(m.entries), "item"))
			}
		}
		if s, ok := m.syncs[v.Name]; ok {
			b.WriteString(syncLine(s))
		}
	}
	if !m.gone {
		b.WriteString(m.emergencyLine())
	}
	if m.busy > 0 {
		b.WriteString("  …")
	}
	m.ui.status.Set(0, b.String())
	m.ui.status.Set(1, m.ui.message)
	m.enableMenus()
}

// plural is "1 item", "2 items".
func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// slot shows one page at a time, filling its box: the right-hand pane.
type slot struct {
	widget.Base
}

func newSlot() *slot {
	s := &slot{}
	s.Init(s)
	return s
}

// Set replaces what the slot shows.
func (s *slot) Set(c widget.Component) {
	s.ClearChildren()
	if c != nil {
		s.Add(c)
	}
	s.RequestLayout()
	s.Invalidate()
}

// Page is what the slot shows.
func (s *slot) Page() widget.Component {
	if kids := s.Children(); len(kids) > 0 {
		return kids[0]
	}
	return nil
}

func (s *slot) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(c.MaxW, c.MaxH))
}

// MinWidth is the floor of the page shown (widget.MinWidther), so that a
// splitter keeps the pane at least that wide.
func (s *slot) MinWidth() float32 { return widget.MinWidthOf(s.Page()) }

func (s *slot) Arrange(r paintengine2d.Rect) {
	s.SetBounds(r)
	for _, c := range s.Children() {
		c.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
	}
}

// shortcutRoot is the window's content with the manager's own keys: those
// no focused widget took reach it.
type shortcutRoot struct {
	widget.Base
	onKey func(widget.KeyEvent) bool
}

func newShortcutRoot(child widget.Component, onKey func(widget.KeyEvent) bool) *shortcutRoot {
	r := &shortcutRoot{onKey: onKey}
	r.Init(r)
	r.Add(child)
	return r
}

func (r *shortcutRoot) Measure(c layout.Constraints) paintengine2d.Point {
	return r.Children()[0].Measure(c)
}

func (r *shortcutRoot) Arrange(b paintengine2d.Rect) {
	r.SetBounds(b)
	r.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

// MinWidth is the content's floor (widget.MinWidther).
func (r *shortcutRoot) MinWidth() float32 { return widget.MinWidthOf(r.Children()[0]) }

func (r *shortcutRoot) KeyPress(e widget.KeyEvent) bool { return r.onKey != nil && r.onKey(e) }

// key handles the keys no widget took, before the menus' accelerators.
func (m *Manager) key(e widget.KeyEvent) bool {
	focus := m.win.Focus()
	switch {
	case e.Key == platform.KeyDown && focus == widget.Component(m.ui.search) && m.ui.items.RowCount > 0:
		// From the search to the results.
		m.win.RequestFocus(m.ui.items)
		if m.ui.items.Selected < 0 {
			m.ui.items.Selected = 0
			m.itemSelected(0)
		}
		return true
	case e.Key == platform.KeyEscape && m.query != "":
		m.ui.search.SetText("") // which clears the search
		return true
	case e.Key == platform.KeyDelete && e.Mods&(platform.ModCtrl|platform.ModAlt|platform.ModShift) == 0:
		// Delete deletes the item only where the item is what has the
		// keyboard: the list, or the item beside it. Anywhere else (a
		// field that had nothing left to delete, the folders) it does
		// nothing, rather than reach the menu's Delete.
		if focus == widget.Component(m.ui.items) || (m.editor == nil && !m.showingHistory() && isUnder(focus, m.ui.pane)) {
			m.deleteItem()
		}
		return true
	}
	return false
}

// isUnder reports whether c is root or inside it.
func isUnder(c, root widget.Component) bool {
	for ; c != nil; c = c.Parent() {
		if c == root {
			return true
		}
	}
	return false
}

// searchField is the search box. Ctrl+C in it copies the selected item's
// secret when no text is selected in it, as KeePassXC's does; with text
// selected, it copies that text, as any field does.
type searchField struct {
	*widgets.TextField
	m *Manager
}

func newSearchField(m *Manager) *searchField {
	f := &searchField{TextField: widgets.NewTextField("", "Search (Ctrl+F)", nil), m: m}
	f.TextField.Init(f)
	f.Clearable = true
	f.OnChange = func(s string) { m.setQuery(s) }
	f.OnSubmit = func(string) { m.openFirstMatch() }
	f.SetAccessibleName("Search")
	return f
}

func (f *searchField) KeyPress(e widget.KeyEvent) bool {
	if e.Key == platform.KeyC && e.Mods.Ctrl() && !e.Mods.Shift() {
		if a, b := f.Selection(); a == b {
			f.m.copySecret()
			return true
		}
	}
	return f.TextField.KeyPress(e)
}
