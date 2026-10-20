package svmanager

import (
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window: its own title bar (titlebar.go), the rail down its left
// (rail.go), and the part the rail picks: Vault, Disk or Tools, or on the
// window's back Settings (flip.go). The Vault part is what the title bar's
// breadcrumbs pick of the vault shown (vaulttabs.go): a list of items
// (content.go) with the item picked beside it, its editor or its history,
// or a page of the vault's own. The Disk part shows the encrypted disk
// picked (disks.go); Tools holds everything that acts outside the vaults
// (toolspage.go). There is no status bar: notes say what there is to say
// (notes.go).

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
	root      *shortcutRoot
	vaultHost *layered // the Vault part, and a locked vault's face over it (lockface.go)
	column    *widgets.FlexBox
	menu      *widgets.MenuBar
	vaultList *vaultListView
	filter    *filterField
	browse    *widgets.Splitter // the list, and the pane beside it
	pane      *slot             // the right-hand pane beside the list
	notes     *notes            // what the window has to say (notes.go)
	message   string            // the last thing it said
	vaultTip  string            // the vault shown's state, its breadcrumb's tip

	sections     *stage           // Vault, Disk, Tools
	rail         *rail            // down the left: the parts, and what is of none of them
	vaultTab     widget.Component // the Vault tab: the vaults, and the tabs beside them
	vaultTabs    *stage           // what is picked under the vault shown: a kind of item, My keys, Contacts, About this vault (vaulttabs.go)
	vaultSub     *stage           // Vault's: Ways to unlock … Settings
	itemsView    widget.Component // the items and the item picked, in the tab of items shown
	keysHost     *slot            // My keys' page
	contactsHost *slot            // Contacts' page
	vaultHosts   []*slot          // the vault page's tabs, a slot each
	// Under the list: making an item, importing, exporting, and the
	// deleted items.
	newItemButton, importButton, exportButton, deletedButton *widgets.ToolButton
	content                                                  *contentList       // the Vault tab's middle pane
	disksHost                                                *slot              // the Disk tab's page
	settingsHost                                             *slot              // Settings' page
	title                                                    *titleBar          // the window's title bar (titlebar.go)
	flip                                                     *widgets.FlipPanel // the window's two faces, which take turns to hold root (flip.go)
	toolsHost                                                *slot              // the Tools tab's page

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

	// The vaults are picked in the title bar, from the vault's
	// breadcrumb (titlebar.go).
	u.vaultList = newVaultList(m)

	u.filter = newFilterField(m)
	u.content = newContentList(m)
	// Under the list: the filter, and making an item of the kind shown.
	// Importing, exporting and the deleted items are the vault's, on the
	// title bar.
	u.newItemButton = iconButton("New item", "New item, of the kind shown", style.IconNew, nil, m.newItemHere)
	u.importButton = iconButton("Import", "Import from a browser or another password manager", style.IconDownload, nil, m.importItems)
	u.exportButton = iconButton("Export", "Export to KeePass (KDBX) or CXF", style.IconExternalLink, nil, m.exportItems)
	u.deletedButton = iconButton("Deleted items", "Deleted items: bring one back", style.IconTrash, nil, m.showDeleted)
	actions := widgets.NewRow(u.newItemButton).WithGap(4)
	middle := widgets.NewColumn(u.content, u.filter, actions).WithGap(gap).WithPad(pad)
	middle.AddFlex(u.content, 1)

	// The pane beside the list shows what is picked in it: an item (or
	// its editor, or its history), or the items picked together.
	u.pane = newSlot()
	u.pane.onSet = m.restateFloor
	right := newInset(widgets.NewPad(pad, u.pane)) // a pane sunk into the window (soft.go)

	// The splitters keep each pane at least as wide as what it holds
	// (uitoolkit's floors): the pane on the right, the page it shows, so
	// the editor's fields and their buttons stay in it. The lists get
	// floors of their own, because a list can do with less than it asks
	// for. The window is kept as wide as all of that together
	// (restateFloor).
	u.browse = widgets.NewSplitter(widgets.SplitColumns, middle, right)
	u.browse.Ratio = 0.38
	u.browse.MinA = listFloor
	// The items and the item are what the Vault part shows of a kind of
	// item; the other things a vault holds have pages of their own
	// (vaulttabs.go). Which is picked in the title bar.
	outer := m.buildVaultTabs(u.browse)
	u.vaultTab = outer
	u.vaultHost = newLayered(outer)

	u.disksHost, u.toolsHost, u.settingsHost = newSlot(), newSlot(), newSlot()
	u.disksHost.onSet, u.toolsHost.onSet, u.settingsHost.onSet = m.restateFloor, m.restateFloor, m.restateFloor
	// The window's parts, Vault, Disk and Tools, picked from the rail
	// down its left edge, and Settings, from the title bar's right end.
	u.sections = newStage([]widget.Component{u.vaultHost, newInset(u.disksHost), newInset(u.toolsHost), newInset(u.settingsHost)}, m.sectionShown)
	u.sections.onSet = m.restateFloor
	u.sections.SetAccessibleName("secretvault")
	u.rail = m.newRail()
	u.rail.mark(secVaults)
	m.drawContent()

	u.column = widgets.NewRow(u.rail, u.sections.slot).WithGap(0)
	u.column.AddFlex(u.sections.slot, 1)
	frame := newPageFrame(m, u.column) // the rail's and title bar's edges
	u.notes = &notes{m: m}
	root := newShortcutRoot(frame, m.key)
	root.menu = u.menu
	u.root = root
	m.buildFaces(root)
	m.buildTitleBar()
	m.win.SetInitialFocus(u.content)
	m.showEmpty()
	m.drawStatus()
}

// buildMenu makes the menus. They are the window's tabs: Vaults, Disks
// and Tools, after secretvault's own; each entry is in the menu of the
// tab where what it does is shown. The TUI's ':' menu has the same groups
// (svtui/menu.go).
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
	// disks does on in the Disks tab, brought forward first.
	disks := func(text string, on func(*disksPage)) *widgets.MenuItem {
		return item(nil, text, "", func() {
			m.showDisks()
			on(m.disks)
		})
	}
	tools := func(text string, tab int) *widgets.MenuItem {
		return item(nil, text, "", func() { m.showTools(tab) })
	}
	return widgets.NewMenuBar(
		widgets.NewMenu("&secretvault",
			item(nil, "Keyboard shortcuts", "F1", m.showKeys),
			item(nil, "About secretvault", "", m.showAbout),
			widgets.Sep(),
			item(nil, "Close window", "Ctrl+W", m.closeWindow),
			item(nil, "Quit", "Ctrl+Q", m.Quit),
		),
		widgets.NewMenu("&Vault",
			item(u.vaultMenu, "Unlock", "Ctrl+U", func() { m.unlockVault("") }),
			item(u.vaultMenu, "Unlock with…", "", m.unlockWith),
			item(u.vaultMenu, "Lock", "Ctrl+L", func() { m.lockVault(false) }),
			item(nil, "Lock all vaults", "Ctrl+Shift+L", func() { m.lockVault(true) }),
			widgets.Sep(),
			item(nil, "New vault…", "", m.newVault),
			item(nil, "Add an existing vault…", "", m.addVaultFolder),
			item(nil, "Join a synced vault…", "", m.joinSynced),
			item(u.vaultMenu, "Make it the default", "", m.makeDefault),
			item(u.vaultMenu, "Import…", "", m.importItems),
			item(u.vaultMenu, "Export…", "", m.exportItems),
			widgets.Sep(),
			widgets.Submenu("Items",
				item(u.vaultMenu, "New item", "Ctrl+N", func() { m.newItem(nil) }),
				item(nil, "Filter", "Ctrl+F", m.focusFilter),
				widgets.Sep(),
				item(u.itemMenu, "Copy password", "Ctrl+C", m.copySecret),
				item(u.itemMenu, "Copy username", "Ctrl+B", m.copyUsername),
				item(u.itemMenu, "Copy one-time code", "Ctrl+T", m.copyCode),
				item(u.itemMenu, "Copy password and minimise", "Ctrl+Shift+C", m.copyAndMinimise),
				item(u.itemMenu, "Copy reference…", "", m.copyReference),
				widgets.Sep(),
				item(u.itemMenu, "Open", "", m.openSelected),
				item(u.itemMenu, "Edit item", "Ctrl+E", m.editItem),
				item(u.itemMenu, "Show or hide concealed values", "Ctrl+R", m.toggleRevealAll),
				item(u.itemMenu, "Rename…", "F2", m.renameItem),
				item(u.itemMenu, "Move to vault…", "", func() { m.moveItem(false) }),
				item(u.itemMenu, "Copy to vault…", "", func() { m.moveItem(true) }),
				item(u.vaultMenu, "Move every item to vault…", "", func() { m.moveAll(m.vault, false) }),
				item(u.vaultMenu, "Copy every item to vault…", "", func() { m.moveAll(m.vault, true) }),
				item(u.itemMenu, "Delete…", "Delete", m.deleteItem),
				item(u.itemMenu, "History", "Ctrl+H", m.showHistory),
				widgets.Sep(),
				item(u.vaultMenu, "Deleted items", "", m.showDeleted),
			),
			widgets.Submenu("My keys",
				item(u.vaultMenu, "OpenPGP keys", "", func() { m.showKeysPage(tabPGP) }),
				item(u.vaultMenu, "S/MIME keys", "", func() { m.showKeysPage(tabSMIME) }),
				item(u.vaultMenu, "age identities", "", func() { m.showKeysPage(tabAge) }),
			),
			widgets.Submenu("Contacts",
				item(nil, "All contacts", "Ctrl+Shift+K", func() { m.showContactsPage(tabPeople) }),
				item(nil, "Add…", "", m.addContact),
				item(nil, "Import…", "", m.importContacts),
				item(nil, "Look up…", "", m.lookupContact),
				item(nil, "Show my QR code…", "", m.showMyQR),
				item(nil, "Check a signer…", "", m.checkSigner),
				item(nil, "Record a key seen in mail…", "", m.recordSeen),
				widgets.Sep(),
				item(nil, "Directories", "", func() { m.showContactsPage(tabDirectories) }),
				item(nil, "Keep contacts in…", "", m.contactsVault),
			),
			widgets.Sep(),
			vault("Ways to unlock", tabKeyslots),
			vault("Sharing and emergency access", tabSharing),
			widgets.Submenu("Emergency access given to me",
				item(nil, "Accept an invite…", "", m.acceptEmergency),
				item(nil, "Ask for access…", "", m.requestEmergency),
				item(nil, "Open the vault…", "", m.openEmergency),
			),
			vault("Devices", tabDevices),
			vault("Sync", tabSync),
			item(u.vaultMenu, "Grants", "Ctrl+Shift+G", func() { m.showVaultPage(tabGrants) }),
			vault("Audit log", tabAudit),
			vault("Settings", tabSettings),
		),
		widgets.NewMenu("&Disk",
			item(nil, "All disks", "", m.showDisks),
			widgets.Sep(),
			disks("New disk…", m.newContainer),
			disks("Mount a disk file…", m.openContainerFile),
			disks("Unmount a disk…", m.closeContainer),
			disks("Delete the disk picked…", m.deleteContainer),
		),
		widgets.NewMenu("&Tools",
			item(nil, "Password generator…", "Ctrl+G", m.openGenerator),
			widgets.Sep(),
			item(nil, "Sign a file…", "", m.signFile),
			item(nil, "Check a signature…", "", m.verifyFile),
			item(nil, "Decrypt a file (OpenPGP)…", "", m.decryptPGPFile),
			item(nil, "Encrypt a file (age)…", "", m.encryptAgeFile),
			item(nil, "Decrypt a file (age)…", "", m.decryptAgeFile),
			item(nil, "Inspect a message…", "", m.inspectMessage),
			item(nil, "Sign and encrypt a message…", "", m.composeMessage),
			widgets.Sep(),
			item(nil, "Resolve a reference…", "", m.resolveReference),
			item(nil, "Check an env file…", "", m.checkEnvFile),
			item(nil, "Check a template…", "", m.checkTemplate),
			widgets.Sep(),
			tools("Identity files", tabIdentities),
			tools("Security keys plugged in", tabSecurityKeys),
			widgets.Sep(),
			tools("Browsers", tabBrowsers),
			tools("System keyring", tabKeyring),
			tools("GnuPG", tabGnuPG),
			tools("Program helpers", tabHelpers),
			tools("Host daemon", tabHost),
			widgets.Sep(),
			item(nil, "Appearance", "", func() { m.showSettings(tabSetAppearance) }),
			item(nil, "Where things are kept", "", func() { m.showSettings(tabSetWhere) }),
		),
	)
}

// enableMenus greys out what cannot be done now, and has the title bar
// say where the window is.
func (m *Manager) enableMenus() {
	defer m.drawTitle()
	v := m.vaultInfo(m.vault)
	for _, it := range m.ui.vaultMenu {
		it.Disabled = m.gone || v == nil
	}
	for _, b := range []*widgets.ToolButton{m.ui.newItemButton, m.ui.importButton, m.ui.exportButton, m.ui.deletedButton} {
		b.SetEnabled(v != nil && !m.gone && m.listed)
	}
	if v != nil && !m.gone {
		m.ui.vaultMenu["Unlock"].Disabled = !v.Locked
		m.ui.vaultMenu["Lock"].Disabled = v.Locked
		m.ui.vaultMenu["Make it the default"].Disabled = v.Default
	}
	// The vault's page covers the items, and the Disks and Tools tabs
	// the whole of the Vaults tab: what acts on an item waits until they
	// are back, rather than act on a pane nobody can see.
	page := m.showingVaultPage() || m.section() != secVaults
	m.ui.vaultMenu["New item"].Disabled = m.ui.vaultMenu["New item"].Disabled || page
	none := m.gone || m.targetName() == "" || page
	for _, it := range m.ui.itemMenu {
		it.Disabled = none
	}
	m.ui.menu.Invalidate()
}

// drawStatus says the vault shown's state, in its breadcrumb's tip (its
// items, and its sync's), and puts up the notes that stay (drawNotes).
func (m *Manager) drawStatus() {
	if m.ui == nil {
		return
	}
	var b strings.Builder
	switch v := m.vaultInfo(m.vault); {
	case m.gone:
		b.WriteString("Not connected to secretvault's background service")
	case m.vault == "":
		b.WriteString("No vault")
	case v == nil:
		b.WriteString(m.vault)
	default:
		b.WriteString(v.Name)
		switch {
		case v.ID == "":
			b.WriteString(": folder missing")
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
	m.ui.vaultTip = b.String()
	m.drawNotes()
	m.enableMenus()
}

// drawNotes puts up what stays as a note: an emergency request, or work
// that is taking a while.
func (m *Manager) drawNotes() {
	n := m.ui.notes
	if n == nil {
		return
	}
	switch {
	case m.busy == 0:
		n.busySince = time.Time{}
	case n.busySince.IsZero():
		n.busySince = m.flipNow()
		widget.After(m.win.Content(), busyAfter, m.drawNotes)
	}
	stay, warn := "", false
	if !m.gone {
		stay = strings.TrimPrefix(m.emergencyLine(), "; ")
		if stay != "" {
			stay, warn = strings.ToUpper(stay[:1])+stay[1:]+".", true
		}
	}
	if stay == "" && m.busy > 0 && m.flipNow().Sub(n.busySince) >= busyAfter {
		stay = "Working…"
	}
	n.stays(stay, warn)
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
	onSet func() // after the page changes: the window's floor follows it
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
	if s.onSet != nil {
		s.onSet()
	}
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
	menu  *widgets.MenuBar // the shortcuts, which no menu bar on screen holds
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
	for _, c := range r.Children() {
		c.Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
	}
}

// MinWidth is the content's floor (widget.MinWidther).
func (r *shortcutRoot) MinWidth() float32 { return widget.MinWidthOf(r.Children()[0]) }

func (r *shortcutRoot) KeyPress(e widget.KeyEvent) bool { return r.onKey != nil && r.onKey(e) }

// HandleAccelerator runs the shortcut of a menu entry (Ctrl+C, F2…): the
// menus are not on screen, but what they hold is what every shortcut
// does, greyed out as they would be (enableMenus).
func (r *shortcutRoot) HandleAccelerator(key platform.Key, mods platform.Modifiers) bool {
	return r.menu != nil && r.menu.HandleAccelerator(key, mods)
}

// key handles the keys no widget took, before the menus' accelerators.
func (m *Manager) key(e widget.KeyEvent) bool {
	focus := m.win.Focus()
	switch {
	case e.Key == platform.KeyDown && focus == widget.Component(m.ui.filter) && len(m.shown) > 0:
		// From the filter to the items it lets through.
		m.focus(m.ui.content)
		if m.entry(m.cursor) == nil {
			m.itemSelected(0)
			m.syncList()
		}
		return true
	case e.Mods&(platform.ModCtrl|platform.ModAlt|platform.ModShift) == platform.ModCtrl &&
		(e.Key == platform.KeyPageDown || e.Key == platform.KeyPageUp):
		// Ctrl+Page Down and Up: the next and the previous of the
		// front's parts, Vault, Disk and Tools; on the back, of
		// Settings' tabs.
		if m.onBack() {
			if pg := m.spage; pg != nil {
				n := len(pg.panes)
				step := 1
				if e.Key == platform.KeyPageUp {
					step = n - 1
				}
				m.selectTab(pg, (pg.selected()+step)%n)
			}
			return true
		}
		n := secTools + 1
		step := 1
		if e.Key == platform.KeyPageUp {
			step = n - 1
		}
		m.showSection((m.section() + step) % n)
		return true
	case e.Mods&(platform.ModCtrl|platform.ModAlt|platform.ModShift) == platform.ModCtrl && e.Key >= platform.Key1 && e.Key <= platform.Key9:
		// Ctrl+1, 2, 3: Vault, Disk and Tools, as a browser's tabs are
		// picked; on the back, Settings' tabs.
		d, _ := platform.DigitRune(e.Key)
		i := int(d - '1')
		if m.onBack() {
			if pg := m.spage; pg != nil && i < len(pg.panes) {
				m.selectTab(pg, i)
				return true
			}
			return false
		}
		if i > secTools {
			return false
		}
		m.showSection(i)
		return true
	case e.Key == platform.KeyEscape && e.Mods == 0 && m.onBack():
		// Escape on the back turns the window back to its front.
		m.turnOver()
		return true
	case e.Key == platform.KeyEscape && m.query != "":
		m.ui.filter.SetText("") // which clears the filter
		return true
	case e.Key == platform.KeyDelete && e.Mods&(platform.ModCtrl|platform.ModAlt|platform.ModShift) == 0:
		// Delete deletes the item only where the item is what has the
		// keyboard: the list (the items picked there, if several are), or
		// the item beside it. Anywhere else (a field that had nothing left
		// to delete) it does nothing, rather than reach the menu's Delete.
		switch {
		case focus == widget.Component(m.ui.content) && len(m.picked) > 1:
			m.deletePicked()
		case focus == widget.Component(m.ui.content) && m.entry(m.cursor) != nil,
			m.editor == nil && !m.showingHistory() && !m.showingVaultPage() && isUnder(focus, m.ui.pane) && len(m.picked) < 2:
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

// filterField is the filter box. Ctrl+C in it copies the selected item's
// secret when no text is selected in it, as KeePassXC's does; with text
// selected, it copies that text, as any field does.
type filterField struct {
	*widgets.TextField
	m *Manager
}

func newFilterField(m *Manager) *filterField {
	f := &filterField{TextField: widgets.NewTextField("", "Filter (Ctrl+F)", nil), m: m}
	f.TextField.Init(f)
	f.Clearable = true
	f.OnChange = func(s string) { m.setQuery(s) }
	f.OnSubmit = func(string) { m.openFirstMatch() }
	f.SetAccessibleName("Filter")
	return f
}

func (f *filterField) KeyPress(e widget.KeyEvent) bool {
	if e.Key == platform.KeyC && e.Mods.Ctrl() && !e.Mods.Shift() {
		if a, b := f.Selection(); a == b {
			f.m.copySecret()
			return true
		}
	}
	return f.TextField.KeyPress(e)
}
