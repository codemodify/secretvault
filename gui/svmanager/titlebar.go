package svmanager

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window's title bar is its own, as a browser's is (the toolkit draws
// the frame around it): at its left, over the rail, secretvault's logo,
// which locks every vault; then where the window is, as breadcrumbs (Vault
// › personal › Logins), each that can change opening, under it, what it
// can change to; then what can be done to what the part shows, and
// Settings, before the window's own buttons. The rest of it is caption: it
// moves the window. The vaults, a vault's kinds of item and every page's
// tabs are picked here, so no list or row of tabs of them stands in the
// window.

// titleBar is the title bar's state.
type titleBar struct {
	bar      *widgets.HeaderBar
	logo     *railItem // secretvault's mark, at the top left: it locks every vault
	settings *railItem
	crumbs   *widgets.Breadcrumbs
	ops      *widgets.FlexBox
	key      string             // what it shows, so that it is made again only on a change
	drop     *dropPanel         // the drop-down up, if one is
	vaultOps []widget.Component // the vault's buttons that stay: import, export, deleted items
}

// crumb is one step of where the window is: its text, its icon, and what
// it can change to: a menu of the toolkit's, or the manager's own
// drop-down (the vaults'), opened under it at, or neither.
type crumb struct {
	text string
	icon style.ToolIcon
	menu func() []*widgets.MenuItem
	open func(from widget.Component, at paintengine2d.Rect)
	tip  string // said when the pointer rests on it ("" for nothing)
}

func (m *Manager) buildTitleBar() {
	t := &titleBar{
		crumbs: widgets.NewBreadcrumbs(),
		ops:    widgets.NewRow().WithGap(4).WithAlign(layout.AlignCenter).WithPadding(0, 0, 8, 0),
	}
	m.ui.title = t
	t.crumbs.Arrows = true
	t.crumbs.SetAccessibleName("Where the window is")
	t.settings = newRailItem(iconButton("Settings", "Settings, on the back of the window: the look, the keyboard shortcuts, About secretvault, where things are kept. Click again to turn back",
		style.IconSettings, nil, m.turnOver)) // uitoolkit's own gear, drawn by its button
	t.settings.ground = true // the rail's colour: the rail runs up under it
	t.vaultOps = []widget.Component{m.ui.importButton, m.ui.exportButton, m.ui.deletedButton}
	// At the top left, over the rail, secretvault's mark: a click on it
	// locks every vault.
	t.logo = newRailItem(iconButton("Lock every vault", "Lock every vault: their items need the passphrase again",
		style.IconNone, m.logoMark(iconBox), func() { m.lockVault(true) }))
	t.logo.ground = true // the rail's colour: the rail runs up under it
	// Settings is at the right end, before the window's buttons (the
	// toolkit's frame's).
	t.bar = widgets.NewHeaderBar([]widget.Component{t.logo, t.crumbs}, nil, []widget.Component{t.ops, t.settings})
	m.win.SetTitleBar(t.bar)
	m.win.SetCaptionStyle(style.CaptionMerged)
	m.drawTitle()
}

// drawTitle makes the breadcrumbs and the part's buttons again, when what
// they show has changed.
func (m *Manager) drawTitle() {
	if m.ui == nil || m.ui.title == nil {
		return
	}
	t := m.ui.title
	crumbs := m.crumbs()
	ops, opsKey := m.titleOps()
	var b strings.Builder
	for _, c := range crumbs {
		fmt.Fprintf(&b, "%s\x00%d\x00%v\x00%v\x00%s\x00", c.text, c.icon, c.menu != nil, c.open != nil, c.tip)
	}
	key := b.String() + "|" + opsKey
	t.settings.on = m.section() == secSettings
	t.settings.Invalidate()
	if key == t.key {
		return
	}
	t.key = key
	steps := make([]widgets.Crumb, len(crumbs))
	for i, c := range crumbs {
		steps[i] = widgets.Crumb{Text: c.text, Icon: c.icon, Menu: c.menu, Tip: c.tip}
		if open := c.open; open != nil {
			steps[i].OnClick = func() { open(t.crumbs, t.crumbAt(i)) }
			steps[i].Opens = true
		}
	}
	t.crumbs.SetCrumbs(steps...)
	t.ops.ClearChildren()
	for _, o := range ops {
		t.ops.Add(o)
	}
	t.crumbs.RequestLayout()
	t.ops.RequestLayout()
	t.crumbs.Invalidate()
	t.ops.Invalidate()
}

// crumbs are where the window is: the part, and in it what is shown.
func (m *Manager) crumbs() []crumb {
	switch m.section() {
	case secDisks:
		cs := []crumb{{text: "Disk", icon: style.IconDrive}}
		if p := m.disks; p != nil && len(p.boxes) > 0 {
			name := "Pick a disk"
			if ci := p.container(); ci != nil {
				name = filepath.Base(ci.Path)
			}
			cs = append(cs, crumb{text: name, menu: m.disksMenu, icon: style.IconDrive})
		}
		return cs
	case secTools:
		return m.pageCrumbs(crumb{text: "Tools", icon: style.IconLayout}, m.tpageTabbed())
	case secSettings:
		return m.pageCrumbs(crumb{text: "Settings", icon: style.IconSettings}, m.spage)
	}
	cs := []crumb{{text: "Vault", icon: style.IconSafe}} // the vault's own opens the vaults
	if m.vault == "" {
		return append(cs, crumb{text: "No vault yet", open: m.openVaultsDrop, icon: style.IconPlus})
	}
	padlock := style.IconWarning // a vault whose folder is missing
	if v := m.vaultInfo(m.vault); v != nil && v.ID != "" {
		padlock = style.IconLock
		if !v.Locked {
			padlock = style.IconLockOpen
		}
	}
	cs = append(cs, crumb{text: m.vault, open: m.openVaultsDrop, icon: padlock, tip: m.ui.vaultTip})
	if v := m.vaultInfo(m.vault); m.gone || v == nil || v.ID == "" || v.Locked {
		return cs // shut, it shows nothing of what it holds
	}
	tab := m.ui.vaultTabs.Selected()
	cs = append(cs, crumb{text: vaultTabTitles[tab], menu: m.kindsMenu, icon: kindIcon(vaultTabTitles[tab])})
	switch tab {
	case vtVault:
		k := m.ui.vaultSub.Selected()
		cs = append(cs, crumb{text: vaultPageTitles[k], menu: func() []*widgets.MenuItem {
			return tabsMenu(vaultPageTitles, k, m.showVaultPageTab)
		}, icon: tabIcon(vaultPageTitles[k])})
	case vtMyKeys:
		if m.kpage != nil {
			cs = append(cs, m.tabCrumb(m.kpage.tabbedPage))
		}
	case vtContacts:
		if m.cpage != nil {
			cs = append(cs, m.tabCrumb(m.cpage.tabbedPage))
		}
	}
	return cs
}

// tpageTabbed is the Tools page, if it is made.
func (m *Manager) tpageTabbed() *tabbedPage {
	if m.tpage == nil {
		return nil
	}
	return m.tpage.tabbedPage
}

// pageCrumbs are a part whose page has tabs: the part, and the tab shown.
func (m *Manager) pageCrumbs(part crumb, pg *tabbedPage) []crumb {
	cs := []crumb{part}
	if pg != nil && len(pg.panes) > 1 {
		cs = append(cs, m.tabCrumb(pg))
	}
	return cs
}

// tabCrumb is the tab of pg shown, opening its other tabs.
func (m *Manager) tabCrumb(pg *tabbedPage) crumb {
	titles := make([]string, len(pg.panes))
	for i, p := range pg.panes {
		titles[i] = p.title
	}
	cur := pg.selected()
	return crumb{text: titles[cur], menu: func() []*widgets.MenuItem {
		return tabsMenu(titles, cur, func(i int) { m.selectTab(pg, i) })
	}, icon: tabIcon(titles[cur])}
}

// vaultPageTitles are the vault page's tabs (About this vault).
var vaultPageTitles = []string{"Ways to unlock", "Sharing", "Devices", "Sync", "Grants", "Audit log", "Settings"}

// titleOps are what can be done to what the part shows, and a key that
// says which they are.
func (m *Manager) titleOps() ([]widget.Component, string) {
	switch m.section() {
	case secDisks:
		p := m.disks
		if p == nil {
			return nil, "disks"
		}
		return []widget.Component{
			iconButton("New disk…", "New disk: an encrypted disk file, its key kept in a vault", style.IconPlus, nil, func() { m.newContainer(p) }),
			iconButton("Mount a disk file…", "Mount a disk file: any encrypted disk file, with the key of an item", style.IconOpen, nil, func() { m.openContainerFile(p) }),
			iconButton("Refresh", "Refresh: ask for the disks again", style.IconSync, nil, func() { m.refreshDisks(p) }),
		}, "disks"
	case secTools, secSettings:
		return nil, "none"
	}
	v := m.vaultInfo(m.vault)
	if v == nil || m.gone || v.ID == "" {
		return nil, "novault"
	}
	name := v.Name
	var ops []widget.Component
	if v.Locked {
		ops = append(ops,
			iconButton("Unlock "+name, "Locked: click to unlock it (asks for its passphrase)", style.IconLock, nil, func() { m.unlockVault(name) }),
			iconButton("Unlock "+name+" with…", "Unlock it with a keyfile, the recovery key, an identity file or a security key", style.IconLock, m.plusBadge(), m.unlockWith))
	} else {
		ops = append(ops, iconButton("Lock "+name, "Unlocked: click to lock it (its items then need the passphrase again)", style.IconLockOpen, nil, func() { m.lockVault(false) }))
	}
	ops = append(ops, widgets.NewSpacerSize(8, 0))
	ops = append(ops, m.ui.title.vaultOps...)
	return ops, "vault\x00" + name + "\x00" + strconv.FormatBool(v.Locked)
}

// vaultPart is one of what a vault holds, as its drop-down lists it.
type vaultPart struct {
	tab   int
	count int  // its items, or those the filter lets through
	kind  bool // a kind of item, which has a count
}

// vaultParts are what the vault shown holds: every kind of item, with how
// many it has (or, filtering, how many match; none while it is locked),
// then My keys, Contacts and About this vault.
func (m *Manager) vaultParts() []vaultPart {
	words := strings.Fields(strings.ToLower(m.query))
	counts := map[int]int{}
	for i := range m.entries {
		if t := tabOf(&m.entries[i]); t >= 0 && matches(&m.entries[i], words) {
			counts[t]++
		}
	}
	var out []vaultPart
	for t := vtLogins; t <= lastItemTab; t++ {
		out = append(out, vaultPart{tab: t, count: counts[t], kind: true})
	}
	return append(out, vaultPart{tab: vtMyKeys}, vaultPart{tab: vtContacts}, vaultPart{tab: vtVault})
}

// openVaultsDrop opens the vaults: every one, with its padlocks, and under
// them making, adding and joining one, and locking all of them.
func (m *Manager) openVaultsDrop(from widget.Component, at paintengine2d.Rect) {
	l := m.ui.vaultList
	l.onDone = m.closeDrop
	act := func(do func()) func() { return func() { m.closeDrop(); do() } }
	foot := widgets.NewRow(
		iconButton("New vault", "New: make a vault", style.IconNone, m.newVaultMark(iconBox), act(m.newVault)),
		iconButton("Add a vault", "Add: a vault whose folder is on this computer already", style.IconOpen, nil, act(m.addVaultFolder)),
		iconButton("Join a synced vault", "Sync: join a vault synced from another device", style.IconCloud, nil, act(m.joinSynced)),
		iconButton("Lock all vaults", "Lock all: every vault", style.IconLock, nil, act(func() { m.lockVault(true) })),
	).WithGap(4).WithPadding(10, 6, 10, 2)
	var top widget.Component = l
	if len(l.rows) == 0 {
		top = widgets.NewPad(12, m.paragraph("No vaults yet: New makes one, Add takes one whose folder is here."))
	}
	m.openDrop(from, at, widgets.NewColumn(top, widgets.NewSeparator(), foot).WithGap(4), l)
}

// kindsMenu is what the vault shown holds, the one shown checked: every
// kind of item with how many it has (or, filtering, how many match), then
// My keys, Contacts and About this vault.
func (m *Manager) kindsMenu() []*widgets.MenuItem {
	cur := m.ui.vaultTabs.Selected()
	var items []*widgets.MenuItem
	for _, p := range m.vaultParts() {
		if p.tab == vtMyKeys {
			items = append(items, widgets.Sep())
		}
		tab := p.tab
		it := &widgets.MenuItem{Text: vaultTabTitles[tab], Icon: kindIcon(vaultTabTitles[tab]), Checked: tab == cur,
			OnClick: func() {
				m.showVaultTab(tab)
				if tab <= lastItemTab {
					m.focus(m.ui.content)
				}
			}}
		if p.kind && m.listed {
			it.Shortcut = strconv.Itoa(p.count)
		}
		items = append(items, it)
	}
	return items
}

// tabsMenu is a page's tabs, the one shown, cur, checked.
func tabsMenu(titles []string, cur int, pick func(int)) []*widgets.MenuItem {
	items := make([]*widgets.MenuItem, len(titles))
	for i, t := range titles {
		items[i] = &widgets.MenuItem{Text: t, Icon: tabIcon(t), Checked: i == cur, OnClick: func() { pick(i) }}
	}
	return items
}

// disksMenu is the disks, each with its state, the one shown checked.
func (m *Manager) disksMenu() []*widgets.MenuItem {
	p := m.disks
	if p == nil {
		return nil
	}
	cur := selected(p.ctable)
	items := make([]*widgets.MenuItem, len(p.boxes))
	for i, ci := range p.boxes {
		items[i] = &widgets.MenuItem{Text: filepath.Base(ci.Path), Shortcut: diskState(&ci), Icon: style.IconDrive, Checked: i == cur,
			OnClick: func() {
				p.ctable.Selected = i
				m.drawDisk(p)
				m.drawTitle()
			}}
	}
	return items
}

// crumbAt is where breadcrumb i is, in the window's device pixels.
func (t *titleBar) crumbAt(i int) paintengine2d.Rect {
	return t.crumbs.CrumbRect(i).Translate(widget.DeviceOrigin(t.crumbs))
}

// dropPanel is a breadcrumb's drop-down: what it holds on the look's popup
// colour, under the breadcrumb. Escape, or a click outside it, closes it.
type dropPanel struct {
	widget.Base
	m      *Manager
	from   widget.Component // what opened it
	scroll *widgets.ScrollView
}

// openDrop shows content in a drop-down under at, which is from's, the
// keyboard on focus. It is as wide and as tall as what it holds, in the
// window's look and at its scale; where the window has not the room, it
// scrolls.
func (m *Manager) openDrop(from widget.Component, at paintengine2d.Rect, content, focus widget.Component) {
	m.closeDrop()
	d := &dropPanel{m: m, from: from, scroll: widgets.NewScrollView(content)}
	d.Init(d)
	d.scroll.ShrinkToContent = true
	d.Add(widgets.NewPad(6, d.scroll))
	// Measured once it has the window's look (and so its scale): measured
	// before, in the toolkit's default one, it came out too small.
	widget.PlacePopupForAnchor(from, d, at, 240, 4)
	if !widget.ShowPopup(from, d) {
		return
	}
	m.ui.title.drop = d
	from.Invalidate()
	if focus != nil {
		m.win.FocusOn(focus)
	}
	if r, ok := focus.(interface{ revealCur() }); ok {
		r.revealCur()
	}
}

// reveal scrolls the drop-down c is in so that c is in sight.
func reveal(c widget.Component) {
	for p := c.Parent(); p != nil; p = p.Parent() {
		if s, ok := p.(*widgets.ScrollView); ok {
			s.Reveal(c)
			return
		}
	}
}

// closeDrop takes the drop-down down, if one is up.
func (m *Manager) closeDrop() {
	if m.ui == nil || m.ui.title == nil || m.ui.title.drop == nil {
		return
	}
	d := m.ui.title.drop
	m.ui.title.drop = nil
	widget.DismissPopup(d)
	d.from.Invalidate()
}

func (d *dropPanel) Measure(c layout.Constraints) paintengine2d.Point {
	return d.Children()[0].Measure(c)
}

func (d *dropPanel) Arrange(r paintengine2d.Rect) {
	d.SetBounds(r)
	d.Children()[0].Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

// Paint draws the look's frame for what floats, a menu's.
func (d *dropPanel) Paint(ctx *paintengine2d.Context) {
	d.Look().DrawMenuFrame(ctx, d.LocalBounds())
}

// KeyPress closes the drop-down on Escape; the other keys go to what has
// the keyboard in it first.
func (d *dropPanel) KeyPress(e widget.KeyEvent) bool {
	if e.Key == platform.KeyEscape {
		d.m.closeDrop()
		return true
	}
	return false
}

// Dismissed is the drop-down taken down by a click outside it.
func (d *dropPanel) Dismissed() {
	if t := d.m.ui.title; t != nil && t.drop == d {
		t.drop = nil
		d.from.Invalidate()
	}
}

func (d *dropPanel) Describe(n *a11y.Node) { n.Role = a11y.RoleMenu }
