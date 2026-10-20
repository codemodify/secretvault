package svmanager

import (
	"context"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
)

// Pages of tabs. In the window's Vault tab they are tabs of it beside the
// tabs of items: the vault's own (the ways it unlocks, sharing, devices,
// sync, grants, audit log and settings), the keys kept in it and the
// contacts (vaulttabs.go). The Disk and Tools tabs each hold one page that
// stays (disks.go, toolspage.go). A tab asks the daemon for what it shows
// when it is first shown, and again after something on it changed.
// Escape goes back to the item.

// Kinds of page, besides the vault's.
const (
	pageKeys     = "keys"
	pageContacts = "contacts"
	pageTools    = "tools"
	pageDisks    = "disks"
	pageSettings = "settings"
)

// tabbedPage is a page of tabs.
type tabbedPage struct {
	kind  string
	vault string // the vault it is about, or "" for none
	title string
	tabs  *widgets.TabView // its row of tabs; nil for a page whose tab is chosen for it
	bare  *slot            // where such a page shows its tab
	sel   int              // and which one it shows
	head  *widgets.Label   // the tab's title, over it
	pick  func(int)        // shows tab i, for a page whose tabs another row holds (the vault page's)
	panes []*pane
	keys  func(widget.KeyEvent) bool // the page's own keys, before Escape
}

// selected is the tab shown.
func (pg *tabbedPage) selected() int {
	if pg.tabs != nil {
		return pg.tabs.Selected()
	}
	return pg.sel
}

// pane is one tab of a page.
type pane struct {
	pg     *tabbedPage
	title  string
	box    *slot
	fill   func(*pane) // asks for what it shows, and shows it
	filled bool
	focus  widget.Component // what takes the keyboard once it is shown
	gen    int              // counts the fills, so that only the last one shows
}

func newPane(title string, fill func(*pane)) *pane {
	return &pane{title: title, box: newSlot(), fill: fill}
}

// refresh fills the pane again.
func (p *pane) refresh() {
	p.filled = true
	p.fill(p)
}

// standPage puts a page that stays into host: the Disk, Tools or Settings
// part's, My keys' or Contacts'. Its tabs have no row of their own: the
// title bar picks them (titlebar.go).
func (m *Manager) standPage(pg *tabbedPage, host *slot, tab int) {
	body := m.pageBody(pg, false)
	host.Set(widgets.NewPad(pad, body))
	m.selectTab(pg, tab)
	m.paneShown(pg, pg.selected())
}

// pageBody is what shows pg's tabs: a row of them over the one chosen
// (withRow), or the one chosen alone.
func (m *Manager) pageBody(pg *tabbedPage, withRow bool) widget.Component {
	pg.tabs, pg.bare, pg.sel = nil, nil, 0
	for _, p := range pg.panes {
		p.pg = pg
		p.filled = false
		p.box.Set(m.paragraph("Loading…"))
	}
	if !withRow {
		pg.bare = newSlot()
		pg.bare.Set(pg.panes[0].box)
		pg.bare.SetAccessibleName(pg.title)
		return pg.bare
	}
	tabs := make([]widgets.Tab, len(pg.panes))
	for i, p := range pg.panes {
		tabs[i] = widgets.Tab{Title: p.title, Content: p.box}
	}
	pg.tabs = widgets.NewTabView(tabs...)
	pg.tabs.SetAccessibleName(pg.title)
	pg.tabs.OnChange = func(i int) { m.paneShown(pg, i) }
	return pg.tabs
}

// paneShown fills a tab the first time it is shown, and gives it the
// keyboard.
func (m *Manager) paneShown(pg *tabbedPage, i int) {
	if i < 0 || i >= len(pg.panes) || !m.current(pg) {
		return
	}
	p := pg.panes[i]
	if !p.filled {
		p.refresh()
	} else if p.focus != nil && m.visible(pg) {
		m.focus(p.focus)
	}
}

// selectTab shows tab i of pg, if pg is up.
func (m *Manager) selectTab(pg *tabbedPage, i int) {
	if !m.current(pg) || i < 0 || i >= len(pg.panes) {
		return
	}
	if pg.pick != nil {
		pg.pick(i)
		return
	}
	if pg.tabs != nil {
		pg.tabs.Select(i)
		return
	}
	pg.sel = i
	pg.bare.Set(pg.panes[i].box)
	if pg.head != nil {
		pg.head.SetText(pg.panes[i].title)
	}
	m.paneShown(pg, i)
	m.keepFocus()
	m.drawTitle()
	if pg == m.page {
		m.syncList()
	}
}

// up reports whether pg is up: the page over the items, or the Disks or
// the Tools tab's.
func (m *Manager) up(pg *tabbedPage) bool { return m.current(pg) }

// current reports whether pg is the page in its place, up or being put
// up.
func (m *Manager) current(pg *tabbedPage) bool { return pg != nil && (m.page == pg || m.standing(pg)) }

// visible reports whether pg is up in the window's tab shown, so that it
// may take the keyboard.
func (m *Manager) visible(pg *tabbedPage) bool {
	switch {
	case !m.up(pg):
		return false
	case m.tpage != nil && m.tpage.tabbedPage == pg:
		return m.section() == secTools
	case m.disks != nil && m.disks.tabbedPage == pg:
		return m.section() == secDisks
	case m.spage == pg:
		return m.section() == secSettings
	}
	return m.section() == secVaults && m.page == pg && m.showingVaultPage()
}

// standing reports whether pg is the Disks or the Tools tab's page.
func (m *Manager) standing(pg *tabbedPage) bool {
	return m.tpage != nil && m.tpage.tabbedPage == pg || m.disks != nil && m.disks.tabbedPage == pg || m.spage != nil && m.spage == pg ||
		m.vpage != nil && m.vpage.tabbedPage == pg || m.kpage != nil && m.kpage.tabbedPage == pg ||
		m.cpage != nil && m.cpage.tabbedPage == pg
}

// load asks the daemon with fetch, and once it answers, if the page is
// still up and no later fill has started, shows what draw makes. An error
// is said in the tab, with a button to try again.
func (m *Manager) load(p *pane, fetch func(ctx context.Context, c *secretvault.Client) error, draw func() widget.Component) {
	p.gen++
	gen, pg := p.gen, p.pg
	m.call(fetch, func(err error) {
		if !m.up(pg) || gen != p.gen {
			return
		}
		if err != nil {
			again := newButton("Try again", p.refresh)
			p.focus = again
			p.box.Set(m.message(p.title, m.describe(err), again))
			m.reloadVaults() // asking may have unlocked the vault, or not
			return
		}
		p.focus = nil
		p.box.Set(draw())
		if i := pg.selected(); i >= 0 && pg.panes[i] == p && p.focus != nil && m.visible(pg) {
			m.focus(p.focus)
		}
		m.reloadVaults()
		m.syncCapture()
	})
}

// paneColumn is a tab's usual body: a note, what it lists, its buttons.
func (m *Manager) paneColumn(note string, list widget.Component, actions ...*widgets.Button) *widgets.FlexBox {
	col := widgets.NewColumn().WithGap(gap).WithPad(gap)
	if note != "" {
		col.Add(m.paragraph(note))
	}
	if list != nil {
		col.Add(list)
		col.AddFlex(list, 1)
	}
	if len(actions) > 0 {
		col.Add(buttons(actions...))
	}
	return col
}

// scrolled is a tab's body that may be longer than the tab.
func scrolled(c widget.Component) widget.Component {
	return widgets.NewScrollView(widgets.NewPad(gap, c))
}
