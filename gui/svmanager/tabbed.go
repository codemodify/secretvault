package svmanager

import (
	"context"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
)

// Pages that take the place of the items: the vault's own (its keyslots,
// devices, sharing, sync, containers, grants, audit log and settings), the
// keys kept in it, the contacts, and the desktop's setup. Each is a row of
// tabs; a tab asks the daemon for what it shows when it is first shown,
// and again after something on it changed. Escape goes back to the items.

// Kinds of page over the items, besides the vault's.
const (
	pageKeys     = "keys"
	pageContacts = "contacts"
	pageDesktop  = "desktop"
)

// tabbedPage is the page up over the items.
type tabbedPage struct {
	kind  string
	vault string // the vault it is about, or "" for none
	title string
	tabs  *widgets.TabView
	panes []*pane
	keys  func(widget.KeyEvent) bool // the page's own keys, before Escape
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

// openPage puts a page of tabs up over the items, open at tab.
func (m *Manager) openPage(pg *tabbedPage, tab int) {
	m.leaveHistory()
	m.closeItem()
	m.page = pg
	tabs := make([]widgets.Tab, len(pg.panes))
	for i, p := range pg.panes {
		p.pg = pg
		p.box.Set(m.paragraph("Asking secretvaultd…"))
		tabs[i] = widgets.Tab{Title: p.title, Content: p.box}
	}
	pg.tabs = widgets.NewTabView(tabs...)
	pg.tabs.SetAccessibleName(pg.title)
	pg.tabs.OnChange = func(i int) { m.paneShown(pg, i) }
	back := tip(widgets.NewButton("Back to the items", m.closeVaultPage), "Escape")
	col := widgets.NewColumn(heading(pg.title), pg.tabs, widgets.NewRow(back)).WithGap(gap).WithPad(pad)
	col.AddFlex(pg.tabs, 1)
	m.ui.main.Set(newPage(pg.kind, col, func(e widget.KeyEvent) bool {
		if pg.keys != nil && pg.keys(e) {
			return true
		}
		if e.Key == platform.KeyEscape {
			m.closeVaultPage()
			return true
		}
		return false
	}))
	pg.tabs.Select(tab)
	m.paneShown(pg, pg.tabs.Selected())
	m.enableMenus()
}

// paneShown fills a tab the first time it is shown, and gives it the
// keyboard.
func (m *Manager) paneShown(pg *tabbedPage, i int) {
	if i < 0 || i >= len(pg.panes) || m.page != pg {
		return
	}
	p := pg.panes[i]
	if !p.filled {
		p.refresh()
	} else if p.focus != nil {
		m.win.RequestFocus(p.focus)
	}
}

// selectTab shows tab i of the page up, if it is pg.
func (m *Manager) selectTab(pg *tabbedPage, i int) {
	if m.page == pg && pg.tabs != nil {
		pg.tabs.Select(i)
	}
}

// up reports whether pg is the page up.
func (m *Manager) up(pg *tabbedPage) bool { return pg != nil && m.page == pg && m.showingVaultPage() }

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
			again := widgets.NewButton("Try again", p.refresh)
			p.focus = again
			p.box.Set(m.message(p.title, m.describe(err), again))
			m.reloadVaults() // asking may have unlocked the vault, or not
			return
		}
		p.focus = nil
		p.box.Set(draw())
		if pg.tabs.Selected() >= 0 && pg.panes[pg.tabs.Selected()] == p && p.focus != nil {
			m.win.RequestFocus(p.focus)
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
