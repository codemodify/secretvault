package svmanager

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The Vault tab's middle pane: the items of the tab of items shown, as
// one list, by the names it shows them by (svops.ShownNames), with the
// filter under it. What is picked shows in the pane beside it: a click
// picks one, Enter or a double click opens it; Ctrl+click, Shift+click
// and Ctrl+A pick several, to delete them or move them to another vault
// together.

// contentList is the list of items.
type contentList struct {
	*widgets.ListView
	m *Manager
}

func newContentList(m *Manager) *contentList {
	l := &contentList{ListView: widgets.NewListView(0, m.rowText, nil), m: m}
	l.Mode = widgets.SelectExtended
	l.OnSelect = func(int) { m.contentPicked() }
	l.OnSelectionChange = func([]int) { m.contentPicked() }
	l.OnActivate = m.itemActivated
	l.ItemDetail = m.rowDetail
	l.SetAccessibleName("The vault's items")
	return l
}

// rowText is row i of the list: the item's name as the list shows it.
func (m *Manager) rowText(i int) string {
	if i < 0 || i >= len(m.shown) {
		return ""
	}
	return m.shownName(m.entries[m.shown[i]].Item.Name)
}

// shownName is what the list shows an item as (svops.ShownNames).
func (m *Manager) shownName(name string) string {
	if s, ok := m.names[name]; ok {
		return s
	}
	return name
}

// rowDetail marks an item whose versions conflict, and one with files.
func (m *Manager) rowDetail(i int) string {
	if i < 0 || i >= len(m.shown) {
		return ""
	}
	e := &m.entries[m.shown[i]]
	switch {
	case len(e.Conflicts) > 0:
		return "conflict"
	case len(e.Item.Files) > 0:
		return plural(len(e.Item.Files), "file")
	}
	return ""
}

// rowOf is the row of the item named, or -1.
func (m *Manager) rowOf(name string) int {
	return slices.IndexFunc(m.shown, func(i int) bool { return m.entries[i].Item.Name == name })
}

// drawContent fills the list again from the items shown, keeping what is
// picked picked.
func (m *Manager) drawContent() {
	l := m.ui.content
	l.Count = 0
	if m.listed {
		l.Count = len(m.shown)
	}
	for n := range m.picked {
		if m.rowOf(n) < 0 {
			delete(m.picked, n)
		}
	}
	m.syncList()
	l.RequestLayout()
	l.Invalidate()
}

// syncList picks the rows of what the pane beside the list shows: the
// items picked together, else the item chosen.
func (m *Manager) syncList() {
	l := m.ui.content
	var rows []int
	for n := range m.picked {
		rows = append(rows, m.rowOf(n))
	}
	slices.Sort(rows)
	cur := m.rowOf(m.cursor)
	if len(rows) < 2 {
		rows = nil
		if cur >= 0 {
			rows = []int{cur}
		}
	}
	if !slices.Equal(l.SelectedRows(), rows) || l.Selected != cur {
		l.SetSelectedRows(rows)
		l.Selected = cur
		if cur >= 0 {
			l.EnsureVisible(cur)
		}
	}
}

// contentPicked shows what is picked in the list: several items, or the
// one.
func (m *Manager) contentPicked() {
	l := m.ui.content
	rows := l.SelectedRows()
	if len(rows) > 1 {
		m.picked = map[string]bool{}
		for _, r := range rows {
			if r < len(m.shown) {
				m.picked[m.entries[m.shown[r]].Item.Name] = true
			}
		}
		if l.Selected >= 0 && l.Selected < len(m.shown) {
			m.cursor = m.entries[m.shown[l.Selected]].Item.Name
		}
		m.showPicked()
		return
	}
	was := len(m.picked) > 1
	m.picked = nil
	switch {
	case len(rows) == 0:
		// The last one picked was unpicked (Ctrl+click): nothing is.
		if m.cursor != "" && m.editor == nil && !m.showingHistory() {
			m.cursor = ""
			m.closeItem()
		}
	case rows[0] < len(m.shown) && (was || m.entries[m.shown[rows[0]]].Item.Name != m.cursor):
		m.itemSelected(rows[0])
	}
	m.enableMenus()
}

// pickedNames are the items picked, by name.
func (m *Manager) pickedNames() []string {
	out := make([]string, 0, len(m.picked))
	for n := range m.picked {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// pickNames picks the items named in the list, as Ctrl+click would: one
// is shown beside it, several are said there.
func (m *Manager) pickNames(names []string) {
	m.picked = nil
	switch len(names) {
	case 0:
		return
	case 1:
		m.cursor = names[0]
	default:
		m.picked = map[string]bool{}
		for _, n := range names {
			m.picked[n] = true
		}
		m.cursor = names[0]
	}
	m.syncList()
	m.contentPicked()
}

// showPicked is the pane beside the list with several items picked.
func (m *Manager) showPicked() {
	if m.editor != nil || m.showingHistory() {
		return
	}
	names := m.pickedNames()
	if len(names) < 2 {
		m.closeItem()
		return
	}
	m.dropItem()
	shown := make([]string, len(names))
	for i, n := range names {
		shown[i] = m.shownName(n)
	}
	list := m.paragraph(strings.Join(shown, "\n"))
	moveTo := newButton("Move to vault…", func() { m.movePicked(false) })
	copyTo := newButton("Copy to vault…", func() { m.movePicked(true) })
	del := newButton("Delete…", func() { m.deletePicked() })
	col := widgets.NewColumn(heading(svops.SentenceStart(plural(len(names), "item"))+" picked"),
		m.muted("Ctrl+click picks or unpicks one more, Shift+click all up to one, Ctrl+A every one in the list."),
		list, buttons(moveTo, copyTo, del)).WithGap(gap)
	m.ui.pane.Set(scrolled(col))
	m.enableMenus()
}

// movePicked moves the items picked to another vault; copy keeps them
// where they are too.
func (m *Manager) movePicked(copy bool) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	names := m.pickedNames()
	if len(names) == 0 {
		m.say("Pick the items first.")
		return
	}
	m.moveTo(svrpc.MoveParams{Vault: m.vault, Names: names}, plural(len(names), "item"), "them", copy)
}

// deletePicked deletes the items picked, after asking: each goes to the
// deleted items, from where it can be brought back.
func (m *Manager) deletePicked() {
	names := m.pickedNames()
	vault := m.vault
	shown := make([]string, len(names))
	for i, n := range names {
		shown[i] = m.shownName(n)
	}
	m.confirm("Delete "+plural(len(names), "item")+"?",
		strings.Join(shown, ", ")+" go from "+svops.VaultPhrase(vault)+". You can bring each back as it was from the deleted items.",
		"Delete them", func() {
			m.call(func(ctx context.Context, c *secretvault.Client) error {
				for _, n := range names {
					if err := c.Delete(ctx, vault, n); err != nil {
						return err
					}
				}
				return nil
			}, func(err error) {
				m.picked = nil
				if err != nil {
					m.fail(err)
				} else {
					m.say("Deleted %s.", plural(len(names), "item"))
				}
				m.cursor = ""
				if vault == m.vault {
					m.loadItems()
				}
			})
		})
}

// showItemsPane is the pane beside the list with nothing picked: how
// many items the tab holds, and how to see one. With a filter that lets
// none of them through, it says which tabs have items it lets through.
func (m *Manager) showItemsPane() bool {
	if !m.listed {
		return false
	}
	n := 0
	for i := range m.entries {
		if m.inItemTab(&m.entries[i]) {
			n++
		}
	}
	title := vaultTabTitles[m.itemTab]
	switch {
	case m.query != "" && len(m.shown) == 0:
		words := strings.Fields(strings.ToLower(m.query))
		found := map[int]int{}
		for i := range m.entries {
			if t := tabOf(&m.entries[i]); t >= 0 && matches(&m.entries[i], words) {
				found[t]++
			}
		}
		if len(found) == 0 {
			m.ui.pane.Set(m.message(title, fmt.Sprintf("Nothing in vault %s matches %q.", m.vault, m.query)))
			return true
		}
		var elsewhere []*widgets.Button
		for t := vtLogins; t <= lastItemTab; t++ {
			if k := found[t]; k > 0 {
				elsewhere = append(elsewhere, newButton(fmt.Sprintf("%s (%d)", vaultTabTitles[t], k), func() { m.showVaultTab(t) }))
			}
		}
		m.ui.pane.Set(m.message(title, fmt.Sprintf("Nothing in %s matches %q. These tabs have items that do:", title, m.query), elsewhere...))
	case n == 0:
		m.ui.pane.Set(m.message(title, fmt.Sprintf("None in vault %s yet: the first button under the list makes one.", m.vault)))
	case m.query != "":
		m.ui.pane.Set(m.message(title, fmt.Sprintf("%d of the %s in vault %s match %q. Pick one in the list to see it.",
			len(m.shown), plural(n, "item"), m.vault, m.query)))
	default:
		m.ui.pane.Set(m.message(title, fmt.Sprintf("%s in vault %s. Pick one in the list to see it.", svops.SentenceStart(plural(n, "item")), m.vault)))
	}
	return true
}

// newItemHere opens the editor on a new item of the kind of the tab of
// items shown.
func (m *Manager) newItemHere() {
	if m.itemTab == vtDiskKeys {
		// A disk's key is made with its disk.
		m.newContainer(m.disks)
		return
	}
	m.newItem(nil)
	ed := m.editor
	if ed == nil || ed.orig != "" {
		return
	}
	if k, ok := tabKinds[m.itemTab]; ok {
		ed.setKind(k)
	}
}

// showHelperLogins brings the logins a program's helper keeps (those with
// the attribute attr) forward, picked in the Logins tab; who names the
// program.
func (m *Manager) showHelperLogins(attr, who string) {
	m.showSection(secVaults)
	m.closeVaultPage()
	if m.query != "" {
		m.ui.filter.SetText("")
	}
	m.showVaultTab(vtLogins)
	var names []string
	for _, e := range m.entries {
		if e.Item.Attrs[attr] != "" {
			names = append(names, e.Item.Name)
		}
	}
	if len(names) == 0 {
		m.say("Vault %s has no logins %s keeps yet: the helper makes them as it stores logins.", m.vault, who)
		return
	}
	m.pickNames(names)
}
