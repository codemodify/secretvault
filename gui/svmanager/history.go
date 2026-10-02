package svmanager

import (
	"context"
	"fmt"
	"strings"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// An item's history: every revision, newest first, each one viewable. When
// two devices changed an item at the same time, the vault keeps both: the
// newest wins and is the item, the other is a conflicting head, marked
// here, and can be opened and copied from.

// history is the history page's state.
type history struct {
	name    string
	cur     string          // the current revision
	heads   map[string]bool // the conflicting ones
	table   *widgets.TableView
	below   *slot
	view    *itemView // the revision open below the list
	opened  int
	entries []svrpc.Entry
}

// showHistory lists the target item's revisions.
func (m *Manager) showHistory() {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	vault, gen := m.vault, m.listGen
	var cur svrpc.Entry
	var hist []svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		if cur, err = c.Get(ctx, vault, name); err != nil {
			return err
		}
		wipeItem(&cur.Item)
		hist, err = c.History(ctx, vault, name)
		return err
	}, func(err error) {
		// Dropped, wiped, if meanwhile the vault shown changed or locked
		// (vaultLocked moves listGen on), an edit began, or the vault's
		// page went up.
		if err != nil || vault != m.vault || gen != m.listGen || m.editor != nil || m.showingVaultPage() {
			wipeEntries(hist)
			if err != nil {
				m.fail(err)
			}
			return
		}
		m.closeItem()
		m.wipeHistory()
		m.hist = &history{name: name, cur: cur.Rev, heads: map[string]bool{}, entries: hist, opened: -1}
		for _, r := range cur.Conflicts {
			m.hist.heads[r] = true
		}
		m.drawHistory()
	})
}

func (m *Manager) drawHistory() {
	h := m.hist
	h.table = widgets.NewTableView([]widgets.TableColumn{
		{Title: "When", Width: 150},
		{Title: "Revision", Width: 110},
		{Title: "Signed by", Width: 190},
		{Title: ""},
	}, len(h.entries), func(row, col int) string {
		if row < 0 || row >= len(h.entries) {
			return ""
		}
		e := h.entries[row]
		switch col {
		case 0:
			return e.Time.Local().Format("2006-01-02 15:04:05")
		case 1:
			return short(e.Rev)
		case 2:
			// Who wrote it, as far as its signature tells: as the CLI's
			// history says it.
			return svops.Author(e)
		}
		var note []string
		switch {
		case e.Rev == h.cur:
			note = append(note, "current")
		case h.heads[e.Rev]:
			note = append(note, "conflict")
		}
		if e.Deleted {
			note = append(note, "deleted")
		}
		if e.Ignored {
			note = append(note, "ignored: the vault requires signatures")
		}
		return strings.Join(note, ", ")
	}, func(i int) { m.openRevision(i) })
	h.table.SetAccessibleName("Revisions")
	h.below = newSlot()

	explain := fmt.Sprintf("%s, newest first. Select one to see it.", plural(len(h.entries), "revision"))
	if n := len(h.heads); n > 0 {
		explain = fmt.Sprintf("%s, newest first. %s saved at the same time as the current one, on another device: "+
			"the newest won and is the item; the rows marked conflict are the others. Select one to see it, and copy "+
			"from it what the current one should have.", plural(len(h.entries), "revision"), plural(n, "version was"))
		if n > 1 {
			explain = strings.Replace(explain, "versions was", "versions were", 1)
		}
	}
	note := m.muted(explain)
	note.Wrap = true
	back := tip(widgets.NewButton("Back to the item", m.closeHistory), "Escape")
	col := widgets.NewColumn(heading("History of "+h.name), note, h.table, h.below, widgets.NewRow(back)).WithGap(gap)
	col.AddFlex(h.table, 1)
	col.AddFlex(h.below, 2)
	m.ui.pane.Set(newPage(pageHistory, col, func(e widget.KeyEvent) bool {
		if e.Key == platform.KeyEscape {
			m.closeHistory()
			return true
		}
		return false
	}))
	if len(h.entries) > 0 {
		h.table.Selected = 0
		m.openRevision(0)
	}
	m.win.RequestFocus(h.table)
}

// openRevision shows revision i below the list, read-only.
func (m *Manager) openRevision(i int) {
	h := m.hist
	if h == nil || i < 0 || i >= len(h.entries) || i == h.opened {
		return
	}
	if h.view != nil {
		h.view.forget()
	}
	h.opened = i
	e := &h.entries[i]
	// No one-time codes for a revision: its key stays masked, and is not
	// parsed (which would make a string of it) for a code nobody needs.
	h.view = m.newItemView(e, viewRevision, nil)
	label := "Revision " + short(e.Rev)
	switch {
	case e.Rev == h.cur:
		label += " (current)"
	case h.heads[e.Rev]:
		label += " (conflict)"
	}
	head := widgets.NewRow(m.muted(label)).WithGap(gap).WithAlign(layout.AlignCenter)
	rev, name := e.Rev, h.name
	switch {
	case len(h.heads) > 0 && (e.Rev == h.cur || h.heads[e.Rev]):
		// Changed on two devices at once: this version is kept, and
		// the others go, on every device (the CLI's resolve --keep).
		head.Add(widgets.NewButton("Keep this version on every device…", func() { m.restoreRevision(name, rev, true) }))
	case e.Rev != h.cur:
		head.Add(widgets.NewButton("Make this revision current…", func() { m.restoreRevision(name, rev, false) }))
	}
	h.below.Set(widgets.NewColumn(widgets.NewSeparator(), head, h.view.root).WithGap(gap))
	if col, ok := h.below.Page().(*widgets.FlexBox); ok {
		col.AddFlex(h.view.root, 1)
	}
}

// restoreRevision makes a revision of an item current again (the CLI's
// restore NAME REV); for one of its conflicting versions, that settles
// the conflict in its favour (the CLI's resolve --keep).
func (m *Manager) restoreRevision(name, rev string, keep bool) {
	vault := m.vault
	title, text, action := "Make it current?", fmt.Sprintf("Make revision %s of %s current again?\n\nThe revision now current stays in the history.", short(rev), name), "Make current"
	if keep {
		title, text, action = "Keep this version?", fmt.Sprintf("Keep version %s of %s, on every device?\n\nThe other versions saved at the same time stay in the history, and the conflict is settled.", short(rev), name), "Keep it"
	}
	m.confirm(title, text, action, func() {
		var e svrpc.Entry
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			e, err = c.Restore(ctx, svrpc.RestoreParams{Vault: vault, Name: name, Rev: rev})
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			if keep {
				m.say("Kept that version of %s; the conflict is settled (revision %s).", name, short(e.Rev))
			} else {
				m.say("Restored %s (revision %s).", name, short(e.Rev))
			}
			if vault == m.vault && m.showingHistory() && m.hist != nil && m.hist.name == name {
				m.showHistory()
			}
		})
	})
}

func (m *Manager) closeHistory() {
	if !m.showingHistory() {
		return
	}
	name := ""
	if m.hist != nil {
		name = m.hist.name
	}
	m.wipeHistory()
	m.showSelected()
	if name != "" && m.entry(name) != nil {
		m.openItem(name, false)
	}
	m.win.RequestFocus(m.ui.items)
}

// leaveHistory takes the history down, wiping its revisions, and shows
// the selection in its place: for whatever is about to replace it.
func (m *Manager) leaveHistory() {
	showing := m.showingHistory()
	m.wipeHistory()
	if showing {
		m.showSelected()
	}
}

// wipeHistory forgets the history page's revisions, wiping them.
func (m *Manager) wipeHistory() {
	h := m.hist
	if h == nil {
		return
	}
	if h.view != nil {
		h.view.forget()
	}
	wipeEntries(h.entries)
	m.hist = nil
	m.syncCapture()
}
