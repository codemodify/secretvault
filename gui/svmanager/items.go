package svmanager

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// Items: listing, folders, searching, opening, copying, renaming and
// deleting them.

// loadItems lists the shown vault's items.
func (m *Manager) loadItems() {
	vault, gen := m.vault, m.listGen
	var entries []svrpc.Entry
	m.listing = true
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.List(ctx, vault, "")
		return err
	}, func(err error) {
		if gen != m.listGen {
			return
		}
		m.listing = false
		if err != nil {
			if !m.listed && m.editor == nil && !m.showingVaultPage() {
				m.showSelected()
			}
			m.fail(err)
			m.drawItems()
			m.reloadVaults()
			return
		}
		slices.SortFunc(entries, func(a, b svrpc.Entry) int { return strings.Compare(a.Item.Name, b.Item.Name) })
		m.entries, m.listed = entries, true
		m.lists++
		m.drawFolders()
		m.applyFilter()
		if m.cur == nil && m.editor == nil && !m.showingVaultPage() && !m.showingHistory() {
			m.showSelected()
		}
		m.reloadVaults()
	})
}

// folderOf is the folder an item name is in: everything up to its last
// slash ("web/" for "web/github.com"), or "" at the top.
func folderOf(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i+1]
	}
	return ""
}

// drawFolders makes the folder tree from the items' names: every prefix
// that ends in a slash is a folder, and a folder holds the folders and
// items under it. "All items" is the root.
func (m *Manager) drawFolders() {
	t := m.ui.folders
	if !m.listed {
		t.SetRoots(nil)
		t.Selected = nil
		return
	}
	counts := map[string]int{}
	for _, e := range m.entries {
		name := e.Item.Name
		for i := 0; i < len(name); i++ {
			if name[i] == '/' {
				counts[name[:i+1]]++
			}
		}
	}
	paths := make([]string, 0, len(counts))
	for p := range counts {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	all := widgets.NewTreeNode(fmt.Sprintf("All items (%d)", len(m.entries)))
	all.Data = ""
	all.Expanded = true
	nodes := map[string]*widgets.TreeNode{"": all}
	for _, p := range paths {
		parent := folderOf(strings.TrimSuffix(p, "/"))
		seg := strings.TrimSuffix(strings.TrimPrefix(p, parent), "/")
		n := widgets.NewTreeNode(fmt.Sprintf("%s (%d)", seg, counts[p]))
		n.Data = p
		pn := nodes[parent]
		if pn == nil {
			pn = all
		}
		pn.Children = append(pn.Children, n)
		pn.Expanded = true
		nodes[p] = n
	}
	// Folders that were closed stay closed.
	for p, n := range nodes {
		if old := m.findFolder(p); old != nil && !old.Expanded && len(n.Children) > 0 {
			n.Expanded = false
		}
	}
	if nodes[m.folder] == nil {
		m.folder = ""
	}
	t.SetRoots([]*widgets.TreeNode{all})
	t.Selected = nodes[m.folder]
	t.Invalidate()
}

// findFolder is the node of folder p in the tree as it is, or nil.
func (m *Manager) findFolder(p string) *widgets.TreeNode {
	var found *widgets.TreeNode
	var walk func([]*widgets.TreeNode)
	walk = func(ns []*widgets.TreeNode) {
		for _, n := range ns {
			if s, ok := n.Data.(string); ok && s == p {
				found = n
				return
			}
			walk(n.Children)
		}
	}
	walk(m.ui.folders.Roots)
	return found
}

func (m *Manager) folderSelected(n *widgets.TreeNode) {
	p, _ := n.Data.(string)
	if p == m.folder {
		return
	}
	m.folder = p
	m.applyFilter()
}

// setQuery searches as the person types.
func (m *Manager) setQuery(q string) {
	if q == m.query {
		return
	}
	m.query = q
	m.applyFilter()
}

// matches reports whether an item holds every word of the search in its
// name, label, kind, tags or attributes, ignoring case. Field values are
// not searched: the list holds none.
func matches(e *svrpc.Entry, words []string) bool {
	if len(words) == 0 {
		return true
	}
	var b strings.Builder
	b.WriteString(e.Item.Name + " " + e.Item.Label + " " + e.Item.Kind + " " + strings.Join(e.Item.Tags, " "))
	for k, v := range e.Item.Attrs {
		b.WriteString(" " + k + " " + v)
	}
	hay := strings.ToLower(b.String())
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// applyFilter shows the items of the folder chosen that match the search.
// A search looks in every folder when the folder chosen has no match.
func (m *Manager) applyFilter() {
	before := m.cursor
	words := strings.Fields(strings.ToLower(m.query))
	m.shown = m.shown[:0]
	for i := range m.entries {
		e := &m.entries[i]
		if strings.HasPrefix(e.Item.Name, m.folder) && matches(e, words) {
			m.shown = append(m.shown, i)
		}
	}
	m.drawItems()
	if m.cursor != before && m.editor == nil && !m.showingHistory() {
		// The search moved the selection: the item beside the list
		// follows it, and one that was open closes.
		m.closeItem()
	}
}

// drawItems fills the item list, keeping the selection on the item it was
// on.
func (m *Manager) drawItems() {
	t := m.ui.items
	t.RowCount = len(m.shown)
	t.Selected = -1
	for n, i := range m.shown {
		if m.entries[i].Item.Name == m.cursor {
			t.Selected = n
		}
	}
	if t.Selected < 0 && len(m.shown) > 0 && m.query != "" {
		// Searching: the best match is selected, so Enter opens it.
		t.Selected = 0
		m.cursor = m.entries[m.shown[0]].Item.Name
	}
	if t.Selected >= 0 {
		t.EnsureVisible(t.Selected)
	}
	t.Invalidate()

	note := ""
	switch v := m.vaultInfo(m.vault); {
	case m.gone:
		note = "secretvault's background service is not running: nothing can be shown until it is back."
	case m.vault == "":
	case v != nil && v.ID == "":
		note = "This vault's folder is missing."
	case v != nil && !m.listed && v.Locked:
		note = "Locked. Enter or Ctrl+U unlocks it."
	case !m.listed && m.listing:
		note = "Listing…"
	case !m.listed:
		note = "Not listed yet. Enter on the vault lists its items."
	case len(m.entries) == 0:
		note = "No items yet: Ctrl+N makes one."
	case len(m.shown) == 0:
		note = "Nothing matches."
	case len(m.shown) != len(m.entries):
		note = fmt.Sprintf("%d of %d items", len(m.shown), len(m.entries))
	default:
		note = plural(len(m.entries), "item")
	}
	m.ui.itemsNote.SetText(note)
	m.enableMenus()
}

func (m *Manager) itemCell(row, col int) string {
	if row < 0 || row >= len(m.shown) {
		return ""
	}
	e := &m.entries[m.shown[row]]
	if col == 1 {
		return e.Item.Kind
	}
	// Inside a folder, the folder goes without saying.
	return strings.TrimPrefix(e.Item.Name, m.folder)
}

// itemIcon marks an item whose versions conflict, and one with files.
func (m *Manager) itemIcon(row, col int) (style.ToolIcon, paintengine2d.Color) {
	if col != 0 || row < 0 || row >= len(m.shown) {
		return style.IconNone, paintengine2d.Color{}
	}
	e := &m.entries[m.shown[row]]
	switch {
	case len(e.Conflicts) > 0:
		return style.IconWarning, m.win.Look().Palette().Warning
	case len(e.Item.Files) > 0:
		return style.IconAttach, paintengine2d.Color{}
	}
	return style.IconNone, paintengine2d.Color{}
}

// entry is the listed item of that name, or nil.
func (m *Manager) entry(name string) *svrpc.Entry {
	for i := range m.entries {
		if m.entries[i].Item.Name == name {
			return &m.entries[i]
		}
	}
	return nil
}

// itemSelected follows the selection in the item list. Selecting an item
// shows what the list knows of it, which is everything but its fields;
// its fields are fetched when it is opened (Enter), because every fetch is
// a read the daemon records.
func (m *Manager) itemSelected(i int) {
	if i < 0 || i >= len(m.shown) {
		return
	}
	name := m.entries[m.shown[i]].Item.Name
	if m.cur != nil && m.cur.Item.Name == name {
		m.cursor = name
		return
	}
	m.cursor = name
	defer m.enableMenus()
	if m.editor != nil {
		return // the editor stays until it is saved or closed
	}
	if m.showingHistory() {
		// Another item: its history goes, wiped.
		m.wipeHistory()
		m.closeItem()
		m.showSelected()
		return
	}
	m.closeItem() // which shows the selection
}

// itemActivated is Enter or a double click in the list: the item opens.
func (m *Manager) itemActivated(i int) {
	if i < 0 || i >= len(m.shown) {
		return
	}
	m.cursor = m.entries[m.shown[i]].Item.Name
	m.openItem(m.cursor, false)
}

// openSelected opens the item selected in the list.
func (m *Manager) openSelected() {
	if m.cursor != "" {
		m.openItem(m.cursor, false)
	}
}

// openFirstMatch is Enter in the search: the selected match opens, and the
// list takes the keyboard.
func (m *Manager) openFirstMatch() {
	if len(m.shown) == 0 {
		return
	}
	if m.cursor == "" || m.entry(m.cursor) == nil {
		m.cursor = m.entries[m.shown[0]].Item.Name
	}
	m.win.RequestFocus(m.ui.items)
	m.openItem(m.cursor, false)
}

// targetName is the item an action is about: the one selected in the list,
// else the open one.
func (m *Manager) targetName() string {
	if m.cursor != "" && m.entry(m.cursor) != nil {
		return m.cursor
	}
	if m.cur != nil {
		return m.cur.Item.Name
	}
	return ""
}

// openItem fetches an item with its fields and shows it.
func (m *Manager) openItem(name string, reveal bool) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	// The item takes the place of whatever page was up: a history goes,
	// wiped, and so does the vault's page over the items.
	m.closeVaultPage()
	m.leaveHistory()
	m.closeItem()
	gen, vault := m.itemGen, m.vault
	m.say("Opening %s…", name)
	var e svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		if gen != m.itemGen || vault != m.vault {
			wipeItem(&e.Item)
			return
		}
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		m.say("")
		m.hold(&e, reveal)
		m.reloadVaults() // the open may have unlocked the vault
	})
}

// hold makes e the open item, and shows it.
func (m *Manager) hold(e *svrpc.Entry, reveal bool) {
	m.cur = e
	m.otp = otpKeys(&e.Item)
	m.hasOTP.Store(len(m.otp) > 0)
	m.showItem(reveal)
}

// otpKeys reads an item's otp fields, by field index. The caller wipes
// the keys.
func otpKeys(it *svrpc.Item) map[int]*svotp.Key {
	keys := map[int]*svotp.Key{}
	for i, f := range it.Fields {
		if f.Type == svcore.FieldOTP {
			if k, err := parseOTP(f.Value); err == nil {
				keys[i] = k
			}
		}
	}
	return keys
}

// parseOTP reads an otp field: an otpauth:// URI, or a bare base32 seed
// (a 30-second, six-digit TOTP key, as authenticator apps assume).
func parseOTP(v []byte) (*svotp.Key, error) {
	// svotp reads strings, so the key briefly becomes one here.
	s := strings.TrimSpace(string(v))
	if len(s) > 8 && strings.EqualFold(s[:8], "otpauth:") {
		return svotp.Parse(s)
	}
	secret, err := svotp.DecodeSecret(s)
	if err != nil {
		return nil, err
	}
	return &svotp.Key{Type: "totp", Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30}, nil
}

// closeItem leaves the open item: its values are wiped, and taken off the
// screen, and what is selected shows in its place.
func (m *Manager) closeItem() {
	m.itemGen++ // an open on its way is not wanted now
	m.dropItem()
	if m.ui != nil && m.editor == nil && !m.showingVaultPage() && !m.showingHistory() {
		m.showSelected()
	}
	m.syncCapture()
}

// dropItem wipes the open item and lets the screen go of it, and does
// nothing else.
func (m *Manager) dropItem() {
	if m.ui != nil && m.ui.view != nil {
		m.ui.view.forget()
		m.ui.view = nil
	}
	if m.cur != nil {
		wipeItem(&m.cur.Item)
		m.cur = nil
	}
	for _, k := range m.otp {
		k.Wipe()
	}
	m.otp = map[int]*svotp.Key{}
	m.hasOTP.Store(false)
}

// withItem runs fn on the target item: the open one, or else the one
// selected, fetched for the purpose and wiped afterwards. fn is told which
// vault the item is from. A fetch whose answer comes after the vault shown
// has changed, or locked, is dropped: fn would act on another vault's
// screen.
func (m *Manager) withItem(fn func(vault string, e *svrpc.Entry)) {
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	if m.cur != nil && m.cur.Item.Name == name {
		fn(m.vault, m.cur)
		return
	}
	vault, gen := m.vault, m.listGen
	var e svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		defer wipeItem(&e.Item)
		switch {
		case vault != m.vault || gen != m.listGen:
			return // the vault shown changed, or locked, meanwhile
		case err != nil:
			m.fail(err)
			return
		}
		fn(vault, &e)
	})
}

// copySecret copies the target item's password (its primary secret).
func (m *Manager) copySecret() {
	m.withItem(func(vault string, e *svrpc.Entry) {
		f, ok := secretField(&e.Item)
		if !ok {
			m.say("%s has no secret to copy.", e.Item.Name)
			return
		}
		m.copyValue(f.Value, "The "+f.Name, vault)
	})
}

// copyAndMinimise copies the password and gets the window out of the way
// of the program it is to be pasted into.
func (m *Manager) copyAndMinimise() {
	m.withItem(func(vault string, e *svrpc.Entry) {
		f, ok := secretField(&e.Item)
		if !ok {
			m.say("%s has no secret to copy.", e.Item.Name)
			return
		}
		if m.copyValue(f.Value, "The "+f.Name, vault) {
			m.minimise()
		}
	})
}

func (m *Manager) copyUsername() {
	m.withItem(func(vault string, e *svrpc.Entry) {
		if f, ok := usernameField(&e.Item); ok {
			m.copyValue(f.Value, "The "+f.Name, vault)
			return
		}
		if name := e.Item.Attrs["username"]; name != "" {
			m.copyValue([]byte(name), "The username", vault)
			return
		}
		m.say("%s has no username.", e.Item.Name)
	})
}

func (m *Manager) copyCode() {
	m.withItem(func(vault string, e *svrpc.Entry) {
		for _, f := range e.Item.Fields {
			if f.Type != svcore.FieldOTP {
				continue
			}
			k, err := parseOTP(f.Value)
			if err != nil {
				m.fail(err)
				return
			}
			code, _ := k.Code(m.now())
			k.Wipe()
			m.copyValue([]byte(code), "The one-time code", vault)
			return
		}
		m.say("%s has no one-time password.", e.Item.Name)
	})
}

// copyValue puts a copy of v on the clipboard, for the clipboard to wipe;
// v itself stays with its owner, who may wipe it at any time. what says
// what it was, for the status bar; vault is the vault it came from, whose
// locking takes it back ("" for none: a generated password).
func (m *Manager) copyValue(v []byte, what, vault string) bool {
	if len(v) == 0 {
		m.say("That is empty: nothing was copied.")
		return false
	}
	c := m.clip.SetSecret(append([]byte(nil), v...), m.ttl)
	m.copied, m.copiedFrom = c, vault
	m.say("%s is on the clipboard for %d seconds.", what, int(m.ttl.Seconds()))
	// Said when the copy goes by itself, at its timeout. Taken back (its
	// vault locked) or replaced by another copy, it has been said already.
	c.OnCleared(func() {
		m.post(func() {
			if m.copied == c {
				m.copied = nil
				m.say("%s is no longer on the clipboard.", what)
			}
		})
	})
	return true
}

// secretField is the item's primary secret, as svcore.Item.Secret picks it.
func secretField(it *svrpc.Item) (svrpc.Field, bool) {
	for _, n := range []string{"password", "secret"} {
		for _, f := range it.Fields {
			if f.Name == n {
				return f, true
			}
		}
	}
	for _, f := range it.Fields {
		if f.Type == svcore.FieldConcealed || f.Type == svcore.FieldKey {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

// usernameField is the field that holds the item's username: one named
// so, else the first email field.
func usernameField(it *svrpc.Item) (svrpc.Field, bool) {
	for _, n := range []string{"username", "user", "login", "email"} {
		for _, f := range it.Fields {
			if strings.EqualFold(f.Name, n) {
				return f, true
			}
		}
	}
	for _, f := range it.Fields {
		if f.Type == svcore.FieldEmail {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

// deleteItem deletes the target item, after asking.
func (m *Manager) deleteItem() {
	if m.editor != nil {
		return // Delete is the editor's own key while it is up
	}
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	vault := m.vault
	m.confirm("Delete "+name+"?", svops.DeleteItemText(name, vault, "Edit › Deleted items"), svops.DeleteItemAction,
		func() {
			m.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.Delete(ctx, vault, name)
			}, func(err error) {
				if err != nil {
					m.fail(err)
					return
				}
				if m.cur != nil && m.cur.Item.Name == name {
					m.closeItem()
				}
				if m.cursor == name {
					m.cursor = ""
				}
				m.say("Deleted %s.", name)
				if vault == m.vault {
					m.loadItems()
				}
			})
		})
}

// renameItem gives the target item a new name.
func (m *Manager) renameItem() {
	if m.editor != nil {
		return
	}
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	vault := m.vault
	// uitoolkit's prompt: a name that cannot be used is refused where it
	// was typed, with what was typed still there, rather than after the
	// dialog has gone. That includes the daemon's refusal: the rename is
	// the prompt's check (ValidateAsync), so the dialog waits for the
	// answer and says under the field why a name was not taken.
	widgets.PromptFor(m.root(), "Rename "+name, "New name:", widgets.MessageBoxInput{
		Text: name, Required: true, AcceptLabel: "Rename",
		ValidateAsync: func(to string, done func(error)) {
			to = strings.TrimSpace(to)
			switch {
			case to == name:
				done(nil)
				return
			case svcore.CheckName(to) != nil:
				done(errors.New(svops.BadItemName(to)))
				return
			case m.entry(to) != nil:
				done(fmt.Errorf("There is an item called %s already.", to))
				return
			}
			m.call(func(ctx context.Context, c *secretvault.Client) error {
				_, err := c.Rename(ctx, vault, name, to)
				return err
			}, func(err error) {
				if err != nil {
					done(errors.New(m.describe(err)))
					return
				}
				// Renamed, whether or not the dialog is still up to be
				// told: the window follows either way.
				done(nil)
				m.say("Renamed %s to %s.", name, to)
				m.cursor = to
				if m.cur != nil && m.cur.Item.Name == name {
					m.openItem(to, false)
				}
				if vault == m.vault {
					m.loadItems()
				}
			})
		},
	}, nil)
}

// reopen fetches the open item again, keeping what was revealed.
func (m *Manager) reopen() {
	if m.cur == nil {
		return
	}
	name := m.cur.Item.Name
	m.itemGen++ // a reopen already on its way brings an older item
	vault, gen := m.vault, m.itemGen
	revealed := m.ui.view.revealedFields()
	var e svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		if gen != m.itemGen || vault != m.vault {
			wipeItem(&e.Item)
			return
		}
		if errors.Is(err, svrpc.ErrNotFound) {
			m.closeItem()
			m.say("%s was deleted.", name)
			return
		}
		if err != nil {
			wipeItem(&e.Item)
			return
		}
		m.closeItem()
		m.hold(&e, false)
		m.ui.view.reveal(revealed)
	})
}

// focusSearch is Ctrl+F.
func (m *Manager) focusSearch() {
	m.closeVaultPage() // which covers the search
	m.win.RequestFocus(m.ui.search)
	m.ui.search.SelectAll()
}

// minimise gets the window out of the way (after copying, for pasting
// into the program behind it).
func (m *Manager) minimise() {
	if m.minimiseHook != nil {
		m.minimiseHook()
		return
	}
	m.win.Minimize()
}
