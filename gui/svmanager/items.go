package svmanager

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/uitoolkit/widget"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// Items: listing, filtering, opening, copying, renaming and deleting
// them.

// loadItems lists the shown vault's items.
func (m *Manager) loadItems() {
	vault, gen := m.vault, m.listGen
	var entries []svrpc.Entry
	m.listing, m.listingSince = true, m.flipNow()
	if m.ui != nil && m.ui.vaultHost != nil {
		// A listing that waits (on a prompt) shows the vault's face.
		widget.After(m.ui.vaultHost, faceWait, m.syncFace)
	}
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
			m.syncFace()
			m.reloadVaults()
			return
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Item.Name
		}
		m.names = svops.ShownNames(names)
		// By the names the list shows, as people read them.
		slices.SortFunc(entries, func(a, b svrpc.Entry) int {
			return cmp.Or(strings.Compare(strings.ToLower(m.names[a.Item.Name]), strings.ToLower(m.names[b.Item.Name])),
				strings.Compare(a.Item.Name, b.Item.Name))
		})
		m.entries, m.listed = entries, true
		m.lists++
		m.applyFilter()
		if m.cur == nil && m.editor == nil && !m.showingVaultPage() && !m.showingHistory() {
			m.showSelected()
		}
		m.syncFace() // the items are here: a closed vault's face goes
		m.reloadVaults()
	})
}

// setQuery filters as the person types. When the item chosen is not let
// through, nothing is chosen, and the pane says what the filter finds.
func (m *Manager) setQuery(q string) {
	if q == m.query {
		return
	}
	m.query = q
	m.applyFilter()
	if m.rowOf(m.cursor) < 0 && len(m.picked) < 2 && m.editor == nil && !m.showingHistory() && !m.showingVaultPage() {
		m.cursor = ""
		m.closeItem()
	}
}

// matches reports whether an item holds every word of the filter in its
// name, label, kind, tags or attributes, ignoring case. Field values are
// not looked at: the list holds none.
func matches(e *svrpc.Entry, words []string) bool {
	if len(words) == 0 {
		return true
	}
	var b strings.Builder
	b.WriteString(e.Item.Name + " " + e.Item.Label + " " + e.Item.Kind + " " + svops.KindText(e.Item.Kind) + " " + strings.Join(e.Item.Tags, " "))
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

// applyFilter shows the items of the tab shown that match the filter: the
// filter is one for every tab, kept as the tabs change.
func (m *Manager) applyFilter() {
	before := m.cursor
	words := strings.Fields(strings.ToLower(m.query))
	m.shown = m.shown[:0]
	for i := range m.entries {
		if m.inItemTab(&m.entries[i]) && matches(&m.entries[i], words) {
			m.shown = append(m.shown, i)
		}
	}
	m.drawItems()
	if m.cursor != before && m.editor == nil && !m.showingHistory() && !m.showingVaultPage() {
		// The filter moved the selection: the item beside the list
		// follows it, and one that was open closes.
		m.closeItem()
	}
}

// drawItems fills the list with the items shown, keeping the selection
// on the item it was on.
func (m *Manager) drawItems() {
	if m.query != "" && len(m.shown) > 0 && !slices.ContainsFunc(m.shown, func(i int) bool { return m.entries[i].Item.Name == m.cursor }) {
		// Filtering: the best match is selected, so Enter opens it.
		m.cursor = m.entries[m.shown[0]].Item.Name
	}
	m.drawContent()
	m.enableMenus()
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

// openFirstMatch is Enter in the filter: the selected match opens, and the
// list takes the keyboard.
func (m *Manager) openFirstMatch() {
	if len(m.shown) == 0 {
		return
	}
	if m.cursor == "" || m.entry(m.cursor) == nil {
		m.cursor = m.entries[m.shown[0]].Item.Name
	}
	m.focus(m.ui.content)
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
		// An item opened from elsewhere (one just saved, one brought
		// back) brings its kind's tab forward, where the list shows it.
		if t := tabOf(&e); t >= 0 && t != m.itemTab && m.ui.vaultTabs.Selected() <= lastItemTab {
			m.ui.vaultTabs.Select(t)
			m.cursor = name
			m.syncList()
		}
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
// what it was, for the note that says so; vault is the vault it came
// from, whose locking takes it back ("" for none: a generated password).
func (m *Manager) copyValue(v []byte, what, vault string) bool {
	if len(v) == 0 {
		m.say("That is empty: nothing was copied.")
		return false
	}
	c := m.clip.SetSecret(append([]byte(nil), v...), m.ttl)
	if r, ok := c.(interface{ Cleared() bool }); ok && r.Cleared() {
		// The desktop would not take it (another program holding the
		// clipboard open, say): uitoolkit hands a refused copy back
		// already cleared, and wiped.
		m.fail(fmt.Errorf("%s could not be copied: the clipboard is busy. Try again in a moment.", what))
		return false
	}
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

// secretField is the item's primary secret, as svcore.Item.Secret picks
// it (a passkey has none to hand out).
func secretField(it *svrpc.Item) (svrpc.Field, bool) { return svops.SecretField(it) }

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
	m.confirm("Delete "+name+"?", svops.DeleteItemText(name, vault, "Vault › Items › Deleted items"), svops.DeleteItemAction,
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
	// A name that cannot be used is refused in the dialog, with what was
	// typed still there, rather than after the dialog has gone; so is the
	// daemon's refusal (the dialog stays up for it).
	f := m.newForm("Rename " + name)
	field := f.text("New name", name, "")
	f.show("Rename", func() {
		to := strings.TrimSpace(field.Text)
		switch {
		case to == name:
			f.close()
			return
		case svcore.CheckName(to) != nil:
			f.fail(svops.BadItemName(to))
			return
		case m.entry(to) != nil:
			f.fail(fmt.Sprintf("There is an item called %s already.", to))
			return
		}
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.Rename(ctx, vault, name, to)
			return err
		}, func() {
			m.say("Renamed %s to %s.", name, to)
			m.cursor = to
			if m.cur != nil && m.cur.Item.Name == name {
				m.openItem(to, false)
			}
			if vault == m.vault {
				m.loadItems()
			}
		})
	})
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
		if errors.Is(err, svrpc.ErrNoVault) {
			// The vault went (forgotten, or its folder moved), not the
			// item: say so, in the daemon's words.
			m.closeItem()
			m.fail(err)
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

// focusFilter is Ctrl+F.
func (m *Manager) focusFilter() {
	m.showSection(secVaults)
	m.closeVaultPage() // which covers the filter
	m.focus(m.ui.filter)
	m.ui.filter.SelectAll()
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
