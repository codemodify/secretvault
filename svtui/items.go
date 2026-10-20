package svtui

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// Vaults and items: listing, opening, copying, and the daemon's events.

// start lists the vaults and shows the first one.
func (u *UI) start() {
	var vs []svrpc.VaultInfo
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		vs, err = c.Vaults(ctx)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.vaults = vs
		name := u.opts.Vault
		if name == "" {
			for _, v := range vs {
				if v.Default {
					name = v.Name
				}
			}
		}
		if name == "" && len(vs) > 0 {
			name = vs[0].Name
		}
		if name == "" {
			u.drawVaults()
			u.detail.reset("There are no vaults yet.\n\nN makes one.")
			u.drawStatus()
			return
		}
		u.showVault(name, false)
		for i, v := range vs {
			if v.Name == name {
				u.cursorOnVault(i)
			}
		}
		u.noteEmergency()
	})
}

func (u *UI) vaultInfo(name string) *svrpc.VaultInfo {
	for i := range u.vaults {
		if u.vaults[i].Name == name {
			return &u.vaults[i]
		}
	}
	return nil
}

// reloadVaults asks the daemon for the vaults' states again. A vault it
// says is locked is cleared, even if its vault.locked event went astray;
// unless its items were listed since the question was asked, in which
// case the answer is out of date.
func (u *UI) reloadVaults() {
	var vs []svrpc.VaultInfo
	lists := u.lists
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		vs, err = c.Vaults(ctx)
		return err
	}, func(err error) {
		if err != nil {
			return
		}
		u.vaults = vs
		u.drawVaults()
		if v := u.vaultInfo(u.vault); v != nil && v.Locked && u.listed && lists == u.lists {
			u.vaultLocked(u.vault)
		}
		u.drawStatus()
	})
}

func (u *UI) drawVaults() {
	at := u.vaultRowAt(u.vaultList.GetCurrentItem())
	u.vaultList.Clear()
	u.vrows = u.vrows[:0]
	width := 30 // "   Personal details  123", and the border
	for _, v := range u.vaults {
		// "▸ name *  unlocked", and the border.
		width = max(width, 2+tview.TaggedStringWidth(tview.Escape(v.Name))+2+2+8+2)
	}
	u.body.ResizeItem(u.vaultList, min(width, 34), 0)
	counts := u.kindCounts()
	for i, v := range u.vaults {
		mark := "  "
		if v.Name == u.vault {
			mark = "▸ "
		}
		name := tview.Escape(v.Name)
		if v.Default {
			name += " *"
		}
		state := "[green]unlocked[-]"
		switch {
		case v.ID == "":
			state = "[red]missing[-]"
		case v.Locked:
			state = "[gray]locked[-]"
		}
		u.vaultList.AddItem(fmt.Sprintf("%s%s  %s", mark, name, state), "", 0, nil)
		u.vrows = append(u.vrows, vaultRow{vault: i, part: -1})
		if v.Name != u.vault || !u.listed || u.gone {
			continue
		}
		// The vault shown, open: what it holds.
		for k, r := range svops.KindRows {
			text := fmt.Sprintf("   %-18s %3d", r.Title, counts[k])
			switch {
			case k == u.kind:
				text = "[::b]" + text + "[::-]"
			case counts[k] == 0:
				text = "[gray]" + text + "[-]"
			}
			u.vaultList.AddItem(text, "", 0, nil)
			u.vrows = append(u.vrows, vaultRow{vault: i, part: k})
		}
		for j, t := range []string{svops.MyKeysRow, svops.ContactsRow, svops.AboutVaultRow} {
			u.vaultList.AddItem("   "+t, "", 0, nil)
			u.vrows = append(u.vrows, vaultRow{vault: i, part: len(svops.KindRows) + j})
		}
	}
	// The cursor stays on its row, or on its vault's.
	cur := slices.Index(u.vrows, at)
	if cur < 0 {
		cur = slices.Index(u.vrows, vaultRow{vault: at.vault, part: -1})
	}
	if cur >= 0 {
		u.vaultList.SetCurrentItem(cur)
	}
}

// vaultRow is a row of the vault list: a vault's own (part -1), or one of
// what the open vault holds: a row of svops.KindRows, or after them My
// keys, Contacts and About this vault.
type vaultRow struct{ vault, part int }

// The rows after the kinds', as parts.
var (
	partMyKeys   = len(svops.KindRows)
	partContacts = partMyKeys + 1
	partAbout    = partMyKeys + 2
)

// vaultRowAt is row i of the vault list.
func (u *UI) vaultRowAt(i int) vaultRow {
	if i >= 0 && i < len(u.vrows) {
		return u.vrows[i]
	}
	return vaultRow{vault: max(i, 0), part: -1}
}

// vaultUnderCursor is the vault of the vault list's row under the cursor,
// -1 for none.
func (u *UI) vaultUnderCursor() int {
	if r := u.vaultRowAt(u.vaultList.GetCurrentItem()); r.vault < len(u.vaults) {
		return r.vault
	}
	return -1
}

// cursorOnVault puts the vault list's cursor on vault i's own row.
func (u *UI) cursorOnVault(i int) {
	if at := slices.Index(u.vrows, vaultRow{vault: i, part: -1}); at >= 0 {
		u.vaultList.SetCurrentItem(at)
	} else {
		u.vaultList.SetCurrentItem(i)
	}
}

// vaultRowChosen is Enter on row i of the vault list: a vault is shown
// (unlocked first), a kind's items are listed, and the vault's pages open.
func (u *UI) vaultRowChosen(i int) {
	r := u.vaultRowAt(i)
	if r.vault >= len(u.vaults) {
		return
	}
	switch {
	case r.part < 0:
		u.showVault(u.vaults[r.vault].Name, true)
		u.app.SetFocus(u.itemList)
	case r.part < partMyKeys:
		u.showKind(r.part)
		u.app.SetFocus(u.itemList)
	case r.part == partMyKeys:
		u.showKeys()
	case r.part == partContacts:
		u.showContacts()
	default:
		u.aboutVault()
	}
}

// showKind lists the items of row k of svops.KindRows.
func (u *UI) showKind(k int) {
	if k == u.kind {
		return
	}
	u.kind = k
	u.applyFilter()
	u.drawVaults()
}

// kindCounts are, for each row of svops.KindRows, how many of the vault's
// items it has that the filter lets through.
func (u *UI) kindCounts() map[int]int {
	words := strings.Fields(strings.ToLower(u.filter.GetText()))
	counts := map[int]int{}
	for i := range u.entries {
		if k := svops.KindRowOf(&u.entries[i].Item); k >= 0 && filterMatches(&u.entries[i], words) {
			counts[k]++
		}
	}
	return counts
}

// aboutVault offers the vault's own pages, as the GUI's About this vault.
func (u *UI) aboutVault() {
	if !u.needVault() {
		return
	}
	pages := []struct {
		name string
		do   func()
	}{
		{"Ways to unlock   (K)", u.showSlots}, {"Sharing and emergency access   (E)", u.showSharing},
		{"Devices   (D)", u.showDevices}, {"Sync   (S)", u.showSync}, {"Grants   (G)", u.showGrants},
		{"Audit log   (A)", u.showAudit}, {"Settings: every vault   (V)", u.showVaults},
	}
	names := make([]string, len(pages))
	for i, p := range pages {
		names[i] = p.name
	}
	u.choose("About vault "+u.vault, names, func(i int) { pages[i].do() })
}

// showVault shows a vault's items. A locked vault is listed only when
// unlock is set: listing it makes the daemon ask for its passphrase.
func (u *UI) showVault(name string, unlock bool) {
	if name != u.vault {
		u.closeItem()
		u.filter.SetText("")
		u.middle.ResizeItem(u.filter, 0, 0)
	}
	u.vault = name
	u.listGen++
	u.entries, u.names, u.shown, u.listed = nil, nil, nil, false
	u.drawVaults()
	if v := u.vaultInfo(name); v != nil && v.Locked && !unlock {
		u.drawItems()
		u.drawStatus()
		return
	}
	u.loadItems()
}

// loadItems lists the shown vault's items.
func (u *UI) loadItems() {
	vault, gen := u.vault, u.listGen
	var entries []svrpc.Entry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.List(ctx, vault, "")
		return err
	}, func(err error) {
		if gen != u.listGen {
			return
		}
		if err != nil {
			u.fail(err)
			u.drawItems()
			u.reloadVaults()
			return
		}
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Item.Name
		}
		u.names = svops.ShownNames(names)
		slices.SortFunc(entries, func(a, b svrpc.Entry) int {
			return cmp.Or(strings.Compare(strings.ToLower(u.names[a.Item.Name]), strings.ToLower(u.names[b.Item.Name])),
				strings.Compare(a.Item.Name, b.Item.Name))
		})
		u.entries, u.listed = entries, true
		u.lists++
		u.applyFilter()
		u.reloadVaults()
	})
}

// applyFilter shows the items of the kind listed whose name, label, kind
// or tags hold every word of the filter, ignoring case, in the list's
// order: by the names it shows. The filter is one for every kind; the
// vault list's counts follow it.
func (u *UI) applyFilter() {
	words := strings.Fields(strings.ToLower(u.filter.GetText()))
	u.shown = u.shown[:0]
	for i := range u.entries {
		if svops.KindRowOf(&u.entries[i].Item) == u.kind && filterMatches(&u.entries[i], words) {
			u.shown = append(u.shown, i)
		}
	}
	u.drawItems()
	u.drawVaults()
}

// filterMatches reports whether an item holds every word of the filter
// in its name, label, kind or tags, ignoring case.
func filterMatches(e *svrpc.Entry, words []string) bool {
	hay := strings.ToLower(e.Item.Name + " " + e.Item.Label + " " + e.Item.Kind + " " + svops.KindText(e.Item.Kind) + " " + strings.Join(e.Item.Tags, " "))
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// rowName is the name of the item of row i of u.shown.
func (u *UI) rowName(i int) string { return u.entries[i].Item.Name }

// drawItems fills the item list, keeping the cursor on the item it was on.
func (u *UI) drawItems() {
	want := u.cursor
	u.redraw = true
	defer func() { u.redraw = false }()
	u.itemList.Clear()
	kind := svops.KindRows[u.kind].Title
	title := " " + kind + " "
	if u.vault != "" {
		title = " " + kind + " · " + tview.Escape(u.vault) + " "
	}
	inKind := 0
	for i := range u.entries {
		if svops.KindRowOf(&u.entries[i].Item) == u.kind {
			inKind++
		}
	}
	switch v := u.vaultInfo(u.vault); {
	case u.gone:
		u.itemList.AddItem("[gray]secretvaultd went away[-]", "", 0, nil)
	case v != nil && !u.listed && v.Locked:
		u.itemList.AddItem("[gray]Locked: Enter unlocks[-]", "", 0, func() { u.showVault(u.vault, true) })
	case !u.listed:
	case len(u.shown) == 0 && u.filter.GetText() != "":
		// Nothing of this kind: the kinds that have some, a row each.
		counts := u.kindCounts()
		u.itemList.AddItem("[gray]Nothing here matches; in:[-]", "", 0, nil)
		for k, r := range svops.KindRows {
			if n := counts[k]; n > 0 {
				u.itemList.AddItem(fmt.Sprintf("  → %s (%d)", tview.Escape(r.Title), n), "", 0, func() { u.showKind(k) })
			}
		}
	case inKind == 0:
		u.itemList.AddItem("[gray]None yet: n makes one[-]", "", 0, nil)
	default:
		if len(u.shown) != inKind {
			title = fmt.Sprintf(" %s · %s · %d of %d ", kind, tview.Escape(u.vault), len(u.shown), inKind)
		}
		at := 0
		for n, i := range u.shown {
			e := u.entries[i]
			name := e.Item.Name
			text := tview.Escape(u.shownName(name))
			if len(e.Conflicts) > 0 {
				text += " [red]![-]"
			}
			u.itemList.AddItem(text, "", 0, func() { u.openItem(name, false) })
			if name == want {
				at = n
			}
		}
		u.itemList.SetCurrentItem(at)
		u.cursor = u.rowName(u.shown[at])
	}
	u.itemList.SetTitle(title)
}

// shownName is what the list shows an item as (svops.ShownNames).
func (u *UI) shownName(name string) string {
	if s, ok := u.names[name]; ok {
		return s
	}
	return name
}

// itemMoved follows the cursor in the item list.
func (u *UI) itemMoved(i int) {
	if !u.redraw && u.listed && i >= 0 && i < len(u.shown) {
		u.cursor = u.rowName(u.shown[i])
	}
}

// underCursor is the item under the item list's cursor, if any.
func (u *UI) underCursor() string {
	if i := u.itemList.GetCurrentItem(); u.listed && i >= 0 && i < len(u.shown) {
		return u.entries[u.shown[i]].Item.Name
	}
	return ""
}

// targetName is the item an action is about: the one under the cursor
// when the item list has the focus, else the open one.
func (u *UI) targetName() string {
	under := u.underCursor()
	switch {
	case u.app.GetFocus() == u.itemList && under != "":
		return under
	case u.cur != nil:
		return u.cur.Item.Name
	}
	return under
}

// openItem fetches an item with its fields and shows it.
func (u *UI) openItem(name string, reveal bool) {
	u.closeItem()
	gen, vault := u.itemGen, u.vault
	u.detail.reset("Opening " + tview.Escape(name) + "…")
	u.detail.SetTitle(" " + tview.Escape(name) + " ")
	var e svrpc.Entry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		if gen != u.itemGen || vault != u.vault {
			wipeItem(&e.Item)
			return
		}
		if err != nil {
			u.detail.reset("")
			u.detail.SetTitle(" Item ")
			u.fail(err)
			u.reloadVaults()
			return
		}
		// An item opened from elsewhere (one just saved, one brought
		// back) has its kind listed, where it is.
		if k := svops.KindRowOf(&e.Item); k >= 0 && k != u.kind {
			u.cursor = name
			u.showKind(k)
		}
		u.hold(&e, reveal)
		u.reloadVaults() // the open may have unlocked the vault
	})
}

// hold makes e the open item, and shows it.
func (u *UI) hold(e *svrpc.Entry, reveal bool) {
	u.cur, u.revealed = e, reveal
	u.otp = otpKeys(&e.Item)
	u.hasOTP.Store(len(u.otp) > 0)
	u.drawItem()
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

// closeItem leaves the open item, wiping its values.
func (u *UI) closeItem() {
	u.itemGen++
	if u.cur != nil {
		wipeItem(&u.cur.Item)
		u.cur = nil
	}
	for _, k := range u.otp {
		k.Wipe()
	}
	u.otp = nil
	u.hasOTP.Store(false)
	u.revealed = false
	u.detail.reset("Nothing open.\n\nEnter opens the item under the cursor;\n? lists every key.")
	u.detail.SetTitle(" Item ")
}

func (u *UI) drawItem() {
	if u.cur == nil {
		return
	}
	u.detail.setRows(itemRows(u.cur, u.revealed, u.otp, u.now()))
	u.detail.SetTitle(" " + tview.Escape(u.cur.Item.Name) + " ")
}

func wipeItem(it *svrpc.Item) { svops.Wipe(it) }

func (u *UI) toggleReveal() {
	name := u.targetName()
	switch {
	case name == "":
		u.say("Open an item first.")
	case u.cur == nil || u.cur.Item.Name != name:
		u.openItem(name, true)
	default:
		u.revealed = !u.revealed
		u.drawItem()
	}
}

// withItem runs fn on the target item: the open one, or else the one
// under the cursor, fetched for the purpose and wiped afterwards.
func (u *UI) withItem(fn func(e *svrpc.Entry)) {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	if u.cur != nil && u.cur.Item.Name == name {
		fn(u.cur)
		return
	}
	vault := u.vault
	var e svrpc.Entry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		defer wipeItem(&e.Item)
		if err != nil {
			u.fail(err)
			return
		}
		fn(&e)
	})
}

// copySecret copies the field selected in the open item, else the item's
// secret.
func (u *UI) copySecret() {
	selected := -1
	if u.app.GetFocus() == u.detail && u.cur != nil {
		selected = u.detail.selectedField()
	}
	u.withItem(func(e *svrpc.Entry) {
		if selected >= 0 && selected < len(e.Item.Fields) && e == u.cur {
			if svops.PasskeyHidden(&e.Item, e.Item.Fields[selected]) {
				u.say("A passkey's key is not copied.")
				return
			}
			u.copyValue(e.Item.Fields[selected].Value)
			return
		}
		f, ok := secretField(&e.Item)
		if !ok {
			u.say("%s has no secret to copy.", e.Item.Name)
			return
		}
		u.copyValue(f.Value)
	})
}

func (u *UI) copyUsername() {
	u.withItem(func(e *svrpc.Entry) {
		if f, ok := usernameField(&e.Item); ok {
			u.copyValue(f.Value)
			return
		}
		if name := e.Item.Attrs["username"]; name != "" {
			u.copyValue([]byte(name))
			return
		}
		u.say("%s has no username.", e.Item.Name)
	})
}

func (u *UI) copyCode() {
	u.withItem(func(e *svrpc.Entry) {
		for _, f := range e.Item.Fields {
			if f.Type != svcore.FieldOTP {
				continue
			}
			k, err := parseOTP(f.Value)
			if err != nil {
				u.fail(err)
				return
			}
			code, _ := k.Code(u.now())
			k.Wipe()
			u.copyValue([]byte(code))
			return
		}
		u.say("%s has no one-time password.", e.Item.Name)
	})
}

// copyValue puts a copy of v on the clipboard; v itself stays with its
// owner, who may wipe it at any time.
func (u *UI) copyValue(v []byte) {
	if len(v) == 0 {
		u.say("That field is empty.")
		return
	}
	secret := append([]byte(nil), v...)
	u.call(func(context.Context, *secretvault.Client) error {
		defer clear(secret)
		_, err := u.clip(secret, clipTTL)
		return err
	}, func(err error) {
		if err != nil {
			u.message = "[red]Could not copy: " + tview.Escape(err.Error()) + "[-]"
			u.drawStatus()
			return
		}
		u.say("Copied (clears in %ds)", int(clipTTL.Seconds()))
	})
}

// secretField is the item's primary secret (svops.SecretField).
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

func (u *UI) deleteItem() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	vault := u.vault
	u.confirm("Delete "+name+"?", svops.DeleteItemText(name, vault, "R"), svops.DeleteItemAction,
		func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.Delete(ctx, vault, name)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				if u.cur != nil && u.cur.Item.Name == name {
					u.closeItem()
				}
				u.say("Deleted %s", name)
				if vault == u.vault {
					u.loadItems()
				}
			})
		})
}

func (u *UI) renameItem() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	vault := u.vault
	u.askTo("Rename "+name, "New name:", name, "Rename", func(to string) {
		if to == name {
			return
		}
		if err := svcore.CheckName(to); err != nil {
			u.say("%s", svops.BadItemName(to))
			return
		}
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.Rename(ctx, vault, name, to)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Renamed %s to %s", name, to)
			if u.cur != nil && u.cur.Item.Name == name {
				u.openItem(to, false)
			}
			if vault == u.vault {
				u.loadItems()
			}
		})
	})
}

// lockVault locks the shown vault, or every vault.
func (u *UI) lockVault(all bool) {
	vault := u.vault
	if !all && vault == "" {
		return
	}
	// Clear first: nothing waits for the daemon to be sure.
	if all {
		for _, v := range u.vaults {
			u.vaultLocked(v.Name)
		}
	} else {
		u.vaultLocked(vault)
	}
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		return c.Lock(ctx, vault, all)
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		if all {
			u.say("Locked every vault")
		} else {
			u.say("Locked %s", vault)
		}
		u.reloadVaults()
	})
}

// unlockVault unlocks the vault under the cursor (in the vault list) or
// the shown one; the daemon asks for the passphrase.
func (u *UI) unlockVault() {
	vault := u.vault
	if u.app.GetFocus() == u.vaultList {
		if i := u.vaultUnderCursor(); i >= 0 {
			vault = u.vaults[i].Name
		}
	}
	if vault == "" {
		return
	}
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, nil)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			u.reloadVaults()
			return
		}
		u.say("Unlocked %s", vault)
		u.showVault(vault, true)
	})
}

// vaultLocked forgets everything shown from a vault that has locked:
// secrets are wiped from memory and cleared from the screen.
func (u *UI) vaultLocked(vault string) {
	if v := u.vaultInfo(vault); v != nil {
		v.Locked = true
	}
	// The panels showing what is in it (the contacts' vault may not be the
	// one shown), and any value resolved from a reference, go.
	for _, p := range u.panels {
		if p.vault == vault {
			p.close()
		}
	}
	if u.value != nil {
		u.wipeValue()
		u.closePage(pageInfo)
	}
	if vault != u.vault {
		u.drawVaults()
		return
	}
	u.closeItem()
	u.wipeHistory()
	u.closePage(pageRev)
	if u.pages.HasPage(pagePanel) && u.panels[pagePanel] == nil {
		u.closePage(pagePanel) // the history, the grants, the audit log
	}
	if u.editor != nil {
		u.editor.close()
		u.say("%s locked: the edit was discarded.", vault)
	}
	u.listGen++
	u.entries, u.names, u.shown, u.listed = nil, nil, nil, false
	u.drawVaults()
	u.drawItems()
	u.drawStatus()
}

// event handles the daemon's notifications. They come on the
// connection's goroutine, and in no particular order, so each one is
// checked against the daemon's own answer.
func (u *UI) event(method string, ev svrpc.VaultEvent) {
	u.post(func() {
		switch method {
		case svrpc.EVaultLocked:
			u.vaultLocked(ev.Vault)
			u.reloadVaults()
			u.refreshDisks() // its disks go from the list
		case svrpc.EVaultUnlocked:
			u.reloadVaults()
			u.refreshDisks()
		case svrpc.EEmergency:
			u.noteEmergency()
		case svrpc.EItemChanged:
			if ev.Vault != u.vault || !u.listed {
				return
			}
			u.loadItems()
			if u.cur != nil && u.cur.Item.Name == ev.Item && u.editor == nil {
				u.reopen()
			}
		}
	})
}

// reopen fetches the open item again, keeping it revealed or not.
func (u *UI) reopen() {
	if u.cur == nil {
		return
	}
	name, reveal := u.cur.Item.Name, u.revealed
	vault, gen := u.vault, u.itemGen
	var e svrpc.Entry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Get(ctx, vault, name)
		return err
	}, func(err error) {
		if gen != u.itemGen || vault != u.vault {
			wipeItem(&e.Item)
			return
		}
		if errors.Is(err, svrpc.ErrNotFound) {
			u.closeItem()
			u.say("%s was deleted.", name)
			return
		}
		if errors.Is(err, svrpc.ErrNoVault) {
			// The vault went (forgotten, or its folder moved), not the
			// item: say so, in the daemon's words.
			u.closeItem()
			u.fail(err)
			return
		}
		if err != nil {
			wipeItem(&e.Item)
			return
		}
		u.closeItem()
		u.hold(&e, reveal)
	})
}
