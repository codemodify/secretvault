package svmanager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Vaults: listing them, unlocking, locking, the default, making one, and
// the daemon's events about them.

// minPassphrase is the shortest new passphrase accepted, as everywhere
// else in secretvault.
const minPassphrase = 8

// start lists the vaults and shows the first one.
func (m *Manager) start() {
	var vs []svrpc.VaultInfo
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		vs, err = c.Vaults(ctx)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.vaults = vs
		name := m.opts.Vault
		if name == "" || m.vaultInfo(name) == nil {
			name = ""
			for _, v := range vs {
				if v.Default {
					name = v.Name
				}
			}
		}
		if name == "" && len(vs) > 0 {
			name = vs[0].Name
		}
		m.loadSyncs()
		m.loadEmergency()
		if name == "" {
			m.drawVaults()
			m.showNoVaults()
			m.drawStatus()
			return
		}
		m.showVault(name, false)
	})
}

func (m *Manager) vaultInfo(name string) *svrpc.VaultInfo {
	for i := range m.vaults {
		if m.vaults[i].Name == name {
			return &m.vaults[i]
		}
	}
	return nil
}

// reloadVaults asks the daemon for the vaults' states again. A vault it
// says is locked is cleared, even if its vault.locked event went astray;
// unless its items were listed since the question was asked, in which
// case the answer is out of date.
func (m *Manager) reloadVaults() {
	var vs []svrpc.VaultInfo
	lists := m.lists
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		vs, err = c.Vaults(ctx)
		return err
	}, func(err error) {
		if err != nil {
			return
		}
		m.vaults = vs
		m.drawVaults()
		v := m.vaultInfo(m.vault)
		switch {
		case v != nil && v.Locked && m.listed && lists == m.lists:
			m.vaultLocked(m.vault)
		case v != nil && !v.Locked && !m.listed && !m.listing:
			// Unlocked elsewhere: say so, and offer to list it.
			m.drawItems()
			if m.cur == nil && m.editor == nil && !m.showingVaultPage() && !m.showingHistory() {
				m.showSelected()
			}
		}
		m.drawStatus()
	})
}

// loadSyncs asks how the vaults that sync are doing.
func (m *Manager) loadSyncs() {
	var st []svrpc.SyncStatus
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.SyncStatus(ctx, "")
		return err
	}, func(err error) {
		if err != nil {
			return // a daemon that does not sync, or does not say
		}
		m.syncs = map[string]svrpc.SyncStatus{}
		for _, s := range st {
			m.syncs[s.Vault] = s
		}
		m.drawStatus()
	})
}

// syncLine is how a synced vault is doing, for its breadcrumb's tip.
func syncLine(s svrpc.SyncStatus) string {
	switch {
	case s.Error != "":
		return "; sync failing: " + s.Error
	case s.LastOK.IsZero():
		return "; not synced yet"
	}
	return "; synced " + s.LastOK.Local().Format("15:04")
}

// drawVaults fills the vault list, keeping the vault shown picked.
func (m *Manager) drawVaults() {
	m.ui.vaultList.set(m.vaults, m.vault)
	m.syncFace()
	m.enableMenus()
}

// vaultSelected shows the vault picked in the list.
func (m *Manager) vaultSelected(i int) {
	if i >= 0 && i < len(m.vaults) && m.vaults[i].Name != m.vault {
		m.showVault(m.vaults[i].Name, false)
	}
}

// unlocked, an open one's items take the keyboard.
func (m *Manager) vaultActivated(i int) {
	if i < 0 || i >= len(m.vaults) {
		return
	}
	v := m.vaults[i]
	if v.Name != m.vault {
		m.showVault(v.Name, false)
		if v.Name != m.vault {
			return // an edit is open
		}
	}
	switch {
	case v.Locked:
		m.unlockVault(v.Name)
		return
	case !m.listed && !m.listing:
		m.showVault(v.Name, true)
	}
	m.focus(m.ui.content)
}

// showVault shows a vault's items. A locked vault is listed only when
// unlock is set: listing it makes the daemon ask for its passphrase.
//
// Another vault is not shown while an edit is open: the edit is not
// thrown away for it. The vault shown changes before anything is taken
// down, so that nothing of the last one is drawn again while this one's
// items are fetched.
func (m *Manager) showVault(name string, unlock bool) {
	other := name != m.vault
	if other && m.editor != nil {
		m.say("Save or cancel the edit first.")
		m.drawVaults() // the selection goes back to the vault being edited
		return
	}
	m.vault = name
	m.listGen++
	m.listing = false
	m.entries, m.shown, m.listed = nil, nil, false
	if other {
		m.cursor, m.picked = "", nil
		m.leaveHistory()
		m.closeItem()
		m.vaultChanged()
	}
	// Its items asked for first, so that what is drawn knows they are on
	// their way (a closed vault's face waits for them, lockface.go).
	if v := m.vaultInfo(name); v == nil || !v.Locked || unlock {
		m.loadItems()
	}
	m.drawVaults()
	m.drawItems()
	if m.cur == nil && m.editor == nil && !m.showingVaultPage() && !m.showingHistory() {
		m.showSelected()
	}
	m.drawStatus()
}

// unlockVault unlocks a vault ("" for the one shown); the daemon asks for
// its passphrase, here.
func (m *Manager) unlockVault(vault string) {
	if vault == "" {
		vault = m.vault
	}
	if vault == "" {
		return
	}
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, nil)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		m.say("Unlocked %s.", vault)
		m.unlockedHere(vault)
		m.showVault(vault, true)
		m.focus(m.ui.content)
	})
}

// lockVault locks the vault shown, or every vault.
func (m *Manager) lockVault(all bool) {
	vault := m.vault
	if !all && vault == "" {
		return
	}
	// Clear first: nothing waits for the daemon to be sure.
	if all {
		for _, v := range m.vaults {
			m.vaultLocked(v.Name)
		}
	} else {
		m.vaultLocked(vault)
	}
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		return c.Lock(ctx, vault, all)
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		if all {
			m.say("Locked every vault.")
		} else {
			m.say("Locked %s.", vault)
		}
		m.reloadVaults()
	})
}

// makeDefault makes the vault shown the one programs use when they name
// none.
func (m *Manager) makeDefault() { m.makeDefaultOf(m.vault, nil) }

// makeDefaultOf makes vault the default, and then calls then.
func (m *Manager) makeDefaultOf(vault string, then func()) {
	if vault == "" {
		return
	}
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		return c.SetDefault(ctx, vault)
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.say("%s is the default vault now.", vault)
		m.reloadVaults()
		if then != nil {
			then()
		}
	})
}

// vaultLocked forgets everything shown from a vault that has locked:
// secrets are wiped from memory and taken off the screen at once, and a
// copy of one is taken back from the clipboard.
func (m *Manager) vaultLocked(vault string) {
	if v := m.vaultInfo(vault); v != nil {
		v.Locked = true
	}
	if m.copied != nil && m.copiedFrom == vault {
		m.copied.Clear()
		m.copied = nil
	}
	if vault != m.vault {
		m.drawVaults()
		return
	}
	m.closeItem()
	m.wipeHistory()
	if m.editor != nil {
		m.editor.close()
		m.say("%s locked: the edit was discarded.", vault)
	}
	m.closeVaultPage()
	m.listGen++
	m.listing = false
	m.entries, m.shown, m.listed = nil, nil, false
	m.drawVaults()
	m.drawItems()
	m.showSelected() // which says it is locked, or that the daemon has gone
	m.drawStatus()
}

// event handles the daemon's notifications. They come on the connection's
// goroutine, and in no particular order, so each one is checked against
// the daemon's own answer.
func (m *Manager) event(method string, ev svrpc.VaultEvent) {
	m.post(func() {
		switch method {
		case svrpc.EVaultLocked:
			m.vaultLocked(ev.Vault)
			m.reloadVaults()
			m.refreshDisks(m.disks)
		case svrpc.EVaultUnlocked:
			m.reloadVaults()
			m.refreshDisks(m.disks)
		case svrpc.EEmergency:
			m.loadEmergency()
			if p := m.vpage; p != nil && p.vault == ev.Vault {
				m.refreshTab(p, tabSharing)
			}
		case svrpc.EItemChanged:
			if ev.Vault != m.vault || !m.listed {
				return
			}
			m.loadItems()
			if m.cur != nil && m.cur.Item.Name == ev.Item && m.editor == nil {
				m.reopen()
			}
		}
	})
}

// newVault asks for a new vault's name, cipher suite and passphrase, and
// makes it.
func (m *Manager) newVault() {
	if m.gone {
		m.fail(errGone)
		return
	}
	name := widgets.NewTextField("", "personal, work…", nil)
	name.SetAccessibleName("Name")
	suites := make([]string, len(svops.VaultSuites))
	for i, s := range svops.VaultSuites {
		suites[i] = s.Text
	}
	suite := widgets.NewComboBox(suites, 0, nil)
	suite.SetAccessibleName(svops.SuiteLabel)
	pass := widgets.NewSecretField("At least 8 characters")
	again := widgets.NewSecretField("The same again")
	folder := newPathField(m, "Folder", PickFolder, "")
	recovery := widgets.NewCheckbox("Make a recovery key, shown once", true, nil)
	problem := toned("", widgets.ToneDanger)
	problem.Wrap = true

	form := widgets.NewForm()
	form.AddRow("Name", name)
	form.AddRow(svops.SuiteLabel, suite)
	form.AddRow("Passphrase", pass)
	form.AddRow("Repeat", again)
	form.AddRow("Folder", folder.row)
	body := widgets.NewColumn(m.paragraph(svops.NewVaultIntro), form,
		m.paragraph("Folder: leave it empty to keep the vault in secretvault's data folder, or choose one of your own (a synced folder, say)."),
		widgets.NewTip("A key to write down, which opens the vault if the passphrase is lost", recovery),
		problem).WithGap(gap)

	var d *dialog
	create := newButton(svops.CreateVaultAction, nil)
	create.OnClick = func() {
		n := strings.TrimSpace(name.Text)
		switch {
		case n == "" || strings.ContainsAny(n, "/\\"):
			problem.SetText("Give the vault a name, without slashes.")
			return
		case m.vaultInfo(n) != nil:
			problem.SetText("There is a vault called " + n + " already.")
			return
		case pass.Len() < minPassphrase:
			problem.SetText(fmt.Sprintf("Use a passphrase of at least %d characters.", minPassphrase))
			return
		}
		p, a := pass.Bytes(), again.Bytes()
		same := bytes.Equal(p, a)
		clear(a)
		if !same {
			clear(p)
			pass.Wipe()
			again.Wipe()
			problem.SetText("The two passphrases differ.")
			m.focus(pass)
			return
		}
		dir, err := absPath(folder.Path())
		if err != nil {
			clear(p)
			problem.SetText(sentence(err.Error()))
			return
		}
		params := svrpc.VaultCreateParams{Name: n, Path: dir, Suite: svops.VaultSuites[max(0, suite.Selected)].Name, Passphrase: p, Recovery: recovery.Checked}
		d.Close()
		var res svrpc.VaultCreateResult
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.CreateVault(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Created vault %s.", res.Vault.Name)
			m.reloadVaults()
			m.showVault(res.Vault.Name, true)
			if res.RecoveryKey != "" {
				m.showRecoveryKey(res.Vault.Name, []byte(res.RecoveryKey))
			}
		}, params.Passphrase)
	}
	pass.OnSubmit = func(*widgets.SecretField) { m.focus(again) }
	again.OnSubmit = func(*widgets.SecretField) { create.OnClick() }
	buttons := widgets.NewButtonBox().
		AddButton(create, widgets.RoleAccept).
		AddButton(newButton("Cancel", func() { d.Close() }), widgets.RoleReject)
	// A passphrase made with Caps Lock on would open the vault only with
	// Caps Lock on: said beside the buttons while it is.
	row := widgets.NewRow(secretui.NewCapsLock(), buttons).WithGap(16).WithAlign(layout.AlignCenter)
	row.AddFlex(buttons, 1)
	d = m.showDialog("New vault", body, row, name, func() {
		pass.Wipe()
		again.Wipe()
	})
}

// showRecoveryKey shows a new vault's recovery key, once. It is kept
// nowhere, here or in the daemon; key is wiped when the dialog closes,
// and so when the program quits. It goes over whatever dialog is up,
// which is there as it was once the key has been written down.
//
// The daemon's answer carried it as a string (svrpc.VaultCreateResult),
// which cannot be wiped: that copy lasts until the collector takes it.
func (m *Manager) showRecoveryKey(vault string, key []byte) {
	text := newSecretText(key)
	text.SetReveal(true)
	text.SetAccessibleName("Recovery key")
	note := widgets.NewLabel(svops.RecoveryKeyNote(vault))
	note.Wrap = true
	body := widgets.NewColumn(note, text).WithGap(12)
	var d *dialog
	copyBtn := newButton("Copy the key", func() { m.copyValue(key, "The recovery key", vault) })
	done := newButton("I have written it down", func() { d.Close() })
	buttons := widgets.NewButtonBox().
		AddButton(done, widgets.RoleAccept).
		AddButton(copyBtn, widgets.RoleAction)
	d = m.showDialog("Recovery key for "+vault, body, buttons, done, func() {
		text.Forget()
		clear(key)
	})
}

// showKeys shows the keyboard shortcuts, in Settings.
func (m *Manager) showKeys() { m.showSettings(tabSetShortcuts) }

// fillShortcuts lists the keyboard shortcuts.
func (m *Manager) fillShortcuts(pn *pane) {
	rows := [][2]string{
		{"Ctrl+F", "filter the items, in every tab; Down goes to them"},
		{"Enter", "open the item, or unlock the vault"},
		{"Ctrl+C", "copy the item's password"},
		{"Ctrl+B, Ctrl+T", "copy its username, its one-time code"},
		{"Ctrl+Shift+C", "copy the password, then minimise"},
		{"Ctrl+R", "show or hide concealed values"},
		{"Ctrl+N, Ctrl+E", "a new item; edit the item"},
		{"F2, Delete", "rename, delete the item (asks first)"},
		{"Ctrl+H", "the item's history"},
		{"Ctrl+G", "the password generator"},
		{"Ctrl+U, Ctrl+L", "unlock, lock the vault"},
		{"Ctrl+Shift+L", "lock every vault"},
		{"Ctrl+Shift+G", "the vault's grants"},
		{"Ctrl+Shift+K", "the contacts"},
		{"Escape", "from a page back to the items"},
		{"Ctrl+1, 2, 3", "Vault, Disk, Tools (on the back, Settings' tabs)"},
		{"Ctrl+Page Down, Up", "the next, the previous of Vault, Disk and Tools"},
		{"Ctrl+W, Ctrl+Q", "close the window (to the tray), quit"},
	}
	g := widgets.NewGrid()
	g.ColGap, g.RowGap = 16, 0
	for i, r := range rows {
		k := widgets.NewLabel(r[0])
		k.Mono = true
		g.Place(k, i, 0)
		g.Place(widgets.NewLabel(r[1]), i, 1)
	}
	note := m.muted(fmt.Sprintf("Copies clear themselves from the clipboard after %d seconds.", int(m.ttl/time.Second)))
	pn.focus = nil
	pn.box.Set(scrolled(widgets.NewColumn(g, note).WithGap(12)))
}

// checkName is svcore.CheckName, said as a person would.
func checkName(name string) error {
	if err := svcore.CheckName(name); err != nil {
		return errors.New(svops.BadItemName(name))
	}
	return nil
}
