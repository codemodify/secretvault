package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
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

// syncLine is how a synced vault is doing, for the status bar.
func syncLine(s svrpc.SyncStatus) string {
	switch {
	case s.Error != "":
		return "; sync failing: " + s.Error
	case s.LastOK.IsZero():
		return "; syncs, not yet in step"
	}
	return "; synced " + s.LastOK.Local().Format("15:04")
}

// drawVaults fills the vault list, keeping the vault shown selected.
func (m *Manager) drawVaults() {
	t := m.ui.vaultList
	t.RowCount = len(m.vaults)
	t.Selected = -1
	for i, v := range m.vaults {
		if v.Name == m.vault {
			t.Selected = i
		}
	}
	t.Invalidate()
	m.enableMenus()
}

func (m *Manager) vaultCell(row, col int) string {
	if row < 0 || row >= len(m.vaults) {
		return ""
	}
	v := m.vaults[row]
	if col == 0 {
		return v.Name
	}
	switch {
	case v.ID == "":
		return "missing"
	case v.Locked:
		return "locked"
	}
	return "unlocked"
}

// vaultIcon marks the default vault with a star.
func (m *Manager) vaultIcon(row, col int) (style.ToolIcon, paintengine2d.Color) {
	if col == 0 && row >= 0 && row < len(m.vaults) && m.vaults[row].Default {
		return style.IconStar, paintengine2d.Color{}
	}
	return style.IconNone, paintengine2d.Color{}
}

func (m *Manager) vaultSelected(i int) {
	if i >= 0 && i < len(m.vaults) && m.vaults[i].Name != m.vault {
		m.showVault(m.vaults[i].Name, false)
	}
}

// vaultActivated is Enter or a double click on a vault: a locked one is
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
	m.win.RequestFocus(m.ui.items)
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
		m.folder, m.cursor = "", ""
		m.closeVaultPage()
		m.leaveHistory()
		m.closeItem()
	}
	m.drawVaults()
	m.drawFolders()
	if v := m.vaultInfo(name); v == nil || !v.Locked || unlock {
		m.loadItems()
	}
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
		m.showVault(vault, true)
		m.win.RequestFocus(m.ui.items)
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
func (m *Manager) makeDefault() {
	vault := m.vault
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
	m.drawFolders()
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
		case svrpc.EVaultUnlocked:
			m.reloadVaults()
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
	suites := []string{"sv1-modern", "sv1-nist"}
	suite := widgets.NewComboBox([]string{
		"sv1-modern: XChaCha20-Poly1305, Argon2id",
		"sv1-nist: AES-256-GCM, PBKDF2 (FIPS 140-3)",
	}, 0, nil)
	suite.SetAccessibleName("Cipher suite")
	pass := widgets.NewSecretField("At least 8 characters")
	again := widgets.NewSecretField("The same again")
	recovery := widgets.NewCheckbox("Make a recovery key, shown once", true, nil)
	problem := toned("", toneDanger)
	problem.Wrap = true

	form := widgets.NewForm()
	form.AddRow("Name", name)
	form.AddRow("Cipher suite", suite)
	form.AddRow("Passphrase", pass)
	form.AddRow("Repeat", again)
	body := widgets.NewColumn(form,
		widgets.NewTip("A key to write down, which opens the vault if the passphrase is lost", recovery),
		problem).WithGap(gap)

	var d *dialog
	create := widgets.NewButton("Create", nil)
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
			m.win.RequestFocus(pass)
			return
		}
		params := svrpc.VaultCreateParams{Name: n, Suite: suites[max(0, suite.Selected)], Passphrase: p, Recovery: recovery.Checked}
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
	pass.OnSubmit = func(*widgets.SecretField) { m.win.RequestFocus(again) }
	again.OnSubmit = func(*widgets.SecretField) { create.OnClick() }
	buttons := widgets.NewButtonBox().
		AddButton(create, widgets.RoleAccept).
		AddButton(widgets.NewButton("Cancel", func() { d.Close() }), widgets.RoleReject)
	d = m.showDialog("New vault", body, buttons, name, func() {
		pass.Wipe()
		again.Wipe()
	})
}

// showRecoveryKey shows a new vault's recovery key, once. It is kept
// nowhere, here or in the daemon; key is wiped when the dialog closes.
// A window has one dialog at a time, and showing another takes the one up
// down: so the key waits for whatever dialog is up to be done with,
// rather than take it down (or be taken down, and wiped, unread).
//
// The daemon's answer carried it as a string (svrpc.VaultCreateResult),
// which cannot be wiped: that copy lasts until the collector takes it.
func (m *Manager) showRecoveryKey(vault string, key []byte) {
	m.whenNoDialog(func() { m.recoveryKeyDialog(vault, key) }, func() { clear(key) })
}

func (m *Manager) recoveryKeyDialog(vault string, key []byte) {
	text := newSecretText(key)
	text.SetReveal(true)
	text.SetAccessibleName("Recovery key")
	note := widgets.NewLabel("Write this recovery key down and keep it somewhere safe. It opens vault " + vault +
		" if the passphrase is lost, and it is shown only now: it is stored nowhere.")
	note.Wrap = true
	body := widgets.NewColumn(note, text).WithGap(12)
	var d *dialog
	copyBtn := widgets.NewButton("Copy", func() { m.copyValue(key, "The recovery key", vault) })
	done := widgets.NewButton("I have written it down", func() { d.Close() })
	buttons := widgets.NewButtonBox().
		AddButton(done, widgets.RoleAccept).
		AddButton(copyBtn, widgets.RoleAction)
	d = m.showDialog("Recovery key for "+vault, body, buttons, done, func() {
		text.Forget()
		clear(key)
	})
}

// showKeys lists the keyboard shortcuts.
func (m *Manager) showKeys() {
	rows := [][2]string{
		{"Ctrl+F", "search the items (Down goes to the results)"},
		{"Enter", "open the item, or unlock the vault, selected"},
		{"Ctrl+C", "copy the item's password"},
		{"Ctrl+B, Ctrl+T", "copy its username, its one-time code"},
		{"Ctrl+Shift+C", "copy the password and minimise the window"},
		{"Ctrl+R", "show or hide the item's concealed values"},
		{"Ctrl+N, Ctrl+E", "a new item; edit the item"},
		{"F2, Delete", "rename, delete the item (asks first)"},
		{"Ctrl+H", "the item's history"},
		{"Ctrl+G", "the password generator"},
		{"Ctrl+U, Ctrl+L", "unlock, lock the vault"},
		{"Ctrl+Shift+L", "lock every vault"},
		{"Ctrl+Shift+G", "the vault's grants and audit log"},
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
	var d *dialog
	ok := widgets.NewButton("Close", func() { d.Close() })
	d = m.showDialog("Keys", widgets.NewColumn(g, note).WithGap(12), widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, nil)
}

// checkName is svcore.CheckName, said as a person would.
func checkName(name string) error {
	if err := svcore.CheckName(name); err != nil {
		return fmt.Errorf("%q is not a usable name: use path segments, like web/example.com", name)
	}
	return nil
}
