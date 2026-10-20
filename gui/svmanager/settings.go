package svmanager

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// A vault's settings (where it is, when it locks, whether it opens at
// login), checking every file of it, forgetting it; adding a vault folder
// that is already somewhere; unlocking with a key other than the
// passphrase; and what the daemon says of itself.

func (m *Manager) fillSettings(p *vaultPage, pn *pane) {
	var vs []svrpc.VaultInfo
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		vs, err = c.Vaults(ctx)
		return err
	}, func() widget.Component {
		m.vaults = vs
		m.drawVaults()
		v := m.vaultInfo(p.vault)
		if v == nil {
			return m.paragraph("Vault " + p.vault + " is no longer in the list here: Vault › Add an existing vault… brings it back.")
		}
		info := *v
		p.info = &info
		return m.drawSettings(p, pn, info)
	})
}

// lockText says when a vault locks, as the CLI's vault list does.
func lockText(v svrpc.VaultInfo) string {
	switch {
	case v.LoginUnlock:
		return "when you log out"
	case v.AutoLock.IdleMinutes > 0:
		var also []string
		if v.AutoLock.OnScreenLock {
			also = append(also, "when the screen locks")
		}
		if v.AutoLock.OnSleep {
			also = append(also, "on sleep")
		}
		s := fmt.Sprintf("after %d idle minutes", v.AutoLock.IdleMinutes)
		if len(also) > 0 {
			s += ", " + strings.Join(also, " and ")
		}
		return s
	case v.AutoLock.OnScreenLock || v.AutoLock.OnSleep:
		return "when the screen locks or the computer sleeps"
	}
	return "never by itself"
}

func (m *Manager) drawSettings(p *vaultPage, pn *pane, v svrpc.VaultInfo) widget.Component {
	state := "unlocked"
	switch {
	case v.ID == "":
		state = "missing: its folder is not there"
	case v.Locked:
		state = "locked"
	}
	def := "no"
	if v.Default {
		def = "yes: programs that name no vault use it"
	}
	rows := [][2]string{
		{"Name", v.Name},
		{"State", state},
		{"Folder", v.Path},
		{"ID", v.ID},
		{svops.SuiteLabel, svops.SuiteText(v.Suite)},
		{"Default", def},
		{"Locks", lockText(v)},
	}
	if !v.Created.IsZero() {
		rows = append(rows, [2]string{"Created", v.Created.Local().Format("2006-01-02 15:04")})
	}
	col := widgets.NewColumn(m.facts(rows)).WithGap(gap).WithPad(gap)
	login := widgets.NewCheckbox("Open when I log in", v.LoginUnlock, nil)
	login.OnInput = func(on bool) {
		if !on {
			m.setLoginUnlock(p, false, login)
			return
		}
		// It weakens the vault: asked first, as removing a keyslot is.
		login.Checked = false
		login.Invalidate()
		m.showPlan(svops.LoginUnlockPlain(p.vault), func() {
			login.Checked = true
			login.Invalidate()
			m.setLoginUnlock(p, true, login)
		}, nil)
	}
	col.Add(widgets.NewTip("With a key the system keeps for you; it locks when you log out. Programs still ask before they read it.", login))
	verify := newButton("Check every file…", func() { m.verifyVault(p) })
	pn.focus = verify
	def2 := newButton("Make it the default", func() { m.makeDefaultOf(p.vault, func() { m.refreshTab(p, tabSettings) }) })
	def2.SetEnabled(!v.Default)
	col.Add(buttons(verify, def2, newButton("Forget this vault…", func() { m.forgetVault(p) })))
	// Its items, all at once, to another vault (the CLI's mv --all).
	col.Add(buttons(newButton("Move every item to vault…", func() { m.moveAll(p.vault, false) }),
		newButton("Copy every item to vault…", func() { m.moveAll(p.vault, true) })))
	return scrolled(col)
}

// setLoginUnlock has the vault open at login, or not (the CLI's vault
// login).
func (m *Manager) setLoginUnlock(p *vaultPage, on bool, box *widgets.Checkbox) {
	var v svrpc.VaultInfo
	box.SetEnabled(false) // one change at a time
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		v, err = c.SetLoginUnlock(ctx, p.vault, on)
		return err
	}, func(err error) {
		box.SetEnabled(true)
		if err != nil {
			box.Checked = !on
			box.Invalidate()
			m.fail(err)
			return
		}
		if v.LoginUnlock {
			m.say("Vault %s opens when you log in, and locks when you log out.", v.Name)
		} else {
			m.say("Vault %s no longer opens at login; it locks %s.", v.Name, lockText(v))
		}
		m.refreshTab(p, tabSettings)
	})
}

// verifyVault re-authenticates every file of the vault (the CLI's
// verify), and says what it found.
func (m *Manager) verifyVault(p *vaultPage) {
	var rep svrpc.VerifyResult
	m.say("Checking every file of %s…", p.vault)
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		rep, err = c.Verify(ctx, p.vault)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		title, summary, details, ok := svops.VerifyReport(p.vault, rep)
		m.say("%s", svops.VerifyStatus(p.vault, ok))
		m.showDone(title, summary, details)
	})
}

// forgetVault unregisters the vault, leaving its folder as it is (the
// CLI's vault forget).
func (m *Manager) forgetVault(p *vaultPage) {
	text := svops.ForgetVaultText(p.vault) + " Vault › Add an existing vault… brings it back."
	if p.info != nil && p.info.Path != "" {
		text += "\n\nIts folder: " + p.info.Path
	}
	m.confirm(svops.ForgetVaultTitle(p.vault), text, svops.ForgetVaultAction, func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.ForgetVault(ctx, p.vault)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Forgot vault %s; its folder is still there.", p.vault)
			m.closeVaultPage()
			m.vault = ""
			m.start()
		})
	})
}

// addVaultFolder registers a vault folder that is already somewhere (a
// synced folder, a backup) under a name (the CLI's vault add).
func (m *Manager) addVaultFolder() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm(svops.AddVaultTitle)
	f.intro(svops.AddVaultIntro)
	folder := f.path("Its folder", PickFolder, "")
	name := f.text("Name it", "", "personal, work…")
	f.show(svops.AddVaultAction, func() {
		dir, n := folder.Path(), strings.TrimSpace(name.Text)
		switch {
		case dir == "":
			f.fail("Choose the vault's folder.")
			return
		case n == "" || strings.ContainsAny(n, "/\\"):
			f.fail("Give the vault a name, without slashes.")
			return
		case m.vaultInfo(n) != nil:
			f.fail("There is a vault called " + n + " already.")
			return
		}
		var v svrpc.VaultInfo
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return err
			}
			v, err = c.AddVault(ctx, n, abs)
			return err
		}, func() {
			m.say("Added vault %s.", v.Name)
			m.reloadVaults()
			m.showVault(v.Name, false)
		})
	})
}

// absPath is path made absolute, or "" for "".
func absPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	return filepath.Abs(path)
}

// unlockKinds are the keys Unlock with… offers, as svrpc.Key names them.
var unlockKinds = []struct{ typ, text string }{
	{svformat.SlotPassphrase, "The passphrase (asked for in its own window)"},
	{svformat.SlotRecovery, svops.UnlockKindText[svformat.SlotRecovery]},
	{"shares", svops.UnlockKindText["shares"]},
	{svformat.SlotKeyfile, svops.UnlockKindText[svformat.SlotKeyfile]},
	{"identity", svops.UnlockKindText["identity"]},
	{svformat.SlotFIDO2, svops.UnlockKindText[svformat.SlotFIDO2]},
}

// unlockWith unlocks the vault shown with a key presented up front, as
// the CLI's unlock flags do: a recovery key, recovery shares, a keyfile,
// an identity file or a security key.
func (m *Manager) unlockWith() {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	f := m.newForm("Unlock " + vault + " with…")
	kinds := make([]string, len(unlockKinds))
	for i, k := range unlockKinds {
		kinds[i] = k.text
	}
	kind := widgets.NewRadioGroup(kinds, 1, nil)
	kind.SetAccessibleName("Open it with")
	f.row("Open it with", kind)
	f.show("Next", func() {
		typ := unlockKinds[max(0, kind.Selected())].typ
		f.close()
		switch typ {
		case svformat.SlotPassphrase:
			m.unlockVault(vault)
		case svformat.SlotFIDO2:
			m.presentKey(vault, &svrpc.Key{Type: svformat.SlotFIDO2})
		case "shares":
			m.unlockWithShares(vault)
		case svformat.SlotRecovery:
			g := m.newForm("Unlock " + vault + " with its recovery key")
			rk := g.secret("Recovery key", "")
			g.show("Unlock", func() {
				if rk.Empty() {
					g.fail("Type the recovery key.")
					return
				}
				key := &svrpc.Key{Type: svformat.SlotRecovery, Secret: rk.Bytes()}
				g.call(func(ctx context.Context, c *secretvault.Client) error {
					_, err := c.Unlock(ctx, vault, key)
					return err
				}, func() { m.unlocked(vault) }, key.Secret)
			})
		default: // a keyfile, or an identity file
			what := "Keyfile"
			if typ == "identity" {
				what = "Identity file"
			}
			g := m.newForm("Unlock " + vault + " with a " + strings.ToLower(what))
			path := g.path(what, PickOpen, "")
			g.show("Unlock", func() {
				file := path.Path()
				if file == "" {
					g.fail("Choose the file.")
					return
				}
				g.call(func(ctx context.Context, c *secretvault.Client) error {
					b, err := readFile(file)
					if err != nil {
						return err
					}
					defer clear(b)
					_, err = c.Unlock(ctx, vault, &svrpc.Key{Type: typ, Secret: b})
					return err
				}, func() { m.unlocked(vault) })
			})
		}
	})
}

// presentKey unlocks with a key that needs nothing typed here.
func (m *Manager) presentKey(vault string, key *svrpc.Key) {
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, key)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		m.unlocked(vault)
	})
}

// unlocked shows a vault just unlocked.
func (m *Manager) unlocked(vault string) {
	m.say("Unlocked %s.", vault)
	m.unlockedHere(vault)
	m.showVault(vault, true)
	m.focus(m.ui.content)
}

// unlockWithShares takes recovery shares one at a time, as they are typed
// (svops.ShareCollector), until there are as many as the first says it
// takes, and unlocks with the key they rebuild.
func (m *Manager) unlockWithShares(vault string) {
	shares := &svops.ShareCollector{}
	f := m.newForm("Unlock " + vault + " with recovery shares")
	share := f.secret("Share 1", "")
	count := f.note(svops.SharesIntro)
	f.onClose(shares.Wipe)
	f.failed = func() {
		// The shares did not open it: they are typed again, from the
		// first.
		shares.Wipe()
		*shares = svops.ShareCollector{}
		count.SetText(svops.SharesIntro)
	}
	f.show("Add the share", nil)
	f.accept.OnClick = func() {
		if share.Empty() {
			f.fail("Type a share.")
			return
		}
		b := share.Bytes()
		err := shares.Add(b)
		clear(b)
		share.Wipe()
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		f.fail("")
		if !shares.Done() {
			count.SetText(fmt.Sprintf("%d of %d shares typed.", shares.Have(), shares.Need()))
			f.form.Invalidate()
			m.focus(share)
			return
		}
		rk, err := shares.Key()
		if err != nil {
			shares.Wipe()
			*shares = svops.ShareCollector{}
			count.SetText(svops.SharesIntro)
			f.fail(sentence(err.Error()))
			return
		}
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.Unlock(ctx, vault, &svrpc.Key{Type: svformat.SlotRecovery, Secret: rk})
			return err
		}, func() { m.unlocked(vault) }, rk)
	}
	share.OnSubmit = func(*widgets.SecretField) { f.accept.OnClick() }
}

// showAbout shows About secretvault, in Settings.
func (m *Manager) showAbout() { m.showSettings(tabSetAbout) }

// fillAbout says what the daemon says of itself (the CLI's status and
// version): its version, where it keeps its data, how it asks, whether it
// is the keyring, its SSH and gpg agents, emergency requests, and the
// vaults, where they are and when they lock.
func (m *Manager) fillAbout(pn *pane) {
	if m.gone {
		pn.box.Set(m.message("About secretvault", "secretvault "+secretvault.Version+". "+svops.DaemonNotRunning))
		return
	}
	var st svrpc.Status
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.Status(ctx)
		return err
	}, func() widget.Component {
		rows := [][2]string{
			{"This program", "secretvault-gui " + secretvault.Version},
			{"secretvaultd", fmt.Sprintf("%s, process %d", st.Version, st.PID)},
			{"Data", st.Home},
		}
		if st.Mode == "host" {
			rows = append(rows, [2]string{"Mode", "the host daemon (Tools › Host daemon)"})
		}
		if st.Socket != "" {
			rows = append(rows, [2]string{"Socket", st.Socket})
		}
		rows = append(rows, [2]string{"Prompts", st.Prompts}, [2]string{"Keyring", st.SecretService})
		if st.SSHAgent != "" {
			rows = append(rows, [2]string{"SSH agent", st.SSHAgent + " (SSH_AUTH_SOCK)"})
		}
		if st.GPGAgent != "" {
			homes := "no GnuPG folder uses it yet: Tools › GnuPG"
			if len(st.GnuPGHomes) > 0 {
				homes = "for " + strings.Join(st.GnuPGHomes, ", ")
			}
			rows = append(rows, [2]string{"gpg agent", st.GPGAgent + " (" + homes + ")"})
		}
		col := widgets.NewColumn(m.facts(rows)).WithGap(12)
		if len(st.Emergency) > 0 {
			col.Add(section(m, "Emergency access"))
			for _, n := range st.Emergency {
				l := toned(guiWords(n.Text), widgets.ToneWarning)
				l.Wrap = true
				col.Add(l)
			}
		}
		col.Add(section(m, "Vaults"))
		if len(st.Vaults) == 0 {
			col.Add(m.paragraph("No vaults yet: Vault › New vault… makes one."))
		} else {
			vs := st.Vaults
			t := table("Vaults", []widgets.TableColumn{
				{Title: "Vault", Width: 110}, {Title: "State", Width: 80}, {Title: "Locks", Width: 150}, {Title: "Folder"},
			}, len(vs), func(r, c int) string {
				v := vs[r]
				switch c {
				case 0:
					if v.Default {
						return v.Name + " *"
					}
					return v.Name
				case 1:
					switch {
					case v.ID == "":
						return "missing"
					case v.Locked:
						return "locked"
					}
					return "unlocked"
				case 2:
					return lockText(v)
				}
				return v.Path
			})
			col.Add(widgets.NewHeightBox(min(40+28*float32(len(vs)), 200), t))
		}
		return scrolled(widgets.NewColumn(m.paragraph("The versions of secretvault, the background service and what it serves, and every vault."), col).WithGap(gap))
	})
}
