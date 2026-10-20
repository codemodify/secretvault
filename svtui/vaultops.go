package svtui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Vaults: making one (N), the vaults panel (V: every vault, its path and
// when it locks; the default; forgetting; opening at login; verifying),
// unlocking with another key, and the daemon's status.

// newVault is 'secretvault init': a name, a folder of one's own if
// wanted, the suite, the passphrase, and a recovery key shown once.
func (u *UI) newVault() {
	f := u.newForm("New vault", svops.NewVaultIntro)
	name := f.text("Name", "", "default")
	dir := f.path("Folder", "", svops.VaultFolderPlaceholder+" (or choose one: a synced folder, say)")
	suites := make([]string, len(svops.VaultSuites))
	for i, s := range svops.VaultSuites {
		suites[i] = s.Text
	}
	suite := f.choice(svops.SuiteLabel, suites, 0)
	pass := f.secret("Passphrase")
	again := f.secret("Repeat it")
	recovery := f.check("Make a recovery key", false)
	f.show(svops.CreateVaultAction, func() string {
		si, _ := suite.GetCurrentOption()
		p := svrpc.VaultCreateParams{Name: trimmed(name), Suite: svops.VaultSuites[max(0, si)].Name, Recovery: recovery.IsChecked()}
		if p.Name == "" {
			p.Name = "default"
		}
		if d := filePath(dir); d != "" {
			abs, err := filepath.Abs(d)
			if err != nil {
				return err.Error()
			}
			p.Path = abs
		}
		if problem := newPassphraseProblem(pass, again); problem != "" {
			return problem
		}
		p.Passphrase = pass.value()
		var res svrpc.VaultCreateResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(p.Passphrase)
			if res, err = c.CreateVault(ctx, p); err != nil {
				return err
			}
			// Presenting the passphrase just chosen proves to the daemon
			// that this terminal may use the vault, so it is not asked for
			// again at once.
			_, err = c.Unlock(ctx, res.Vault.Name, &svrpc.Key{Type: svformat.SlotPassphrase, Secret: p.Passphrase})
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Created vault %s", res.Vault.Name)
			u.afterVaultsChange(res.Vault.Name)
			if res.RecoveryKey != "" {
				u.showRecoveryKey(res.Vault.Name, res.RecoveryKey)
			}
		})
		return ""
	})
}

// newPassphraseProblem checks a new passphrase typed twice, as the
// daemon's prompt does.
func newPassphraseProblem(pass, again *secretInput) string {
	switch {
	case len(pass.buf) < minPassphrase:
		return fmt.Sprintf("Use at least %d characters for the passphrase.", minPassphrase)
	case string(pass.buf) != string(again.buf):
		return "The two passphrases differ."
	}
	return ""
}

// showRecoveryKey shows vault's new recovery key, once.
func (u *UI) showRecoveryKey(vault, rk string) {
	u.showOnce("Recovery key for "+vault, []onceLine{
		{text: svops.RecoveryKeyNote(vault)},
		{},
		{secret: []byte(rk)},
		{},
		{text: "To open the vault with it: Unlock with… › " + svops.UnlockKindText[svformat.SlotRecovery] + "."},
	}, nil)
}

// afterVaultsChange lists the vaults again, and shows name ("" to keep
// the one shown, or the first there is).
func (u *UI) afterVaultsChange(name string) {
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
		if name == "" && u.vaultInfo(u.vault) != nil {
			name = u.vault
		}
		if name == "" {
			for _, v := range vs {
				if v.Default || name == "" {
					name = v.Name
				}
			}
		}
		for i, v := range vs {
			if v.Name == name {
				u.cursorOnVault(i)
			}
		}
		if name == "" {
			u.vault = ""
			u.closeItem()
			u.entries, u.names, u.shown, u.listed = nil, nil, nil, false
			u.drawVaults()
			u.drawItems()
			u.detail.reset("There are no vaults yet.\n\nN makes one.")
			u.drawStatus()
			return
		}
		u.showVault(name, false)
		if p := u.panels[pagePanel]; p != nil && p.title == "Vaults" {
			p.refresh()
		}
	})
}

// addVault is 'secretvault vault add NAME DIR'.
func (u *UI) addVault() {
	f := u.newForm(svops.AddVaultTitle, svops.AddVaultIntro)
	name := f.text("Name it", "", "personal, work…")
	dir := f.path("Its folder", "", "the vault's folder")
	f.show(svops.AddVaultAction, func() string {
		n, d := trimmed(name), filePath(dir)
		if n == "" || d == "" {
			return "Give the vault a name, and its folder."
		}
		abs, err := filepath.Abs(d)
		if err != nil {
			return err.Error()
		}
		var v svrpc.VaultInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			v, err = c.AddVault(ctx, n, abs)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Added vault %s", v.Name)
			u.afterVaultsChange(v.Name)
		})
		return ""
	})
}

// showVaults is the vaults panel: 'secretvault vault list', with what can
// be done to each.
func (u *UI) showVaults() {
	p := u.newPanel("Vaults", "NAME", "STATE", "LOCKS", "PATH")
	p.reload = func() {
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
			u.drawVaults()
			p.clear()
			if len(vs) == 0 {
				p.none("None yet (n makes one).")
			}
			for _, v := range vs {
				name := v.Name
				if v.Default {
					name += " *"
				}
				p.row(v, name, vaultState(v), lockText(v), v.Path)
			}
			p.done()
		})
	}
	p.setHead("* marks the default vault. A vault opened at login locks at logout; the others lock when idle, on screen lock and on sleep.")
	vault := func(ref any) string { return ref.(svrpc.VaultInfo).Name }
	isVault := is[svrpc.VaultInfo]
	p.rowAct('s', "Show its items", isVault, func(ref any) {
		p.close()
		u.showVault(vault(ref), true)
		u.app.SetFocus(u.itemList)
	})
	p.rowAct('d', "Make it the default", isVault, func(ref any) { u.makeDefaultOf(vault(ref)) })
	p.rowAct('o', "Open it when I log in (on or off)…", isVault, func(ref any) { u.toggleLoginOf(ref.(svrpc.VaultInfo)) })
	p.rowAct('v', "Check every file", isVault, func(ref any) { u.verify(vault(ref)) })
	p.rowAct('u', "Unlock with another key…", isVault, func(ref any) { u.unlockWithOf(vault(ref)) })
	p.rowAct('x', "Forget it…", isVault, func(ref any) { u.forget(vault(ref)) })
	p.act('n', "New vault…", u.newVault)
	p.act('a', "Add an existing vault…", u.addVault)
	p.show()
}

func vaultState(v svrpc.VaultInfo) string {
	switch {
	case v.ID == "":
		return "missing"
	case v.Locked:
		return "locked"
	}
	return "unlocked"
}

// lockText is when a vault locks itself, as 'secretvault vault list' says.
func lockText(v svrpc.VaultInfo) string {
	switch {
	case v.LoginUnlock:
		return "at logout"
	case v.AutoLock.IdleMinutes > 0:
		return fmt.Sprintf("%d min idle", v.AutoLock.IdleMinutes)
	}
	return "never"
}

// refreshVaults refills the vaults panel, if it is up, and the pane.
func (u *UI) refreshVaults() {
	if p := u.panels[pagePanel]; p != nil && p.title == "Vaults" {
		p.refresh()
		return
	}
	u.reloadVaults()
}

func (u *UI) makeDefault() {
	if u.needVault() {
		u.makeDefaultOf(u.vault)
	}
}

// makeDefaultOf is 'secretvault vault default NAME'.
func (u *UI) makeDefaultOf(vault string) {
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		return c.SetDefault(ctx, vault)
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.say("%s is the default vault", vault)
		u.refreshVaults()
	})
}

func (u *UI) forgetVault() {
	if u.needVault() {
		u.forget(u.vault)
	}
}

// forget is 'secretvault vault forget NAME': the folder stays.
func (u *UI) forget(vault string) {
	u.confirm(svops.ForgetVaultTitle(vault), svops.ForgetVaultText(vault)+" Add an existing vault (a, on the vaults panel) brings it back.", svops.ForgetVaultAction, func() {
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.ForgetVault(ctx, vault)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Forgot vault %s; its folder is still there", vault)
			next := ""
			if vault == u.vault {
				u.vault = ""
			}
			u.afterVaultsChange(next)
		})
	})
}

func (u *UI) toggleLogin() {
	if !u.needVault() {
		return
	}
	if v := u.vaultInfo(u.vault); v != nil {
		u.toggleLoginOf(*v)
	}
}

// toggleLoginOf is 'secretvault vault login on|off'.
func (u *UI) toggleLoginOf(v svrpc.VaultInfo) {
	on := !v.LoginUnlock
	pl := svops.LoginUnlockPlain(v.Name)
	if !on {
		pl = svops.Plain{
			Title:   "Stop opening " + v.Name + " at login?",
			Summary: fmt.Sprintf("Vault %s will need its passphrase again, and it locks after a few idle minutes, on screen lock and on sleep.", v.Name),
			Action:  "Stop opening it at login",
		}
	}
	u.showPlan(pl, func() {
		var res svrpc.VaultInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.SetLoginUnlock(ctx, v.Name, on)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if res.LoginUnlock {
				u.say("Vault %s opens when you log in, and locks when you log out", res.Name)
			} else {
				u.say("Vault %s no longer opens at login; it locks after %d idle minutes, on screen lock and on sleep", res.Name, res.AutoLock.IdleMinutes)
			}
			u.refreshVaults()
		})
	})
}

func (u *UI) verifyVault() {
	if u.needVault() {
		u.verify(u.vault)
	}
}

// verify is 'secretvault verify': the report.
func (u *UI) verify(vault string) {
	var rep svrpc.VerifyResult
	u.say("Checking every file of %s…", vault)
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		rep, err = c.Verify(ctx, vault)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		title, summary, details, ok := svops.VerifyReport(vault, rep)
		u.say("%s", svops.VerifyStatus(vault, ok))
		u.showDone(title, summary, details)
	})
}

func (u *UI) unlockWith() {
	if u.needVault() {
		u.unlockWithOf(u.vault)
	}
}

// unlockWithOf is 'secretvault unlock' with --keyfile, --identity,
// --recovery, --shares, --fido2 or --passphrase-file.
func (u *UI) unlockWithOf(vault string) {
	options := []string{
		svops.UnlockKindText[svformat.SlotPassphrase],
		svops.UnlockKindText[svformat.SlotFIDO2] + " (its PIN, if it has one, is asked for here)",
		svops.UnlockKindText[svformat.SlotKeyfile] + "…",
		svops.UnlockKindText["identity"] + "…",
		svops.UnlockKindText[svformat.SlotRecovery] + "…",
		svops.UnlockKindText["shares"] + "…",
		svops.UnlockKindText["passphrase-file"] + "…",
	}
	u.choose("Unlock "+vault+" with", options, func(i int) {
		switch i {
		case 0:
			u.unlockKey(vault, nil)
		case 1:
			u.unlockKey(vault, &svrpc.Key{Type: svformat.SlotFIDO2})
		case 2:
			u.unlockFromFile(vault, svformat.SlotKeyfile, "Keyfile")
		case 3:
			u.unlockFromFile(vault, "identity", "Identity file")
		case 4:
			f := u.newForm("Unlock "+vault, "Type the recovery key, as it was written down.")
			rk := f.secret("Recovery key")
			f.show("Unlock", func() string {
				if len(rk.buf) == 0 {
					return "Type the recovery key."
				}
				u.unlockKey(vault, &svrpc.Key{Type: svformat.SlotRecovery, Secret: rk.value()})
				return ""
			})
		case 5:
			u.askShares(vault, &svops.ShareCollector{})
		case 6:
			u.unlockFromFile(vault, svformat.SlotPassphrase, "Passphrase file")
		}
	})
}

// unlockFromFile reads a key from a file and presents it.
func (u *UI) unlockFromFile(vault, typ, label string) {
	f := u.newForm("Unlock "+vault, "")
	path := f.path(label, "", "")
	f.show("Unlock", func() string {
		p := filePath(path)
		if p == "" {
			return "Give the file's path."
		}
		k, err := svops.KeyFromFile(typ, p)
		if err != nil {
			return err.Error()
		}
		u.unlockKey(vault, k)
		return ""
	})
}

// askShares asks for recovery shares one at a time until there are as
// many as the first says it takes, then unlocks with the key they make.
func (u *UI) askShares(vault string, shares *svops.ShareCollector) {
	label := fmt.Sprintf("Share %d", shares.Have()+1)
	if shares.Need() > 0 {
		label = fmt.Sprintf("Share %d of %d", shares.Have()+1, shares.Need())
	}
	f := u.newForm("Unlock "+vault+" with recovery shares", svops.SharesIntro)
	in := f.secret(label)
	f.onCancel = shares.Wipe
	f.show("Next", func() string {
		b := in.value()
		err := shares.Add(b)
		clear(b)
		if err != nil {
			in.wipe()
			return err.Error()
		}
		if !shares.Done() {
			u.post(func() { u.askShares(vault, shares) })
			return ""
		}
		rk, err := shares.Key()
		shares.Wipe()
		if err != nil {
			u.fail(err)
			return ""
		}
		u.unlockKey(vault, &svrpc.Key{Type: svformat.SlotRecovery, Secret: rk})
		return ""
	})
}

// unlockKey unlocks vault with k (nil: the daemon asks), wiping k after.
func (u *UI) unlockKey(vault string, k *svrpc.Key) {
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		if k != nil {
			defer clear(k.Secret)
		}
		_, err := c.Unlock(ctx, vault, k)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			u.reloadVaults()
			return
		}
		u.say("Unlocked %s", vault)
		if p := u.panels[pagePanel]; p != nil && p.title == "Vaults" {
			p.refresh()
		}
		if vault == u.vault {
			u.showVault(vault, true)
		} else {
			u.reloadVaults()
		}
	})
}

// fetchStatus asks the daemon how it is.
func (u *UI) fetchStatus(then func(svrpc.Status, error)) {
	var st svrpc.Status
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.Status(ctx)
		return err
	}, func(err error) { then(st, err) })
}

// statusText is 'secretvault status' and 'secretvault version'.
func statusText(st svrpc.Status, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[::b]secretvault-tui %s[::-]\n", tview.Escape(secretvault.Version))
	if err != nil {
		b.WriteString(svops.DaemonNotAnswering + "\n")
		return b.String()
	}
	fmt.Fprintf(&b, "secretvaultd %s, process %d\n", tview.Escape(st.Version), st.PID)
	if st.Mode == "host" {
		b.WriteString("mode:    host (the machine's service: the H panel says more)\n")
	}
	fmt.Fprintf(&b, "data:    %s\n", tview.Escape(st.Home))
	if st.Config != "" && st.Config != st.Home {
		fmt.Fprintf(&b, "config:  %s\n", tview.Escape(st.Config))
	}
	if st.Socket != "" {
		fmt.Fprintf(&b, "socket:  %s\n", tview.Escape(st.Socket))
	}
	fmt.Fprintf(&b, "prompts: %s\n", tview.Escape(st.Prompts))
	fmt.Fprintf(&b, "keyring: %s\n", tview.Escape(st.SecretService))
	if st.SSHAgent != "" {
		fmt.Fprintf(&b, "ssh:     %s (export SSH_AUTH_SOCK=%s)\n", tview.Escape(st.SSHAgent), tview.Escape(st.SSHAgent))
	}
	if st.GPGAgent != "" {
		homes := "no GnuPG folder uses it yet: Tools › GnuPG"
		if len(st.GnuPGHomes) > 0 {
			homes = "for " + strings.Join(st.GnuPGHomes, ", ")
		}
		fmt.Fprintf(&b, "gpg:     %s (%s)\n", tview.Escape(st.GPGAgent), tview.Escape(homes))
	}
	if len(st.Emergency) > 0 {
		b.WriteString("\n[::b]Emergency access[::-]\n")
		for _, n := range st.Emergency {
			fmt.Fprintf(&b, "  %s\n", tview.Escape(n.Text))
		}
	}
	if len(st.Vaults) > 0 {
		b.WriteString("\n[::b]Vaults[::-]\n")
		for _, v := range st.Vaults {
			name := v.Name
			if v.Default {
				name += " *"
			}
			fmt.Fprintf(&b, "  %-20s %-9s %-12s %s\n", tview.Escape(name), vaultState(v), lockText(v), tview.Escape(v.Path))
		}
	}
	return b.String()
}

// showStatus is secretvault › About: the versions and the daemon's status.
func (u *UI) showStatus() {
	u.fetchStatus(func(st svrpc.Status, err error) {
		u.showText("About secretvault", statusText(st, err))
	})
}

// noteEmergency puts requests for emergency access on the status line,
// as the daemon's status lists them.
func (u *UI) noteEmergency() {
	u.fetchStatus(func(st svrpc.Status, err error) {
		if err != nil {
			return
		}
		u.emergency = u.emergency[:0]
		for _, n := range st.Emergency {
			u.emergency = append(u.emergency, n.Text)
		}
		u.drawStatus()
	})
}
