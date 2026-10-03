package svtui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The keyslots panel (K): the ways the vault opens ('secretvault slot
// ls'), adding one of each kind (a recovery key shown once, or as
// shares), removing one, changing the passphrase, rotating the vault key;
// and the security keys plugged in ('secretvault fido2 ls').

func (u *UI) showSlots() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Keyslots · "+vault, "ID", "TYPE", "LABEL", "CREATED", "DETAIL")
	p.vault = vault
	p.setHead(svops.KeyslotsNote)
	p.reload = func() {
		var slots []svrpc.SlotInfo
		var keys []svrpc.FIDO2Device
		var keysErr error
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if slots, err = c.Slots(ctx, vault); err != nil {
				return err
			}
			keys, keysErr = c.SecurityKeys(ctx)
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			p.heading("Keyslots")
			for _, s := range slots {
				detail := s.Detail
				if s.Recipient != "" {
					detail = s.Recipient[:min(40, len(s.Recipient))] + "…"
				}
				p.row(s, s.ID, svops.SlotTypeName(s.Type), s.Label, s.Created.Local().Format("2006-01-02 15:04"), detail)
			}
			p.heading("Security keys plugged in")
			switch {
			case keysErr != nil:
				p.setHead("Security keys: [red]" + tview.Escape(u.describe(keysErr)) + "[-]")
			case len(keys) == 0:
				p.none("None plugged in.")
			}
			for _, k := range keys {
				what := svops.SecurityKeyCan(k)
				if k.Problem != "" {
					what = k.Problem
				}
				p.row(k, k.Name, "security key", "", "", what)
			}
			p.done()
		})
	}
	p.rowAct('x', "Remove it…", is[svrpc.SlotInfo], func(ref any) {
		s := ref.(svrpc.SlotInfo)
		u.confirm(svops.RemoveSlotTitle, svops.RemoveSlotText(vault, s)+" That is r on this panel.", svops.RemoveSlotAction, func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.RemoveSlot(ctx, vault, s.ID)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("%s", svops.SlotRemoved(vault, s))
				p.refresh()
			})
		})
	})
	p.rowAct('i', "What it can do", is[svrpc.FIDO2Device], func(ref any) { u.showSecurityKey(ref.(svrpc.FIDO2Device)) })
	p.act('a', "Add a keyslot…", func() { u.addSlot(vault, p.refresh) })
	p.act('p', "Change the passphrase…", func() { u.changePassphrase(vault) })
	p.act('r', "Give the vault a new key…", func() { u.rotateKey(vault, nil, p.refresh) })
	p.show()
}

// showSecurityKey is one key of 'secretvault fido2 ls'.
func (u *UI) showSecurityKey(k svrpc.FIDO2Device) {
	var b strings.Builder
	fmt.Fprintf(&b, "[::b]%s[::-]\n", tview.Escape(k.Name))
	for _, r := range svops.SecurityKeyFacts(k) {
		fmt.Fprintf(&b, "  %-14s %s\n", r[0]+":", tview.Escape(r[1]))
	}
	u.showText("Security key", b.String())
}

// addSlot is 'secretvault slot add TYPE'.
func (u *UI) addSlot(vault string, then func()) {
	kinds := make([]string, len(svops.SlotKinds))
	for i, k := range svops.SlotKinds {
		kinds[i] = k.Text
	}
	u.choose(svops.AddSlotTitle(vault)+": which?", kinds, func(i int) {
		add := func(p svrpc.SlotAddParams, after func(svrpc.SlotInfo)) {
			p.Vault = vault
			var info svrpc.SlotInfo
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				defer clear(p.Secret)
				info, err = c.AddSlot(ctx, p)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("%s", svops.SlotAdded(vault, info))
				if then != nil {
					then()
				}
				if after != nil {
					after(info)
				}
			})
		}
		switch i {
		case 0:
			f := u.newForm("Add a passphrase to "+vault, "Another passphrase that opens the vault on its own, as the one it has does.")
			label := f.text("Label", "", svops.SlotLabelPlaceholder)
			pass := f.secret("Passphrase")
			again := f.secret("Repeat it")
			f.show(svops.SlotAddAction(svformat.SlotPassphrase), func() string {
				if problem := newPassphraseProblem(pass, again); problem != "" {
					return problem
				}
				add(svrpc.SlotAddParams{Type: svformat.SlotPassphrase, Label: trimmed(label), Secret: pass.value()}, nil)
				return ""
			})
		case 1:
			f := u.newForm("Add a recovery key to "+vault, svops.RecoveryKeyIntro+" "+svops.RecoverySplitIntro)
			label := f.text("Label", "", svops.SlotLabelPlaceholder)
			split := f.text("Shares", "", "how many to split it into (empty: one key, not split)")
			threshold := f.text("Shares needed", "", "how many together open it (empty: a majority)")
			f.show(svops.SlotAddAction(svformat.SlotRecovery), func() string {
				n, k := 0, 0
				var err error
				if s := trimmed(split); s != "" {
					if n, err = strconv.Atoi(s); err != nil {
						return "The number of shares is a number."
					}
				}
				if s := trimmed(threshold); s != "" {
					if k, err = strconv.Atoi(s); err != nil {
						return "Shares needed is a number."
					}
				}
				p := svrpc.SlotAddParams{Type: svformat.SlotRecovery, Label: trimmed(label)}
				if n != 0 || k != 0 {
					if k, err = svops.SplitThreshold(n, k); err != nil {
						return err.Error()
					}
					if p.Label == "" {
						p.Label = svops.SplitLabel(n, k)
					}
				}
				add(p, func(info svrpc.SlotInfo) {
					switch {
					case info.RecoveryKey != "" && n > 0:
						u.showShares(info.RecoveryKey, n, k)
					case info.RecoveryKey != "":
						u.showRecoveryKey(vault, info.RecoveryKey)
					}
				})
				return ""
			})
		case 2:
			f := u.newForm("Add a keyfile to "+vault, svops.KeyfileIntro)
			label := f.text("Label", "", svops.SlotLabelPlaceholder)
			path := f.path("Keyfile", "", "")
			create := f.check("Make a new keyfile there", false)
			f.show(svops.SlotAddAction(svformat.SlotKeyfile), func() string {
				pth := filePath(path)
				if pth == "" {
					return "Give the keyfile's path."
				}
				if create.IsChecked() {
					if err := svops.CreateKeyfile(pth); err != nil {
						return err.Error()
					}
				}
				k, err := svops.KeyFromFile(svformat.SlotKeyfile, pth)
				if err != nil {
					return err.Error()
				}
				add(svrpc.SlotAddParams{Type: svformat.SlotKeyfile, Label: trimmed(label), Secret: k.Secret}, nil)
				return ""
			})
		case 3:
			u.shareWith(vault, then)
		case 4:
			f := u.newForm("Add the security key plugged in to "+vault, svops.FIDO2SlotIntro)
			label := f.text("Label", "", svops.SlotLabelPlaceholder)
			uv := f.choice(svops.FIDO2PINLabel, svops.FIDO2PINChoices, 0)
			f.show(svops.SlotAddAction(svformat.SlotFIDO2), func() string {
				p := svrpc.SlotAddParams{Type: svformat.SlotFIDO2, Label: trimmed(label)}
				switch i, _ := uv.GetCurrentOption(); i {
				case 1:
					yes := true
					p.UV = &yes
				case 2:
					no := false
					p.UV = &no
				}
				u.say("Touch your security key…")
				add(p, func(info svrpc.SlotInfo) {
					u.say("%s now opens vault %s (%s)", info.Label, vault, info.Detail)
				})
				return ""
			})
		}
	})
}

// showShares splits a new recovery key and shows the shares, once,
// instead of it: the whole key is never shown.
func (u *UI) showShares(text string, n, k int) {
	shares, err := svops.SplitRecoveryKey(text, n, k)
	if err != nil {
		u.fail(err)
		return
	}
	lines := []onceLine{
		{text: fmt.Sprintf("The recovery key, as %d shares: any %d of them together open the vault, fewer reveal nothing.", n, k)},
		{text: "Give each to a different person or place. They are shown only now."},
	}
	for i, s := range shares {
		lines = append(lines, onceLine{}, onceLine{text: fmt.Sprintf("Share %d of %d:", i+1, n)}, onceLine{secret: []byte(s)})
	}
	lines = append(lines, onceLine{}, onceLine{text: fmt.Sprintf("To open the vault with them: Unlock with… › Recovery shares, then type any %d.", k)})
	u.showOnce("Recovery shares", lines, nil)
}

// proveThen unlocks vault (the daemon asks, if it must) before then: an
// operation that asks for a new passphrase proves it is the person first,
// as the CLI does.
func (u *UI) proveThen(vault string, then func()) {
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, nil)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		then()
	})
}

// changePassphrase is 'secretvault passwd'.
func (u *UI) changePassphrase(vault string) {
	u.proveThen(vault, func() {
		f := u.newForm(svops.ChangePassphraseTitle(vault), svops.ChangePassphraseIntro)
		pass := f.secret("New passphrase")
		again := f.secret("Repeat it")
		f.show(svops.ChangePassphraseAction, func() string {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			p := pass.value()
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				defer clear(p)
				_, err := c.Passwd(ctx, vault, p)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("%s", svops.PassphraseChanged(vault))
				if pn := u.panels[pagePanel]; pn != nil && pn.vault == vault {
					pn.refresh()
				}
			})
			return ""
		})
	})
}

// rotateKey is 'secretvault vault rotate', and with drop 'secretvault
// unshare': a new vault key, opened by the passphrase given, a new
// recovery key if asked, and every recipient slot but those dropped.
func (u *UI) rotateKey(vault string, drop []string, then func()) {
	u.proveThen(vault, func() {
		f := u.newForm(svops.RotateTitle(vault, len(drop) > 0), svops.RotateIntro(len(drop)))
		pass := f.secret("Passphrase")
		again := f.secret("Repeat it")
		recovery := f.check(svops.RotateRecoveryCheck, false)
		f.show(svops.RotateAction(len(drop) > 0), func() string {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			p := svrpc.RotateParams{Vault: vault, Passphrase: pass.value(), Recovery: recovery.IsChecked(), Drop: drop}
			var res svrpc.RotateResult
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				defer clear(p.Passphrase)
				res, err = c.Rotate(ctx, p)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("%s", svops.RotateStatus(vault))
				if then != nil {
					then()
				}
				lines := []onceLine{{text: svops.RotateDone(vault, res, len(drop))}, {}}
				for _, l := range svops.RotateDetails(res) {
					lines = append(lines, onceLine{text: l})
				}
				if res.RecoveryKey != "" {
					lines = append(lines, onceLine{}, onceLine{text: "The new recovery key (write it down; it is shown only now):"}, onceLine{secret: []byte(res.RecoveryKey)})
				}
				u.showOnce("Vault "+vault+" has a new key", lines, nil)
			})
			return ""
		})
	})
}
