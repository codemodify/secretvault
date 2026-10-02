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
			p.heading("The ways " + vault + " opens")
			for _, s := range slots {
				detail := s.Detail
				if s.Recipient != "" {
					detail = s.Recipient[:min(40, len(s.Recipient))] + "…"
				}
				p.row(s, s.ID, s.Type, s.Label, s.Created.Local().Format("2006-01-02 15:04"), detail)
			}
			p.heading("Security keys plugged in")
			switch {
			case keysErr != nil:
				p.none(u.describe(keysErr))
			case len(keys) == 0:
				p.none("No security key is plugged in.")
			}
			for _, k := range keys {
				what := "cannot hold a keyslot"
				if k.HMACSecret {
					what = "can hold a keyslot"
				}
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
		name := s.Label
		if name == "" {
			name = s.Type
		}
		u.confirm("Remove keyslot?", fmt.Sprintf("Remove keyslot %s (%s)? It no longer opens %s.\n\nTo cut off someone who already opened it, rotate the key as well (Sharing › Cut off).", s.ID, name, vault), "Remove", func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.RemoveSlot(ctx, vault, s.ID)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Removed slot %s", s.ID)
				p.refresh()
			})
		})
	})
	p.rowAct('i', "What it can do", is[svrpc.FIDO2Device], func(ref any) { u.showSecurityKey(ref.(svrpc.FIDO2Device)) })
	p.act('a', "Add a keyslot…", func() { u.addSlot(vault, p.refresh) })
	p.act('p', "Change the passphrase…", func() { u.changePassphrase(vault) })
	p.act('r', "Rotate the vault key…", func() { u.rotateKey(vault, nil, p.refresh) })
	p.show()
}

// showSecurityKey is one key of 'secretvault fido2 ls'.
func (u *UI) showSecurityKey(k svrpc.FIDO2Device) {
	var b strings.Builder
	fmt.Fprintf(&b, "[::b]%s[::-]\n", tview.Escape(k.Name))
	if k.Path != "" {
		fmt.Fprintf(&b, "  device:      %s\n", tview.Escape(k.Path))
	}
	if len(k.Versions) > 0 {
		fmt.Fprintf(&b, "  speaks:      %s\n", tview.Escape(strings.Join(k.Versions, ", ")))
		fmt.Fprintf(&b, "  model:       %s\n", tview.Escape(k.AAGUID))
		pin := "cannot have one"
		switch k.PIN {
		case "set":
			pin = fmt.Sprintf("set, %d tries left", k.Retries)
		case "not set":
			pin = "not set"
		}
		fmt.Fprintf(&b, "  PIN:         %s\n", pin)
		fmt.Fprintf(&b, "  hmac-secret: %s\n", yesNo(k.HMACSecret))
	}
	if k.Problem != "" {
		fmt.Fprintf(&b, "  problem:     %s\n", tview.Escape(k.Problem))
	}
	u.showText("Security key", b.String())
}

// addSlot is 'secretvault slot add TYPE'.
func (u *UI) addSlot(vault string, then func()) {
	kinds := []string{
		"A passphrase",
		"A recovery key (shown once, or as shares for several people)",
		"A keyfile (made here, or one you have)",
		"A recipient: a person's or device's identity",
		"The security key plugged in",
	}
	u.choose("Add which keyslot to "+vault+"?", kinds, func(i int) {
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
				u.say("Added %s slot %s", info.Type, info.ID)
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
			f := u.newForm("Add a passphrase to "+vault, "")
			label := f.text("Label", "", "(optional)")
			pass := f.secret("Passphrase")
			again := f.secret("Repeat it")
			f.show("Add", func() string {
				if problem := newPassphraseProblem(pass, again); problem != "" {
					return problem
				}
				add(svrpc.SlotAddParams{Type: svformat.SlotPassphrase, Label: trimmed(label), Secret: pass.value()}, nil)
				return ""
			})
		case 1:
			f := u.newForm("Add a recovery key to "+vault, "The key opens the vault on its own. Split, it is shown as shares instead, for several people or places: any threshold of them open the vault, fewer reveal nothing. It is shown only once.")
			label := f.text("Label", "", "(optional)")
			split := f.text("Shares", "", "how many to split it into (none: one key)")
			threshold := f.text("Threshold", "", "how many open it (default: a majority)")
			f.show("Add", func() string {
				n, k := 0, 0
				var err error
				if s := trimmed(split); s != "" {
					if n, err = strconv.Atoi(s); err != nil {
						return "The number of shares is a number."
					}
				}
				if s := trimmed(threshold); s != "" {
					if k, err = strconv.Atoi(s); err != nil {
						return "The threshold is a number."
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
						u.showRecoveryKey("Recovery key of "+vault, info.RecoveryKey)
					}
				})
				return ""
			})
		case 2:
			f := u.newForm("Add a keyfile to "+vault, "Any file can be a keyfile: its bytes open the vault. One made here is 64 random bytes, mode 0600.")
			label := f.text("Label", "", "(optional)")
			path := f.path("Keyfile", "", "")
			create := f.check("Make it here (a new file)", false)
			f.show("Add", func() string {
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
			f := u.newForm("Add the security key plugged in to "+vault, "Touch it when it blinks. With its PIN, the PIN is asked for with every touch; a touch alone is enough otherwise.")
			label := f.text("Label", "", "(optional)")
			uv := f.choice("PIN", []string{"with every touch, if it has one", "always (it must have one)", "never: a touch alone opens the vault"}, 0)
			f.show("Add", func() string {
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
					u.say("%s opens the vault with: %s", info.Label, info.Detail)
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
		{text: fmt.Sprintf("The recovery key, as %d shares; any %d of them open the vault, fewer reveal nothing.", n, k)},
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
		f := u.newForm("Change the passphrase of "+vault, "The new passphrase replaces the one that opened the vault.")
		pass := f.secret("New passphrase")
		again := f.secret("Repeat it")
		f.show("Change", func() string {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			p := pass.value()
			var info svrpc.SlotInfo
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				defer clear(p)
				info, err = c.Passwd(ctx, vault, p)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Passphrase changed (slot %s)", info.ID)
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
		intro := "The vault gets a new key. It opens with the passphrase given here (it may be the one it has), and with every person's keyslot"
		if len(drop) > 0 {
			intro += " but " + strings.Join(drop, ", ") + ", who are cut off"
		}
		intro += ". Keyfiles and security keys are added again afterwards."
		f := u.newForm("Rotate the key of "+vault, intro)
		pass := f.secret("Passphrase")
		again := f.secret("Repeat it")
		recovery := f.check("A new recovery key (the old one stops working)", false)
		f.show("Rotate", func() string {
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
				u.say("The key of %s was rotated (epoch %d)", vault, res.Epoch)
				if then != nil {
					then()
				}
				lines := []onceLine{{text: fmt.Sprintf("The vault key was rotated (epoch %d). It opens with:", res.Epoch)}}
				for _, s := range res.Slots {
					label := s.Label
					if label == "" {
						label = s.Type
					}
					lines = append(lines, onceLine{text: "  " + s.ID + "  " + label})
				}
				if len(res.Dropped) > 0 {
					lines = append(lines, onceLine{}, onceLine{text: "No longer opening it (add them again in Keyslots, or with Emergency access › Grant):"})
					for _, s := range res.Dropped {
						lines = append(lines, onceLine{text: fmt.Sprintf("  %s  %s (%s)", s.ID, s.Label, s.Type)})
					}
				}
				if res.RecoveryKey != "" {
					lines = append(lines, onceLine{}, onceLine{text: "The new recovery key (write it down; it is shown only now):"}, onceLine{secret: []byte(res.RecoveryKey)})
				}
				u.showOnce("Rotated "+vault, lines, nil)
			})
			return ""
		})
	})
}
