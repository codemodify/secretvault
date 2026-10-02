package svtui

import (
	"context"
	"fmt"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The devices panel (D): the devices registered in the vault, whose keys
// sign what they write ('secretvault device ls'), naming, removing and
// vouching for one, and the vault's policy on signatures ('secretvault
// vault signatures').

func (u *UI) showDevices() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Devices · "+vault, "KEY", "LABEL", "DEVICE", "REGISTERED", "STANDING")
	p.vault = vault
	var policy svrpc.SignaturePolicy
	p.reload = func() {
		var devs []svrpc.Device
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if devs, err = c.Devices(ctx, vault); err != nil {
				return err
			}
			policy, err = c.Signatures(ctx, vault, nil)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			rule := "[yellow]Every revision counts, signed or not[-]; the history says who signed each."
			if policy.Require {
				rule = "[green]Only revisions signed by a device registered here count[-]; the rest show in the history as ignored."
			}
			p.setHead(rule + " s changes it.\n\nAnyone who can open the vault can register a device, under any label. Before vouching for one, check that its key is the one this panel shows as \"this device\" on that device.")
			p.clear()
			if len(devs) == 0 {
				p.none("None yet.")
			}
			for _, d := range devs {
				p.row(d, d.Key, d.Label, d.Device[:min(8, len(d.Device))], d.Registered.Local().Format("2006-01-02 15:04"), svops.DeviceStanding(d))
			}
			p.done()
		})
	}
	isDevice := is[svrpc.Device]
	p.rowAct('l', "Name it…", isDevice, func(ref any) {
		d := ref.(svrpc.Device)
		u.ask("Name device "+d.Key[:min(16, len(d.Key))], "Label:", d.Label, func(label string) {
			device := d.Key
			if d.This {
				device = ""
			}
			var res svrpc.Device
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.LabelDevice(ctx, vault, device, label)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Device %s is now %q", res.Key, res.Label)
				p.refresh()
			})
		})
	})
	p.rowAct('v', "Vouch for it, or stop…", func(ref any) bool {
		d, ok := ref.(svrpc.Device)
		return ok && !d.This
	}, func(ref any) {
		d := ref.(svrpc.Device)
		withdraw := d.Vouched
		text := fmt.Sprintf("Vouch for %s %q? This device then believes what it signs, and the devices it vouches for.\n\nCheck first that %s is the key that device shows as its own.", d.Key, d.Label, d.Key)
		action := "Vouch"
		if withdraw {
			text = fmt.Sprintf("Stop vouching for %s %q?", d.Key, d.Label)
			action = "Withdraw"
		}
		u.confirm(action+"?", text, action, func() {
			var res svrpc.Device
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.VouchDevice(ctx, vault, d.Key, withdraw)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				if withdraw {
					u.say("This device no longer vouches for %s %q", res.Key, res.Label)
				} else {
					u.say("This device vouches for %s %q, and for the devices it vouches for", res.Key, res.Label)
				}
				p.refresh()
			})
		})
	})
	p.rowAct('x', "Remove it…", func(ref any) bool {
		d, ok := ref.(svrpc.Device)
		return ok && !d.Removed
	}, func(ref any) {
		d := ref.(svrpc.Device)
		u.confirm("Remove device?", fmt.Sprintf("Mark %s %q removed? What it signed still verifies, and shows as a removed device's.\n\nIt can still open the vault and write to it: to cut it off, rotate the key without it (Sharing › Cut off, or Keyslots › Rotate).", d.Key, d.Label), "Remove", func() {
			var res svrpc.Device
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.RemoveDevice(ctx, vault, d.Key)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Removed device %s %q", res.Key, res.Label)
				p.refresh()
			})
		})
	})
	p.act('s', "Signatures: required or not…", func() { u.toggleSignatures(vault, policy.Require, p.refresh) })
	p.show()
}

// toggleSignatures is 'secretvault vault signatures required|optional'.
func (u *UI) toggleSignatures(vault string, required bool, then func()) {
	require := !required
	text := fmt.Sprintf("Count only revisions of %s signed by a device registered in it? The rest show in the history as ignored, and versions of secretvault that cannot sign cannot write to it.", vault)
	action := "Require"
	if !require {
		text = fmt.Sprintf("Count every revision of %s, signed or not?", vault)
		action = "Allow unsigned"
	}
	u.confirm("Signatures", text, action, func() {
		var p svrpc.SignaturePolicy
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			p, err = c.Signatures(ctx, vault, &require)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if p.Require {
				u.say("Vault %s counts only revisions signed by a device registered in it", p.Vault)
			} else {
				u.say("Vault %s counts every revision, signed or not", p.Vault)
			}
			if then != nil {
				then()
			}
		})
	})
}

// opsList is the operations a grant may cover, as 'grant allow --ops'
// takes them.
var opsList = []string{"read", "list", "write", "delete", "manage", "sign", "decrypt", "mount"}

// decideProgram is 'secretvault grant allow|deny PROGRAM'.
func (u *UI) decideProgram(vault string, allow bool, then func()) {
	title, action := "Allow a program", "Allow"
	if !allow {
		title, action = "Deny a program", "Deny"
	}
	f := u.newForm(title+" · "+vault, "Decide about a program ahead of time: a path, flatpak:APP or snap:NAME. The decision covers an item, the vault's contacts, or (neither) the whole vault, for the operations listed.")
	program := f.path("Program", "", "/usr/bin/… or flatpak:APP or snap:NAME")
	item := f.text("Only the item", "", "(optional: the whole vault)")
	contacts := f.check("The vault's contacts, not an item", false)
	ops := f.text("Operations", "read", strings.Join(opsList, ","))
	var untilLock *tview.Checkbox
	if allow {
		untilLock = f.check("Only until the vault locks", false)
	}
	f.show(action, func() string {
		params := svrpc.GrantAddParams{Vault: vault, Program: trimmed(program), Item: trimmed(item), Contacts: contacts.IsChecked(), Decision: "allow-always"}
		if params.Program == "" {
			return "Name the program."
		}
		for _, o := range strings.Split(trimmed(ops), ",") {
			if o = strings.TrimSpace(o); o != "" {
				params.Ops = append(params.Ops, o)
			}
		}
		switch {
		case !allow:
			params.Decision = "deny-always"
		case untilLock.IsChecked():
			params.Decision = "allow-until-lock"
		}
		var g svrpc.Grant
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			g, err = c.Grant(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			what := "the whole vault"
			if g.Item != "" {
				what = fmt.Sprintf("%q", g.Item)
			}
			u.say("%s: %s may %s %s", g.Decision, g.Program, strings.Join(g.Ops, ","), what)
			if then != nil {
				then()
			}
		})
		return ""
	})
}
