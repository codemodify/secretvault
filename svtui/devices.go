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
	p := u.newPanel("Devices · "+vault, "KEY", "NAME", "DEVICE", "ADDED", "TRUSTED")
	p.vault = vault
	var policy svrpc.SignaturePolicy
	p.reload = func() {
		var devs []svrpc.Device
		var pol svrpc.SignaturePolicy
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if devs, err = c.Devices(ctx, vault); err != nil {
				return err
			}
			pol, err = c.Signatures(ctx, vault, nil)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			policy = pol
			rule := "[yellow]Every change counts, signed or not[-]; the history says which device signed each."
			if policy.Require {
				rule = "[green]Only changes signed by a device listed here count[-]; the history marks the rest as ignored."
			}
			p.setHead(rule + " s changes it.\n\n" + tview.Escape(svops.DevicesAbout))
			p.clear()
			if len(devs) == 0 {
				p.none("None yet (added on unlock).")
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
		u.askTo("Name device "+d.Key[:min(16, len(d.Key))], "Name:", d.Label, "Save the name", func(label string) {
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
		do := func() {
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
		}
		if withdraw {
			stop := svops.WithdrawPlain(d.Label)
			u.confirm(stop.Title, stop.Summary, stop.Action, do)
			return
		}
		u.showPlan(svops.VouchPlain(d.Label, d.Key), do)
	})
	p.rowAct('x', "Remove it…", func(ref any) bool {
		d, ok := ref.(svrpc.Device)
		return ok && !d.Removed
	}, func(ref any) {
		d := ref.(svrpc.Device)
		u.showPlan(svops.RemoveDevicePlain(d.Label, d.Key), func() {
			var res svrpc.Device
			u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.RemoveDevice(ctx, vault, d.Key)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Marked %s as removed", svops.DeviceName(res.Label, res.Key))
				p.refresh()
			})
		})
	})
	p.act('s', "Signatures: required or not…", func() {
		if policy.Vault == "" {
			return // not read yet
		}
		u.toggleSignatures(vault, policy.Require, p.refresh)
	})
	p.show()
}

// toggleSignatures is 'secretvault vault signatures required|optional'.
func (u *UI) toggleSignatures(vault string, required bool, then func()) {
	require := !required
	title, action := "Count only signed changes?", "Count only signed changes"
	text := fmt.Sprintf("Changes to %s not signed by a device listed in it are then ignored, and the history marks them. Older versions of secretvault, which cannot sign, can then no longer change it.", vault)
	if !require {
		title, action = "Count unsigned changes too?", "Count every change"
		text = fmt.Sprintf("Every change to %s counts again, signed or not; the history still says which device signed each.", vault)
	}
	u.confirm(title, text, action, func() {
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
				u.say("Vault %s counts only changes signed by a device listed in it", p.Vault)
			} else {
				u.say("Vault %s counts every change, signed or not", p.Vault)
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
	title, action := "Allow a program", "Allow the program"
	if !allow {
		title, action = "Deny a program", "Deny the program"
	}
	f := u.newForm(title+" · "+vault, "Decide now whether a program may use this vault, so that it is not asked later. The decision covers one item, the vault's contacts, or (neither) the whole vault, for the operations listed.")
	program := f.path("Program", "", "/usr/bin/… or flatpak:APP or snap:NAME")
	item := f.text("Only the item", "", "(optional: the whole vault)")
	contacts := f.check("The vault's contacts, not an item", false)
	ops := f.text("What it may do", "read", strings.Join(opsList, ","))
	var untilLock *tview.Checkbox
	if allow {
		untilLock = f.check("Only until the vault locks", false)
	}
	f.show(action, func() string {
		params := svrpc.GrantAddParams{Vault: vault, Program: filePath(program), Item: trimmed(item), Contacts: contacts.IsChecked(), Decision: "allow-always"}
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
			u.say("%s", strings.TrimSuffix(svops.GrantDecided(g), "."))
			if then != nil {
				then()
			}
		})
		return ""
	})
}
