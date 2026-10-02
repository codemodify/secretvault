package svtui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svqr"
	"github.com/codemodify/secretvault/svrpc"
)

// The sync panel (S): every synced vault and how it is doing ('secretvault
// sync status'), the shown vault's devices ('sync devices'), setting it
// up, inviting a device (the invite shown once, with its QR code),
// syncing now, removing a device, stopping; and joining a synced vault
// from an invite.

// syncDeviceRef is a device row of the sync panel.
type syncDeviceRef struct{ svrpc.SyncDevice }

func (u *UI) showSync() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Sync", "VAULT / DEVICE", "SERVER / LABEL", "LAST", "SENT", "FETCHED", "STATE")
	p.reload = func() {
		var sts []svrpc.SyncStatus
		var devs []svrpc.SyncDevice
		var devErr error
		synced := false
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if sts, err = c.SyncStatus(ctx, ""); err != nil {
				return err
			}
			for _, st := range sts {
				if st.Vault == vault {
					synced = true
				}
			}
			if synced {
				devs, devErr = c.SyncDevices(ctx, vault)
			}
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			p.setHead("A synced vault is kept in step with a sync server, through which its other devices get its ciphertext. u sets this vault up; i invites a device; j joins a vault from an invite.")
			p.heading("Synced vaults")
			if len(sts) == 0 {
				p.none("None (u sets this one up).")
			}
			for _, st := range sts {
				p.row(st, st.Vault, st.URL, syncLast(st), fmt.Sprint(st.Pushed), fmt.Sprint(st.Pulled+st.Removed), syncState(st))
			}
			p.heading("Devices of " + vault)
			switch {
			case !synced:
				p.none("It does not sync.")
			case devErr != nil:
				p.setHead("[red]" + tview.Escape(u.describe(devErr)) + "[-]")
			}
			for _, d := range devs {
				label := d.Label
				if d.This {
					label += " (this device)"
				}
				seen := "never"
				if d.LastSeen != nil {
					seen = d.LastSeen.Local().Format("2006-01-02 15:04")
				}
				p.row(syncDeviceRef{d}, d.Key, label, seen, "", "", "added "+d.Added.Local().Format("2006-01-02"))
			}
			p.done()
		})
	}
	p.act('u', "Set up "+vault+"…", func() { u.syncSetup(vault, p.refresh) })
	p.act('i', "Invite a device…", func() { u.syncInvite(vault) })
	p.act('n', "Sync now", func() {
		var st svrpc.SyncStatus
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			st, err = c.SyncNow(ctx, vault)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Synced %s: %s", st.Vault, syncState(st))
			p.refresh()
		})
	})
	p.rowAct('x', "Remove the device…", func(ref any) bool {
		d, ok := ref.(syncDeviceRef)
		return ok && !d.This
	}, func(ref any) {
		d := ref.(syncDeviceRef)
		u.confirm("Remove device?", fmt.Sprintf("Remove %s (%s) from %s on the server?\n\nIt keeps what it already has, and any key it opens the vault with: to cut it off for good, remove its keyslot and rotate (Sharing › Cut off).", d.Label, d.Key, vault), "Remove", func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.SyncRemove(ctx, vault, d.Key)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Removed %s from %s", d.Label, vault)
				p.refresh()
			})
		})
	})
	p.act('o', "Stop syncing "+vault+"…", func() {
		u.confirm("Stop syncing?", fmt.Sprintf("Stop syncing %s? It stays here as it is; the server's copy is left alone.", vault), "Stop", func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.SyncOff(ctx, vault)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("%s no longer syncs", vault)
				p.refresh()
			})
		})
	})
	p.act('j', "Join a synced vault…", func() { u.syncJoin() })
	p.show()
}

func syncLast(st svrpc.SyncStatus) string {
	if st.Last.IsZero() {
		return "not yet"
	}
	return st.Last.Local().Format(time.DateTime)
}

// syncState is a synced vault's state, as 'secretvault sync status' says.
func syncState(st svrpc.SyncStatus) string {
	switch {
	case st.Error != "":
		return st.Error
	case st.Last.IsZero():
		return "starting"
	case st.Kept > 0:
		return fmt.Sprintf("ok; refused %d keyslot removals that would have left no key", st.Kept)
	}
	return "ok"
}

// syncSetup is 'secretvault sync setup URL'.
func (u *UI) syncSetup(vault string, then func()) {
	f := u.newForm("Sync "+vault+" with a server", "The vault is made on the server, with this device as its first device. A self-signed server is pinned by its certificate's fingerprint, as secretvault-server printed it.")
	url := f.text("Server", "", "https://sync.example.com:8443")
	fp := f.text("Fingerprint", "", "(for a self-signed certificate)")
	token := f.path("Admin token file", "", "(when the server does not let anyone make vaults)")
	label := f.text("This device's name", "", "default: the host name")
	f.show("Set up", func() string {
		p := svrpc.SyncSetupParams{Vault: vault, URL: trimmed(url), Fingerprint: trimmed(fp), Label: trimmed(label)}
		if p.URL == "" {
			return "Give the server's address."
		}
		if t := filePath(token); t != "" {
			b, err := os.ReadFile(t)
			if err != nil {
				return err.Error()
			}
			p.AdminToken = strings.TrimSpace(string(b))
			clear(b)
		}
		var st svrpc.SyncStatus
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			st, err = c.SyncSetup(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Vault %s now syncs with %s (sent %d files); invite another device with i", st.Vault, st.URL, st.Pushed)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// syncInvite is 'secretvault sync invite --qr': the invite, once, with
// its QR code.
func (u *UI) syncInvite(vault string) {
	var inv svrpc.SyncInvite
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		inv, err = c.SyncInvite(ctx, vault)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		code, err := svqr.Encode([]byte(inv.Invite), svqr.M)
		if err != nil {
			code = nil
		}
		u.showOnce("Invite a device to "+vault, []onceLine{
			{text: "On the new device, join with this invite (before " + inv.Expires.Local().Format("15:04") + "; it works once):"},
			{secret: []byte(inv.Invite)},
			{},
			{text: "Sync › Join a synced vault here, or 'secretvault sync join INVITE'. It gets the vault's ciphertext;"},
			{text: "opening it still takes the passphrase, or a keyslot you add for it. Or scan it (the same one-time code):"},
		}, code)
	})
}

// syncJoin is 'secretvault sync join INVITE'.
func (u *UI) syncJoin() {
	f := u.newForm("Join a synced vault", "Paste the invite a device that syncs the vault made (Sync › Invite a device). The vault is fetched here, and syncs from then on.")
	invite := f.text("Invite", "", "secretvault-sync:…")
	name := f.text("Name here", "", "default")
	dir := f.path("Folder", "", "secretvault's own (or a folder of your own)")
	label := f.text("This device's name", "", "default: the host name")
	f.show("Join", func() string {
		p := svrpc.SyncJoinParams{Invite: trimmed(invite), Name: trimmed(name), Label: trimmed(label)}
		if p.Invite == "" {
			return "Paste the invite."
		}
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
		var v svrpc.VaultInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			v, err = c.SyncJoin(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Fetched vault %s into %s; it syncs from now on. Unlock it with its passphrase", v.Name, v.Path)
			u.afterVaultsChange(v.Name)
		})
		return ""
	})
}
