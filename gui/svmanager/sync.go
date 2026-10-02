package svmanager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// Sync: keeping a vault in step with a sync server of one's own, the
// devices that sync it, inviting another, and joining a synced vault on
// this device.

func (m *Manager) fillSync(p *vaultPage, pn *pane) {
	var st []svrpc.SyncStatus
	var devs []svrpc.SyncDevice
	var devErr error
	open := false
	if v := m.vaultInfo(p.vault); v != nil && !v.Locked {
		open = true
	}
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		if st, err = c.SyncStatus(ctx, p.vault); err != nil {
			return err
		}
		if len(st) > 0 && open {
			devs, devErr = c.SyncDevices(ctx, p.vault)
		}
		return nil
	}, func() widget.Component {
		p.sync = nil
		if len(st) > 0 {
			p.sync = &st[0]
			m.syncs[p.vault] = st[0]
			m.drawStatus()
		}
		p.syncDevs = devs
		return m.drawSync(p, pn, open, devErr)
	})
}

func (m *Manager) drawSync(p *vaultPage, pn *pane, open bool, devErr error) widget.Component {
	s := p.sync
	if s == nil {
		setup := widgets.NewButton("Set up…", func() { m.setupSync(p) })
		setup.Primary = true
		pn.focus = setup
		return m.paneColumn("This vault does not sync. Setting it up keeps it in step with a sync server of your own "+
			"(secretvault-server), and lets other devices join it.", nil, setup)
	}
	when := func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	}
	col := widgets.NewColumn(m.facts([][2]string{
		{"Server", s.URL},
		{"Vault on the server", s.ServerVault},
		{"This device", s.Device},
		{"Last sync", when(s.Last)},
		{"Last good sync", when(s.LastOK)},
		{"Since the daemon started", fmt.Sprintf("%d pulled, %d pushed, %d removed", s.Pulled, s.Pushed, s.Removed)},
	})).WithGap(gap).WithPad(gap)
	if s.Error != "" {
		e := toned("The last sync failed: "+s.Error, widgets.ToneDanger)
		e.Wrap = true
		col.Add(e)
	}
	if s.Kept > 0 {
		k := toned(fmt.Sprintf("%d keyslot removals were refused, because they would have left the vault with no key.", s.Kept), widgets.ToneWarning)
		k.Wrap = true
		col.Add(k)
	}
	now := widgets.NewButton("Sync now", func() { m.syncNow(p) })
	pn.focus = now
	col.Add(buttons(now, widgets.NewButton("Refresh", pn.refresh),
		widgets.NewButton("Invite a device…", func() { m.inviteDevice(p) }),
		widgets.NewButton("Stop syncing…", func() { m.syncOff(p) })))
	col.Add(section(m, "Devices that sync it"))
	switch {
	case !open:
		col.Add(m.paragraph("They show once the vault is unlocked."))
	case devErr != nil:
		col.Add(m.paragraph(m.describe(devErr)))
	default:
		devs := p.syncDevs
		p.sdtable = table("Devices that sync", []widgets.TableColumn{
			{Title: "Key", Width: 160},
			{Title: "Label"},
			{Title: "Added", Width: 130},
			{Title: "Last seen", Width: 130},
		}, len(devs), func(r, c int) string {
			d := devs[r]
			switch c {
			case 0:
				return d.Key
			case 1:
				if d.This {
					return d.Label + " (this device)"
				}
				return d.Label
			case 2:
				return d.Added.Local().Format("2006-01-02 15:04")
			}
			if d.LastSeen == nil {
				return "never"
			}
			return d.LastSeen.Local().Format("2006-01-02 15:04")
		})
		col.Add(widgets.NewHeightBox(160, p.sdtable))
		col.Add(buttons(widgets.NewButton("Remove a device…", func() { m.removeSyncDevice(p) })))
	}
	return scrolled(col)
}

// setupSync starts syncing the vault with a server (the CLI's sync
// setup).
func (m *Manager) setupSync(p *vaultPage) {
	f := m.newForm("Sync " + p.vault)
	url := f.text("Server", "", "https://sync.example.com:8443")
	fp := f.text("Fingerprint", "", "for a self-signed certificate, as secretvault-server printed it")
	token := f.secret("Admin token", "only if the server does not let anyone make vaults")
	label := f.text("This device", "", "its name to the others (default: the host name)")
	f.note("The vault is made on the server, with this device as its first. Only its ciphertext leaves this device.")
	f.show("Set up", func() {
		u := strings.TrimSpace(url.Text)
		if u == "" {
			f.fail("Give the server's address.")
			return
		}
		// The token goes to the daemon as a string (svrpc.SyncSetupParams),
		// as the CLI sends it from its file.
		tok := token.Bytes()
		params := svrpc.SyncSetupParams{Vault: p.vault, URL: u, Fingerprint: strings.TrimSpace(fp.Text),
			AdminToken: strings.TrimSpace(string(tok)), Label: strings.TrimSpace(label.Text)}
		clear(tok)
		var st svrpc.SyncStatus
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			st, err = c.SyncSetup(ctx, params)
			return err
		}, func() {
			m.say("Vault %s now syncs with %s (sent %d files).", st.Vault, st.URL, st.Pushed)
			m.loadSyncs()
			m.refreshTab(p, tabSync)
		})
	})
}

// syncNow syncs at once (the CLI's sync now).
func (m *Manager) syncNow(p *vaultPage) {
	var st svrpc.SyncStatus
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.SyncNow(ctx, p.vault)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		if st.Error != "" {
			m.say("The sync failed: %s", st.Error)
		} else {
			m.say("Synced %s: %d pulled, %d pushed, %d removed since the daemon started.", st.Vault, st.Pulled, st.Pushed, st.Removed)
		}
		m.loadSyncs()
		m.refreshTab(p, tabSync)
	})
}

// inviteDevice makes a one-time invite for another device to join (the
// CLI's sync invite), shown once, and as a QR code to scan.
func (m *Manager) inviteDevice(p *vaultPage) {
	var inv svrpc.SyncInvite
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		inv, err = c.SyncInvite(ctx, p.vault)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.showSecrets("Invite a device to "+p.vault,
			"On the new device: File › Join a synced vault…, and paste this invite, or scan it. It works once, before "+
				inv.Expires.Local().Format("15:04")+". The device gets the vault's ciphertext; opening it still takes the passphrase, "+
				"or a keyslot you add for it.",
			[]secretShown{{label: "Invite", value: []byte(inv.Invite)}}, true, "Done")
	})
}

// removeSyncDevice takes a device off the server (the CLI's sync
// rm-device).
func (m *Manager) removeSyncDevice(p *vaultPage) {
	i := selected(p.sdtable)
	if i < 0 || i >= len(p.syncDevs) {
		m.say("Choose a device first.")
		return
	}
	d := p.syncDevs[i]
	m.confirm("Remove the device?", fmt.Sprintf("Stop %s (%s) syncing vault %s?\n\nThat device keeps what it already has, and any key it opens the vault with: "+
		"to cut it off for good, remove its keyslot and rotate the key (Sharing › Cut off).", d.Label, d.Key, p.vault), "Remove", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.SyncRemove(ctx, p.vault, d.Key)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Removed %s from the sync server.", d.Key)
			m.refreshTab(p, tabSync)
		})
	})
}

// syncOff stops syncing the vault (the CLI's sync off).
func (m *Manager) syncOff(p *vaultPage) {
	m.confirm("Stop syncing?", "Stop syncing vault "+p.vault+"?\n\nThis device keeps its copy; the server and the other devices keep theirs.", "Stop syncing", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.SyncOff(ctx, p.vault)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			delete(m.syncs, p.vault)
			m.say("Vault %s no longer syncs.", p.vault)
			m.drawStatus()
			m.refreshTab(p, tabSync)
		})
	})
}

// joinSynced fetches a synced vault onto this device with an invite from
// one that syncs it (the CLI's sync join).
func (m *Manager) joinSynced() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Join a synced vault")
	invite := f.secret("Invite", "secretvault-sync:…, from Sync › Invite a device… on the other device")
	name := f.text("Name here", "", "personal, work…")
	folder := f.path("Folder", PickFolder, "")
	f.note("Folder: leave it empty to keep the vault in secretvault's data folder.")
	label := f.text("This device", "", "its name to the others (default: the host name)")
	f.show("Join", func() {
		n := strings.TrimSpace(name.Text)
		switch {
		case invite.Empty():
			f.fail("Paste the invite.")
			return
		case n == "" || strings.ContainsAny(n, "/\\"):
			f.fail("Give the vault a name, without slashes.")
			return
		case m.vaultInfo(n) != nil:
			f.fail("There is a vault called " + n + " already.")
			return
		}
		// The invite goes to the daemon as a string
		// (svrpc.SyncJoinParams); it works once, and has then been used.
		inv := invite.Bytes()
		params := svrpc.SyncJoinParams{Invite: strings.TrimSpace(string(inv)), Name: n, Path: folder.Path(), Label: strings.TrimSpace(label.Text)}
		clear(inv)
		var v svrpc.VaultInfo
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Path, err = absPath(params.Path); err != nil {
				return err
			}
			v, err = c.SyncJoin(ctx, params)
			return err
		}, func() {
			m.say("Fetched vault %s into %s; it syncs from now on. Unlock it with its passphrase.", v.Name, v.Path)
			m.reloadVaults()
			m.loadSyncs()
			m.showVault(v.Name, false)
		})
	})
}
