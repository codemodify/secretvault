package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The Disks tab: encrypted disks (the CLI's containers), LUKS2 image
// files on this computer's drive, mounted like a USB drive, whose keys are
// items of a vault. It lists every disk whose key an unlocked vault keeps,
// and says which vaults are locked, since a disk is known only by the item
// that holds its key. Making one, opening (mounting) and closing it,
// backing up its header, and giving it a passphrase of its own.

// disksPage is the Disk tab's page's state: the list of disks on the
// left, and the one picked, with what can be done with it, beside it.
type disksPage struct {
	*tabbedPage
	boxes  []svrpc.ContainerInfo
	ctable *widgets.TableView
	detail *slot
}

// showDisks brings the Disks tab forward, its disks asked for again.
func (m *Manager) showDisks() {
	if m.section() != secDisks {
		m.showSection(secDisks) // which fills it (sectionShown)
		return
	}
	m.disksShown()
}

// disksShown makes the Disks tab's page, or asks for its disks again.
func (m *Manager) disksShown() {
	if m.disks == nil {
		p := &disksPage{tabbedPage: &tabbedPage{kind: pageDisks, title: "Disks"}}
		p.panes = []*pane{newPane("Disks", func(pn *pane) { m.fillDisks(p, pn) })}
		m.disks = p
		m.standPage(p.tabbedPage, m.ui.disksHost, 0)
		return
	}
	m.disks.panes[0].refresh()
}

// refreshDisks asks for the disks again, if they were shown.
func (m *Manager) refreshDisks(p *disksPage) {
	if p != nil && m.up(p.tabbedPage) && p.panes[0].filled {
		p.panes[0].refresh()
	}
}

// keyVaults are the vaults a disk's key can be kept in, or looked for
// in: every one whose folder is there. A locked one is fine: the daemon
// asks for its passphrase when the disk is made or opened.
func (m *Manager) keyVaults() []svrpc.VaultInfo {
	var out []svrpc.VaultInfo
	for _, v := range m.vaults {
		if v.ID != "" {
			out = append(out, v)
		}
	}
	return out
}

// vaultChoice adds a choice of vaults to f, at want if it is one of them,
// saying which are locked.
func vaultChoice(f *formDialog, label string, vaults []svrpc.VaultInfo, want string) func() string {
	names := make([]string, len(vaults))
	at := 0
	for i, v := range vaults {
		names[i] = v.Name
		if v.Locked {
			names[i] += " (locked: asks for its passphrase)"
		}
		if v.Name == want {
			at = i
		}
	}
	c := f.choice(label, names, at)
	return func() string { return vaults[max(0, c.Selected)].Name }
}

func (m *Manager) fillDisks(p *disksPage, pn *pane) {
	var list []svrpc.ContainerInfo
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		// Every vault's, a locked one's by file alone, as this computer
		// last saw them: nothing is unlocked, and nobody is asked.
		list, err = c.KnownContainers(ctx)
		return err
	}, func() widget.Component {
		var locked []string
		for _, v := range m.vaults {
			if v.Locked && v.ID != "" {
				locked = append(locked, v.Name)
			}
		}
		p.boxes = list
		p.ctable = table("Disks", []widgets.TableColumn{
			{Title: "Disk file"}, {Title: "Key kept in", Width: 140}, {Title: "State", Width: 200},
		}, len(list), func(r, c int) string {
			ci := list[r]
			switch c {
			case 0:
				return ci.Path
			case 1:
				if ci.Locked {
					return "vault " + ci.Vault + " (locked)"
				}
				return "vault " + ci.Vault
			}
			return diskState(&ci)
		})
		p.ctable.OnSelect = func(int) { m.drawDisk(p) }
		// The disk shown is picked in the title bar; the first, until
		// one is, or one asked for (Show the disk).
		if len(list) > 0 {
			p.ctable.Selected = 0
		}
		if m.wantDisk != [2]string{} {
			for i, ci := range list {
				if ci.Vault == m.wantDisk[0] && ci.Item == m.wantDisk[1] {
					p.ctable.Selected = i
				}
			}
			m.wantDisk = [2]string{}
		}
		note := svops.ContainersAbout
		if len(list) == 0 {
			note = svops.ContainersNone + " New disk… makes one."
		}
		if len(locked) > 0 {
			note += " " + svops.DisksLockedSeen + strings.Join(locked, ", ") + "."
		}
		if err := svops.MountsHere(); err != nil {
			note += " " + sentence(err.Error())
		}
		// The disks are listed in the title bar, from the disk's
		// breadcrumb; making and mounting one are on it too.
		p.detail = newSlot()
		m.drawDisk(p)
		defer m.drawTitle()
		return scrolled(widgets.NewColumn(m.paragraph(note), p.detail).WithGap(gap).WithPad(gap))
	})
}

// diskState says how a disk is, in words.
func diskState(ci *svrpc.ContainerInfo) string {
	switch ci.State {
	case "mounted":
		return "mounted, in " + ci.MountPoint
	case "closed":
		return "not mounted"
	case "unlocked":
		return "unlocked, not mounted"
	case "attached":
		return "attached, locked"
	case "unknown":
		return "not known on this system"
	case "missing":
		return "the file is missing"
	}
	return ci.State
}

// drawDisk shows the disk picked, and what can be done with it.
func (m *Manager) drawDisk(p *disksPage) {
	if p.detail == nil {
		return
	}
	ci := p.container()
	if ci == nil && len(p.boxes) == 0 {
		mk := newButton("New disk…", func() { m.newContainer(p) })
		mk.Primary = true
		p.detail.Set(m.message("No disks yet", "New disk… makes one, its key kept in a vault; "+
			"Mount a disk file… opens one made somewhere else, with the key of an item.",
			mk, newButton("Mount a disk file…", func() { m.openContainerFile(p) })))
		return
	}
	if ci == nil {
		p.detail.Set(m.message("No disk chosen", "Pick one at the top, beside Disk, to see it, and to mount, unmount or delete it."))
		return
	}
	size := "the file is missing"
	if st, err := os.Stat(ci.Path); err == nil {
		size = svops.HumanSize(st.Size())
	}
	own := "no: only the key kept in the vault opens it"
	if ci.Passphrase {
		own = "yes: it opens without secretvault too"
	}
	keyIn := "vault " + ci.Vault + ", item " + ci.Item
	if ci.Locked {
		keyIn, own = "vault "+ci.Vault+", locked", "known once the vault is unlocked"
	}
	rows := [][2]string{
		{"File", ci.Path},
		{"Size", size},
		{"Key kept in", keyIn},
		{"State", diskState(ci)},
		{"Own passphrase", own},
	}
	if ci.UUID != "" {
		rows = append(rows, [2]string{"LUKS UUID", ci.UUID})
	}
	mounted := ci.State == "mounted"
	mount := newButton("Mount", func() { m.openContainer(p) })
	mount.SetEnabled(!mounted)
	unmount := newButton("Unmount…", func() { m.closeContainer(p) })
	unmount.SetEnabled(ci.State != "closed" && ci.State != "unknown")
	copyPath := newButton("Copy the folder's path", func() { m.copyMountPoint(p) })
	copyPath.SetEnabled(mounted && ci.MountPoint != "")
	col := widgets.NewColumn(heading(filepath.Base(ci.Path)), m.facts(rows)).WithGap(gap)
	if !ci.Locked && ci.Item != "" {
		vault, item := ci.Vault, ci.Item
		col.Add(buttons(newButton("Show its key", func() { m.showItemOf(vault, item) })))
	}
	if ci.Locked {
		vault := ci.Vault
		col.Add(m.paragraph(svops.DiskVaultLocked(vault)))
		col.Add(buttons(newButton("Unlock vault "+vault+"…", func() { m.unlockVault(vault) })))
	}
	col.Add(buttons(mount, unmount, copyPath,
		newButton("Its own passphrase…", func() { m.containerPassphrase(p) }),
		newButton("Back up the header…", func() { m.backupHeader(p) }),
		newButton("Delete…", func() { m.deleteContainer(p) })))
	p.detail.Set(scrolled(col))
}

// container is the disk selected, or nil.
func (p *disksPage) container() *svrpc.ContainerInfo {
	if p == nil {
		return nil
	}
	i := selected(p.ctable)
	if i < 0 || i >= len(p.boxes) {
		return nil
	}
	return &p.boxes[i]
}

// newContainer makes a disk (the CLI's container create), its key in a
// vault chosen.
func (m *Manager) newContainer(p *disksPage) {
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	vaults := m.keyVaults()
	if len(vaults) == 0 {
		m.noVaultForDisk()
		return
	}
	f := m.newForm("New disk")
	f.intro(svops.ContainerNewAbout)
	vault := vaultChoice(f, "Keep its key in vault", vaults, m.vault)
	file := f.path("Disk file", PickSave, "private.img")
	size := f.text("Size", "1G", "how much it holds: 512M, 1G…")
	fs := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Disk name", "", "optional: what file managers call it")
	item := f.text("Keep its key in", "", "default: an item named after the file")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	mount := f.text("Mount options", "", "optional, for experts: noexec, nodev…")
	withPass := f.check("Also give it a passphrase, to open it without secretvault", false)
	pass := f.secret("Passphrase", "only with the box below ticked")
	again := f.secret("Repeat", "The same again")
	f.show("Make the disk", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose where the disk file goes.")
			return
		}
		n, err := svops.ParseSize(size.Text)
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		name := strings.TrimSpace(item.Text)
		params := svrpc.ContainerCreateParams{Vault: vault(), Item: name, Path: abs, Size: n,
			FS: svcontainer.Filesystems[max(0, fs.Selected)], Label: strings.TrimSpace(label.Text),
			SectorSize: []int{4096, 512}[max(0, sector.Selected)], MountOptions: strings.TrimSpace(mount.Text)}
		if withPass.Checked {
			if pass.Len() < minPassphrase {
				f.fail(fmt.Sprintf("Use a passphrase of at least %d characters.", minPassphrase))
				return
			}
			a, b := pass.Bytes(), again.Bytes()
			same := bytes.Equal(a, b)
			clear(b)
			if !same {
				clear(a)
				pass.Wipe()
				again.Wipe()
				f.fail("The two passphrases differ.")
				return
			}
			params.Passphrase = a
		}
		var info svrpc.ContainerInfo
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			info, err = c.CreateContainer(ctx, params)
			return err
		}, func() {
			m.say("%s", svops.ContainerCreated(info.Path, svops.HumanSize(n), params.FS, info.MountPoint, info.Item, len(params.Passphrase) > 0))
			m.refreshDisks(p)
		}, params.Passphrase)
	})
}

// openContainer mounts the disk selected (the CLI's container open), and
// says where.
func (m *Manager) openContainer(p *disksPage) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a disk first.")
		return
	}
	m.mountImage(p, ci.Vault, ci.Path, ci.Item, "")
}

// mountImage mounts the image at path with the key in item of vault (""
// for the one made for it).
func (m *Manager) mountImage(p *disksPage, vault, path, item, opts string) {
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	var info svrpc.ContainerInfo
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		abs, err := svops.ExistingImage(path)
		if err != nil {
			return err
		}
		info, err = c.OpenContainer(ctx, svrpc.ContainerOpenParams{Vault: vault, Item: item, Path: abs, MountOptions: opts})
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.say("%s", svops.ContainerOpened(info.Path, info.MountPoint))
		m.refreshDisks(p)
	})
}

// openContainerFile mounts a disk file chosen, with the key in an item of
// a vault chosen, named or the one made for it.
func (m *Manager) openContainerFile(p *disksPage) {
	vaults := m.keyVaults()
	if len(vaults) == 0 {
		m.noVaultForDisk()
		return
	}
	f := m.newForm("Mount a disk file")
	f.intro(svops.ContainerOpenAbout)
	file := f.path("Disk file", PickOpen, "")
	vault := vaultChoice(f, "Its key is in vault", vaults, m.vault)
	item := f.text("In the item", "", "default: the one made with it")
	opts := f.text("Mount options", "", "optional, for experts: ro, noexec…")
	f.show("Mount it", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the disk file.")
			return
		}
		f.close()
		m.mountImage(p, vault(), path, strings.TrimSpace(item.Text), strings.TrimSpace(opts.Text))
	})
}

// closeContainer unmounts a disk (the CLI's container close): the one
// selected, or any image or mount point named.
func (m *Manager) closeContainer(p *disksPage) {
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	f := m.newForm("Unmount a disk")
	f.intro(svops.ContainerCloseAbout)
	target := f.path("Disk file or its folder", PickOpen, "")
	if ci := p.container(); ci != nil {
		target.field.SetText(ci.Path)
	}
	f.show("Unmount it", func() {
		t := target.Path()
		if t == "" {
			f.fail("Choose the disk file, or the folder its files are in.")
			return
		}
		var info svrpc.ContainerInfo
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			abs, err := filepath.Abs(t)
			if err != nil {
				return err
			}
			info, err = c.CloseContainer(ctx, abs)
			return err
		}, func() {
			m.say("%s", svops.ContainerClosed(info.Path))
			m.refreshDisks(p)
		})
	})
}

// copyMountPoint copies where the disk selected is open, for a file
// manager or a terminal.
func (m *Manager) copyMountPoint(p *disksPage) {
	ci := p.container()
	if ci == nil || ci.MountPoint == "" {
		m.say("Open a disk first.")
		return
	}
	m.copyValue([]byte(ci.MountPoint), "The folder's path", "")
}

// backupHeader writes a disk image's header to a file (the CLI's
// container header-backup, svcontainer.BackupHeader): the one selected,
// or any image named. It needs no vault.
func (m *Manager) backupHeader(p *disksPage) {
	f := m.newForm("Back up a disk's header")
	f.intro(svops.HeaderBackupAbout)
	image := f.path("Disk file", PickOpen, "")
	if ci := p.container(); ci != nil {
		image.field.SetText(ci.Path)
	}
	out := f.path("Copy it to", PickSave, "")
	out.field.Placeholder = "Optional: a new file"
	f.warn(svops.HeaderBackupWarning)
	f.show("Copy the header", func() {
		src, dst := image.Path(), out.Path()
		if dst == "" && src != "" {
			dst = src + ".header"
		}
		if src == "" {
			f.fail("Choose the disk file.")
			return
		}
		// A new file, never over one that is there (svcontainer says so).
		f.work(func() error { return svcontainer.BackupHeader(src, dst) }, func() {
			m.say("%s", svops.HeaderBackedUp(src, dst))
		})
	})
}

// containerPassphrase gives a disk a passphrase keyslot, changes it, or
// removes it (the CLI's container passwd): the one selected, or any image
// named, with the item of the vault that holds its key.
func (m *Manager) containerPassphrase(p *disksPage) {
	vaults := m.keyVaults()
	if len(vaults) == 0 {
		m.noVaultForDisk()
		return
	}
	f := m.newForm("A disk's own passphrase")
	f.intro(svops.ContainerPassphraseAbout)
	image := f.path("Disk file", PickOpen, "")
	in := m.vault
	ci := p.container()
	if ci != nil {
		in = ci.Vault
	}
	vault := vaultChoice(f, "Its key is in vault", vaults, in)
	item := f.text("In the item", "", "default: the one made with it")
	if ci != nil {
		image.field.SetText(ci.Path)
		item.SetText(ci.Item)
	}
	remove := f.check("Remove its passphrase instead", false)
	newPass := f.newPassphrase("New passphrase")
	f.show("Set the passphrase", func() {
		path := image.Path()
		if path == "" {
			f.fail("Choose the disk file.")
			return
		}
		params := svrpc.ContainerPasswdParams{Vault: vault(), Item: strings.TrimSpace(item.Text), Remove: remove.Checked}
		if !remove.Checked {
			pass, ok := newPass()
			if !ok {
				return
			}
			params.Passphrase = pass
		}
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			abs, err := svops.ExistingImage(path)
			if err != nil {
				return err
			}
			params.Path = abs
			_, err = c.ContainerPasswd(ctx, params)
			return err
		}, func() {
			m.say("%s", svops.ContainerPassphraseDone(path, params.Remove))
			m.refreshDisks(p)
		}, params.Passphrase)
	})
	// The button says which it does.
	remove.OnChange = func(on bool) {
		f.accept.Text = "Set the passphrase"
		if on {
			f.accept.Text = "Remove the passphrase"
		}
		f.accept.RequestLayout()
	}
}

// deleteContainer deletes the disk picked, its file and its key (the
// CLI's container delete), once the person says so: the key goes to the
// vault's deleted items, so a copy of the file kept elsewhere can still
// be opened. A mounted disk is unmounted first.
func (m *Manager) deleteContainer(p *disksPage) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a disk first.")
		return
	}
	if ci.State == "mounted" || ci.State == "unlocked" || ci.State == "attached" {
		m.say("Unmount %s first: its files are in use.", filepath.Base(ci.Path))
		return
	}
	disk := *ci
	m.confirm(svops.DeleteDiskTitle(disk.Path), svops.DeleteDiskText(disk.Path, disk.Vault), svops.DeleteDiskAction, func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.DeleteContainer(ctx, svrpc.ContainerDeleteParams{Vault: disk.Vault, Item: disk.Item, Path: disk.Path})
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("%s", svops.DiskDeleted(disk.Path, disk.Vault))
			m.refreshDisks(p)
		})
	})
}

// noVaultForDisk says, in a dialog, that a disk needs a vault to keep its
// key, and offers to make one.
func (m *Manager) noVaultForDisk() {
	var d *dialog
	body := m.paragraph("A disk's key is kept in a vault, and there is no vault yet. Make one first; the disk's key then goes in it.")
	create := newButton("New vault…", func() {
		d.Close()
		m.newVault()
	})
	cancel := newButton("Cancel", func() { d.Close() })
	d = m.showDialog("A vault is needed", body, widgets.NewButtonBox().AddButton(create, widgets.RoleAccept).AddButton(cancel, widgets.RoleReject), create, nil)
}

// showDiskOf brings the Disk tab forward with the disk whose key is item
// of vault picked.
func (m *Manager) showDiskOf(vault, item string) {
	m.wantDisk = [2]string{vault, item}
	m.showDisks()
}

// showItemOf brings the Vault tab forward at Disk keys, with item of
// vault picked: a disk's key.
func (m *Manager) showItemOf(vault, item string) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	m.showSection(secVaults)
	m.cursor = item
	if vault != m.vault {
		m.showVault(vault, false)
		m.cursor = item // the vault shown anew keeps no cursor
	}
	m.showVaultTab(vtDiskKeys)
	m.drawItems()
	m.closeItem()
}
