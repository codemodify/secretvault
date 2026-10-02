package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Encrypted containers: LUKS2 image files, mounted as disks, whose keys
// are items of the vault. Making one, opening (mounting) and closing it,
// backing up its header, and giving it a passphrase of its own.

func (m *Manager) fillContainers(p *vaultPage, pn *pane) {
	var list []svrpc.ContainerInfo
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		list, err = c.Containers(ctx, p.vault)
		return err
	}, func() widget.Component {
		p.boxes = list
		p.ctable = table("Containers", []widgets.TableColumn{
			{Title: "Item", Width: 160}, {Title: "File"}, {Title: "State", Width: 200},
		}, len(list), func(r, c int) string {
			ci := list[r]
			switch c {
			case 0:
				return ci.Item
			case 1:
				return ci.Path
			}
			switch ci.State {
			case "mounted":
				return "open, at " + ci.MountPoint
			case "unknown":
				return "-"
			}
			return ci.State
		})
		pn.focus = p.ctable
		note := "Each container is an image file with a filesystem inside, encrypted with a key kept as an item of this vault. " +
			"Opening one mounts it, with your consent like any other use of the vault."
		if len(list) == 0 {
			note = "No containers in this vault. A container is an image file with a filesystem inside, encrypted with a key kept here."
		}
		if err := svops.MountsHere(); err != nil {
			note += " " + sentence(err.Error())
		}
		col := m.paneColumn(note, p.ctable,
			widgets.NewButton("New container…", func() { m.newContainer(p) }),
			widgets.NewButton("Open", func() { m.openContainer(p, "") }),
			widgets.NewButton("Close", func() { m.closeContainer(p) }),
			widgets.NewButton("Copy the folder's path", func() { m.copyMountPoint(p) }),
			widgets.NewButton("Passphrase…", func() { m.containerPassphrase(p) }),
			widgets.NewButton("Back up the header…", func() { m.backupHeader(p) }),
			widgets.NewButton("Open another file…", func() { m.openContainerFile(p) }))
		return col
	})
}

// container is the container selected, or nil.
func (p *vaultPage) container() *svrpc.ContainerInfo {
	i := selected(p.ctable)
	if i < 0 || i >= len(p.boxes) {
		return nil
	}
	return &p.boxes[i]
}

// newContainer makes a container (the CLI's container create).
func (m *Manager) newContainer(p *vaultPage) {
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	f := m.newForm("New container in " + p.vault)
	file := f.path("Image file", PickSave, "private.img")
	size := f.text("Size", "1G", "the whole image: 512M, 1G…")
	fs := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Its label", "", "optional: the filesystem's label")
	item := f.text("Key item", "", "default: containers/ and the file's name")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	mount := f.text("Mount options", "", "optional: noexec, nodev…")
	withPass := f.check("Also give it a passphrase, so it opens with cryptsetup alone", false)
	pass := f.secret("Passphrase", "only with the box above")
	again := f.secret("Repeat", "The same again")
	f.show("Create", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose where the image goes.")
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
		if name == "" {
			name = svops.ContainerItemName(abs)
		}
		params := svrpc.ContainerCreateParams{Vault: p.vault, Item: name, Path: abs, Size: n,
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
			msg := fmt.Sprintf("Created %s (%s, %s), open at %s; its key is the item %s.", info.Path, svops.HumanSize(n), params.FS, info.MountPoint, info.Item)
			if len(params.Passphrase) > 0 {
				msg += " The passphrase also opens it, with cryptsetup alone."
			}
			m.say("%s", msg)
			m.refreshTab(p, tabContainers)
		}, params.Passphrase)
	})
}

// openContainer mounts the container selected, or the image at path (the
// CLI's container open), and says where.
func (m *Manager) openContainer(p *vaultPage, item string) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a container first.")
		return
	}
	m.mountImage(p, ci.Path, ci.Item, "")
}

// mountImage mounts the image at path with the key in item ("" for the one
// made for it).
func (m *Manager) mountImage(p *vaultPage, path, item, opts string) {
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
		info, err = c.OpenContainer(ctx, svrpc.ContainerOpenParams{Vault: p.vault, Item: item, Path: abs, MountOptions: opts})
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.say("Opened %s at %s.", info.Path, info.MountPoint)
		m.refreshTab(p, tabContainers)
	})
}

// openContainerFile mounts an image chosen, with the key in an item named
// or the one made for it.
func (m *Manager) openContainerFile(p *vaultPage) {
	f := m.newForm("Open a container")
	file := f.path("Image file", PickOpen, "")
	item := f.text("Key item", "", "default: the item made for this image")
	opts := f.text("Mount options", "", "optional: ro, noexec…")
	f.show("Open", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the image.")
			return
		}
		f.close()
		m.mountImage(p, path, strings.TrimSpace(item.Text), strings.TrimSpace(opts.Text))
	})
}

// closeContainer unmounts the container selected (the CLI's container
// close).
func (m *Manager) closeContainer(p *vaultPage) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a container first.")
		return
	}
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	target := ci.Path
	var info svrpc.ContainerInfo
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		info, err = c.CloseContainer(ctx, target)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.say("Closed %s.", info.Path)
		m.refreshTab(p, tabContainers)
	})
}

// copyMountPoint copies where the container selected is open, for a file
// manager or a terminal.
func (m *Manager) copyMountPoint(p *vaultPage) {
	ci := p.container()
	if ci == nil || ci.MountPoint == "" {
		m.say("Open a container first.")
		return
	}
	m.copyValue([]byte(ci.MountPoint), "The folder's path", "")
}

// backupHeader writes the header of the container selected to a file
// (the CLI's container header-backup, svcontainer.BackupHeader).
func (m *Manager) backupHeader(p *vaultPage) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a container first.")
		return
	}
	src := ci.Path
	m.pickFile(PickSave, filepath.Base(src)+".header", func(out string) {
		if out == "" {
			return
		}
		m.work(func() error { return svcontainer.BackupHeader(src, out) }, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.showText("Header backed up", fmt.Sprintf("Wrote %s's header to %s. Keep it as safe as the key: with it, any key or passphrase "+
				"that opens the container today opens it later, even after that keyslot is gone.", src, out), "")
		})
	})
}

// containerPassphrase gives the container selected a passphrase keyslot,
// changes it, or removes it (the CLI's container passwd).
func (m *Manager) containerPassphrase(p *vaultPage) {
	ci := p.container()
	if ci == nil {
		m.say("Choose a container first.")
		return
	}
	path, item := ci.Path, ci.Item
	f := m.newForm("Passphrase of " + filepath.Base(path))
	f.note("A passphrase keyslot of its own opens the container with cryptsetup alone, without secretvault.")
	remove := f.check("Remove its passphrase instead: only the vault's key opens it then", false)
	newPass := f.newPassphrase("New passphrase")
	f.show("Change", func() {
		params := svrpc.ContainerPasswdParams{Vault: p.vault, Item: item, Remove: remove.Checked}
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
			if params.Remove {
				m.say("Removed the passphrase of %s; only the vault's key opens it now.", path)
			} else {
				m.say("%s opens with the new passphrase (and cryptsetup alone).", path)
			}
			m.refreshTab(p, tabContainers)
		}, params.Passphrase)
	})
}
