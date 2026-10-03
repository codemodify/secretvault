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
			{Title: "Key item", Width: 160}, {Title: "Container file"}, {Title: "State", Width: 200},
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
				return "open, in " + ci.MountPoint
			case "unknown":
				return "-"
			}
			return ci.State
		})
		pn.focus = p.ctable
		note := svops.ContainersAbout
		if len(list) == 0 {
			note = svops.ContainersNone + " New container… makes one."
		}
		if err := svops.MountsHere(); err != nil {
			note += " " + sentence(err.Error())
		}
		col := m.paneColumn(note, p.ctable,
			widgets.NewButton("New container…", func() { m.newContainer(p) }),
			widgets.NewButton("Open", func() { m.openContainer(p, "") }),
			widgets.NewButton("Close…", func() { m.closeContainer(p) }),
			widgets.NewButton("Copy the folder's path", func() { m.copyMountPoint(p) }),
			widgets.NewButton("Its own passphrase…", func() { m.containerPassphrase(p) }),
			widgets.NewButton("Back up the header…", func() { m.backupHeader(p) }),
			widgets.NewButton("Open a container file…", func() { m.openContainerFile(p) }))
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
	f.intro(svops.ContainerNewAbout)
	file := f.path("Container file", PickSave, "private.img")
	size := f.text("Size", "1G", "how much it holds: 512M, 1G…")
	fs := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Disk name", "", "optional: what file managers call it")
	item := f.text("Keep its key in", "", "default: an item named after the file")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	mount := f.text("Mount options", "", "optional, for experts: noexec, nodev…")
	withPass := f.check("Also give it a passphrase, to open it without secretvault", false)
	pass := f.secret("Passphrase", "only with the box below ticked")
	again := f.secret("Repeat", "The same again")
	f.show("Make the container", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose where the container file goes.")
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
			m.say("%s", svops.ContainerCreated(info.Path, svops.HumanSize(n), params.FS, info.MountPoint, info.Item, len(params.Passphrase) > 0))
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
		m.say("%s", svops.ContainerOpened(info.Path, info.MountPoint))
		m.refreshTab(p, tabContainers)
	})
}

// openContainerFile mounts an image chosen, with the key in an item named
// or the one made for it.
func (m *Manager) openContainerFile(p *vaultPage) {
	f := m.newForm("Open a container")
	f.intro(svops.ContainerOpenAbout)
	file := f.path("Container file", PickOpen, "")
	item := f.text("Its key is in", "", "an item; default: the one made with it")
	opts := f.text("Mount options", "", "optional, for experts: ro, noexec…")
	f.show("Open it", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the container file.")
			return
		}
		f.close()
		m.mountImage(p, path, strings.TrimSpace(item.Text), strings.TrimSpace(opts.Text))
	})
}

// closeContainer unmounts a container (the CLI's container close): the
// one selected, or any image or mount point named.
func (m *Manager) closeContainer(p *vaultPage) {
	if err := svops.MountsHere(); err != nil {
		m.fail(err)
		return
	}
	f := m.newForm("Close a container")
	f.intro(svops.ContainerCloseAbout)
	target := f.path("Container file or its folder", PickOpen, "")
	if ci := p.container(); ci != nil {
		target.field.SetText(ci.Path)
	}
	f.show("Close it", func() {
		t := target.Path()
		if t == "" {
			f.fail("Choose the container file, or the folder its files are in.")
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
			m.refreshTab(p, tabContainers)
		})
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

// backupHeader writes a container image's header to a file (the CLI's
// container header-backup, svcontainer.BackupHeader): the one selected,
// or any image named. It needs no vault.
func (m *Manager) backupHeader(p *vaultPage) {
	f := m.newForm("Back up a container's header")
	f.intro(svops.HeaderBackupAbout)
	image := f.path("Container file", PickOpen, "")
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
			f.fail("Choose the container file.")
			return
		}
		// A new file, never over one that is there (svcontainer says so).
		f.work(func() error { return svcontainer.BackupHeader(src, dst) }, func() {
			m.say("%s", svops.HeaderBackedUp(src, dst))
		})
	})
}

// containerPassphrase gives a container a passphrase keyslot, changes it,
// or removes it (the CLI's container passwd): the one selected, or any
// image named, with the item that holds its key.
func (m *Manager) containerPassphrase(p *vaultPage) {
	f := m.newForm("A container's own passphrase")
	f.intro(svops.ContainerPassphraseAbout)
	image := f.path("Container file", PickOpen, "")
	item := f.text("Its key is in", "", "an item; default: the one made with it")
	if ci := p.container(); ci != nil {
		image.field.SetText(ci.Path)
		item.SetText(ci.Item)
	}
	remove := f.check("Remove its passphrase instead", false)
	newPass := f.newPassphrase("New passphrase")
	f.show("Set the passphrase", func() {
		path := image.Path()
		if path == "" {
			f.fail("Choose the container file.")
			return
		}
		params := svrpc.ContainerPasswdParams{Vault: p.vault, Item: strings.TrimSpace(item.Text), Remove: remove.Checked}
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
			m.refreshTab(p, tabContainers)
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
