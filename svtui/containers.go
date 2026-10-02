package svtui

import (
	"context"
	"path/filepath"
	"strconv"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The containers panel (M): encrypted containers, LUKS2 image files whose
// keys are vault items ('secretvault container'): making one, opening
// (mounting) and closing it, backing its header up, and its own
// passphrase.

func (u *UI) showContainers() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Containers · "+vault, "ITEM", "FILE", "STATE")
	p.vault = vault
	p.setHead("Encrypted containers: image files mounted as disks, whose keys are kept in the vault. Opening one asks, as reading an item does.")
	if err := svops.MountsHere(); err != nil {
		p.setHead("[yellow]" + tview.Escape(sentence(err.Error())) + "[-] The list and header backups still work.")
	}
	p.reload = func() {
		var list []svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			list, err = c.Containers(ctx, vault)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			if len(list) == 0 {
				p.none("None (n makes one).")
			}
			for _, ci := range list {
				state := ci.State
				switch ci.State {
				case "mounted":
					state = "mounted at " + ci.MountPoint
				case "unknown":
					state = "-"
				}
				p.row(ci, ci.Item, ci.Path, state)
			}
			p.done()
		})
	}
	isOpen := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && ci.State != "closed" && ci.State != "unknown"
	}
	isClosed := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && !isOpen(ci)
	}
	p.act('n', "New container…", func() { u.newContainer(vault, p.refresh) })
	p.rowAct('o', "Open (mount) it…", isClosed, func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.openContainer(vault, ci.Path, ci.Item, p.refresh)
	})
	p.act('O', "Open an image…", func() { u.openContainer(vault, "", "", p.refresh) })
	p.rowAct('c', "Close it", isOpen, func(ref any) { u.closeContainer(ref.(svrpc.ContainerInfo).Path, p.refresh) })
	p.act('C', "Close by file or mount point…", func() { u.closeContainerAsk(p.refresh) })
	p.rowAct('b', "Back up its header…", is[svrpc.ContainerInfo], func(ref any) { u.backupHeader(ref.(svrpc.ContainerInfo).Path) })
	p.rowAct('p', "Its own passphrase…", is[svrpc.ContainerInfo], func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.containerPassphrase(vault, ci.Path, ci.Item)
	})
	p.show()
}

// newContainer is 'secretvault container create FILE'.
func (u *UI) newContainer(vault string, then func()) {
	f := u.newForm("New container in "+vault, "A new image file, of the size given in all, with a filesystem inside, mounted; its key is kept in an item. A passphrase of its own, if given, opens it with cryptsetup alone.")
	path := f.path("File", "", "a new image file")
	size := f.text("Size", "", "like 512M or 1G")
	fsType := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Label", "", "the filesystem's (optional)")
	item := f.text("Item", "", "default: containers/ and the file's name")
	pass := f.secret("Its own passphrase")
	again := f.secret("Repeat it")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	opts := f.text("Mount options", "", "like noexec (optional)")
	f.show("Create", func() string {
		if err := svops.MountsHere(); err != nil {
			return err.Error()
		}
		if filePath(path) == "" {
			return "Give the new image's path."
		}
		n, err := svops.ParseSize(trimmed(size))
		if err != nil {
			return err.Error()
		}
		abs, err := filepath.Abs(filePath(path))
		if err != nil {
			return err.Error()
		}
		p := svrpc.ContainerCreateParams{Vault: vault, Item: trimmed(item), Path: abs, Size: n, FS: option(fsType), Label: trimmed(label), MountOptions: trimmed(opts)}
		p.SectorSize, _ = strconv.Atoi(option(sector))
		if p.Item == "" {
			p.Item = svops.ContainerItemName(abs)
		}
		if len(pass.buf) > 0 {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			p.Passphrase = pass.value()
		}
		var info svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(p.Passphrase)
			info, err = c.CreateContainer(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			also := ""
			if p.Passphrase != nil {
				also = "; the passphrase also opens it, with cryptsetup alone"
			}
			u.say("Created %s (%s, %s), mounted at %s; its key is the item %s%s", info.Path, svops.HumanSize(n), p.FS, info.MountPoint, info.Item, also)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// openContainer is 'secretvault container open FILE'.
func (u *UI) openContainer(vault, path, item string, then func()) {
	f := u.newForm("Open a container", "It is mounted with the key kept in the vault.")
	file := f.path("File", path, "the image file")
	it := f.text("Item", item, "default: the one made for this image")
	opts := f.text("Mount options", "", "like ro or noexec (optional)")
	f.show("Open", func() string {
		if err := svops.MountsHere(); err != nil {
			return err.Error()
		}
		abs, err := svops.ExistingImage(filePath(file))
		if err != nil {
			return err.Error()
		}
		p := svrpc.ContainerOpenParams{Vault: vault, Item: trimmed(it), Path: abs, MountOptions: trimmed(opts)}
		var info svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			info, err = c.OpenContainer(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Opened %s at %s", info.Path, info.MountPoint)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// closeContainer is 'secretvault container close FILE|MOUNTPOINT'.
func (u *UI) closeContainer(target string, then func()) {
	if err := svops.MountsHere(); err != nil {
		u.fail(err)
		return
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		u.fail(err)
		return
	}
	var info svrpc.ContainerInfo
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		info, err = c.CloseContainer(ctx, abs)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.say("Closed %s", info.Path)
		if then != nil {
			then()
		}
	})
}

func (u *UI) closeContainerAsk(then func()) {
	f := u.newForm("Close a container", "")
	target := f.path("File or mount point", "", "")
	f.show("Close", func() string {
		t := filePath(target)
		if t == "" {
			return "Give the image file, or where it is mounted."
		}
		u.closeContainer(t, then)
		return ""
	})
}

// backupHeader is 'secretvault container header-backup FILE OUT'
// (svcontainer.BackupHeader: it needs no key).
func (u *UI) backupHeader(path string) {
	f := u.newForm("Back up the header of "+filepath.Base(path), "Keep it as safe as the key: with it, any key or passphrase that opens the container today opens it later, even after that keyslot is gone.")
	out := f.path("To the new file", "", "")
	f.show("Back up", func() string {
		dst := filePath(out)
		if dst == "" {
			return "Give the new file's path."
		}
		if err := svcontainer.BackupHeader(path, dst); err != nil {
			return err.Error()
		}
		u.say("Wrote %s's header to %s", path, dst)
		return ""
	})
}

// containerPassphrase is 'secretvault container passwd FILE [--remove]'.
func (u *UI) containerPassphrase(vault, path, item string) {
	f := u.newForm("The passphrase of "+filepath.Base(path), "A passphrase of the container's own opens it with cryptsetup alone, without secretvault. Set or change it, or remove it.")
	remove := f.check("Remove it: only the vault's key opens it", false)
	pass := f.secret("New passphrase")
	again := f.secret("Repeat it")
	f.show("Change", func() string {
		p := svrpc.ContainerPasswdParams{Vault: vault, Item: item, Path: path, Remove: remove.IsChecked()}
		if !p.Remove {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			p.Passphrase = pass.value()
		}
		var info svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(p.Passphrase)
			info, err = c.ContainerPasswd(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if p.Remove {
				u.say("Removed the passphrase keyslot of %s; only the vault's key opens it now", info.Path)
			} else {
				u.say("%s opens with the new passphrase (and cryptsetup alone)", info.Path)
			}
		})
		return ""
	})
}
