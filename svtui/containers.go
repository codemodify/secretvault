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
	p := u.newPanel("Containers · "+vault, "KEY ITEM", "CONTAINER FILE", "STATE")
	p.vault = vault
	p.setHead(tview.Escape(svops.ContainersAbout))
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
				p.none("None yet: n makes one.")
			}
			for _, ci := range list {
				state := ci.State
				switch ci.State {
				case "mounted":
					state = "open, in " + ci.MountPoint
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
	p.rowAct('o', "Open it…", isClosed, func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.openContainer(vault, ci.Path, ci.Item, p.refresh)
	})
	p.act('O', "Open a container file…", func() { u.openContainer(vault, "", "", p.refresh) })
	p.rowAct('c', "Close it", isOpen, func(ref any) { u.closeContainer(ref.(svrpc.ContainerInfo).Path, p.refresh) })
	p.act('C', "Close one by its file or folder…", func() { u.closeContainerAsk(p.refresh) })
	p.rowAct('b', "Back up its header…", is[svrpc.ContainerInfo], func(ref any) { u.backupHeader(ref.(svrpc.ContainerInfo).Path) })
	p.rowAct('p', "Its own passphrase…", is[svrpc.ContainerInfo], func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.containerPassphrase(vault, ci.Path, ci.Item)
	})
	p.show()
}

// newContainer is 'secretvault container create FILE'.
func (u *UI) newContainer(vault string, then func()) {
	f := u.newForm("New container in "+vault, svops.ContainerNewAbout+" A passphrase of its own, if you give one, opens it without secretvault too.")
	path := f.path("Container file", "", "a new file, like ~/private.img")
	size := f.text("Size", "", "like 512M or 1G")
	fsType := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Disk name", "", "for file managers (optional)")
	item := f.text("Keep its key in", "", "default: named after the file")
	pass := f.secret("Its own passphrase")
	again := f.secret("Repeat it")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	opts := f.text("Mount options", "", "for experts (optional)")
	f.show("Make the container", func() string {
		if err := svops.MountsHere(); err != nil {
			return err.Error()
		}
		if filePath(path) == "" {
			return "Give the new container file's path."
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
			u.say("%s", svops.ContainerCreated(info.Path, svops.HumanSize(n), p.FS, info.MountPoint, info.Item, p.Passphrase != nil))
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// openContainer is 'secretvault container open FILE'.
func (u *UI) openContainer(vault, path, item string, then func()) {
	f := u.newForm("Open a container", svops.ContainerOpenAbout)
	file := f.path("Container file", path, "")
	it := f.text("Its key is in", item, "default: the one made with it")
	opts := f.text("Mount options", "", "for experts, like ro (optional)")
	f.show("Open it", func() string {
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
			u.say("%s", svops.ContainerOpened(info.Path, info.MountPoint))
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
		u.say("%s", svops.ContainerClosed(info.Path))
		if then != nil {
			then()
		}
	})
}

func (u *UI) closeContainerAsk(then func()) {
	f := u.newForm("Close a container", svops.ContainerCloseAbout)
	target := f.path("Container file or its folder", "", "")
	f.show("Close it", func() string {
		t := filePath(target)
		if t == "" {
			return "Give the container file, or the folder its files are in."
		}
		u.closeContainer(t, then)
		return ""
	})
}

// backupHeader is 'secretvault container header-backup FILE OUT'
// (svcontainer.BackupHeader: it needs no key).
func (u *UI) backupHeader(path string) {
	f := u.newForm("Back up the header of "+filepath.Base(path), svops.HeaderBackupAbout+"\n\n[yellow]"+tview.Escape(svops.HeaderBackupWarning)+"[-]")
	out := f.path("Copy it to", "", "a new file")
	f.show("Copy the header", func() string {
		dst := filePath(out)
		if dst == "" {
			return "Give the new file's path."
		}
		if err := svcontainer.BackupHeader(path, dst); err != nil {
			return err.Error()
		}
		u.say("%s", svops.HeaderBackedUp(path, dst))
		return ""
	})
}

// containerPassphrase is 'secretvault container passwd FILE [--remove]'.
func (u *UI) containerPassphrase(vault, path, item string) {
	f := u.newForm("A passphrase of its own for "+filepath.Base(path), svops.ContainerPassphraseAbout)
	remove := f.check("Remove it instead: only the key in the vault opens it then", false)
	pass := f.secret("New passphrase")
	again := f.secret("Repeat it")
	f.show("Set the passphrase", func() string {
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
			u.say("%s", svops.ContainerPassphraseDone(info.Path, p.Remove))
		})
		return ""
	})
	// The button says which it does.
	remove.SetChangedFunc(func(on bool) {
		label := "Set the passphrase"
		if on {
			label = "Remove the passphrase"
		}
		f.form.GetButton(0).SetLabel(label)
	})
}
