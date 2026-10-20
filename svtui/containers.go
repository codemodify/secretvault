package svtui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The Disk tab (2, or M): encrypted disks (the CLI's containers), LUKS2
// image files on this computer's drive whose keys are vault items
// ('secretvault container'). On the left, every vault's disks
// ('secretvault container ls --all'): an unlocked vault's with the items
// that keep their keys, a locked one's by file only, as the daemon last
// saw them, without unlocking it; on the right, the disk selected: its
// file, size, key, state, LUKS UUID and own passphrase, and what can be
// done to it. Making one, mounting and unmounting it, backing its header
// up, its own passphrase and deleting it, each on the vault that keeps
// the row's key (a locked one asks for its passphrase first).
//
// The keys: n a new disk; m mounts the disk selected, u unmounts it; f
// mounts any disk file, F unmounts one by its file or folder; b backs its
// header up, p its own passphrase, x (or Delete) deletes it; U unlocks a
// locked vault's disk's vault; r refreshes.

// newDisksTab makes the Disk tab's panel, the list beside the selected
// disk's details; showTab fills it.
func (u *UI) newDisksTab() *panel {
	p := u.newPanel("Encrypted disks", "FILE", "KEY KEPT IN", "STATE")
	p.reload = func() { u.loadDisks(p) }
	isOpen := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && diskInUse(ci)
	}
	isClosed := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && !isOpen(ci) && ci.State != "missing"
	}
	isThere := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && ci.State != "missing"
	}
	isLocked := func(ref any) bool {
		ci, ok := ref.(svrpc.ContainerInfo)
		return ok && ci.Locked
	}
	p.act('n', "New disk…", func() { u.newContainer(u.vault, p.refresh) })
	p.rowAct('m', "Mount it…", isClosed, func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.openContainer(ci.Vault, ci.Path, ci.Item, p.refresh)
	})
	p.rowAct('u', "Unmount it", isOpen, func(ref any) { u.closeContainer(ref.(svrpc.ContainerInfo).Path, p.refresh) })
	p.act('f', "Mount a disk file…", func() { u.openContainer(u.vault, "", "", p.refresh) })
	p.act('F', "Unmount one by its file or folder…", func() { u.closeContainerAsk(p.refresh) })
	p.rowAct('b', "Back up its header…", isThere, func(ref any) { u.backupHeader(ref.(svrpc.ContainerInfo).Path) })
	p.rowAct('p', "Its own passphrase…", isThere, func(ref any) {
		ci := ref.(svrpc.ContainerInfo)
		u.containerPassphrase(ci.Vault, ci.Path, ci.Item)
	})
	p.rowAct('x', "Delete…", isThere, func(ref any) { u.deleteDisk(ref.(svrpc.ContainerInfo), p.refresh) })
	p.rowAct('U', "Unlock its vault", isLocked, func(ref any) { u.unlockDiskVault(ref.(svrpc.ContainerInfo).Vault) })
	p.act('r', "Refresh", p.refresh)
	p.embed()

	// The disk selected, beside the list. It never takes the focus: the
	// keys are the list's.
	u.diskDetail = tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	u.diskDetail.SetBorder(true).SetTitle(" Disk ").SetBorderPadding(0, 0, 1, 1)
	u.diskDetail.SetFocusFunc(func() { u.app.SetFocus(p.t) })
	panes := tview.NewFlex().
		AddItem(p.t, 0, 3, true).
		AddItem(tview.NewBox(), 1, 0, false).
		AddItem(u.diskDetail, 0, 2, false)
	p.frame.Clear().SetDirection(tview.FlexRow).
		AddItem(p.head, 0, 0, false).
		AddItem(panes, 0, 1, true).
		AddItem(p.foot, 1, 0, false)
	p.setHead("")
	p.drawFoot()
	p.t.SetSelectionChangedFunc(func(int, int) { u.drawDiskDetail() })
	u.drawDiskDetail()
	return p
}

// showDisks brings the Disk tab forward (M), its disks asked for again.
func (u *UI) showDisks() { u.showTab(tabDisks) }

// refreshDisks asks for the disks again, if the Disk tab is up.
func (u *UI) refreshDisks() {
	if u.tab == tabDisks {
		u.disks.refresh()
	}
}

// loadDisks fills the Disk tab: every vault's disks, as the daemon knows
// them ('secretvault container ls --all'). A locked vault's are listed by
// file, as the daemon last saw them, without unlocking it; the locked
// vaults are named under the list.
func (u *UI) loadDisks(p *panel) {
	u.disksGen++
	gen := u.disksGen
	var list []svrpc.ContainerInfo
	var locked []string
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		vs, err := c.Vaults(ctx)
		if err != nil {
			return err
		}
		for _, v := range vs {
			if v.ID != "" && v.Locked {
				locked = append(locked, v.Name)
			}
		}
		list, err = c.KnownContainers(ctx)
		return err
	}, func(err error) {
		if gen != u.disksGen {
			return // asked again since
		}
		p.clear()
		if err != nil {
			u.fail(err)
			p.setHead("[red]" + tview.Escape(u.describe(err)) + "[-]")
			p.done()
			u.drawDiskDetail()
			return
		}
		head := tview.Escape(svops.ContainersAbout)
		if len(list) == 0 {
			head = tview.Escape(svops.ContainersNone + " n makes one.")
		}
		if len(locked) > 0 {
			head += "\n" + tview.Escape(svops.DisksLockedSeen+strings.Join(locked, ", ")+".")
		}
		if err := svops.MountsHere(); err != nil {
			head += "\n[yellow]" + tview.Escape(sentence(err.Error())) + "[-] The list and header backups still work."
		}
		p.setHead(head)
		for _, ci := range list {
			vault := ci.Vault
			if ci.Locked {
				vault += " (locked)"
			}
			p.row(ci, filepath.Base(ci.Path), vault, diskState(ci))
		}
		p.done()
		u.drawDiskDetail()
	})
}

// diskInUse reports whether a disk is attached, unlocked or mounted: in
// use, so not to be mounted again, nor deleted.
func diskInUse(ci svrpc.ContainerInfo) bool {
	return ci.State == "mounted" || ci.State == "unlocked" || ci.State == "attached"
}

// diskState is a disk's state, in words.
func diskState(ci svrpc.ContainerInfo) string {
	switch ci.State {
	case "mounted":
		return "mounted, in " + ci.MountPoint
	case "closed":
		return "not mounted"
	case "unlocked":
		return "unlocked, not mounted"
	case "attached":
		return "attached, locked"
	case "missing":
		return "file not there"
	case "unknown":
		return "-"
	}
	return ci.State
}

// drawDiskDetail shows the disk selected on the Disk tab: its file and
// folder, its size, the vault and item that keep its key, its state, its
// LUKS UUID, whether it has a passphrase of its own, and what can be done
// to it.
func (u *UI) drawDiskDetail() {
	if u.diskDetail == nil {
		return
	}
	var ci svrpc.ContainerInfo
	ok := false
	if u.disks != nil {
		ci, ok = u.disks.selected().(svrpc.ContainerInfo)
	}
	if !ok {
		u.diskDetail.SetTitle(" Disk ")
		u.diskDetail.SetText("[gray]No disk chosen.[-]\n\nChoose one on the left to see it here, and what can be done to it.")
		return
	}
	u.diskDetail.SetTitle(" " + tview.Escape(filepath.Base(ci.Path)) + " ")
	var b strings.Builder
	line := func(label, value string) {
		b.WriteString("[gray]" + label + ":[-] " + tview.Escape(value) + "\n")
	}
	line("File", filepath.Base(ci.Path))
	line("In the folder", filepath.Dir(ci.Path))
	if st, err := os.Stat(ci.Path); err == nil {
		line("Size", svops.HumanSize(st.Size()))
	} else if errors.Is(err, os.ErrNotExist) {
		line("Size", svops.DiskMissing)
	}
	switch {
	case ci.Locked:
		line("Its key is kept in", "vault "+ci.Vault+", which is locked")
	case ci.Item == "":
		line("Its key is kept in", "vault "+ci.Vault)
	default:
		line("Its key is kept in", "vault "+ci.Vault+", item "+ci.Item)
	}
	state := diskState(ci)
	switch ci.State {
	case "mounted":
		state = "mounted: its files are in " + ci.MountPoint
	case "missing":
		state = svops.DiskMissing
	case "unknown":
		state = "not known here"
	}
	line("State", state)
	if ci.UUID != "" {
		line("Disk ID (LUKS UUID)", ci.UUID)
	}
	if ci.Locked {
		b.WriteString("\n[yellow]" + tview.Escape(svops.DiskVaultLocked(ci.Vault)) + "[-] U unlocks it.\n")
	} else {
		own := "none; only the key kept in the vault opens it"
		if ci.Passphrase {
			own = "yes; it also opens without secretvault, with cryptsetup"
		}
		line("A passphrase of its own", own)
	}
	b.WriteString("\n[::b]What you can do[::-]\n")
	for _, a := range u.disks.acts {
		if a.on != nil && a.on(ci) {
			b.WriteString(fmt.Sprintf("  [yellow]%c[-]  %s\n", a.key, tview.Escape(a.label)))
		}
	}
	u.diskDetail.SetText(b.String())
	u.diskDetail.ScrollToBeginning()
}

// deleteDisk is 'secretvault container delete FILE': the disk's file goes
// for good, its key to the deleted items, once the person says so. A disk
// in use is said to be, instead of asked about.
func (u *UI) deleteDisk(ci svrpc.ContainerInfo, then func()) {
	if diskInUse(ci) {
		u.say("%s is in use: unmount it first (u on the Disk tab), then delete it.", filepath.Base(ci.Path))
		return
	}
	u.confirm(svops.DeleteDiskTitle(ci.Path), svops.DeleteDiskText(ci.Path, ci.Vault), svops.DeleteDiskAction, func() {
		var info svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			info, err = c.DeleteContainer(ctx, svrpc.ContainerDeleteParams{Vault: ci.Vault, Item: ci.Item, Path: ci.Path})
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("%s", svops.DiskDeleted(info.Path, info.Vault))
			if then != nil {
				then()
			}
		})
	})
}

// deleteDiskAsk is the ':' menu's Delete a disk…: the disk selected on
// the Disk tab, or else a disk file named, its key in a vault chosen.
func (u *UI) deleteDiskAsk() {
	if u.tab == tabDisks {
		if ci, ok := u.disks.selected().(svrpc.ContainerInfo); ok {
			u.deleteDisk(ci, u.refreshDisks)
			return
		}
	}
	if !u.needVault() {
		return
	}
	f := u.newForm("Delete a disk", "Name the disk file to delete; you are asked before anything goes.")
	file := f.path("Disk file", "", "")
	keptIn := u.vaultChoice(f, "Its key is in vault", u.vault)
	it := f.text("In the item", "", "default: the one made with it")
	f.show("Next", func() string {
		abs, err := svops.ExistingImage(filePath(file))
		if err != nil {
			return err.Error()
		}
		ci := svrpc.ContainerInfo{Vault: keptIn(), Item: trimmed(it), Path: abs, State: "unknown"}
		// Whether it is in use, as the daemon knows: without unlocking
		// the vault, which deleting it asks for in its turn.
		var list []svrpc.ContainerInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			list, err = c.KnownContainers(ctx)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			for _, l := range list {
				if svcontainer.Canonical(l.Path) == svcontainer.Canonical(abs) && (ci.Item == "" || l.Item == "" || l.Item == ci.Item) {
					ci.State, ci.MountPoint = l.State, l.MountPoint
				}
			}
			u.deleteDisk(ci, u.refreshDisks)
		})
		return ""
	})
}

// vaultChoice adds to f a choice of the vaults there, at want; it returns
// the vault chosen. A locked one is said to be: choosing it asks for its
// passphrase.
func (u *UI) vaultChoice(f *formDialog, label, want string) func() string {
	var names, labels []string
	at := 0
	for _, v := range u.vaults {
		if v.ID == "" {
			continue
		}
		if v.Name == want {
			at = len(names)
		}
		text := v.Name
		if v.Locked {
			text += " (locked)"
		}
		names, labels = append(names, v.Name), append(labels, text)
	}
	if len(names) == 0 && want != "" {
		names, labels = []string{want}, []string{want}
	}
	d := f.choice(label, labels, at)
	return func() string {
		i, _ := d.GetCurrentOption()
		if i < 0 || i >= len(names) {
			return ""
		}
		return names[i]
	}
}

// newContainer is 'secretvault container create FILE': its key in a
// vault chosen, vault first.
func (u *UI) newContainer(vault string, then func()) {
	if !u.needVault() {
		return
	}
	f := u.newForm("New disk", svops.ContainerNewAbout+" A passphrase of its own, if you give one, opens it without secretvault too.")
	keptIn := u.vaultChoice(f, "Keep its key in vault", vault)
	path := f.path("Disk file", "", "a new file, like ~/private.img")
	size := f.text("Size", "", "like 512M or 1G")
	fsType := f.choice("Filesystem", svcontainer.Filesystems, 0)
	label := f.text("Disk name", "", "for file managers (optional)")
	item := f.text("In the item", "", "default: named after the file")
	pass := f.secret("Its own passphrase")
	again := f.secret("Repeat it")
	sector := f.choice("Sector size", []string{"4096", "512"}, 0)
	opts := f.text("Mount options", "", "for experts (optional)")
	f.show("Make the disk", func() string {
		if err := svops.MountsHere(); err != nil {
			return err.Error()
		}
		if filePath(path) == "" {
			return "Give the new disk file's path."
		}
		vault := keptIn()
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

// openContainer is 'secretvault container open FILE', Mount: the disk at
// path, its key in vault (a row of the Disk tab); or, path "", a disk
// file chosen, its key in a vault chosen (vault first).
func (u *UI) openContainer(vault, path, item string, then func()) {
	if !u.needVault() {
		return
	}
	f := u.newForm("Mount a disk file", svops.ContainerOpenAbout)
	file := f.path("Disk file", path, "")
	keptIn := func() string { return vault }
	if path == "" {
		keptIn = u.vaultChoice(f, "Its key is in vault", vault)
	}
	it := f.text("In the item", item, "default: the one made with it")
	opts := f.text("Mount options", "", "for experts, like ro (optional)")
	f.show("Mount it", func() string {
		if err := svops.MountsHere(); err != nil {
			return err.Error()
		}
		abs, err := svops.ExistingImage(filePath(file))
		if err != nil {
			return err.Error()
		}
		p := svrpc.ContainerOpenParams{Vault: keptIn(), Item: trimmed(it), Path: abs, MountOptions: trimmed(opts)}
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

// closeContainer is 'secretvault container close FILE|MOUNTPOINT', Unmount.
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
	f := u.newForm("Unmount a disk", svops.ContainerCloseAbout)
	target := f.path("Disk file or its folder", "", "")
	f.show("Unmount it", func() string {
		t := filePath(target)
		if t == "" {
			return "Give the disk file, or the folder its files are in."
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

// unlockDiskVault unlocks the vault that keeps a disk's key (U on a
// locked vault's disk); the daemon asks for its passphrase. Its disks are
// then listed with their keys' items.
func (u *UI) unlockDiskVault(vault string) {
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, nil)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			u.reloadVaults()
			return
		}
		u.say("Unlocked %s", vault)
		u.reloadVaults()
		u.refreshDisks()
	})
}
