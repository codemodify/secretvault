package svd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svudisks"
)

// Encrypted containers: LUKS2 image files (svcontainer) whose keys are
// vault items of kind "container", mounted by UDisks2 on Linux. Consent is
// the vault's, as for any item:
//
//   - container.create stores a new item: a write to the vault;
//   - container.open uses the container's item as "mount", its own
//     operation: opening a container is not reading its key (item.get),
//     and a program allowed one is not allowed the other;
//   - container.passwd reads the item (a passphrase keyslot is as good as
//     the key) and changes it;
//   - container.list lists the vault;
//   - container.known lists every vault's disks: an unlocked vault's as
//     container.list does, asked the same, and a locked one's as the
//     daemon remembers them (disks_seen.go), asking nothing and unlocking
//     nothing: only their files, which any program running as you can
//     read in the daemon's data directory, and what the system says of
//     them;
//   - container.close needs none: whoever may reach UDisks2 can unmount
//     their own disks without us;
//   - container.delete deletes the image file and then the item, asked
//     as "delete" on the item, the question naming the file. It is open
//     to every program, as item.delete is: a program running as you can
//     delete your files itself, and the item goes where item.delete puts
//     it, to the vault's deleted items (so a copy of the image kept
//     elsewhere still opens once it is brought back). What the daemon
//     adds is care: it deletes only a LUKS2 image the item is the key of
//     (its UUID, or else the key opening it), never one attached as a
//     disk, and never a copy while the image the item names is there.
//
// A key goes from the vault to UDisks2 (and the kernel) and to no client.
//
// Containers stay mounted when vaults lock, as VeraCrypt's do: a vault
// locking on idle should not pull a disk out from under the programs
// writing to it. With close_containers_on_lock in the config, a vault that
// locks closes the containers whose keys it holds (unmounting only what is
// not busy), after the lock and apart from it.

const (
	kindContainer = "container"
	fieldKey      = "key"
	attrImage     = "image"
	attrUUID      = "luks_uuid"
	attrPassSlot  = "passphrase_slot"
)

func init() {
	registerMethod(svrpc.MContainerCreate, (*Daemon).containerCreate)
	registerMethod(svrpc.MContainerOpen, (*Daemon).containerOpen)
	registerMethod(svrpc.MContainerClose, (*Daemon).containerClose)
	registerMethod(svrpc.MContainerList, (*Daemon).containerList)
	registerMethod(svrpc.MContainerPasswd, (*Daemon).containerPasswd)
	registerMethod(svrpc.MContainerDelete, (*Daemon).containerDelete)
}

// containers is the daemon's container state.
type containers struct {
	// mu makes container operations one at a time: two of them on one
	// image would race on its header and its loop device.
	mu sync.Mutex

	connMu sync.Mutex
	disks  *svcontainer.Disks

	// closing counts containers being closed after their vault locked, so
	// a daemon that stops can wait for them.
	closing sync.WaitGroup

	// seen are the disks seen, vault by vault (disks_seen.go).
	seen seenDisks
}

// disks is the connection to the OS's disk service, made on first use and
// again after it drops.
func (d *Daemon) disks() (*svcontainer.Disks, error) {
	d.ctr.connMu.Lock()
	defer d.ctr.connMu.Unlock()
	if d.ctr.disks != nil {
		select {
		case <-d.ctr.disks.Done():
			d.ctr.disks = nil
		default:
			return d.ctr.disks, nil
		}
	}
	disks, err := svcontainer.ConnectDisks()
	if err != nil {
		return nil, containerErr(err)
	}
	d.ctr.disks = disks
	return disks, nil
}

// containerErr gives mounting errors their protocol codes.
func containerErr(err error) error {
	var e *svrpc.Error
	switch {
	case err == nil, errors.As(err, &e):
		return err
	case errors.Is(err, svudisks.ErrNotAuthorized):
		return svrpc.Errorf(svrpc.CodeDenied, "%v", err)
	case errors.Is(err, svcontainer.ErrNotOpen):
		return svrpc.Errorf(svrpc.CodeNotFound, "%v", err)
	}
	return svrpc.Errorf(svrpc.CodeFailed, "%v", err)
}

func (d *Daemon) containerCreate(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContainerCreateParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	defer clear(p.Passphrase)
	if p.FS == "" {
		p.FS = svcontainer.Filesystems[0]
	}
	invalid := func(format string, args ...any) error { return svrpc.Errorf(svrpc.CodeInvalidParams, format, args...) }
	switch {
	case !filepath.IsAbs(p.Path):
		return nil, invalid("the image's path must be absolute")
	case p.Size < svcontainer.MinSize:
		return nil, invalid("a container must be at least %d MiB", svcontainer.MinSize>>20)
	case p.SectorSize != 0 && p.SectorSize != 512 && p.SectorSize != 4096:
		return nil, invalid("the sector size is 512 or 4096")
	case len(p.Passphrase) > 0 && len(p.Passphrase) < MinPassphrase:
		return nil, invalid("the passphrase is too short: use at least %d characters", MinPassphrase)
	}
	// With no item named, the key is named for the file, beside an item
	// of that name.
	named := p.Item != ""
	if !named {
		p.Item = svops.ContainerItemName(p.Path)
	}
	if err := svcore.CheckName(p.Item); err != nil {
		return nil, invalid("%v", err)
	}
	if err := svcontainer.CheckFormat(p.FS, p.Label); err != nil {
		return nil, invalid("%v", err)
	}
	if _, err := os.Lstat(p.Path); err == nil {
		return nil, svrpc.Errorf(svrpc.CodeExists, "%s already exists; a container is only ever made as a new file", p.Path)
	}
	disks, err := d.disks()
	if err != nil {
		return nil, err
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", p.Item, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	itemExists := func() error {
		return svrpc.Errorf(svrpc.CodeExists, "there is already an item named %q", p.Item)
	}
	if !named {
		p.Item = mv.v.FreeName(p.Item, "disk")
	} else if e, err := mv.v.Get(p.Item); err == nil {
		e.Item.Wipe()
		return nil, itemExists()
	}

	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	path := svcontainer.Canonical(p.Path)
	key := svcontainer.NewKey()
	defer clear(key)
	img, err := svcontainer.CreateImage(path, key, svcontainer.CreateOptions{Size: p.Size, SectorSize: p.SectorSize, Label: p.Label, Passphrase: p.Passphrase})
	if err != nil {
		return nil, containerErr(err)
	}
	// The key is stored before the image is formatted and mounted, so it
	// cannot be lost to a crash in between; and only as a new item, never
	// over one another request stored meanwhile.
	it := svcore.Item{Kind: kindContainer, Name: p.Item, Label: p.Label,
		Attrs:  map[string]string{attrImage: path, attrUUID: img.UUID},
		Fields: []svcore.Field{{Name: fieldKey, Type: svcore.FieldConcealed, Value: append([]byte(nil), key...)}}}
	if it.Label == "" {
		it.Label = filepath.Base(path)
	}
	if img.PassphraseSlot >= 0 {
		it.Attrs[attrPassSlot] = strconv.Itoa(img.PassphraseSlot)
	}
	e, err := mv.v.PutNew(it)
	it.Wipe()
	if err != nil {
		os.Remove(path)
		if errors.Is(err, svcore.ErrItemExists) {
			return nil, itemExists()
		}
		return nil, err
	}
	e.Item.Wipe()
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})

	st, err := disks.Format(ctx, path, key, p.FS, p.Label, p.MountOptions)
	if err != nil {
		// Nothing half-made is left: not the image, not its item (this
		// one: made above, and found by its identity, not its name).
		os.Remove(path)
		if cur, gerr := mv.v.GetID(e.ID); gerr == nil {
			cur.Item.Wipe()
			if mv.v.Delete(p.Item) == nil {
				d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})
			}
		}
		return nil, containerErr(err)
	}
	d.opts.Log(fmt.Sprintf("created container %s (%s, key in %s/%s)", path, p.FS, mv.cfg.Name, p.Item))
	d.sawDisk(mv.cfg.Name, path)
	return containerInfo(mv.cfg.Name, p.Item, path, img.UUID, img.PassphraseSlot >= 0, st, true), nil
}

// containerItem finds the item holding a container's key and authorizes
// op on it: by name, or else (the vault unlocked first, asking if need be)
// as the container item whose luks_uuid is the image's. The person is
// told which image is meant. The caller wipes the entry.
func (d *Daemon) containerItem(ctx context.Context, cl *client, vault, name, path string, op svbroker.Op) (*managedVault, svcore.Entry, error) {
	var uuid string
	if name == "" {
		if path == "" {
			return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "name the container's image or its item")
		}
		// Before any consent, say no more than whether this is a
		// container: the program asking can read the file itself anyway.
		h, err := svcontainer.Inspect(path)
		if err != nil {
			return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%s is not a container secretvault can open", path)
		}
		uuid = h.UUID()
	}
	mv, err := d.vault(vault)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	what := "a container"
	if path != "" {
		what = "the container " + path
	}
	why := fmt.Sprintf("%s wants to use %s, whose key is in vault %q.", cl.display(), what, mv.cfg.Name)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		d.recorder(cl, mv, name, op)(outcomeOf(err), err.Error())
		return nil, svcore.Entry{}, err
	}
	if name == "" {
		entries, err := mv.v.List("")
		if err != nil {
			return nil, svcore.Entry{}, err
		}
		want := svcontainer.Canonical(path)
		for _, e := range entries {
			e.Item.Wipe()
			if e.Item.Kind != kindContainer || e.Item.Attrs[attrUUID] != uuid {
				continue
			}
			// Copies of an image share its UUID: the item naming this file
			// wins, else the first.
			if name == "" || e.Item.Attrs[attrImage] == want {
				name = e.Item.Name
			}
		}
		if name == "" {
			return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeNotFound,
				"no item in vault %q holds the key of %s; name it with --item", mv.cfg.Name, path)
		}
	}
	e, err := mv.v.Get(name)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	if e.Item.Kind != kindContainer {
		e.Item.Wipe()
		return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is a %s item, not a container's key", name, e.Item.Kind)
	}
	if path == "" {
		path = e.Item.Attrs[attrImage]
	}
	switch op {
	case svbroker.OpMount:
		why = fmt.Sprintf("%s wants to open the container %s with the key in %q, in vault %q.", cl.display(), path, name, mv.cfg.Name)
	case svbroker.OpDelete:
		why = fmt.Sprintf("%s wants to delete the container %s, and its key %q in vault %q.\n"+
			"The file and every file in it are deleted from this computer for good; the key goes to the vault's deleted items.",
			cl.display(), path, name, mv.cfg.Name)
	default:
		why = describeRequest(cl, mv, name, op) + "\n(It is the key of the container " + path + ".)"
	}
	if err := d.decide(ctx, cl, mv, e.ID.String(), name, op, why, prompted, own, d.recorder(cl, mv, name, op)); err != nil {
		e.Item.Wipe()
		return nil, svcore.Entry{}, err
	}
	return mv, e, nil
}

// keyOf is a container item's key, checked.
func keyOf(e svcore.Entry) ([]byte, error) {
	f, ok := e.Item.Field(fieldKey)
	if !ok || svcontainer.CheckKey(f.Value) != nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "item %q holds no container key", e.Item.Name)
	}
	return f.Value, nil
}

func (d *Daemon) containerOpen(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContainerOpenParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if p.Path != "" && !filepath.IsAbs(p.Path) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the image's path must be absolute")
	}
	disks, err := d.disks()
	if err != nil {
		return nil, err
	}
	mv, e, err := d.containerItem(ctx, cl, p.Vault, p.Item, p.Path, svbroker.OpMount)
	if err != nil {
		return nil, err
	}
	defer e.Item.Wipe()
	key, err := keyOf(e)
	if err != nil {
		return nil, err
	}
	path := p.Path
	if path == "" {
		path = e.Item.Attrs[attrImage]
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	// Mount checks the header itself (sound, AES-XTS, opened by the key)
	// on the very descriptor it attaches, before the kernel sees it.
	st, err := disks.Mount(ctx, path, key, p.MountOptions)
	if err != nil {
		return nil, containerErr(err)
	}
	d.sawDisk(mv.cfg.Name, st.Image)
	return containerInfo(mv.cfg.Name, e.Item.Name, st.Image, e.Item.Attrs[attrUUID], e.Item.Attrs[attrPassSlot] != "", st, true), nil
}

func (d *Daemon) containerClose(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContainerCloseParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(p.Target) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "name the image or mount point by an absolute path")
	}
	disks, err := d.disks()
	if err != nil {
		return nil, err
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	st, err := disks.Unmount(ctx, p.Target)
	if errors.Is(err, svcontainer.ErrNotOpen) {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "%s is not an open container", p.Target)
	}
	if err != nil {
		return nil, containerErr(err)
	}
	d.opts.Log(fmt.Sprintf("closed container %s (asked by %s)", st.Image, cl.display()))
	return containerInfo("", "", st.Image, "", false, st, true), nil
}

func (d *Daemon) containerList(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.VaultRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpList)
	if err != nil {
		return nil, err
	}
	// Where each image is, when this system can say.
	status, known := d.diskStatus(ctx)
	return d.listContainers(mv, status, known)
}

func (d *Daemon) containerPasswd(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContainerPasswdParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	defer clear(p.Passphrase)
	switch {
	case p.Path != "" && !filepath.IsAbs(p.Path):
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the image's path must be absolute")
	case !p.Remove && len(p.Passphrase) < MinPassphrase:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the passphrase is too short: use at least %d characters", MinPassphrase)
	}
	// A passphrase keyslot opens the container as well as its key does:
	// reading the key and changing the item are both asked for.
	mv, e, err := d.containerItem(ctx, cl, p.Vault, p.Item, p.Path, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	defer e.Item.Wipe()
	if err := d.authorize(ctx, cl, mv, e.ID.String(), e.Item.Name, svbroker.OpWrite); err != nil {
		return nil, err
	}
	key, err := keyOf(e)
	if err != nil {
		return nil, err
	}
	path := p.Path
	if path == "" {
		path = e.Item.Attrs[attrImage]
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	// The keyslot the item names is a keyslot of the image it was made
	// for: another image (a path given by the caller) is refused.
	if h, err := svcontainer.Inspect(path); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "%v", err)
	} else if h.UUID() != e.Item.Attrs[attrUUID] {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s is not the container %q was made for (its LUKS UUID is not %s)", path, e.Item.Name, e.Item.Attrs[attrUUID])
	}
	old := -1
	if s, ok := e.Item.Attrs[attrPassSlot]; ok {
		if n, err := strconv.Atoi(s); err == nil {
			old = n
		}
	}
	it := e.Item
	if it.Attrs == nil {
		it.Attrs = map[string]string{}
	}
	added := -1
	if p.Remove {
		if old < 0 {
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "%s has no passphrase keyslot that secretvault made", path)
		}
		if err := svcontainer.RemoveKeyslot(path, key, old); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeFailed, "%v", err)
		}
		delete(it.Attrs, attrPassSlot)
	} else {
		slot, err := svcontainer.SetPassphrase(path, key, p.Passphrase, old)
		if err != nil {
			return nil, svrpc.Errorf(svrpc.CodeFailed, "%v", err)
		}
		if slot != old {
			added = slot
		}
		it.Attrs[attrPassSlot] = strconv.Itoa(slot)
	}
	ne, err := mv.v.Put(it)
	if err != nil {
		// A keyslot the item does not name would be one nobody knows of.
		if added >= 0 {
			svcontainer.RemoveKeyslot(path, key, added)
		}
		return nil, err
	}
	ne.Item.Wipe()
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: it.Name})
	d.sawDisk(mv.cfg.Name, path)
	return containerInfo(mv.cfg.Name, it.Name, path, it.Attrs[attrUUID], !p.Remove, svcontainer.Status{}, false), nil
}

// containerDelete deletes a container: its image file, for good, then its
// key's item, to the vault's deleted items. What can refuse it that the
// program could find out itself (the file is no LUKS2 image, it is in
// use as a disk) is said before anyone is asked, and checked again after.
func (d *Daemon) containerDelete(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContainerDeleteParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(p.Path) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "name the disk's file by its absolute path")
	}
	mv, err := d.vault(p.Vault)
	if err != nil {
		return nil, err
	}
	if mv.cfg.Emergency != "" {
		return nil, errTheirs(mv)
	}
	path := svcontainer.Canonical(p.Path)
	if _, _, err := d.deletable(ctx, path); err != nil {
		return nil, err
	}
	mv, e, err := d.containerItem(ctx, cl, p.Vault, p.Item, path, svbroker.OpDelete)
	if err != nil {
		return nil, err
	}
	defer e.Item.Wipe()
	name := e.Item.Name
	record := d.recorder(cl, mv, name, svbroker.OpDelete)
	fail := func(err error) (any, error) {
		record("failed", "the container "+path+" was not deleted: "+reasonOf(err))
		return nil, err
	}
	if err := mv.v.Writable(); err != nil {
		return fail(svrpc.Errorf(svrpc.CodeFailed, "vault %q: %s: nothing was deleted", mv.cfg.Name, strings.TrimPrefix(err.Error(), "svcore: ")))
	}

	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	// Again, now that it is our turn: it may have been mounted, or
	// replaced, while the person was asked.
	uuid, fi, err := d.deletable(ctx, path)
	if err != nil {
		return fail(err)
	}
	// Only a file this item is the key of: an item merely naming a file
	// does not make it a container.
	if want := e.Item.Attrs[attrUUID]; want != "" {
		if uuid != want {
			return fail(svrpc.Errorf(svrpc.CodeInvalidParams,
				"%s is not the disk %q was made for (its LUKS UUID is %s, not %s), so it was not deleted: name the disk's own file, or its own item with --item",
				path, name, uuid, want))
		}
	} else {
		key, err := keyOf(e)
		if err != nil {
			return fail(err)
		}
		if _, err := svcontainer.Check(path, key); err != nil {
			return fail(svrpc.Errorf(svrpc.CodeInvalidParams,
				"the key in %q does not open %s, so it was not deleted: name the disk's own file, or its own item with --item", name, path))
		}
	}
	// A copy (the same UUID), while the image the item was made for is
	// still there: deleting the key would leave that one with none.
	if img := e.Item.Attrs[attrImage]; img != "" && svcontainer.Canonical(img) != path {
		if h, st, err := svcontainer.Identify(img); err == nil && h.UUID() == uuid && !os.SameFile(st, fi) {
			return fail(svrpc.Errorf(svrpc.CodeInvalidParams,
				"%s is a copy of %s, the disk %q was made for, which is still there, so it was not deleted: delete %s itself, or delete this copy with your file manager and keep the key",
				path, img, name, img))
		}
	}
	// The file checked is the file deleted.
	if cur, err := os.Lstat(path); err != nil || !os.SameFile(cur, fi) {
		return fail(svrpc.Errorf(svrpc.CodeFailed, "%s changed while it was being checked, so it was not deleted: try again", path))
	}
	if err := os.Remove(path); err != nil {
		why := err.Error()
		var pe *os.PathError
		if errors.As(err, &pe) {
			why = pe.Err.Error()
		}
		return fail(svrpc.Errorf(svrpc.CodeFailed, "%s could not be deleted (%s), and its key stays in %q: check that you may change its folder, and try again", path, why, name))
	}
	d.opts.Log(fmt.Sprintf("deleted container %s (key in %s/%s, now in its deleted items; asked by %s)", path, mv.cfg.Name, name, cl.display()))
	d.lostDisk(mv.cfg.Name, path)
	// The key the ordinary way: to the vault's deleted items, from where
	// it can be brought back for a copy of the image kept elsewhere.
	if err := mv.v.Delete(name); err != nil {
		record("failed", "deleted the container "+path+", but not its key: "+reasonOf(err))
		return nil, svrpc.Errorf(svrpc.CodeFailed, "deleted %s, but its key stays in %q, in vault %q (%s): delete the item with 'secretvault rm %s'",
			path, name, mv.cfg.Name, reasonOf(err), name)
	}
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	record("allowed", "deleted the container "+path+"; its key is in the deleted items")
	return svrpc.ContainerInfo{Vault: mv.cfg.Name, Item: name, Path: path, UUID: uuid, State: "deleted", Passphrase: e.Item.Attrs[attrPassSlot] != ""}, nil
}

// deletable checks that the file at path can be deleted as a container's
// image: a LUKS2 image, attached as a disk under no name (deleting it
// would pull its files from under whoever uses them). It returns its LUKS
// UUID and which file it is.
func (d *Daemon) deletable(ctx context.Context, path string) (string, os.FileInfo, error) {
	// Said before any consent, so no more than whether a container is
	// there, as for container.open: the program can look itself.
	h, fi, err := svcontainer.Identify(path)
	if err != nil {
		return "", nil, svrpc.Errorf(svrpc.CodeInvalidParams,
			"there is no disk at %s that secretvault can delete (only a LUKS2 image is deleted), so nothing was: name the disk's file where it is now", path)
	}
	st, used, err := d.containerInUse(ctx, path, fi)
	switch {
	case err != nil:
		return "", nil, err
	case used && st.Mounted():
		return "", nil, svrpc.Errorf(svrpc.CodeFailed, "%s is mounted, its files in %s: unmount it first ('secretvault container close %s'), then delete it",
			path, st.MountPoint, path)
	case used:
		return "", nil, svrpc.Errorf(svrpc.CodeFailed, "%s is still attached as a disk: unmount it first ('secretvault container close %s'), then delete it",
			path, path)
	}
	return h.UUID(), fi, nil
}

// containerInUse is how the image fi, at path, is attached as a disk, by
// any of its names (a hard link, a path through a symbolic link), if it
// is. Where secretvault mounts nothing, nothing is.
func (d *Daemon) containerInUse(ctx context.Context, path string, fi os.FileInfo) (svcontainer.Status, bool, error) {
	if runtime.GOOS != "linux" {
		return svcontainer.Status{}, false, nil
	}
	disks, err := d.disks()
	var all []svcontainer.Status
	if err == nil {
		all, err = disks.All(ctx)
	}
	if err != nil {
		return svcontainer.Status{}, false, svrpc.Errorf(svrpc.CodeFailed,
			"secretvault cannot tell whether %s is in use as a disk (%s), so it was not deleted: try again once the disk service, UDisks2, answers",
			path, reasonOf(err))
	}
	for _, s := range all {
		if !s.Attached {
			continue
		}
		if s.Image == path {
			return s, true, nil
		}
		if st, err := os.Stat(s.Image); err == nil && os.SameFile(st, fi) {
			return s, true, nil
		}
	}
	return svcontainer.Status{}, false, nil
}

func containerInfo(vault, item, path, uuid string, pass bool, st svcontainer.Status, known bool) svrpc.ContainerInfo {
	out := svrpc.ContainerInfo{Vault: vault, Item: item, Path: path, UUID: uuid, Passphrase: pass,
		MountPoint: st.MountPoint, Device: st.Device}
	switch {
	case !known:
		out.State = "unknown"
	case st.Mounted():
		out.State = "mounted"
	case st.Unlocked:
		out.State = "unlocked"
	case st.Attached:
		out.State = "attached"
	default:
		out.State = "closed"
	}
	return out
}

// containerImages lists the images whose keys mv holds, when the config
// says containers close with their vault. It is called just before mv
// locks.
func (d *Daemon) containerImages(mv *managedVault) []string {
	d.mu.Lock()
	enabled := d.cfg.CloseContainersOnLock
	d.mu.Unlock()
	if !enabled || mv.v.Locked() {
		return nil
	}
	entries, err := mv.v.List("")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		e.Item.Wipe()
		if e.Item.Kind == kindContainer && e.Item.Attrs[attrImage] != "" {
			out = append(out, e.Item.Attrs[attrImage])
		}
	}
	return out
}

// closeContainersLater closes whichever of images are open, after their
// vault locked, without holding up the lock (or the next vault's): a
// container operation in progress, or a busy filesystem, can take long.
func (d *Daemon) closeContainersLater(images []string, vault, why string) {
	if len(images) == 0 {
		return
	}
	d.ctr.closing.Add(1)
	go func() {
		defer d.ctr.closing.Done()
		d.closeContainers(images, vault, why)
	}()
}

func (d *Daemon) closeContainers(images []string, vault, why string) {
	disks, err := d.disks()
	if err != nil {
		d.opts.Log("closing containers: " + err.Error())
		return
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	// The minute starts once it is our turn.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, img := range images {
		st, err := disks.Status(ctx, img)
		if err != nil || !st.Attached {
			continue
		}
		if _, err := disks.Unmount(ctx, img); err != nil {
			d.opts.Log(fmt.Sprintf("container %s stays open after vault %s locked: %v", img, vault, err))
			continue
		}
		d.opts.Log(fmt.Sprintf("closed container %s: vault %s locked (%s)", img, vault, why))
	}
}

// waitContainers waits, up to limit, for containers still being closed.
func (d *Daemon) waitContainers(limit time.Duration) {
	done := make(chan struct{})
	go func() { d.ctr.closing.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(limit):
		d.opts.Log("stopping with containers still being closed")
	}
}
