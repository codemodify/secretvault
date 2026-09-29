package svd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svudisks"
)

// Encrypted containers: LUKS2 image files (svcontainer) whose keys are
// vault items of kind "container", mounted by UDisks2 on Linux. Consent is
// the vault's, as for any item:
//
//   - container.create stores a new item: a write to the vault;
//   - container.open reads the container's item, as item.get does;
//   - container.passwd reads the item and changes it;
//   - container.list lists the vault;
//   - container.close needs none: whoever may reach UDisks2 can unmount
//     their own disks without us.
//
// A key goes from the vault to UDisks2 (and the kernel) and to no client.
//
// Containers stay mounted when vaults lock, as VeraCrypt's do: a vault
// locking on idle should not pull a disk out from under the programs
// writing to it. With close_containers_on_lock in the config, a vault that
// locks closes the containers whose keys it holds (unmounting only what is
// not busy).

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
}

// containers is the daemon's container state.
type containers struct {
	// mu makes container operations one at a time: two of them on one
	// image would race on its header and its loop device.
	mu sync.Mutex

	connMu sync.Mutex
	disks  *svcontainer.Disks
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
	if e, err := mv.v.Get(p.Item); err == nil {
		e.Item.Wipe()
		return nil, svrpc.Errorf(svrpc.CodeExists, "there is already an item named %q", p.Item)
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
	// cannot be lost to a crash in between.
	it := svcore.Item{Kind: kindContainer, Name: p.Item, Label: p.Label,
		Attrs:  map[string]string{attrImage: path, attrUUID: img.UUID},
		Fields: []svcore.Field{{Name: fieldKey, Type: svcore.FieldConcealed, Value: append([]byte(nil), key...)}}}
	if it.Label == "" {
		it.Label = filepath.Base(path)
	}
	if img.PassphraseSlot >= 0 {
		it.Attrs[attrPassSlot] = strconv.Itoa(img.PassphraseSlot)
	}
	e, err := mv.v.Put(it)
	it.Wipe()
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	e.Item.Wipe()
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})

	st, err := disks.Format(ctx, path, key, p.FS, p.Label, p.MountOptions)
	if err != nil {
		// Nothing half-made is left: not the image, not its item.
		os.Remove(path)
		if derr := mv.v.Delete(p.Item); derr == nil {
			d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})
		}
		return nil, containerErr(err)
	}
	d.opts.Log(fmt.Sprintf("created container %s (%s, key in %s/%s)", path, p.FS, mv.cfg.Name, p.Item))
	return containerInfo(mv.cfg.Name, p.Item, path, img.UUID, img.PassphraseSlot >= 0, st, true), nil
}

// containerItem finds the item holding a container's key and authorizes
// op on it: by name, or else (the vault unlocked first, asking if need be)
// as the container item whose luks_uuid is the image's. The caller wipes
// the entry.
func (d *Daemon) containerItem(ctx context.Context, cl *client, vault, name, path string, op svbroker.Op) (*managedVault, svcore.Entry, error) {
	if name != "" {
		mv, e, err := d.item(ctx, cl, vault, name, op)
		if err == nil && e.Item.Kind != kindContainer {
			e.Item.Wipe()
			return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is a %s item, not a container's key", name, e.Item.Kind)
		}
		return mv, e, err
	}
	if path == "" {
		return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "name the container's image or its item")
	}
	h, err := svcontainer.Inspect(path)
	if err != nil {
		return nil, svcore.Entry{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	mv, err := d.vault(vault)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	why := fmt.Sprintf("%s wants to use the container %s, whose key is in vault %q.", cl.display(), path, mv.cfg.Name)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		d.recorder(cl, mv, "", op)(outcomeOf(err), err.Error())
		return nil, svcore.Entry{}, err
	}
	entries, err := mv.v.List("")
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	want := svcontainer.Canonical(path)
	for _, e := range entries {
		e.Item.Wipe()
		if e.Item.Kind != kindContainer || e.Item.Attrs[attrUUID] != h.UUID() {
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
			"no item in vault %q holds the key of %s (LUKS UUID %s); name it with --item", mv.cfg.Name, path, h.UUID())
	}
	e, err := mv.v.Get(name)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	why = describeRequest(cl, mv, name, op)
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
	mv, e, err := d.containerItem(ctx, cl, p.Vault, p.Item, p.Path, svbroker.OpRead)
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
	// Our own check of the header, before the kernel sees it: it is sound,
	// its data cipher is AES-XTS, and the key opens it.
	if _, err := svcontainer.Check(path, key); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "%v", err)
	}
	st, err := disks.Mount(ctx, path, key, p.MountOptions)
	if err != nil {
		return nil, containerErr(err)
	}
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
	entries, err := mv.v.List("")
	if err != nil {
		return nil, err
	}
	// Where each image is, when this system can say.
	status := map[string]svcontainer.Status{}
	known := false
	if disks, err := d.disks(); err == nil {
		if all, err := disks.All(ctx); err == nil {
			known = true
			for _, s := range all {
				status[s.Image] = s
			}
		}
	}
	out := []svrpc.ContainerInfo{}
	for _, e := range entries {
		e.Item.Wipe()
		if e.Item.Kind != kindContainer {
			continue
		}
		path := e.Item.Attrs[attrImage]
		st := status[svcontainer.Canonical(path)]
		out = append(out, containerInfo(mv.cfg.Name, e.Item.Name, path, e.Item.Attrs[attrUUID], e.Item.Attrs[attrPassSlot] != "", st, known))
	}
	return out, nil
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
	// Reading the key, and changing the item: both are asked for.
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
	old := -1
	if s, ok := e.Item.Attrs[attrPassSlot]; ok {
		if n, err := strconv.Atoi(s); err == nil {
			old = n
		}
	}
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
	it := e.Item
	if it.Attrs == nil {
		it.Attrs = map[string]string{}
	}
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
		it.Attrs[attrPassSlot] = strconv.Itoa(slot)
	}
	ne, err := mv.v.Put(it)
	if err != nil {
		return nil, err
	}
	ne.Item.Wipe()
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: it.Name})
	return containerInfo(mv.cfg.Name, it.Name, path, it.Attrs[attrUUID], !p.Remove, svcontainer.Status{}, false), nil
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

// closeContainers closes whichever of images are open, after their vault
// locked.
func (d *Daemon) closeContainers(images []string, vault, why string) {
	if len(images) == 0 {
		return
	}
	disks, err := d.disks()
	if err != nil {
		d.opts.Log("closing containers: " + err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d.ctr.mu.Lock()
	defer d.ctr.mu.Unlock()
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
