//go:build linux

package svd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svudisks"
)

// Containers against udiskstest's pretend UDisks2: nothing is attached,
// unlocked or mounted for real.

func containerHarness(t *testing.T) (*harness, *udiskstest.Fake, *secretvault.Client, string) {
	t.Helper()
	fake := udiskstest.Start(t)
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })
	h := newHarness(t)
	cli := h.setup()
	return h, fake, cli, t.TempDir()
}

func containerKey(t *testing.T, cli *secretvault.Client, item string) (svrpc.Entry, []byte) {
	t.Helper()
	e, err := cli.Get(ctx(t), "", item)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range e.Item.Fields {
		if f.Name == "key" {
			return e, f.Value
		}
	}
	t.Fatalf("%s has no key: %+v", item, e.Item)
	return e, nil
}

func TestContainers(t *testing.T) {
	h, fake, cli, dir := containerHarness(t)
	path := filepath.Join(dir, "work.img")
	info, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/work", Path: path, Size: 40 << 20,
		Label: "Work", Passphrase: []byte("a passphrase to recover with")})
	if err != nil {
		t.Fatal(err)
	}
	if info.State != "mounted" || info.MountPoint == "" || info.Item != "containers/work" || info.Vault != "personal" || !info.Passphrase || info.UUID == "" {
		t.Fatalf("created %+v", info)
	}
	if st, _ := fake.Image(path); st.FSType != "ext4" || st.Label != "Work" || !st.Owned {
		t.Fatalf("UDisks2 saw %+v", st)
	}
	e, key := containerKey(t, cli, "containers/work")
	if e.Item.Kind != "container" || e.Item.Attrs["image"] != path || e.Item.Attrs["luks_uuid"] != info.UUID ||
		e.Item.Attrs["passphrase_slot"] != "1" || svcontainer.CheckKey(key) != nil {
		t.Fatalf("the item: %+v", e.Item)
	}
	if slot, err := svcontainer.Check(path, key); err != nil || slot != 0 {
		t.Fatalf("the item's key: %d %v", slot, err)
	}

	list, err := cli.Containers(ctx(t), "")
	if err != nil || len(list) != 1 || list[0].State != "mounted" || list[0].Path != path {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := cli.CloseContainer(ctx(t), info.MountPoint); err != nil {
		t.Fatal(err)
	}
	if list, _ := cli.Containers(ctx(t), ""); list[0].State != "closed" {
		t.Fatalf("after close: %+v", list)
	}
	if _, err := cli.CloseContainer(ctx(t), path); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("closing it twice: %v", err)
	}

	// Opened by its file alone: the item is found by the image's UUID.
	info, err = cli.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: path, MountOptions: "noexec"})
	if err != nil || info.State != "mounted" || info.Item != "containers/work" {
		t.Fatalf("open: %+v %v", info, err)
	}
	if st, _ := fake.Image(path); st.MountOptions != "noexec" {
		t.Fatalf("mount options: %+v", st)
	}

	// Another program opens a container only with the person's consent,
	// asked as "mount", naming the image; and that is not reading the key.
	files := h.connect("/usr/bin/nautilus", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := files.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: path}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("denied: %v", err)
	}
	if q := h.desk.asked[0]; !strings.Contains(q.Description, "wants to open the container "+path+` with the key in "containers/work"`) {
		t.Fatalf("the prompt said %q", q.Description)
	}
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	if info, err := files.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Item: "containers/work"}); err != nil || info.State != "mounted" {
		t.Fatalf("allowed, by item: %+v %v", info, err)
	}
	if _, err := files.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: path}); err != nil {
		t.Fatalf("always means always: %v", err)
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := files.Get(ctx(t), "", "containers/work"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("mounting let the program read the key: %v", err)
	}
	if q := h.desk.asked[len(h.desk.asked)-1]; !strings.Contains(q.Description, `wants to read "containers/work"`) {
		t.Fatalf("reading the key was not asked about as such: %q", q.Description)
	}
	h.desk.done(t)
	// Creating is a write to the vault: asked too.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := files.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/other", Path: filepath.Join(dir, "other.img"), Size: 40 << 20}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("create denied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.img")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a denied create left a file")
	}
	if _, err := cli.CloseContainer(ctx(t), path); err != nil {
		t.Fatal(err)
	}
}

func TestContainerRefusals(t *testing.T) {
	_, fake, cli, dir := containerHarness(t)
	path := filepath.Join(dir, "c.img")
	create := func(p svrpc.ContainerCreateParams) error {
		if p.Item == "" {
			p.Item = "containers/c"
		}
		if p.Path == "" {
			p.Path = path
		}
		if p.Size == 0 {
			p.Size = 40 << 20
		}
		_, err := cli.CreateContainer(ctx(t), p)
		return err
	}
	for name, c := range map[string]struct {
		p    svrpc.ContainerCreateParams
		code int
	}{
		"relative path":    {svrpc.ContainerCreateParams{Path: "c.img"}, svrpc.CodeInvalidParams},
		"too small":        {svrpc.ContainerCreateParams{Size: 1 << 20}, svrpc.CodeInvalidParams},
		"unknown fs":       {svrpc.ContainerCreateParams{FS: "zfs"}, svrpc.CodeInvalidParams},
		"long vfat label":  {svrpc.ContainerCreateParams{FS: "vfat", Label: "much too long"}, svrpc.CodeInvalidParams},
		"short passphrase": {svrpc.ContainerCreateParams{Passphrase: []byte("short")}, svrpc.CodeInvalidParams},
		"bad item name":    {svrpc.ContainerCreateParams{Item: "a//b"}, svrpc.CodeInvalidParams},
		"existing item":    {svrpc.ContainerCreateParams{Item: "mail/imap"}, svrpc.CodeExists},
		"odd sector size":  {svrpc.ContainerCreateParams{SectorSize: 1024}, svrpc.CodeInvalidParams},
		"an existing path": {svrpc.ContainerCreateParams{Path: dir}, svrpc.CodeExists},
	} {
		var e *svrpc.Error
		if err := create(c.p); !errors.As(err, &e) || e.Code != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused create left a file")
	}

	// UDisks2 refusing half way (polkit, here) leaves no image and no item.
	fake.Fail("Mount", svudisks.ErrorNotAuthorized, "Not authorized to perform operation")
	err := create(svrpc.ContainerCreateParams{FS: "exfat", Label: "Stick"})
	if !errors.Is(err, svrpc.ErrDenied) || !strings.Contains(err.Error(), "your session is not active") {
		t.Fatalf("polkit's no: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the image was left behind")
	}
	if _, err := cli.Get(ctx(t), "", "containers/c"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("the item was left behind: %v", err)
	}
	if len(fake.Attached()) != 0 {
		t.Fatalf("left attached: %+v", fake.Attached())
	}
	fake.Fail("Mount", "", "")

	// FAT has no owners to take.
	if err := create(svrpc.ContainerCreateParams{FS: "vfat", Label: "STICK"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := fake.Image(path); st.FSType != "vfat" || st.Owned {
		t.Fatalf("vfat: %+v", st)
	}
	if _, err := cli.CloseContainer(ctx(t), path); err != nil {
		t.Fatal(err)
	}
	// Open refuses what is not a container, and items that are not keys.
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, make([]byte, 1<<16), 0o600)
	if _, err := cli.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: plain}); err == nil || !strings.Contains(err.Error(), "not a container") {
		t.Fatalf("a plain file: %v", err)
	}
	if _, err := cli.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: path, Item: "mail/imap"}); err == nil || !strings.Contains(err.Error(), "not a container's key") {
		t.Fatalf("a login item: %v", err)
	}
	// An image whose item is gone is named as such.
	if err := cli.Delete(ctx(t), "", "containers/c"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.OpenContainer(ctx(t), svrpc.ContainerOpenParams{Path: path}); !errors.Is(err, svrpc.ErrNotFound) || !strings.Contains(err.Error(), "holds the key of") {
		t.Fatalf("no item: %v", err)
	}
}

func TestContainerPasswd(t *testing.T) {
	_, _, cli, dir := containerHarness(t)
	path := filepath.Join(dir, "c.img")
	if _, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "c", Path: path, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	cli.CloseContainer(ctx(t), path)
	first, second := []byte("first passphrase"), []byte("second passphrase")
	if _, err := cli.ContainerPasswd(ctx(t), svrpc.ContainerPasswdParams{Path: path, Remove: true}); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("removing what is not there: %v", err)
	}
	if info, err := cli.ContainerPasswd(ctx(t), svrpc.ContainerPasswdParams{Path: path, Passphrase: first}); err != nil || !info.Passphrase {
		t.Fatalf("add: %+v %v", info, err)
	}
	if n, err := svcontainer.CheckPassphrase(path, first); err != nil || n != 1 {
		t.Fatalf("the passphrase: %d %v", n, err)
	}
	if _, err := cli.ContainerPasswd(ctx(t), svrpc.ContainerPasswdParams{Item: "c", Passphrase: second}); err != nil {
		t.Fatal(err)
	}
	if _, err := svcontainer.CheckPassphrase(path, first); err == nil {
		t.Fatal("the old passphrase still opens")
	}
	if n, err := svcontainer.CheckPassphrase(path, second); err != nil || n != 1 {
		t.Fatalf("the new passphrase: %d %v", n, err)
	}
	if _, err := cli.ContainerPasswd(ctx(t), svrpc.ContainerPasswdParams{Path: path, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svcontainer.CheckPassphrase(path, second); err == nil {
		t.Fatal("a removed passphrase still opens")
	}
	if e, _ := containerKey(t, cli, "c"); e.Item.Attrs["passphrase_slot"] != "" {
		t.Fatalf("the item still names a passphrase keyslot: %v", e.Item.Attrs)
	}
	// The item's keyslot numbers are its own image's: another image named
	// with it is refused.
	other := filepath.Join(dir, "other.img")
	if _, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "other", Path: other, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	cli.CloseContainer(ctx(t), other)
	if _, err := cli.ContainerPasswd(ctx(t), svrpc.ContainerPasswdParams{Item: "c", Path: other, Passphrase: first}); err == nil || !strings.Contains(err.Error(), "is not the container") {
		t.Fatalf("another image: %v", err)
	}
}

func TestContainersAndLocking(t *testing.T) {
	h, fake, cli, dir := containerHarness(t)
	path := filepath.Join(dir, "c.img")
	if _, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "c", Path: path, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	// By default a container outlives its vault's lock.
	h.d.LockAll("test")
	if st, err := fake.Image(path); err != nil || st.MountPoint == "" {
		t.Fatalf("closed on lock by default: %+v %v", st, err)
	}
	// With close_containers_on_lock, locking closes it.
	h.d.mu.Lock()
	h.d.cfg.CloseContainersOnLock = true
	h.d.mu.Unlock()
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: "passphrase", Secret: append([]byte(nil), pass...)}); err != nil {
		t.Fatal(err)
	}
	// The lock itself does not wait for the container: it is closed after.
	h.d.ctr.mu.Lock()
	h.d.LockAll("test")
	if vs, _ := cli.Vaults(ctx(t)); !vs[0].Locked {
		t.Fatal("the vault waited for its containers to lock")
	}
	h.d.ctr.mu.Unlock()
	h.d.waitContainers(10 * time.Second)
	if _, err := fake.Image(path); !errors.Is(err, udiskstest.ErrNoSuchImage) {
		t.Fatalf("still open after the lock: %v", err)
	}
}

// Deleting a container takes its image file, for good, and then its key,
// to the vault's deleted items; never a file in use, a file that is not
// a LUKS2 image, an image the item is not the key of, or a copy while
// the image the item was made for is there.
func TestContainerDelete(t *testing.T) {
	h, _, cli, dir := containerHarness(t)
	path := filepath.Join(dir, "private.img")
	info, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/private", Path: path, Size: 40 << 20})
	if err != nil {
		t.Fatal(err)
	}
	del := func(c *secretvault.Client, p svrpc.ContainerDeleteParams) (svrpc.ContainerInfo, error) {
		if p.Path == "" {
			p.Path = path
		}
		return c.DeleteContainer(ctx(t), p)
	}
	invalid := func(err error) bool {
		var e *svrpc.Error
		return errors.As(err, &e) && e.Code == svrpc.CodeInvalidParams
	}
	stillThere := func(what string) {
		t.Helper()
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: the image is gone: %v", what, err)
		}
		if _, err := cli.Get(ctx(t), "", "containers/private"); err != nil {
			t.Fatalf("%s: the key is gone: %v", what, err)
		}
	}

	// Mounted: unmount it first.
	if _, err := del(cli, svrpc.ContainerDeleteParams{}); err == nil || !strings.Contains(err.Error(), "unmount it first") ||
		!strings.Contains(err.Error(), info.MountPoint) {
		t.Fatalf("mounted: %v", err)
	}
	stillThere("mounted")
	if _, err := cli.CloseContainer(ctx(t), path); err != nil {
		t.Fatal(err)
	}

	// A file that is not a LUKS2 image, even one an item names, is never
	// deleted; nor is it asked about.
	plain := filepath.Join(dir, "notes.txt")
	os.WriteFile(plain, make([]byte, 1<<16), 0o600)
	if _, err := cli.Put(ctx(t), "", svrpc.Item{Kind: "container", Name: "containers/notes", Attrs: map[string]string{"image": plain}}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{"", "containers/notes"} {
		if _, err := del(cli, svrpc.ContainerDeleteParams{Path: plain, Item: item}); !invalid(err) || !strings.Contains(err.Error(), "only a LUKS2 image is deleted") ||
			strings.Contains(err.Error(), "LUKS header") {
			t.Fatalf("a plain file, item %q: %v", item, err)
		}
	}
	if _, err := os.Stat(plain); err != nil {
		t.Fatal("a plain file was deleted")
	}
	if _, err := del(cli, svrpc.ContainerDeleteParams{Path: filepath.Join(dir, "nothing.img")}); !invalid(err) || !strings.Contains(err.Error(), "there is no disk at") {
		t.Fatalf("no file: %v", err)
	}

	// Another disk's key does not delete this one: its UUID is not the one
	// that item records.
	other := filepath.Join(dir, "other.img")
	if _, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/other", Path: other, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	cli.CloseContainer(ctx(t), other)
	if _, err := del(cli, svrpc.ContainerDeleteParams{Item: "containers/other"}); !invalid(err) || !strings.Contains(err.Error(), "is not the disk") {
		t.Fatalf("another disk's item: %v", err)
	}
	stillThere("another disk's item")

	// A copy of the image, while the image is there: its key stays.
	cp := filepath.Join(dir, "copy.img")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cp, data, 0o600)
	if _, err := del(cli, svrpc.ContainerDeleteParams{Path: cp}); err == nil || !strings.Contains(err.Error(), "is a copy of "+path) {
		t.Fatalf("a copy: %v", err)
	}
	if _, err := os.Stat(cp); err != nil {
		t.Fatal("the copy was deleted")
	}

	// Another program is asked, as deleting the item, the question naming
	// the file; no is no.
	files := h.connect("/usr/bin/nautilus", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := del(files, svrpc.ContainerDeleteParams{}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("denied: %v", err)
	}
	if q := h.desk.asked[0]; !strings.Contains(q.Description, "wants to delete the container "+path+`, and its key "containers/private"`) ||
		!strings.Contains(q.Description, "deleted items") {
		t.Fatalf("the prompt said %q", q.Description)
	}
	h.desk.done(t)
	stillThere("denied")

	// Deleted: the file, and the key into the deleted items.
	got, err := del(cli, svrpc.ContainerDeleteParams{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Vault != "personal" || got.Item != "containers/private" || got.Path != path || got.UUID != info.UUID || got.State != "deleted" {
		t.Fatalf("deleted %+v", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the image is still there: %v", err)
	}
	if _, err := cli.Get(ctx(t), "", "containers/private"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("the key is still there: %v", err)
	}
	gone, err := cli.Deleted(ctx(t), "", "containers/")
	if err != nil || len(gone) != 1 || gone[0].Name != "containers/private" || gone[0].Kind != "container" {
		t.Fatalf("the deleted items: %+v %v", gone, err)
	}
	audit, err := cli.Audit(ctx(t), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	logged := false
	for _, a := range audit {
		logged = logged || a.Op == "delete" && a.Item == "containers/private" && a.Outcome == "allowed" && strings.Contains(a.Reason, "deleted the container "+path)
	}
	if !logged {
		t.Fatalf("the audit log: %+v", audit)
	}

	// Brought back, the key opens the copy kept elsewhere; and with the
	// image it was made for gone, the copy can be deleted in turn.
	if _, err := cli.Restore(ctx(t), svrpc.RestoreParams{Name: "containers/private"}); err != nil {
		t.Fatal(err)
	}
	if _, key := containerKey(t, cli, "containers/private"); svcontainer.CheckKey(key) != nil {
		t.Fatal("the key came back without its key")
	} else if _, err := svcontainer.Check(cp, key); err != nil {
		t.Fatalf("the key does not open the copy: %v", err)
	}
	if got, err := del(cli, svrpc.ContainerDeleteParams{Path: cp}); err != nil || got.Item != "containers/private" {
		t.Fatalf("the copy, its image gone: %+v %v", got, err)
	}
	if _, err := os.Stat(cp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the copy is still there")
	}
}

// container.known lists every vault's disks: an unlocked vault's as
// container.list does, a locked one's as the daemon remembers them (its
// file, UUID and state, nothing of its key's item), without asking or
// unlocking anything. The memory outlives a restart, holds no item
// names, says when a file is gone, and forgets what is deleted and the
// disks of a vault forgotten.
func TestTheDisksOfLockedVaultsAreKnown(t *testing.T) {
	h, fake, cli, dir := containerHarness(t)
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "work", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	a, b, w := filepath.Join(dir, "a.img"), filepath.Join(dir, "b.img"), filepath.Join(dir, "w.img")
	ia, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/a", Path: a, Size: 40 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ib, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Item: "containers/b", Path: b, Size: 40 << 20})
	if err != nil {
		t.Fatal(err)
	}
	cli.CloseContainer(ctx(t), b)
	if _, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Vault: "work", Item: "disks/w", Path: w, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := cli.Lock(ctx(t), "personal", false); err != nil {
		t.Fatal(err)
	}

	byPath := func(list []svrpc.ContainerInfo) map[string]svrpc.ContainerInfo {
		m := map[string]svrpc.ContainerInfo{}
		for _, ci := range list {
			m[ci.Path] = ci
		}
		return m
	}
	known, err := cli.KnownContainers(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	got := byPath(known)
	mountA, _ := fake.Image(a)
	if len(known) != 3 ||
		got[a] != (svrpc.ContainerInfo{Vault: "personal", Path: a, UUID: ia.UUID, State: "mounted", MountPoint: mountA.MountPoint, Device: got[a].Device, Locked: true}) ||
		got[b] != (svrpc.ContainerInfo{Vault: "personal", Path: b, UUID: ib.UUID, State: "closed", Locked: true}) ||
		got[w].Vault != "work" || got[w].Item != "disks/w" || got[w].Locked || got[w].State != "mounted" {
		t.Fatalf("known: %+v", known)
	}
	if vs, _ := cli.Vaults(ctx(t)); vs[0].Name == "personal" && !vs[0].Locked || vs[1].Name == "personal" && !vs[1].Locked {
		t.Fatalf("listing unlocked a vault: %+v", vs)
	}
	if h.desk.count() != 0 {
		t.Fatal("listing asked")
	}

	// What the daemon keeps: vault names and files, no item names.
	data, err := os.ReadFile(filepath.Join(h.home, "disks.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"personal"`, `"work"`, a, b, w} {
		if !strings.Contains(string(data), want) {
			t.Errorf("disks.json lacks %s:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "containers/") || strings.Contains(string(data), "disks/") {
		t.Errorf("disks.json names items:\n%s", data)
	}
	if st, _ := os.Stat(filepath.Join(h.home, "disks.json")); st.Mode().Perm() != 0o600 {
		t.Errorf("disks.json is %v", st.Mode())
	}

	// Another program: not asked about the locked vault; asked about the
	// unlocked one, and told no, it gets that one's files only.
	files := h.connect("/usr/bin/nautilus", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	known, err = files.KnownContainers(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := byPath(known); len(known) != 3 || got[w].Item != "" || got[w].Locked || got[w].State != "mounted" || !got[a].Locked {
		t.Fatalf("known to another program: %+v", known)
	}
	h.desk.done(t)
	if n := len(h.desk.asked); n != 1 || !strings.Contains(h.desk.asked[0].Description, `vault "work"`) {
		t.Fatalf("asked %d times: %+v", n, h.desk.asked)
	}

	// A file gone is still listed, as missing; and the memory outlives a
	// restart.
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	h.restart()
	cli = h.connect("/usr/bin/secretvault", &scripted{answers: []string{"pass:" + string(pass)}})
	known, err = cli.KnownContainers(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := byPath(known); len(known) != 3 || got[b].State != "missing" || !got[b].Locked || !got[a].Locked || !got[w].Locked {
		t.Fatalf("after a restart: %+v", known)
	}

	// Unlocked, the vault's own list: the item of the gone file says
	// missing too. A disk deleted is forgotten.
	if _, err := cli.Unlock(ctx(t), "personal", &svrpc.Key{Type: "passphrase", Secret: append([]byte(nil), pass...)}); err != nil {
		t.Fatal(err)
	}
	known, _ = cli.Containers(ctx(t), "personal")
	if got := byPath(known); got[b].State != "missing" || got[b].Item != "containers/b" || got[a].Item != "containers/a" {
		t.Fatalf("personal, unlocked: %+v", known)
	}
	cli.CloseContainer(ctx(t), a)
	if _, err := cli.DeleteContainer(ctx(t), svrpc.ContainerDeleteParams{Path: a}); err != nil {
		t.Fatal(err)
	}
	cli.Lock(ctx(t), "", true)
	known, _ = cli.KnownContainers(ctx(t))
	if got := byPath(known); len(known) != 2 || got[a].Path != "" || got[b].Vault != "personal" || got[w].Vault != "work" {
		t.Fatalf("after deleting a.img: %+v", known)
	}

	// A vault forgotten takes its disks with it, and comes back knowing
	// none until it is listed.
	vs, _ := cli.Vaults(ctx(t))
	var workPath string
	for _, v := range vs {
		if v.Name == "work" {
			workPath = v.Path
		}
	}
	if err := cli.ForgetVault(ctx(t), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddVault(ctx(t), "work", workPath); err != nil {
		t.Fatal(err)
	}
	known, _ = cli.KnownContainers(ctx(t))
	if len(known) != 1 || known[0].Path != b {
		t.Fatalf("after forgetting work: %+v", known)
	}
}

// A disk made with no item named has its key named for its file; one
// whose name an item has already goes beside it, never over it.
func TestADisksKeyIsNamedForItsFile(t *testing.T) {
	_, _, cli, dir := containerHarness(t)
	if _, err := cli.Put(ctx(t), "", svrpc.Item{Kind: "note", Name: "notes", Fields: []svrpc.Field{{Name: "notes", Type: "text", Value: []byte("mine")}}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ file, want string }{
		{"work.img", "work"},
		{"notes.img", "notes (disk)"},
	} {
		info, err := cli.CreateContainer(ctx(t), svrpc.ContainerCreateParams{Path: filepath.Join(dir, c.file), Size: 40 << 20})
		if err != nil || info.Item != c.want {
			t.Fatalf("%s: %+v, %v", c.file, info, err)
		}
		if e, key := containerKey(t, cli, c.want); e.Item.Kind != "container" || svcontainer.CheckKey(key) != nil {
			t.Fatalf("%s: its key %+v", c.file, e.Item)
		}
	}
	if e, err := cli.Get(ctx(t), "", "notes"); err != nil || e.Item.Kind != "note" {
		t.Fatalf("the item of the file's name became %+v, %v", e.Item, err)
	}
}
