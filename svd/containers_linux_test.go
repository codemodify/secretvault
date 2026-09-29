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
