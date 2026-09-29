package svcontainer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svudisks"
)

func init() {
	PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestKeys(t *testing.T) {
	a, b := NewKey(), NewKey()
	if CheckKey(a) != nil || string(a) == string(b) {
		t.Fatalf("keys %s %s", a, b)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("G", 64), strings.Repeat("A", 64)} {
		if CheckKey([]byte(bad)) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCreateImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.img")
	key := NewKey()
	img, err := CreateImage(path, key, CreateOptions{Size: 40<<20 + 1, Passphrase: []byte("a person's passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Size() != 41<<20 || st.Mode().Perm() != 0o600 {
		t.Fatalf("size %d, mode %v", st.Size(), st.Mode())
	}
	if img.KeySlot != 0 || img.PassphraseSlot != 1 || img.UUID == "" {
		t.Fatalf("%+v", img)
	}
	h, err := Inspect(path)
	if err != nil || h.UUID() != img.UUID || h.SectorSize() != 4096 || h.Subsystem() != "secretvault" {
		t.Fatalf("inspect: %v", err)
	}
	if slot, err := Check(path, key); err != nil || slot != 0 {
		t.Fatalf("check: %d %v", slot, err)
	}
	if _, err := Check(path, NewKey()); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("another key: %v", err)
	}
	// Never over an existing file, never too small, and nothing left on
	// failure.
	if _, err := CreateImage(path, key, CreateOptions{Size: MinSize}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("over an existing file: %v", err)
	}
	small := filepath.Join(dir, "small.img")
	if _, err := CreateImage(small, key, CreateOptions{Size: 20 << 20}); err == nil {
		t.Fatal("made a 20 MiB container")
	}
	if _, err := os.Stat(small); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("left a file behind")
	}
	if _, err := Inspect(filepath.Join(dir, "none")); err == nil {
		t.Fatal("inspected nothing")
	}
	os.WriteFile(filepath.Join(dir, "plain"), make([]byte, 1<<16), 0o600)
	if _, err := Inspect(filepath.Join(dir, "plain")); err == nil || !strings.Contains(err.Error(), "not a container") {
		t.Fatalf("a plain file: %v", err)
	}
}

func TestPassphraseSlots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.img")
	key := NewKey()
	if _, err := CreateImage(path, key, CreateOptions{Size: MinSize}); err != nil {
		t.Fatal(err)
	}
	first := []byte("first passphrase")
	slot, err := SetPassphrase(path, key, first, -1)
	if err != nil || slot != 1 {
		t.Fatalf("add: %d %v", slot, err)
	}
	if n, err := Check(path, first); err != nil || n != 1 {
		t.Fatalf("the passphrase: %d %v", n, err)
	}
	second := []byte("second passphrase")
	if n, err := SetPassphrase(path, key, second, slot); err != nil || n != slot {
		t.Fatalf("change: %d %v", n, err)
	}
	if _, err := Check(path, first); err == nil {
		t.Fatal("the old passphrase still opens")
	}
	if _, err := SetPassphrase(path, key, second, 0); err == nil {
		t.Fatal("replaced the key's own keyslot")
	}
	if err := RemoveKeyslot(path, key, 0); err == nil {
		t.Fatal("removed the key's own keyslot")
	}
	if err := RemoveKeyslot(path, key, slot); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(path, second); err == nil {
		t.Fatal("a removed passphrase still opens")
	}
	if _, err := SetPassphrase(path, NewKey(), second, -1); err == nil {
		t.Fatal("added a passphrase without the key")
	}
}

// The container key and a passphrase slot both open the image in plain
// cryptsetup: the recovery path without secretvault.
func TestCryptsetupOpensContainers(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup is not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "c.img")
	key := NewKey()
	pass := []byte("recover without secretvault")
	if _, err := CreateImage(path, key, CreateOptions{Size: MinSize, Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{key, pass} {
		kf := filepath.Join(dir, "k")
		os.WriteFile(kf, secret, 0o600)
		if out, err := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", kf, path).CombinedOutput(); err != nil {
			t.Fatalf("cryptsetup: %v\n%s", err, out)
		}
	}
	// The key typed (or piped) as a line, as 'secretvault get' prints it.
	cmd := exec.Command("cryptsetup", "open", "--test-passphrase", path)
	cmd.Stdin = strings.NewReader(string(key) + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cryptsetup with the key on stdin: %v\n%s", err, out)
	}
}

func TestBackupHeader(t *testing.T) {
	dir := t.TempDir()
	path, out := filepath.Join(dir, "c.img"), filepath.Join(dir, "c.header")
	if _, err := CreateImage(path, NewKey(), CreateOptions{Size: MinSize}); err != nil {
		t.Fatal(err)
	}
	if err := BackupHeader(path, out); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(out)
	if st.Size() != svluks.DataOffset || st.Mode().Perm() != 0o600 {
		t.Fatalf("backup: %d bytes, %v", st.Size(), st.Mode())
	}
	if err := BackupHeader(path, out); !errors.Is(err, os.ErrExist) {
		t.Fatalf("over an existing backup: %v", err)
	}
}

func TestCheckFormat(t *testing.T) {
	for _, ok := range [][2]string{{"ext4", ""}, {"ext4", "Sixteen chars ok"}, {"vfat", "NO_NAME"}, {"exfat", "Photos"}, {"btrfs", strings.Repeat("b", 255)}} {
		if err := CheckFormat(ok[0], ok[1]); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][2]string{{"ntfs", ""}, {"ext4", "seventeen chars!!"}, {"vfat", "twelve chars"}, {"vfat", "héllo"}, {"ext4", "tab\there"}} {
		if err := CheckFormat(bad[0], bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestDisks(t *testing.T) {
	if runtime.GOOS != "linux" {
		if _, err := ConnectDisks(); !errors.Is(err, ErrNoMount) {
			t.Fatalf("on %s: %v", runtime.GOOS, err)
		}
		return
	}
	fake := udiskstest.Start(t)
	d, err := ConnectDisks()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "c.img")
	key := NewKey()
	if _, err := CreateImage(path, key, CreateOptions{Size: MinSize}); err != nil {
		t.Fatal(err)
	}

	st, err := d.Format(ctx(t), path, key, "ext4", "Work", "")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Attached || !st.Unlocked || st.MountPoint == "" || st.Device != "/dev/dm-0" || st.Image != path {
		t.Fatalf("after format: %+v", st)
	}
	if fs, _ := fake.Image(path); fs.FSType != "ext4" || fs.Label != "Work" || !fs.Owned {
		t.Fatalf("the fake saw %+v", fs)
	}
	// Mounting what is mounted says where.
	again, err := d.Mount(ctx(t), path, key, "")
	if err != nil || again.MountPoint != st.MountPoint {
		t.Fatalf("mount again: %+v %v", again, err)
	}
	// Close by mount point, open again (the filesystem is found), close by
	// path through a symbolic link.
	if _, err := d.Unmount(ctx(t), st.MountPoint); err != nil {
		t.Fatal(err)
	}
	if len(fake.Attached()) != 0 {
		t.Fatalf("left attached: %+v", fake.Attached())
	}
	st, err = d.Mount(ctx(t), path, key, "ro")
	if err != nil || !st.Mounted() {
		t.Fatalf("reopen: %+v %v", st, err)
	}
	if fs, _ := fake.Image(path); fs.MountOptions != "ro" {
		t.Fatalf("mount options: %+v", fs)
	}
	link := filepath.Join(dir, "link.img")
	os.Symlink(path, link)
	if now, _ := d.Status(ctx(t), link); !now.Mounted() {
		t.Fatalf("status through a link: %+v", now)
	}
	if _, err := d.Unmount(ctx(t), link); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Unmount(ctx(t), path); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("closing a closed container: %v", err)
	}

	// A wrong key, or a refusal half way, leaves nothing attached.
	if _, err := d.Mount(ctx(t), path, NewKey(), ""); err == nil {
		t.Fatal("mounted with a wrong key")
	}
	fake.Fail("Mount", svudisks.ErrorNotAuthorized, "Not authorized to perform operation")
	_, err = d.Mount(ctx(t), path, key, "")
	if !errors.Is(err, svudisks.ErrNotAuthorized) || !strings.Contains(err.Error(), "your session is not active") {
		t.Fatalf("polkit's no: %v", err)
	}
	if len(fake.Attached()) != 0 {
		t.Fatalf("left attached after failures: %+v", fake.Attached())
	}
	fake.Fail("Mount", "", "")

	// A container attached but locked (after a crash, say) is taken up
	// from there.
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	ud, err := svudisks.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer ud.Close()
	if _, err := ud.LoopSetup(ctx(t), f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, err := d.Mount(ctx(t), path, key, ""); err != nil || !st.Mounted() {
		t.Fatalf("from attached: %+v %v", st, err)
	}
	// Ours was the last LoopSetup: Mount took up from the attached image.
	if calls := strings.Join(fake.Calls(), " "); !strings.HasSuffix(calls, "Mount Lock Delete LoopSetup(c.img) Unlock Mount") {
		t.Fatalf("calls: %s", calls)
	}

	// A desktop that automounts new disks gets there first: where it
	// mounted is the answer, for a new container and a reopened one.
	d.Unmount(ctx(t), path)
	fake.Automount(true)
	auto := filepath.Join(dir, "auto.img")
	if _, err := CreateImage(auto, key, CreateOptions{Size: MinSize}); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Format(ctx(t), auto, key, "exfat", "Auto", ""); err != nil || !st.Mounted() {
		t.Fatalf("automounted after format: %+v %v", st, err)
	}
	d.Unmount(ctx(t), auto)
	if st, err := d.Mount(ctx(t), auto, key, ""); err != nil || !st.Mounted() {
		t.Fatalf("automounted after unlock: %+v %v", st, err)
	}
	d.Unmount(ctx(t), auto)
	if len(fake.Attached()) != 0 {
		t.Fatalf("left attached: %+v", fake.Attached())
	}
}
