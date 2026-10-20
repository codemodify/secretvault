//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
)

// The container commands against udiskstest's pretend UDisks2: nothing is
// attached, unlocked or mounted for real.

func containerHarness(t *testing.T) (*harness, *udiskstest.Fake) {
	t.Helper()
	fake := udiskstest.Start(t)
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })
	h := newHarness(t)
	h.init()
	return h, fake
}

func TestContainerCommands(t *testing.T) {
	h, fake := containerHarness(t)
	img := filepath.Join(h.dir, "work.img")
	recovery := h.write("recovery", "recover me without secretvault\n")

	out, errs, code := h.run("", h.with("container", "create", img, "--size", "40M", "--label", "Work", "--new-passphrase-file", recovery)...)
	if code != 0 {
		t.Fatalf("create: %d %s", code, errs)
	}
	mp := strings.TrimSpace(out)
	if st, _ := fake.Image(img); st.MountPoint != mp || st.FSType != "ext4" || st.Label != "Work" {
		t.Fatalf("create printed %q; UDisks2 saw %+v", mp, st)
	}
	if !strings.Contains(errs, "its key is the item work") || !strings.Contains(errs, "40 MiB") {
		t.Fatalf("create said %q", errs)
	}
	if st, _ := os.Stat(img); st.Size() != 40<<20 {
		t.Fatalf("the image is %d bytes", st.Size())
	}

	ls := h.ok("", h.with("container", "ls")...)
	if !strings.Contains(strings.ReplaceAll(ls, img, ""), "work") || !strings.Contains(ls, img) || !strings.Contains(ls, "mounted at "+mp) {
		t.Fatalf("ls:\n%s", ls)
	}
	h.ok("", "container", "close", mp)
	if ls := h.ok("", h.with("container", "ls")...); !strings.Contains(ls, "closed") {
		t.Fatalf("ls after close:\n%s", ls)
	}
	if got := strings.TrimSpace(h.ok("", h.with("container", "open", img, "--mount-options", "ro")...)); got != mp {
		t.Fatalf("open printed %q, want %q", got, mp)
	}
	if st, _ := fake.Image(img); st.MountOptions != "ro" {
		t.Fatalf("mount options: %+v", st)
	}
	h.ok("", "container", "close", img)
	if _, errs, code := h.run("", "container", "close", img); code != 1 || !strings.Contains(errs, "is not an open container") {
		t.Fatalf("closing twice: %d %s", code, errs)
	}

	// The key is an ordinary item, and opens the image with cryptsetup
	// too, as does the passphrase.
	key := strings.TrimSpace(h.ok("", h.with("get", "work")...))
	if svcontainer.CheckKey([]byte(key)) != nil {
		t.Fatalf("the item holds %q", key)
	}
	if _, err := exec.LookPath("cryptsetup"); err == nil {
		for _, secret := range []string{key + "\n", "recover me without secretvault\n"} {
			cmd := exec.Command("cryptsetup", "open", "--test-passphrase", img)
			cmd.Stdin = strings.NewReader(secret)
			if o, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cryptsetup: %v\n%s", err, o)
			}
		}
	}

	// A new passphrase replaces the old; header-backup writes a new file.
	newPass := h.write("newpass", "a brand new passphrase\n")
	h.ok("", h.with("container", "passwd", img, "--new-passphrase-file", newPass)...)
	if _, err := svcontainer.CheckPassphrase(img, []byte("recover me without secretvault")); err == nil {
		t.Fatal("the old passphrase still opens")
	}
	if _, err := svcontainer.CheckPassphrase(img, []byte("a brand new passphrase")); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(h.dir, "work.header")
	h.ok("", "container", "header-backup", img, backup)
	if st, err := os.Stat(backup); err != nil || st.Size() != svluks.DataOffset {
		t.Fatalf("backup: %v", err)
	}
	if _, errs, code := h.run("", "container", "header-backup", img, backup); code != 1 || !strings.Contains(errs, "exists") {
		t.Fatalf("over an existing backup: %d %s", code, errs)
	}
}

func TestContainerCommandErrors(t *testing.T) {
	h, _ := containerHarness(t)
	img := filepath.Join(h.dir, "c.img")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"container", "create", img}, "--size"},
		{[]string{"container", "create", img, "--size", "lots"}, "is not a size"},
		{[]string{"container", "create", img, "--size", "1M"}, "at least 32 MiB"},
		{[]string{"container", "create", img, "--size", "40M", "--fs", "ntfs"}, "not one of"},
		{[]string{"container", "open", h.passFile}, "not a container"},
		{[]string{"container", "frobnicate"}, "unknown subcommand"},
	} {
		if _, errs, code := h.run("", h.with(c.args...)...); code == 0 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: %d %q", c.args, code, errs)
		}
	}
	h.write("c.img", "taken")
	if _, errs, code := h.run("", h.with("container", "create", img, "--size", "40M")...); code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatalf("over an existing file: %d %q", code, errs)
	}
}

// container delete asks first, Enter meaning no; says what went and how
// the key comes back; and does not ask about a disk still mounted.
func TestContainerDeleteAsksFirst(t *testing.T) {
	h, _ := containerHarness(t)
	img := filepath.Join(h.dir, "private.img")
	h.ok("", h.with("container", "create", img, "--size", "40M")...)

	if _, errs, code := h.run("", h.with("container", "delete", img)...); code != 1 || !strings.Contains(errs, "unmount it first") ||
		strings.Contains(errs, "Delete the disk") {
		t.Fatalf("mounted: %d %q", code, errs)
	}
	h.ok("", "container", "close", img)

	h.answers = []string{""} // Enter
	_, errs, code := h.run("", h.with("container", "delete", img)...)
	if code != 1 || !strings.Contains(errs, "Delete the disk private.img?") || !strings.Contains(errs, "deleted items of vault default") ||
		!strings.Contains(errs, "nothing was deleted") {
		t.Fatalf("Enter: %d %q", code, errs)
	}
	if _, err := os.Stat(img); err != nil {
		t.Fatalf("Enter deleted it: %v", err)
	}

	h.answers = []string{"y"}
	_, errs, code = h.run("", h.with("container", "delete", img)...)
	if code != 0 || !strings.Contains(errs, "Deleted "+img) || !strings.Contains(errs, "'secretvault restore private --vault default' brings it back") {
		t.Fatalf("yes: %d %q", code, errs)
	}
	if _, err := os.Stat(img); !os.IsNotExist(err) {
		t.Fatalf("the image is still there: %v", err)
	}
	if _, errs, code := h.run("", h.with("get", "private")...); code == 0 {
		t.Fatalf("the key is still there: %q", errs)
	}
	h.ok("", h.with("restore", "private")...)
	if key := strings.TrimSpace(h.ok("", h.with("get", "private")...)); svcontainer.CheckKey([]byte(key)) != nil {
		t.Fatalf("the key came back as %q", key)
	}

	// --yes asks nothing.
	other := filepath.Join(h.dir, "other.img")
	h.ok("", h.with("container", "create", other, "--size", "40M", "--item", "disks/other")...)
	h.ok("", "container", "close", other)
	h.answers = nil
	if _, errs, code := h.run("", h.with("container", "delete", other, "--yes")...); code != 0 || !strings.Contains(errs, "the item disks/other") {
		t.Fatalf("--yes: %d %q", code, errs)
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("--yes left it: %v", err)
	}
}

// container ls --all lists every vault's containers, a locked vault's by
// file only, without unlocking it or asking for anything.
func TestContainerLsAllListsLockedVaults(t *testing.T) {
	h, _ := containerHarness(t)
	img := filepath.Join(h.dir, "work.img")
	h.ok("", h.with("container", "create", img, "--size", "40M")...)
	h.ok("", "container", "close", img)
	h.ok("", "lock", "--all")
	out, errs, code := h.run("", "container", "ls", "--all") // nothing typed: nothing may be asked
	if code != 0 {
		t.Fatalf("ls --all: %d %s", code, errs)
	}
	if !strings.Contains(out, "VAULT") || !strings.Contains(out, "default") || !strings.Contains(out, "(vault locked)") ||
		!strings.Contains(out, img) || !strings.Contains(out, "closed") || strings.Contains(strings.ReplaceAll(out, img, ""), "work") {
		t.Fatalf("ls --all:\n%s", out)
	}
	if !strings.Contains(errs, "secretvault unlock") {
		t.Fatalf("ls --all said %q", errs)
	}
	if st := h.ok("", "status"); !strings.Contains(st, "locked") {
		t.Fatalf("listing unlocked the vault:\n%s", st)
	}
	os.Remove(img)
	if out := h.ok("", "container", "ls", "--all"); !strings.Contains(out, "missing (the file is not there)") {
		t.Fatalf("ls --all, the file gone:\n%s", out)
	}
}
