//go:build linux

package svmanager

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/platform"

	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// openDisks brings the Disks tab forward, its disks listed.
func (h *harness) openDisks() *disksPage {
	h.t.Helper()
	h.m.showDisks()
	h.waitFor("the Disks tab", func() bool { return h.m.disks != nil && h.m.disks.ctable != nil })
	h.idle()
	return h.m.disks
}

// Disks against udiskstest's pretend UDisks2, on a private bus: nothing
// is attached, unlocked or mounted for real.
func TestDisksAreMadeOpenedAndClosed(t *testing.T) {
	fake := udiskstest.Start(t)
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openDisks()
	if h.m.section() != secDisks {
		t.Fatal("the Disks tab is not the one shown")
	}
	img := filepath.Join(h.dir, "work.img")

	h.pressTool("New disk…")
	h.fill("Disk file", img)
	h.fill("Size", "lots")
	h.press("Make the disk")
	if !strings.Contains(h.problem(), "is not a size") {
		t.Fatalf("a wrong size: %q", h.problem())
	}
	h.fill("Size", "40M")
	h.fill("Disk name", "Work")
	h.tick("Also give it a passphrase", true)
	h.fill("Passphrase", "recover me without it")
	h.fill("Repeat", "recover me without it")
	h.press("Make the disk")
	h.said("Made the disk work.img (40 MiB")
	h.idle()
	st, _ := fake.Image(img)
	if st.MountPoint == "" || st.Label != "Work" || len(p.boxes) != 1 || p.boxes[0].Item != "work" || p.boxes[0].Vault != "personal" {
		t.Fatalf("UDisks2 saw %+v; the tab shows %+v", st, p.boxes)
	}
	if !strings.Contains(h.m.ui.message, "Its passphrase opens it without secretvault too") {
		t.Fatalf("said %q", h.m.ui.message)
	}

	h.pressOn("Unmount…")
	h.press("Unmount it")
	h.said("Unmounted work.img")
	h.idle()
	if p.boxes[0].State != "closed" {
		t.Fatalf("after closing: %+v", p.boxes[0])
	}
	h.pressOn("Mount")
	h.said("Mounted work.img: its files are in ")

	// Any image's header, without the vault, to a new file only.
	taken := filepath.Join(h.dir, "taken.header")
	os.WriteFile(taken, []byte("old"), 0o600)
	h.pressOn("Back up the header…")
	h.fill("Copy it to", taken)
	h.press("Copy the header")
	if got := h.failed(); !strings.Contains(got, "exists") {
		t.Fatalf("a backup over a file: %q", got)
	}
	out := filepath.Join(h.dir, "work.header")
	h.fill("Copy it to", out)
	h.press("Copy the header")
	h.said("Copied the header of work.img to " + out)
	if st, err := os.Stat(out); err != nil || st.Size() < 1024 {
		t.Fatalf("the header backup: %v %v", st, err)
	}

	h.pressOn("Its own passphrase…")
	h.tick("Remove its passphrase", true)
	h.press("Remove the passphrase")
	h.said("Removed the passphrase")

	// The disk picked is shown beside the list.
	h.idle()
	for _, want := range []string{"Key kept in", "vault personal, item work", "mounted, in "} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("the disk's details lack %q:\n%s", want, h.text())
		}
	}
	// From the disk to its key, in the vault's Disk keys, and back.
	h.pressOn("Show its key")
	h.waitFor("the key in Disk keys", func() bool {
		return h.m.section() == secVaults && h.m.ui.vaultTabs.Selected() == vtDiskKeys && h.m.cursor == "work"
	})
	if got := h.listItems(); !slices.Equal(got, []string{"work"}) {
		t.Fatalf("Disk keys shows %v", got)
	}
	h.idle()
	h.pressOn("Show the disk")
	h.waitFor("the Disk tab", func() bool { return h.m.section() == secDisks && h.m.disks.container() != nil })
	h.idle()
	if ci := h.m.disks.container(); ci.Item != "work" {
		t.Fatalf("the disk picked: %+v", ci)
	}

	// Delete: not while it is mounted; then the file goes, and its key to
	// the vault's deleted items.
	h.pressOn("Delete…")
	h.said("Unmount work.img first")
	h.pressOn("Unmount…")
	h.press("Unmount it")
	h.said("Unmounted work.img")
	h.idle()
	h.pressOn("Delete…")
	h.waitText("Delete the disk work.img?")
	h.press("Delete the disk")
	h.waitFor("the disk file to go", func() bool { _, err := os.Stat(img); return errors.Is(err, os.ErrNotExist) })
	if _, err := h.get("work"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("its key is still there: %v", err)
	}
	if del, err := h.admin.Deleted(h.ctx(), "", ""); err != nil || !slices.ContainsFunc(del, func(d svrpc.DeletedItem) bool { return d.Name == "work" }) {
		t.Fatalf("its key is not in the deleted items: %v %v", del, err)
	}
}

// The Disk tab lists the disks of every vault, each with the vault that
// keeps its key; a locked vault's by file alone, as this computer last saw
// them, without asking for its passphrase.
func TestDisksAreListedFromEveryUnlockedVault(t *testing.T) {
	udiskstest.Start(t)
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	c := h.ctx()
	for _, name := range []string{"work", "spare"} {
		if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: name, Passphrase: []byte(pass)}); err != nil {
			t.Fatal(err)
		}
	}
	// The test's own client asks for the vault as any program would.
	if _, err := h.admin.Unlock(c, "personal", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"personal", "work", "spare"} {
		if _, err := h.admin.CreateContainer(c, svrpc.ContainerCreateParams{Vault: v, Item: "containers/" + v,
			Path: filepath.Join(h.dir, v+".img"), Size: 40 << 20, FS: svcontainer.Filesystems[0], SectorSize: 4096}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.admin.Lock(c, "spare", false); err != nil {
		t.Fatal(err)
	}
	h.m.reloadVaults()
	h.waitFor("the three vaults", func() bool { return len(h.m.vaults) == 3 })

	// This program has not used vault work, which another program made
	// and unlocked: the daemon asks the person first, as it would.
	h.m.showDisks()
	d := h.asking()
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	p := h.openDisks()
	var in []string
	for _, ci := range p.boxes {
		in = append(in, ci.Vault)
	}
	slices.Sort(in)
	if !slices.Equal(in, []string{"personal", "spare", "work"}) {
		t.Fatalf("the disks listed are kept in %v", in)
	}
	h.waitText(svops.DisksLockedSeen + "spare.")
	// The disks are picked in the title bar, each with its state.
	h.openCrumb(filepath.Base(p.container().Path))
	if rows := h.dropRows(); len(rows) != 3 {
		t.Fatalf("the disks' drop-down lists %q", rows)
	}
	h.closeDrop()
	// A locked vault's disk says so, and offers to unlock it.
	for i, ci := range p.boxes {
		if ci.Vault == "spare" {
			if !ci.Locked || ci.Item != "" {
				t.Fatalf("spare's disk: %+v", ci)
			}
			p.ctable.Selected = i
			h.m.drawDisk(p)
		}
	}
	h.waitText("Unlock vault spare…")
}
