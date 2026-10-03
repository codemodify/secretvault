//go:build linux

package svmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
)

// Containers against udiskstest's pretend UDisks2, on a private bus:
// nothing is attached, unlocked or mounted for real.
func TestContainersAreMadeOpenedAndClosed(t *testing.T) {
	fake := udiskstest.Start(t)
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openVaultPage(tabContainers)
	img := filepath.Join(h.dir, "work.img")

	h.pressOn("New container…")
	h.fill("Container file", img)
	h.fill("Size", "lots")
	h.press("Make the container")
	if !strings.Contains(h.problem(), "is not a size") {
		t.Fatalf("a wrong size: %q", h.problem())
	}
	h.fill("Size", "40M")
	h.fill("Disk name", "Work")
	h.tick("Also give it a passphrase", true)
	h.fill("Passphrase", "recover me without it")
	h.fill("Repeat", "recover me without it")
	h.press("Make the container")
	h.said("Made the container work.img (40 MiB")
	h.idle()
	st, _ := fake.Image(img)
	if st.MountPoint == "" || st.Label != "Work" || len(p.boxes) != 1 || p.boxes[0].Item != "containers/work" {
		t.Fatalf("UDisks2 saw %+v; the tab shows %+v", st, p.boxes)
	}
	if !strings.Contains(h.m.ui.message, "Its passphrase opens it without secretvault too") {
		t.Fatalf("said %q", h.m.ui.message)
	}

	h.pressOn("Close…")
	h.press("Close it")
	h.said("Closed work.img")
	h.idle()
	if p.boxes[0].State != "closed" {
		t.Fatalf("after closing: %+v", p.boxes[0])
	}
	h.pressOn("Open")
	h.said("Opened work.img: its files are in ")

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
}
