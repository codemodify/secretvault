package svtui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svrpc"
)

// Containers against udiskstest's pretend UDisks2, on a private bus:
// nothing is attached, unlocked or mounted for real.
func TestContainersAreMadeOpenedClosedAndBackedUp(t *testing.T) {
	h := newHarness(t)
	fake := udiskstest.Start(t) // after the harness: its bus is the one named
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })

	const own = "the container's own passphrase"
	img := filepath.Join(h.dir, "work.img")
	h.start(Options{}, own)
	h.unlock()
	h.typeText("M")
	h.waitFor("Containers · personal")
	h.waitFor("None (n makes one)")
	h.typeText("n")
	h.waitFor("New container in personal")
	h.typeText(img)
	h.tabs(1)
	h.typeText("40M")
	h.tabs(2)
	h.typeText("Work")
	h.tabs(2)
	h.typeText(own)
	h.tabs(1)
	h.typeText(own)
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitSaid("its key is the item containers/work")
	st, _ := fake.Image(img)
	if st.FSType != "ext4" || st.Label != "Work" || st.MountPoint == "" {
		t.Fatalf("UDisks2 saw %+v", st)
	}
	if _, err := svcontainer.CheckPassphrase(img, []byte(own)); err != nil {
		t.Fatalf("its own passphrase: %v", err)
	}
	h.waitFor("mounted at ")
	if h.leaked.Load() {
		t.Fatal("the passphrase was drawn")
	}

	// Closed, then opened read-only.
	selectRef[svrpc.ContainerInfo](h)
	h.typeText("c")
	h.waitSaid("Closed " + img)
	h.waitFor("closed")
	selectRef[svrpc.ContainerInfo](h)
	h.typeText("o")
	h.waitFor("Open a container")
	h.tabs(2)
	h.typeText("ro")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitSaid("Opened " + img)
	if st, _ := fake.Image(img); st.MountOptions != "ro" {
		t.Fatalf("mount options: %+v", st)
	}

	// Its passphrase removed; its header backed up.
	selectRef[svrpc.ContainerInfo](h)
	h.typeText("p")
	h.waitFor("The passphrase of work.img")
	h.key(tcell.KeyEnter) // remove it
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitSaid("Removed the passphrase keyslot")
	if _, err := svcontainer.CheckPassphrase(img, []byte(own)); err == nil {
		t.Fatal("the passphrase still opens it")
	}
	backup := filepath.Join(h.dir, "work.header")
	h.typeText("b")
	h.waitFor("Back up the header of work.img")
	h.typeText(backup)
	h.key(tcell.KeyEnter)
	h.waitSaid("Wrote " + img + "'s header to " + backup)
	if st, err := os.Stat(backup); err != nil || st.Size() != svluks.DataOffset {
		t.Fatalf("backup: %v", err)
	}
	h.typeText("b")
	h.waitFor("Back up the header of work.img")
	h.typeText(backup)
	h.key(tcell.KeyEnter)
	h.waitFor("exists")
}
