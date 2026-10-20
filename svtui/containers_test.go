package svtui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// selectDisk selects the Disk tab's first disk.
func selectDisk(h *harness) {
	h.t.Helper()
	h.eventually("a disk to select", func() bool {
		p := h.u.disks
		for r := 1; r < p.t.GetRowCount(); r++ {
			if _, ok := p.t.GetCell(r, 0).GetReference().(svrpc.ContainerInfo); ok {
				p.t.Select(r, 0)
				return true
			}
		}
		return false
	})
}

// Disks (the CLI's containers) against udiskstest's pretend UDisks2, on a
// private bus: nothing is attached, unlocked or mounted for real.
func TestDisksAreMadeMountedUnmountedAndBackedUp(t *testing.T) {
	h := newHarness(t)
	fake := udiskstest.Start(t) // after the harness: its bus is the one named
	kdf := svcontainer.PassphraseKDF
	svcontainer.PassphraseKDF = svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	t.Cleanup(func() { svcontainer.PassphraseKDF = kdf })

	const own = "the container's own passphrase"
	img := filepath.Join(h.dir, "work.img")
	h.start(Options{}, own)
	h.unlock()
	h.typeText("M") // brings the Disk tab forward
	h.waitFor("Encrypted disks")
	h.waitFor("No encrypted disks yet")
	h.typeText("n")
	h.waitFor(" New disk ═")
	h.waitFor("Keep its key in vault")
	h.tabs(1) // past the vault: personal, the only one
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
	h.waitSaid("its key is in the item work")
	st, _ := fake.Image(img)
	if st.FSType != "ext4" || st.Label != "Work" || st.MountPoint == "" {
		t.Fatalf("UDisks2 saw %+v", st)
	}
	if _, err := svcontainer.CheckPassphrase(img, []byte(own)); err != nil {
		t.Fatalf("its own passphrase: %v", err)
	}
	h.waitLine("work.img", "personal", "mounted, in ")
	if h.leaked.Load() {
		t.Fatal("the passphrase was drawn")
	}

	// Unmounted, then mounted read-only.
	selectDisk(h)
	h.typeText("u")
	h.waitSaid("Unmounted work.img")
	h.waitLine("work.img", "personal", "not mounted")
	selectDisk(h)
	h.typeText("m")
	h.waitFor(" Mount a disk file ═")
	h.tabs(2)
	h.typeText("ro")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitSaid("Mounted work.img: its files are in ")
	if st, _ := fake.Image(img); st.MountOptions != "ro" {
		t.Fatalf("mount options: %+v", st)
	}

	// Its passphrase removed; its header backed up.
	selectDisk(h)
	h.typeText("p")
	h.waitFor("A passphrase of its own for work.img")
	h.key(tcell.KeyEnter) // remove it
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitSaid("Removed the passphrase of work.img")
	if _, err := svcontainer.CheckPassphrase(img, []byte(own)); err == nil {
		t.Fatal("the passphrase still opens it")
	}
	backup := filepath.Join(h.dir, "work.header")
	h.typeText("b")
	h.waitFor("Back up the header of work.img")
	h.typeText(backup)
	h.key(tcell.KeyEnter)
	h.waitSaid("Copied the header of work.img to " + backup)
	if st, err := os.Stat(backup); err != nil || st.Size() != svluks.DataOffset {
		t.Fatalf("backup: %v", err)
	}
	h.typeText("b")
	h.waitFor("Back up the header of work.img")
	h.typeText(backup)
	h.key(tcell.KeyEnter)
	h.waitFor("exists")
}

// 1, 2 and 3 bring the tabs forward, but not while the filter is typed in;
// the Disk tab lists every vault's disks, each with the vault that keeps
// its key, and names the vaults that are locked.
func TestTheTabsAndTheDisksOfEveryUnlockedVault(t *testing.T) {
	h := newHarness(t)
	fake := udiskstest.Start(t)
	h.withWork()
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "home", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"work", "home"} {
		img := filepath.Join(h.dir, v+".img")
		if _, err := h.admin.CreateContainer(c, svrpc.ContainerCreateParams{Vault: v, Item: "containers/" + v, Path: img, Size: 40 << 20}); err != nil {
			t.Fatal(err)
		}
	}
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks") // personal, the default
	h.waitFor("1 2 3 switch tabs")

	// Not while the filter is typed in.
	h.typeText("/2")
	h.waitFor("/ 2")
	h.do(func() {
		if h.u.tab != tabVaults {
			t.Errorf("typing 2 in the filter brought tab %d forward", h.u.tab)
		}
	})
	h.key(tcell.KeyEscape)
	h.waitGone("/ 2")

	h.typeText("2")
	h.waitFor("Encrypted disks")
	h.waitAnswering("home.img")
	h.waitAnswering("work.img")
	h.waitLine("work.img", "work", "mounted, in ")
	h.waitLine("home.img", "home", "mounted, in ")
	h.eventually("the locked vault to be named", func() bool {
		return strings.Contains(strings.Join(strings.Fields(h.u.disks.head.GetText(true)), " "), svops.DisksLockedSeen+"personal.")
	})

	// A row acts on the vault that keeps its key: unmounted, then mounted
	// again.
	h.do(func() {
		p := h.u.disks
		for r := 1; r < p.t.GetRowCount(); r++ {
			if ci, ok := p.t.GetCell(r, 0).GetReference().(svrpc.ContainerInfo); ok && ci.Vault == "home" {
				p.t.Select(r, 0)
			}
		}
	})
	h.typeText("u")
	h.waitSaid("Unmounted home.img")
	h.waitLine("home.img", "home", "not mounted")
	h.typeText("m")
	h.waitFor(" Mount a disk file ═")
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitAnswering("Mounted home.img")
	if st, _ := fake.Image(filepath.Join(h.dir, "home.img")); st.MountPoint == "" {
		t.Fatalf("home.img: %+v", st)
	}

	h.typeText("3")
	h.waitFor("Files and mail")
	h.waitFor(firstSentence(svops.DecryptPGPAbout))
	h.waitFor("Lists the security keys plugged in")
	h.typeText("1")
	h.waitFor("Locked: Enter unlocks")
	h.waitGone("Files and mail")
	h.typeText("3")
	h.waitFor("Files and mail")
	h.key(tcell.KeyEscape) // back to Vault
	h.waitGone("Files and mail")
	h.do(func() {
		if h.u.tab != tabVaults || h.u.app.GetFocus() != h.u.itemList {
			t.Errorf("Esc left tab %d, the focus on %T", h.u.tab, h.u.app.GetFocus())
		}
	})
}

// The Tools tab's Enter runs the row's tool, as the ':' menu does.
func TestTheToolsTabRunsWhatIsSelected(t *testing.T) {
	h := newHarness(t)
	h.plug(fidotest.Options{Name: "Test Key 7"})
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.typeText("3")
	h.waitFor("Security keys plugged in")
	h.do(func() {
		p := h.u.tools
		for r := 1; r < p.t.GetRowCount(); r++ {
			if tl, ok := p.t.GetCell(r, 0).GetReference().(tool); ok && tl.label == "Security keys plugged in" {
				p.t.Select(r, 0)
			}
		}
	})
	h.key(tcell.KeyEnter)
	h.waitFor("WHAT IT CAN DO")
	h.waitFor("Test Key 7")
	h.key(tcell.KeyEnter)
	h.waitFor("Opens a vault:")
	h.key(tcell.KeyEscape)
	h.waitGone("Opens a vault:")
	h.key(tcell.KeyEscape) // the panel
	h.waitGone("Test Key 7")
	h.waitFor("Files and mail") // the Tools tab, still
}

// The Disk tab shows the disk selected beside the list: its file and
// folder, size, key, state, LUKS UUID, own passphrase and what can be
// done to it. Deleting one asks first, Cancel the default; its file goes,
// and its key to the vault's deleted items. A mounted one is said to be
// in use, not asked about. The ':' menu deletes any disk file named.
func TestADiskIsShownBesideTheListAndDeleted(t *testing.T) {
	h := newHarness(t)
	fake := udiskstest.Start(t)
	img := filepath.Join(h.dir, "private.img")
	other := filepath.Join(h.dir, "other.img")
	h.unlockAdmin("")
	info, err := h.admin.CreateContainer(h.ctx(), svrpc.ContainerCreateParams{Item: "containers/private", Path: img, Size: 40 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.CreateContainer(h.ctx(), svrpc.ContainerCreateParams{Item: "disks/other", Path: other, Size: 40 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.CloseContainer(h.ctx(), other); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.typeText("2")
	h.waitLine("private.img", "personal", "mounted, in ")
	h.waitLine("other.img", "personal", "not mounted")
	h.do(func() {
		p := h.u.disks
		for r := 1; r < p.t.GetRowCount(); r++ {
			if ci, ok := p.t.GetCell(r, 0).GetReference().(svrpc.ContainerInfo); ok && ci.Item == "containers/private" {
				p.t.Select(r, 0)
			}
		}
	})
	detail := func(want ...string) {
		t.Helper()
		h.eventually("the details to say "+strings.Join(want, ", "), func() bool {
			text := h.u.diskDetail.GetText(true)
			for _, w := range want {
				if !strings.Contains(text, w) {
					return false
				}
			}
			return true
		})
	}
	detail("File: private.img", "In the folder: "+h.dir, "Size: 40 MiB", "Its key is kept in: vault personal, item containers/private",
		"State: mounted: its files are in "+info.MountPoint, "Disk ID (LUKS UUID): "+info.UUID,
		"A passphrase of its own: none; only the key kept in the vault opens it", "u  Unmount it", "x  Delete…")
	h.do(func() {
		if text := h.u.diskDetail.GetText(true); strings.Contains(text, "Mount it…") {
			t.Errorf("a mounted disk offers to be mounted:\n%s", text)
		}
	})
	h.waitFor(" private.img ") // the pane's title

	// Mounted: in use, so not asked about.
	h.typeText("x")
	h.waitSaid("private.img is in use: unmount it first (u on the Disk tab), then delete it.")
	h.do(func() {
		if front, _ := h.u.pages.GetFrontPage(); front != pageMain {
			t.Errorf("a mounted disk was asked about (%s)", front)
		}
	})
	h.typeText("u")
	h.waitSaid("Unmounted private.img")
	h.waitLine("private.img", "personal", "not mounted")
	detail("State: not mounted", "m  Mount it…")

	// Asked first; Enter is Cancel.
	h.typeText("x")
	h.waitFor("Delete the disk private.img?")
	h.waitForWords("The disk file private.img and every file in it are deleted from this computer for good.")
	h.waitForWords("Its key goes to the deleted items of vault personal")
	h.key(tcell.KeyEnter)
	h.waitGone("Delete the disk private.img?")
	if _, err := os.Stat(img); err != nil {
		t.Fatalf("Cancel deleted it: %v", err)
	}
	h.typeText("x")
	h.waitFor("Delete the disk private.img?")
	h.typeText("y")
	h.waitSaid(svops.DiskDeleted(img, "personal"))
	h.eventually("the row to go", func() bool {
		p := h.u.disks
		for r := 1; r < p.t.GetRowCount(); r++ {
			if ci, ok := p.t.GetCell(r, 0).GetReference().(svrpc.ContainerInfo); ok && ci.Path == img {
				return false
			}
		}
		return p.t.GetRowCount() == 2 // the header, and other.img
	})
	if _, err := os.Stat(img); !os.IsNotExist(err) {
		t.Fatalf("the file is still there: %v", err)
	}
	h.unlockAdmin("") // the admin connection proves itself again
	gone, err := h.admin.Deleted(h.ctx(), "", "containers/")
	if err != nil || len(gone) != 1 || gone[0].Name != "containers/private" {
		t.Fatalf("the deleted items: %+v %v", gone, err)
	}

	// From the ':' menu, by its file, on the Vault tab.
	h.typeText("1")
	h.menu("delete a disk…")
	h.waitFor(" Delete a disk ═")
	h.typeText(other)
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitFor("Delete the disk other.img?")
	h.typeText("y")
	h.waitSaid(svops.DiskDeleted(other, "personal"))
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("other.img is still there: %v", err)
	}
	if len(fake.Attached()) != 0 {
		t.Fatalf("left attached: %+v", fake.Attached())
	}
	h.typeText("2")
	h.waitFor("No encrypted disks yet")
	detail("No disk chosen.")
}

// The Disk tab lists a locked vault's disks too, by file, as the daemon
// last saw them, unlocking nothing; the details say the vault is locked,
// and U unlocks it, after which its key's item shows. New disk… with
// every vault locked offers them all, locked ones marked, and the daemon
// asks for the passphrase.
func TestTheDisksOfLockedVaultsAreListedAndUnlocked(t *testing.T) {
	h := newHarness(t)
	fake := udiskstest.Start(t)
	img := filepath.Join(h.dir, "private.img")
	h.unlockAdmin("")
	info, err := h.admin.CreateContainer(h.ctx(), svrpc.ContainerCreateParams{Item: "containers/private", Path: img, Size: 40 << 20})
	if err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.typeText("2")
	h.waitLine("private.img", "personal (locked)", "mounted, in ")
	selectDisk(h)
	detail := func(want ...string) {
		t.Helper()
		h.eventually("the details to say "+strings.Join(want, ", "), func() bool {
			text := strings.Join(strings.Fields(h.u.diskDetail.GetText(true)), " ")
			for _, w := range want {
				if !strings.Contains(text, strings.Join(strings.Fields(w), " ")) {
					return false
				}
			}
			return true
		})
	}
	detail("Its key is kept in: vault personal, which is locked", "Disk ID (LUKS UUID): "+info.UUID,
		svops.DiskVaultLocked("personal"), "U Unlock its vault", "u Unmount it")
	h.do(func() {
		if text := h.u.diskDetail.GetText(true); strings.Contains(text, "containers/private") || strings.Contains(text, "A passphrase of its own") {
			t.Errorf("a locked vault's disk shows its key's item:\n%s", text)
		}
	})
	if v := h.vaults()["personal"]; !v.Locked {
		t.Fatal("listing the disks unlocked the vault")
	}

	// U unlocks its vault: the daemon asks.
	h.typeText("U")
	h.waitFor("Unlock vault personal")
	h.typeText(pass)
	h.key(tcell.KeyEnter)
	h.waitSaid("Unlocked personal")
	h.waitLine("private.img", "personal ", "mounted, in ")
	detail("Its key is kept in: vault personal, item containers/private", "A passphrase of its own")

	// Every vault locked: New disk… offers them, marked, and the daemon
	// asks for the passphrase.
	h.lockAll()
	h.waitLine("private.img", "personal (locked)")
	second := filepath.Join(h.dir, "second.img")
	h.typeText("n")
	h.waitFor(" New disk ═")
	h.waitFor("personal (locked)")
	h.tabs(1)
	h.typeText(second)
	h.tabs(1)
	h.typeText("40M")
	h.tabs(8) // past the filesystem, its name, the item, the passphrase twice, the sector size and mount options
	h.key(tcell.KeyEnter)
	h.waitFor("Unlock vault personal")
	h.typeText(pass)
	h.key(tcell.KeyEnter)
	h.waitSaid("its key is in the item second")
	if st, _ := fake.Image(second); st.MountPoint == "" {
		t.Fatalf("second.img: %+v", st)
	}
}
