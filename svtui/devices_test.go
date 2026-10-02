package svtui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// selectWhere selects the panel's first row whose reference is a T that
// match accepts.
func selectWhere[T any](h *harness, match func(T) bool) {
	h.t.Helper()
	h.eventually("a row to select", func() bool {
		p := h.u.panels[pagePanel]
		if p == nil {
			return false
		}
		for r := 1; r < p.t.GetRowCount(); r++ {
			if v, ok := p.t.GetCell(r, 0).GetReference().(T); ok && match(v) {
				p.t.Select(r, 0)
				return true
			}
		}
		return false
	})
}

func TestDevicesAreNamedVouchedForAndRemoved(t *testing.T) {
	h := newHarness(t)
	// Another device opens the same folder, and registers itself.
	other := newHarness(t)
	path := h.vaults()["personal"].Path
	if _, err := other.admin.AddVault(other.ctx(), "shared", path); err != nil {
		t.Fatal(err)
	}
	if _, err := other.admin.Unlock(other.ctx(), "shared", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := other.admin.LabelDevice(other.ctx(), "shared", "", "the other one"); err != nil {
		t.Fatal(err)
	}

	h.start(Options{}, "")
	h.unlock()
	h.typeText("D")
	h.waitFor("Devices · personal")
	h.waitFor("this device")
	h.waitFor("the other one")
	h.waitFor("not vouched for")
	h.waitFor("Every revision counts")

	// Name this one.
	selectWhere(h, func(d svrpc.Device) bool { return d.This })
	h.typeText("l")
	h.waitFor("Label:")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText("my laptop")
	h.key(tcell.KeyEnter)
	h.waitFor(`is now "my laptop"`)

	// Vouch for the other, then remove it.
	selectWhere(h, func(d svrpc.Device) bool { return !d.This })
	h.typeText("v")
	h.waitFor("Vouch for")
	h.typeText("y")
	h.waitFor("This device vouches for")
	h.waitFor("vouched for")
	selectWhere(h, func(d svrpc.Device) bool { return !d.This })
	h.typeText("x")
	h.waitFor("Remove device?")
	h.typeText("y")
	h.waitFor("Removed device")
	h.waitFor("removed")

	// Only signed revisions count.
	h.typeText("s")
	h.waitFor("Count only revisions of personal signed")
	h.typeText("y")
	h.waitFor("Only revisions signed by a device registered here count")
	h.unlockAdmin("")
	p, err := h.admin.Signatures(h.ctx(), "", nil)
	if err != nil || !p.Require {
		t.Fatalf("the policy: %+v %v", p, err)
	}
}

func TestProgramsAreAllowedAndDeniedAheadOfTime(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.typeText("G")
	h.waitFor("Grants · personal")
	h.waitFor("No decisions remembered")
	h.typeText("a")
	h.waitFor("Allow a program · personal")
	h.typeText("/usr/bin/true")
	h.tabs(1)
	h.typeText("web/gitlab.com")
	h.tabs(2)
	h.typeText(",list")
	h.tabs(1)
	h.key(tcell.KeyEnter) // until the vault locks
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("allow-until-lock: true (/usr/bin/true) may read,list")
	h.typeText("n")
	h.waitFor("Deny a program · personal")
	h.typeText("flatpak:org.example.Spy")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("deny-always")
	h.unlockAdmin("")
	gs, err := h.admin.Grants(h.ctx(), "")
	if err != nil || len(gs) != 2 {
		t.Fatalf("grants %+v %v", gs, err)
	}
}
