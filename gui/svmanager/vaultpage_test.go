package svmanager

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The vault's page, against the harness's daemon: each tab does what the
// CLI's command does, through the same daemon method or svops function.

// openVaultPage unlocks the vault and opens its page at tab.
func (h *harness) openVaultPage(tab int) *vaultPage {
	h.t.Helper()
	h.m.showVaultPage(tab)
	h.waitFor("the vault's page", h.m.showingVaultPage)
	h.idle()
	return h.m.vpage
}

// slotTypes are the vault's keyslots' types, as the daemon says.
func (h *harness) slotTypes() []string {
	h.t.Helper()
	slots, err := h.admin.Slots(h.ctx(), "")
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, s := range slots {
		out = append(out, s.Type)
	}
	return out
}

func TestKeyslotsAreListedAddedAndRemoved(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openVaultPage(tabKeyslots)
	if len(p.slots) != 1 || p.stable.CellText(0, 1) != svformat.SlotPassphrase {
		t.Fatalf("keyslots: %+v", p.slots)
	}

	// One step: the kind at the head of the form, and under it only what
	// that kind takes, the rows under it moved up with no gap
	// (uitoolkit-gaps.md, 38 and 45).
	h.pressOn("Add a keyslot…")
	shows := func(name string) bool {
		return shown(find(h.overlay(), func(c interface {
			widget.Component
			AccessibleName() string
		}) bool {
			return c.AccessibleName() == name
		}))
	}
	if !shows("Passphrase") || !shows("Repeat") || shows("Keyfile") || shows("Opening asks") || strings.Contains(h.text(), "Split it into shares") {
		t.Fatalf("adding a passphrase shows another kind's fields:\n%s", h.text())
	}
	// The first row under the label is as far below it whatever the kind
	// (the dialog itself is centred again for its new height).
	label := find(h.overlay(), func(f *widgets.TextField) bool { return f.AccessibleName() == "Label" })
	below := func(c widget.Component) float32 {
		return widget.DeviceOrigin(c).Y - widget.DeviceOrigin(label).Y - label.Bounds().Dy()
	}
	under := below(find(h.overlay(), func(f *widgets.SecretField) bool { return f.AccessibleName() == "Passphrase" }))
	h.choose("Opens with", 4)
	h.pump()
	if shows("Passphrase") || !shows("Opening asks") || !strings.Contains(h.text(), "Touch the security key plugged in when it blinks") {
		t.Fatalf("adding a security key shows another kind's fields:\n%s", h.text())
	}
	if got := below(find(h.overlay(), func(c *widgets.ComboBox) bool { return c.AccessibleName() == "Opening asks" })); math.Abs(float64(got-under)) > 1 {
		t.Fatalf("the security key's row is %v under the label, the passphrase's was %v: hidden rows left a gap", got, under)
	}
	if !shown(label) {
		t.Fatal("the label, which every kind takes, went with the kind")
	}

	// Another passphrase.
	h.choose("Opens with", 0)
	h.pump()
	h.fill("Label", "spare")
	h.fill("Passphrase", "spare passphrase 1")
	h.fill("Repeat", "spare passphrase 2")
	h.press("Add the passphrase")
	if h.problem() != "The two passphrases differ." {
		t.Fatalf("differing passphrases: %q", h.problem())
	}
	h.fill("Passphrase", "spare passphrase 1")
	h.fill("Repeat", "spare passphrase 1")
	h.press("Add the passphrase")
	h.said(`Vault personal now also opens with the passphrase "spare".`)
	h.idle()
	if got := h.slotTypes(); len(got) != 2 {
		t.Fatalf("keyslots now %v", got)
	}
	if len(p.slots) != 2 {
		t.Fatal("the tab did not show the new keyslot")
	}

	// A keyfile, made here.
	key := filepath.Join(h.dir, "vault.key")
	h.pressOn("Add a keyslot…")
	h.choose("Opens with", 2)
	h.fill("Keyfile", key)
	h.tick("Make a new keyfile there", true)
	h.press("Add the keyfile")
	h.said("Vault personal now also opens with the keyfile.")
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0o600 || st.Size() != 64 {
		t.Fatalf("the keyfile: %v %v", st, err)
	}

	// Removing one asks first.
	h.idle()
	for i, s := range p.slots {
		if s.Label == "spare" {
			p.stable.Selected = i
		}
	}
	h.pressOn("Remove…")
	if !strings.Contains(h.text(), "giving the vault a new key shuts them out") {
		t.Fatalf("removing did not say what it does not do:\n%s", h.text())
	}
	h.press("Remove the keyslot")
	h.said(`Vault personal no longer opens with the passphrase "spare".`)
	if got := h.slotTypes(); len(got) != 2 || got[0] == got[1] {
		t.Fatalf("keyslots after removing: %v", got)
	}

	// The keyfile unlocks: Vault › Unlock with… › a keyfile.
	h.win().Press(platform.KeyL, platform.ModCtrl)
	h.idle()
	h.m.unlockWith()
	h.pump()
	h.choose("Open it with", 3)
	h.press("Next")
	h.fill("Keyfile", key)
	h.press("Unlock")
	h.said("Unlocked personal.")
	h.waitFor("the items", func() bool { return h.m.listed })
}

func TestARecoveryKeySplitIntoSharesIsShownOnceAndOpensTheVault(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabKeyslots)
	h.pressOn("Add a keyslot…")
	h.choose("Opens with", 1)
	h.tick("Split it into shares", true)
	find(h.overlay(), func(f *widgets.NumberField) bool { return f.AccessibleName() == "Shares" }).Value = 3
	find(h.overlay(), func(f *widgets.NumberField) bool { return f.AccessibleName() == "Shares it takes" }).Value = 2
	h.press("Make the recovery key")
	h.waitText("Recovery shares for personal")
	shown := h.secrets()
	if len(shown) != 3 {
		t.Fatalf("%d shares shown", len(shown))
	}
	var shares [][]byte
	var held [][]byte
	for _, s := range shown {
		shares = append(shares, append([]byte(nil), s.value...))
		held = append(held, s.value)
		if strings.Contains(h.text(), string(s.value)) {
			t.Fatal("a share went into the accessibility tree")
		}
	}
	if !strings.Contains(h.text(), "any 2 of them open vault personal") {
		t.Fatalf("the threshold is not said:\n%s", h.text())
	}
	h.press("I have handed them out")
	if h.overlay() != nil {
		t.Fatalf("the shares are still up:\n%s", h.text())
	}
	for _, b := range held {
		if !allZero(b) {
			t.Fatal("a share was not wiped")
		}
	}
	if slots, _ := h.admin.Slots(h.ctx(), ""); slots[len(slots)-1].Label != svops.SplitLabel(3, 2) {
		t.Fatalf("the keyslot is labelled %q", slots[len(slots)-1].Label)
	}

	// Two of them open it, typed one at a time.
	h.win().Press(platform.KeyL, platform.ModCtrl)
	h.idle()
	h.m.unlockWith()
	h.pump()
	h.choose("Open it with", 2)
	h.press("Next")
	h.fill("Share 1", "not a share")
	h.press("Add the share")
	if h.problem() == "" {
		t.Fatal("a mistyped share was taken")
	}
	h.fill("Share 1", string(shares[2]))
	h.press("Add the share")
	if !strings.Contains(h.text(), "1 of 2 shares typed.") {
		t.Fatalf("the count is not said:\n%s", h.text())
	}
	h.fill("Share 1", string(shares[0]))
	h.press("Add the share")
	h.said("Unlocked personal.")
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
}

func TestChangingThePassphraseAndRotatingTheKey(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabKeyslots)
	h.pressOn("Change the passphrase…")
	h.waitText("Change the passphrase of personal")
	h.fill("New passphrase", "a new passphrase 9")
	h.fill("Repeat", "a new passphrase 9")
	h.press("Change the passphrase")
	h.said("Changed the passphrase of vault personal.")
	if err := h.admin.Lock(h.ctx(), "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "passphrase", Secret: []byte("a new passphrase 9")}); err != nil {
		t.Fatalf("the new passphrase does not open it: %v", err)
	}

	// Rotating: the passphrase asked for again (the GUI proves itself
	// first), a new recovery key shown once over the report.
	h.waitFor("the page to close on the lock", func() bool { return !h.m.showingVaultPage() })
	h.m.showVaultPage(tabKeyslots)
	h.idle()
	h.pressOn("Give the vault a new key…")
	h.waitFor("the rotation's form, or the daemon's question", func() bool {
		return h.m.asking != nil && h.m.asking.win != nil || strings.Contains(h.text(), "Give vault personal a new key")
	})
	if d := h.m.asking; d != nil {
		d.win.Type("a new passphrase 9")
		d.win.Press(platform.KeyReturn)
	}
	h.waitText("Give vault personal a new key")
	h.fill("Passphrase", "a new passphrase 9")
	h.fill("Repeat", "a new passphrase 9")
	h.tick("Make a new recovery key", true)
	h.press("Make a new key")
	// The vault was unlocked by another program meanwhile: the daemon
	// asks this one to prove itself before it rotates.
	h.waitFor("the recovery key, or the daemon's question", func() bool {
		return h.m.asking != nil && h.m.asking.win != nil || strings.Contains(h.text(), "Recovery key for personal")
	})
	if d := h.m.asking; d != nil {
		d.win.Type("a new passphrase 9")
		d.win.Press(platform.KeyReturn)
	}
	h.waitText("Recovery key for personal")
	rk := append([]byte(nil), h.secrets()[0].value...)
	h.press("I have written it down")
	h.waitText("The vault has a new key")
	if !strings.Contains(h.text(), "Vault personal has a new key: a key kept from before cannot read anything written from now on.") {
		t.Fatalf("the report:\n%s", h.text())
	}
	h.press("Close")
	if err := h.admin.Lock(h.ctx(), "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "recovery", Secret: rk}); err != nil {
		t.Fatalf("the new recovery key does not open it: %v", err)
	}
}

func TestASecurityKeyIsAddedAndUnlocks(t *testing.T) {
	h := newHarness(t)
	h.plug(fidotest.Options{Name: "Desk key"})
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabKeyslots)
	h.pressOn("Add a keyslot…")
	h.choose("Opens with", 4)
	h.choose("Opening asks", 2)
	h.fill("Label", "desk key")
	h.press("Add the security key")
	h.waitText("Security key added")
	if !strings.Contains(h.text(), "desk key now opens vault personal (touch") {
		t.Fatalf("what the key opens with is not said:\n%s", h.text())
	}
	h.press("Close")
	h.win().Press(platform.KeyL, platform.ModCtrl)
	h.idle()
	h.m.unlockWith()
	h.pump()
	h.choose("Open it with", 5)
	h.press("Next")
	h.said("Unlocked personal.")
}

func TestThePINOfASecurityKeyIsAskedInItsOwnWindow(t *testing.T) {
	h := newHarness(t)
	h.plug(fidotest.Options{Name: "YubiKey 5", PIN: "123456"})
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabKeyslots)
	h.pressOn("Add a keyslot…")
	h.choose("Opens with", 4)
	h.press("Add the security key")
	d := h.asking()
	if !strings.Contains(windowText(d.win), "Enter the PIN of your security key (YubiKey 5)") {
		t.Fatalf("the PIN prompt says:\n%s", windowText(d.win))
	}
	d.win.Type("123456")
	d.win.Press(platform.KeyReturn)
	h.waitText("Security key added")
	if !strings.Contains(h.text(), "PIN and touch") {
		t.Fatalf("what the key opens with is not said:\n%s", h.text())
	}
}
