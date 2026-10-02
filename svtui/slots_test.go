package svtui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// slots lists the vault's keyslots as the CLI would.
func (h *harness) slots() []svrpc.SlotInfo {
	h.t.Helper()
	s, err := h.admin.Slots(h.ctx(), "")
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func slotTypes(slots []svrpc.SlotInfo) string {
	var out []string
	for _, s := range slots {
		out = append(out, s.Type)
	}
	return strings.Join(out, ",")
}

// onceSecrets are the secrets the once view shows.
func (h *harness) onceSecrets() []string {
	var out []string
	h.do(func() {
		if h.u.once == nil {
			return
		}
		for _, l := range h.u.once.lines {
			if l.secret != nil {
				out = append(out, string(l.secret))
			}
		}
	})
	return out
}

// closeOnce closes the once view, saying yes when asked.
func (h *harness) closeOnce() {
	h.t.Helper()
	h.key(tcell.KeyEscape)
	h.waitFor("This is not shown again")
	h.typeText("y")
	h.eventually("the once view closing", func() bool { return h.u.once == nil })
}

func TestRecoverySharesAreShownOnceAndOpenTheVault(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.typeText("K")
	h.waitFor("Keyslots · personal")
	h.waitFor("passphrase")
	h.typeText("a")
	h.waitFor("Add which keyslot to personal?")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Add a recovery key to personal")
	h.tabs(1)
	h.typeText("3")
	h.tabs(1)
	h.typeText("2")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("The recovery key, as 3 shares; any 2 of them open the vault")
	shares := h.onceSecrets()
	if len(shares) != 3 || !strings.HasPrefix(shares[0], "SVRS1-") {
		t.Fatalf("shares %q", shares)
	}
	h.waitFor(shares[0])
	h.closeOnce()
	h.waitFor("recovery key, 2 of 3 shares")

	// Lock, and open it again with two of them, typed one at a time.
	h.lockAll()
	h.waitFor("Locked: Enter unlocks")
	h.menu("unlock with")
	h.waitFor("Unlock personal with")
	for range 5 {
		h.key(tcell.KeyDown)
	}
	h.key(tcell.KeyEnter)
	h.waitFor("Share 1")
	h.typeText("SVRS1-not-a-share")
	h.key(tcell.KeyEnter)
	h.waitFor("not a valid recovery share")
	h.typeText(shares[2])
	h.key(tcell.KeyEnter)
	h.waitFor("Share 2 of 2")
	h.typeText(shares[0])
	h.key(tcell.KeyEnter)
	h.waitFor("Unlocked personal")
	if strings.Contains(h.text(), shares[2]) {
		t.Fatal("a share was drawn while it was typed")
	}
}

func TestKeyfilesPassphrasesAndRotation(t *testing.T) {
	h := newHarness(t)
	const newPass = "a brand new passphrase"
	h.start(Options{}, newPass)
	h.unlock()
	h.typeText("K")
	h.waitFor("Keyslots · personal")

	// A keyfile made here.
	keyfile := filepath.Join(h.dir, "vault.key")
	h.typeText("a")
	h.waitFor("Add which keyslot")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Add a keyfile to personal")
	h.typeText("laptop key")
	h.tabs(1)
	h.typeText(keyfile)
	h.tabs(1)
	h.key(tcell.KeyEnter) // make it here
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("Added keyfile slot")
	h.waitFor("laptop key")
	key, err := os.ReadFile(keyfile)
	if err != nil || len(key) != 64 {
		t.Fatalf("the keyfile: %d bytes, %v", len(key), err)
	}
	if got := slotTypes(h.slots()); got != "passphrase,keyfile" {
		t.Fatalf("slots %s", got)
	}

	// Removed again.
	h.do(func() {
		p := h.u.panels[pagePanel]
		for r := 1; r < p.t.GetRowCount(); r++ {
			if s, ok := p.t.GetCell(r, 0).GetReference().(svrpc.SlotInfo); ok && s.Type == "keyfile" {
				p.t.Select(r, 0)
			}
		}
	})
	h.typeText("x")
	h.waitFor("Remove keyslot")
	h.typeText("y")
	h.waitFor("Removed slot")
	if got := slotTypes(h.slots()); got != "passphrase" {
		t.Fatalf("slots after removing: %s", got)
	}

	// A new passphrase.
	h.typeText("p")
	h.waitFor("Change the passphrase of personal")
	h.typeText(newPass)
	h.tabs(1)
	h.typeText(newPass)
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("Passphrase changed")
	h.lockAll()
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(newPass)}); err != nil {
		t.Fatalf("the new passphrase: %v", err)
	}
	if h.leaked.Load() {
		t.Fatal("the new passphrase was drawn")
	}
}

func TestRotatingTheKeyShowsTheNewRecoveryKeyOnce(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.typeText("K")
	h.waitFor("Keyslots · personal")
	h.typeText("r")
	h.waitFor("Rotate the key of personal")
	h.typeText(pass)
	h.tabs(1)
	h.typeText(pass)
	h.tabs(1)
	h.key(tcell.KeyEnter) // a new recovery key
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("The vault key was rotated (epoch")
	rk := h.onceSecrets()
	if len(rk) != 1 {
		t.Fatalf("recovery keys shown: %d", len(rk))
	}
	h.closeOnce()
	h.waitFor("recovery")
	h.lockAll()
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: svformat.SlotRecovery, Secret: []byte(rk[0])}); err != nil {
		t.Fatalf("the new recovery key: %v", err)
	}
	if e, err := h.admin.Get(h.ctx(), "", "web/github.com"); err != nil || field(e, "password") != "hunter2-github" {
		t.Fatalf("after rotating: %v", err)
	}
}

func TestSecurityKeysAreListedAndAdded(t *testing.T) {
	h := newHarness(t)
	h.plug(fidotest.Options{Name: "Test Key 5"})
	h.start(Options{}, "")
	h.unlock()
	h.typeText("K")
	h.waitFor("Security keys plugged in")
	h.waitFor("Test Key 5")
	h.waitFor("can hold a keyslot")
	h.do(func() {
		p := h.u.panels[pagePanel]
		for r := 1; r < p.t.GetRowCount(); r++ {
			if _, ok := p.t.GetCell(r, 0).GetReference().(svrpc.FIDO2Device); ok {
				p.t.Select(r, 0)
			}
		}
	})
	h.typeText("i")
	h.waitFor("hmac-secret: yes")
	h.key(tcell.KeyEscape)
	h.waitGone("hmac-secret")

	h.typeText("a")
	h.waitFor("Add which keyslot")
	for range 4 {
		h.key(tcell.KeyDown)
	}
	h.key(tcell.KeyEnter)
	h.waitFor("Add the security key plugged in")
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("opens the vault with")
	if got := slotTypes(h.slots()); got != "passphrase,fido2" {
		t.Fatalf("slots %s", got)
	}
	// It opens the vault: Unlock with › a security key.
	h.lockAll()
	h.waitFor("Locked: Enter unlocks")
	h.menu("unlock with")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Unlocked personal")
}
