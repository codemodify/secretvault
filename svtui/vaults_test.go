package svtui

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// menu runs an action from the ':' menu, found by typing part of its name.
func (h *harness) menu(find string) {
	h.t.Helper()
	h.typeText(":")
	h.waitFor("Actions — type to find")
	h.typeText(find)
	h.key(tcell.KeyEnter)
	h.waitGone("Actions — type to find")
}

// waitAnswering waits for want, typing the passphrase whenever the
// daemon asks whether this terminal may use a vault.
func (h *harness) waitAnswering(want string) {
	h.t.Helper()
	deadline := time.Now().Add(waitTime)
	for s := h.text(); !strings.Contains(s, want); s = h.text() {
		if strings.Contains(s, "has not used vault") {
			h.typeText(pass)
			h.key(tcell.KeyEnter)
			h.waitGone("has not used vault")
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%q never appeared:\n%s", want, s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// eventually waits for cond, checked on the manager's goroutine.
func (h *harness) eventually(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(waitTime)
	for time.Now().Before(deadline) {
		ok := false
		h.do(func() { ok = cond() })
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("%s never happened:\n%s", what, h.text())
}

// vaults lists the vaults as the CLI would.
func (h *harness) vaults() map[string]svrpc.VaultInfo {
	h.t.Helper()
	vs, err := h.admin.Vaults(h.ctx())
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]svrpc.VaultInfo{}
	for _, v := range vs {
		out[v.Name] = v
	}
	return out
}

func TestANewVaultShowsItsRecoveryKeyOnce(t *testing.T) {
	h := newHarness(t)
	const newPass = "the work passphrase"
	h.start(Options{}, newPass)
	h.waitFor("Locked: Enter unlocks")
	h.typeText("N")
	h.waitFor("New vault")
	h.typeText("work")
	h.tabs(3) // the folder, the suite
	h.typeText("short")
	h.tabs(1)
	h.typeText("short")
	h.tabs(2) // the recovery key, then Create
	h.key(tcell.KeyEnter)
	h.waitFor("Use at least 8 characters")
	h.key(tcell.KeyBacktab) // back to the recovery key
	h.key(tcell.KeyEnter)   // ticked
	h.key(tcell.KeyBacktab)
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(newPass)
	h.key(tcell.KeyBacktab)
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(newPass)
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitFor("Recovery key for work")
	h.waitFor("shown only now")
	h.waitFor("No items yet") // listed without asking again: the passphrase was presented
	var held []byte
	h.do(func() {
		for _, l := range h.u.once.lines {
			if l.secret != nil {
				held = l.secret
			}
		}
	})
	rk := string(bytes.Clone(held))
	if !strings.Contains(h.text(), rk) {
		t.Fatalf("the recovery key %q is not shown:\n%s", rk, h.text())
	}
	if h.leaked.Load() {
		t.Fatal("the passphrase was drawn")
	}
	v, ok := h.vaults()["work"]
	if !ok || v.Locked {
		t.Fatalf("after creating it: %+v", h.vaults())
	}
	// The key opens it, on its own.
	if err := h.admin.Lock(h.ctx(), "work", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "work", &svrpc.Key{Type: svformat.SlotRecovery, Secret: []byte(rk)}); err != nil {
		t.Fatalf("the recovery key shown does not open the vault: %v", err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "work", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(newPass)}); err != nil {
		t.Fatalf("the passphrase typed does not open the vault: %v", err)
	}

	// Closing asks first, since it is never shown again; then it is wiped.
	h.key(tcell.KeyEscape)
	h.waitFor("This is not shown again")
	h.typeText("n")
	h.waitFor("Recovery key for work")
	h.closeOnce()
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("the recovery key is still held after the view closed")
	}
}

func TestTheVaultsPanelSaysWhereEachIsAndWhenItLocks(t *testing.T) {
	h := newHarness(t)
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "work", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	h.start(Options{}, "")
	h.unlock()
	h.typeText("V")
	h.waitFor("NAME")
	h.waitFor("15 min idle")
	h.waitFor("personal *")
	h.waitFor(filepath.Base(h.vaults()["work"].Path))

	// The second row is work: make it the default.
	h.key(tcell.KeyDown)
	h.typeText("d")
	h.waitFor("work is the default vault")
	if !h.vaults()["work"].Default {
		t.Fatal("work is not the default")
	}
	h.waitFor("work *")

	// Open at login: on, through the fake sealer.
	h.typeText("o")
	h.waitFor("Open work when you log in?")
	h.waitForWords("Anyone who can use your logged-in account can then open this vault")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab) // Cancel, then Open it at login
	h.key(tcell.KeyEnter)
	h.waitAnswering("Vault work opens when you log in")
	if !h.vaults()["work"].LoginUnlock {
		t.Fatal("work does not open at login")
	}

	// Verify, from the row's own menu (Enter).
	h.key(tcell.KeyEnter)
	h.waitFor("What to do with it?")
	h.typeText("vvvv") // not keys of a list: nothing happens
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Vault work is sound")
	h.waitFor("is as secretvault wrote it")
	h.key(tcell.KeyEscape)
	h.waitGone("is as secretvault wrote it")

	// Forget it; then add its folder back under another name.
	path := h.vaults()["work"].Path
	h.typeText("x")
	h.waitFor("Forget vault work?")
	h.typeText("y")
	h.waitFor("Forgot vault work")
	if _, ok := h.vaults()["work"]; ok {
		t.Fatal("work is still registered")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("forgetting removed the folder: %v", err)
	}
	h.typeText("a")
	h.waitFor("Add an existing vault")
	h.typeText("job")
	h.tabs(1)
	h.typeText(path)
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("Added vault job")
	if v, ok := h.vaults()["job"]; !ok || v.Path != path {
		t.Fatalf("after adding: %+v", h.vaults())
	}
	h.key(tcell.KeyEscape)
	h.waitGone("15 min idle")
}

func TestUnlockingWithAKeyfileOrRecoveryShares(t *testing.T) {
	h := newHarness(t)
	c := h.ctx()
	if _, err := h.admin.Unlock(c, "", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 64)
	if _, err := h.admin.AddSlot(c, svrpc.SlotAddParams{Type: svformat.SlotKeyfile, Secret: key}); err != nil {
		t.Fatal(err)
	}
	keyfile := filepath.Join(h.dir, "vault.key")
	if err := os.WriteFile(keyfile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.admin.Lock(c, "", true); err != nil {
		t.Fatal(err)
	}
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.menu("unlock with")
	h.waitFor("Unlock personal with")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Keyfile")
	h.typeText(keyfile)
	h.key(tcell.KeyEnter)
	h.waitFor("Unlocked personal")
	h.waitFor("web/github.com")
}

func TestTheHelpSaysTheVersionsAndTheStatus(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.menu("about")
	h.waitFor("About secretvault")
	h.waitFor("secretvaultd")
	h.waitFor("prompts:")
	h.key(tcell.KeyEscape)
	h.waitGone("About secretvault")
	h.typeText("?")
	h.waitFor("secretvault-tui")
	h.waitFor("the action menu")
}
