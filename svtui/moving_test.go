package svtui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svrpc"
)

// withWork makes a second vault, work, left unlocked as the CLI leaves
// it, with an item of its own.
func (h *harness) withWork() {
	h.t.Helper()
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "work", Passphrase: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.admin.Put(c, "work", login("work/vpn", "ada", "vpn-secret")); err != nil {
		h.t.Fatal(err)
	}
}

// inWork reads an item of work as the CLI would.
func (h *harness) inWork(name string) (svrpc.Entry, error) {
	return h.admin.Get(h.ctx(), "work", name)
}

// waitLine waits for a line of the screen that holds every one of want.
func (h *harness) waitLine(want ...string) {
	h.t.Helper()
	deadline := time.Now().Add(waitTime)
	for time.Now().Before(deadline) {
		for _, l := range strings.Split(h.text(), "\n") {
			ok := true
			for _, w := range want {
				ok = ok && strings.Contains(l, w)
			}
			if ok {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("no line holds %q:\n%s", want, h.text())
}

// planAnswered waits for the plan titled title, answering the daemon's
// question for work's passphrase on the way, then presses its action.
func (h *harness) planAnswered(title, words string) {
	h.t.Helper()
	h.waitAnswering(title)
	h.waitForWords(words)
	h.key(tcell.KeyTab) // Cancel
	h.key(tcell.KeyTab) // the action
	h.key(tcell.KeyEnter)
	h.waitGone(title)
}

func TestMovingAnItemToAnotherVault(t *testing.T) {
	h := newHarness(t)
	h.withWork()
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("work  unlocked")
	h.open("web/gitlab.com")
	h.menu("move the item to another vault")
	h.waitFor("Move web/gitlab.com to which vault?")
	h.key(tcell.KeyEnter) // work, the only other one
	h.waitAnswering("Move 1 item to work?")
	h.waitLine("Cancel", " Move 1 item ") // the button says what it does
	h.waitForWords(`1 item goes from vault personal to vault work: "web/gitlab.com"`)
	h.planAnswered("Move 1 item to work?", "deleted items")
	h.waitSaid("Moved 1 item to vault work.")
	h.waitFor("Nothing open.") // it left this vault
	h.waitGone("gitlab.com")
	if e, err := h.inWork("web/gitlab.com"); err != nil || field(e, "password") != "gitlab-pass-42" {
		t.Fatalf("in work after moving: %v", err)
	}
	if _, err := h.get("web/gitlab.com"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("in personal after moving: %v", err)
	}
}

func TestCopyingAnItemKeepsIt(t *testing.T) {
	h := newHarness(t)
	h.withWork()
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("work  unlocked")
	h.open("mail/fastmail")
	h.typeText("+")
	h.waitFor("Copy mail/fastmail to which vault?")
	h.key(tcell.KeyEnter)
	h.planAnswered("Copy 1 item to work?", "Vault personal keeps them as they are")
	h.waitSaid("Copied 1 item to vault work.")
	if e, err := h.inWork("mail/fastmail"); err != nil || field(e, "password") != "fastmail-secret" {
		t.Fatalf("in work after copying: %v", err)
	}
	if e, err := h.get("mail/fastmail"); err != nil || field(e, "password") != "fastmail-secret" {
		t.Fatalf("in personal after copying: %v", err)
	}
	h.waitFor(" mail/fastmail ─") // still open
}

func TestMovingTheItemsWhoseNamesStartAlike(t *testing.T) {
	h := newHarness(t)
	h.withWork()
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("work  unlocked")
	h.open("web/github.com")
	h.menu("move the items whose names start")
	h.waitFor("Move items to another vault")
	h.waitLine("Names that start with:", "web/") // the open item's folder
	h.key(tcell.KeyEnter)
	h.waitFor("Move the items whose names start with web/ to which vault?")
	h.key(tcell.KeyEnter)
	h.planAnswered("Move 2 items to work?", "2 items go from vault personal to vault work")
	h.waitSaid("Moved 2 items to vault work.")
	h.waitFor("Nothing open.")
	for _, name := range []string{"web/github.com", "web/gitlab.com"} {
		if _, err := h.inWork(name); err != nil {
			t.Fatalf("%s in work after moving: %v", name, err)
		}
		if _, err := h.get(name); !errors.Is(err, svrpc.ErrNotFound) {
			t.Fatalf("%s in personal after moving: %v", name, err)
		}
	}
	if _, err := h.get("mail/fastmail"); err != nil {
		t.Fatalf("an item of another folder moved too: %v", err)
	}
}

func TestMovingWithNoOtherVaultSaysSo(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.open("web/gitlab.com")
	h.typeText(">")
	h.waitSaid("There is no other vault to move it to: N makes one.")
	h.menu("copy the items whose names start")
	h.waitFor("Copy items to another vault")
	h.key(tcell.KeyEnter)
	h.waitSaid("There is no other vault to copy them to: N makes one.")
}
