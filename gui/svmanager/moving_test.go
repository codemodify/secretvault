package svmanager

import (
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svrpc"
)

// menu runs the entry text of the menu title, as a click on it does; it
// must be enabled.
func (h *harness) menu(title, text string) {
	h.t.Helper()
	for _, mn := range h.m.ui.menu.Menus() {
		if mn.Title != title {
			continue
		}
		for _, it := range mn.Items {
			if it.Text != text {
				continue
			}
			if it.Disabled {
				h.t.Fatalf("%s › %s is greyed out; the window says:\n%s", title, text, h.text())
			}
			it.OnClick()
			h.pump()
			return
		}
	}
	h.t.Fatalf("there is no %s › %s", title, text)
}

// namesIn are the names of vault's items, as the CLI lists them,
// presenting the key.
func (h *harness) namesIn(vault string) []string {
	h.t.Helper()
	if _, err := h.admin.Unlock(h.ctx(), vault, &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
	entries, err := h.admin.List(h.ctx(), vault, "")
	if err != nil {
		h.t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Item.Name)
	}
	slices.Sort(names)
	return names
}

// toWork chooses vault work in the dialog up, and waits for the plan,
// answering work's passphrase when the daemon asks this program for it.
func (h *harness) toWork(title string) {
	h.t.Helper()
	if !strings.Contains(h.text(), "work") {
		h.t.Fatalf("the vaults offered are not work; the window says:\n%s", h.text())
	}
	h.choose("To vault", 0)
	h.press("Next")
	h.until("the plan", pass, func() bool { return strings.Contains(h.text(), title) })
	h.idle()
}

func TestAnItemMovesToAnotherVaultFromTheEditMenu(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()
	h.open("web/github.com")

	h.menu("&Edit", "Move to vault…")
	h.waitText("Move web/github.com to another vault")
	h.toWork("Move 1 item to work?")
	for _, want := range []string{"goes from vault personal to vault work", "deleted items"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("the plan does not say %q:\n%s", want, h.text())
		}
	}
	if b := button(h.overlay(), "Move 1 item"); b == nil {
		t.Fatalf("the plan has no Move 1 item button:\n%s", h.text())
	}
	h.press("Move 1 item")
	h.said("Moved 1 item to vault work.")
	h.waitFor("the item gone from the list", func() bool {
		return h.m.listed && !h.m.listing && h.m.entry("web/github.com") == nil && len(h.m.entries) == 3
	})
	h.idle()
	if h.m.cur != nil {
		t.Fatalf("the moved item is still open: %s", h.m.cur.Item.Name)
	}
	if got := h.namesIn("work"); !slices.Equal(got, []string{"web/github.com"}) {
		t.Fatalf("work holds %v", got)
	}
	if got := h.namesIn("personal"); slices.Contains(got, "web/github.com") {
		t.Fatalf("personal still holds it: %v", got)
	}
	e, err := h.admin.Get(h.ctx(), "work", "web/github.com")
	if err != nil || field(e, "password") != "hunter2-github" {
		t.Fatalf("in work: %v, %v", e.Item.Name, err)
	}
}

func TestACopyKeepsTheItem(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()
	h.selectItem("mail/fastmail")

	// The item's own page offers it too.
	h.click(h.win(), button(h.m.ui.pane, "Copy to vault…"))
	h.pump()
	h.waitText("Copy mail/fastmail to another vault")
	h.toWork("Copy 1 item to work?")
	h.press("Copy 1 item")
	h.said("Copied 1 item to vault work.")
	h.idle()
	if h.m.entry("mail/fastmail") == nil {
		t.Fatal("the copied item left the list")
	}
	if got := h.namesIn("work"); !slices.Equal(got, []string{"mail/fastmail"}) {
		t.Fatalf("work holds %v", got)
	}
	if got := h.namesIn("personal"); !slices.Contains(got, "mail/fastmail") {
		t.Fatalf("personal lost it: %v", got)
	}
}

func TestAFolderMovesToAnotherVault(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()

	// With "All items" chosen there is no folder to move.
	if !menuEntry(h, "Move folder to vault…").Disabled {
		t.Fatal("Move folder to vault… is offered with no folder chosen")
	}
	n := h.m.findFolder("web/")
	if n == nil {
		t.Fatal("no folder web/")
	}
	h.m.ui.folders.Selected = n
	h.m.folderSelected(n)
	h.pump()

	h.menu("&Edit", "Move folder to vault…")
	h.waitText("Move folder web/ to another vault")
	h.toWork("Move 2 items to work?")
	for _, want := range []string{"web/github.com", "web/gitlab.com"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("the plan does not name %s:\n%s", want, h.text())
		}
	}
	h.press("Move 2 items")
	h.said("Moved 2 items to vault work.")
	h.waitFor("the folder gone", func() bool {
		return h.m.listed && !h.m.listing && len(h.m.entries) == 2 && h.m.folder == ""
	})
	h.idle()
	if got := h.namesIn("work"); !slices.Equal(got, []string{"web/github.com", "web/gitlab.com"}) {
		t.Fatalf("work holds %v", got)
	}
	if got := h.namesIn("personal"); !slices.Equal(got, []string{"2fa/example", "mail/fastmail"}) {
		t.Fatalf("personal holds %v", got)
	}
}

// menuEntry is the menu entry text, in whichever menu it is.
func menuEntry(h *harness, text string) *widgets.MenuItem {
	h.t.Helper()
	for _, mn := range h.m.ui.menu.Menus() {
		for _, it := range mn.Items {
			if it.Text == text {
				return it
			}
		}
	}
	h.t.Fatalf("there is no %s", text)
	return nil
}

func TestWithNoOtherVaultMovingSaysSo(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.selectItem("web/github.com")
	h.menu("&Edit", "Move to vault…")
	h.said("There is no other vault to move it to: File › New vault… makes one.")
	if h.overlay() != nil {
		t.Fatalf("a dialog came up:\n%s", h.text())
	}
	h.menu("&Edit", "Copy to vault…")
	h.said("There is no other vault to copy it to")
}

// A plan the daemon refuses is said in the dialog, which stays up: a name
// the other vault has already.
func TestAMoveOntoANameTakenIsRefusedBeforeAnything(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	if _, err := h.admin.Unlock(h.ctx(), "work", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Put(h.ctx(), "work", login("web/gitlab.com", "someone", "else")); err != nil {
		t.Fatal(err)
	}
	h.start(Options{Vault: "personal"})
	h.unlock()
	h.selectItem("web/gitlab.com")
	h.menu("&Edit", "Move to vault…")
	h.waitText("Move web/gitlab.com to another vault")
	h.choose("To vault", 0)
	h.press("Next")
	var said string
	h.until("the refusal", pass, func() bool { said = h.problem(); return said != "" })
	if !strings.Contains(said, "web/gitlab.com") {
		t.Fatalf("the dialog says %q", said)
	}
	if h.m.entry("web/gitlab.com") == nil {
		t.Fatal("the item went")
	}
}
