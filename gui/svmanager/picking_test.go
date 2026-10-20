package svmanager

import (
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// The items are one list, by the names it shows them by: no folders.
func TestTheItemsAreOneListWithoutFolders(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	if got := h.listRows(); !slices.Equal(got, []string{"fastmail", "github.com", "gitlab.com"}) {
		t.Fatalf("the list shows %q", got)
	}
	h.pickRow("web/github.com", 0)
	if !strings.Contains(h.text(), "Full name: web/github.com") {
		t.Fatalf("the item beside the list does not say its whole name:\n%s", h.text())
	}
	if find(h.main().Content(), func(b *widgets.ToolButton) bool { return b.AccessibleName() == "New folder" }) != nil {
		t.Fatal("there is a New folder button")
	}
	for _, l := range strings.Split(h.text(), "\n") {
		// A vault's own folder, on this computer, is another thing.
		if strings.Contains(strings.ToLower(l), "folder") && !strings.Contains(l, "vault whose folder") {
			t.Errorf("a folder is still spoken of: %q", l)
		}
	}
}

// Ctrl+click picks several items in the list, Shift+click a run of them
// and Ctrl+A all of them; Delete then deletes them, after asking.
func TestItemsArePickedTogetherAndDeleted(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.pickRow("mail/fastmail", 0)
	h.pickRow("web/gitlab.com", platform.ModCtrl)
	if got := h.m.pickedNames(); len(got) != 2 || !strings.Contains(h.text(), "2 items picked") {
		t.Fatalf("picked %v; the window says:\n%s", got, h.text())
	}
	// Ctrl+click again takes one out: the other shows alone.
	h.pickRow("web/gitlab.com", platform.ModCtrl)
	if len(h.m.picked) != 0 || h.m.cursor != "mail/fastmail" || strings.Contains(h.text(), "items picked") {
		t.Fatalf("one left picked: %v, %q; the window says:\n%s", h.m.picked, h.m.cursor, h.text())
	}
	h.pickRow("mail/fastmail", 0)
	h.pickRow("web/github.com", platform.ModShift)
	if got := h.m.pickedNames(); !slices.Equal(got, []string{"mail/fastmail", "web/github.com"}) {
		t.Fatalf("Shift+click picked %v", got)
	}
	h.win().FocusOn(h.m.ui.content)
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.pump()
	if got := h.m.pickedNames(); len(got) != 3 || !strings.Contains(h.text(), "3 items picked") {
		t.Fatalf("Ctrl+A picked %v", got)
	}
	h.pickRow("web/github.com", platform.ModCtrl)
	h.win().FocusOn(h.m.ui.content)
	h.win().Press(platform.KeyDelete)
	h.press("Delete them")
	h.said("Deleted 2 items.")
	h.waitFor("the two to go", func() bool {
		return h.m.entry("mail/fastmail") == nil && h.m.entry("web/gitlab.com") == nil && h.m.entry("web/github.com") != nil
	})
}
