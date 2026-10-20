package svmanager

import (
	"slices"
	"testing"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// The window has no menu bar: what the menus held is in buttons and the
// toolbar, and the menus, kept off screen, hold the shortcuts, in groups
// that are the window's tabs, in the order the TUI's ':' menu has them
// (svtui.menuGroups).
func TestTheMenusAreTheTabs(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	if bar := find(h.main().Content(), func(*widgets.MenuBar) bool { return true }); bar != nil {
		t.Fatal("the window shows a menu bar")
	}
	h.waitText("Vault personal is locked")
	for _, b := range []string{"Settings", "Vault", "Disk", "Tools", "Password generator…", "Quit",
		"Import", "Export", "Deleted items", "Unlock personal", "Unlock personal with…"} {
		if h.toolButton(b) == nil {
			t.Errorf("no %s button", b)
		}
	}
	// New item is the open vault's: a locked one's logo is all there is.
	if h.toolButton("New item") != nil {
		t.Error("a locked vault shows New item")
	}
	h.unlock()
	if h.toolButton("New item") == nil {
		t.Error("no New item button in an open vault")
	}
	h.openCrumb("personal")
	for _, b := range []string{"New vault", "Add a vault", "Join a synced vault", "Lock all vaults"} {
		if h.toolButton(b) == nil {
			t.Errorf("no %s button in the vaults' drop-down", b)
		}
	}
	h.closeDrop()
	var titles []string
	keys := map[platform.Key]string{}
	for _, mn := range h.m.ui.menu.Menus() {
		label, key, _ := widgets.ParseMnemonic(mn.Title)
		titles = append(titles, label)
		if key == platform.KeyUnknown {
			t.Errorf("%s has no Alt key", label)
		} else if other, ok := keys[key]; ok {
			t.Errorf("%s and %s have the same Alt key", other, label)
		}
		keys[key] = label
	}
	want := []string{"secretvault", "Vault", "Disk", "Tools"}
	if !slices.Equal(titles, want) {
		t.Errorf("the menus are %v, want %v", titles, want)
	}
}
