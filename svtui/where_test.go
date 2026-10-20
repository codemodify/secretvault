package svtui

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// Where things are kept, from the ':' menu: the daemon's places, grouped,
// with what each holds; Enter shows one whole, c copies its path.
func TestWhereThingsAreKeptListsTheDaemonsPlaces(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.menu("Where things are kept")
	h.waitFor("WHAT IT HOLDS")
	h.waitFor("Settings")
	h.waitFor("While running")
	h.waitFor(`The vault "personal", encrypted`)
	h.waitFor("not there yet")

	// The first place is the settings file.
	config := filepath.Join(h.dir, "home", "config.json")
	h.typeText("c")
	h.waitFor("Copied " + config)
	if !slices.Contains(h.copies(), config) {
		t.Fatalf("copied %q", h.copies())
	}
	h.key(tcell.KeyEnter)
	h.waitFor("Your settings: which vaults there are")
	h.key(tcell.KeyEscape)
	h.key(tcell.KeyEscape)
	h.waitGone("WHAT IT HOLDS")

	// The Tools tab has it too.
	h.typeText("3")
	h.waitFor("Every folder and file secretvault keeps")
}
