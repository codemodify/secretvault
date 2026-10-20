package svtui

import (
	"slices"
	"testing"
)

// The ':' menu shows the groups of menuGroups and nothing else, so an
// entry filed under any other group could never be found; and no two
// entries say the same.
func TestEveryMenuEntryIsInAGroupShown(t *testing.T) {
	want := []string{"secretvault", "Vault", "Disk", "Tools"}
	if !slices.Equal(menuGroups, want) {
		t.Errorf("the groups are %v, not the desktop manager's %v", menuGroups, want)
	}
	seen := map[string]bool{}
	for _, e := range (&UI{}).menu() {
		if !slices.Contains(menuGroups, e.group) {
			t.Errorf("%q is filed under %q, which the menu does not show", e.label, e.group)
		}
		if seen[e.label] {
			t.Errorf("%q is in the menu twice", e.label)
		}
		seen[e.label] = true
	}
}
