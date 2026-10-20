package svops

import (
	"strings"
	"testing"
)

// The confirmations both managers show about sharing, syncing and a
// vault's devices say themselves in plain words first (docs/wording.md):
// a title, a summary of at most three sentences without internal names,
// and a button that says what it does.
func TestSharingPlansAreSaidPlainly(t *testing.T) {
	key := "329e6239ed925e042e8b6ff07c497071"
	plans := map[string]Plain{
		"deny":               DenyEmergencyPlain("Ada", "personal"),
		"remove sync device": RemoveSyncDevicePlain("personal", "laptop", key),
		"remove, no label":   RemoveSyncDevicePlain("personal", "", key),
		"stop sync":          StopSyncPlain("personal"),
		"vouch":              VouchPlain("laptop", key),
		"withdraw":           WithdrawPlain("laptop"),
		"remove device":      RemoveDevicePlain("", key),
		"remove directory":   RemoveDirectoryPlain("example"),
	}
	for name, p := range plans {
		if strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.Summary) == "" {
			t.Errorf("%s: no title or no summary: %+v", name, p)
		}
		if n := strings.Count(p.Summary, ". ") + 1; n > 3 {
			t.Errorf("%s: a summary of %d sentences: %q", name, n, p.Summary)
		}
		// (The Ways to unlock tab may be named, as where to go.)
		for _, word := range []string{"sv://", "keyslot", "recipient", "epoch", "secretvault "} {
			if strings.Contains(p.Title+" "+p.Summary, word) {
				t.Errorf("%s says %q: %q / %q", name, word, p.Title, p.Summary)
			}
		}
		switch p.Action {
		case "", "OK", "Yes", "Do it", "Remove", "Undo":
			t.Errorf("%s: the button %q does not say what it does", name, p.Action)
		}
	}
	// The key to compare is in the words read, not folded away.
	if !strings.Contains(VouchPlain("laptop", key).Summary, key) {
		t.Error("vouching does not show the key to compare")
	}
}
