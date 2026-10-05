package svops

import (
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
)

func TestMovingSaysWhatGoesWhereAndWhoElseReadsIt(t *testing.T) {
	plan := svrpc.MoveResult{Vault: "personal", To: "team", Items: []string{"pgp/a", "pgp/b", "pgp/c", "pgp/d", "pgp/e", "pgp/f", "pgp/g"},
		Readers: &svrpc.VaultReaders{People: []string{"alice", ""}, Trustees: []string{"Bob"}, Devices: []string{"laptop"}, Sync: "sync.example.org"}}
	for _, copy := range []bool{false, true} {
		p := MovePlain(plan, copy)
		if n := strings.Count(p.Summary, ". ") + 1; n > 3 {
			t.Errorf("a summary of %d sentences: %q", n, p.Summary)
		}
		if !strings.Contains(p.Summary, `"pgp/a", "pgp/b", "pgp/c", "pgp/d", "pgp/e" and 2 more`) || len(p.Details) != 7 {
			t.Errorf("the items: %+v", p)
		}
		if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], `"alice" and a person or device without a name open it with keys of their own`) ||
			!strings.Contains(p.Notes[0], `"Bob" can get it through emergency access`) || !strings.Contains(p.Notes[0], "sync.example.org") ||
			!strings.Contains(p.Notes[0], "All of them will be able to read the items there.") {
			t.Errorf("who else reads it: %q", p.Notes)
		}
		want := map[bool]string{false: "Move 7 items", true: "Copy 7 items"}[copy]
		if p.Action != want || p.Title != strings.Replace(want, "7 items", "7 items to team?", 1) {
			t.Errorf("title %q, button %q", p.Title, p.Action)
		}
	}
	if p := MovePlain(svrpc.MoveResult{Vault: "a", To: "b", Items: []string{"x"}}, false); len(p.Notes) != 0 ||
		!strings.HasPrefix(p.Summary, `1 item goes from vault a to vault b: "x".`) {
		t.Errorf("one item, nobody else: %+v", p)
	}

	if s := MovedText(svrpc.MoveResult{Vault: "a", To: "b", Done: []string{"x", "y"}}, false); s != "Moved 2 items to vault b. Vault a's deleted items can bring them back." {
		t.Errorf("moved: %q", s)
	}
	s := MovedText(svrpc.MoveResult{Vault: "a", To: "b", Done: []string{"x"}, Both: []string{"y"}, NotDone: []string{"z"}}, false)
	for _, want := range []string{"Moved 1 item to vault b", `1 item in both vaults ("y")`, `1 item still in vault a only ("z")`, "Nothing was lost"} {
		if !strings.Contains(s, want) {
			t.Errorf("partly moved does not say %q: %q", want, s)
		}
	}
}
