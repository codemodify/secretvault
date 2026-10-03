package svtui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
)

func TestReferencesAreCopiedResolvedAndChecked(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "hunter2-github")
	h.unlock()

	// The item's reference, then its username field's.
	h.open("web/github.com")
	h.typeText("y")
	if got := h.lastCopy(); got != "sv://personal/web/github.com" {
		t.Fatalf("copied %q", got)
	}
	h.key(tcell.KeyRight) // to the item
	selectField(h, "username")
	h.typeText("y")
	h.eventually("the field's reference", func() bool {
		c := h.copies()
		return len(c) == 2 && c[1] == "sv://personal/web/github.com#username"
	})
	h.key(tcell.KeyLeft)

	// Resolved: masked until revealed, and copied.
	h.menu("resolve a reference")
	h.waitFor("Resolve a reference")
	h.typeText("sv://-/web/github.com#password")
	h.key(tcell.KeyEnter)
	h.waitFor("14 bytes")
	if h.leaked.Load() {
		t.Fatal("the value was drawn before it was revealed")
	}
	h.typeText("c")
	h.eventually("the value copied", func() bool {
		c := h.copies()
		return len(c) == 3 && c[2] == "hunter2-github"
	})
	h.typeText("r")
	h.waitFor("hunter2-github")
	h.key(tcell.KeyEscape)
	h.waitGone("hunter2-github")

	// An env file: each reference checked, no value shown.
	env := h.file("app.env", "# the app\nDB_PASS=sv://personal/web/gitlab.com#password\nUSER=ada\nMISSING=sv://-/no/such\n")
	h.menu("check an env file")
	h.waitFor("Check an env file")
	h.typeText(env)
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("DB_PASS")
	h.waitFor("1 of 2 references in it cannot be read")
	if strings.Contains(h.text(), "gitlab-pass-42") {
		t.Fatal("a value was shown")
	}
	h.key(tcell.KeyEscape)

	// A template, checked and filled into a new file.
	tmpl := h.file("config.tmpl", "user: ada\npass: {{ sv://-/web/gitlab.com#password }}\n")
	out := filepath.Join(h.dir, "config.yml")
	h.menu("check a template")
	h.waitFor("Check a template")
	h.typeText(tmpl)
	h.tabs(1)
	h.typeText(out)
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("The reference in it can be read")
	h.waitFor("Filled into")
	if b, _ := os.ReadFile(out); string(b) != "user: ada\npass: gitlab-pass-42\n" {
		t.Fatalf("filled: %q", b)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("the filled file's mode: %v", st.Mode())
	}
}

// selectField selects the open item's row showing field name.
func selectField(h *harness, name string) {
	h.t.Helper()
	h.eventually("the field "+name, func() bool {
		for i, r := range h.u.detail.rows {
			if r.field >= 0 && r.field < len(h.u.cur.Item.Fields) && h.u.cur.Item.Fields[r.field].Name == name {
				h.u.detail.selected = i
				return true
			}
		}
		return false
	})
}
