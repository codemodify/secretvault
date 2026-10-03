package svtui

import (
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

// Helpers for the plans the TUI shows (plain.go).

// waitForWords waits for words the dialog up may wrap over its lines:
// what is inside its double border, line by line, read as one text.
func (h *harness) waitForWords(want string) {
	h.t.Helper()
	words := func() string {
		var in []string
		for _, l := range strings.Split(h.text(), "\n") {
			if i, j := strings.Index(l, "║"), strings.LastIndex(l, "║"); i >= 0 && j > i {
				in = append(in, l[i+len("║"):j])
			}
		}
		return strings.Join(strings.Fields(strings.Join(in, " ")), " ")
	}
	deadline := time.Now().Add(waitTime)
	for time.Now().Before(deadline) {
		if strings.Contains(words(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("%q never appeared:\n%s", want, h.text())
}

// details opens the plan's "Show details" (the buttons are Cancel, the
// action, then Show details), leaving the focus on it: Backtab is the
// action.
func (h *harness) details() {
	h.t.Helper()
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("Hide details")
}
