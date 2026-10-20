package svmanager

import (
	"fmt"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/a11y/a11ytest"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
)

// Every page and tab, and the kinds of dialog the pages open (a form, a
// plan, secrets shown once), pass the accessibility audit: everything is
// named, and nothing secret is in the tree.
func TestThePagesAreAccessible(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	inTools := func() bool { return h.m.section() == secTools && h.m.tpage != nil }
	inDisks := func() bool { return h.m.section() == secDisks && h.m.disks != nil }
	pages := []struct {
		name string
		open func(int)
		up   func() bool
		tabs int
	}{
		{"the vault's page", h.m.showVaultPage, h.m.showingVaultPage, tabSettings + 1},
		{"the keys' page", h.m.showKeysPage, h.m.showingVaultPage, tabAge + 1},
		{"the contacts' page", h.m.showContactsPage, h.m.showingVaultPage, tabDirectories + 1},
		{"the Tools tab", h.m.showTools, inTools, tabHost + 1},
		{"the Disks tab", func(int) { h.m.showDisks() }, inDisks, 1},
	}
	for _, pg := range pages {
		pg.open(0)
		h.waitFor(pg.name, pg.up)
		h.idle()
		for i := range pg.tabs {
			h.tab(i)
			h.waitFor("the tab filled", func() bool { return !strings.Contains(h.text(), "Loading…") })
			title := h.shownPage().panes[i].title
			a11ytest.Audit(t, fmt.Sprintf("%s, tab %s", pg.name, title), h.win().AccessibleTree())
		}
		h.escape()
	}
	h.m.showSection(secVaults)

	h.m.showVaultPage(tabKeyslots)
	h.idle()
	h.pressOn("Add a way to unlock…")
	a11ytest.Audit(t, "a form", h.win().AccessibleTree())
	if find(h.overlay(), func(*widgets.RadioGroup) bool { return true }).AccessibleName() != "Opens with" {
		t.Error("the choice of kind is not named")
	}
	h.escape()

	h.m.showRecoveryKey("personal", []byte("RK-1234-5678"))
	h.pump()
	a11ytest.Audit(t, "a secret shown once", h.win().AccessibleTree())
	if strings.Contains(h.text(), "RK-1234-5678") {
		t.Error("the secret is in the accessibility tree")
	}
	h.press("I have written it down")

	h.m.showPlan(svops.Plain{Title: "A plan", Summary: "It writes a file.", Action: "Do it", Details: []string{"write a file", "restart a unit"}}, func() {}, nil)
	h.pump()
	h.expand("Show details")
	h.pump()
	a11ytest.Audit(t, "a plan", h.win().AccessibleTree())
	h.press("Cancel")
}
