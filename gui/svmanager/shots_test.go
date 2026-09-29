package svmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// TestScreenshots draws the manager's windows to PNG files, for people to
// look at: SVGUI_SHOTS=DIR go test -run Screenshots ./svmanager. It is
// skipped otherwise; nothing is drawn anywhere but into those files.
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("SVGUI_SHOTS")
	if dir == "" {
		t.Skip("SVGUI_SHOTS is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	shoot := func(w *app.Window, name string) {
		t.Helper()
		w.App().PumpOnce()
		if err := w.WritePNG(filepath.Join(dir, name+".png")); err != nil {
			t.Fatal(err)
		}
	}
	for _, scheme := range []string{"dark", "light"} {
		// The look the program starts in, in a desktop of each mode.
		suffix := "-" + scheme
		t.Setenv("UITK_COLOR_SCHEME", scheme)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		a := uitoolkit.New(uitoolkit.Options{Headless: true, Scale: 1, DisableLookWatch: true})
		h := newHarness(t)
		h.start(Options{App: a})
		h.waitText("Vault personal is locked")
		h.idle()
		shoot(h.win(), "01-locked"+suffix)

		h.win().Press(platform.KeyU, platform.ModCtrl)
		d := h.asking()
		d.win.Type("not it")
		shoot(d.win, "02-prompt"+suffix)
		d.win.Press(platform.KeyReturn)
		h.waitFor("the second question", func() bool { return h.m.asking != nil && h.m.asking.id != d.id })
		d = h.asking()
		capsLock(d.win, true, h.pump) // the usual reason for a refusal
		shoot(d.win, "03-prompt-again"+suffix)
		capsLock(d.win, false, h.pump)
		d.win.Type(pass)
		d.win.Press(platform.KeyReturn)
		h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
		h.idle()
		h.selectItem("web/github.com")
		shoot(h.win(), "04-selected"+suffix)

		h.open("web/github.com")
		shoot(h.win(), "05-open"+suffix)
		h.win().Press(platform.KeyR, platform.ModCtrl)
		shoot(h.win(), "06-revealed"+suffix)

		h.open("2fa/example")
		shoot(h.win(), "07-otp"+suffix)

		h.win().FocusOn(h.m.ui.search)
		h.win().Type("git")
		h.idle()
		shoot(h.win(), "08-search"+suffix)
		h.win().Press(platform.KeyEscape)

		h.selectItem("web/github.com")
		h.win().Press(platform.KeyE, platform.ModCtrl)
		h.waitFor("the editor", func() bool { return h.m.editor != nil })
		h.idle()
		shoot(h.win(), "09-editor"+suffix)
		h.win().Press(platform.KeyG, platform.ModCtrl)
		shoot(h.win(), "10-generator"+suffix)
		h.win().Press(platform.KeyEscape)
		h.win().Press(platform.KeyEscape)

		// Two remembered decisions, as a person might have made them.
		h.prove()
		for _, g := range []svrpc.GrantAddParams{
			{Program: "/usr/bin/git", Item: "web/github.com", Decision: "allow-always"},
			{Program: "/usr/bin/curl", Decision: "deny-always"},
		} {
			if _, err := h.admin.Grant(h.ctx(), g); err != nil {
				t.Logf("grant %s: %v", g.Program, err)
			}
		}
		h.win().Press(platform.KeyG, platform.ModCtrl|platform.ModShift)
		h.waitFor("the vault page", h.m.showingVaultPage)
		h.idle()
		shoot(h.win(), "11-grants"+suffix)
		h.m.vpage.tabs.Select(1)
		shoot(h.win(), "12-audit"+suffix)
		h.win().Press(platform.KeyEscape)

		h.selectItem("web/github.com")
		h.win().Press(platform.KeyH, platform.ModCtrl)
		h.waitFor("the history", h.m.showingHistory)
		h.idle()
		shoot(h.win(), "13-history"+suffix)
		h.win().Press(platform.KeyEscape)

		h.m.newVault()
		shoot(h.win(), "14-new-vault"+suffix)
		d2 := h.overlay()
		name := find(d2, func(f *widgets.TextField) bool { return f.Placeholder == "personal, work…" })
		h.win().FocusOn(name)
		h.win().Type("work")
		for _, ph := range []string{"At least 8 characters", "The same again"} {
			h.win().FocusOn(find(d2, func(f *widgets.SecretField) bool { return f.Placeholder == ph }))
			h.win().Type("work passphrase 1")
		}
		h.win().Press(platform.KeyReturn)
		h.waitText("Recovery key for work")
		shoot(h.win(), "15-recovery-key"+suffix)
		h.click(h.win(), button(h.overlay(), "I have written it down"))
		h.idle()

		h.m.showVault("personal", false)
		h.idle()
		h.selectItem("web/gitlab.com")
		h.win().FocusOn(h.m.ui.items)
		h.win().Press(platform.KeyDelete)
		shoot(h.win(), "16-delete"+suffix)
		h.win().Press(platform.KeyEscape)

		h.win().Press(platform.KeyF1)
		shoot(h.win(), "17-keys"+suffix)
		h.win().Press(platform.KeyEscape)

		h.stopDaemon()
		h.waitText("No connection to secretvaultd")
		shoot(h.win(), "18-gone"+suffix)
	}

	// A conflict, and its history.
	h := newHarness(t)
	h.addConflicted()
	h.start(Options{Vault: "shared"})
	h.waitText("Vault shared is locked")
	h.unlockAgain()
	h.open("site")
	shoot(h.win(), "19-conflict-dark")
	h.win().Press(platform.KeyH, platform.ModCtrl)
	h.waitFor("the history", h.m.showingHistory)
	h.idle()
	for i, e := range h.m.hist.entries {
		if h.m.hist.heads[e.Rev] {
			h.m.hist.table.Selected = i
			h.m.openRevision(i)
		}
	}
	shoot(h.win(), "20-conflict-history-dark")
}
