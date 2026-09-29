package svmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
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
	for _, light := range []bool{false, true} {
		suffix := "-dark"
		look := style.DarkLook()
		if light {
			suffix, look = "-light", style.LightLook()
		}
		h := newHarness(t)
		h.start(Options{App: uitoolkit.New(uitoolkit.Options{Look: look, Headless: true, Scale: 1, DisableLookWatch: true})})
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
		shoot(d.win, "03-prompt-again"+suffix)
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
	}
}
