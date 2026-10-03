package svmanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/app"
)

// TestPlanScreenshots draws the plans the desktop page asks about, in
// plain words and with their details open, to PNG files for people to
// look at: SVGUI_SHOTS=DIR go test -run PlanScreenshots ./svmanager. It is
// skipped otherwise, and nothing is carried out: each plan is cancelled.
func TestPlanScreenshots(t *testing.T) {
	dir := os.Getenv("SVGUI_SHOTS")
	if dir == "" {
		t.Skip("SVGUI_SHOTS is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UITK_COLOR_SCHEME", "light")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	a := uitoolkit.New(uitoolkit.Options{Headless: true, Scale: 1, DisableLookWatch: true})
	h := newHarness(t)
	h.start(Options{App: a})
	h.unlock()
	shoot := func(w *app.Window, name string) {
		t.Helper()
		w.App().PumpOnce()
		if err := w.WritePNG(filepath.Join(dir, name+".png")); err != nil {
			t.Fatal(err)
		}
	}
	h.fakeCLI()
	os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".mozilla"), 0o700)
	t.Cleanup(func() { os.RemoveAll(filepath.Join(os.Getenv("HOME"), ".mozilla")) })

	h.openDesktopPage(tabBrowsers)
	shoot(h.win(), "40-browsers-tab")
	h.pressOn("Let browsers use secretvault…")
	shoot(h.win(), "41-browsers-choose")
	h.tick("Firefox", true)
	h.press("Next")
	h.waitText("Let Firefox use secretvault")
	shoot(h.win(), "42-browsers-plan")
	h.expand("Show details")
	shoot(h.win(), "43-browsers-plan-details")
	h.press("Cancel")

	h.m.daemonExe = func() string { return "/opt/test/secretvaultd" }
	h.openDesktopPage(tabKeyring)
	shoot(h.win(), "44-keyring-tab")
	h.pressOn("Take over the keyring…")
	h.waitText("Make secretvault your system keyring")
	h.expand("Show details")
	shoot(h.win(), "45-keyring-plan-details")
	h.press("Cancel")

	h.openDesktopPage(tabHelpers)
	h.pressOn("Let git, docker and age use secretvault…")
	h.waitText("Let git, docker and age use secretvault")
	shoot(h.win(), "46-helpers-plan")
	h.press("Cancel")

	h.openDesktopPage(tabGnuPG)
	h.pressOn("Let gpg use the vault's keys…")
	shoot(h.win(), "47-gnupg-form")
	h.escape()
}
