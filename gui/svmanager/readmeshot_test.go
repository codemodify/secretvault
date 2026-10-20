package svmanager

import (
	"os"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
)

// TestReadmeScreenshot draws the picture at the top of the README, from
// the test vault and never from anyone's own: a login open, its password
// masked, in the window's own frame.
//
//	SVGUI_README=$PWD/../docs/screenshots/manager.png \
//	  go test -tags theme_engine_hangar,theme_engine_plastik -run ReadmeScreenshot ./svmanager
//
// An item says which device changed it last, by the machine's name: run
// it where that name is one to show (unshare --user --map-root-user --uts
// sh -c 'hostname laptop && go test ...'). It is skipped otherwise.
func TestReadmeScreenshot(t *testing.T) {
	out := os.Getenv("SVGUI_README")
	if out == "" {
		t.Skip("SVGUI_README is not set")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UITK_DECORATIONS", "toolkit") // the frame it has on a desktop (offscreen windows have none)
	a := uitoolkit.New(uitoolkit.Options{Headless: true, Scale: 1, DisableLookWatch: true})
	secretui.UseLook(a)
	h := newHarness(t)
	h.start(Options{App: a})
	h.unlock()
	h.open("web/github.com")
	h.idle()
	widgets.DismissToasts(h.main().Content()) // "Unlocked personal." has gone by
	h.pump()
	img := h.main().Capture()
	if img == nil {
		t.Fatal("the window could not be drawn")
	}
	if err := img.WritePNGFile(out); err != nil {
		t.Fatal(err)
	}
}
