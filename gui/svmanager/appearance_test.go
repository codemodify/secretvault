package svmanager

import (
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
)

// Settings › Appearance shows the look, and says it is the only one: the
// windows are in it whatever the desktop is set to, and there is nothing
// to pick.
func TestTheLookIsShownInSettings(t *testing.T) {
	t.Setenv(svcore.EnvConfig, t.TempDir())
	h := newHarness(t)
	h.start(Options{})
	secretui.UseLook(h.app)
	h.waitText("Vault personal is locked")
	h.m.showSettings(tabSetAppearance)
	h.idle()
	for _, want := range []string{"one look", "ask for a passphrase", "A sample of the look"} {
		if !strings.Contains(h.text(), want) {
			t.Fatalf("Appearance lacks %q:\n%s", want, h.text())
		}
	}
	if find(h.area(), func(*widgets.RadioButton) bool { return true }) != nil {
		t.Fatal("Appearance offers a choice of looks")
	}
	if got, want := h.app.Theme().Pack, secretui.ThemeFor(svops.LookDesktop, style.SchemeLight).Pack; got != want {
		t.Fatalf("the windows are in %q", got)
	}
}
