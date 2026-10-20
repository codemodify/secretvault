package secretui

import (
	"testing"

	"github.com/codemodify/uitoolkit/style"

	"github.com/codemodify/secretvault/svops"
)

// secretvault's look is uitoolkit's Hangar, where the program is built
// with it, and the dark pack here where it is not: dark either way, and
// the look whatever is chosen and whatever the desktop prefers.
func TestTheLookIsHangar(t *testing.T) {
	want := PackDark
	if HangarBuiltIn() {
		want = Hangar
	}
	p, ok := style.LoadTheme(want)
	if !ok {
		t.Fatalf("%s is not registered", want)
	}
	if style.ParseTheme(string(p.Palette)) != style.ThemeDark {
		t.Errorf("%s is not dark", want)
	}
	for _, look := range []string{svops.LookDesktop, svops.LookDark, svops.LookLight} {
		for _, s := range []style.ColorScheme{style.SchemeLight, style.SchemeDark, style.SchemeNoPreference} {
			if got := ThemeFor(look, s).Pack; got != want {
				t.Errorf("%s on a desktop that prefers %v gets %s", look, s, got)
			}
		}
	}
}
