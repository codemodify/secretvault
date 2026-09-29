package secretui

import (
	"os"
	"strings"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/style"
)

// MatchDesktop puts a in the desktop's dark look when the desktop prefers
// dark and nobody has chosen a look for uitoolkit's programs.
//
// A choice, when there is one, is the person's and is left alone: a
// look.json saved by uitoolkit's Settings, or UITK_THEME. Without one,
// uitoolkit opens every window in its default pack, which is light and,
// in the default build, has no dark sibling to follow the desktop to; a
// prompt that flares up white on a dark desktop is hard to read at the
// moment it matters. So the default pack's dark sibling is taken, or
// uitoolkit's plain dark pack where it has none. The display scale needs
// nothing from here: uitoolkit reads the desktop's for each window.
func MatchDesktop(a *uitoolkit.Application) {
	if a == nil || a.DesktopColorScheme() != uitoolkit.SchemeDark {
		return
	}
	if strings.TrimSpace(os.Getenv(style.ThemeEnv)) != "" {
		return
	}
	if _, err := os.Stat(uitoolkit.AppearancePath()); err == nil {
		return
	}
	ap := a.Appearance()
	if isDark(ap.Theme) {
		return
	}
	p, ok := uitoolkit.LoadTheme(uitoolkit.SchemeVariant(ap.Name, uitoolkit.SchemeDark))
	if !ok || !isDark(p.Palette) {
		if p, ok = uitoolkit.LoadTheme("dark"); !ok || !isDark(p.Palette) {
			return
		}
	}
	ap.Name, ap.Theme = p.Name, p.Palette
	a.ApplyAppearance(ap)
}

func isDark(t style.ThemeName) bool { return style.ParseTheme(string(t)) == style.ThemeDark }
