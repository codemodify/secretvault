package svmanager

import (
	"errors"
	"io/fs"
	"os"

	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/style"
)

// FollowTheDesktop makes a's look follow the desktop's light or dark mode,
// unless the person has chosen a look of their own in uitoolkit's
// Settings (its look.json), which is then kept as they chose it. Call it
// once, after uitoolkit.New and before the first window.
//
// uitoolkit follows the desktop only when look.json says so, and with no
// look.json it shows its default pack in that pack's palette, whatever the
// desktop's mode. A plain build's default pack, Plastik, has no dark
// sibling to follow with, so then the manager wears the light and dark
// pair every build carries.
func FollowTheDesktop(a *app.Application) {
	if _, err := os.Stat(style.AppearancePath()); !errors.Is(err, fs.ErrNotExist) {
		return
	}
	ap := a.Appearance()
	ap.FollowDesktop = true
	if style.SchemeVariant(ap.Name, style.SchemeDark) == style.SchemeVariant(ap.Name, style.SchemeLight) {
		ap.Name, ap.Theme = "light", style.ThemeLight
	}
	a.ApplyAppearance(ap)
}
