package secretui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// Headless windows only: TestMain takes the display, the session bus and
// the user's directories away before anything runs.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "svsecretui")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"DISPLAY": "", "WAYLAND_DISPLAY": "", "UITK_BACKEND": "", "UITK_THEME": "", "UITK_COLOR_SCHEME": "",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + filepath.Join(tmp, "no-bus"),
		"XDG_RUNTIME_DIR":          tmp, "XDG_CONFIG_HOME": filepath.Join(tmp, "config"),
		"UITK_SYSTEM_FONTS": "0",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func headless(look style.LookAndFeel) *uitoolkit.Application {
	return uitoolkit.New(uitoolkit.Options{Headless: true, Look: look, DisableLookWatch: true})
}

func TestADialogIsOpenedAsOne(t *testing.T) {
	a := headless(uitoolkit.LightLook())
	field := widgets.NewSecretField("")
	ok := widgets.NewButton("OK", nil)
	escaped := false
	f := NewFrame("Unlock vault Personal", widgets.NewColumn(widgets.NewLabel("Why"), field, ok).WithPad(16))
	f.OnEscape = func() { escaped = true }
	w, err := Open(a, "test", 460, f)
	if err != nil {
		t.Fatal(err)
	}
	a.PumpOnce()
	o := w.Surface().(*platform.Offscreen)
	if o.WindowRole() != platform.RoleDialog || !o.Centered() || !o.KeepAboveRequested() ||
		o.Sizing() != platform.SizingFixed || !o.ExcludeFromCapture() || o.Activations() == 0 {
		t.Fatalf("role %v centred %v above %v sizing %v uncaptured %v activations %d",
			o.WindowRole(), o.Centered(), o.KeepAboveRequested(), o.Sizing(), o.ExcludeFromCapture(), o.Activations())
	}
	// As tall as its content: the button is inside the window.
	_, h := w.PixelSize()
	if bottom := widget.DeviceOrigin(ok).Y + ok.Bounds().Dy(); ok.Bounds().Empty() || bottom > float32(h) {
		t.Fatalf("the last widget ends at %v in a window %d tall", bottom, h)
	}

	// The keyboard is held while the secret field has it, and only then.
	w.FocusOn(field)
	if !o.SecureInput() || !f.Holding() {
		t.Fatal("not held in the secret field")
	}
	w.FocusOn(ok)
	if o.SecureInput() || f.Holding() {
		t.Fatal("held on a button")
	}
	w.FocusOn(field)
	f.Release()
	if o.SecureInput() {
		t.Fatal("Release did not let go")
	}
	w.Press(platform.KeyEscape)
	if !escaped {
		t.Fatal("Escape did not reach the frame")
	}
}

// A password TextField is a secret too; an ordinary one is not.
func TestWhatIsASecret(t *testing.T) {
	pw := widgets.NewPasswordField("", nil)
	if !IsSecret(widgets.NewSecretField("")) || !IsSecret(pw) || IsSecret(widgets.NewTextField("", "", nil)) || IsSecret(nil) {
		t.Fatal("IsSecret is wrong")
	}
}

func dark(a *uitoolkit.Application) bool {
	return style.ParseTheme(string(a.Appearance().Theme)) == style.ThemeDark
}

// On a dark desktop, a person who never chose a look gets a dark one; a
// choice, when there is one, stands.
func TestTheDialogsFollowADarkDesktop(t *testing.T) {
	t.Cleanup(func() { style.SetDesktopColorScheme(style.SchemeNoPreference) })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	t.Setenv("UITK_COLOR_SCHEME", "light")
	a := headless(nil)
	MatchDesktop(a)
	if dark(a) {
		t.Fatal("dark on a light desktop")
	}

	t.Setenv("UITK_COLOR_SCHEME", "dark")
	a = headless(nil)
	MatchDesktop(a)
	if !dark(a) {
		t.Fatalf("%s on a dark desktop", a.Appearance().Name)
	}

	// A saved choice of a light look is kept.
	if err := uitoolkit.SaveAppearance(style.Appearance{Name: "light"}); err != nil {
		t.Fatal(err)
	}
	a = headless(nil)
	MatchDesktop(a)
	if dark(a) {
		t.Fatal("a saved light look was overridden")
	}
}
