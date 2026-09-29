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

// A dialog is as tall as what it says, at any display scale: its last row
// is inside the window and there is no empty band under it. The height is
// settled as the window is opened, before its first frame, so it is
// centred for the height it opens at.
func TestADialogIsAsTallAsItsContent(t *testing.T) {
	for _, scale := range []float32{1, 1.5, 2} {
		for _, lines := range []int{1, 6} {
			a := uitoolkit.New(uitoolkit.Options{Headless: true, Look: uitoolkit.LightLook(), Scale: scale, DisableLookWatch: true})
			body := widgets.NewColumn().WithGap(10).WithPad(16)
			for i := 0; i < lines; i++ {
				l := widgets.NewLabel("A description long enough to wrap in a dialog of this width, at least once.")
				l.Wrap = true
				body.Add(l)
			}
			ok := widgets.NewButton("OK", nil)
			body.Add(ok)
			w, err := Open(a, "test", 460, NewFrame("Unlock vault Personal", body))
			if err != nil {
				t.Fatal(err)
			}
			_, opened := w.Size()
			a.PumpOnce()
			if _, h := w.Size(); h != opened {
				t.Errorf("%.1fx, %d lines: opened %d tall, laid out %d tall", scale, lines, opened, h)
			}
			_, h := w.PixelSize()
			bottom := widget.DeviceOrigin(ok).Y + ok.Bounds().Dy()
			if bottom > float32(h) || float32(h)-bottom > 16*scale+2 {
				t.Errorf("%.1fx, %d lines: the last row ends at %v in a window %d tall", scale, lines, bottom, h)
			}
			w.Close()
		}
	}
}

// The Caps Lock line shows while Caps Lock is on: before the first key
// where the window can tell, and as it is toggled.
func TestTheCapsLockLine(t *testing.T) {
	a := headless(uitoolkit.LightLook())
	field := widgets.NewSecretField("")
	caps := NewCapsLock()
	f := NewFrame("Unlock vault Personal", widgets.NewColumn(field, caps).WithPad(16))
	w, err := Open(a, "test", 460, f)
	if err != nil {
		t.Fatal(err)
	}
	a.PumpOnce()
	o := w.Surface().(*platform.Offscreen)

	// Caps Lock pressed and released, as a keyboard sends it: the press
	// carries the state before, the release the state after.
	toggle := func(on bool) {
		before, after := platform.ModCapsLock, platform.Modifiers(0)
		if on {
			before, after = after, before
		}
		w.Inject(platform.Event{Kind: platform.EventKeyDown, Mods: before})
		o.SetLockKeys(on, false)
		w.Inject(platform.Event{Kind: platform.EventKeyUp, Mods: after})
		a.PumpOnce()
	}

	o.SetLockKeys(true, false)
	caps.Follow(w)
	if !caps.On() {
		t.Fatal("not shown with Caps Lock on before the first key")
	}
	w.FocusOn(field)
	toggle(false)
	if caps.On() {
		t.Fatal("still shown with Caps Lock off")
	}
	toggle(true)
	if !caps.On() || caps.Bounds().Empty() {
		t.Fatal("not shown when Caps Lock was turned on")
	}
	w.Press(platform.KeyA, platform.ModCapsLock)
	// Coming back into focus is not Caps Lock going off.
	w.Inject(platform.Event{Kind: platform.EventFocusOut})
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if !caps.On() {
		t.Fatal("hidden when the window came back into focus, with Caps Lock still on")
	}
	caps.Stop()
	if caps.On() {
		t.Fatal("shown after Stop")
	}
	toggle(false)
	toggle(true)
	if caps.On() {
		t.Fatal("still following after Stop")
	}
}

// The icon is the header's padlock on the header's colour.
func TestTheIcon(t *testing.T) {
	img := Icon(32)
	if img.Width != 32 || img.Height != 32 {
		t.Fatalf("%dx%d", img.Width, img.Height)
	}
	opaque := 0
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] == 255 {
			opaque++
		}
	}
	if opaque < 32*32/2 {
		t.Fatalf("only %d of its pixels are painted", opaque)
	}
}
