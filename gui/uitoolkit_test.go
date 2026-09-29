package gui

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// What secretvault asked uitoolkit for (uitoolkit-gaps.md), checked
// against the uitoolkit this module is built with: one test per item that
// was open before v0.22.1, and per gap found moving to it (25 on), named
// after the item.
//
// A test of an item uitoolkit provides pins the behaviour secretvault now
// relies on instead of its own workaround. A test of an item it does not
// provide yet pins the gap as it stands, and fails the day uitoolkit
// closes it: that failure is the signal to update uitoolkit-gaps.md and
// take out secretvault's workaround.
//
// Headless only: TestMain takes the display, the session bus and the
// user's directories away before anything runs.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "svuitk")
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
	// Set at all, even empty, these are a choice of look (item 26).
	os.Unsetenv("UITK_FONT")
	os.Unsetenv("UITK_FONT_MONO")
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

func headless(t *testing.T, scale float32) *uitoolkit.Application {
	t.Helper()
	return uitoolkit.New(uitoolkit.Options{Headless: true, Look: uitoolkit.LightLook(), Scale: scale, DisableLookWatch: true})
}

func window(t *testing.T, a *uitoolkit.Application, w, h int, content widget.Component) *uitoolkit.Window {
	t.Helper()
	win, err := a.NewWindow(uitoolkit.WindowOptions{Width: w, Height: h, Headless: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(win.Close)
	win.SetContent(content)
	a.PumpOnce()
	return win
}

// 8. SecretLabel (256978b) is uitoolkit's own label for a secret, and it
// keeps a revealed value out of the shape cache and the accessibility
// tree. What it does not do is what secretvault's secretText
// (svmanager/secret.go) does besides: its mask is a bullet per rune, so
// the screen and a screen reader both say how long the secret is, and it
// draws one line, so a private key cannot be shown in it.
func TestItem08SecretLabel(t *testing.T) {
	a := headless(t, 1)
	value := []byte("hunter2-github")
	l := widgets.NewSecretLabel(func() []byte { return value })
	l.Reveal = true
	w := window(t, a, 300, 60, widgets.NewColumn(l))
	for _, k := range style.ShapeCacheKeysForTest(w.Look().MonoFont()) {
		if strings.Contains(k, "hunter2") {
			t.Fatal("provided part broke: a revealed SecretLabel reached the shape cache")
		}
	}
	if strings.Contains(treeText(w), "hunter2") {
		t.Fatal("provided part broke: a revealed SecretLabel reached the accessibility tree")
	}

	l.Reveal = false
	short := []byte("ab")
	sl := widgets.NewSecretLabel(func() []byte { return short })
	w2 := window(t, a, 300, 60, widgets.NewColumn(l, sl))
	long, shrt := l.Measure(layout.Unbounded()).X, sl.Measure(layout.Unbounded()).X
	if long == shrt {
		t.Fatal("uitoolkit now masks a SecretLabel at a fixed length: see uitoolkit-gaps.md item 8, and consider SecretLabel for secretText")
	}
	if !strings.Contains(treeText(w2), strings.Repeat("•", len(value))) {
		t.Fatal("uitoolkit no longer tells a screen reader a SecretLabel's length: see uitoolkit-gaps.md item 8")
	}
	value = []byte("-----BEGIN KEY-----\nabc\n-----END KEY-----")
	l.Reveal = true
	if h, line := l.Measure(layout.Unbounded()).Y, w.Look().MonoFont().Height(); h > 2*line {
		t.Fatal("uitoolkit's SecretLabel now shows several lines: see uitoolkit-gaps.md item 8")
	}
}

func treeText(w *uitoolkit.Window) string {
	var b strings.Builder
	w.AccessibleTree().Walk(func(n *a11y.Node) bool {
		b.WriteString(n.Name + "\n" + n.Value + "\n" + n.Description + "\n")
		return true
	})
	return b.String()
}

// ink is how many pixels r leaves when drawn in f.
func ink(f *style.Font, r rune) int {
	img := paintengine2d.NewImage(28, 28)
	ctx := paintengine2d.NewContext(img)
	f.Draw(ctx, string(r), paintengine2d.Pt(4, 4), paintengine2d.White)
	img.Touch()
	n := 0
	for y := 0; y < 28; y++ {
		for x := 0; x < 28; x++ {
			if _, _, _, a := img.PremulAt(x, y); a > 0 {
				n++
			}
		}
	}
	return n
}

// 11. Declined by design (docs/contracts.md, "No font fallback"): a rune
// the interface face lacks draws as a box, and marks are icons (954da57,
// which the manager uses for its star, warning and paperclip). What
// secretvault types into its own labels is in the face: the ellipsis of
// "Rename…", the middle dot between an item's facts, and the bullets of
// a mask.
func TestItem11SymbolFallback(t *testing.T) {
	a := headless(t, 1)
	f := a.Look().Font()
	box := ink(f, '') // a private-use rune: the notdef box
	for _, r := range []rune{'…', '·', '•'} {
		if n := ink(f, r); n == 0 || n == box {
			t.Errorf("%q, which secretvault's labels use, is not in the interface face", r)
		}
	}
	if n := ink(f, '✓'); n != box {
		t.Fatal("the interface face draws ✓ now: see uitoolkit-gaps.md item 11")
	}
}

// 12. The lock keys (923fab0): a window can say Caps Lock is on before
// the first key where the backend can be asked (X11, Windows), and says
// when it changes. But a focus-in, which carries no modifiers on any
// backend, is taken for the lock keys being off: a window that comes back
// into focus with Caps Lock on says it is off until the next key.
func TestItem12CapsLock(t *testing.T) {
	a := headless(t, 1)
	w := window(t, a, 300, 80, widgets.NewSecretField(""))
	o := w.Surface().(*platform.Offscreen)
	o.SetLockKeys(true, false)
	if caps, _ := w.LockKeys(); !caps {
		t.Fatal("a window that has seen no key cannot say Caps Lock is on")
	}
	var got []bool
	w.OnLockKeys(func(caps, _ bool) { got = append(got, caps) })
	w.Press(platform.KeyA, platform.ModCapsLock)
	w.Press(platform.KeyA)
	if len(got) != 1 || got[0] {
		t.Fatalf("OnLockKeys said %v, want one change, to off", got)
	}

	w.Press(platform.KeyA, platform.ModCapsLock)
	w.Inject(platform.Event{Kind: platform.EventFocusOut})
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if caps, _ := w.LockKeys(); caps {
		t.Fatal("a focus-in no longer reads as Caps Lock off: see uitoolkit-gaps.md item 12, and secretui.CapsLock's asKeyboard")
	}
}

// 13. A program nobody has configured follows the desktop's dark mode
// (c98f83b): DefaultAppearance follows the desktop, and the default pack
// has a dark sibling. A choice (look.json, UITK_THEME) is left alone.
func TestItem13DarkDesktop(t *testing.T) {
	t.Cleanup(func() { style.SetDesktopColorScheme(style.SchemeNoPreference) })
	dark := func(a *uitoolkit.Application) bool {
		return style.ParseTheme(string(a.Appearance().Theme)) == style.ThemeDark
	}
	app := func() *uitoolkit.Application {
		return uitoolkit.New(uitoolkit.Options{Headless: true, DisableLookWatch: true})
	}
	for _, scheme := range []string{"dark", "light"} {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		t.Setenv("UITK_COLOR_SCHEME", scheme)
		a := app()
		if !a.Appearance().FollowDesktop || dark(a) != (scheme == "dark") {
			t.Errorf("on a %s desktop with no look chosen: %s, following %v", scheme, a.Appearance().Name, a.Appearance().FollowDesktop)
		}
	}
	// It follows while it runs, not only as it starts.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UITK_COLOR_SCHEME", "")
	style.SetDesktopColorScheme(style.SchemeLight)
	a := app()
	style.SetDesktopColorScheme(style.SchemeDark)
	a.ReloadPreferredLook()
	if !dark(a) {
		t.Errorf("the desktop went dark and %s stayed light", a.Appearance().Name)
	}

	t.Setenv("UITK_COLOR_SCHEME", "dark")
	if err := uitoolkit.SaveAppearance(style.Appearance{Name: "light"}); err != nil {
		t.Fatal(err)
	}
	if a := app(); dark(a) {
		t.Error("a saved light look was overridden")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UITK_THEME", "light")
	if a := app(); dark(a) || a.Appearance().FollowDesktop {
		t.Error("UITK_THEME was overridden")
	}
}

// 14. Gaps and padding follow the display scale (201bbd6) in FlexBox and
// Grid, and so in Form.
func TestItem14Spacing(t *testing.T) {
	a := headless(t, 2)
	inner := widgets.NewSpacerSize(10, 10)
	col := widgets.NewColumn(inner).WithPad(20)
	form := widgets.NewForm()
	form.RowGap = 6
	one, two := widgets.NewLabel("one"), widgets.NewLabel("two")
	form.AddRow("A", one)
	form.AddRow("B", two)
	window(t, a, 400, 300, widgets.NewColumn(col, form))
	if got := inner.Bounds().Min.X; got != 40 {
		t.Errorf("WithPad(20) at scale 2 is %v pixels", got)
	}
	if gap := two.Bounds().Min.Y - one.Bounds().Max.Y; gap < 11.5 {
		t.Errorf("a form's RowGap 6 at scale 2 is %v pixels", gap)
	}
}

// 15. A window as tall as its content (923fab0), at every scale.
func TestItem15FitContent(t *testing.T) {
	for _, scale := range []float32{1, 1.5, 2} {
		a := headless(t, scale)
		w, err := a.NewWindow(uitoolkit.WindowOptions{Width: 360, Height: 50, Headless: true, FitContent: true,
			Sizing: platform.SizingFixed})
		if err != nil {
			t.Fatal(err)
		}
		last := widgets.NewButton("OK", nil)
		col := widgets.NewColumn().WithGap(10).WithPad(16)
		for i := 0; i < 5; i++ {
			l := widgets.NewLabel("A line of a description long enough that it wraps at this width, once at least.")
			l.Wrap = true
			col.Add(l)
		}
		col.Add(last)
		w.SetContent(col)
		a.PumpOnce()
		_, h := w.PixelSize()
		bottom := widget.DeviceOrigin(last).Y + last.Bounds().Dy()
		if bottom > float32(h) || float32(h)-bottom > 16*scale+2 {
			t.Errorf("%.1fx: the last row ends at %v in a window %d tall", scale, bottom, h)
		}
		w.Close()
	}
}

// 16. Every pack marks its default button (256978b): Plastik and its dark
// sibling, the looks the programs open in, paint a Primary button
// differently from the others.
func TestItem16DefaultButton(t *testing.T) {
	for _, name := range []string{"plastik", "plastik-night"} {
		p, ok := uitoolkit.LoadTheme(name)
		if !ok {
			t.Fatalf("no %s in this build", name)
		}
		lk := style.Appearance{Name: p.Name, Theme: p.Palette}.Look()
		a := uitoolkit.New(uitoolkit.Options{Headless: true, Look: lk, Scale: 1, DisableLookWatch: true})
		plain, def := widgets.NewButton("Deny", nil), widgets.NewButton("Deny", nil)
		def.Primary = true
		w := window(t, a, 300, 60, widgets.NewRow(plain, def).WithGap(10).WithPad(10))
		img := w.Capture()
		pb, db := plain.Bounds(), def.Bounds()
		po, do := widget.DeviceOrigin(plain), widget.DeviceOrigin(def)
		differ := 0
		for y := 0; y < int(pb.Dy()); y++ {
			for x := 0; x < int(pb.Dx()) && x < int(db.Dx()); x++ {
				r1, g1, b1, _ := img.At(int(po.X)+x, int(po.Y)+y).RGBA()
				r2, g2, b2, _ := img.At(int(do.X)+x, int(do.Y)+y).RGBA()
				if d := absDiff(r1, r2) + absDiff(g1, g2) + absDiff(b1, b2); d/3/257 > 4 {
					differ++
				}
			}
		}
		if differ < 24 {
			t.Errorf("in %s a default button differs from another by %d pixels", name, differ)
		}
		t.Logf("%s: the default button differs by %d pixels (the pack's own face: %v)", name, differ, style.PrimaryFaceOf(lk))
	}
}

func absDiff(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

// 17. Text measured at its own width no longer wraps (256978b), and a
// form of short wrapping labels measures a line a row.
func TestItem17WrapAtOwnWidth(t *testing.T) {
	a := headless(t, 1)
	form := widgets.NewForm()
	var values []*widgets.Label
	for _, s := range []string{"/usr/bin/mail", "4242", "ssh (/usr/bin/ssh), process 3187"} {
		v := widgets.NewLabel(s)
		v.Wrap = true
		form.AddRow("Program:", v)
		values = append(values, v)
	}
	w := window(t, a, 600, 200, widgets.NewColumn(form))
	line := w.Look().Font().Height()
	for _, v := range values {
		one := v.Measure(layout.Unbounded())
		at := v.Measure(layout.Constraints{MaxW: float32(math.Ceil(float64(one.X))), MaxH: -1})
		if at.Y != one.Y {
			t.Errorf("%q is %v tall at its own width, %v unbounded", v.Text, at.Y, one.Y)
		}
		if v.Bounds().Dy() > line*1.6 {
			t.Errorf("%q's row is %v tall, a line is %v", v.Text, v.Bounds().Dy(), line)
		}
	}
}

// 18. A SecretField takes its contents only as typing and pasting.
func TestItem18SecretFieldSetBytes(t *testing.T) {
	if _, ok := reflect.TypeOf(&widgets.SecretField{}).MethodByName("SetBytes"); ok {
		t.Fatal("SecretField has SetBytes now: see uitoolkit-gaps.md item 18, and editor.go's rune-by-rune feed")
	}
}

// 19. There is no secret text area: a SecretField is one line, and a
// newline does not go into it.
func TestItem19SecretArea(t *testing.T) {
	a := headless(t, 1)
	f := widgets.NewSecretField("")
	w := window(t, a, 300, 80, f)
	w.FocusOn(f)
	w.Type("a\nb")
	b := f.Bytes()
	defer uitoolkit.WipeBytes(b)
	if string(b) != "ab" {
		t.Fatalf("a SecretField took a newline (%d bytes): see uitoolkit-gaps.md item 19", len(b))
	}
}

// 20. A window has one overlay: showing a second dismisses the first and
// runs its OnClose.
func TestItem20DialogsStack(t *testing.T) {
	a := headless(t, 1)
	root := widgets.NewColumn(widgets.NewLabel("window"))
	window(t, a, 400, 300, root)
	closed := 0
	first := widgets.NewOverlay(widgets.NewPanel("first", widgets.NewLabel("x")))
	first.OnClose = func() { closed++ }
	widget.ShowOverlay(root, first)
	a.PumpOnce()
	widget.ShowOverlay(root, widgets.NewOverlay(widgets.NewPanel("second", widgets.NewLabel("y"))))
	a.PumpOnce()
	if closed == 0 {
		t.Fatal("a second overlay left the first up: dialogs stack now, see uitoolkit-gaps.md item 20")
	}
}

// 21. A column measures a wrapping label once, at the width it is offered;
// laid out narrower, the label needs more lines than were measured, and
// what follows it is pushed outside the column's box. Rows measure again
// at the final width (fa0093a); columns do not.
func TestItem21WrapInAColumn(t *testing.T) {
	a := headless(t, 1)
	l := widgets.NewLabel(strings.Repeat("a wrapping label in a column, ", 12))
	l.Wrap = true
	ok := widgets.NewButton("OK", nil)
	col := widgets.NewColumn(l, ok).WithGap(8)
	col.SetLook(a.Look())
	sz := col.Measure(layout.Constraints{MaxW: 600, MaxH: -1})
	col.Arrange(paintengine2d.XYWH(0, 0, 300, sz.Y))
	if ok.Bounds().Max.Y <= sz.Y {
		t.Fatal("a column laid out narrower than it was measured keeps its last child inside: see uitoolkit-gaps.md item 21")
	}
}

// 22. ClickComponent clicks where a component's box is, which for a button
// below a ScrollView's fold is outside the view.
func TestItem22ClickBelowTheFold(t *testing.T) {
	a := headless(t, 1)
	pressed := false
	b := widgets.NewButton("Far down", func() { pressed = true })
	col := widgets.NewColumn(widgets.NewSpacerSize(10, 800), b)
	w := window(t, a, 300, 200, widgets.NewScrollView(col))
	w.ClickComponent(b)
	if pressed {
		t.Fatal("ClickComponent reveals what it clicks now: see uitoolkit-gaps.md item 22, and the harness's click")
	}
}

// 23. A status item says whether it is alive, not whether a host shows
// it.
func TestItem23TrayShown(t *testing.T) {
	if _, ok := reflect.TypeOf((*platform.StatusItem)(nil)).Elem().MethodByName("Shown"); ok {
		t.Fatal("StatusItem has Shown now: see uitoolkit-gaps.md item 23, and the manager's sniHostRegistered")
	}
}

// 24. A component taken out of the tree keeps its window.
func TestItem24RemoveKeepsHost(t *testing.T) {
	a := headless(t, 1)
	child := widgets.NewLabel("gone")
	root := widgets.NewColumn(child)
	window(t, a, 200, 100, root)
	root.Remove(child)
	if child.Host() == nil {
		t.Fatal("Remove clears the host now: see uitoolkit-gaps.md item 24")
	}
}

// Found while moving to v0.22.1.

// 25. Pad's insets, a Spacer's size and a ProgressBar's natural width are
// still device pixels.
func TestItem25DevicePixelLengths(t *testing.T) {
	a := headless(t, 2)
	spacer := widgets.NewSpacerSize(10, 10)
	pad := widgets.NewPad(20, widgets.NewSpacerSize(10, 10))
	bar := widgets.NewProgressBar(0)
	window(t, a, 600, 300, widgets.NewColumn(widgets.NewRow(spacer), pad, widgets.NewRow(bar)))
	if got := pad.Children()[0].Bounds().Min.X; got != 20 {
		t.Fatalf("uitoolkit now scales Pad (%v pixels): see uitoolkit-gaps.md item 25", got)
	}
	if got := spacer.Bounds().Dx(); got != 10 {
		t.Fatalf("uitoolkit now scales a Spacer's size (%v pixels): see uitoolkit-gaps.md item 25", got)
	}
	if got := bar.Bounds().Dx(); got != 160 {
		t.Fatalf("uitoolkit now scales a ProgressBar's width (%v pixels): see uitoolkit-gaps.md item 25", got)
	}
}

// 26. UITK_FONT, set with no look.json, turns following the desktop off.
func TestItem26FontEnvStopsFollowing(t *testing.T) {
	t.Cleanup(func() { style.SetDesktopColorScheme(style.SchemeNoPreference) })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UITK_COLOR_SCHEME", "dark")
	t.Setenv("UITK_FONT", "theme")
	a := uitoolkit.New(uitoolkit.Options{Headless: true, DisableLookWatch: true})
	if a.Appearance().FollowDesktop {
		t.Fatal("UITK_FONT leaves following the desktop on now: see uitoolkit-gaps.md item 26")
	}
}

// 28. A window has one OnLockKeys: a second listener replaces the first.
func TestItem28OneLockKeysListener(t *testing.T) {
	a := headless(t, 1)
	w := window(t, a, 300, 80, widgets.NewSecretField(""))
	first, second := 0, 0
	w.OnLockKeys(func(bool, bool) { first++ })
	w.OnLockKeys(func(bool, bool) { second++ })
	w.Press(platform.KeyA)
	w.Press(platform.KeyA, platform.ModCapsLock)
	if second != 1 || first != 0 {
		t.Fatalf("listeners heard %d and %d: see uitoolkit-gaps.md item 28", first, second)
	}
}

// 29. plastik-night, the default pack's dark sibling, keeps KDE 3's light
// status colours: its Danger is 2.2:1 on its background.
func TestItem29DarkStatusColours(t *testing.T) {
	p, ok := uitoolkit.LoadTheme("plastik-night")
	if !ok {
		t.Fatal("no plastik-night")
	}
	pal := style.Appearance{Name: p.Name, Theme: p.Palette}.Look().Palette()
	if r := style.ContrastRatio(pal.Danger, pal.Background); r >= 4.5 {
		t.Fatalf("plastik-night's Danger is %.1f:1 now: see uitoolkit-gaps.md item 29", r)
	}
}
