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
// against the uitoolkit this module is built with: one test per item from
// 8 that was open before v0.22.1, and per gap found since (25 on), named
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

// 8. SecretLabel (256978b; 649af18): a revealed value stays out of the
// shape cache and the accessibility tree; with MaskLen the hidden label
// is measured for its mask alone and two secrets of different lengths
// read identically; Lines shows a key's lines. What it still does not do
// is 33: hidden, it holds a copy of the secret, and nothing wipes that
// copy when the label leaves the window.
func TestItem08SecretLabel(t *testing.T) {
	a := headless(t, 1)
	value := []byte("hunter2-github")
	l := widgets.NewSecretLabel(func() []byte { return value })
	l.Reveal = true
	w := window(t, a, 300, 60, widgets.NewColumn(l))
	for _, k := range style.ShapeCacheKeysForTest(w.Look().MonoFont()) {
		if strings.Contains(k, "hunter2") {
			t.Fatal("a revealed SecretLabel reached the shape cache")
		}
	}
	if strings.Contains(treeText(w), "hunter2") {
		t.Fatal("a revealed SecretLabel reached the accessibility tree")
	}

	short := []byte("ab")
	long := widgets.NewSecretLabel(func() []byte { return value })
	sl := widgets.NewSecretLabel(func() []byte { return short })
	long.MaskLen, sl.MaskLen = 8, 8
	w2 := window(t, a, 300, 80, widgets.NewColumn(long, sl))
	if lw, sw := long.Measure(layout.Unbounded()), sl.Measure(layout.Unbounded()); lw != sw {
		t.Fatalf("hidden with a fixed mask, 14 and 2 characters measure %v and %v", lw, sw)
	}
	if strings.Contains(treeText(w2), "•") {
		t.Fatal("a SecretLabel tells a screen reader its bullets")
	}

	key := []byte("-----BEGIN KEY-----\nabc\n-----END KEY-----")
	kl := widgets.NewSecretLabel(func() []byte { return key })
	kl.Reveal, kl.Lines = true, true
	window(t, a, 400, 120, widgets.NewColumn(kl))
	if h, line := kl.Measure(layout.Unbounded()).Y, w.Look().MonoFont().Height(); h < 3*line {
		t.Fatalf("a key of three lines is %v tall, a line %v", h, line)
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
// backend, is still taken for the lock keys being off (v0.22.5): a window
// that comes back into focus with Caps Lock on says it is off until the
// next key.
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

// 18. SecretField.SetBytes (58140ea) takes a buffer over and wipes the
// one it replaces: the editor puts an item's secrets in its fields so.
func TestItem18SecretFieldSetBytes(t *testing.T) {
	f := widgets.NewSecretField("")
	f.SetBytes([]byte("first"))
	old := f.Bytes()
	uitoolkit.WipeBytes(old)
	held := []byte("second\x01value")
	f.SetBytes(held)
	b := f.Bytes()
	defer uitoolkit.WipeBytes(b)
	if string(b) != "second\x01value" {
		t.Fatalf("SetBytes then Bytes gave %q", b)
	}
	f.Wipe()
	for _, c := range held {
		if c != 0 {
			t.Fatal("the buffer SetBytes took over was not wiped with the field")
		}
	}
}

// 19. SecretArea (fc42680): a SecretField over several lines, for a key.
// A SecretField still drops a newline.
func TestItem19SecretArea(t *testing.T) {
	a := headless(t, 1)
	area := widgets.NewSecretArea("")
	field := widgets.NewSecretField("")
	w := window(t, a, 400, 300, widgets.NewColumn(area, field))
	w.FocusOn(area)
	w.Type("a")
	w.Press(platform.KeyReturn)
	w.Type("b")
	b := area.Bytes()
	defer uitoolkit.WipeBytes(b)
	if string(b) != "a\nb" {
		t.Fatalf("a SecretArea holds %q after a, Return, b", b)
	}
	if !widget.IsSecretTarget(area) {
		t.Fatal("a SecretArea does not say it takes a secret")
	}
	w.FocusOn(field)
	w.Type("a\nb")
	fb := field.Bytes()
	defer uitoolkit.WipeBytes(fb)
	if string(fb) != "ab" {
		t.Fatalf("a SecretField took a newline (%d bytes)", len(fb))
	}
}

// 20. Overlays stack (fc42680): a second leaves the first up and runs
// nothing of it, and closing the second goes back to the first.
func TestItem20DialogsStack(t *testing.T) {
	a := headless(t, 1)
	root := widgets.NewColumn(widgets.NewLabel("window"))
	w := window(t, a, 400, 300, root)
	closed := 0
	first := widgets.NewOverlay(widgets.NewPanel("first", widgets.NewLabel("x")))
	first.OnClose = func() { closed++ }
	widget.ShowOverlay(root, first)
	a.PumpOnce()
	second := widgets.NewOverlay(widgets.NewPanel("second", widgets.NewLabel("y")))
	widget.ShowOverlay(root, second)
	a.PumpOnce()
	if closed != 0 || len(w.Overlays()) != 2 {
		t.Fatalf("a second overlay closed the first (%d), or is not over it (%d up)", closed, len(w.Overlays()))
	}
	widget.DismissOverlay(second)
	if closed != 0 || w.Overlay() != first {
		t.Fatal("closing the second did not go back to the first")
	}
}

// 21. An Overlay settles its card's width before asking its height
// (91133b2), so a long wrapping message in a narrow window keeps its
// buttons inside the card; the manager's confirmations did not. A column
// that is itself measured at one width and laid out at another still
// puts its last child outside its box: uitoolkit's release notes say a
// container cannot grow a box it was given, and that is the caller's.
func TestItem21WrapInAColumn(t *testing.T) {
	a := headless(t, 1)
	root := widgets.NewColumn(widgets.NewLabel("window"))
	window(t, a, 420, 500, root)
	msg := widgets.NewLabel("Allow /usr/lib/very/long/path/to/some/program/that/asks/for/a/secret to read web/github.com in vault personal, now and every time after?")
	msg.Wrap = true
	ok := widgets.NewButton("OK", nil)
	card := widgets.NewPanel("Allow?", widgets.NewColumn(msg, ok).WithGap(16).WithPad(6))
	o := widgets.NewOverlay(card)
	widget.ShowOverlay(root, o)
	a.PumpOnce()
	if okBottom, cardBottom := widget.DeviceOrigin(ok).Y+ok.Bounds().Dy(), widget.DeviceOrigin(card).Y+card.Bounds().Dy(); okBottom > cardBottom {
		t.Fatalf("the card's button ends at %v, below the card at %v", okBottom, cardBottom)
	}

	l := widgets.NewLabel(strings.Repeat("a wrapping label in a column, ", 12))
	l.Wrap = true
	last := widgets.NewButton("OK", nil)
	col := widgets.NewColumn(l, last).WithGap(8)
	col.SetLook(a.Look())
	sz := col.Measure(layout.Constraints{MaxW: 600, MaxH: -1})
	col.Arrange(paintengine2d.XYWH(0, 0, 300, sz.Y))
	if last.Bounds().Max.Y <= sz.Y {
		t.Fatal("a column laid out narrower than it was measured keeps its last child inside now: see uitoolkit-gaps.md item 21")
	}
}

// 22. ClickComponent scrolls to what it clicks (5e7a6cc).
func TestItem22ClickBelowTheFold(t *testing.T) {
	a := headless(t, 1)
	pressed := false
	b := widgets.NewButton("Far down", func() { pressed = true })
	col := widgets.NewColumn(widgets.NewSpacerSize(10, 800), b)
	w := window(t, a, 300, 200, widgets.NewScrollView(col))
	w.ClickComponent(b)
	if !pressed {
		t.Fatal("ClickComponent did not press a button below the fold")
	}
}

// 23. StatusItem.Shown and SetOnShownChange (58140ea). The fake tray
// shows its icon until told otherwise, and says when that changes. (With
// no StatusNotifierWatcher on the bus at all, the Linux item says it is
// shown: svmanager's tray test pins that half.)
func TestItem23TrayShown(t *testing.T) {
	t.Setenv("UITK_TRAY", "fake")
	item, err := platform.NewStatusItem(platform.StatusItemOptions{ID: "svuitk"})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	fake := item.(*platform.FakeStatusItem)
	var heard []bool
	item.SetOnShownChange(func(shown bool) { heard = append(heard, shown) })
	if !item.Shown() {
		t.Fatal("a fake tray is not shown")
	}
	fake.SetShown(false)
	if item.Shown() || len(heard) != 1 || heard[0] {
		t.Fatalf("hidden: shown %v, heard %v", item.Shown(), heard)
	}
}

// 24. A component taken out of the tree lets go of its window (58140ea).
func TestItem24RemoveKeepsHost(t *testing.T) {
	a := headless(t, 1)
	inner := widgets.NewLabel("gone")
	child := widgets.NewColumn(inner)
	root := widgets.NewColumn(child)
	window(t, a, 200, 100, root)
	root.Remove(child)
	if child.Host() != nil || inner.Host() != nil {
		t.Fatal("a component taken out of the tree, or its child, still has its window")
	}
}

// Found while moving to v0.22.1.

// 25. Pad's insets, a Spacer's size and a ProgressBar's natural width
// follow the display scale (36685fe).
func TestItem25DevicePixelLengths(t *testing.T) {
	a := headless(t, 2)
	spacer := widgets.NewSpacerSize(10, 10)
	pad := widgets.NewPad(20, widgets.NewSpacerSize(10, 10))
	bar := widgets.NewProgressBar(0)
	window(t, a, 600, 300, widgets.NewColumn(widgets.NewRow(spacer), pad, widgets.NewRow(bar)))
	if got := pad.Children()[0].Bounds().Min.X; got != 40 {
		t.Errorf("NewPad(20) at scale 2 is %v pixels", got)
	}
	if got := spacer.Bounds().Dx(); got != 20 {
		t.Errorf("NewSpacerSize(10, 10) at scale 2 is %v pixels", got)
	}
	if got := bar.Bounds().Dx(); got != 320 {
		t.Errorf("a ProgressBar at scale 2 is %v pixels", got)
	}
}

// 26. UITK_FONT with no look.json leaves following the desktop on
// (58140ea).
func TestItem26FontEnvStopsFollowing(t *testing.T) {
	t.Cleanup(func() { style.SetDesktopColorScheme(style.SchemeNoPreference) })
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("UITK_COLOR_SCHEME", "dark")
	t.Setenv("UITK_FONT", "theme")
	a := uitoolkit.New(uitoolkit.Options{Headless: true, DisableLookWatch: true})
	if !a.Appearance().FollowDesktop || style.ParseTheme(string(a.Appearance().Theme)) != style.ThemeDark {
		t.Fatalf("UITK_FONT on a dark desktop: %s, following %v", a.Appearance().Name, a.Appearance().FollowDesktop)
	}
}

// 27. A window opened with Center and FitContent is centred again for
// the height it is fitted to (58140ea).
func TestItem27FittedAndCentred(t *testing.T) {
	a := headless(t, 1)
	w, err := a.NewWindow(uitoolkit.WindowOptions{Width: 360, Height: 600, Headless: true,
		Center: true, FitContent: true, Sizing: platform.SizingFixed})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetContent(widgets.NewColumn(widgets.NewLabel("one line")).WithPad(16))
	a.PumpOnce()
	if _, h := w.Size(); h > 200 {
		t.Fatalf("not fitted: %d tall", h)
	}
	if n := w.Surface().(*platform.Offscreen).Centerings(); n < 2 {
		t.Fatalf("centred %d times: not again for the fitted height", n)
	}
}

// 28. widget.LockKeysWatcher, and a SecretField that marks Caps Lock
// itself (5e7a6cc): every watcher in a window hears a change. Since
// 649af18 a field asks its window as it takes the focus, so one focused
// in a window opened with Caps Lock on knows it. But the focus-in that
// every backend then sends carries no modifiers, and is now reported to
// the watchers as the lock going off (item 12): the mark goes as the
// window comes into focus.
type lockWatcher struct {
	*widgets.Label
	heard int
}

func (l *lockWatcher) LockKeysChanged(bool, bool) { l.heard++ }

func TestItem28LockKeysWatchers(t *testing.T) {
	a := headless(t, 1)
	one, two := &lockWatcher{Label: widgets.NewLabel("1")}, &lockWatcher{Label: widgets.NewLabel("2")}
	one.Label.Init(one)
	two.Label.Init(two)
	field := widgets.NewSecretField("")
	before := widgets.NewButton("before", nil)
	w := window(t, a, 300, 160, widgets.NewColumn(before, field, one, two))
	w.FocusOn(before)
	o := w.Surface().(*platform.Offscreen)
	o.SetLockKeys(true, false)
	w.FocusOn(field)
	if !field.CapsLockOn() || !field.CapsHint {
		t.Fatal("a field focused in a window with Caps Lock on does not know it")
	}
	// The window coming into focus, as X11, Wayland, Windows and AppKit
	// all send it: with no modifiers.
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if caps, _ := o.LockKeys(); !caps || field.CapsLockOn() {
		t.Fatalf("the keyboard says Caps Lock %v, the field %v: a focus-in no longer turns the mark off, see uitoolkit-gaps.md items 12 and 28", caps, field.CapsLockOn())
	}
	w.Press(platform.KeyA, platform.ModCapsLock)
	w.Press(platform.KeyA)
	if one.heard < 2 || two.heard < 2 || field.CapsLockOn() {
		t.Fatalf("watchers heard %d and %d; the field marks Caps Lock %v", one.heard, two.heard, field.CapsLockOn())
	}
}

// 29. Status colours as ink (36685fe): Palette.DangerInk and friends, and
// Label.Tone, read at 4.5:1 in plastik-night. The palette's own Danger
// stays the pack's, at 2.2:1, by design. (That they keep their colour
// is 31.)
func TestItem29DarkStatusColours(t *testing.T) {
	pal := packPalette(t, "plastik-night")
	if r := style.ContrastRatio(pal.Danger, pal.Background); r >= style.MinInkContrast {
		t.Errorf("plastik-night's own Danger is %.1f:1 now", r)
	}
	for name, c := range map[string]paintengine2d.Color{"danger": pal.DangerInk(), "warning": pal.WarningInk(), "success": pal.SuccessInk()} {
		if r := style.ContrastRatio(c, pal.Background); r < style.MinInkContrast {
			t.Errorf("plastik-night's %s ink is %.1f:1", name, r)
		}
	}
}

func packPalette(t *testing.T, name string) style.Palette {
	t.Helper()
	p, ok := uitoolkit.LoadTheme(name)
	if !ok {
		t.Fatalf("no %s in this build", name)
	}
	return style.Appearance{Name: p.Name, Theme: p.Palette}.Look().Palette()
}

// Found while moving to v0.22.2.

// 30. DismissOverlay from outside every overlay closes the top one again
// (6e1d4f9). The top one only: with two up, one is left, which is why the
// manager quits with Window.SetOverlay(nil), which closes them all.
func TestItem30DismissFromOutside(t *testing.T) {
	a := headless(t, 1)
	root := widgets.NewColumn(widgets.NewLabel("window"))
	w := window(t, a, 400, 300, root)
	closed := 0
	for _, name := range []string{"under", "over"} {
		o := widgets.NewOverlay(widgets.NewPanel(name, widgets.NewLabel(name)))
		o.OnClose = func() { closed++ }
		widget.ShowOverlay(root, o)
		a.PumpOnce()
	}
	widget.DismissOverlay(root)
	if closed != 1 || len(w.Overlays()) != 1 {
		t.Fatalf("DismissOverlay from outside closed %d, left %d up; want the top one only", closed, len(w.Overlays()))
	}
	w.SetOverlay(nil)
	if closed != 2 || w.Overlay() != nil || len(w.Overlays()) != 0 {
		t.Fatal("SetOverlay(nil) left a dialog up, or did not close it")
	}
}

// 31. Palette.Ink keeps the colour (6e1d4f9): a status colour that does
// not read is moved along its own lightness, not to white or black.
func TestItem31InkKeepsItsColour(t *testing.T) {
	for _, name := range []string{"plastik", "plastik-night"} {
		pal := packPalette(t, name)
		for what, c := range map[string][2]paintengine2d.Color{
			"danger": {pal.Danger, pal.DangerInk()}, "warning": {pal.Warning, pal.WarningInk()}, "success": {pal.Success, pal.SuccessInk()},
		} {
			declared, ink := c[0], c[1]
			if strongest(ink) != strongest(declared) || saturation(ink) < 0.5 {
				t.Errorf("%s's %s ink is %v, from %v: not the same colour", name, what, ink, declared)
			}
		}
	}
}

func strongest(c paintengine2d.Color) int {
	switch {
	case c.R >= c.G && c.R >= c.B:
		return 0
	case c.G >= c.B:
		return 1
	}
	return 2
}

func saturation(c paintengine2d.Color) float32 {
	hi, lo := max(c.R, c.G, c.B), min(c.R, c.G, c.B)
	if hi == 0 {
		return 0
	}
	return (hi - lo) / hi
}

// 32. A SecretArea takes the width it is offered and asks for what a
// SecretField does (6e1d4f9): in a grid's flexible column the two are as
// wide as each other, at every width. (Neither can fold, so the column
// still gives neither less than 180; that is Grid's rule for everything
// that cannot fold.)
func TestItem32SecretAreaInANarrowGrid(t *testing.T) {
	for _, width := range []int{360, 420, 600} {
		a := headless(t, 1)
		area := widgets.NewSecretArea("")
		field := widgets.NewSecretField("")
		g := widgets.NewGrid()
		g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1), widgets.Auto()}
		g.Place(widgets.NewLabel("private-key"), 0, 0)
		g.Place(area, 0, 1)
		g.Place(widgets.NewButton("Remove", nil), 0, 2)
		g.Place(widgets.NewLabel("pin"), 1, 0)
		g.Place(field, 1, 1)
		window(t, a, width, 300, widgets.NewColumn(g))
		if area.Bounds().Dx() != field.Bounds().Dx() {
			t.Errorf("%d wide: the area is %v, a field beside it %v", width, area.Bounds().Dx(), field.Bounds().Dx())
		}
	}
}

// Found while moving to v0.22.5.

// 33. A hidden SecretLabel holds a copy of the secret: it asks Value on
// every measure and paint and copies the answer into a buffer of its
// own, though bullets are all it draws. Nothing wipes that copy when the
// label leaves the window; only Hide does, which an application has to
// remember to call.
func TestItem33HiddenSecretLabelHoldsACopy(t *testing.T) {
	a := headless(t, 1)
	value := []byte("hunter2-github")
	l := widgets.NewSecretLabel(func() []byte { return value })
	l.MaskLen = 8
	root := widgets.NewColumn(l)
	window(t, a, 300, 60, root)
	held := reflect.ValueOf(l).Elem().FieldByName("buf")
	if held.Len() != len(value) {
		t.Fatalf("a hidden label holds %d bytes: it no longer copies what it only masks, see uitoolkit-gaps.md item 33", held.Len())
	}
	root.Remove(l)
	if held = reflect.ValueOf(l).Elem().FieldByName("buf"); held.Len() == 0 || held.Index(0).Uint() == 0 {
		t.Fatal("a label taken out of the window wipes its copy now: see uitoolkit-gaps.md item 33")
	}
	l.Hide()
}

// 34. A floor for a window, from its content (the maintainers' note on
// 32, 0.22.4). widget.MinWidthOf answers for a form, but not through a
// Splitter, which has floors of its own and does not report them; a
// TextField can be no narrower than the 180 it asks for, with no
// PreferredWidth to lower it as a SecretField has; and a window's minimum
// is set only as it is made, with nothing to change it afterwards.
func TestItem34AWindowFloorFromItsContent(t *testing.T) {
	a := headless(t, 1)
	left, right := widgets.NewPad(0, widgets.NewSpacerSize(300, 10)), widgets.NewPad(0, widgets.NewSpacerSize(300, 10))
	sp := widgets.NewSplitter(widgets.SplitColumns, left, right)
	window(t, a, 800, 200, widgets.NewColumn(sp))
	if got, panes := widget.MinWidthOf(sp), widget.MinWidthOf(left)+widget.MinWidthOf(right); got >= panes {
		t.Fatalf("a splitter says its floor is %v, its panes' %v: see uitoolkit-gaps.md item 34", got, panes)
	}
	if _, ok := reflect.TypeOf(widgets.TextField{}).FieldByName("PreferredWidth"); ok {
		t.Fatal("TextField has PreferredWidth now: see uitoolkit-gaps.md item 34")
	}
	for _, m := range []string{"SetMinSize", "SetSizeLimits", "SetMinWidth"} {
		if _, ok := reflect.TypeOf(&uitoolkit.Window{}).MethodByName(m); ok {
			t.Fatalf("Window has %s now: see uitoolkit-gaps.md item 34, and the manager's minWindowWidth", m)
		}
	}
}
