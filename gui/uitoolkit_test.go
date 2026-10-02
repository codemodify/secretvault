package gui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
// read identically; Lines shows a key's lines. Since v0.23.1 a masked
// label keeps no copy of the secret (33).
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
// when it changes. Since v0.23.1 (285b6b7) a focus-in, which carries no
// modifiers on any backend, leaves the lock state alone: a window that
// comes back into focus with Caps Lock on still says so, and no watcher
// hears it go off. What is left is the other half: a Wayland surface
// still cannot be asked (it is no LockKeysSurface, though the backend
// keeps the xkb state the compositor sends after its enter), so there a
// prompt says nothing of Caps Lock until the first key or pointer event.
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
	got = nil
	w.Inject(platform.Event{Kind: platform.EventFocusOut})
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if caps, _ := w.LockKeys(); !caps || len(got) != 0 {
		t.Fatalf("after a focus-in the window says Caps Lock %v, and OnLockKeys heard %v: a focus-in reads as the lock off again, see uitoolkit-gaps.md item 12", caps, got)
	}

	if uitoolkitHas(t, "wayland*_linux.go", "func (s *wlSurface) LockKeys(") {
		t.Fatal("a Wayland surface can be asked for the lock keys now: see uitoolkit-gaps.md item 12")
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
// in a window opened with Caps Lock on knows it, and since v0.23.1 the
// focus-in every backend then sends, with no modifiers, leaves the mark
// alone (item 12).
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
	heard := one.heard
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if caps, _ := o.LockKeys(); !caps || !field.CapsLockOn() || one.heard != heard {
		t.Fatalf("the keyboard says Caps Lock %v, the field %v, a watcher heard %d changes more: a focus-in turns the mark off again, see uitoolkit-gaps.md items 12 and 28",
			caps, field.CapsLockOn(), one.heard-heard)
	}
	w.Press(platform.KeyA, platform.ModCapsLock)
	w.Press(platform.KeyA)
	if one.heard-heard < 2 || two.heard-heard < 2 || field.CapsLockOn() {
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

// 33. A masked SecretLabel keeps no copy of the secret (6126bcd): it
// takes the rune count from what Value hands it and lets the bytes go.
// Revealed, it draws from a copy of its own, as it says; that copy is
// zeroed the first time the label is drawn masked again, and when the
// label leaves its window, with no Hide called. (The manager's secretText
// keeps no copy even revealed: it draws from the caller's bytes.)
func TestItem33AMaskedSecretLabelKeepsNoCopy(t *testing.T) {
	a := headless(t, 1)
	value := []byte("hunter2-github")
	l := widgets.NewSecretLabel(func() []byte { return value })
	l.MaskLen = 8
	root := widgets.NewColumn(l)
	window(t, a, 300, 60, root)
	// all is the label's buffer to its capacity, what it left behind
	// there included; held is the part it draws from.
	all := func() []byte {
		buf := reflect.ValueOf(l).Elem().FieldByName("buf")
		out := make([]byte, buf.Cap())
		for i := range out {
			out[i] = byte(buf.Slice(0, buf.Cap()).Index(i).Uint())
		}
		return out
	}
	held := func() []byte {
		return all()[:reflect.ValueOf(l).Elem().FieldByName("buf").Len()]
	}
	if n := len(held()); n != 0 {
		t.Fatalf("a masked label holds %d bytes: it copies what it only masks again, see uitoolkit-gaps.md item 33", n)
	}
	if l.Len() != 14 {
		t.Fatalf("a masked label says the value is %d runes long", l.Len())
	}

	l.Reveal = true
	l.RequestLayout()
	a.PumpOnce()
	if string(held()) != string(value) {
		t.Fatal("a revealed label does not draw from a copy of its own, which is what this pin checks is wiped")
	}
	l.Reveal = false
	l.RequestLayout()
	a.PumpOnce()
	if b := all(); strings.Contains(string(b), "hunter2") || len(held()) != 0 {
		t.Fatal("a label masked again keeps what it showed: see uitoolkit-gaps.md item 33")
	}

	l.Reveal = true
	l.RequestLayout()
	a.PumpOnce()
	root.Remove(l)
	if b := all(); strings.Contains(string(b), "hunter2") {
		t.Fatal("a revealed label taken out of the window keeps what it showed: see uitoolkit-gaps.md item 33")
	}
}

// 34. A window's floor from its content (afa38a3, 3a0fba6). A Splitter
// answers widget.MinWidthOf with its panes' floors and its bar; a
// TextField has PreferredWidth, and its floor follows it; and a window's
// minimum can be stated after the window is made (Window.SetMinSize,
// platform.SizeLimitSurface on all four backends), once the content that
// decides it is there. That it does not last is 44.
func TestItem34AWindowFloorFromItsContent(t *testing.T) {
	a := headless(t, 1)
	left, right := widgets.NewPad(0, widgets.NewSpacerSize(300, 10)), widgets.NewPad(0, widgets.NewSpacerSize(300, 10))
	sp := widgets.NewSplitter(widgets.SplitColumns, left, right)
	w := window(t, a, 800, 200, widgets.NewColumn(sp))
	if got, panes := widget.MinWidthOf(sp), widget.MinWidthOf(left)+widget.MinWidthOf(right); got <= panes {
		t.Fatalf("a splitter says its floor is %v, its panes' and its bar's %v: see uitoolkit-gaps.md item 34", got, panes)
	}
	narrow := widgets.NewTextField("", "", nil)
	narrow.PreferredWidth = 120
	window(t, a, 400, 80, widgets.NewColumn(narrow))
	if got := widget.MinWidthOf(narrow); got != 120 {
		t.Fatalf("a TextField asking for 120 has a floor of %v: see uitoolkit-gaps.md item 34", got)
	}
	floor := widget.MinWidthOf(w.Content()) / w.Scale()
	if !w.SetMinSize(floor, 0) {
		t.Fatal("a window's minimum cannot be stated after it is made: see uitoolkit-gaps.md item 34")
	}
	if mw, mh := w.MinSize(); mw != float32(int(floor+0.5)) || mh != 0 {
		t.Fatalf("stated %v by nothing, the window's minimum is %v by %v", floor, mw, mh)
	}
}

// uitoolkitDir is uitoolkit's platform package as this test is built
// against it, for the gaps that are about what the code does where no
// headless window can show it.
func uitoolkitDir() string {
	file, _ := runtime.FuncForPC(reflect.ValueOf(platform.ClipboardGetSecret).Pointer()).FileLine(0)
	return filepath.Dir(file)
}

// uitoolkitSource reads a file of uitoolkit's platform package.
func uitoolkitSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(uitoolkitDir(), name))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	return string(b)
}

// uitoolkitHas reports whether any file of the platform package that
// matches glob holds needle.
func uitoolkitHas(t *testing.T, glob, needle string) bool {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(uitoolkitDir(), glob))
	if len(files) == 0 {
		t.Skipf("uitoolkit's source is not where it was built from: no %s", glob)
	}
	for _, f := range files {
		if strings.Contains(uitoolkitSource(t, filepath.Base(f)), needle) {
			return true
		}
	}
	return false
}

// uitoolkitFunc is the source of one function of the platform package:
// name, a method of recv where recv is not empty.
func uitoolkitFunc(t *testing.T, file, recv, name string) string {
	t.Helper()
	src := uitoolkitSource(t, file)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name {
			continue
		}
		on := ""
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok {
					on = id.Name
				}
			}
		}
		if on == recv {
			return src[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset]
		}
	}
	t.Fatalf("uitoolkit's %s has no %s.%s: what this pin reads has moved", file, recv, name)
	return ""
}

// Found in the audit of v0.23.0.

// 35. A secret on the Linux clipboard (e54cba4) is carried as bytes to
// both owners, each of which keeps a copy of its own and zeroes it when
// the selection is given up, cleared or replaced; the X11 owner serves
// from the slice itself, with no C.CString; and a paste from another
// program has a bytes path on X11 and Wayland. Three things fall short:
// the Wayland owner makes a string of the secret at every paste (41), a
// pasted secret still leaves copies nothing wipes (42), and on X11 a
// paste of the program's own copy reads the last paste instead (43).
func TestItem35TheLinuxSecretClipboardIsBytes(t *testing.T) {
	set := uitoolkitFunc(t, "clipboard_secret_linux.go", "", "clipboardNativeSetSecret")
	get := uitoolkitFunc(t, "clipboard_secret_linux.go", "", "clipboardNativeGetSecret")
	if strings.Contains(set, "string(") || strings.Contains(get, "string(") ||
		!strings.Contains(get, "wlClipGetBytes") || !strings.Contains(get, "x11ClipGetBytes") {
		t.Fatal("the Linux secret clipboard goes through a string again: see uitoolkit-gaps.md items 7 and 35")
	}
	own := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "setClipboardSelBytes")
	wipe := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "wipeClipLocked")
	serve := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleSelReq")
	take := uitoolkitFunc(t, "x11_linux.go", "", "x11ClipGetBytes")
	if !strings.Contains(own, "append([]byte(nil), b...)") || !strings.Contains(wipe, "] = 0") ||
		strings.Contains(serve, "C.CString(") || strings.Contains(serve, "string(") ||
		strings.Contains(take, "string(") || !strings.Contains(take, "c.pasteData = nil") {
		t.Fatal("the X11 owner no longer holds, serves and hands over a secret as bytes it zeroes: see uitoolkit-gaps.md item 35")
	}
	cache := uitoolkitFunc(t, "wlstate.go", "clipCache", "setBytes")
	zero := uitoolkitFunc(t, "wlstate.go", "clipCache", "wipe")
	gone := uitoolkitFunc(t, "wlstate.go", "clipCache", "invalidate")
	if !strings.Contains(cache, "c.wipe()") || !strings.Contains(zero, "] = 0") || !strings.Contains(gone, "c.wipe()") {
		t.Fatal("the Wayland owner no longer zeroes what it held: see uitoolkit-gaps.md item 35")
	}
}

// 36. A form's value is read as itself (570438f): Form.AddRow no longer
// names a Label after its caption, so a row of "Program:" and a program
// is read as both; a field that takes input is still named after its
// caption.
func TestItem36AFormValueIsReadAsItself(t *testing.T) {
	a := headless(t, 1)
	form := widgets.NewForm()
	form.AddRow("Program:", widgets.NewLabel("/usr/bin/mail"))
	name := widgets.NewTextField("", "", nil)
	form.AddRow("Name:", name)
	w := window(t, a, 400, 80, form)
	if !strings.Contains(treeText(w), "/usr/bin/mail") {
		t.Fatal("a form's label value is not read aloud: see uitoolkit-gaps.md item 36, and the prompt's facts")
	}
	if got := name.AccessibleName(); got != "Name" {
		t.Fatalf("a form's text field is named %q, not after its caption", got)
	}
}

// 37. Secure input says what is in effect (3c3c2c7): Window.SecureInputHeld
// and OnSecureInput, called on every change, which on X11 is the grab
// itself (a SecureInputHeldSurface); and a request made before an X11
// window is mapped is recorded and the grab taken at the map, with no
// wait, then retaken at each focus-in before the window hears of it.
// Headless, the offscreen surface records the request and reads as
// held. What was asked and not given: a failed grab is still no
// diagnostic.
func TestItem37SecureInputHeld(t *testing.T) {
	a := headless(t, 1)
	w := window(t, a, 300, 80, widgets.NewSecretField(""))
	var heard []bool
	w.OnSecureInput(func(held bool) { heard = append(heard, held) })
	if w.SecureInputHeld() {
		t.Fatal("a window says it holds the keyboard before it was asked to")
	}
	w.SetSecureInput(true)
	if !w.SecureInputHeld() || len(heard) != 1 || !heard[0] {
		t.Fatalf("asked to hold the keyboard: held %v, OnSecureInput heard %v", w.SecureInputHeld(), heard)
	}
	w.SetSecureInput(false)
	if w.SecureInputHeld() || len(heard) != 2 || heard[1] {
		t.Fatalf("let go of the keyboard: held %v, OnSecureInput heard %v", w.SecureInputHeld(), heard)
	}

	set := uitoolkitFunc(t, "x11_secure_linux.go", "x11Surface", "SetSecureInput")
	if !strings.Contains(set, "if !s.mapped {") || !uitoolkitHas(t, "x11_linux.go", "s.grabIfWantedLocked()") ||
		!uitoolkitHas(t, "x11_secure_linux.go", "func (s *x11Surface) SecureInputHeld() bool") ||
		!uitoolkitHas(t, "x11_linux.go", "defer s.secureFocusChangedLocked(true)") {
		t.Fatal("X11 secure input asks a window that is not mapped yet again, or no longer says what is in effect: see uitoolkit-gaps.md item 37")
	}
	if uitoolkitHas(t, "x11_secure_linux.go", "diag.") {
		t.Fatal("a failed X11 grab is a diagnostic now: see uitoolkit-gaps.md item 37")
	}
}

// Found while bringing the manager level with the CLI.

// 38. A form's rows can be shown and hidden (021593b): Form.Row returns
// the row, hiding it hides its caption with its field, out of the
// accessibility tree too, and once the form is laid out again the rows
// under it move up. How far, and when, is 45.
func TestItem38AFormRowShownOrHidden(t *testing.T) {
	a := headless(t, 1)
	form, mid, last := keyslotForm(true)
	w := window(t, a, 400, 200, widgets.NewColumn(form, widgets.NewLabel("under")))
	shown := widget.DeviceOrigin(last).Y
	mid.SetVisible(false)
	form.RequestLayout()
	a.PumpOnce()
	if mid.Visible() || mid.Label.Visible() || mid.Field.Visible() || strings.Contains(treeText(w), "Keyfile") {
		t.Fatal("a hidden form row, its caption or its field is still there, or still read aloud: see uitoolkit-gaps.md item 38")
	}
	if got := widget.DeviceOrigin(last).Y; got >= shown {
		t.Fatalf("with a row hidden the next stays at %v: see uitoolkit-gaps.md item 38", got)
	}
	mid.SetVisible(true)
	form.RequestLayout()
	a.PumpOnce()
	if got := widget.DeviceOrigin(last).Y; got != shown {
		t.Fatalf("a row shown again puts the next at %v, not %v", got, shown)
	}
}

// keyslotForm is a form of three rows, or of two without the middle one:
// the middle one, if any, and the field of the last.
func keyslotForm(withKeyfile bool) (*widgets.Form, *widgets.FormRow, *widgets.TextField) {
	form := widgets.NewForm()
	form.RowGap = 6
	form.Row("Passphrase", widgets.NewTextField("", "", nil))
	var mid *widgets.FormRow
	if withKeyfile {
		mid = form.Row("Keyfile", widgets.NewTextField("", "", nil))
	}
	last := widgets.NewTextField("", "", nil)
	form.Row("Shares", last)
	return form, mid, last
}

// probe records the widths it is offered.
type probe struct {
	widget.Base
	unbounded bool
	bounded   float32 // the narrowest width it was measured at, if any
	height    float32 // what it asks for, whatever it is offered (0: what it is offered)
}

func newProbe() *probe {
	p := &probe{}
	p.Init(p)
	return p
}

func (p *probe) Measure(c layout.Constraints) paintengine2d.Point {
	if !c.HasMaxW() {
		p.unbounded = true
	} else if p.bounded == 0 || c.MaxW < p.bounded {
		p.bounded = c.MaxW
	}
	if p.height > 0 {
		return paintengine2d.Pt(100, p.height)
	}
	return c.Constrain(paintengine2d.Pt(600, 20))
}

func (p *probe) Arrange(r paintengine2d.Rect) { p.SetBounds(r) }

// 39. A Grid measures what is in an Auto or Flex column with no width to
// keep to, however narrow the grid: a cell that wraps to the width it is
// offered (the manager's secret text, drawn from bytes) reports one long
// line as its column's natural width, so the manager breaks a long key at
// a fixed number of characters. The maintainers say so in v0.23.1's
// "Known not done", and that heights are measured at the column's real
// width: that much holds.
func TestItem39AGridCellIsOfferedNoWidth(t *testing.T) {
	a := headless(t, 1)
	p := newProbe()
	g := widgets.NewGrid()
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
	g.Place(widgets.NewLabel("Share 1"), 0, 0)
	g.Place(p, 0, 1)
	window(t, a, 300, 100, widgets.NewColumn(g))
	if p.bounded == 0 || p.bounded > 300 {
		t.Errorf("a Flex cell's height is not measured at its column's width (narrowest offered: %v)", p.bounded)
	}
	if !p.unbounded {
		t.Fatal("a Grid offers its Flex cells a width now: see uitoolkit-gaps.md item 39, and the manager's wrapAt")
	}
}

// 40. A dialog taller than its window (bba1c63): DialogCard's body
// scrolls and its action row stays at the foot, in view. But only
// DialogCard's, whose body is a string: an Overlay of any other card (a
// form, secrets, a QR code: the manager's dialogs) is still held to the
// window and lays out what does not fit past its foot, buttons and all.
// So the manager keeps dialogs short: a QR code in a dialog of its own,
// long lists in a box of their own height.
func TestItem40ADialogTallerThanItsWindow(t *testing.T) {
	a := headless(t, 1)
	col := widgets.NewColumn()
	window(t, a, 400, 300, col)
	read := widgets.NewButton("OK", nil)
	plan := widgets.NewOverlay(widgets.DialogCard("Plan", strings.Repeat("a line of the plan\n", 60), read))
	plan.Modal = true
	widget.ShowOverlay(col, plan)
	a.PumpOnce()
	if b := widget.DeviceBounds(read); b.Dy() <= 0 || b.Max.Y > 300 {
		t.Fatalf("a DialogCard with a long body puts its button at %v, outside a window 300 tall: see uitoolkit-gaps.md item 40", b)
	}
	widget.DismissOverlay(plan)

	tall := newProbe()
	tall.height = 600 // as a QR code is: it does not shrink
	ok := widgets.NewButton("Done", nil)
	card := widgets.NewPanel("Tall", widgets.NewColumn(tall, ok))
	card.Window = true
	o := widgets.NewOverlay(card)
	o.Modal = true
	widget.ShowOverlay(col, o)
	a.PumpOnce()
	body, button := widget.DeviceBounds(tall), widget.DeviceBounds(ok)
	if body.Max.Y <= button.Min.Y && button.Max.Y <= 300 {
		t.Fatalf("a tall dialog keeps its buttons in view now (body %v, button %v): see uitoolkit-gaps.md item 40", body, button)
	}
}

// Found in the audit of v0.23.1.

// 41. The Wayland owner serves a secret from a string: it holds the bytes
// and zeroes them, but each paste another program asks for is answered
// with clipCache.get, which is string(c.data), and the string is turned
// into bytes again to write to the pipe. Every paste leaves two copies of
// the passphrase that nothing can wipe.
func TestItem41WaylandServesASecretFromAString(t *testing.T) {
	send := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataSend")
	write := uitoolkitFunc(t, "wayland_linux.go", "", "wlSendSelection")
	get := uitoolkitFunc(t, "wlstate.go", "clipCache", "get")
	if !strings.Contains(send, "c.clip.get()") || !strings.Contains(write, "text string") || !strings.Contains(get, "string(c.data)") {
		t.Fatal("the Wayland owner serves a secret from its bytes now: see uitoolkit-gaps.md item 41")
	}
}

// 42. A secret pasted from another program leaves copies nothing wipes,
// though it no longer arrives as a string on Linux: when the bytes path
// fails, ClipboardGetSecret reads the clipboard again as a string; the
// Wayland reader's 4 KiB buffer, which the secret passes through, is
// never zeroed, and nor is the property X11 hands back (XFree does not
// zero it, the reason v0.23.1 gave for dropping C.CString on the serving
// side); and on Windows and macOS there is no bytes path at all.
func TestItem42APastedSecretLeavesCopies(t *testing.T) {
	get := uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardGetSecret")
	loop := uitoolkitFunc(t, "wayland_transfer_linux.go", "", "wlReadLoop")
	notify := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleSelNotify")
	win := uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardNativeGetSecret")
	mac := uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardNativeGetSecret")
	for what, open := range map[string]bool{
		"a failed bytes read falls back to a string": strings.Contains(get, "s := ClipboardGet()"),
		"the Wayland read buffer is not zeroed":      !strings.Contains(loop, "clear(buf)") && !strings.Contains(loop, "buf[i] = 0"),
		"the X11 property is freed unzeroed":         strings.Contains(notify, "C.GoBytes") && !strings.Contains(notify, "memset") && !strings.Contains(notify, "bzero"),
		"Windows has no bytes path":                  strings.Contains(win, "return nil, false"),
		"macOS has no bytes path":                    strings.Contains(mac, "return nil, false"),
	} {
		if !open {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 42", what)
		}
	}
}

// 43. On X11 a paste of what this program itself put on the clipboard
// reads the last paste from another program instead, or nothing (new in
// v0.23.1): readSelection no longer answers an owned selection with what
// it serves, and both readers then take pasteData, which is whatever the
// last paste from elsewhere left there. So Ctrl+C then Ctrl+V between two
// of the program's own fields pastes something else, and into a
// SecretField pastes nothing.
func TestItem43X11ReadsItsOwnCopyAsTheLastPaste(t *testing.T) {
	read := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "readSelection")
	text := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "readSelectionString")
	if strings.Contains(read, "clipData") || !strings.Contains(text, "string(c.pasteData)") {
		t.Fatal("X11 reads its own selection as what it serves again: see uitoolkit-gaps.md item 43")
	}
}

// 44. A window's minimum stated after it is made (34) does not last: a
// resize of the window by the program puts WindowOptions' minimum back on
// Windows (winSurface.Resize) and headless, and a change of its resize
// policy does on every backend (syncLimits), as rolling a Wayland window
// up and down does. The manager states its floor again whenever the page
// it shows changes.
func TestItem44AStatedMinimumDoesNotLast(t *testing.T) {
	a := headless(t, 1)
	w, err := a.NewWindow(uitoolkit.WindowOptions{Width: 800, Height: 400, MinWidth: 300, MinHeight: 200, Headless: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	w.SetContent(widgets.NewLabel("x"))
	a.PumpOnce()
	w.SetMinSize(600, 0)
	if mw, mh := w.MinSize(); mw != 600 || mh != 200 {
		t.Fatalf("stated 600 by nothing, the minimum is %v by %v", mw, mh)
	}
	w.SetSize(900, 500)
	a.PumpOnce()
	if mw, _ := w.MinSize(); mw != 300 {
		t.Fatalf("after a resize the minimum is %v: what SetMinSize stated lasts now, see uitoolkit-gaps.md item 44", mw)
	}
	resize := uitoolkitFunc(t, "win32_windows.go", "winSurface", "Resize")
	sync := uitoolkitFunc(t, "x11_linux.go", "x11Surface", "syncLimits")
	if !strings.Contains(resize, "limitsFor(s.sizing, s.opts") || !strings.Contains(sync, "limitsFor(s.sizing, s.opts") {
		t.Fatal("the backends keep a stated minimum now: see uitoolkit-gaps.md item 44")
	}
}

// 45. A form row hidden (38) leaves its gap, and is hidden only at the
// next layout: FormRow.SetVisible repaints the form and does not lay it
// out again, so nothing moves until something else asks for a layout;
// and laid out again, the grid still counts the hidden row among its
// rows and puts a RowGap where it was. A form of eight rows showing three
// has five gaps too many between them, so the manager still asks for a
// keyslot's kind before the form for it.
func TestItem45AHiddenFormRowKeepsItsGap(t *testing.T) {
	a := headless(t, 1)
	form, mid, last := keyslotForm(true)
	window(t, a, 400, 200, widgets.NewColumn(form, widgets.NewLabel("under")))
	shown := widget.DeviceOrigin(last).Y
	mid.SetVisible(false)
	a.PumpOnce()
	if got := widget.DeviceOrigin(last).Y; got != shown {
		t.Fatalf("hiding a row lays the form out again now (the next row went from %v to %v): see uitoolkit-gaps.md item 45", shown, got)
	}
	form.RequestLayout()
	a.PumpOnce()
	never, _, lastOfNever := keyslotForm(false)
	window(t, a, 400, 200, widgets.NewColumn(never, widgets.NewLabel("under")))
	got, want := widget.DeviceOrigin(last).Y, widget.DeviceOrigin(lastOfNever).Y
	if got == want {
		t.Fatal("a hidden row leaves no gap now: see uitoolkit-gaps.md item 45, and the manager's two-step Add… for a keyslot")
	}
	if gap := got - want; gap != 6 {
		t.Fatalf("a hidden row leaves %v pixels, not its RowGap", gap)
	}
}
