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
	"slices"
	"sort"
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

// 7. A clipboard that can hold a secret (7020c65, 58140ea, e54cba4;
// 9e7e1c6): ClipboardSetSecret takes the bytes over, a paste in the
// program reads a copy of them, and Clear wipes them; since v0.23.2 the
// copy is zeroed before anything says it has gone, and OnCleared runs
// after the clipboard was told. (ClipboardClear, which a lock and the
// quit run, still calls back before it tells the clipboard.) Headless:
// what reaches the desktop's clipboards is 35, 41-43 and 47-49, and the
// gaps left there 56, 57 and 58.
func TestItem07ASecretOnTheClipboard(t *testing.T) {
	t.Cleanup(platform.ClipboardClear)
	data := []byte("hunter2-github")
	c := platform.ClipboardSetSecret(data, -1)
	got := platform.ClipboardGetSecret()
	if !platform.ClipboardHoldsSecret() || string(got) != "hunter2-github" || &got[0] == &data[0] {
		t.Fatal("a secret copied is not held, or a paste in the program does not read a copy of it")
	}
	uitoolkit.WipeBytes(got)
	zeroed, held := false, true
	c.OnCleared(func() { zeroed, held = allZero(data), platform.ClipboardHoldsSecret() })
	c.Clear()
	if !allZero(data) || platform.ClipboardHoldsSecret() || !c.Cleared() || !zeroed || held {
		t.Fatalf("cleared: wiped %v, held %v; when OnCleared ran, wiped %v and held %v: see uitoolkit-gaps.md item 7",
			allZero(data), platform.ClipboardHoldsSecret(), zeroed, held)
	}
	clr := uitoolkitFunc(t, "clipboard_secret.go", "SecretClip", "Clear")
	if i, j := strings.Index(clr, "c.wipe()"), strings.Index(clr, "clipboardNativeClear()"); i < 0 || j < i {
		t.Fatal("Clear tells the clipboard before it wipes the copy again: see uitoolkit-gaps.md item 7")
	}
	all := uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardClear")
	if i, j := strings.Index(all, "held.forget()"), strings.Index(all, "clipboardNativeClear()"); i < 0 || j < i {
		t.Fatal("ClipboardClear calls back after the clipboard is clear now: see uitoolkit-gaps.md item 7")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
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
// the first key where the backend can be asked, and says when it changes.
// Since v0.23.1 (285b6b7) a focus-in, which carries no modifiers on any
// backend, leaves the lock state alone: a window that comes back into
// focus with Caps Lock on still says so, and no watcher hears it go off.
// Since v0.23.3 (dbcb934) every backend can be asked: X11 and Windows as
// before, AppKit from NSEvent.modifierFlags, the keyboard's at any time,
// and Wayland from what the compositor's modifiers event left
// (uitkWlKeyMods keeps it, and the surface reads it under wlMu). Since
// v0.23.4 a Wayland window is told when the compositor says, and every
// window asks the keyboard again as it takes the focus (51).
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
	o.SetLockKeys(true, false)
	got = nil
	w.Inject(platform.Event{Kind: platform.EventFocusOut})
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if caps, _ := w.LockKeys(); !caps || len(got) != 0 {
		t.Fatalf("after a focus-in the window says Caps Lock %v, and OnLockKeys heard %v: a focus-in reads as the lock off again, see uitoolkit-gaps.md item 12", caps, got)
	}

	// Every backend's surface can be asked, and asks the keyboard (on
	// Wayland, what the compositor last said of it), not an event.
	for _, s := range []struct{ file, recv, asks string }{
		{"x11_locks_linux.go", "x11Surface", "ui_lock_state("},
		{"win32_locks_windows.go", "winSurface", "procGetKeyState"},
		{"appkit_locks_darwin.go", "akSurface", "uitk_ak_lock_state("},
		{"wayland_locks_linux.go", "wlSurface", "s.conn.mods"},
	} {
		if !strings.Contains(uitoolkitFunc(t, s.file, s.recv, "LockKeys"), s.asks) {
			t.Errorf("%s's %s.LockKeys no longer asks the keyboard: see uitoolkit-gaps.md item 12", s.file, s.recv)
		}
	}
	if !uitoolkitHas(t, "appkit_locks_darwin.go", "[NSEvent modifierFlags]") {
		t.Error("an AppKit surface no longer reads the keyboard's own flags: see uitoolkit-gaps.md item 12")
	}
	if mods := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlKeyMods"); !strings.Contains(mods, "c.mods = wlMods(c)") {
		t.Fatal("the Wayland backend no longer keeps what the compositor's modifiers event says: see uitoolkit-gaps.md items 12 and 51")
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
// alone (item 12). Since v0.23.4 the window asks the keyboard again at
// that focus-in, and a watcher that hears of it hears the lock on.
type lockWatcher struct {
	*widgets.Label
	heard int
	caps  bool // what it heard last
}

func (l *lockWatcher) LockKeysChanged(caps, _ bool) { l.heard, l.caps = l.heard+1, caps }

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
	if caps, _ := o.LockKeys(); !caps || !field.CapsLockOn() || (one.heard != heard && !one.caps) {
		t.Fatalf("the keyboard says Caps Lock %v, the field %v, a watcher heard %d changes more, the last %v: a focus-in turns the mark off again, see uitoolkit-gaps.md items 12 and 28",
			caps, field.CapsLockOn(), one.heard-heard, one.caps)
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
// decides it is there. It lasts since v0.23.2 (44). And since v0.23.2
// (99e0c22) a component that holds one thing, as a key handler does, is
// never narrower than what it holds, where it does not say so itself (the
// manager's own wrappers do, and answer exactly their child's floor).
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
	wrapped := &wrapper{}
	wrapped.Init(wrapped)
	inner := widgets.NewSplitter(widgets.SplitColumns, widgets.NewPad(0, widgets.NewSpacerSize(400, 10)), widgets.NewPad(0, widgets.NewSpacerSize(400, 10)))
	wrapped.Add(inner)
	window(t, a, 900, 200, wrapped)
	if got, need := widget.MinWidthOf(wrapped), widget.MinWidthOf(inner); got < need {
		t.Fatalf("a wrapper round a splitter says its floor is %v, the splitter's %v: see uitoolkit-gaps.md item 34", got, need)
	}
}

// wrapper holds one thing and passes everything through to it.
type wrapper struct{ widget.Base }

func (w *wrapper) Measure(c layout.Constraints) paintengine2d.Point {
	return w.Children()[0].Measure(c)
}

func (w *wrapper) Arrange(r paintengine2d.Rect) {
	w.SetBounds(r)
	w.Children()[0].Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
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

// uitoolkitCalls is what one function of the platform package calls, by
// name ("C.x" for C, the selector's name for a method or another
// package's function), for a pin that must notice any new step in it,
// whatever it is called.
func uitoolkitCalls(t *testing.T, file, recv, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, "package p\n"+uitoolkitFunc(t, file, recv, name), 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				seen[fn.Name] = true
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "C" {
					seen["C."+fn.Sel.Name] = true
				} else {
					seen[fn.Sel.Name] = true
				}
			}
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// uitoolkitHolders is every function of the platform package's secret
// clipboard that reads or changes which secret is held.
func uitoolkitHolders(t *testing.T) []string {
	t.Helper()
	src := uitoolkitSource(t, "clipboard_secret.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "clipboard_secret.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && strings.Contains(src[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset], "secretHeld") {
			out = append(out, fd.Name.Name)
		}
	}
	sort.Strings(out)
	return out
}

// callsOnly reports whether a function calls nothing but want.
func callsOnly(calls []string, want ...string) bool {
	sort.Strings(want)
	return strings.Join(calls, " ") == strings.Join(want, " ")
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
// accessibility tree too, and the rows under it move up; shown again, they
// go back. That they move at once, and as far as the row and its gap, is
// 45 (d9356f0).
func TestItem38AFormRowShownOrHidden(t *testing.T) {
	a := headless(t, 1)
	form, mid, last := keyslotForm(true)
	w := window(t, a, 400, 200, widgets.NewColumn(form, widgets.NewLabel("under")))
	shown := widget.DeviceOrigin(last).Y
	mid.SetVisible(false)
	a.PumpOnce()
	if mid.Visible() || mid.Label.Visible() || mid.Field.Visible() || strings.Contains(treeText(w), "Keyfile") {
		t.Fatal("a hidden form row, its caption or its field is still there, or still read aloud: see uitoolkit-gaps.md item 38")
	}
	if got := widget.DeviceOrigin(last).Y; got >= shown {
		t.Fatalf("with a row hidden the next stays at %v: see uitoolkit-gaps.md item 38", got)
	}
	mid.SetVisible(true)
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

// floorProbe is a probe that says how narrow it may be, as the manager's
// secret text does (widget.MinWidther).
type floorProbe struct{ probe }

func (p *floorProbe) MinWidth() float32 { return 40 }

// 39. A grid column that measures at its share (e011659): what is in a
// Share column is asked for its width only through widget.MinWidthOf, so
// a cell that says its floor (as the manager's secret text does) is never
// measured unbounded, only at the width the column is given; and the
// column asks the grid for its cells' floors alone. A Flex column is as
// it was, by design: measured unbounded first, and its heights at the
// column's real width. The manager's secret text wraps to the width it is
// offered, in a Share column where it is in a grid, and breaks a long key
// there rather than every 48 characters.
func TestItem39AShareColumnOffersItsWidth(t *testing.T) {
	a := headless(t, 1)
	shared := &floorProbe{}
	shared.Init(shared)
	flexed := newProbe()
	g := widgets.NewGrid()
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Share(1)}
	g.Place(widgets.NewLabel("Share 1"), 0, 0)
	g.Place(shared, 0, 1)
	f := widgets.NewGrid()
	f.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
	f.Place(widgets.NewLabel("Share 1"), 0, 0)
	f.Place(flexed, 0, 1)
	window(t, a, 300, 100, widgets.NewColumn(g, f))
	if shared.unbounded || shared.bounded == 0 || shared.bounded > 300 {
		t.Fatalf("a Share cell was measured unbounded %v, at %v at the narrowest: it is to be offered its column's width, see uitoolkit-gaps.md item 39",
			shared.unbounded, shared.bounded)
	}
	if g.Bounds().Dx() > 300 || shared.Bounds().Max.X > g.Bounds().Dx() || shared.Bounds().Dx() < shared.bounded-1 {
		t.Fatalf("a grid with a Share column is %v wide, its cell %v, in a window 300 wide; the cell was measured at %v", g.Bounds().Dx(), shared.Bounds(), shared.bounded)
	}
	if !flexed.unbounded || flexed.bounded == 0 || flexed.bounded > 300 {
		t.Fatalf("a Flex cell: measured unbounded %v, at %v at the narrowest; it was both, at the column's width", flexed.unbounded, flexed.bounded)
	}
}

// 40. A dialog taller than its window keeps its buttons in view
// (bba1c63, dbb2644): DialogCard's body scrolls and its action row stays
// at the foot, and widgets.DialogContent is that arrangement for a card
// an application builds, a QR code in it or not. The Overlay itself does
// nothing of the kind for any other card, and says so. That
// DialogContent's body takes the whole window, however little it holds,
// is 46; the manager builds the same arrangement with a body that does
// not, and its dialogs scroll.
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
	tall.height = 600 // as a QR code under a secret is: it does not shrink
	ok := widgets.NewButton("Done", nil)
	content := widgets.DialogContent(tall, widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept))
	card := widgets.NewPanel("Tall", content)
	card.Window = true
	o := widgets.NewOverlay(card)
	o.Modal = true
	widget.ShowOverlay(col, o)
	a.PumpOnce()
	scroll, _ := content.Children()[0].(*widgets.ScrollView)
	if b := widget.DeviceBounds(ok); b.Dy() <= 0 || b.Max.Y > 300 || scroll == nil || scroll.MaxOffset() <= 0 {
		t.Fatalf("a card built of DialogContent with a body 600 tall puts its button at %v in a window 300 tall, its body scrolling %v: see uitoolkit-gaps.md item 40",
			b, scroll != nil && scroll.MaxOffset() > 0)
	}
}

// Found in the audit of v0.23.1.

// 41. The Wayland owner serves a secret from its bytes (d9356f0): each
// paste another program asks for is written to the pipe from the cache's
// own slice, on CLIPBOARD and PRIMARY alike, with no string of it on the
// way. What the hint is answered with is 47.
func TestItem41WaylandServesASecretFromItsBytes(t *testing.T) {
	send := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataSend")
	prim := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlPrimSend")
	write := uitoolkitFunc(t, "wayland_linux.go", "", "wlSendSelection")
	for name, fn := range map[string]string{"uitkWlDataSend": send, "uitkWlPrimSend": prim} {
		if !strings.Contains(fn, ".getBytes()") || strings.Contains(fn, ".get()") || strings.Contains(fn, "string(") {
			t.Fatalf("the Wayland owner's %s serves a secret through a string again: see uitoolkit-gaps.md item 41", name)
		}
	}
	if !strings.Contains(write, "b []byte") || strings.Contains(write, "string") || strings.Contains(write, "[]byte(") {
		t.Fatal("wlSendSelection takes a string again, or copies what it writes: see uitoolkit-gaps.md item 41")
	}
}

// 42. A secret pasted from another program leaves no string, and the
// buffers it passes through are zeroed (d9356f0, 18a98d9): where the
// platform has a bytes path, a failed read is a failed read, with no
// second try through the string reader; the Wayland reader zeroes its
// 4 KiB staging buffer, and a partial read before dropping it; X11 zeroes
// the property before XFree; Windows decodes CF_UNICODETEXT into bytes and
// zeroes its UTF-16 copy and the runes; macOS copies the pasteboard's
// bytes out of a buffer it zeroes before freeing. With no display at all
// (headless, as here) the clipboard is this process's own buffer, read as
// it always was. A paste longer than one read leaves what it outgrew: 49.
func TestItem42APastedSecretLeavesNoString(t *testing.T) {
	get := uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardGetSecret")
	if i, j := strings.Index(get, "clipboardSecretBytesPath()"), strings.Index(get, "ClipboardGet()"); i < 0 || j < 0 || i > j {
		t.Fatal("a failed bytes read falls back to the string reader again: see uitoolkit-gaps.md item 42")
	}
	loop := uitoolkitFunc(t, "wayland_transfer_linux.go", "", "wlReadLoop")
	partial := uitoolkitFunc(t, "wayland_linux.go", "", "wlReadFDBytes")
	notify := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleSelNotify")
	win := uitoolkitFunc(t, "clipboard_secret_windows.go", "", "winSecretFromGlobal")
	mac := uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardNativeGetSecret")
	for what, held := range map[string]bool{
		"the Wayland staging buffer is zeroed": strings.Contains(loop, "defer func()") && strings.Contains(loop, "buf[i] = 0"),
		"a partial Wayland read is zeroed":     strings.Contains(partial, "out[i] = 0"),
		"the X11 property is zeroed":           strings.Index(notify, "C.ui_zero(") >= 0 && strings.Index(notify, "C.ui_zero(") < strings.LastIndex(notify, "C.ui_xfree("),
		"Windows reads bytes, and zeroes":      !strings.Contains(win, "string") && strings.Contains(win, "u[i] = 0") && strings.Contains(win, "runes[i] = 0"),
		"macOS reads bytes, and zeroes":        strings.Contains(mac, "C.uitk_pb_zfree(") && !strings.Contains(mac, "GoString"),
		"Windows has a bytes path":             strings.Contains(uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardSecretBytesPath"), "return true"),
		"macOS has a bytes path":               strings.Contains(uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardSecretBytesPath"), "return true"),
	} {
		if !held {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 42", what)
		}
	}
	if !uitoolkitHas(t, "clipboard_secret_darwin.go", "volatile unsigned char *q") || !uitoolkitHas(t, "x11_linux.go", "volatile unsigned char* q") {
		t.Error("a C buffer is cleared through a plain pointer again, which a compiler may drop before free: see uitoolkit-gaps.md item 42")
	}
}

// 43. On X11 a paste of what this program itself put on the clipboard
// reads what it serves again (99e0c22): readSelection answers an owned
// selection, CLIPBOARD or PRIMARY, by putting a copy of what it serves in
// pasteData, which both readers take, the secret one handing it over.
func TestItem43X11ReadsItsOwnCopy(t *testing.T) {
	read := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "readSelection")
	owned := strings.Index(read, "c.ownClip)")
	if owned < 0 || !strings.Contains(read[owned:], "c.pasteData = append([]byte(nil), c.clipData...)") ||
		!strings.Contains(read, "c.atomPrimary && c.ownPrim") {
		t.Fatal("X11 reads its own selection as the last paste from elsewhere again: see uitoolkit-gaps.md item 43")
	}
	take := uitoolkitFunc(t, "x11_linux.go", "", "x11ClipGetBytes")
	if !strings.Contains(take, "c.pasteData = nil") || strings.Contains(take, "string(") {
		t.Fatal("the X11 secret reader no longer hands over what it read: see uitoolkit-gaps.md items 35 and 43")
	}
}

// 44. A window's stated minimum lasts (99e0c22): SetMinSize writes the
// limits back into the options every backend recomputes them from, so a
// resize by the program and a change of resize policy keep it, on all
// five surfaces (headless here). The manager no longer states its floor
// again after a resize.
func TestItem44AStatedMinimumLasts(t *testing.T) {
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
	if mw, mh := w.MinSize(); mw != 600 || mh != 200 {
		t.Fatalf("after a resize the minimum is %v by %v: what SetMinSize stated does not last, see uitoolkit-gaps.md item 44", mw, mh)
	}
	platform.SetSurfaceSizing(w.Surface(), platform.SizingFixed)
	platform.SetSurfaceSizing(w.Surface(), platform.SizingResizable)
	if mw, _ := w.MinSize(); mw != 600 {
		t.Fatalf("after the resize policy changed and back the minimum is %v: see uitoolkit-gaps.md item 44", mw)
	}
	for file, recv := range map[string]string{
		"x11_linux.go": "x11Surface", "wayland_linux.go": "wlSurface", "win32_windows.go": "winSurface",
		"appkit_geometry_darwin.go": "akSurface", "offscreen.go": "Offscreen",
	} {
		if !strings.Contains(uitoolkitFunc(t, file, recv, "SetSizeLimits"), "stateLimits(") {
			t.Errorf("%s's %s.SetSizeLimits no longer keeps what it is told: see uitoolkit-gaps.md item 44", file, recv)
		}
	}
}

// 45. A form row hidden (38) is gone at once, gap and all (d9356f0):
// FormRow.SetVisible asks for a layout, and the grid leaves a row nothing
// visible is in out of its tracks, its gap too. The rows under it are
// where they are in a form that never had it, so the manager adds a
// keyslot in one step, the kind at the head of the form.
func TestItem45AHiddenFormRowLeavesNoGap(t *testing.T) {
	a := headless(t, 1)
	form, mid, last := keyslotForm(true)
	window(t, a, 400, 200, widgets.NewColumn(form, widgets.NewLabel("under")))
	shown := widget.DeviceOrigin(last).Y
	mid.SetVisible(false)
	a.PumpOnce()
	never, _, lastOfNever := keyslotForm(false)
	window(t, a, 400, 200, widgets.NewColumn(never, widgets.NewLabel("under")))
	got, want := widget.DeviceOrigin(last).Y, widget.DeviceOrigin(lastOfNever).Y
	if got == shown {
		t.Fatal("hiding a row lays the form out only at the next layout again: see uitoolkit-gaps.md item 45")
	}
	if got != want {
		t.Fatalf("with a row hidden the next is at %v, in a form that never had it at %v: see uitoolkit-gaps.md item 45, and the manager's Add… for a keyslot", got, want)
	}
}

// Found in the audit of v0.23.2.

// 46. DialogContent fits what it holds (244f2ac): its ScrollView shrinks
// to its content, so a one-line DialogCard is as tall as its text and its
// button, and scrolls only past what the window allows (40); and a
// ButtonBox handed to it alone is given the foot's whole width, so the
// platform's left-hand group (a destructive button, under Mac and GNOME
// looks, which the light look follows) stays apart. A foot that holds a
// ButtonBox beside something else is still squeezed: 54.
func TestItem46DialogContentFitsWhatItHolds(t *testing.T) {
	a := headless(t, 1)
	col := widgets.NewColumn()
	window(t, a, 600, 700, col)
	ok := widgets.NewButton("OK", nil)
	card := widgets.DialogCard("Short", "One line.", ok)
	o := widgets.NewOverlay(card)
	widget.ShowOverlay(col, o)
	a.PumpOnce()
	h := widget.DeviceBounds(card).Dy()
	widget.DismissOverlay(o)

	del, cancel := widgets.NewButton("Delete", nil), widgets.NewButton("Cancel", nil)
	box := widgets.NewButtonBox().AddButton(del, widgets.RoleDestructive).AddButton(cancel, widgets.RoleReject)
	content := widgets.DialogContent(widgets.NewLabel("Delete it?"), box)
	c2 := widgets.NewPanel("Delete?", content)
	c2.Window = true
	o2 := widgets.NewOverlay(c2)
	widget.ShowOverlay(col, o2)
	a.PumpOnce()
	foot, d, c := widget.DeviceBounds(box), widget.DeviceBounds(del), widget.DeviceBounds(cancel)
	if h > 0.3*700 || foot.Dx() < widget.DeviceBounds(content).Dx()-10 || d.Min.X > foot.Min.X+1 || c.Max.X < foot.Max.X-1 {
		t.Fatalf("a one-line DialogCard is %v tall in a window 700 tall; a ButtonBox in DialogContent is %v wide in %v, Delete at %v and Cancel at %v: see uitoolkit-gaps.md item 46",
			h, foot.Dx(), widget.DeviceBounds(content).Dx(), d, c)
	}
}

// 47. On Wayland the password-manager hint is answered "secret"
// (dbcb934): the data source's send handler passes the type asked for
// through, uitkWlDataSend answers the hint before it reads the selection,
// and only while what it offers is a secret (clipSecret, set by the copy
// and dropped when the source is cancelled); the text types still get the
// bytes. X11 answers the hint target with "secret", as it always did.
func TestItem47WaylandAnswersTheHintSecret(t *testing.T) {
	send := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataSend")
	hint := uitoolkitFunc(t, "wayland_linux.go", "", "wlHintAnswerFor")
	set := uitoolkitFunc(t, "wayland_linux.go", "", "wlClipSetSel")
	gone := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataCancelled")
	i, j := strings.Index(send, "wlHintAnswer(c, mime)"), strings.Index(send, ".getBytes()")
	for what, held := range map[string]bool{
		"the send handler passes the type through":          uitoolkitHas(t, "wayland_linux.go", "uitkWlDataSend((uintptr_t)data, (char *)mime, fd);"),
		"the hint is answered before the selection is read": i >= 0 && j > i,
		"the hint, and only it, is answered \"secret\", and only for a secret": strings.Contains(hint, `[]byte("secret"), true`) &&
			strings.Contains(hint, "!c.clipSecret") && strings.Contains(hint, "mime != wlPasswordHintMime"),
		"a secret copy says it is one, and offers the hint": strings.Contains(set, "c.clipSecret = secret") && strings.Contains(set, "C.CString(wlPasswordHintMime)"),
		"a cancelled source is a secret no more":            strings.Contains(gone, "c.clipSecret = false"),
		"the hint is KDE's":                                 uitoolkitHas(t, "wayland_linux.go", `wlPasswordHintMime = "x-kde-passwordManagerHint"`),
	} {
		if !held {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 47", what)
		}
	}
	x11 := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleSelReq")
	if !strings.Contains(x11, "case c.atomPwHint:") || !strings.Contains(x11, `[]byte("secret")`) {
		t.Fatal("X11 no longer answers the hint with \"secret\": see uitoolkit-gaps.md items 7 and 47")
	}
}

// 48. A copied secret ends when the clipboard moves on (c3ba669): the
// program's own ordinary copy ends it on every platform (ClipboardSet),
// and another program's does too, since v0.23.4 on all four (52). The
// held copy is wiped and its OnCleared runs, a secret paste reads what was
// copied since, ClipboardHoldsSecret says no, and the clear at its time
// leaves the clipboard alone. And every backend's clear checks the
// clipboard is still that copy: X11 that it owns the selection, Wayland
// that it has a source (55), Windows the clipboard's sequence number,
// macOS the pasteboard's changeCount, both kept atomically since v0.23.4.
func TestItem48ACopiedSecretEndsWithTheClipboard(t *testing.T) {
	t.Cleanup(platform.ClipboardClear)
	data := []byte("hunter2-github")
	c := platform.ClipboardSetSecret(data, -1)
	told := false
	c.OnCleared(func() { told = true })
	platform.ClipboardSet("an ordinary copy since")
	got := platform.ClipboardGetSecret()
	held := platform.ClipboardHoldsSecret()
	c.Clear()
	if string(got) != "an ordinary copy since" || held || !allZero(data) || !told || platform.ClipboardGet() != "an ordinary copy since" {
		t.Fatalf("after an ordinary copy a secret paste reads %q, a secret is held %v, the copy is wiped %v and said gone %v, and its clear left %q: see uitoolkit-gaps.md item 48",
			got, held, allZero(data), told, platform.ClipboardGet())
	}
	uitoolkit.WipeBytes(got)

	set := uitoolkitFunc(t, "clipboard.go", "", "ClipboardSet")
	cancelled := uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataCancelled")
	winSet := uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardNativeSetSecret")
	winClear := uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardNativeClear")
	macSet := uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardNativeSetSecret")
	macClear := uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardNativeClear")
	x11Clear := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "clearClipboard")
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	for what, ok := range map[string]bool{
		"an ordinary copy ends the held secret":           before(set, "forgetHeldSecret()", "clip = s"),
		"a Wayland source cancelled ends it":              strings.Contains(cancelled, "forgetHeldSecretIf(lost)") && strings.Contains(cancelled, "c.clip.invalidate()"),
		"Windows notes its copy and clears only that one": strings.Contains(winSet, "winClipSeq.Store(clipboardSeq())") && before(winClear, "clipboardStillHoldsOurSecret()", "procEmptyClipboard"),
		"macOS notes its copy and clears only that one":   strings.Contains(macSet, "akPbChange.Store(int64(C.uitk_pb_change_count()))") && before(macClear, "clipboardStillHoldsOurSecret()", "C.uitk_pb_clear()"),
		"X11 gives up only a selection it owns":           before(x11Clear, "if c.ownClip {", "c.atomClipboard"),
		"the noted numbers are kept atomically": uitoolkitHas(t, "clipboard_secret_windows.go", "var winClipSeq atomic.Uint32") &&
			uitoolkitHas(t, "clipboard_secret_darwin.go", "var akPbChange atomic.Int64"),
	} {
		if !ok {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 48", what)
		}
	}
}

// 49. A long pasted secret leaves nothing it outgrew
// (244f2ac): both readers grow by hand (appendWiping), zeroing the array
// they outgrow, the Wayland pipe's reader and X11's INCR assembly alike;
// the Wayland staging buffer and a partial read are zeroed as before
// (42); since v0.23.4 X11 zeroes each INCR piece Xlib read too (53).
func TestItem49ALongPasteLeavesNothingItOutgrew(t *testing.T) {
	var buf []byte
	var outgrown [][]byte
	for i := 0; i < 40; i++ {
		was := buf
		buf, _ = platform.AppendINCRPiece(buf, []byte(strings.Repeat("k", 1000)))
		if cap(was) > 0 && &was[:cap(was)][0] != &buf[:cap(buf)][0] {
			outgrown = append(outgrown, was[:cap(was)])
		}
	}
	if len(outgrown) == 0 || len(buf) != 40000 || strings.Trim(string(buf), "k") != "" {
		t.Fatalf("a transfer of 40 pieces grew %d times to %d bytes", len(outgrown), len(buf))
	}
	for i, old := range outgrown {
		if !allZero(old) {
			t.Fatalf("the %d. array a long paste outgrew still holds it: see uitoolkit-gaps.md item 49", i+1)
		}
	}
	loop := uitoolkitFunc(t, "wayland_transfer_linux.go", "", "wlReadLoop")
	if !strings.Contains(loop, "appendWiping(out, buf[:n])") || strings.Contains(loop, "append(out,") {
		t.Fatal("the Wayland reader grows a paste by append again: see uitoolkit-gaps.md item 49")
	}
	if !strings.Contains(uitoolkitFunc(t, "incr.go", "", "AppendINCRPiece"), "appendWiping(dst, piece)") {
		t.Fatal("X11's INCR assembly grows a paste by append again: see uitoolkit-gaps.md item 49")
	}
}

// Found in the plain-language pass over the dialogs.

// 50. A text view a few rows tall, in the default look (Plastik), keeps a
// scroll bar that says something (16aca25): a bar short of room gives up
// its step buttons rather than shrinking them (three, then one at each
// end, then none, as Qt's styles do), and a track too short for the look's
// smallest thumb shows none rather than one that cannot move; the lines
// wrap to the width the bar leaves; and a word longer than the line (a
// path) breaks after its last '/', '\', '-' or '.' (style.CanBreakAfter,
// shared with Font.Wrap). The manager's detailText stays: a plan's lines
// are as tall as they are in a dialog that scrolls as a whole, which is
// better there than a box to scroll inside.
func TestItem50AShortTextViewKeepsItsBar(t *testing.T) {
	pack, ok := style.LoadTheme("plastik")
	if !ok {
		t.Fatal("no Plastik in this uitoolkit: see uitoolkit-gaps.md item 50")
	}
	lk := pack.Look()
	a := uitoolkit.New(uitoolkit.Options{Headless: true, Look: lk, Scale: 1, DisableLookWatch: true})
	text := "firefox: write /home/ada/.mozilla/native-messaging-hosts/io.github.codemodify.secretvault.json " +
		"and so on, a plan of more lines than the view has rows, as the setup of the browsers was"
	view := widgets.NewMonoTextView(text, "")
	view.MinRows = 2
	window(t, a, 520, 200, widgets.NewColumn(view).WithPad(12))

	pad := lk.Metrics().FieldPad
	if pad <= 0 {
		pad = 8 // as TextArea takes it
	}
	b := view.Bounds()
	inner := paintengine2d.XYWH(0, pad, b.Dx(), b.Dy()-2*pad)
	lineH := lk.MonoFont().Height() + 2
	lines := view.Lines()
	content := float32(len(lines)) * lineH
	if content <= inner.Dy() {
		t.Fatalf("the text fits its %v rows: the pin needs more lines (%d)", view.MinRows, len(lines))
	}
	bar := style.ScrollBarStyleOf(lk)
	at := func(off float32) style.ScrollParts {
		return style.ScrollGeometry(lk, inner, true, content, inner.Dy(), off, false)
	}
	top, end := at(0), at(content-inner.Dy())
	squeezed := !top.Dec.Empty() && top.Dec.Dy() < bar.ArrowLen-0.5
	still := !top.Thumb.Empty() && top.Thumb == end.Thumb
	f := lk.MonoFont()
	room := b.Dx() - 2*pad - style.ScrollGutter(lk)
	runes := []rune(text)
	var under, midName []string
	for i, l := range lines {
		if f.Advance(l.Text) > room+0.5 {
			under = append(under, l.Text)
		}
		// A line that ends inside a word ends after a separator: every
		// long word here has one.
		if i < len(lines)-1 && l.End > 0 && l.End < len(runes) && runes[l.End-1] != ' ' && runes[l.End] != ' ' && !style.CanBreakAfter(runes[l.End-1]) {
			midName = append(midName, l.Text)
		}
	}
	if squeezed || still || len(under) > 0 || len(midName) > 0 {
		t.Fatalf("a two-row text view: its step buttons %v long for %v (squeezed %v), its thumb %v at the top and %v at the end (still %v), "+
			"lines under the bar %q, a name broken in its middle %q: see uitoolkit-gaps.md item 50", top.Dec.Dy(), bar.ArrowLen, squeezed, top.Thumb, end.Thumb, still, under, midName)
	}
	if top.Thumb.Empty() || top.Thumb == end.Thumb {
		t.Fatalf("a two-row text view's bar shows no position: its thumb %v at the top and %v at the end: see uitoolkit-gaps.md item 50", top.Thumb, end.Thumb)
	}
}

// Found in the audit of v0.23.3.

// 51. A window learns the lock keys it opened in (70f4d6e, e535eb1). On
// Wayland the compositor's modifiers, which follow wl_keyboard.enter and
// so come after the window's first layout, reach the window as
// EventLockKeys (uitkWlKeyMods pushes it to the surface that has the
// keyboard), and the window tells the field and every watcher. And every
// window asks its surface again as it takes the focus, so a lock changed
// in another program is said at once. (The commit says Wayland and AppKit
// are left out of that; they are not, since both surfaces are still
// LockKeysSurfaces, and their answers are the compositor's last word and
// the keyboard's own, so it does no harm.)
func TestItem51AWindowLearnsTheLocksItOpenedIn(t *testing.T) {
	a := headless(t, 1)
	field := widgets.NewSecretField("")
	watch := &lockWatcher{Label: widgets.NewLabel("w")}
	watch.Label.Init(watch)
	w := window(t, a, 300, 120, widgets.NewColumn(field, watch))
	o := w.Surface().(*platform.Offscreen)
	o.SetLockKeys(false, false)
	w.FocusOn(field)
	if field.CapsLockOn() {
		t.Fatal("a field marks Caps Lock with it off")
	}
	// The compositor's modifiers, right after enter.
	o.SetLockKeys(true, false)
	w.Inject(platform.Event{Kind: platform.EventLockKeys, Mods: platform.ModCapsLock})
	a.PumpOnce()
	if !field.CapsLockOn() || watch.heard == 0 || !watch.caps {
		t.Fatalf("the window system said Caps Lock is on: the field marks it %v, a watcher heard %d changes, the last %v: see uitoolkit-gaps.md item 51",
			field.CapsLockOn(), watch.heard, watch.caps)
	}
	// Turned off in another program, then the focus back.
	w.Inject(platform.Event{Kind: platform.EventFocusOut})
	o.SetLockKeys(false, false)
	w.Inject(platform.Event{Kind: platform.EventFocusIn})
	a.PumpOnce()
	if field.CapsLockOn() || watch.caps {
		t.Fatal("a window that comes back into focus after Caps Lock went off elsewhere still says it is on: see uitoolkit-gaps.md item 51")
	}
	mods := strings.Join(strings.Fields(uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlKeyMods")), " ")
	if !strings.Contains(mods, "c.mods = wlMods(c)") || !strings.Contains(mods, "wlSurfBy(C.uintptr_t(c.keySurf))") ||
		!strings.Contains(mods, "push(Event{Kind: EventLockKeys, Mods: c.mods})") {
		t.Fatal("the Wayland backend no longer tells the window what the compositor's modifiers say: see uitoolkit-gaps.md items 12 and 51")
	}
	for file, recv := range map[string]string{"wayland_locks_linux.go": "wlSurface", "appkit_locks_darwin.go": "akSurface"} {
		uitoolkitFunc(t, file, recv, "LockKeys") // still a LockKeysSurface, so asked at a focus-in too
	}
}

// 52. Another program's copy ends a held secret on every backend
// (4a6691c). X11 is told: a SelectionClear of the CLIPBOARD a secret was
// on ends the held copy (endLostSecret), unless the Wayland selection is
// still serving it (55). Windows and macOS are not told, so they are
// asked: a secret paste and ClipboardHoldsSecret first read the
// clipboard's sequence number or the pasteboard's changeCount back
// (clipboardStillHoldsOurSecret), and where it moved on the held copy is
// wiped, said gone and not served. Linux answers that from what it was
// told, so it is always yes there, and so is the in-process buffer.
// Read rather than run: "another program" is nothing a headless test has.
func TestItem52AnotherCopyEndsAHeldSecret(t *testing.T) {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	clr := norm(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleSelClear"))
	end := norm(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "endLostSecret"))
	still := norm(uitoolkitFunc(t, "clipboard_secret.go", "", "heldSecretIfStillOnTheClipboard"))
	get := uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardGetSecret")
	winStill := norm(uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardStillHoldsOurSecret"))
	macStill := norm(uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardStillHoldsOurSecret"))
	for what, held := range map[string]bool{
		"X11's SelectionClear of the secret's CLIPBOARD ends the held copy": before(clr, "lostSecret = c.clipSecret", "c.wipeClipLocked()") &&
			before(clr, "c.wipeClipLocked()", "c.endLostSecret()"),
		"unless Wayland still serves it": before(end, "wlStillServesTheSecret()", "forgetHeldSecretIf(lost)"),
		"a secret paste asks first":      before(get, "heldSecretIfStillOnTheClipboard()", "copy(out, held.data)"),
		"so does ClipboardHoldsSecret": callsOnly(uitoolkitCalls(t, "clipboard_secret.go", "", "ClipboardHoldsSecret"),
			"Cleared", "heldSecretIfStillOnTheClipboard"),
		"a copy no longer on the clipboard ends": strings.Contains(still, "clipboardStillHoldsOurSecret()") && strings.Contains(still, "forgetHeldSecretIf(held)"),
		"Windows asks the sequence number":       strings.Contains(winStill, "clipboardSeq()") && strings.Contains(winStill, "seq == was"),
		"macOS asks the changeCount":             strings.Contains(macStill, "C.uitk_pb_change_count()") && strings.Contains(macStill, "== was"),
		"Linux and the in-process buffer answer from what they were told": strings.Contains(uitoolkitFunc(t, "clipboard_secret_linux.go", "", "clipboardStillHoldsOurSecret"), "return true") &&
			strings.Contains(uitoolkitFunc(t, "clipboard_secret_stub.go", "", "clipboardStillHoldsOurSecret"), "return true"),
	} {
		if !held {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 52", what)
		}
	}
}

// 53. X11's INCR transfer leaves no pieces (6e161a6, 16aca25): each piece
// Xlib read is zeroed (ui_zero, through the volatile helper) before XFree,
// and the Go copy after it is appended; the transfer's buffer is zeroed
// wherever it is dropped (dropINCRLocked), at the start of every paste and
// when it completes; and a transfer that completes after its paste stopped
// waiting is dropped rather than left in pasteData. What a paste that gave
// up waiting kept until the next one (56), v0.23.5 drops.
func TestItem53X11INCRLeavesNoPieces(t *testing.T) {
	prop := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "handleProperty")
	incr, end := strings.Index(prop, "c.incrRecv.active"), strings.Index(prop, "state != propertyDelete")
	if incr < 0 || end < incr {
		t.Fatal("what this pin reads of X11's INCR transfer has moved: see uitoolkit-gaps.md item 53")
	}
	branch := prop[incr:end]
	zero, free := strings.Index(branch, "C.ui_zero(unsafe.Pointer(data), C.size_t(n))"), strings.Index(branch, "C.ui_xfree(unsafe.Pointer(data))")
	if i := strings.Index(branch, "C.GoBytes("); i < 0 || zero < i || free < zero || strings.Count(branch, "C.ui_xfree(") != 1 ||
		!strings.Contains(branch, "piece[i] = 0") || !strings.Contains(branch, "c.finishINCRLocked()") {
		t.Fatal("an INCR piece Xlib read is freed unzeroed again: see uitoolkit-gaps.md item 53")
	}
	finish := strings.Join(strings.Fields(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "finishINCRLocked")), " ")
	if !strings.Contains(finish, "if c.pasteWaiting { c.pasteData = append([]byte(nil), c.incrRecv.buf...)") || !strings.HasSuffix(finish, "c.dropINCRLocked() }") {
		t.Fatal("a completed INCR transfer is kept for nobody, or its buffer is not let go: see uitoolkit-gaps.md item 53")
	}
	if !strings.Contains(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "dropINCRLocked"), "c.incrRecv.buf[i] = 0") {
		t.Fatal("a dropped INCR transfer is no longer zeroed: see uitoolkit-gaps.md item 53")
	}
	read := uitoolkitFunc(t, "x11_linux.go", "x11Conn", "readSelection")
	if i, j := strings.Index(read, "c.dropINCRLocked()"), strings.Index(read, "C.ui_convert("); i < 0 || j < i || strings.Contains(read, "c.incrRecv = incrRecvState{}") {
		t.Fatal("a paste starts over what an earlier transfer left without zeroing it: see uitoolkit-gaps.md item 53")
	}
}

// 54. A dialog's foot keeps its room (70f4d6e, 16aca25). DialogContent
// gives a ButtonBox the foot's width wherever it is among the actions,
// with whatever else there is to its left; and DialogContentFoot takes a
// foot the application lays out itself, at the dialog's whole width. The
// manager's showDialog is DialogContentFoot now, its foot a row of "Caps
// Lock is on" and a flexed ButtonBox where a secret is asked for.
func TestItem54ADialogsFootKeepsItsRoom(t *testing.T) {
	a := headless(t, 1)
	col := widgets.NewColumn()
	window(t, a, 600, 700, col)
	show := func(content widget.Component) {
		card := widgets.NewPanel("Import", content)
		card.Window = true
		o := widgets.NewOverlay(card)
		widget.ShowOverlay(col, o)
		a.PumpOnce()
		t.Cleanup(func() { widget.DismissOverlay(o) })
	}
	buttons := func() (*widgets.ButtonBox, *widgets.Button, *widgets.Button) {
		back, cancel := widgets.NewButton("Back", nil), widgets.NewButton("Cancel", nil)
		return widgets.NewButtonBox().AddButton(back, widgets.RoleHelp).AddButton(cancel, widgets.RoleReject), back, cancel
	}
	// apart reports whether Back is at the box's left and Cancel at its
	// right, the box reaching the content's right edge.
	apart := func(box *widgets.ButtonBox, back, cancel *widgets.Button, content widget.Component) bool {
		bb, bk, cn, ct := widget.DeviceBounds(box), widget.DeviceBounds(back), widget.DeviceBounds(cancel), widget.DeviceBounds(content)
		return bk.Min.X <= bb.Min.X+1 && cn.Max.X >= bb.Max.X-1 && bb.Max.X >= ct.Max.X-10 && cn.Min.X-bk.Max.X > 40
	}

	box, back, cancel := buttons()
	foot := widgets.NewRow(widgets.NewLabel("Caps Lock is on"), box).WithGap(16).WithAlign(layout.AlignCenter)
	foot.AddFlex(box, 1)
	content := widgets.DialogContentFoot(widgets.NewLabel("Import"), foot)
	show(content)
	if got, room := widget.DeviceBounds(foot).Dx(), widget.DeviceBounds(content).Dx(); got < room-10 || !apart(box, back, cancel, content) {
		t.Fatalf("a foot of a label and a ButtonBox is %v wide in DialogContentFoot's %v, Back at %v and Cancel at %v: see uitoolkit-gaps.md item 54",
			got, room, widget.DeviceBounds(back), widget.DeviceBounds(cancel))
	}

	box, back, cancel = buttons()
	content = widgets.DialogContent(widgets.NewLabel("Import"), widgets.NewLabel("Caps Lock is on"), box)
	show(content)
	if !apart(box, back, cancel, content) {
		t.Fatalf("a ButtonBox beside a label in DialogContent is squeezed: Back at %v and Cancel at %v in %v: see uitoolkit-gaps.md item 54",
			widget.DeviceBounds(back), widget.DeviceBounds(cancel), widget.DeviceBounds(content))
	}
}

// 55. The Wayland end of a secret copy (6e161a6, 16aca25). The clear gives
// up the selections this process owns (wlClipClear: destroys its source,
// and only then unsets the selection) rather than copying nothing onto
// them, so it no longer takes the primary selection from whoever has it.
// A cancel ends the copy that was held when it came, not whatever is held
// when its goroutine runs, and not while the X11 owner still serves a
// secret, which with XWayland beside the compositor it does: the copy took
// both clipboards, and a compositor bridging X11 to Wayland cancels the
// Wayland source at once. X11's SelectionClear makes the mirror check
// (52). What was left, the copy named when its loss is handled (57) and
// the primary selection unset whoever held it (58), v0.23.5 closed.
func TestItem55TheWaylandEndOfASecretCopy(t *testing.T) {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	clear := uitoolkitFunc(t, "clipboard_secret_linux.go", "", "clipboardNativeClear")
	wl := norm(uitoolkitFunc(t, "wayland_linux.go", "", "wlClipClear"))
	gone := norm(uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataCancelled"))
	x11 := norm(uitoolkitFunc(t, "clipboard_secret_x11check_linux.go", "", "x11StillServesTheSecret"))
	wls := norm(uitoolkitFunc(t, "clipboard_secret_x11check_linux.go", "", "wlStillServesTheSecret"))
	forget := norm(uitoolkitFunc(t, "clipboard_secret.go", "", "forgetHeldSecretIf"))
	for what, held := range map[string]bool{
		"the clear gives the selections up": strings.Contains(clear, "wlClipClear()") && !strings.Contains(clear, "wlClipSet("),
		"only a source of its own":          before(wl, "if c.dataSrc != nil {", "C.ui_wl_set_selection(c.dataDev, nil,") && before(wl, "if c.primSrc != nil {", "C.ui_wl_prim_set(c.primDev, nil,"),
		"and wipes its copy":                strings.Contains(wl, "c.clip.invalidate()"),
		"a cancel names the copy it ended":  before(gone, "lost := heldSecret()", "go func()") && strings.Contains(gone, "forgetHeldSecretIf(lost)") && !strings.Contains(gone, "forgetHeldSecret()"),
		"and leaves it while X11 serves it": before(gone, "if x11StillServesTheSecret() { return }", "forgetHeldSecretIf(lost)") && strings.Contains(x11, "c.ownClip && c.clipSecret"),
		"X11's loss makes the mirror check": strings.Contains(wls, "wlc.dataSrc != nil && wlc.clipSecret"),
		"only the named copy ends":          strings.Contains(forget, "c != nil && held != c"),
	} {
		if !held {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 55", what)
		}
	}
}

// Found in the audit of v0.23.4.

// 56. An X11 paste that gave up waiting keeps nothing that arrives after
// it (716d552). handleSelNotify takes a reply only while a paste is
// waiting, and only for the selection it asked about (pasteAskedFor reads
// pasteWant); any other is read, zeroed before XFree and dropped
// (discardSelNotify), an INCR one becoming a transfer that reads its
// pieces into nothing. A paste stops waiting as it gives up
// (endPasteWaitLocked), and a transfer still running then has what it
// read zeroed and the rest read into nothing (discardINCRLocked). A
// drop's transfer zeroes what was there before it takes the state over,
// and closing the connection wipes both.
func TestItem56ALatePasteIsDropped(t *testing.T) {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	between := func(fn, a, b string) string {
		i := strings.Index(fn, a)
		if i < 0 {
			return ""
		}
		j := strings.Index(fn[i:], b)
		if j < 0 {
			return ""
		}
		return fn[i : i+j+len(b)]
	}
	x11 := func(name string) string { return norm(uitoolkitFunc(t, "x11_linux.go", "x11Conn", name)) }
	notify, read, discard := x11("handleSelNotify"), x11("readSelection"), x11("discardSelNotify")
	late := between(x11("handleProperty"), "if c.incrRecv.discard {", "AppendINCRPiece(")
	drop := norm(uitoolkitFunc(t, "x11_dnd_linux.go", "x11Conn", "xdndSelNotify"))
	closing := x11("closeLocked")
	for what, held := range map[string]bool{
		"a reply is taken only while a paste waits for it": before(notify, "if !c.pasteWaiting || !c.pasteAskedFor(xe) { c.discardSelNotify(xe, prop) return }", "c.pasteData = C.GoBytes(") &&
			before(notify, "c.discardSelNotify(xe, prop)", "c.incrRecv = incrRecvState{active: true"),
		"and for the selection it asked about": strings.Contains(x11("pasteAskedFor"), "if C.ui_sn_selection(xe) != c.pasteWant { return false }") &&
			strings.Contains(read, "c.pasteWant = sel"),
		"any other is zeroed and dropped": before(discard, "C.ui_zero(unsafe.Pointer(data)", "C.ui_xfree(unsafe.Pointer(data))") &&
			!strings.Contains(discard, "pasteData") && strings.Contains(discard, "prop: prop, discard: true}"),
		"a paste stops waiting as it gives up": !strings.Contains(read, "pasteWaiting = false") &&
			strings.Contains(x11("endPasteWaitLocked"), "c.pasteWaiting = false c.pasteWant = 0"),
		"a transfer it gave up on is zeroed": before(read, "ok := c.pasteDone c.endPasteWaitLocked() if !ok && c.incrRecv.active {", "c.discardINCRLocked() } x11Mu.Unlock() return ok, ok") &&
			before(x11("discardINCRLocked"), "c.incrRecv.buf[i] = 0", "c.incrRecv.discard = true"),
		"and the rest of it read into nothing": strings.Contains(late, "piece[i] = 0") && strings.Contains(late, "return } var done bool"),
		"a drop's transfer zeroes what was there": strings.Contains(drop, "c.dropINCRLocked() c.incrRecv = incrRecvState{active: true, win: win, prop: prop}") &&
			!uitoolkitHas(t, "x11_dnd_linux.go", "c.incrRecv = incrRecvState{}"),
		"closing the connection wipes both": before(closing, "c.wipePasteLocked()", "C.XCloseDisplay(") && before(closing, "c.dropINCRLocked()", "C.XCloseDisplay("),
	} {
		if !held {
			t.Errorf("no longer so, %s: see uitoolkit-gaps.md item 56", what)
		}
	}
}

// 57. A loss still on its way finds no copy to end (34a8a36).
// ClipboardSetSecret lets the copy it replaces go before it puts the new
// one on the clipboard, and makes the new one the held copy only once the
// platform has taken it (a refused one never, 60). So a SelectionClear
// for the old copy, which X11's own round trip inside the new copy
// dispatches, finds nothing held, and endLostSecret ends nothing.
func TestItem57ACopyIsHeldOnlyOnceItIsOnTheClipboard(t *testing.T) {
	set := strings.Join(strings.Fields(uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardSetSecret")), " ")
	prev, none := strings.Index(set, "prev := secretHeld"), strings.Index(set, "secretHeld = nil")
	native, held := strings.Index(set, "SetSecret(data)"), strings.Index(set, "secretHeld = c")
	if prev < 0 || none < prev || native < none || held < native || strings.Count(set, "secretHeld = c") != 1 {
		t.Fatal("a secret copy is held before it is on the clipboard again: see uitoolkit-gaps.md item 57")
	}
	lost := strings.Join(strings.Fields(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "endLostSecret")), " ")
	if !strings.Contains(lost, "lost := heldSecret() if lost == nil { return }") {
		t.Fatal("X11's SelectionClear ends a copy it did not name again: see uitoolkit-gaps.md item 57")
	}
}

// 58. A Wayland secret copy leaves another program's primary selection
// alone (88f39fa). wlClipSetSel unsets the primary selection only where
// the source on it is this program's own (c.primSrc), as wlClipClear does
// (55), and drops its cache of it either way. X11 gives PRIMARY up only
// when it owns it, as before.
func TestItem58AWaylandSecretCopyLeavesThePrimarySelectionAlone(t *testing.T) {
	set := strings.Join(strings.Fields(uitoolkitFunc(t, "wayland_linux.go", "", "wlClipSetSel")), " ")
	i := strings.LastIndex(set, "if secret {")
	j := strings.Index(set, "} else if c.primMan != nil && c.primDev != nil {")
	if i < 0 || j < i {
		t.Fatal("what this pin reads of the Wayland copy has moved: see uitoolkit-gaps.md item 58")
	}
	if secret := set[i:j]; strings.Count(secret, "C.ui_wl_prim_set(") != 1 || !strings.Contains(secret, "c.prim.invalidate()") ||
		!strings.Contains(secret, "if c.primSrc != nil { C.ui_wl_prim_source_destroy(c.primSrc) c.primSrc = nil "+
			"if c.primMan != nil && c.primDev != nil { C.ui_wl_prim_set(c.primDev, nil, C.uint32_t(c.serial)) } }") {
		t.Fatal("a Wayland secret copy unsets a primary selection that is not its own again: see uitoolkit-gaps.md item 58")
	}
	x11 := strings.Join(strings.Fields(uitoolkitFunc(t, "x11_linux.go", "x11Conn", "setClipboardSelBytes")), " ")
	if !strings.Contains(x11, "if c.ownPrim { C.ui_set_owner(c.dpy, 0, c.atomPrimary, t)") {
		t.Fatal("an X11 secret copy no longer gives PRIMARY up only when it owns it: see uitoolkit-gaps.md items 7 and 58")
	}
}

// 59. A secret's clear runs on the loop (f1cd408). Its timer hands the
// clear to onLoop, which posts it to the UI goroutine through the poster
// app.Run lends the platform for as long as it runs, and runs it where it
// fired only where no loop runs; one posted as the loop ends is done by
// the quit's ClipboardClearSecret. So the clear no longer meets the
// Wayland callbacks the loop dispatches; the clipboard service, which
// dispatches them where there is no window, is stopped by wlRetain before
// the clear goes on, as before.
func TestItem59ASecretsClearRunsOnTheLoop(t *testing.T) {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	set := norm(uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardSetSecret"))
	if !strings.Contains(set, "time.AfterFunc(clearAfter, func() { onLoop(c.Clear) })") || strings.Contains(set, "time.AfterFunc(clearAfter, c.Clear)") {
		t.Fatal("a secret's timeout clears on its timer's goroutine again: see uitoolkit-gaps.md item 59")
	}
	if !before(norm(uitoolkitFunc(t, "looppost.go", "", "onLoop")), "post := loopPost", "if post == nil { fn() return } post(fn)") ||
		!strings.Contains(uitoolkitFunc(t, "looppost.go", "", "SetLoopPoster"), "loopPost = fn") {
		t.Fatal("onLoop no longer posts to the loop where one runs: see uitoolkit-gaps.md item 59")
	}
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "app.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	run := string(src)
	if i := strings.Index(run, "func (a *Application) Run() error {"); i >= 0 {
		run = run[i:]
		if j := strings.Index(run, "\n}\n"); j >= 0 {
			run = run[:j]
		}
	}
	if run = norm(run); !before(run, "a.looping = true", "platform.SetLoopPoster(a.Post)") ||
		!before(run, "platform.SetLoopPoster(a.Post)", "platform.SetLoopPoster(nil)") ||
		!before(run, "platform.SetLoopPoster(nil)", "for !a.quit.Load() {") || !before(run, "for !a.quit.Load() {", "platform.ClipboardClearSecret()") {
		t.Fatal("app.Run no longer lends its loop to the secret clipboard while it runs: see uitoolkit-gaps.md item 59")
	}
	if !before(norm(uitoolkitFunc(t, "wayland_linux.go", "", "wlRetain")), "done := c.svcDone", "<-done") ||
		!before(norm(uitoolkitFunc(t, "wayland_linux.go", "", "wlClipClear")), "c, err := wlRetain()", "wlMu.Lock()") {
		t.Fatal("a Wayland clear no longer stops the clipboard service before it goes on: see uitoolkit-gaps.md item 59")
	}
}

// 60. A secret copy the platform refuses is not taken for one that was
// made (d635a4b). clipboardNativeSetSecret says whether the copy was
// made, on every backend, and ClipboardSetSecret hands a refused one back
// already cleared: wiped, never held, no timer, its OnCleared called at
// once. Windows notes the sequence number only when the copy was made,
// and zeroes a block SetClipboardData refused before it frees it
// (winGlobalWipeFree); macOS notes changeCount only when the string went
// on the pasteboard.
func TestItem60ARefusedCopyIsNotTakenForOne(t *testing.T) {
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	before := func(fn, a, b string) bool {
		i, j := strings.Index(fn, a), strings.Index(fn, b)
		return i >= 0 && j > i
	}
	set := norm(uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardSetSecret"))
	refusedAt := strings.Index(set, "if !nativeSetSecret(data) {")
	refusedEnd := refusedAt + strings.Index(set[max(refusedAt, 0):], "return c }")
	if !uitoolkitHas(t, "clipboard_secret.go", "var nativeSetSecret = clipboardNativeSetSecret") || refusedAt < 0 || refusedEnd < refusedAt ||
		!strings.Contains(set[refusedAt:refusedEnd], "c.forget()") ||
		!before(set, "return c }", "secretHeld = c") || !before(set, "return c }", "time.AfterFunc(") {
		t.Fatal("a refused secret copy is held, or timed, again: see uitoolkit-gaps.md item 60")
	}
	win := norm(uitoolkitFunc(t, "clipboard_secret_windows.go", "", "clipboardNativeSetSecret"))
	if !strings.HasPrefix(win, "func clipboardNativeSetSecret(b []byte) bool {") || strings.Count(win, "winClipSeq.Store(") != 1 ||
		!strings.Contains(win, "ok := withClipboard(") || !strings.HasSuffix(win, "if ok { winClipSeq.Store(clipboardSeq()) } return ok }") {
		t.Fatal("a Windows secret copy notes the sequence number whether or not it was made again: see uitoolkit-gaps.md item 60")
	}
	refused := win[max(strings.Index(win, "procSetClipboardData.Call(cfUnicodeText, h); r == 0 {"), 0):]
	refused = refused[:max(strings.Index(refused, "return false"), 0)]
	if !strings.Contains(refused, "winGlobalWipeFree(h, len(raw))") || strings.Contains(refused, "procGlobalFree.Call(h)") ||
		!before(norm(uitoolkitFunc(t, "clipboard_secret_windows.go", "", "winGlobalWipeFree")), "blk[i] = 0", "procGlobalFree.Call(h)") {
		t.Fatal("a block SetClipboardData refused is freed unzeroed again: see uitoolkit-gaps.md item 60")
	}
	mac := norm(uitoolkitFunc(t, "clipboard_secret_darwin.go", "", "clipboardNativeSetSecret"))
	if strings.Contains(mac, "defer") || !strings.HasSuffix(mac, "if ok { akPbChange.Store(int64(C.uitk_pb_change_count())) } return ok }") ||
		!uitoolkitHas(t, "clipboard_secret_darwin.go", "return ok ? 1 : 0;") {
		t.Fatal("a macOS secret copy notes changeCount whether or not the string went on the pasteboard again: see uitoolkit-gaps.md item 60")
	}
}

// A TreeView picks one node: it has Selected and nothing that holds
// several. The manager's items are a ListView now, which picks several
// (gui/svmanager/content.go); the tree's gap stays pinned.
func TestItem61ATreePicksOneNode(t *testing.T) {
	tv := reflect.TypeOf(widgets.TreeView{})
	for i := range tv.NumField() {
		f := tv.Field(i)
		if f.IsExported() && (strings.Contains(f.Name, "Selection") || f.Name == "SelectedNodes" || f.Name == "MultiSelect" ||
			f.Name == "OnSelectionChange") {
			t.Fatalf("TreeView has %s now: it picks several nodes, see uitoolkit-gaps.md item 61", f.Name)
		}
	}
	if _, ok := reflect.TypeOf(&widgets.TreeView{}).MethodByName("SelectedNodes"); ok {
		t.Fatal("TreeView has SelectedNodes now: see uitoolkit-gaps.md item 61")
	}
}

// keyLog is a box that notes the keys it is offered and takes none; it
// lays its children out one under the other.
type keyLog struct {
	widget.Base
	got []platform.Key
}

func newKeyLog(focusable bool, children ...widget.Component) *keyLog {
	k := &keyLog{}
	k.Init(k)
	k.SetWantsFocus(focusable)
	for _, c := range children {
		k.Add(c)
	}
	return k
}

func (k *keyLog) KeyPress(e widget.KeyEvent) bool { k.got = append(k.got, e.Key); return false }

func (k *keyLog) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(200, 30*float32(max(1, len(k.Children())))))
}

func (k *keyLog) Arrange(r paintengine2d.Rect) {
	k.SetBounds(r)
	for i, c := range k.Children() {
		c.Arrange(paintengine2d.XYWH(0, 30*float32(i), r.Dx(), 30))
	}
}

// 62. A key in a popup reaches what has the keyboard in it first, then the
// popup (6f6fc45); Tab goes round the popup's widgets. The manager's
// drop-downs take Escape alone (dropPanel.KeyPress,
// gui/svmanager/titlebar.go), and the rest reach the list in them.
func TestItem62AKeyInAPopupReachesWhatHasTheKeyboard(t *testing.T) {
	a := headless(t, 1)
	anchor := newKeyLog(true)
	root := newKeyLog(false, anchor)
	win := window(t, a, 400, 300, root)
	first, second := newKeyLog(true), newKeyLog(true)
	pop := newKeyLog(false, first, second)
	pop.Arrange(paintengine2d.XYWH(10, 40, 200, 60))
	if !widget.ShowPopup(anchor, pop) {
		t.Fatal("the popup did not show")
	}
	t.Cleanup(func() { widget.DismissPopup(pop) })
	win.FocusOn(first)
	a.PumpOnce()
	win.Press(platform.KeyDown)
	a.PumpOnce()
	if len(first.got) == 0 || len(pop.got) == 0 {
		t.Fatalf("in a popup, what has the keyboard heard %v, and the popup %v: see uitoolkit-gaps.md item 62", first.got, pop.got)
	}
	win.Press(platform.KeyTab)
	a.PumpOnce()
	if win.Focus() != widget.Component(second) {
		t.Fatalf("Tab in a popup moved the keyboard to %T, not to the popup's next widget: see uitoolkit-gaps.md item 62", win.Focus())
	}
}

// 63. A key with the keyboard on nothing, or on what left the window,
// reaches the content root (6f6fc45), where the window's own keys are
// (the manager's Ctrl+Page Up and Down, Escape clearing the filter).
func TestItem63AKeyWithTheKeyboardOnNothingReachesTheRoot(t *testing.T) {
	a := headless(t, 1)
	page := newKeyLog(true)
	holder := newKeyLog(false, page)
	root := newKeyLog(false, holder)
	win := window(t, a, 400, 300, root)
	win.FocusOn(page)
	a.PumpOnce()
	holder.ClearChildren() // the page is swapped out, the keyboard on it
	a.PumpOnce()
	win.Press(platform.KeyPageDown, platform.ModCtrl)
	a.PumpOnce()
	if len(root.got) == 0 {
		t.Fatal("a key with the keyboard on what left the window reached nothing: see uitoolkit-gaps.md item 63")
	}
}

// 64. A scroll view leaves Ctrl+Page Up and Down (125681b), so in a page
// that scrolls they still go to the next and the previous part. The
// manager's pages are plain scroll views.
func TestItem64AScrollViewLeavesCtrlPageUpAndDown(t *testing.T) {
	a := headless(t, 1)
	tall := newProbe()
	tall.height = 2000
	sv := widgets.NewScrollView(tall)
	window(t, a, 300, 200, sv)
	for _, k := range []platform.Key{platform.KeyPageDown, platform.KeyPageUp} {
		if sv.KeyPress(widget.KeyEvent{Key: k, Mods: platform.ModCtrl}) {
			t.Fatalf("a scroll view takes Ctrl+%v: see uitoolkit-gaps.md item 64", k)
		}
	}
}

// 65. ShowPopup shows a popup at its size in the look it is drawn in
// (4d237e5), whatever it was measured at before. The manager places its
// drop-downs with PlacePopupForAnchor all the same, which measures in that
// look to begin with (openDrop, gui/svmanager/titlebar.go).
func TestItem65ShowPopupShowsAPopupAtItsSizeInTheWindowsLook(t *testing.T) {
	a := headless(t, 2)
	anchor := newKeyLog(true)
	window(t, a, 400, 300, newKeyLog(false, anchor))
	pop := widgets.NewPad(6, widgets.NewLabel("comms-mail-personal"))
	before := pop.Measure(layout.Unbounded())
	pop.Arrange(paintengine2d.XYWH(0, 40, before.X, before.Y))
	if !widget.ShowPopup(anchor, pop) {
		t.Fatal("the popup did not show")
	}
	t.Cleanup(func() { widget.DismissPopup(pop) })
	a.PumpOnce()
	after := pop.Measure(layout.Unbounded())
	if got := pop.Bounds(); got.Dy() < after.Y-0.5 || got.Dx() < after.X-0.5 {
		t.Fatalf("measured before it was shown the popup was %v, in the window's look %v, and shown %v: see uitoolkit-gaps.md item 65",
			before, after, got)
	}
}

// 66. Breadcrumbs (c9d508b): a path of steps, as arrows whose points sit
// in the next one's notches, each with an icon, a click on it going there
// or opening a menu of what it can change to. The manager's title bar is
// one (gui/svmanager/titlebar.go).
func TestItem66Breadcrumbs(t *testing.T) {
	a := headless(t, 1)
	var went []int
	b := widgets.NewBreadcrumbs(
		widgets.Crumb{Text: "Vault", Icon: style.IconSafe, OnClick: func() { went = append(went, 0) }},
		widgets.Crumb{Text: "personal", Icon: style.IconLock, OnClick: func() { went = append(went, 1) }},
		widgets.Crumb{Text: "Logins", Menu: func() []*widgets.MenuItem { return []*widgets.MenuItem{widgets.Item("Notes", nil)} }},
	)
	b.Arrows = true
	window(t, a, 600, 60, b)
	a.PumpOnce()
	r := b.CrumbRect(1)
	if r.Empty() || b.CrumbRect(2).Empty() {
		t.Fatal("the steps are not laid out: see uitoolkit-gaps.md item 66")
	}
	at := paintengine2d.Pt((r.Min.X+r.Max.X)/2, (r.Min.Y+r.Max.Y)/2)
	b.MousePress(widget.MouseEvent{Pos: at, Button: platform.ButtonLeft})
	b.MouseRelease(widget.MouseEvent{Pos: at, Button: platform.ButtonLeft})
	if len(went) != 1 || went[0] != 1 {
		t.Fatalf("a click on the second step went to %v: see uitoolkit-gaps.md item 66", went)
	}
}

// 67. The icons a password manager needs (52541d9): a padlock open, a key,
// a password masked, a shell prompt, a drive, a safe and dice. The manager
// uses them for its parts, its kinds of item and its padlocks.
func TestItem67IconsAPasswordManagerNeeds(t *testing.T) {
	for _, ic := range []style.ToolIcon{style.IconLockOpen, style.IconKey, style.IconPassword, style.IconTerminal,
		style.IconDrive, style.IconSafe, style.IconDice} {
		if !style.Drawable(ic) {
			t.Fatalf("icon %d cannot be drawn: see uitoolkit-gaps.md item 67", ic)
		}
	}
}

// 68. A cover lies over the whole window inside its frame, title bar and
// all (c575c39), and takes the pointer and the keyboard while it is up.
// The manager's window turning over is one (gui/svmanager/flip.go).
func TestItem68ACoverLiesOverTheTitleBar(t *testing.T) {
	a := headless(t, 1)
	win := window(t, a, 400, 300, newProbe())
	bar := widgets.NewHeaderBar([]widget.Component{widgets.NewLabel("crumbs")}, nil, nil)
	win.SetTitleBar(bar)
	cover := newProbe()
	win.SetCover(cover)
	win.Layout()
	if c, b := widget.DeviceBounds(cover), widget.DeviceBounds(bar); c.Union(b) != c || b.Empty() {
		t.Fatalf("the cover is %v, the title bar %v: see uitoolkit-gaps.md item 68", c, b)
	}
}

// 69. Window.Layout lays the window out at once (7002b3f), as its next
// frame would. The manager lays it out before it paints the faces of its
// turn (gui/svmanager/flip.go).
func TestItem69AWindowIsLaidOutAtOnce(t *testing.T) {
	a := headless(t, 1)
	p := newProbe()
	win, err := a.NewWindow(uitoolkit.WindowOptions{Width: 300, Height: 200, Headless: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(win.Close)
	win.SetContent(p)
	win.Layout()
	if p.Bounds().Empty() {
		t.Fatal("Window.Layout left the content unarranged: see uitoolkit-gaps.md item 69")
	}
}

// 70. A picture in perspective: paintengine2d still draws an image into a
// rectangle alone, but what the manager needed it for, a card turning
// over, is the toolkit's now (widgets.FlipPanel, 2041083): it turns in
// perspective, cut into strips, and says the card's outline as it turns,
// which the manager's window takes as its shape (gui/svmanager/flip.go).
func TestItem70ACardTurnsInPerspective(t *testing.T) {
	f := reflect.TypeOf((*widgets.FlipPanel)(nil))
	for _, name := range []string{"ShowBack", "ShowFront", "Turning", "CardOutline"} {
		if _, ok := f.MethodByName(name); !ok {
			t.Fatalf("FlipPanel has no %s: see uitoolkit-gaps.md item 70", name)
		}
	}
	if _, ok := f.Elem().FieldByName("Perspective"); !ok {
		t.Fatal("FlipPanel turns in perspective no more: see uitoolkit-gaps.md item 70")
	}
}

// 71. The pointing hand (5dc6a0d), the desktop's "pointer". The manager's
// locked vault's logo shows it (lockFace.CursorAt,
// gui/svmanager/lockface.go).
func TestItem71ThePointingHand(t *testing.T) {
	if !strings.Contains(uitoolkitSource(t, "cursor.go"), `CursorPointer: "pointer"`) {
		t.Fatal(`CursorPointer is not the desktop's "pointer" now: see uitoolkit-gaps.md item 71`)
	}
}

// 72. A passing note (e7c055b): ShowToast puts a line over the window's
// content that goes by itself, or stays, a negative time given, until it
// is taken down. The manager's notes are these (gui/svmanager/notes.go).
func TestItem72APassingNote(t *testing.T) {
	a := headless(t, 1)
	root := newProbe()
	window(t, a, 400, 300, root)
	n := widgets.ShowToast(root, "Copied.", widgets.ToastInfo, -1)
	if n == nil {
		t.Fatal("no note: see uitoolkit-gaps.md item 72")
	}
	a.PumpOnce()
	if got := widgets.Toasts(root); len(got) != 1 || got[0] != n || n.Timeout != 0 {
		t.Fatalf("the note that stays is not up: %v: see uitoolkit-gaps.md item 72", got)
	}
	widgets.DismissToasts(root)
	if len(widgets.Toasts(root)) != 0 {
		t.Fatal("the notes are still up: see uitoolkit-gaps.md item 72")
	}
}

// 73. A skin can say what its radios' well looks like (2a518d9): the
// format has a "radio" part. The manager's look is a pack now, Hangar, and
// no skin of its own.
func TestItem73ASkinHasARadiosWell(t *testing.T) {
	if !slices.Contains(style.SkinPartNames(), "radio") {
		t.Fatal(`the skin format has no "radio" part: see uitoolkit-gaps.md item 73`)
	}
}

// 74. A button's mark is in its label's ink (da6819a, c74233f): the engine
// is handed the mark with the label (style.ButtonDraw) and draws both. The
// manager's default buttons are the toolkit's as they are.
func TestItem74AButtonsMarkIsInItsLabelsInk(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "widgets", "button.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if !strings.Contains(string(src), "style.ButtonDraw{Label: b.Text, Icon: b.Icon}") {
		t.Fatal("a button's mark is not handed to the engine with its label: see uitoolkit-gaps.md item 74")
	}
}

// 75. A framed window can drop its shadow (1fa7918), keeping the toolkit's
// frame, buttons and resizing. The manager's window has none.
func TestItem75AFramedWindowDropsItsShadow(t *testing.T) {
	a := headless(t, 1)
	win := window(t, a, 300, 200, newProbe())
	win.SetFrameShadow(false)
	if win.FrameShadow() {
		t.Fatal("the window keeps its shadow: see uitoolkit-gaps.md item 75")
	}
}

// 76. A look's capitals reach the labels it paints (9a643ab,
// style.ControlLabelOf), as written for a screen reader. Hangar, the
// manager's look, sets its chrome's labels in capitals.
func TestItem76ALooksCapitalsReachItsLabels(t *testing.T) {
	p, ok := style.LoadTheme("hangar")
	if !ok {
		t.Skip("built without Hangar (-tags theme_engine_hangar)")
	}
	if got := style.ControlLabelOf(p.Look(), style.RoleButton, "Copy password"); got != "COPY PASSWORD" {
		t.Fatalf("Hangar's button says %q: see uitoolkit-gaps.md item 76", got)
	}
}

// Found with v0.23.6.

// 77. A framed window turns over with its frame (f754b65): Window.Flip
// turns a window wearing the toolkit's frame as a picture of itself,
// photographed with each face up, its buttons and its resizing kept. The
// manager's window does (gui/svmanager/flip.go).
func TestItem77AFramedWindowTurnsOverWithItsFrame(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "flip.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, "func (w *Window) turnWholeWindow()") || !strings.Contains(s, "return w.geom.framed && widget.Animates(w.flip)") {
		t.Fatal("a framed window no longer turns as a picture of itself: see uitoolkit-gaps.md item 77")
	}
}

// 78. A turn's pictures are wiped (c40b170): the flip panel zeroes its
// pictures of the faces wherever a turn ends, and a framed window its
// photographs of itself.
func TestItem78ATurnsPicturesAreWiped(t *testing.T) {
	flip, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "widgets", "flip.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	s := string(flip)
	i := strings.Index(s, "func (f *FlipPanel) end() {")
	if i < 0 || !strings.Contains(s[i:i+strings.Index(s[i:], "\n}\n")], "f.turn.wipe()") {
		t.Fatal("a flip panel's turn ends without wiping its pictures: see uitoolkit-gaps.md item 78")
	}
	app, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "flip.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if !strings.Contains(string(app), "shot.wipe()") {
		t.Fatal("a framed window's photographs of itself are not wiped: see uitoolkit-gaps.md item 78")
	}
}

// 79. A breadcrumb says a tip of its own (aadd607), and its description to
// a screen reader. The vault's step says the vault's state and its sync's.
func TestItem79ABreadcrumbHasATip(t *testing.T) {
	if _, ok := reflect.TypeOf(widgets.Crumb{}).FieldByName("Tip"); !ok {
		t.Fatal("Crumb has no Tip: see uitoolkit-gaps.md item 79")
	}
}

// 80. A mark's strip is the same width in logical pixels at every scale
// (714f8ab).
func TestItem80AMarkedButtonsStripScales(t *testing.T) {
	strip := func(scale float32) float32 {
		a := headless(t, scale)
		var w [2]float32
		for i, icon := range []style.ToolIcon{style.IconNone, style.IconCheck} {
			b := widgets.NewButton("Allow until the vault locks", nil)
			b.Icon = icon
			window(t, a, 400, 200, widgets.NewRow(b))
			a.PumpOnce()
			w[i] = b.Measure(layout.Unbounded()).X
		}
		return (w[1] - w[0]) / scale
	}
	if one, two := strip(1), strip(2); math.Abs(float64(one-two)) >= 1 {
		t.Fatalf("a mark's strip is %.1f at 1x and %.1f at 2x: see uitoolkit-gaps.md item 80", one, two)
	}
}

// 81. A breadcrumb that opens something wears a chevron (aadd607): a step
// with a Menu, or with Opens set, as the vault's is.
func TestItem81ABreadcrumbThatOpensIsMarked(t *testing.T) {
	if _, ok := reflect.TypeOf(widgets.Crumb{}).FieldByName("Opens"); !ok {
		t.Fatal("Crumb has no Opens: see uitoolkit-gaps.md item 81")
	}
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "widgets", "breadcrumbs.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if !strings.Contains(string(src), "func crumbOpens(c Crumb) bool { return c.Menu != nil || c.Opens }") {
		t.Fatal("a breadcrumb that opens something is marked otherwise now: see uitoolkit-gaps.md item 81")
	}
}

// 82. Words fitted to the width they were measured with are not cut short
// (f899ec5): Font.Fit allows a part of a pixel.
func TestItem82WordsFitTheWidthTheyWereMeasuredWith(t *testing.T) {
	f := uitoolkit.LightLook().Font()
	text := "GRANTS"
	if got := f.Fit(text, f.Advance(text)-0.0001); got != text {
		t.Fatalf("words fitted to a hair under their width come out %q: see uitoolkit-gaps.md item 82", got)
	}
}

// 83. A window keeps its look's outline when its own bar is the caption
// (05f6aa2): Hangar's corners are cut on the manager's window, whose title
// bar is merged.
func TestItem83AMergedCaptionKeepsTheLooksSilhouette(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "style", "silhouette.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if strings.Contains(string(src), "st.Maximized || st.Tiled != 0 || st.Merged {") {
		t.Fatal("a merged caption drops the look's silhouette again: see uitoolkit-gaps.md item 83")
	}
}

// 84. A cut corner's hairline is drawn over the content (44415e8,
// style.DecorationOverEngine): the manager's rail no longer buries
// Hangar's bracket.
func TestItem84ACutCornersBorderIsOverTheContent(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "window.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if !strings.Contains(string(src), "w.paintDecorationOver(ctx)") {
		t.Fatal("the frame paints nothing over the content: see uitoolkit-gaps.md item 84")
	}
}

// 85. A Wayland cancel handled while nothing is held ends nothing
// (39e4fa4), as X11's loss does.
func TestItem85AWaylandCancelWithNothingHeldEndsNothing(t *testing.T) {
	gone := strings.Join(strings.Fields(uitoolkitFunc(t, "wayland_linux.go", "", "uitkWlDataCancelled")), " ")
	if !strings.Contains(gone, "lost := heldSecret()") || !strings.Contains(gone, "if lost == nil {") {
		t.Fatal("a Wayland cancel with nothing held ends the next secret again: see uitoolkit-gaps.md item 85")
	}
}

// 86. A refused copy clears the one before it (39e4fa4): the copy being
// replaced is let go only once the new one is made, and cleared when the
// new one is refused.
func TestItem86ARefusedCopyClearsTheOneBefore(t *testing.T) {
	set := strings.Join(strings.Fields(uitoolkitFunc(t, "clipboard_secret.go", "", "ClipboardSetSecret")), " ")
	refused, made := strings.Index(set, "if !nativeSetSecret(data) {"), strings.Index(set, "prev.forget()")
	if refused < 0 || made < refused || !strings.Contains(set[refused:made], "prev.Clear()") {
		t.Fatal("a refused copy leaves the one before it again: see uitoolkit-gaps.md item 86")
	}
}

// 87. An application says which of its motion is the thing itself
// (b076d9b): SetMotion on a widget or a window, read by widget.Animates.
// The manager's flip panel turns with style.MotionAlways, the rest of the
// window keeping to the person's setting.
func TestItem87MotionThatIsTheThingItself(t *testing.T) {
	c := newProbe()
	c.SetMotion(style.MotionAlways)
	was := style.ReduceMotion()
	style.SetReduceMotion(true)
	defer style.SetReduceMotion(was)
	if os.Getenv(style.AnimationsEnv) == "0" {
		t.Skip("UITK_ANIMATIONS=0 beats everything, as it should")
	}
	if !widget.Animates(c) {
		t.Fatal("MotionAlways does not animate where the person asks for less motion: see uitoolkit-gaps.md item 87")
	}
}

// 88. A window panel's silhouette is not its window's shape: a Panel with
// Window clips its chrome to the outline the look gives a window, but the
// window under it takes a look's silhouette only where the toolkit draws
// its frame. A frameless window whose chrome is a window panel stays a
// rectangle. The manager's window wears the toolkit's frame again (77),
// so it does not meet this.
func TestItem88AWindowPanelsSilhouetteIsNotItsWindowsShape(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "shape.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	if !strings.Contains(string(src), "if w.caption == nil || !w.framed() {") {
		t.Fatal("a window takes a look's silhouette without the toolkit's frame now: see uitoolkit-gaps.md item 88")
	}
}

// 89. A panel's floor holds the chrome it draws (5179abe).
func TestItem89APanelsFloorHoldsItsChrome(t *testing.T) {
	if _, ok := reflect.TypeOf((*widgets.Panel)(nil)).MethodByName("MinWidth"); !ok {
		t.Fatal("Panel answers no MinWidth: see uitoolkit-gaps.md item 89")
	}
}

// Found with v0.23.7.

// 90. A flip panel offers a key to the face that is up (8ca4b6d): a key
// from a turned window's title bar, or with nothing focused, reaches the
// content on its face, where the manager's own keys are.
func TestItem90AFlipPanelOffersAKeyToTheFaceUp(t *testing.T) {
	a := headless(t, 1)
	front, back := newKeyLog(true), newKeyLog(true)
	win := window(t, a, 400, 300, newProbe())
	p := win.SetFlipFaces(front, back)
	a.PumpOnce()
	p.KeyPress(widget.KeyEvent{Key: platform.KeyPageDown, Mods: platform.ModCtrl})
	if len(front.got) == 0 || len(back.got) > 0 {
		t.Fatalf("a key to the flip panel reached the front %v and the back %v: see uitoolkit-gaps.md item 90", front.got, back.got)
	}
}

// 91. A framed window comes back the way it went (a12ba05): the stand-in
// panel of its two pictures turns to its front where the window is
// coming back to its front.
func TestItem91AFramedWindowComesBackTheWayItWent(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "flip.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	s := string(src)
	i := strings.Index(s, "func (w *Window) turnWholeWindow() {")
	if i < 0 {
		t.Fatal("what this pin reads of the window's turn has moved: see uitoolkit-gaps.md item 91")
	}
	body := s[i : i+strings.Index(s[i:], "\n}\n")]
	if !strings.Contains(body, "toBack := !w.flip.Showing()") || !strings.Contains(body, "p.ShowFront()") {
		t.Fatal("a framed window's turn no longer goes the way the window does: see uitoolkit-gaps.md item 91")
	}
}

// Found looking again for what the manager works round (2026-10-13).

// 92. Every digit is a key (398d343): Key0 to Key9, in a run. The manager
// picks its parts with Ctrl+1, 2 and 3 (key, gui/svmanager/layout.go).
func TestItem92EveryDigitIsAKey(t *testing.T) {
	for d := '0'; d <= '9'; d++ {
		k := platform.DigitKey(d)
		if k != platform.Key0+platform.Key(d-'0') {
			t.Fatalf("digit %c is key %v: see uitoolkit-gaps.md item 92", d, k)
		}
		if r, ok := platform.DigitRune(k); !ok || r != d {
			t.Fatalf("key %v is digit %c, %v: see uitoolkit-gaps.md item 92", k, r, ok)
		}
	}
}

// 93. A cloud, and a badge on the corner of an icon (a097e91): the
// manager's Join a synced vault is the cloud, and Unlock with… and New
// vault carry the toolkit's plus (style.DrawIconBadge, marks.go).
func TestItem93ACloudAndABadge(t *testing.T) {
	if !style.Drawable(style.IconCloud) {
		t.Fatal("the cloud cannot be drawn: see uitoolkit-gaps.md item 93")
	}
	img := paintengine2d.NewImage(32, 32)
	style.DrawIconBadge(paintengine2d.NewContext(img), paintengine2d.XYWH(0, 0, 32, 32), style.IconBadge{Mark: style.BadgePlus}, uitoolkit.LightLook())
	painted := false
	for _, b := range img.Pix {
		painted = painted || b != 0
	}
	if !painted {
		t.Fatal("a plus badge draws nothing: see uitoolkit-gaps.md item 93")
	}
}

// Found moving to v0.23.14.

// 94. A framed window's turn takes its flip panel's clock (6100823):
// FlipPanel.SetClock, set before Flip, holds the turn a framed window
// builds for itself, so a test steps it a frame at a time. The manager's
// test of its turn does (TestTheWindowTurnsOverWithItsFrame).
func TestItem94AFramedWindowsTurnTakesItsClock(t *testing.T) {
	if _, ok := reflect.TypeOf((*widgets.FlipPanel)(nil)).MethodByName("Clock"); !ok {
		t.Fatal("FlipPanel has no Clock to carry: see uitoolkit-gaps.md item 94")
	}
	src, err := os.ReadFile(filepath.Join(uitoolkitDir(), "..", "app", "flip.go"))
	if err != nil {
		t.Skipf("uitoolkit's source is not where it was built from: %v", err)
	}
	s := string(src)
	i := strings.Index(s, "func (w *Window) turnWholeWindow() {")
	if i < 0 {
		t.Fatal("what this pin reads of the window's turn has moved: see uitoolkit-gaps.md item 94")
	}
	if body := s[i : i+strings.Index(s[i:], "\n}\n")]; !strings.Contains(body, "SetClock(") {
		t.Fatal("a framed window's turn no longer takes its flip panel's clock: see uitoolkit-gaps.md item 94")
	}
}
