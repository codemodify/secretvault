package secretui

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// Frame is the inside of a secretvault dialog window: the header, then
// the dialog's own body. It does what every such dialog needs from its
// window, whatever the body holds:
//
//   - While a secret field has the keyboard, the window holds it
//     ([uitoolkit.Window.SetSecureInput]): an X11 keyboard grab, Wayland's
//     shortcut inhibitor, macOS secure event input. It lets go when the
//     focus moves to a button, and when the dialog closes ([Frame.Release]).
//   - The header says "Typing is private" while the keyboard is held, which is
//     what is in effect rather than what was asked for
//     ([uitoolkit.Window.SecureInputHeld]): on X11 the grab is taken once
//     the window is mapped and has the focus, dropped when it loses it,
//     and can fail. Nothing is said while it is not held, which is all
//     there is to say on Windows.
//   - Escape that nothing under the focus took runs OnEscape.
//
// Input methods need nothing from here: uitoolkit turns text input off on
// the window while a SecretField has the focus, because a SecretField is
// deliberately not an input-method target.
type Frame struct {
	widget.Base
	// OnEscape runs when Escape reaches the frame: the user dismissed the
	// dialog.
	OnEscape func()

	header *Header
	col    *widgets.FlexBox
	win    *uitoolkit.Window
	held   bool
}

// NewFrame is title's header over body.
func NewFrame(title string, body widget.Component) *Frame {
	f := &Frame{header: NewHeader(title)}
	f.Init(f)
	f.col = widgets.NewColumn(f.header).WithGap(0)
	f.col.AddFlex(body, 1)
	f.Add(f.col)
	return f
}

// Header is the frame's header band.
func (f *Frame) Header() *Header { return f.header }

// Window is the window the frame was opened in ([Open]), or nil.
func (f *Frame) Window() *uitoolkit.Window { return f.win }

func (f *Frame) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(f.col.Measure(c))
}

func (f *Frame) Arrange(r paintengine2d.Rect) {
	f.SetBounds(r)
	f.col.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

func (f *Frame) KeyPress(e widget.KeyEvent) bool {
	if e.Key == platform.KeyEscape && f.OnEscape != nil {
		f.OnEscape()
		return true
	}
	return false
}

// FocusMoved is the window telling the frame where the keyboard went
// ([widget.FocusWatcher]); it holds the keyboard while that is a secret
// field.
func (f *Frame) FocusMoved(now widget.Component) { f.hold(IsSecret(now)) }

func (f *Frame) hold(on bool) {
	if f.win == nil || on == f.held {
		return
	}
	f.held = on
	f.win.SetSecureInput(on)
}

// Holding reports whether the frame has asked its window to hold the
// keyboard. Whether the desktop agreed is the window's to say, and the
// header's ([Header.Held]); on Windows, which has nothing to offer, it
// did not.
func (f *Frame) Holding() bool { return f.held }

// Release lets go of the keyboard. A dialog calls it as it closes, before
// the answer is acted on.
func (f *Frame) Release() { f.hold(false) }

// IsSecret reports whether c is where a secret is typed: a SecretField,
// or a widget that says it takes one (a TextField with Password set).
func IsSecret(c widget.Component) bool {
	if c == nil {
		return false
	}
	if _, ok := c.(*widgets.SecretField); ok {
		return true
	}
	return widget.IsSecretTarget(c)
}

// Open shows f in a new dialog window, width logical pixels across and as
// tall as f needs, and returns the window. The window is:
//
//   - a dialog to the desktop, centred, above the other windows and fixed
//     in size, all asked for at creation rather than a frame later;
//   - as tall as f, measured by uitoolkit at the window's own scale and
//     with any frame it draws itself (FitContent);
//   - kept out of screenshots, recordings and screen shares where the
//     platform can do that (Windows and macOS; not X11 or Wayland);
//   - activated, so the keyboard is there when it opens.
func Open(a *uitoolkit.Application, title string, width int, f *Frame) (*uitoolkit.Window, error) {
	w, err := a.NewWindow(uitoolkit.WindowOptions{
		// The height is a first guess, which the content replaces.
		Title: title, Width: width, Height: width / 2,
		Role: uitoolkit.RoleDialog, Center: true, KeepAbove: true,
		Sizing: platform.SizingFixed, FitContent: true,
	})
	if err != nil {
		return nil, err
	}
	f.win = w
	w.OnSecureInput(f.header.SetHeld)
	// The desktop shows secretvault's padlock for it, as for the manager:
	// a question that comes up on its own says whose it is in the task
	// bar and the window switcher too.
	w.SetIcon(Icons()...)
	// FitContent fits the window to f when it is first laid out, before
	// it is shown, and centres it again for the height it then has.
	w.SetContent(f)
	w.SetExcludeFromCapture(true)
	w.Activate()
	return w, nil
}
