package svmanager

import (
	"math"
	"slices"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// dialog is a modal dialog: a window of its own, belonging to the
// manager's (or to the dialog it was opened from), with a body and a row
// of buttons laid out as the look's platform lays them out. While one is
// up the window under it takes nothing in: a click there brings the
// dialog forward, as a desktop's own modal dialogs do. Escape, the
// window's close control and Close all end it the same way, through
// onClose, which is where whatever was typed into it gets wiped.
//
// Dialogs stack: one shown while another is up belongs to it, and the
// one underneath comes back as it was when the top one is done with, its
// fields still holding what was typed. Where no window can be opened the
// dialog is a card over the window instead (an overlay).
type dialog struct {
	m       *Manager
	win     *app.Window      // its own window
	overlay *widgets.Overlay // or the card over the window, where there is none
	onClose func()
	closed  bool
}

// showDialog shows a dialog of title over whatever is up. buttons is the
// row at its foot: a ButtonBox, or a row that holds one.
//
// It is widgets.DialogContentFoot (uitoolkit-gaps.md, 54): the body as
// tall as what it holds, scrolled when the dialog is taller than its
// window, with the foot below it in view (40, 46), at the dialog's whole
// width, so that a foot holding a ButtonBox beside something else (every
// passphrase question says "Caps Lock is on" there) keeps the platform's
// left-hand group (Back, and a destructive button under Mac and GNOME
// looks) apart.
func (m *Manager) showDialog(title string, body, buttons, focus widget.Component, onClose func()) *dialog {
	d := &dialog{m: m, onClose: onClose}
	// The width is held outside it: a scroll view takes all the width it
	// is offered.
	content := newFixedWidth(widgets.DialogContentFoot(body, buttons), dialogWidth)
	if d.openWindow(title, content, focus) {
		m.dialogs = append(m.dialogs, d)
		m.blockWindow()
		m.syncCapture()
		return d
	}
	card := widgets.NewPanel(title, content)
	card.Window = true
	card.Raised = true
	card.OnClose = d.Close
	d.overlay = widgets.NewOverlay(card)
	d.overlay.Modal = true
	d.overlay.MinCardW = 420
	d.overlay.InitialFocus = focus
	d.overlay.OnClose = d.ended
	widget.ShowOverlay(m.root(), d.overlay)
	m.syncCapture()
	return d
}

// openWindow puts the dialog in a window of its own, sized to what it
// holds, belonging to the window it was opened from.
func (d *dialog) openWindow(title string, content, focus widget.Component) bool {
	m := d.m
	owner := m.win
	if top := m.topDialog(); top != nil {
		owner = top.win
	}
	if owner == nil || owner.Closed() || owner.App() == nil {
		return false
	}
	root := newDialogRoot(d, content)
	w, err := owner.App().NewWindow(platform.WindowOptions{
		Title: title, Width: dialogWidth + 2*pad, Height: 200,
		Role: platform.RoleDialog, Owner: owner.Surface(), Center: true,
	})
	if err != nil {
		return false
	}
	d.win = w
	w.SetContent(root)
	if focus != nil {
		w.SetInitialFocus(focus)
	}
	// Its close control ends it the way Cancel does; Close closes the
	// window.
	w.SetOnCloseRequest(func() bool {
		d.Close()
		return false
	})
	root.fit()
	return true
}

// focus gives the keyboard to c, in whichever window holds it: a
// dialog's, or the manager's.
func (m *Manager) focus(c widget.Component) {
	for _, d := range m.dialogs {
		if d.win != nil && !d.win.Closed() && isUnder(c, d.win.Content()) {
			d.win.RequestFocus(c)
			return
		}
	}
	m.win.RequestFocus(c)
}

// topDialog is the dialog in a window of its own that is up on top, or
// nil.
func (m *Manager) topDialog() *dialog {
	if len(m.dialogs) == 0 {
		return nil
	}
	return m.dialogs[len(m.dialogs)-1]
}

// Close takes the dialog down, and only it: a dialog under it stays up.
func (d *dialog) Close() {
	if d == nil || d.closed {
		return
	}
	if d.win != nil {
		d.closed = true
		m := d.m
		m.dialogs = slices.DeleteFunc(m.dialogs, func(x *dialog) bool { return x == d })
		d.win.SetContent(nil)
		d.win.Close()
		if len(m.dialogs) == 0 {
			m.unblockWindow()
		}
		if top := m.topDialog(); top != nil {
			top.win.Raise()
		} else if !m.win.Closed() {
			m.win.Raise()
		}
		d.ended()
		return
	}
	widget.DismissOverlay(d.overlay)
	if !d.closed {
		// It was never shown (a window with no host): end it all the same.
		d.overlay.Dismissed()
	}
}

// ended runs once the dialog is down, whichever way it went.
func (d *dialog) ended() {
	d.closed = true
	if d.onClose != nil {
		d.onClose()
	}
	d.m.syncCapture()
}

// closeDialogs takes every dialog down, the top one first (quitting).
func (m *Manager) closeDialogs() {
	for len(m.dialogs) > 0 {
		m.topDialog().Close()
	}
}

// overlayRoot is where something of the toolkit's that is shown over a
// window (a file chooser) goes: the top dialog's window, or the manager's.
func (m *Manager) overlayRoot() widget.Component {
	if top := m.topDialog(); top != nil {
		return top.win.Content()
	}
	return m.root()
}

// dialogRoot is a dialog window's content: the dialog, padded, ended by
// Escape, and the window kept as tall as the dialog needs while it grows
// (a problem said under a form, a step that asks more).
type dialogRoot struct {
	widget.Base
	d     *dialog
	last  float32 // the height the window was last given, in 1x pixels
	lastW int     // and the width
}

func newDialogRoot(d *dialog, content widget.Component) *dialogRoot {
	r := &dialogRoot{d: d}
	r.Init(r)
	r.Add(widgets.NewPad(pad, content))
	return r
}

func (r *dialogRoot) Measure(c layout.Constraints) paintengine2d.Point {
	return r.Children()[0].Measure(c)
}

func (r *dialogRoot) Arrange(b paintengine2d.Rect) {
	r.SetBounds(b)
	r.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
	if !r.d.closed {
		r.d.m.post(r.fit)
	}
}

func (r *dialogRoot) KeyPress(e widget.KeyEvent) bool {
	if e.Key == platform.KeyEscape {
		r.d.Close()
		return true
	}
	return false
}

// MinWidth is the dialog's floor (widget.MinWidther).
func (r *dialogRoot) MinWidth() float32 { return widget.MinWidthOf(r.Children()[0]) }

// maxDialogHeight is as tall as a dialog's window grows, in 1x pixels;
// past it, its body scrolls.
const maxDialogHeight = 760

// fit makes the window as wide as what it holds needs at least, and as
// tall as it needs, up to maxDialogHeight.
func (r *dialogRoot) fit() {
	w := r.d.win
	if w == nil || w.Closed() || r.d.closed {
		return
	}
	scale := w.Scale()
	width, height := w.Size()
	floor := int(math.Ceil(float64(widget.MinWidthOf(r) / scale)))
	if width < floor {
		width = floor
		w.SetMinSize(float32(floor), 120)
	}
	sz := r.Children()[0].Measure(layout.Constraints{MinW: float32(width) * scale, MaxW: float32(width) * scale, MaxH: -1})
	h := float32(math.Ceil(float64(sz.Y / scale)))
	h = min(max(h, 120), maxDialogHeight)
	if h != r.last || width != r.lastW {
		r.last, r.lastW = h, width
		if int(h) != height || width != r.width() {
			w.SetSize(width, int(h))
		}
	}
}

// width is the window's width, in 1x pixels.
func (r *dialogRoot) width() int {
	w, _ := r.d.win.Size()
	return w
}

// dialogWidth is how wide a dialog's content is, in the look's 1x pixels.
const dialogWidth = 500

// fixedWidth gives its child one width, whatever it is offered (up to
// what there is), so that a dialog is dialogWidth across whatever its
// text: offered the window, a wrapping message would take most of it.
type fixedWidth struct {
	widget.Base
	w float32
}

func newFixedWidth(child widget.Component, w float32) *fixedWidth {
	f := &fixedWidth{w: w}
	f.Init(f)
	f.Add(child)
	return f
}

func (f *fixedWidth) width(c layout.Constraints) float32 {
	// One width, but never less than what it holds needs: a row of
	// buttons wider than it (each with its icon) widens the dialog rather
	// than run off it.
	w := max(style.Dip(f.Look(), f.w), widget.MinWidthOf(f.Children()[0]))
	if c.HasMaxW() && c.MaxW < w {
		w = c.MaxW
	}
	return w
}

func (f *fixedWidth) Measure(c layout.Constraints) paintengine2d.Point {
	w := f.width(c)
	sz := f.Children()[0].Measure(layout.Constraints{MinW: w, MaxW: w, MaxH: c.MaxH})
	return c.Constrain(paintengine2d.Pt(w, sz.Y))
}

// MinWidth is the one width, or the child's floor where that is wider
// (widget.MinWidther).
func (f *fixedWidth) MinWidth() float32 {
	return max(style.Dip(f.Look(), f.w), widget.MinWidthOf(f.Children()[0]))
}

func (f *fixedWidth) Arrange(r paintengine2d.Rect) {
	f.SetBounds(r)
	f.Children()[0].Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

// confirm asks before doing something that cannot be taken back.
func (m *Manager) confirm(title, text, action string, do func()) {
	body := widgets.NewLabel(text)
	body.Wrap = true
	var d *dialog
	yes := newButton(action, func() {
		d.Close()
		do()
	})
	no := newButton("Cancel", func() { d.Close() })
	buttons := widgets.NewButtonBox().AddButton(yes, widgets.RoleDestructive).AddButton(no, widgets.RoleReject)
	no.Primary = true
	d = m.showDialog(title, body, buttons, no, nil)
}
