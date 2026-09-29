package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// dialog is a modal card over the window: a title, a body, and a row of
// buttons laid out as the look's platform lays them out. Escape, the
// card's close box and Close all end it the same way, through onClose,
// which is where whatever was typed into it gets wiped.
type dialog struct {
	overlay *widgets.Overlay
	closed  bool
}

func (m *Manager) showDialog(title string, body widget.Component, buttons *widgets.ButtonBox, focus widget.Component, onClose func()) *dialog {
	d := &dialog{}
	col := widgets.NewColumn(newFixedWidth(body, dialogWidth), buttons).WithGap(16).WithPad(6)
	card := widgets.NewPanel(title, col)
	card.Window = true
	card.Raised = true
	card.OnClose = d.Close
	d.overlay = widgets.NewOverlay(card)
	d.overlay.Modal = true
	d.overlay.MinCardW = 420
	d.overlay.InitialFocus = focus
	d.overlay.OnClose = func() {
		d.closed = true
		if onClose != nil {
			onClose()
		}
	}
	widget.ShowOverlay(m.root(), d.overlay)
	return d
}

// dialogWidth is how wide a dialog's body is, in the look's 1x pixels.
const dialogWidth = 500

// fixedWidth gives its child one width, whatever it is offered (up to
// what there is): text that wraps then wraps at the same place when the
// dialog is measured and when it is laid out, so the card is as tall as
// what it holds. uitoolkit's columns measure a wrapping label once, at
// the width offered, and a card that then comes out narrower cuts its
// last lines, and its buttons, off.
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
	w := style.Dip(f.Look(), f.w)
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

func (f *fixedWidth) Arrange(r paintengine2d.Rect) {
	f.SetBounds(r)
	f.Children()[0].Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

// Close takes the dialog down.
func (d *dialog) Close() {
	if d == nil || d.closed {
		return
	}
	widget.DismissOverlay(d.overlay)
	if !d.closed {
		// It was never shown (a window with no host): end it all the same.
		d.overlay.Dismissed()
	}
}

// confirm asks before doing something that cannot be taken back.
func (m *Manager) confirm(title, text, action string, do func()) {
	body := widgets.NewLabel(text)
	body.Wrap = true
	var d *dialog
	yes := widgets.NewButton(action, func() {
		d.Close()
		do()
	})
	no := widgets.NewButton("Cancel", func() { d.Close() })
	buttons := widgets.NewButtonBox().AddButton(yes, widgets.RoleDestructive).AddButton(no, widgets.RoleReject)
	no.Primary = true
	d = m.showDialog(title, body, buttons, no, nil)
}

// ask asks for one line of text.
func (m *Manager) ask(title, label, value string, done func(string)) {
	f := widgets.NewTextField(value, "", nil)
	f.SetAccessibleName(label)
	f.SelectAll()
	var d *dialog
	ok := widgets.NewButton("OK", nil)
	ok.OnClick = func() {
		text := f.Text
		d.Close()
		if text != "" {
			done(text)
		}
	}
	f.OnSubmit = func(string) { ok.OnClick() }
	body := widgets.NewColumn(widgets.NewLabel(label).For(f), f).WithGap(gap)
	buttons := widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept).
		AddButton(widgets.NewButton("Cancel", func() { d.Close() }), widgets.RoleReject)
	d = m.showDialog(title, body, buttons, f, nil)
}
