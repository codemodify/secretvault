package main

import (
	"crypto/subtle"
	"math"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// Nothing in this file turns a passphrase into a string, and a test reads
// it to keep it that way: the passphrase is typed into a SecretField,
// whose contents are a []byte, and leaves as a copy of that []byte, which
// svprompt.Serve escapes on bytes into a D line and wipes. The fields are
// wiped as the dialog closes, whichever way it closes.

// kind is what a dialog asks.
type kind int

const (
	askPIN     kind = iota // a passphrase, or a new one twice (GETPIN)
	askChoose              // one of the choices offered (CHOOSE)
	askConfirm             // OK, Cancel and perhaps a third answer (CONFIRM)
	askMessage             // something to read, and one button (MESSAGE)
)

// Dialog widths, in logical pixels. A dialog is at least minWidth, wider
// where its buttons need it to sit on one line (a consent question has
// four side by side), and at most maxWidth, past which they fold.
const (
	minWidth = 460
	maxWidth = 760
	sidePad  = 20 // the body's margin, left and right
)

// answer is how a dialog ended. Whoever receives secret owns it, and
// wipes it.
type answer struct {
	secret []byte
	// choice is the chosen ID (askChoose), or "ok", "notok" or "cancel"
	// (askConfirm), as svprompt.UI has them.
	choice string
	// err is svprompt.ErrCanceled, svprompt.ErrTimeout, or why the
	// dialog could not be shown.
	err error
}

// dialog is one question on screen. It is made on the protocol's
// goroutine and handed to the UI thread, which opens it; from then on
// everything but the answer channel is the UI thread's.
type dialog struct {
	kind    kind
	req     svprompt.Request
	notOK   string                     // askConfirm's third button, if any
	choices []svprompt.Choice          // askChoose's answers
	asker   string                     // the program that started this prompt, when that is worth saying
	answer  chan answer                // the one answer, sent once
	buttons map[string]*widgets.Button // by choice ID, or "ok", "notok", "cancel"

	win        *uitoolkit.Window
	frame      *secretui.Frame
	pin        *widgets.SecretField
	repeat     *widgets.SecretField
	problem    *widgets.Label     // SETERROR, and later a repeat that did not match
	caps       *secretui.CapsLock // "Caps Lock is on", beside a passphrase's buttons
	factValues []*widgets.Label   // "/usr/bin/mail", beside "Program:"
	stop       func()             // the timeout's timer
	done       bool
}

func newDialog(k kind, r svprompt.Request) *dialog {
	return &dialog{kind: k, req: r, answer: make(chan answer, 1), buttons: map[string]*widgets.Button{}}
}

// title is the header's line under the name. secretvaultd's titles name
// the vault ("Unlock vault Personal"); other programs may send none.
func (d *dialog) title() string {
	if d.req.Title != "" {
		return d.req.Title
	}
	switch d.kind {
	case askPIN:
		return "Passphrase"
	case askMessage:
		return "Message"
	}
	return "Confirm"
}

// width is the dialog's width for its button row: what the row needs on
// one line, within minWidth and maxWidth.
func (d *dialog) width(a *uitoolkit.Application, actions widget.Component) int {
	actions.SetLook(a.Look())
	need := actions.Measure(layout.Unbounded()).X/a.Scale() + 2*sidePad
	actions.SetLook(nil)
	return min(max(minWidth, int(math.Ceil(float64(need)))), maxWidth)
}

// open builds the dialog and shows it in a window of a. UI thread only.
func (d *dialog) open(a *uitoolkit.Application) error {
	body, actions, first := d.build(a)
	width := d.width(a, actions)
	d.frame = secretui.NewFrame(d.title(), body)
	d.frame.OnEscape = d.cancel
	w, err := secretui.Open(a, secretui.Name+": "+d.title(), width, d.frame)
	if err != nil {
		return err
	}
	d.win = w
	w.SetInitialFocus(first)
	// The window manager's close button is a cancel.
	w.SetOnCloseRequest(func() bool {
		d.cancel()
		return false
	})
	if d.req.Timeout > 0 {
		d.stop = w.AfterFunc(d.req.Timeout, func() { d.finish(answer{err: svprompt.ErrTimeout}) })
	}
	return nil
}

// build is the dialog's body, the row of buttons at its foot, and what
// has the keyboard when it opens.
func (d *dialog) build(a *uitoolkit.Application) (body, actions, first widget.Component) {
	pal := a.Look().Palette()
	// Gaps and padding are 1x lengths, which uitoolkit scales to the
	// display as it scales the widgets.
	col := widgets.NewColumn().WithGap(10).WithPadding(sidePad, 16, sidePad, 16)

	paras, facts := splitDescription(d.req.Description)
	for i, p := range paras {
		// A paragraph's lines, with a little more room between two
		// paragraphs than between two lines.
		para := widgets.NewColumn().WithGap(10)
		if i > 0 {
			para.WithPadding(0, 12, 0, 0)
		}
		for _, line := range p {
			l := widgets.NewLabel(line)
			l.Wrap = true
			para.Add(l)
		}
		col.Add(para)
	}
	if d.asker != "" {
		facts = append(facts, fact{"Asked by", d.asker})
	}
	if len(facts) > 0 {
		form := widgets.NewForm()
		form.RowGap = 4
		for _, f := range facts {
			// A long value (a program's path) wraps rather than being
			// cut short; a short one takes its one line.
			v := widgets.NewLabel(f.value)
			v.Wrap = true
			name := form.AddRow(f.name+":", v)
			name.Tone = widgets.ToneMuted
			d.factValues = append(d.factValues, v)
		}
		col.Add(form)
	}
	// The error line: SETERROR's, after a wrong try, and the mismatch of
	// a new passphrase's two entries, which needs its line kept for it.
	if d.req.Error != "" || d.kind == askPIN && d.req.Repeat != "" {
		d.problem = widgets.NewLabel(d.req.Error)
		d.problem.Wrap = true
		d.problem.MinLines = 1
		d.problem.Color = secretui.Ink(pal.Danger, pal.Background) // readable, in dark looks too
		col.Add(d.problem)
	}

	var row widget.Component
	switch d.kind {
	case askPIN:
		form := widgets.NewForm()
		d.pin = widgets.NewSecretField("")
		d.pin.OnSubmit = d.submit
		d.pin.OnEscape = d.cancel
		form.AddRow(orDefault(d.req.Prompt, "Passphrase:"), d.pin)
		if d.req.Repeat != "" {
			d.repeat = widgets.NewSecretField("")
			d.repeat.OnSubmit = d.submit
			d.repeat.OnEscape = d.cancel
			form.AddRow(d.req.Repeat, d.repeat)
		}
		col.Add(form)
		first = d.pin
		bb := widgets.NewButtonBox()
		bb.AddButton(d.button("ok", orDefault(d.req.OK, "OK"), func() { d.submit(nil) }), widgets.RoleAccept)
		bb.AddButton(d.button("cancel", orDefault(d.req.Cancel, "Cancel"), d.cancel), widgets.RoleReject)
		// Caps Lock is said beside the buttons while it is on, where it
		// takes no room of its own: the dialog stays as tall as it opened.
		d.caps = secretui.NewCapsLock()
		r := widgets.NewRow(d.caps, bb).WithGap(16).WithAlign(layout.AlignCenter)
		r.AddFlex(bb, 1)
		row = r
	case askChoose:
		// Every answer offered, in the order offered. The default is the
		// refusal (secretvaultd's "deny", or else the last answer, which
		// is where a refusal goes): it has the keyboard, so an Enter
		// pressed without reading refuses, and it sits apart at the
		// right. The others fold onto a second line if they must.
		def := d.choices[len(d.choices)-1].ID
		for _, c := range d.choices {
			if c.ID == svrpc.ChoiceDeny {
				def = c.ID
			}
		}
		rest := widgets.NewWrap()
		var refuse *widgets.Button
		for _, c := range d.choices {
			id := c.ID
			b := d.button(id, c.Label, func() { d.finish(answer{choice: id}) })
			if id == def {
				refuse = b
				continue
			}
			rest.Add(b)
		}
		refuse.Primary = true
		r := widgets.NewRow(rest, refuse).WithGap(16).WithAlign(layout.AlignStart)
		r.AddFlex(rest, 1)
		first, row = refuse, r
	case askConfirm:
		bb := widgets.NewButtonBox()
		ok := d.button("ok", orDefault(d.req.OK, "OK"), func() { d.finish(answer{choice: "ok"}) })
		bb.AddButton(ok, widgets.RoleAccept)
		if d.notOK != "" {
			bb.AddButton(d.button("notok", d.notOK, func() { d.finish(answer{choice: "notok"}) }), widgets.RoleDestructive)
		}
		bb.AddButton(d.button("cancel", orDefault(d.req.Cancel, "Cancel"), d.cancel), widgets.RoleReject)
		first = ok
		row = bb
	case askMessage:
		bb := widgets.NewButtonBox()
		ok := d.button("ok", orDefault(d.req.OK, "OK"), func() { d.finish(answer{}) })
		bb.AddButton(ok, widgets.RoleAccept)
		first = ok
		row = bb
	}
	// The buttons sit a little apart from what they answer.
	col.Add(widgets.NewColumn(row).WithPadding(0, 14, 0, 0))
	return col, row, first
}

func (d *dialog) button(id, text string, onClick func()) *widgets.Button {
	b := widgets.NewButton(text, onClick)
	d.buttons[id] = b
	return b
}

// submit takes the passphrase (OK, or Enter in a field; from is the
// field, or nil for the button). A new passphrase is typed twice: Enter
// in the first field moves on to the second while that is empty, and
// the two must match before either goes anywhere.
func (d *dialog) submit(from *widgets.SecretField) {
	if d.done {
		return
	}
	if d.repeat == nil {
		d.finish(answer{secret: d.pin.Bytes()})
		return
	}
	if from == d.pin && d.repeat.Empty() {
		d.win.RequestFocus(d.repeat)
		return
	}
	first, second := d.pin.Bytes(), d.repeat.Bytes()
	same := subtle.ConstantTimeCompare(first, second) == 1
	uitoolkit.WipeBytes(second)
	if !same {
		uitoolkit.WipeBytes(first)
		d.repeat.Wipe()
		d.problem.SetText(orDefault(d.req.RepeatError, "The two entries do not match."))
		d.win.RequestFocus(d.repeat)
		return
	}
	d.finish(answer{secret: first})
}

// cancel is Escape, the Cancel button and the window's close button.
func (d *dialog) cancel() {
	switch d.kind {
	case askConfirm:
		d.finish(answer{choice: "cancel"})
	case askMessage:
		// A message has nothing to refuse: dismissing it is reading it.
		d.finish(answer{})
	default:
		d.finish(answer{err: svprompt.ErrCanceled})
	}
}

// fail ends a dialog that could not be answered: it could not be shown,
// or its window went away without an answer. It is a no-op on a dialog
// that has been answered.
func (d *dialog) fail(err error) { d.finish(answer{err: err}) }

// finish ends the dialog with a, once: the keyboard is let go, the fields
// are wiped, the window closes, and then the answer goes to whoever asked.
// A second answer (a timeout racing a click) is dropped, and wiped.
func (d *dialog) finish(a answer) {
	if d.done {
		uitoolkit.WipeBytes(a.secret)
		return
	}
	d.done = true
	if d.stop != nil {
		d.stop()
	}
	if d.frame != nil {
		d.frame.Release()
	}
	for _, f := range []*widgets.SecretField{d.pin, d.repeat} {
		if f != nil {
			f.Wipe()
		}
	}
	if d.win != nil {
		d.win.Close()
	}
	d.answer <- a
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
