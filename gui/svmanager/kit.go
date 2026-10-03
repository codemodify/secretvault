package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svqr"
)

// The parts every dialog and page here is made of: a form that says what
// went wrong where it was filled in, a report to read and copy, a plan to
// read before it is carried out, secrets shown once, and a QR code.
//
// Each operation is the daemon's (through the client) or svops's: what is
// here only asks for its inputs and shows its results.

// work runs fn, local work that may take a while (reading a file, running
// a program), off the interface's goroutine, and hands its error to then
// on it. It is call for what does not need the daemon.
func (m *Manager) work(fn func() error, then func(error)) {
	m.busy++
	m.drawStatus()
	go func() {
		err := fn()
		m.post(func() {
			m.busy--
			then(err)
			m.drawStatus()
		})
	}()
}

// formDialog is a dialog that asks for something: a form, notes under it,
// and the problem with what was given, said under them while the dialog
// stays up, with everything typed still there. Its secret fields are
// wiped when it closes, whichever way it goes.
type formDialog struct {
	m       *Manager
	title   string
	d       *dialog
	form    *widgets.Form
	body    *widgets.FlexBox
	problem *widgets.Label
	accept  *widgets.Button
	secrets []*widgets.SecretField
	areas   []*widgets.SecretArea
	closers []func()
	caps    bool // a new passphrase is typed: Caps Lock is said beside the buttons
	first   widget.Component
	running bool
	failed  func()    // what the dialog does when what it asked for fails
	adding  *formPart // what is being added goes in this part too (part)
	back    func()    // a Back button closes the dialog and runs it (the step before)
}

// formPart is what one choice in a dialog adds to it: rows of the form,
// and lines under it, shown or hidden together (showPart).
type formPart struct {
	rows  []*widgets.FormRow
	lines []widget.Component
}

// part runs add, and gathers what it adds to the dialog into a part.
func (f *formDialog) part(add func()) *formPart {
	p := &formPart{}
	f.adding = p
	add()
	f.adding = nil
	return p
}

// showPart shows the part of parts at i, and hides the others: a hidden
// row of the form takes no room, and leaves no gap (uitoolkit-gaps.md,
// 38 and 45).
func (f *formDialog) showPart(parts []*formPart, i int) {
	for j, p := range parts {
		for _, r := range p.rows {
			r.SetVisible(j == i)
		}
		for _, l := range p.lines {
			l.SetVisible(j == i)
		}
	}
	f.body.RequestLayout()
}

// addRow adds a row to the form.
func (f *formDialog) addRow(label string, c widget.Component) {
	r := f.form.Row(label, c)
	if f.adding != nil {
		f.adding.rows = append(f.adding.rows, r)
	}
}

// addLine adds a line under the form.
func (f *formDialog) addLine(c widget.Component) {
	f.body.Add(c)
	if f.adding != nil {
		f.adding.lines = append(f.adding.lines, c)
	}
}

// newForm starts a dialog of title.
func (m *Manager) newForm(title string) *formDialog {
	f := &formDialog{m: m, title: title, form: widgets.NewForm()}
	f.problem = toned("", widgets.ToneDanger)
	f.problem.Wrap = true
	f.body = widgets.NewColumn(f.form).WithGap(gap)
	return f
}

// head puts c above the form: what to read before filling it in. It
// goes in before any line under the form.
func (f *formDialog) head(c widget.Component) {
	f.body.ClearChildren()
	f.body.Add(c)
	f.body.Add(f.form)
}

// focusFirst remembers the first field, for the keyboard to start in.
func (f *formDialog) focusFirst(c widget.Component) {
	if f.first == nil {
		f.first = c
	}
}

// text adds a line of text.
func (f *formDialog) text(label, value, placeholder string) *widgets.TextField {
	t := widgets.NewTextField(value, placeholder, nil)
	t.SetAccessibleName(label)
	f.addRow(label, t)
	f.focusFirst(t)
	return t
}

// secret adds a field for a secret, wiped when the dialog closes.
func (f *formDialog) secret(label, placeholder string) *widgets.SecretField {
	s := widgets.NewSecretField(placeholder)
	s.SetAccessibleName(label)
	f.addRow(label, s)
	f.secrets = append(f.secrets, s)
	f.caps = true
	f.focusFirst(s)
	return s
}

// newPassphrase adds a new passphrase and its repetition, and returns
// what takes it: the passphrase, for the caller to wipe, or false when it
// is too short or the two differ, which is said in the dialog (and both
// fields are emptied).
func (f *formDialog) newPassphrase(label string) func() ([]byte, bool) {
	return f.newPassphraseMin(label, minPassphrase)
}

// newPassphraseMin is newPassphrase for one at least least characters
// long (a file's own passphrase is as long as its owner likes, as the CLI
// takes it).
func (f *formDialog) newPassphraseMin(label string, least int) func() ([]byte, bool) {
	least = max(1, least)
	hint := fmt.Sprintf("At least %d characters", least)
	if least == 1 {
		hint = ""
	}
	pass := f.secret(label, hint)
	again := f.secret("Repeat", "The same again")
	pass.OnSubmit = func(*widgets.SecretField) { f.m.win.RequestFocus(again) }
	return func() ([]byte, bool) {
		if pass.Len() < least {
			f.fail(fmt.Sprintf("Use a passphrase of at least %d characters.", least))
			f.m.win.RequestFocus(pass)
			return nil, false
		}
		p, a := pass.Bytes(), again.Bytes()
		same := bytes.Equal(p, a)
		clear(a)
		if !same {
			clear(p)
			pass.Wipe()
			again.Wipe()
			f.fail("The two passphrases differ.")
			f.m.win.RequestFocus(pass)
			return nil, false
		}
		return p, true
	}
}

// secretArea adds a field for a secret of several lines (a key pasted),
// wiped when the dialog closes.
func (f *formDialog) secretArea(label, placeholder string) *widgets.SecretArea {
	s := widgets.NewSecretArea(placeholder)
	s.SetAccessibleName(label)
	f.addRow(label, s)
	f.areas = append(f.areas, s)
	f.focusFirst(s)
	return s
}

// choice adds a drop-down list.
func (f *formDialog) choice(label string, items []string, selected int) *widgets.ComboBox {
	c := widgets.NewComboBox(items, selected, nil)
	c.SetAccessibleName(label)
	f.addRow(label, c)
	f.focusFirst(c)
	return c
}

// check adds a checkbox under the form.
func (f *formDialog) check(text string, on bool) *widgets.Checkbox {
	c := widgets.NewCheckbox(text, on, nil)
	f.addLine(c)
	return c
}

// row adds a field of any kind to the form.
func (f *formDialog) row(label string, c widget.Component) {
	f.addRow(label, c)
	f.focusFirst(c)
}

// note adds a muted, wrapped line under the form.
func (f *formDialog) note(text string) *widgets.Label {
	l := f.m.muted(text)
	l.Wrap = true
	f.addLine(l)
	return l
}

// warn adds a warning under the form.
func (f *formDialog) warn(text string) *widgets.Label {
	l := toned(text, widgets.ToneWarning)
	l.Wrap = true
	f.addLine(l)
	return l
}

// path adds a file's path, typed or chosen.
func (f *formDialog) path(label string, mode PickMode, suggested string) *pathField {
	p := newPathField(f.m, label, mode, suggested)
	f.addRow(label, p.row)
	f.focusFirst(p.field)
	return p
}

// onClose runs fn when the dialog closes, after its fields are wiped.
func (f *formDialog) onClose(fn func()) { f.closers = append(f.closers, fn) }

// show puts the dialog up, with an accept button that calls accept.
func (f *formDialog) show(acceptLabel string, accept func()) *formDialog {
	f.body.Add(f.problem)
	// While what it asked for runs, its button is greyed, and Enter in a
	// field does nothing either: a secret is not taken twice.
	run := func() {
		if !f.running && accept != nil {
			accept()
		}
	}
	f.accept = widgets.NewButton(acceptLabel, run)
	cancel := widgets.NewButton("Cancel", func() { f.close() })
	buttons := widgets.NewButtonBox().AddButton(f.accept, widgets.RoleAccept).AddButton(cancel, widgets.RoleReject)
	if f.back != nil {
		// Back to the step before, at the far left in every look, where
		// an assistant's Back goes; what was typed here is wiped.
		back := f.back
		buttons.AddButton(widgets.NewButton("Back", func() {
			f.close()
			back()
		}), widgets.RoleHelp)
	}
	var foot widget.Component = buttons
	if f.caps {
		// A secret typed with Caps Lock on would be a different one.
		row := widgets.NewRow(secretui.NewCapsLock(), buttons).WithGap(16).WithAlign(layout.AlignCenter)
		row.AddFlex(buttons, 1)
		foot = row
	}
	focus := f.first
	if focus == nil {
		focus = f.accept
	}
	for _, s := range f.secrets {
		if s.OnSubmit == nil {
			s.OnSubmit = func(*widgets.SecretField) { run() }
		}
	}
	f.d = f.m.showDialog(f.title, f.body, foot, focus, func() {
		f.wipe()
		for _, fn := range f.closers {
			fn()
		}
	})
	return f
}

// wipe empties every secret field.
func (f *formDialog) wipe() {
	for _, s := range f.secrets {
		s.Wipe()
	}
	for _, a := range f.areas {
		a.Wipe()
	}
}

// fail says what is wrong, under the form, with the dialog still up.
func (f *formDialog) fail(text string) {
	f.problem.SetText(text)
	f.problem.RequestLayout()
}

// close takes the dialog down.
func (f *formDialog) close() { f.d.Close() }

// closed reports whether the dialog has gone.
func (f *formDialog) closed() bool { return f.d == nil || f.d.closed }

// call runs fn against the daemon with the dialog up and its button
// greyed; an error is said in the dialog, which stays, and success
// closes it and calls done. sent are wiped once fn is done.
func (f *formDialog) call(fn func(ctx context.Context, c *secretvault.Client) error, done func(), sent ...[]byte) {
	if f.running {
		for _, b := range sent {
			clear(b)
		}
		return
	}
	f.running = true
	f.accept.SetEnabled(false)
	f.fail("")
	f.m.call(fn, func(err error) {
		f.after(err, done)
	}, sent...)
}

// work is call for local work.
func (f *formDialog) work(fn func() error, done func()) {
	if f.running {
		return
	}
	f.running = true
	f.accept.SetEnabled(false)
	f.fail("")
	f.m.work(fn, func(err error) { f.after(err, done) })
}

func (f *formDialog) after(err error, done func()) {
	f.running = false
	if f.closed() {
		// Taken down meanwhile: what it asked for went ahead all the
		// same, so say how it went.
		if err != nil {
			f.m.fail(err)
		} else if done != nil {
			done()
		}
		return
	}
	f.accept.SetEnabled(true)
	if err != nil {
		f.fail(f.m.describe(err))
		if f.failed != nil {
			f.failed()
		}
		return
	}
	f.close()
	if done != nil {
		done()
	}
}

// replacing runs do once the person has said a file that is at path may
// be replaced (a path typed, rather than chosen in the file dialog, which
// asks itself); at once when nothing is there.
func (m *Manager) replacing(path string, do func()) {
	if _, err := os.Lstat(path); err != nil {
		do()
		return
	}
	m.confirm("Replace "+filepath.Base(path)+"?", path+" is there already.\n\nReplace it?", "Replace", do)
}

// pathField is a path, typed or chosen with the file dialog.
type pathField struct {
	field *widgets.TextField
	row   *widgets.FlexBox
}

func newPathField(m *Manager, label string, mode PickMode, suggested string) *pathField {
	p := &pathField{field: widgets.NewTextField("", pathPlaceholder(mode), nil)}
	p.field.SetAccessibleName(label)
	choose := widgets.NewButton("Choose…", func() {
		m.pickFile(mode, suggested, func(path string) {
			if path != "" {
				p.field.SetText(path)
			}
		})
	})
	choose.SetAccessibleName("Choose " + strings.ToLower(label))
	p.row = widgets.NewRow(p.field, choose).WithGap(gap).WithAlign(layout.AlignCenter)
	p.row.AddFlex(p.field, 1)
	return p
}

func pathPlaceholder(mode PickMode) string {
	switch mode {
	case PickFolder:
		return "A folder"
	case PickSave:
		return "Where to save it"
	}
	return "A file"
}

// Path is the path given, trimmed.
func (p *pathField) Path() string { return strings.TrimSpace(p.field.Text) }

// showText shows text to read, select and copy: a report, a public key,
// a recipient. Nothing secret goes here: the text becomes a string.
func (m *Manager) showText(title, intro, text string) {
	m.showTextWith(title, intro, text, nil, nil)
}

// showTextWith is showText with below under the text (a QR code of it),
// and onClose run when the dialog closes.
func (m *Manager) showTextWith(title, intro, text string, below widget.Component, onClose func()) {
	col := widgets.NewColumn().WithGap(12)
	if intro != "" {
		l := widgets.NewLabel(intro)
		l.Wrap = true
		col.Add(l)
	}
	view := widgets.NewMonoTextView(text, "")
	view.SetAccessibleName(title)
	view.MinRows = min(max(strings.Count(text, "\n")+1, 2), 16)
	col.Add(view)
	if below != nil {
		col.Add(below)
	}
	var d *dialog
	ok := widgets.NewButton("Close", func() { d.Close() })
	buttons := widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept)
	if text != "" {
		buttons.AddButton(widgets.NewButton("Copy", func() { m.copyValue([]byte(text), title, "") }), widgets.RoleAction)
	}
	d = m.showDialog(title, col, buttons, ok, onClose)
}

// showPlan shows what an operation would change, as the CLI's --dry-run
// does, and carries it out only if the person says so; cancel runs when
// they do not (a plan that holds something to give back).
func (m *Manager) showPlan(title, intro string, lines []string, action string, apply, cancel func()) {
	col := widgets.NewColumn().WithGap(12)
	l := widgets.NewLabel(intro)
	l.Wrap = true
	col.Add(l)
	if len(lines) > 0 {
		view := widgets.NewMonoTextView(strings.Join(lines, "\n"), "")
		view.SetAccessibleName("The plan")
		view.MinRows = min(max(len(lines), 2), 14)
		col.Add(view)
	}
	var d *dialog
	applied := false
	yes := widgets.NewButton(action, func() {
		applied = true
		d.Close()
		apply()
	})
	no := widgets.NewButton("Cancel", func() { d.Close() })
	no.Primary = true
	buttons := widgets.NewButtonBox().AddButton(yes, widgets.RoleAccept).AddButton(no, widgets.RoleReject)
	d = m.showDialog(title, col, buttons, no, func() {
		if !applied && cancel != nil {
			cancel()
		}
	})
}

// secretShown is one secret in a dialog that shows it once.
type secretShown struct {
	label string
	value []byte
}

// showSecrets shows secrets once: a recovery key, its shares, an invite.
// Each is drawn from its bytes, copied from them, and wiped when the
// dialog closes, and so when the program quits; withQR draws the first as
// a QR code as well, under them, for another device to scan. They are
// kept nowhere else, here or in the daemon. A dialog too tall for the
// window scrolls, its buttons in view (uitoolkit-gaps.md, 40).
func (m *Manager) showSecrets(title, note string, secrets []secretShown, withQR bool, doneLabel string) *dialog {
	col := widgets.NewColumn().WithGap(12)
	nl := widgets.NewLabel(note)
	nl.Wrap = true
	col.Add(nl)
	var texts []*secretText
	list := widgets.NewColumn().WithGap(8)
	for _, s := range secrets {
		t := newSecretText(s.value)
		t.wrap = true
		t.SetReveal(true)
		t.SetAccessibleName(s.label)
		texts = append(texts, t)
		value, label := s.value, s.label
		spacer := widgets.NewSpacer()
		head := widgets.NewRow(m.muted(s.label), spacer,
			widgets.NewButton("Copy", func() { m.copyValue(value, label, "") })).WithGap(gap).WithAlign(layout.AlignCenter)
		head.AddFlex(spacer, 1)
		list.Add(head)
		list.Add(t)
	}
	col.Add(list)
	var code *qrView
	if withQR && len(secrets) > 0 {
		var qr widget.Component
		if qr, code = m.qrCode(secrets[0].label, secrets[0].value,
			"Or scan it with the other device's camera. It holds the same as the text: keep it as private."); qr != nil {
			col.Add(qr)
		}
	}
	if doneLabel == "" {
		doneLabel = "Done"
	}
	var d *dialog
	done := widgets.NewButton(doneLabel, func() { d.Close() })
	d = m.showDialog(title, col, widgets.NewButtonBox().AddButton(done, widgets.RoleAccept), done, func() {
		code.forget() // it was made from these bytes
		for _, t := range texts {
			t.Forget()
		}
		for _, s := range secrets {
			clear(s.value)
		}
	})
	return d
}

// qrCode is value as a QR code, for another device to scan, under a line
// that says so; forget wipes the code. Nothing (said) when value does not
// fit a code; value stays its caller's.
func (m *Manager) qrCode(label string, value []byte, note string) (widget.Component, *qrView) {
	c, err := svqr.Encode(value, svqr.M)
	if err != nil {
		m.fail(err)
		return nil, nil
	}
	code := newQRView(c)
	code.SetAccessibleName("QR code of the " + strings.ToLower(label))
	return widgets.NewColumn(m.paragraph(note), widgets.NewRow(code).WithJustify(layout.JustifyCenter)).WithGap(12), code
}

// qrView draws a QR code from its modules, dark on light whatever the
// look, with the quiet zone round it a scanner needs. It holds the code;
// forget wipes it.
type qrView struct {
	widget.Base
	code *svqr.Code
}

// qrModule is how big a module is drawn, in the look's 1x pixels.
const qrModule = 4

func newQRView(c *svqr.Code) *qrView {
	q := &qrView{code: c}
	q.Init(q)
	return q
}

func (q *qrView) side() float32 {
	if q.code == nil {
		return 0
	}
	return float32(q.code.Size+8) * qrModule
}

func (q *qrView) Measure(c layout.Constraints) paintengine2d.Point {
	s := q.side()
	return c.Constrain(paintengine2d.Pt(s, s))
}

func (q *qrView) Arrange(r paintengine2d.Rect) { q.SetBounds(r) }

func (q *qrView) Paint(ctx *paintengine2d.Context) {
	if q.code == nil {
		return
	}
	b := q.LocalBounds()
	s := min(b.Dx(), b.Dy())
	cell := s / float32(q.code.Size+8)
	ctx.DrawRect(paintengine2d.XYWH(b.Min.X, b.Min.Y, s, s), paintengine2d.Fill(paintengine2d.RGB(1, 1, 1)))
	dark := paintengine2d.Fill(paintengine2d.RGB(0, 0, 0))
	for y := range q.code.Size {
		for x := range q.code.Size {
			if q.code.Dark(x, y) {
				ctx.DrawRect(paintengine2d.XYWH(b.Min.X+float32(x+4)*cell, b.Min.Y+float32(y+4)*cell, cell+0.5, cell+0.5), dark)
			}
		}
	}
}

// Describe says what it is, and nothing of what it holds.
func (q *qrView) Describe(n *a11y.Node) {
	n.Role = a11y.RoleImage
	n.Description = "a QR code, to scan with the other device's camera"
}

// forget wipes the code and draws nothing.
func (q *qrView) forget() {
	if q == nil {
		return
	}
	if q.code != nil {
		q.code.Wipe()
		q.code = nil
	}
	q.Invalidate()
}

// table is a table of rows, with an accessible name, filled by cell.
func table(name string, cols []widgets.TableColumn, rows int, cell func(row, col int) string) *widgets.TableView {
	t := widgets.NewTableView(cols, rows, func(r, c int) string {
		if r < 0 || r >= rows {
			return ""
		}
		return cell(r, c)
	}, nil)
	t.SetAccessibleName(name)
	if rows > 0 {
		t.Selected = 0
	}
	return t
}

// selected is the row selected in t, or -1 when none is (or t is nil).
func selected(t *widgets.TableView) int {
	if t == nil || t.Selected < 0 || t.Selected >= t.RowCount {
		return -1
	}
	return t.Selected
}

// facts lays out pairs of name and value, a row each.
func (m *Manager) facts(rows [][2]string) *widgets.Grid {
	g := widgets.NewGrid()
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
	g.ColGap = 16
	for i, r := range rows {
		g.Place(m.muted(r[0]), i, 0)
		v := widgets.NewLabel(r[1])
		v.Wrap = true
		v.SetAccessibleName(r[0] + ": " + r[1])
		g.Place(v, i, 1)
	}
	return g
}

// buttons is a row of buttons that wraps when the pane is narrow.
func buttons(bs ...*widgets.Button) *widgets.Wrap {
	w := widgets.NewWrap()
	for _, b := range bs {
		w.Add(b)
	}
	return w
}

// paragraph is a wrapped, muted note.
func (m *Manager) paragraph(text string) *widgets.Label {
	l := m.muted(text)
	l.Wrap = true
	return l
}
