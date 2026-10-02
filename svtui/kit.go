package svtui

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// The pieces the panels and dialogs are made of: forms, plans to confirm,
// texts to read, choices. Every operation's dialog is one of these, so
// they all behave alike: Tab moves, Enter goes on, Escape cancels.

// More pages, over the ones in ui.go. Pages stack in the order they open;
// the daemon's prompts always go on top.
const (
	pageSub  = "subpanel" // a panel opened from a panel (a contact's keys)
	pageInfo = "info"     // a text to read: a report, a status, the help
	pageOnce = "once"     // something shown only once: a recovery key, an invite
)

// formDialog is a dialog of labelled fields over a line of buttons.
// Secrets are typed into secretInputs, wiped when the dialog closes.
type formDialog struct {
	u       *UI
	title   string
	intro   *tview.TextView
	introH  int
	form    *tview.Form
	heights []int
	secrets []*secretInput
	width   int
	closed  bool
	single  tview.FormItem // the only field, when there is one: Enter submits
	fields  int

	// onCancel runs when the dialog is cancelled rather than submitted.
	onCancel func()
}

// newForm starts a dialog. intro, if not "", is said above the fields.
func (u *UI) newForm(title, intro string) *formDialog {
	f := &formDialog{u: u, title: title, form: tview.NewForm(), width: 78}
	f.form.SetBorderPadding(1, 0, 1, 1)
	if intro != "" {
		f.intro = tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
		f.intro.SetText(intro)
		f.introH = wrappedLines(intro, f.width-4)
	}
	return f
}

// wrappedLines is how many lines text takes in width columns.
func wrappedLines(text string, width int) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		n += max(1, len(tview.WordWrap(l, width)))
	}
	return n
}

func (f *formDialog) add(item tview.FormItem, height int) {
	f.form.AddFormItem(item)
	f.heights = append(f.heights, height)
	f.fields++
	if f.fields == 1 {
		f.single = item
	} else {
		f.single = nil
	}
}

// text adds a line of text.
func (f *formDialog) text(label, value, placeholder string) *tview.InputField {
	in := tview.NewInputField().SetLabel(label).SetText(value).SetPlaceholder(placeholder)
	f.add(in, 1)
	return in
}

// path adds a file's path, completed as it is typed (Tab takes the first
// suggestion, ↓ chooses).
func (f *formDialog) path(label, value, placeholder string) *tview.InputField {
	in := f.text(label, value, placeholder)
	in.SetAutocompleteFunc(completePath)
	return in
}

// secret adds a masked field for a passphrase, a key or a share.
func (f *formDialog) secret(label string) *secretInput {
	s := newSecretInput(label)
	f.secrets = append(f.secrets, s)
	f.add(s, 1)
	return s
}

// choice adds a drop-down.
func (f *formDialog) choice(label string, options []string, current int) *tview.DropDown {
	d := tview.NewDropDown().SetLabel(label).SetOptions(options, nil).SetCurrentOption(current)
	f.add(d, 1)
	return d
}

// check adds a checkbox.
func (f *formDialog) check(label string, on bool) *tview.Checkbox {
	c := tview.NewCheckbox().SetLabel(label).SetChecked(on)
	f.add(c, 1)
	return c
}

// area adds text of several lines.
func (f *formDialog) area(label, value string, height int) *tview.TextArea {
	a := tview.NewTextArea().SetLabel(label).SetSize(height, 0)
	a.SetText(value, false)
	f.add(a, height)
	return a
}

// show puts the dialog up, with action's button. ok runs when it is
// pressed: when it returns a problem, the problem is said and the dialog
// stays; else the dialog closes, wiping what was typed. ok copies what
// it needs before it returns.
func (f *formDialog) show(action string, ok func() string) {
	u := f.u
	problem := tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	frame := tview.NewFlex().SetDirection(tview.FlexRow)
	if f.intro != nil {
		frame.AddItem(f.intro, f.introH, 0, false)
	}
	frame.AddItem(problem, 0, 0, false)
	submit := func() {
		if f.closed {
			return
		}
		if p := ok(); p != "" {
			problem.SetText("[red]" + tview.Escape(sentence(p)) + "[-]")
			frame.ResizeItem(problem, wrappedLines(p, f.width-4), 0)
			return
		}
		f.close()
	}
	if f.single != nil {
		if in, ok := f.single.(interface {
			SetInputCapture(func(*tcell.EventKey) *tcell.EventKey) *tview.Box
		}); ok {
			in.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
				if ev.Key() == tcell.KeyEnter {
					submit()
					return nil
				}
				return ev
			})
		}
	}
	f.form.AddButton(action, submit).AddButton("Cancel", f.cancel)
	f.form.SetCancelFunc(f.cancel)
	h := 0
	for _, x := range f.heights {
		h += x + 1
	}
	h += 2 // the buttons, and the space before them
	frame.AddItem(f.form, h, 0, true)
	frame.SetBorder(true).SetBorderPadding(0, 0, 1, 1).SetTitle(" " + tview.Escape(f.title) + " ")
	height := 2 + f.introH + h + 3 // the problem's room
	u.openPage(pageDialog, centred(frame, f.width, height), f.form)
}

// cancel takes the dialog down without doing anything.
func (f *formDialog) cancel() {
	if !f.closed && f.onCancel != nil {
		f.onCancel()
	}
	f.close()
}

// close takes the dialog down and wipes what was typed.
func (f *formDialog) close() {
	if f.closed {
		return
	}
	f.closed = true
	for _, s := range f.secrets {
		s.wipe()
	}
	f.u.closePage(pageDialog)
}

// trimmed is a text field, trimmed.
func trimmed(in *tview.InputField) string { return strings.TrimSpace(in.GetText()) }

// option is a drop-down's current option.
func option(d *tview.DropDown) string {
	_, s := d.GetCurrentOption()
	return s
}

// completePath suggests the files and folders that start with what was
// typed.
func completePath(text string) []string {
	if text == "" {
		return nil
	}
	expanded := expandHome(text)
	if _, err := os.Stat(expanded); err == nil && !strings.HasSuffix(expanded, string(filepath.Separator)) {
		return nil // it names something already
	}
	dir, base := filepath.Split(expanded)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), base) || (strings.HasPrefix(e.Name(), ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		s := text[:len(text)-len(base)] + e.Name()
		if e.IsDir() {
			s += string(filepath.Separator)
		}
		out = append(out, s)
		if len(out) == 50 {
			break
		}
	}
	sort.Strings(out)
	if len(out) == 1 && out[0] == text {
		return nil
	}
	return out
}

// expandHome turns a leading ~ into the home directory, as a shell would.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// filePath is what the person typed, as a path: ~ expanded.
func filePath(in *tview.InputField) string { return expandHome(trimmed(in)) }

// showText puts a scrollable text up until Escape.
func (u *UI) showText(title, body string) {
	view := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true).SetWordWrap(true)
	view.SetText(body)
	view.SetBorder(true).SetTitle(" " + tview.Escape(title) + " — Esc closes ")
	view.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyEnter || ev.Rune() == 'q' || ev.Rune() == '?' {
			u.closePage(pageInfo)
			return nil
		}
		return ev
	})
	u.openPage(pageInfo, inset(view), view)
}

// showPlan shows what an operation is about to do, and does it only when
// the person says so: the TUI's --dry-run. Nothing is done on Escape but
// cancelled, if given.
func (u *UI) showPlan(title, body, action string, do func(), cancelled ...func()) {
	view := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true).SetWordWrap(true)
	view.SetText(body)
	buttons := tview.NewForm().SetButtonsAlign(tview.AlignCenter)
	buttons.SetBorderPadding(0, 0, 0, 0)
	closed := false
	cancel := func() {
		if !closed {
			closed = true
			u.closePage(pageDialog)
			for _, f := range cancelled {
				f()
			}
		}
	}
	buttons.AddButton("Cancel", cancel).AddButton(action, func() {
		if !closed {
			closed = true
			u.closePage(pageDialog)
			do()
		}
	})
	buttons.SetCancelFunc(cancel)
	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(view, 0, 1, false).
		AddItem(buttons, 1, 0, true)
	frame.SetBorder(true).SetBorderPadding(0, 0, 1, 1).SetTitle(" " + tview.Escape(title) + " — ↑↓ scroll · Tab: " + action + " · Esc cancels ")
	view.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			cancel()
			return nil
		case tcell.KeyTab, tcell.KeyBacktab:
			u.app.SetFocus(buttons)
			return nil
		}
		return ev
	})
	buttons.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyUp || ev.Key() == tcell.KeyDown || ev.Key() == tcell.KeyPgUp || ev.Key() == tcell.KeyPgDn {
			u.app.SetFocus(view)
			return ev
		}
		return ev
	})
	height := min(wrappedLines(body, 70)+4, 30)
	u.openPage(pageDialog, centred(frame, 78, height), view)
}

// choose asks which of options; done gets its index.
func (u *UI) choose(title string, options []string, done func(int)) {
	list := tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true)
	for i, o := range options {
		list.AddItem(tview.Escape(o), "", 0, func() {
			u.closePage(pageDialog)
			done(i)
		})
	}
	list.SetDoneFunc(func() { u.closePage(pageDialog) })
	list.SetBorder(true).SetTitle(" " + tview.Escape(title) + " — Esc cancels ")
	width := len(title) + 20
	for _, o := range options {
		width = max(width, len(o)+6)
	}
	u.openPage(pageDialog, centred(list, min(width, 90), len(options)+2), list)
}

// yesNo is how the TUI writes a flag.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var colourTag = regexp.MustCompile(`\[[a-zA-Z0-9_,;:#.\-]*\]`)

// stripTags is text without its colour tags, to measure it.
func stripTags(text string) string { return colourTag.ReplaceAllString(text, "") }

// needVault says so when there is no vault to act on.
func (u *UI) needVault() bool {
	if u.vault == "" {
		u.say("There is no vault yet: N makes one.")
		return false
	}
	return true
}
