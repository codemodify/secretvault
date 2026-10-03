package svtui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svops"
)

// Asking before a change, in plain words first (docs/wording.md), as the
// GUI asks: the plan's summary and what else to know, its technical lines
// behind "Show details", and a button that says what it does. svops says
// all of it.

// showPlan asks before making the change p says, and does it only when
// the person says so. Nothing is done on Escape but cancelled, if given.
// A plan with nothing to do (no Action) is only shown.
func (u *UI) showPlan(p svops.Plain, do func(), cancelled ...func()) {
	body := plainText(p.Summary, p.Notes)
	details := ""
	if len(p.Details) > 0 {
		details = "\n\n[::b]Details[::-]\n" + lines(p.Details)
	}
	view := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true).SetWordWrap(true)
	view.SetText(body)
	buttons := tview.NewForm().SetButtonsAlign(tview.AlignCenter)
	buttons.SetBorderPadding(0, 0, 1, 1)
	// The padding is the text's and the buttons' own: a Flex does not clear
	// its own, and what is under the dialog would show through it.
	view.SetBorderPadding(0, 0, 1, 1)
	closed := false
	var id int
	cancel := func() {
		if !closed {
			closed = true
			u.closeDialog(id)
			for _, f := range cancelled {
				f()
			}
		}
	}
	const width = 78
	height := func(text string) int { return u.fit(wrappedLines(text, width-4) + 4) }
	column := tview.NewFlex().SetDirection(tview.FlexRow)
	frame := tview.NewFlex().SetDirection(tview.FlexRow)
	no := "Cancel"
	if p.Action == "" {
		no = "Close"
	}
	// Cancel, the action, then the details: Tab from the text reaches
	// Cancel, and the action is the next.
	buttons.AddButton(no, cancel)
	if p.Action != "" {
		buttons.AddButton(p.Action, func() {
			if !closed {
				closed = true
				u.closeDialog(id)
				do()
			}
		})
	}
	if details != "" {
		open := false
		buttons.AddButton("Show details", nil)
		b := buttons.GetButton(buttons.GetButtonCount() - 1)
		b.SetSelectedFunc(func() {
			open = !open
			text, label := body, "Show details"
			if open {
				text, label = body+details, "Hide details"
			}
			view.SetText(text)
			b.SetLabel(label)
			column.ResizeItem(frame, height(text), 0)
		})
	}
	buttons.SetCancelFunc(cancel)
	frame.AddItem(view, 0, 1, false).AddItem(buttons, 1, 0, true)
	frame.SetBorder(true).SetTitle(" " + tview.Escape(p.Title) + " — Tab: the buttons · Esc cancels ")
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
	column.AddItem(nil, 0, 1, false).AddItem(frame, height(body), 0, true).AddItem(nil, 0, 1, false)
	outer := tview.NewFlex().AddItem(nil, 0, 1, false).AddItem(column, width, 0, true).AddItem(nil, 0, 1, false)
	id = u.openDialog(outer, view, cancel)
}

// plainText is a summary over its notes, escaped, the notes in yellow.
func plainText(summary string, notes []string) string {
	text := tview.Escape(summary)
	for _, n := range notes {
		text += "\n\n[yellow]" + tview.Escape(n) + "[-]"
	}
	return text
}

// showDone says how a change went: what it means, then what was done,
// line by line.
func (u *UI) showDone(title, summary string, done []string) {
	text := tview.Escape(summary)
	if len(done) > 0 {
		text += "\n\n[::b]Details[::-]\n" + lines(done)
	}
	u.showText(title, text)
}

// failedText is an error said in red, under what was done before it.
func failedText(text string, err error) string {
	return strings.TrimSpace(text + "\n\n[red]" + tview.Escape(sentence(err.Error())) + "[-]")
}
