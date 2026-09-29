package svtui

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svrpc"
)

// The daemon's questions. secretvaultd treats this program as it treats
// the CLI: when it needs to know the person is there (to unlock a vault,
// or to allow this terminal to use one), it asks for the vault's
// passphrase through prompt.ask, and the question is put here, in a
// dialog over whatever is on the screen.

// minPassphrase is the shortest new passphrase accepted, as everywhere
// else in secretvault.
const minPassphrase = 8

// promptDialog is the question on the screen.
type promptDialog struct {
	id     int
	inputs []*secretInput
	answer chan<- svrpc.PromptAnswer
}

// prompt answers prompt.ask. It runs on the connection's goroutine, puts
// the question up, and waits for the person, the daemon giving up, or
// the program quitting.
func (u *UI) prompt(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
	switch q.Kind {
	case svrpc.PromptPassphrase, svrpc.PromptNewPassphrase:
	case svrpc.PromptChoose:
		// Not asked of terminal programs today; answered all the same.
		if len(q.Choices) == 0 {
			return svrpc.PromptAnswer{Canceled: true}, nil
		}
	default:
		return svrpc.PromptAnswer{Canceled: true}, nil
	}
	u.promptMu.Lock()
	defer u.promptMu.Unlock()
	answer := make(chan svrpc.PromptAnswer, 1)
	var id int
	u.post(func() { id = u.showPrompt(q, answer) })
	select {
	case a := <-answer:
		return a, nil
	case <-ctx.Done():
	case <-u.done:
	}
	u.post(func() { u.dropPrompt(id) })
	select {
	case a := <-answer:
		clear(a.Secret)
	default:
	}
	return svrpc.PromptAnswer{Canceled: true}, nil
}

// showPrompt puts a question up and returns its number.
func (u *UI) showPrompt(q svrpc.PromptAsk, answer chan<- svrpc.PromptAnswer) int {
	u.promptID++
	d := &promptDialog{id: u.promptID, answer: answer}
	const width = 72
	text := tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	lines := 0
	explain := func(problem string) {
		body := strings.TrimSpace(q.Description)
		if problem != "" {
			body += "\n\n! " + problem
		}
		lines = 0
		for _, l := range strings.Split(body, "\n") {
			lines += max(1, len(tview.WordWrap(l, width-4)))
		}
		out := tview.Escape(strings.TrimSpace(q.Description))
		if problem != "" {
			out += "\n\n[red]! " + tview.Escape(problem) + "[-]"
		}
		text.SetText(out)
	}
	explain(q.Error)
	room := lines
	if q.Kind == svrpc.PromptNewPassphrase && q.Error == "" {
		room += 2 // for saying the two did not match
	}

	finish := func(a svrpc.PromptAnswer) {
		if u.asking != d {
			clear(a.Secret)
			return
		}
		u.dropPrompt(d.id)
		d.answer <- a
	}
	cancel := func() { finish(svrpc.PromptAnswer{Canceled: true}) }

	var focus, body tview.Primitive
	height := 0
	switch q.Kind {
	case svrpc.PromptChoose:
		list := tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true)
		for _, c := range q.Choices {
			list.AddItem(tview.Escape(c.Label), "", 0, func() { finish(svrpc.PromptAnswer{Choice: c.ID}) })
		}
		list.SetDoneFunc(cancel)
		list.SetBorderPadding(1, 0, 1, 1)
		body, focus, height = list, list, len(q.Choices)+1
	default:
		form := tview.NewForm()
		form.SetBorderPadding(1, 0, 1, 1)
		first := newSecretInput(promptLabel(q.Prompt, "Passphrase:"))
		d.inputs = append(d.inputs, first)
		form.AddFormItem(first)
		submit := func() {
			if len(first.buf) == 0 {
				return
			}
			finish(svrpc.PromptAnswer{Secret: first.value()})
		}
		if q.Kind == svrpc.PromptNewPassphrase {
			first.label = promptLabel(q.Prompt, "New passphrase:")
			again := newSecretInput("Repeat:")
			d.inputs = append(d.inputs, again)
			form.AddFormItem(again)
			submit = func() {
				problem := ""
				switch {
				case len(first.buf) < minPassphrase:
					problem = fmt.Sprintf("Use at least %d characters.", minPassphrase)
				case !bytes.Equal(first.buf, again.buf):
					problem = "The two passphrases differ."
				default:
					finish(svrpc.PromptAnswer{Secret: first.value()})
					return
				}
				first.wipe()
				again.wipe()
				explain(problem)
				form.SetFocus(0)
				u.app.SetFocus(form)
			}
		}
		last := d.inputs[len(d.inputs)-1]
		last.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			if ev.Key() == tcell.KeyEnter {
				submit()
				return nil
			}
			return ev
		})
		form.AddButton("OK", submit).AddButton("Cancel", cancel)
		form.SetCancelFunc(cancel)
		body, focus, height = form, form, 2*len(d.inputs)+2
	}
	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(text, room, 0, false).
		AddItem(body, height, 0, true)
	frame.SetBorder(true).SetBorderPadding(0, 0, 1, 1).SetTitle(" " + tview.Escape(q.Title) + " ")
	u.asking = d
	u.openPage(pagePrompt, centred(frame, width, room+height+2), focus)
	return d.id
}

// dropPrompt takes question id down, wiping what was typed into it.
func (u *UI) dropPrompt(id int) {
	d := u.asking
	if d == nil || d.id != id {
		return
	}
	for _, in := range d.inputs {
		in.wipe()
	}
	u.asking = nil
	u.closePage(pagePrompt)
}

func promptLabel(prompt, fallback string) string {
	if p := strings.TrimSpace(prompt); p != "" {
		return tview.Escape(p)
	}
	return fallback
}

// centred puts a box of a fixed size in the middle of the screen.
func centred(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 0, true).
			AddItem(nil, 0, 1, false), width, 0, true).
		AddItem(nil, 0, 1, false)
}
