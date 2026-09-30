package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svrpc"
)

// The daemon's questions. secretvaultd treats this program as it treats
// the CLI: when it needs to know the person is there (to unlock a vault,
// or to allow this program to use one), it asks for the vault's passphrase
// through prompt.ask, and the question is put here, in a dialog window of
// its own, above the others and centred, whether or not the main window
// is showing: secretui's, which secretvault-gui-prompt asks in too. While
// the passphrase field has the keyboard the window holds it where the
// platform allows (uitoolkit's SetSecureInput), and it stays out of
// screenshots where the platform allows (SetExcludeFromCapture). The passphrase is typed
// into a SecretField, whose contents never become a string, and wiped as
// soon as it is sent.

// promptDialog is the question on the screen.
type promptDialog struct {
	id       int
	win      *app.Window
	frame    *secretui.Frame
	fields   []*widgets.SecretField
	problem  *widgets.Label
	caps     *secretui.CapsLock      // beside the buttons while Caps Lock is on
	answer   chan svrpc.PromptAnswer // buffered: one answer
	answered bool
}

// prompt answers prompt.ask. It runs on the connection's goroutine, puts
// the question up, and waits for the person, the daemon giving up, or the
// program quitting.
func (m *Manager) prompt(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
	switch q.Kind {
	case svrpc.PromptPassphrase, svrpc.PromptNewPassphrase:
	case svrpc.PromptChoose:
		// Not asked of secretvault's own programs today; answered all
		// the same.
		if len(q.Choices) == 0 {
			return svrpc.PromptAnswer{Canceled: true}, nil
		}
	default:
		return svrpc.PromptAnswer{Canceled: true}, nil
	}
	m.promptMu.Lock()
	defer m.promptMu.Unlock()
	answer := make(chan svrpc.PromptAnswer, 1)
	shown := make(chan int, 1)
	m.post(func() { shown <- m.showPrompt(q, answer) })
	select {
	case a := <-answer:
		return a, nil
	case <-ctx.Done():
	case <-m.done:
	}
	// Taken down on the interface's goroutine, and only then is the
	// channel emptied: an answer given meanwhile is wiped, not left in it.
	dropped := make(chan struct{})
	m.post(func() {
		select {
		case id := <-shown:
			m.dropPrompt(id)
		default:
		}
		close(dropped)
	})
	select {
	case <-dropped:
	case <-m.done: // shutdown has taken it down
	}
	select {
	case a := <-answer:
		clear(a.Secret)
	default:
	}
	return svrpc.PromptAnswer{Canceled: true}, nil
}

// promptWidth is the dialog's width, in logical pixels.
const promptWidth = 480

// showPrompt puts a question up and returns its number. It is asked in
// secretui's frame and window, as secretvault-gui-prompt asks its
// questions: the same header, and a dialog window that is centred, above
// the others, out of screen captures where the platform allows, and that
// holds the keyboard while the passphrase field has it.
func (m *Manager) showPrompt(q svrpc.PromptAsk, answer chan svrpc.PromptAnswer) int {
	if m.asking != nil {
		m.dropPrompt(m.asking.id)
	}
	m.promptN++
	d := &promptDialog{id: m.promptN, answer: answer}
	title := strings.TrimSpace(q.Title)
	if title == "" {
		title = "Passphrase"
	}
	m.asking = d

	finish := func(a svrpc.PromptAnswer) {
		if m.asking != d || d.answered {
			clear(a.Secret)
			return
		}
		d.answered = true
		m.dropPrompt(d.id)
		d.answer <- a
	}
	cancel := func() { finish(svrpc.PromptAnswer{Canceled: true}) }

	col := widgets.NewColumn().WithGap(10).WithPadding(20, 16, 20, 16)
	if text := strings.TrimSpace(q.Description); text != "" {
		desc := widgets.NewLabel(text)
		desc.Wrap = true
		col.Add(desc)
	}
	d.problem = toned(q.Error, widgets.ToneDanger)
	d.problem.Wrap = true
	buttons := widgets.NewButtonBox()
	var focus widget.Component
	// Left of the buttons: nothing, or for a passphrase, Caps Lock while
	// it is on.
	var left widget.Component = widgets.NewSpacer()

	switch q.Kind {
	case svrpc.PromptChoose:
		for _, c := range q.Choices {
			b := widgets.NewButton(c.Label, func() { finish(svrpc.PromptAnswer{Choice: c.ID}) })
			role := widgets.RoleAction
			if c.ID == svrpc.ChoiceDeny {
				role = widgets.RoleReject
			}
			buttons.AddButton(b, role)
			if focus == nil {
				focus = b
			}
		}
		col.Add(d.problem)
	default:
		first := widgets.NewSecretField("")
		first.SetAccessibleName(promptLabel(q.Prompt, "Passphrase"))
		d.fields = append(d.fields, first)
		form := widgets.NewForm()
		form.AddRow(promptLabel(q.Prompt, "Passphrase"), first)
		ok := widgets.NewButton("Unlock", nil)
		submit := func() {
			if first.Empty() {
				return
			}
			finish(svrpc.PromptAnswer{Secret: first.Bytes()})
		}
		if q.Kind == svrpc.PromptNewPassphrase {
			ok.Text = "OK"
			again := widgets.NewSecretField("")
			again.SetAccessibleName("Repeat")
			d.fields = append(d.fields, again)
			form.AddRow("Repeat", again)
			first.OnSubmit = func(*widgets.SecretField) { d.win.RequestFocus(again) }
			submit = func() {
				a, b := first.Bytes(), again.Bytes()
				defer clear(b)
				switch {
				case first.Len() < minPassphrase:
					d.problem.SetText(fmt.Sprintf("Use at least %d characters.", minPassphrase))
				case !bytes.Equal(a, b):
					d.problem.SetText("The two passphrases differ.")
				default:
					finish(svrpc.PromptAnswer{Secret: a})
					return
				}
				clear(a)
				first.Wipe()
				again.Wipe()
				d.win.RequestFocus(first)
			}
			again.OnSubmit = func(*widgets.SecretField) { submit() }
		} else {
			first.OnSubmit = func(*widgets.SecretField) { submit() }
		}
		for _, f := range d.fields {
			f.OnEscape = cancel
		}
		ok.OnClick = submit
		buttons.AddButton(ok, widgets.RoleAccept)
		buttons.AddButton(widgets.NewButton("Cancel", cancel), widgets.RoleReject)
		col.Add(form)
		col.Add(d.problem)
		focus = first
		d.caps = secretui.NewCapsLock()
		left = d.caps
	}
	row := widgets.NewRow(left, buttons).WithJustify(layout.JustifyEnd).WithAlign(layout.AlignCenter)
	row.AddFlex(left, 1)
	col.Add(row)

	d.frame = secretui.NewFrame(title, col)
	d.frame.OnEscape = cancel
	win, err := secretui.Open(m.app, secretui.Name+": "+title, promptWidth, d.frame)
	if err != nil {
		m.asking = nil
		d.answered = true
		answer <- svrpc.PromptAnswer{Canceled: true}
		return d.id
	}
	d.win = win
	win.SetInitialFocus(focus)
	win.SetOnCloseRequest(func() bool {
		cancel()
		return false // cancel has closed it already
	})
	win.RequestFocus(focus)
	return d.id
}

// dropPrompt takes question id down, wiping what was typed into it. A
// question still waiting is answered: canceled.
func (m *Manager) dropPrompt(id int) {
	d := m.asking
	if d == nil || d.id != id {
		return
	}
	for _, f := range d.fields {
		f.Wipe()
	}
	if !d.answered {
		d.answered = true
		d.answer <- svrpc.PromptAnswer{Canceled: true}
	}
	m.asking = nil
	if d.frame != nil {
		d.frame.Release()
	}
	if d.win != nil && !d.win.Closed() {
		d.win.Close()
	}
}

func promptLabel(prompt, fallback string) string {
	if p := strings.TrimSuffix(strings.TrimSpace(prompt), ":"); p != "" {
		return p
	}
	return fallback
}
