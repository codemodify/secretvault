package svtui

import (
	"context"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Dialogs and panels: questions, history, grants, the audit log.

// confirm asks before doing something that cannot be taken back. y, or
// the action's button, does it; n, Escape or Cancel does not.
func (u *UI) confirm(title, text, action string, do func()) {
	u.confirmWith(title, text, "Cancel", action, do)
}

// confirmWith is confirm with its own word for not doing it ("Keep it").
func (u *UI) confirmWith(title, text, cancel, action string, do func()) {
	m := tview.NewModal().SetText(text).AddButtons([]string{cancel, action})
	m.SetTitle(" " + tview.Escape(title) + " ")
	m.SetDoneFunc(func(_ int, label string) {
		u.closePage(pageDialog)
		if label == action {
			do()
		}
	})
	m.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case 'y', 'Y':
			u.closePage(pageDialog)
			do()
			return nil
		case 'n', 'N':
			u.closePage(pageDialog)
			return nil
		}
		return ev
	})
	u.openDialog(m, m, nil)
}

// ask asks for one line of text; its button says Continue. askTo names
// what the button does.
func (u *UI) ask(title, label, value string, done func(string)) {
	u.askTo(title, label, value, "Continue", done)
}

// askTo asks for one line of text, with a button that says what it does
// ("Rename").
func (u *UI) askTo(title, label, value, action string, done func(string)) {
	form := tview.NewForm()
	field := tview.NewInputField().SetLabel(label).SetText(value)
	form.AddFormItem(field)
	ok := func() {
		text := strings.TrimSpace(field.GetText())
		u.closePage(pageDialog)
		if text != "" {
			done(text)
		}
	}
	field.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEnter {
			ok()
			return nil
		}
		return ev
	})
	form.AddButton(action, ok).AddButton("Cancel", func() { u.closePage(pageDialog) })
	form.SetCancelFunc(func() { u.closePage(pageDialog) })
	form.SetBorder(true).SetTitle(" " + tview.Escape(title) + " ")
	u.openDialog(centred(form, 64, 7), form, nil)
}

// table makes a panel table with a header row.
func table(title string, header ...string) *tview.Table {
	t := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	t.SetBorder(true).SetTitle(title)
	for i, h := range header {
		t.SetCell(0, i, tview.NewTableCell(h).SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))
	}
	return t
}

func (u *UI) closeHistory() {
	u.closePage(pageRev)
	u.closePage(pagePanel)
	u.wipeHistory()
}

// wipeHistory forgets the history panel's revisions, wiping them.
func (u *UI) wipeHistory() {
	for i := range u.history {
		wipeItem(&u.history[i].Item)
	}
	u.history, u.revision = nil, nil
}

// revisionView is one revision, shown read-only over the history.
type revisionView struct {
	view   *detailView
	entry  *svrpc.Entry
	reveal bool
}

func (u *UI) showRevision(name string, e *svrpc.Entry) {
	rv := &revisionView{view: newDetailView(), entry: e}
	draw := func() {
		keys := otpKeys(&e.Item)
		rv.view.setRows(itemRows(e, rv.reveal, keys, u.now()))
		for _, k := range keys {
			k.Wipe()
		}
	}
	draw()
	rv.view.SetBorder(true).SetTitle(" " + tview.Escape(name) + " · revision " + short(e.Rev) + " (read-only) — r reveals · c copies · Esc goes back ")
	rv.view.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyEscape || ev.Rune() == 'q':
			u.revision = nil
			u.closePage(pageRev)
		case ev.Rune() == 'r':
			rv.reveal = !rv.reveal
			draw()
		case ev.Rune() == 'c':
			if i := rv.view.selectedField(); i >= 0 && i < len(e.Item.Fields) && !svops.PasskeyHidden(&e.Item, e.Item.Fields[i]) {
				u.copyValue(e.Item.Fields[i].Value)
			} else if f, ok := secretField(&e.Item); ok {
				u.copyValue(f.Value)
			} else {
				u.say("This revision has no secret to copy.")
			}
		default:
			return ev
		}
		return nil
	})
	u.revision = rv
	u.openPage(pageRev, inset(rv.view), rv.view)
}

// showGrants lists the programs with a remembered decision about the
// shown vault ('secretvault grant ls'): a allows a program and n denies
// one ahead of time ('grant allow', 'grant deny'); x (or Delete) revokes
// the one selected ('grant revoke').
func (u *UI) showGrants() {
	vault := u.vault
	if vault == "" {
		return
	}
	p := u.newPanel("Grants · "+vault, "DECISION", "PROGRAM", "ITEM", "MAY", "SINCE")
	p.vault = vault
	p.reload = func() {
		var grants []svrpc.Grant
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			grants, err = c.Grants(ctx, vault)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			p.setHead("")
			if len(grants) == 0 {
				p.setHead(svops.GrantsEmpty)
				p.none("None yet.")
			}
			for _, g := range grants {
				item := g.Item
				if item == "" {
					item = "(the whole vault)"
				}
				colour := "green"
				if strings.HasPrefix(g.Decision, "deny") {
					colour = "red"
				}
				p.row(g, tagged("["+colour+"]"+tview.Escape(svops.DecisionText(g.Decision))+"[-]"), g.Program, item, strings.Join(g.Ops, ","), g.Created.Local().Format("2006-01-02 15:04"))
			}
			p.done()
		})
	}
	p.rowAct('x', "Forget the decision…", is[svrpc.Grant], func(ref any) {
		g := ref.(svrpc.Grant)
		u.confirm(svops.RevokeGrantTitle, svops.RevokeGrantText(g), svops.RevokeGrantAction, func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.Revoke(ctx, vault, g.ID)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Forgot the decision about %s", g.Program)
				p.refresh()
			})
		})
	})
	p.act('a', "Allow a program…", func() { u.decideProgram(vault, true, p.refresh) })
	p.act('n', "Deny a program…", func() { u.decideProgram(vault, false, p.refresh) })
	p.show()
}

// showAudit shows the newest entries of the shown vault's audit log.
func (u *UI) showAudit() {
	vault := u.vault
	if vault == "" {
		return
	}
	var entries []svrpc.AuditEntry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.Audit(ctx, vault, 500)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		t := table(" Audit log · "+tview.Escape(vault)+" — Esc closes ", "WHEN", "OUTCOME", "WHAT", "PROGRAM", "WHY")
		if len(entries) == 0 {
			t.SetCell(1, 0, tview.NewTableCell("Nothing has been recorded yet.").SetTextColor(tcell.ColorGray))
		}
		for i, e := range entries {
			row := i + 1
			if e.Outcome == "log-damaged" {
				t.SetCell(row, 0, tview.NewTableCell("!! "+tview.Escape(e.Reason)).SetTextColor(tcell.ColorRed))
				continue
			}
			colour := tcell.ColorGreen
			switch e.Outcome {
			case "denied", "failed":
				colour = tcell.ColorRed
			case "canceled":
				colour = tcell.ColorYellow
			}
			t.SetCell(row, 0, tview.NewTableCell(e.Time.Local().Format("2006-01-02 15:04:05")))
			t.SetCell(row, 1, tview.NewTableCell(e.Outcome).SetTextColor(colour))
			t.SetCell(row, 2, tview.NewTableCell(tview.Escape(strings.TrimSpace(e.Op+" "+e.Item))))
			t.SetCell(row, 3, tview.NewTableCell(tview.Escape(e.Program)).SetMaxWidth(40))
			t.SetCell(row, 4, tview.NewTableCell(tview.Escape(e.Reason)))
		}
		if n := t.GetRowCount(); n > 1 {
			t.Select(n-1, 0)
		}
		t.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			if ev.Key() == tcell.KeyEscape || ev.Rune() == 'q' {
				u.closePage(pagePanel)
				return nil
			}
			return ev
		})
		u.openPage(pagePanel, t, t)
	})
}
