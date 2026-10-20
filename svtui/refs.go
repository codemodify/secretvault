package svtui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// References, sv://VAULT/ITEM[#FIELD], which 'read', 'run' and 'inject'
// resolve for other programs: copying an item's (y), seeing what one
// resolves to (masked until revealed), and checking an env file or a
// template, whose values are never shown; a template can be filled into
// a new file, as 'inject -o' does.

// copyReference copies the target item's reference, or the selected
// field's.
func (u *UI) copyReference() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	if u.cur != nil && u.cur.Item.Name == name && svops.IsPasskey(&u.cur.Item) {
		u.say("A passkey signs you in through the browser extension; there is no secret to refer to.")
		return
	}
	r := svrpc.Ref{Vault: u.vault, Item: name}
	if u.app.GetFocus() == u.detail && u.cur != nil && u.cur.Item.Name == name {
		if i := u.detail.selectedField(); i >= 0 && i < len(u.cur.Item.Fields) {
			r.Field = u.cur.Item.Fields[i].Name
		}
	}
	text := r.String()
	secret := []byte(text)
	u.call(func(context.Context, *secretvault.Client) error {
		_, err := u.clip(secret, clipTTL)
		return err
	}, func(err error) {
		if err != nil {
			u.message = "[red]Could not copy: " + tview.Escape(err.Error()) + "[-]"
			u.drawStatus()
			return
		}
		u.say("Copied %s", text)
	})
}

// resolveReference is 'secretvault read REF', for a person: the value,
// masked until revealed (r), copied with c.
func (u *UI) resolveReference() {
	f := u.newForm("Resolve a reference", svops.ResolveReferenceAbout)
	ref := f.text("Reference", "", "sv://-/example.com#password")
	f.show("Show what it names", func() string {
		r, err := svrpc.ParseRef(trimmed(ref))
		if err != nil {
			return err.Error()
		}
		var v []byte
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			v, err = svops.Resolve(ctx, c, r)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.showValue(r.String(), v)
		})
		return ""
	})
}

// showValue shows one secret value, masked until revealed, and wipes it
// when it closes.
func (u *UI) showValue(title string, v []byte) {
	view := newDetailView()
	reveal := false
	draw := func() {
		plain := tcell.StyleDefault.Foreground(tview.Styles.PrimaryTextColor)
		row := detailRow{label: "value", text: mask, style: plain, field: 0, note: fmt.Sprintf("%d bytes", len(v))}
		if reveal {
			row.text, row.secret = "", v
			if len(v) == 0 {
				row.text = " "
			}
		}
		view.setRows([]detailRow{row})
		view.selected = 0
	}
	draw()
	view.SetBorder(true).SetTitle(" " + tview.Escape(title) + " — r reveals · c copies · Esc closes ")
	view.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyEnter || ev.Rune() == 'q':
			view.reset("")
			u.wipeValue()
			u.closePage(pageInfo)
		case ev.Rune() == 'r':
			reveal = !reveal
			draw()
		case ev.Rune() == 'c':
			u.copyValue(v)
		default:
			return ev
		}
		return nil
	})
	u.wipeValue()
	u.value = v
	u.openPage(pageInfo, centred(view, 84, 5), view)
}

// wipeValue wipes the value showValue shows, if any.
func (u *UI) wipeValue() {
	clear(u.value)
	u.value = nil
}

// checkResult is one reference checked: whether it resolves, never what
// to.
type checkResult struct {
	where, ref string
	n          int
	err        error
}

// checkRefs resolves each reference, keeping only whether it does.
func checkRefs(ctx context.Context, c *secretvault.Client, refs [][2]string) []checkResult {
	var out []checkResult
	for _, wr := range refs {
		res := checkResult{where: wr[0], ref: wr[1]}
		r, err := svrpc.ParseRef(wr[1])
		if err == nil {
			var v []byte
			v, err = svops.Resolve(ctx, c, r)
			res.n = len(v)
			clear(v)
		}
		res.err = err
		out = append(out, res)
	}
	return out
}

// checkText says how many of the references can be read, then each, and
// why one cannot.
func (u *UI) checkText(results []checkResult) string {
	var b strings.Builder
	bad := 0
	for _, r := range results {
		if r.err != nil {
			bad++
			fmt.Fprintf(&b, "\n[red]✗[-] %s  %s  [red]%s[-]", tview.Escape(r.where), tview.Escape(r.ref), tview.Escape(u.describe(r.err)))
			continue
		}
		fmt.Fprintf(&b, "\n[green]✓[-] %s  %s  %s (%d bytes)", tview.Escape(r.where), tview.Escape(r.ref), mask, r.n)
	}
	summary := tview.Escape(svops.ReferencesChecked(len(results)-bad, len(results)))
	if bad > 0 {
		summary = "[red]" + summary + "[-]"
	}
	if b.Len() > 0 {
		summary += "\n"
	}
	return summary + b.String()
}

// checkEnvFile is 'secretvault run --env-file F --env K=V', for a
// person: each sv:// reference the environment would hold, and whether
// it resolves (svops.Environ).
func (u *UI) checkEnvFile() {
	f := u.newForm("Check an env file", svops.CheckEnvFileAbout)
	files := f.area("Env files", "", 3)
	files.SetPlaceholder("one path per line")
	pairs := f.area("Variables", "", 2)
	pairs.SetPlaceholder("KEY=VALUE, one per line (optional)")
	f.show("Check the references", func() string {
		env := svops.NewEnviron(nil)
		var paths, kvs []string
		for _, l := range strings.Split(files.GetText(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				paths = append(paths, expandHome(l))
			}
		}
		for _, l := range strings.Split(pairs.GetText(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				kvs = append(kvs, l)
			}
		}
		if err := env.LoadFiles(paths); err != nil {
			return err.Error()
		}
		if err := env.SetPairs(kvs); err != nil {
			return strings.Replace(err.Error(), "--env ", "", 1)
		}
		var refs [][2]string
		for _, k := range env.Refs() {
			refs = append(refs, [2]string{k, env.Get(k)})
		}
		var results []checkResult
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			results = checkRefs(ctx, c, refs)
			return nil
		}, func(error) { u.showText("Env file", u.checkText(results)) })
		return ""
	})
}

// checkTemplate is 'secretvault inject -i TEMPLATE [-o OUT]', for a
// person: each {{ sv://... }} reference checked, and, if asked, the
// template filled into a new file (svops.Inject, svops.WriteNew).
func (u *UI) checkTemplate() {
	f := u.newForm("Check a template", svops.CheckTemplateAbout)
	in := f.path("Template", "", "")
	out := f.path("Fill it into", "", "a new file (optional)")
	f.show("Check the template", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the template's path."
		}
		tmpl, err := os.ReadFile(src)
		if err != nil {
			return err.Error()
		}
		dst := filePath(out)
		var refs [][2]string
		for _, r := range svops.TemplateRefs(tmpl) {
			refs = append(refs, [2]string{"{{ }}", r})
		}
		var results []checkResult
		var injectErr error
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			results = checkRefs(ctx, c, refs)
			if dst == "" {
				return nil
			}
			filled, err := svops.Inject(tmpl, func(r svrpc.Ref) ([]byte, error) {
				return svops.Resolve(ctx, c, r)
			})
			if err == nil {
				err = svops.WriteNew(dst, filled)
				clear(filled)
			}
			injectErr = err
			return nil
		}, func(error) {
			text := u.checkText(results)
			switch {
			case dst == "":
			case injectErr != nil:
				text += "\n\n[red]The filled-in copy was not written: " + tview.Escape(u.describe(injectErr)) + "[-]"
			default:
				text += "\n\nFilled into " + tview.Escape(dst) + ", which only you can read."
				u.say("Filled the template into %s", dst)
			}
			u.showText("Template", text)
		})
		return ""
	})
}
