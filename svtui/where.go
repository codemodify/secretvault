package svtui

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// showWhere is 'secretvault where': every folder and file secretvault
// keeps, and what it changed in other programs, grouped, with what each
// holds. Enter shows a place whole; c copies its path.
func (u *UI) showWhere() {
	p := u.newPanel("Where things are kept", "PLACE", "WHAT IT HOLDS")
	p.reload = func() {
		var places []svrpc.Place
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			places, err = c.Where(ctx)
			var e *svrpc.Error
			if errors.As(err, &e) && e.Code == svrpc.CodeMethodNotFound {
				places, err = svops.WhereHere() // a daemon too old to say
			}
			return err
		}, func(err error) {
			p.clear()
			if err != nil {
				p.setHead("[red]" + tview.Escape(u.describe(err)) + "[-]")
				p.none("Nothing to show.")
				p.done()
				return
			}
			p.setHead(tview.Escape(svops.WhereAbout) + " [::d]Enter shows a place whole; c copies its path.[::-]")
			for _, group := range svops.WhereGroups(places) {
				p.heading(group[0].Group)
				for _, pl := range group {
					place := tview.Escape(placePath(pl))
					if !pl.Exists {
						place += " [::d](" + svops.WhereMissing + ")[::-]"
					}
					p.row(pl, tagged(place), pl.What)
					p.t.GetCell(p.t.GetRowCount()-1, 1).SetMaxWidth(0) // as wide as the screen lets it be
				}
			}
			p.done()
		})
	}
	p.enter = func(ref any) {
		pl := ref.(svrpc.Place)
		text := "[::b]" + tview.Escape(placePath(pl)) + "[::-]\n\n" + tview.Escape(pl.What)
		if !pl.Exists {
			text += "\n\nIt is not there yet."
		}
		u.showText(pl.Group, text)
	}
	p.enterIs = "shows it whole"
	p.rowAct('c', "Copy the path", is[svrpc.Place], func(ref any) { u.copyPath(ref.(svrpc.Place).Path) })
	p.act('r', "Refresh", p.refresh)
	p.show()
}

// placePath is a place's path, a folder's ending in a separator.
func placePath(pl svrpc.Place) string {
	if pl.Dir && !strings.HasSuffix(pl.Path, string(filepath.Separator)) {
		return pl.Path + string(filepath.Separator)
	}
	return pl.Path
}

// copyPath copies a path, which is no secret, to the clipboard.
func (u *UI) copyPath(path string) {
	text := []byte(path)
	u.call(func(context.Context, *secretvault.Client) error {
		_, err := u.clip(text, clipTTL)
		return err
	}, func(err error) {
		if err != nil {
			u.message = "[red]Could not copy: " + tview.Escape(err.Error()) + "[-]"
			u.drawStatus()
			return
		}
		u.say("Copied %s", path)
	})
}
