package svtui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// An item's past: its history (h), each revision viewable and restorable,
// with who signed it; settling a conflict (keeping one version on every
// device); deleted items (R); and the item's attached files (f).

// revisionRef is a row of the history: the index of its revision.
type revisionRef int

// showHistory lists the target item's revisions, newest first, with who
// signed each ('secretvault history'). Enter opens one, read-only; R
// makes it current again ('secretvault restore'); k keeps a conflicting
// version on every device ('secretvault resolve --keep').
func (u *UI) showHistory() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	vault := u.vault
	p := u.newPanel("History of "+name, "WHEN", "REVISION", "SIGNED BY", "")
	p.vault = vault
	p.onClose = u.closeHistory
	var cur svrpc.Entry
	p.reload = func() {
		var hist []svrpc.Entry
		var now svrpc.Entry
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if now, err = c.Get(ctx, vault, name); err != nil {
				return err
			}
			wipeItem(&now.Item)
			hist, err = c.History(ctx, vault, name)
			return err
		}, func(err error) {
			if err == nil {
				cur = now
			}
			if err != nil || vault != u.vault {
				for i := range hist {
					wipeItem(&hist[i].Item)
				}
				if err != nil {
					u.fail(err)
					p.close()
				}
				return
			}
			u.closePage(pageRev)
			u.wipeHistory()
			u.history = hist
			heads := map[string]bool{}
			for _, r := range cur.Conflicts {
				heads[r] = true
			}
			head := ""
			if len(cur.Conflicts) > 0 {
				head = fmt.Sprintf("[red]%s was changed on two devices at once.[-] Its versions are marked; open each (Enter), and keep one on every device with k.", tview.Escape(name))
			}
			p.setHead(head)
			p.clear()
			for i, e := range hist { // newest first
				var note []string
				switch {
				case e.Rev == cur.Rev:
					note = append(note, "[green]current[-]")
				case heads[e.Rev]:
					note = append(note, "[red]conflict[-]")
				}
				if e.Deleted {
					note = append(note, "deleted")
				}
				if e.Ignored {
					note = append(note, "[yellow]ignored: the vault requires signatures[-]")
				}
				signer := svops.Author(e)
				if e.Signature.Status == svrpc.SigBad {
					signer = tagged("[red]" + tview.Escape(signer) + "[-]")
				}
				p.row(revisionRef(i), e.Time.Local().Format("2006-01-02 15:04:05"), svops.Short(e.Rev), signer, tagged(strings.Join(note, " ")))
			}
			p.done()
		})
	}
	entry := func(ref any) *svrpc.Entry {
		if i, ok := ref.(revisionRef); ok && int(i) < len(u.history) {
			return &u.history[i]
		}
		return nil
	}
	p.enter = func(ref any) {
		if e := entry(ref); e != nil {
			u.showRevision(name, e)
		}
	}
	p.rowAct('R', "Go back to this version…", func(ref any) bool {
		e := entry(ref)
		return e != nil && e.Rev != cur.Rev
	}, func(ref any) {
		e := entry(ref)
		rev, when := e.Rev, e.Time.Local().Format("2006-01-02 15:04")
		u.confirm(svops.RestoreRevisionTitle, svops.RestoreRevisionText(name, when), svops.RestoreRevisionAction, func() {
			u.restore(vault, name, rev, false, p.refresh)
		})
	})
	p.rowAct('k', "Keep this version on every device…", func(ref any) bool {
		e := entry(ref)
		if e == nil || len(cur.Conflicts) == 0 {
			return false
		}
		if e.Rev == cur.Rev {
			return true
		}
		for _, r := range cur.Conflicts {
			if r == e.Rev {
				return true
			}
		}
		return false
	}, func(ref any) {
		rev := entry(ref).Rev
		u.confirm(svops.KeepVersionTitle, svops.KeepVersionText(name), svops.KeepVersionAction, func() {
			u.restore(vault, name, rev, true, p.refresh)
		})
	})
	p.rowAct('v', "View it", func(ref any) bool { return entry(ref) != nil }, p.enter)
	p.show()
}

// restore is 'secretvault restore NAME [REV]', and with keep 'secretvault
// resolve NAME --keep REV'.
func (u *UI) restore(vault, name, rev string, keep bool, then func()) {
	var e svrpc.Entry
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		e, err = c.Restore(ctx, svrpc.RestoreParams{Vault: vault, Name: name, Rev: rev})
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		if keep {
			u.say("Kept that version of %s; the conflict is settled (revision %s)", e.Item.Name, svops.Short(e.Rev))
		} else {
			u.say("Restored %s", e.Item.Name)
		}
		if then != nil {
			then()
		}
		if vault == u.vault {
			u.loadItems()
			if u.cur != nil && u.cur.Item.Name == name && u.editor == nil {
				u.reopen()
			}
		}
	})
}

// versionRef is a row of the resolve panel: the index of its version.
type versionRef int

// showResolve is 'secretvault resolve NAME': the versions of an item
// changed on two devices at once (svops.Conflicts), each viewable, and
// keeping one.
func (u *UI) showResolve() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	vault := u.vault
	p := u.newPanel("Resolve "+name, "REVISION", "WHEN", "SIGNED BY", "FIELDS", "")
	p.vault = vault
	p.onClose = u.closeHistory
	p.reload = func() {
		var con *svops.Conflict
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			con, err = svops.Conflicts(ctx, c, vault, name)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			u.closePage(pageRev)
			u.wipeHistory()
			u.history = con.Versions
			p.clear()
			if len(con.Current.Conflicts) == 0 {
				p.setHead("")
				p.none("No conflict.")
				p.done()
				return
			}
			p.setHead(tview.Escape(name) + " was changed on two devices at once. Open each version (Enter), and keep one with k: it becomes the item on every device.")
			for i, e := range con.Versions {
				note := ""
				if e.Rev == con.Current.Rev {
					note = "(shown now)"
				}
				var fields []string
				for _, f := range e.Item.Fields {
					fields = append(fields, f.Name)
				}
				p.row(versionRef(i), svops.Short(e.Rev), e.Time.Local().Format("2006-01-02 15:04:05"), svops.Author(e), strings.Join(fields, ","), note)
			}
			p.done()
		})
	}
	entry := func(ref any) *svrpc.Entry {
		if i, ok := ref.(versionRef); ok && int(i) < len(u.history) {
			return &u.history[i]
		}
		return nil
	}
	p.enter = func(ref any) {
		if e := entry(ref); e != nil {
			u.showRevision(name, e)
		}
	}
	p.rowAct('k', "Keep this version on every device…", is[versionRef], func(ref any) {
		rev := entry(ref).Rev
		u.confirm(svops.KeepVersionTitle, svops.KeepVersionText(name), svops.KeepVersionAction, func() {
			u.restore(vault, name, rev, true, p.refresh)
		})
	})
	p.rowAct('v', "View it", is[versionRef], p.enter)
	p.show()
}

// showDeleted is 'secretvault ls --deleted': the deleted items, each
// brought back with Enter ('secretvault restore NAME').
func (u *UI) showDeleted() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Deleted items · "+vault, "NAME", "KIND", "DELETED")
	p.vault = vault
	p.reload = func() {
		var del []svrpc.DeletedItem
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			del, err = c.Deleted(ctx, vault, "")
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			if len(del) == 0 {
				p.none("Nothing deleted from it.")
			}
			for _, d := range del {
				p.row(d, d.Name, svops.KindText(d.Kind), d.Deleted.Local().Format("2006-01-02 15:04"))
			}
			p.done()
		})
	}
	restore := func(ref any) {
		d := ref.(svrpc.DeletedItem)
		u.confirm("Bring "+d.Name+" back?", svops.RestoreDeletedText(d.Name), svops.RestoreDeletedAction, func() {
			u.restore(vault, d.Name, "", false, p.refresh)
		})
	}
	p.enter = restore
	p.rowAct('r', "Bring it back…", is[svrpc.DeletedItem], restore)
	p.show()
}

// showFiles is the target item's attached files ('secretvault file ls'):
// a attaches one, s saves one, x removes one.
func (u *UI) showFiles() {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	vault := u.vault
	p := u.newPanel("Files of "+name, "NAME", "SIZE", "TYPE", "SHA-256")
	p.vault = vault
	p.reload = func() {
		var e svrpc.Entry
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			e, err = c.Get(ctx, vault, name)
			wipeItem(&e.Item)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			if len(e.Item.Files) == 0 {
				p.none("No files (a attaches one).")
			}
			for _, f := range e.Item.Files {
				sum := f.SHA256
				if len(sum) > 16 {
					sum = sum[:16] + "…"
				}
				p.row(f, f.Name, fmt.Sprint(f.Size), f.Type, sum)
			}
			p.done()
		})
	}
	p.act('a', "Attach a file…", func() { u.attachFile(vault, name, p.refresh) })
	p.rowAct('s', "Save it to a file…", is[svrpc.FileInfo], func(ref any) { u.saveFile(vault, name, ref.(svrpc.FileInfo)) })
	p.rowAct('x', "Remove it…", is[svrpc.FileInfo], func(ref any) {
		f := ref.(svrpc.FileInfo)
		u.confirm("Remove "+f.Name+"?", svops.RemoveFileText(f.Name, name), svops.RemoveFileAction, func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				_, err := c.Detach(ctx, vault, name, f.Name)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Removed %s from %s", f.Name, name)
				p.refresh()
			})
		})
	})
	p.show()
}

// attachFile is 'secretvault attach ITEM FILE' (svops.ReadAttachment).
func (u *UI) attachFile(vault, item string, then func()) {
	f := u.newForm("Attach a file to "+item, "A file of the same name in the item is replaced.")
	path := f.path("File", "", "")
	name := f.text("Name in the item", "", "the file's own")
	typ := f.text("Media type", "", "from its extension")
	f.show("Attach", func() string {
		pth := filePath(path)
		if pth == "" {
			return "Give the file's path."
		}
		if pth == "-" {
			return "Give a file, not standard input."
		}
		params, err := svops.ReadAttachment(pth, nil, trimmed(name), trimmed(typ))
		if err != nil {
			return err.Error()
		}
		params.Vault, params.Item = vault, item
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			defer clear(params.Data)
			_, err := c.Attach(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Attached %s (%d bytes) to %s", params.Name, len(params.Data), item)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// saveFile is 'secretvault file get ITEM NAME -o PATH' (svops.SaveFile).
func (u *UI) saveFile(vault, item string, info svrpc.FileInfo) {
	f := u.newForm("Save "+info.Name, "")
	path := f.path("Save as", filepath.Base(info.Name), "")
	force := f.check("Replace the file if it is there", false)
	f.show("Save", func() string {
		pth := filePath(path)
		if pth == "" {
			return "Give a path to save it to."
		}
		if _, err := os.Lstat(pth); err == nil && !force.IsChecked() {
			return pth + " exists: tick Replace to write over it, or choose another name."
		}
		replace := force.IsChecked()
		var n int
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			fd, err := c.File(ctx, vault, item, info.Name)
			if err != nil {
				return err
			}
			defer clear(fd.Data)
			n = len(fd.Data)
			return svops.SaveFile(pth, fd.Data, replace)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Wrote %s (%d bytes)", pth, n)
		})
		return ""
	})
}
