package svtui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Import (I) and export (X): svimport reads the other manager's file,
// svops stores what it read, and reads and writes the export, as for the
// CLI. The import's dry run is its plan: the names are shown first, and
// stored only when the person says so.

// newCtx bounds one request of a long run of them (svops.StoreImport,
// svops.ReadForExport).
func (u *UI) newCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(u.ctx, callTimeout)
}

// importFile is 'secretvault import SOURCE FILE', in steps, as the GUI's
// File › Import… is: where the passwords are now (svops.ImportSources),
// then how to export them from there and only what that export needs,
// then the names (the dry run), and only then the import. An export that
// was not encrypted is offered for deletion once it is in.
func (u *UI) importFile() { u.chooseImportSource(0) }

// importQuestion is the first step's question.
const importQuestion = "Where are your passwords now?"

// chooseImportSource asks where the passwords come from, at source at.
func (u *UI) chooseImportSource(at int) {
	if !u.needVault() {
		return
	}
	vault := u.vault
	labels := make([]string, len(svops.ImportSources))
	for i, s := range svops.ImportSources {
		labels[i] = s.Label
	}
	u.chooseAt(importQuestion, labels, at, func(i int) { u.importFrom(vault, i) })
}

// importFrom is the second step: source i's steps for its export, the
// file, and only what that export needs; Back returns to the list.
func (u *UI) importFrom(vault string, i int) {
	src := svops.ImportSources[i]
	var b strings.Builder
	b.WriteString("[::b]What to do in " + tview.Escape(src.Program) + "[::-]\n")
	for _, st := range src.NumberedSteps() {
		b.WriteString(tview.Escape(st) + "\n")
	}
	if note := src.UnencryptedNote(); note != "" {
		b.WriteString("[yellow]" + tview.Escape(note) + "[-]\n")
	}
	b.WriteString("\nThen give the export file. Nothing is stored until you have seen the names it would make.")
	f := u.newForm("Import from "+src.Label, b.String())
	path := f.path("Export file", "", "its path, like ~/Downloads/"+src.File)
	var srcPass *secretInput
	if src.Passphrase != "" {
		srcPass = f.secret(src.Passphrase)
	}
	var srcKey *tview.InputField
	if src.Keyfile {
		srcKey = f.path("Key file", "", "only if you use one")
	}
	prefix := f.text("Put them in a folder", "", "optional, like imported/"+src.Name)
	overwrite := f.check("Replace items that exist", false)
	f.back = func() { u.chooseImportSource(i) }
	f.show("Read it", func() string {
		p := filePath(path)
		if p == "" {
			return "Give the export file's path."
		}
		opts := svimport.Options{Prefix: strings.TrimSpace(trimmed(prefix))}
		if srcKey != nil {
			if k := filePath(srcKey); k != "" {
				b, err := os.ReadFile(k)
				if err != nil {
					return err.Error()
				}
				opts.Keyfile = b
			}
		}
		if srcPass != nil && len(srcPass.buf) > 0 {
			opts.Passphrase = srcPass.value()
		}
		u.readExport(vault, p, src.Name, opts, overwrite.IsChecked(), 0)
		return ""
	})
}

// readExport reads the export (asking for its passphrase when it needs
// one, up to three times), then shows what would be imported.
func (u *UI) readExport(vault, path, format string, opts svimport.Options, overwrite bool, tries int) {
	var res *svimport.Result
	var f svimport.Format
	var guessed bool
	u.call(func(context.Context, *secretvault.Client) error {
		data, err := svops.ReadImportFile(path)
		if err != nil {
			return err
		}
		defer clear(data)
		if f, guessed, err = svops.ImportFormat(format, path, data); err != nil {
			return err
		}
		res, err = svimport.Import(f, data, opts)
		if src, ok := svops.FindImportSource(format); ok && errors.Is(err, svimport.ErrFormat) {
			return fmt.Errorf("%s does not look like an export from %s: check its steps, or go back and choose where it comes from", filepath.Base(path), src.Program)
		}
		return err
	}, func(err error) {
		wipe := func() { clear(opts.Passphrase); clear(opts.Keyfile) }
		switch {
		case err == nil:
		case tries < 3 && svops.NeedsPassphrase(err):
			intro := filepath.Base(path) + " is encrypted: type its own passphrase."
			if svops.WrongPassphrase(err) && len(opts.Passphrase) > 0 {
				intro = "That passphrase does not open " + filepath.Base(path) + ". Try again."
			}
			clear(opts.Passphrase)
			opts.Passphrase = nil
			fd := u.newForm("Passphrase for "+filepath.Base(path), intro)
			in := fd.secret("Passphrase")
			fd.onCancel = wipe
			fd.show("Read it", func() string {
				opts.Passphrase = in.value()
				u.readExport(vault, path, format, opts, overwrite, tries+1)
				return ""
			})
			return
		default:
			wipe()
			u.fail(err)
			return
		}
		wipe()
		var b strings.Builder
		if guessed {
			fmt.Fprintf(&b, "Reading %s as %s.\n\n", tview.Escape(path), f)
		}
		fmt.Fprintf(&b, "[::b]%d items to import into %s:[::-]\n", len(res.Items), tview.Escape(vault))
		for _, it := range res.Items {
			b.WriteString("  " + tview.Escape(it.Name) + "\n")
		}
		for _, w := range res.Warnings {
			b.WriteString("\n[yellow]warning:[-] " + tview.Escape(w))
		}
		if overwrite {
			b.WriteString("\n\nItems that exist already are replaced.")
		} else {
			b.WriteString("\n\nItems that exist already are skipped.")
		}
		plain := !res.Encrypted
		u.showPlan("Import "+filepath.Base(path), b.String(), fmt.Sprintf("Import %d items", len(res.Items)), func() {
			u.storeImport(vault, path, res, opts.Prefix, overwrite, plain)
		}, res.Wipe)
	})
}

// storeImport stores what was read (svops.StoreImport), and says how it
// went; an export that was not encrypted (plain) is then offered for
// deletion.
func (u *UI) storeImport(vault, path string, res *svimport.Result, prefix string, overwrite, plain bool) {
	var rep *svops.ImportReport
	u.call(func(_ context.Context, c *secretvault.Client) (err error) {
		defer res.Wipe()
		rep, err = svops.StoreImport(u.newCtx, c, res, svops.ImportOptions{Vault: vault, Prefix: prefix, Overwrite: overwrite, Describe: describeErr,
			Skipped: func(name string) string { return name + ": already exists, skipped (tick Replace to replace it)" }})
		return err
	}, func(err error) {
		var b strings.Builder
		if rep != nil {
			withFiles := ""
			if rep.Files > 0 {
				withFiles = fmt.Sprintf(" (%d files)", rep.Files)
			}
			fmt.Fprintf(&b, "Imported %d items%s, skipped %d, with %d warnings.\n", rep.Imported, withFiles, rep.Skipped, len(rep.Warnings))
			for _, w := range rep.Warnings {
				b.WriteString("\n[yellow]warning:[-] " + tview.Escape(w))
			}
		}
		if err != nil {
			b.WriteString("\n\n[red]" + tview.Escape(sentence(err.Error())) + "[-]")
			u.fail(err)
		} else {
			u.say("Imported %d items into %s", rep.Imported, vault)
		}
		u.showText("Import", b.String())
		if err == nil && plain {
			u.offerDeleteExport(path, vault)
		}
		if vault == u.vault {
			u.loadItems()
		}
	})
}

// offerDeleteExport offers to delete an export that held the passwords
// unencrypted, now that they are in vault: a plain remove
// (svops.RemoveExport), and said to be no more than that.
func (u *UI) offerDeleteExport(path, vault string) {
	u.confirmWith("Delete "+filepath.Base(path)+"?", svops.DeleteExportNote(path, vault), "Keep it", "Delete it", func() {
		if err := svops.RemoveExport(path); err != nil {
			u.fail(err)
			return
		}
		u.say("Deleted %s", path)
	})
}

// exportFile is 'secretvault export cxf|kdbx FILE'.
func (u *UI) exportFile() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	f := u.newForm("Export from "+vault, "KDBX (KeePass) is encrypted under the passphrase given here. CXF is not encrypted: anyone who can read the file has every secret in it.")
	format := f.choice("Format", svops.ExportFormats, 1)
	path := f.path("New file", "", "export writes only new files")
	prefix := f.text("Only the items under", "", "a folder (optional: all of them)")
	pass := f.secret("KDBX passphrase")
	again := f.secret("Repeat it")
	f.show("Export", func() string {
		fmtName, p := option(format), filePath(path)
		if p == "" {
			return "Give the new file's path."
		}
		if err := svops.CheckExport(fmtName, p); err != nil {
			return err.Error()
		}
		var secret []byte
		if fmtName == "kdbx" {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			secret = pass.value()
		}
		do := func() { u.writeExport(vault, fmtName, p, trimmed(prefix), secret) }
		if fmtName == "cxf" {
			u.post(func() {
				u.confirm("Not encrypted", p+" will not be encrypted: anyone who can read it has every secret in it. Import it where it is going, then delete it.", "Export", do)
			})
			return ""
		}
		do()
		return ""
	})
}

// writeExport reads the items (svops.ReadForExport), encodes them
// (svops.EncodeExport) and writes the new file (svops.WriteNew).
func (u *UI) writeExport(vault, format, path, prefix string, pass []byte) {
	var n int
	var conflicts []string
	u.call(func(_ context.Context, c *secretvault.Client) error {
		defer clear(pass)
		items, err := svops.ReadForExport(u.newCtx, c, svops.ExportOptions{Vault: vault, Prefix: prefix, Describe: describeErr,
			Each: func(e svrpc.Entry) {
				if len(e.Conflicts) > 0 {
					conflicts = append(conflicts, e.Item.Name)
				}
			}})
		if err != nil {
			return err
		}
		defer func() {
			for i := range items {
				svops.Wipe(&items[i])
			}
		}()
		out, err := svops.EncodeExport(format, items, pass)
		if err != nil {
			return err
		}
		defer clear(out)
		n = len(items)
		return svops.WriteNew(path, out)
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.say("Exported %d items to %s", n, path)
		if len(conflicts) > 0 {
			u.showText("Exported", fmt.Sprintf("Exported %d items to %s.\n\n[yellow]These have conflicting versions; the newest of each was exported (their history settles them):[-]\n  %s",
				n, tview.Escape(path), tview.Escape(strings.Join(conflicts, "\n  "))))
		}
	})
}
