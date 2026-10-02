package svtui

import (
	"context"
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

// importFile is 'secretvault import FORMAT FILE'.
func (u *UI) importFile() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	formats := []string{"auto"}
	for _, f := range svimport.Formats {
		formats = append(formats, string(f))
	}
	f := u.newForm("Import into "+vault, "Another password manager's export. Its names are shown before anything is stored. pass and gopass stores are not read yet.")
	path := f.path("File", "", "")
	format := f.choice("Format", formats, 0)
	prefix := f.text("Folder", "", "put every item under it, like imported/keepass (optional)")
	overwrite := f.check("Replace items that exist", false)
	srcPass := f.secret("Its passphrase")
	srcKey := f.path("KeePass key file", "", "(optional)")
	f.show("Read it", func() string {
		p := filePath(path)
		if p == "" {
			return "Give the export's path."
		}
		opts := svimport.Options{Prefix: strings.TrimSpace(trimmed(prefix))}
		if k := filePath(srcKey); k != "" {
			b, err := os.ReadFile(k)
			if err != nil {
				return err.Error()
			}
			opts.Keyfile = b
		}
		if len(srcPass.buf) > 0 {
			opts.Passphrase = srcPass.value()
		}
		u.readExport(vault, p, option(format), opts, overwrite.IsChecked(), 0)
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
		u.showPlan("Import "+filepath.Base(path), b.String(), fmt.Sprintf("Import %d items", len(res.Items)), func() {
			u.storeImport(vault, res, opts.Prefix, overwrite)
		}, res.Wipe)
	})
}

// storeImport stores what was read (svops.StoreImport), and says how it
// went.
func (u *UI) storeImport(vault string, res *svimport.Result, prefix string, overwrite bool) {
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
		if vault == u.vault {
			u.loadItems()
		}
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
