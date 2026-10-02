package svmanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Moving secrets in from other password managers, and out to KeePass and
// CXF files, as the CLI's import and export do: svimport reads and writes
// the formats, svops reads the files and stores what was read.

// importItems reads another password manager's export, shows what it
// would make (the CLI's --dry-run), and stores it in the vault shown.
func (m *Manager) importItems() {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	formats := []string{"auto: guess from the file"}
	for _, f := range svimport.Formats {
		formats = append(formats, string(f))
	}
	f := m.newForm("Import into " + vault)
	file := f.path("Export", PickOpen, "")
	format := f.choice("Format", formats, 0)
	prefix := f.text("Folder", "", "optional: put every item under it, like imported/keepass")
	overwrite := f.check("Replace items that exist (else they are skipped)", false)
	pass := f.secret("Its passphrase", "only if the export is encrypted")
	keyfile := f.path("KeePass key file", PickOpen, "")
	f.note("KeePass, Bitwarden, 1Password, Proton Pass, CSV, Aegis, Google Authenticator and CXF exports. " +
		"Nothing is stored until the names it would make are shown.")
	f.show("Preview", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the export.")
			return
		}
		name := "auto"
		if format.Selected > 0 {
			name = formats[format.Selected]
		}
		opts := svimport.Options{Prefix: strings.TrimSpace(prefix.Text), Passphrase: pass.Bytes()}
		keyPath, replace := keyfile.Path(), overwrite.Checked
		var read *svimport.Result
		var guessed svimport.Format
		f.work(func() error {
			defer func() { clear(opts.Passphrase); clear(opts.Keyfile) }()
			data, err := svops.ReadImportFile(path)
			if err != nil {
				return err
			}
			defer clear(data)
			fmtv, wasGuessed, err := svops.ImportFormat(name, path, data)
			if err != nil {
				return err
			}
			if wasGuessed {
				guessed = fmtv
			}
			if keyPath != "" {
				if opts.Keyfile, err = os.ReadFile(keyPath); err != nil {
					return err
				}
			}
			read, err = svimport.Import(fmtv, data, opts)
			switch {
			case err == nil:
				return nil
			case svops.WrongPassphrase(err) && len(opts.Passphrase) > 0:
				return fmt.Errorf("that passphrase does not open %s", filepath.Base(path))
			case svops.NeedsPassphrase(err):
				return fmt.Errorf("%s is encrypted: type its passphrase", filepath.Base(path))
			}
			return err
		}, func() {
			// The preview takes the form's place, holding what was read
			// until it is imported or put down.
			m.previewImport(vault, path, guessed, read, opts.Prefix, replace)
		})
	})
}

// previewImport shows the names an import would make, and its warnings,
// and stores it if the person says so.
func (m *Manager) previewImport(vault, path string, guessed svimport.Format, res *svimport.Result, prefix string, overwrite bool) {
	var lines []string
	for _, it := range res.Items {
		lines = append(lines, it.Name)
	}
	for _, w := range res.Warnings {
		lines = append(lines, "warning: "+w)
	}
	intro := fmt.Sprintf("%s holds %s to import into vault %s.", filepath.Base(path), plural(len(res.Items), "item"), vault)
	if guessed != "" {
		intro = fmt.Sprintf("Read %s as %s: %s to import into vault %s.", filepath.Base(path), guessed, plural(len(res.Items), "item"), vault)
	}
	if overwrite {
		intro += " Items that exist are replaced."
	} else {
		intro += " Items that exist are skipped."
	}
	m.showPlan("Import into "+vault, intro, lines, "Import", func() {
		var rep *svops.ImportReport
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer res.Wipe()
			rep, err = svops.StoreImport(func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(m.ctx, callTimeout)
			}, c, res, svops.ImportOptions{Vault: vault, Prefix: prefix, Overwrite: overwrite, Describe: m.describe,
				Skipped: func(name string) string {
					return name + ": already exists, skipped (Replace items that exist replaces it)"
				}})
			return err
		}, func(err error) {
			if rep != nil {
				withFiles := ""
				if rep.Files > 0 {
					withFiles = fmt.Sprintf(" (%d files)", rep.Files)
				}
				intro := fmt.Sprintf("Imported %d items%s, skipped %d, with %s.", rep.Imported, withFiles, rep.Skipped, plural(len(rep.Warnings), "warning"))
				if err != nil {
					intro = m.describe(err) + " " + intro
				}
				m.showText("Imported", intro, strings.Join(rep.Warnings, "\n"))
				m.say("%s", intro)
			} else if err != nil {
				m.fail(err)
			}
			if vault == m.vault {
				m.loadItems()
			}
		})
	}, res.Wipe)
}

// exportItems writes the vault's items (or a folder of them) to a new
// KeePass or CXF file (the CLI's export).
func (m *Manager) exportItems() {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	f := m.newForm("Export from " + vault)
	format := f.choice("Format", []string{"KeePass (KDBX), encrypted with a passphrase", "CXF, not encrypted"}, 0)
	file := f.path("File", PickSave, vault+".kdbx")
	prefix := f.text("Folder", "", "optional: only the items under it")
	newPass := f.newPassphrase("Its passphrase")
	f.warn("A CXF file is not encrypted: anyone who can read it has every secret in it. Import it where it is going, then delete it. KeePass files take the passphrase above.")
	f.show("Export", func() {
		formatName := svops.ExportFormats[[]int{1, 0}[max(0, format.Selected)]]
		path := file.Path()
		if path == "" {
			f.fail("Choose where the export goes.")
			return
		}
		if err := svops.CheckExport(formatName, path); err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		var pass []byte
		if formatName == "kdbx" {
			p, ok := newPass()
			if !ok {
				return
			}
			pass = p
		}
		var n int
		var warnings []string
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			items, err := svops.ReadForExport(func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(m.ctx, callTimeout)
			}, c, svops.ExportOptions{Vault: vault, Prefix: strings.TrimSpace(prefix.Text), Describe: m.describe,
				Each: func(e svrpc.Entry) {
					if len(e.Conflicts) > 0 {
						warnings = append(warnings, fmt.Sprintf("%s has %d conflicting versions; the newest is exported (Edit › History shows them)", e.Item.Name, len(e.Conflicts)))
					}
					if e.Signature.Status == svrpc.SigBad {
						warnings = append(warnings, fmt.Sprintf("the current revision of %s has a bad signature: someone who can open the vault changed it, posing as another device", e.Item.Name))
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
			out, err := svops.EncodeExport(formatName, items, pass)
			if err != nil {
				return err
			}
			defer clear(out)
			n = len(items)
			return svops.WriteNew(path, out)
		}, func() {
			intro := fmt.Sprintf("Exported %s to %s.", plural(n, "item"), path)
			if formatName == "cxf" {
				intro += " It is not encrypted: import it where it is going, then delete it."
			}
			m.say("%s", intro)
			if len(warnings) > 0 {
				m.showText("Exported", intro, strings.Join(warnings, "\n"))
			}
		}, pass)
	})
}
