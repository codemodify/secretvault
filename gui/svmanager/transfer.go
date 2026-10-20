package svmanager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Moving secrets in from other password managers, and out to KeePass and
// CXF files, as the CLI's import and export do: svimport reads and writes
// the formats, svops reads the files and stores what was read.

// importItems is Vault › Import…, in steps: where the passwords are now;
// then how to export them from there, and only what that export needs;
// then the names it would make (the CLI's --dry-run); and only then the
// import. An export that was not encrypted is offered for deletion once
// it is in. The words are svops.ImportSources', as the CLI's and the
// TUI's are.
func (m *Manager) importItems() { m.chooseImportSource(0) }

// importQuestion is the first step's question, and its list's name.
const importQuestion = "Where are your passwords now?"

// chooseImportSource asks where the passwords come from, at source at.
func (m *Manager) chooseImportSource(at int) {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	labels := make([]string, len(svops.ImportSources))
	for i, s := range svops.ImportSources {
		labels[i] = s.Label
	}
	f := m.newForm("Import into " + vault)
	f.head(heading(importQuestion))
	list := widgets.NewRadioGroup(labels, at, nil)
	list.SetAccessibleName(importQuestion)
	f.addLine(list)
	f.focusFirst(list)
	f.show("Next", func() {
		i := max(0, list.Selected())
		f.close()
		m.importFrom(vault, i)
	})
}

// importFrom is the second step: how to export from source i, the file,
// and only what that export needs; the folder and replacing what exists
// under More options.
func (m *Manager) importFrom(vault string, i int) {
	if m.gone {
		return
	}
	src := svops.ImportSources[i]
	f := m.newForm("Import from " + src.Label)
	steps := widgets.NewColumn().WithGap(6)
	steps.Add(heading("What to do in " + src.Program))
	for _, s := range src.NumberedSteps() {
		l := widgets.NewLabel(s)
		l.Wrap = true
		steps.Add(l)
	}
	if note := src.UnencryptedNote(); note != "" {
		w := toned(note, widgets.ToneWarning)
		w.Wrap = true
		steps.Add(w)
	}
	f.head(steps)

	var path string
	chosen := m.muted("No file chosen yet")
	chosen.Wrap = true
	choose := newButton("Choose the export file…", func() {
		m.pickFile(PickOpen, src.File, func(p string) {
			if p == "" {
				return
			}
			path = p
			chosen.SetText(filepath.Base(p) + ", in " + filepath.Dir(p))
			chosen.RequestLayout()
			f.fail("")
		})
	})
	f.focusFirst(choose) // the keyboard starts on the button, not the row it is in
	f.row("File", widgets.NewColumn(widgets.NewRow(choose), chosen).WithGap(4))
	var pass *widgets.SecretField
	if src.Passphrase != "" {
		pass = f.secret(src.Passphrase, src.PassphraseHint)
	}
	var keyfile *pathField
	if src.Keyfile {
		keyfile = f.path("Key file", PickOpen, "")
		keyfile.field.Placeholder = "Only if you use one"
	}

	overwrite := widgets.NewCheckbox("Replace items that exist (else they are skipped)", false, nil)
	f.addLine(widgets.NewExpander("More options", false, overwrite))
	f.note("Nothing is stored until you have seen the names it would make.")
	f.back = func() { m.chooseImportSource(i) }

	f.show("Preview", func() {
		if path == "" {
			f.fail("Choose the export file first.")
			m.focus(choose)
			return
		}
		opts := svimport.Options{}
		if pass != nil {
			opts.Passphrase = pass.Bytes()
		}
		keyPath, replace := "", overwrite.Checked
		if keyfile != nil {
			keyPath = keyfile.Path()
		}
		var read *svimport.Result
		f.work(func() error {
			defer func() { clear(opts.Passphrase); clear(opts.Keyfile) }()
			data, err := svops.ReadImportFile(path)
			if err != nil {
				return err
			}
			defer clear(data)
			if keyPath != "" {
				if opts.Keyfile, err = os.ReadFile(keyPath); err != nil {
					return err
				}
			}
			read, err = svimport.Import(src.Format, data, opts)
			base := filepath.Base(path)
			switch {
			case err == nil:
				return nil
			case svops.WrongPassphrase(err) && len(opts.Passphrase)+len(opts.Keyfile) > 0:
				return fmt.Errorf("that %s does not open %s", strings.ToLower(src.Passphrase), base)
			case svops.NeedsPassphrase(err) && src.Passphrase != "":
				return fmt.Errorf("%s is encrypted: type its %s", base, strings.ToLower(src.Passphrase))
			case errors.Is(err, svimport.ErrFormat):
				return fmt.Errorf("%s does not look like an export from %s. Check the steps above, or go back and choose where it comes from", base, src.Program)
			}
			return err
		}, func() {
			// The preview takes the form's place, holding what was read
			// until it is imported or put down.
			m.previewImport(vault, path, read, replace)
		})
	})
}

// previewImport shows the names an import would make, and its warnings,
// and stores it if the person says so; an export that was not encrypted
// is offered for deletion once it is in.
func (m *Manager) previewImport(vault, path string, res *svimport.Result, overwrite bool) {
	var names []string
	for _, it := range res.Items {
		names = append(names, it.Name)
	}
	plain := !res.Encrypted
	m.showPlan(svops.ImportPlain(path, vault, names, res.Warnings, overwrite), func() {
		var rep *svops.ImportReport
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer res.Wipe()
			rep, err = svops.StoreImport(func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(m.ctx, callTimeout)
			}, c, res, svops.ImportOptions{Vault: vault, Overwrite: overwrite, Describe: m.describe,
				Skipped: func(name string) string {
					return name + ": the vault has it already, so it was skipped (More options › Replace items that exist replaces it)"
				}})
			return err
		}, func(err error) {
			var then func()
			if err == nil && plain {
				then = func() { m.offerDeleteExport(path, vault) }
			}
			if rep != nil {
				// What it means, and the warnings under "Show details";
				// the offer to delete the export once it is closed.
				intro := svops.ImportedText(rep.Imported, rep.Files, rep.Skipped, len(rep.Warnings))
				if err != nil {
					intro = m.describe(err) + " " + intro
				}
				var d *dialog
				ok := newButton("Close", func() { d.Close() })
				d = m.showDialog("Imported into "+vault, plainBody(m, intro, nil, rep.Warnings),
					widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, then)
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

// offerDeleteExport offers to delete an export that held the passwords
// unencrypted, now that they are in vault: a plain remove
// (svops.RemoveExport), and said to be no more than that.
func (m *Manager) offerDeleteExport(path, vault string) {
	if m.gone {
		return
	}
	body := widgets.NewLabel(svops.DeleteExportNote(path, vault))
	body.Wrap = true
	var d *dialog
	del := newButton("Delete the file", func() {
		d.Close()
		m.work(func() error { return svops.RemoveExport(path) }, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Deleted %s.", path)
		})
	})
	keep := newButton("Keep it", func() { d.Close() })
	keep.Primary = true
	buttons := widgets.NewButtonBox().AddButton(del, widgets.RoleDestructive).AddButton(keep, widgets.RoleReject)
	d = m.showDialog("Delete "+filepath.Base(path)+"?", body, buttons, keep, nil)
}

// exportItems writes the vault's items to a new KeePass or CXF file (the
// CLI's export).
func (m *Manager) exportItems() {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	f := m.newForm("Export from " + vault)
	format := f.choice("Format", []string{"KeePass (KDBX), encrypted with a passphrase", "CXF, not encrypted"}, 0)
	file := f.path("File", PickSave, vault+".kdbx")
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
			}, c, svops.ExportOptions{Vault: vault, Describe: m.describe,
				Each: func(e svrpc.Entry) {
					if len(e.Conflicts) > 0 {
						warnings = append(warnings, fmt.Sprintf("%s has %d conflicting versions; the newest is exported (Vault › Items › History shows them)", e.Item.Name, len(e.Conflicts)))
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
