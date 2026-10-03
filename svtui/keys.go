package svtui

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The keys panel (P): your OpenPGP keys ('secretvault pgp'), S/MIME keys
// ('secretvault smime'), age identities ('secretvault age'), and
// identity files ('secretvault identity'). Signing, decrypting and
// encrypting files are tools (tools.go), in the ':' menu.

// pgpRef, smimeRef and ageRef are the panel's rows.
type (
	pgpRef   struct{ e svrpc.Entry }
	smimeRef struct{ k svrpc.SMIMEKey }
	ageRef   struct{ e svrpc.Entry }
)

func (u *UI) showKeys() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Keys · "+vault, "ITEM", "FINGERPRINT / PUBLIC KEY", "FOR")
	p.vault = vault
	p.setHead(svops.KeysInVaultNote + " Signing, decrypting and encrypting files are in the : menu, under Tools.")
	p.reload = func() {
		var entries []svrpc.Entry
		var smime []svrpc.SMIMEKey
		var smimeErr error
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if entries, err = c.List(ctx, vault, ""); err != nil {
				return err
			}
			smime, smimeErr = c.SMIMEKeys(ctx, vault)
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			p.heading("OpenPGP keys")
			pgp := svops.PGPKeyEntries(entries)
			if len(pgp) == 0 {
				p.none("None (n makes one).")
			}
			for _, e := range pgp {
				p.row(pgpRef{e}, e.Item.Name, svops.GroupFingerprint(e.Item.Attrs[svrpc.PGPFingerprint]), e.Item.Attrs[svrpc.PGPUserID])
			}
			p.heading("S/MIME keys")
			switch {
			case smimeErr != nil:
				p.none(u.describe(smimeErr))
			case len(smime) == 0:
				p.none("None (m imports one).")
			}
			for _, k := range smime {
				sum := k.SHA256
				if len(sum) > 16 {
					sum = sum[:16]
				}
				p.row(smimeRef{k}, k.Item, sum, strings.Join(k.Emails, ", ")+", until "+k.NotAfter.Local().Format("2006-01-02"))
			}
			p.heading("age identities")
			n := 0
			for _, e := range entries {
				if rcpt := e.Item.Attrs[svops.AgeRecipientName]; rcpt != "" {
					p.row(ageRef{e}, e.Item.Name, rcpt[:min(40, len(rcpt))]+"…", e.Item.Label)
					n++
				}
			}
			if n == 0 {
				p.none("None (k makes one).")
			}
			p.done()
		})
	}
	isPGP, isAge := is[pgpRef], is[ageRef]
	p.act('n', "New OpenPGP key…", func() { u.newPGPKey(vault, p.refresh) })
	p.act('i', "Import an OpenPGP key…", func() { u.importPGPKey(vault, p.refresh) })
	p.rowAct('c', "Copy the public key", isPGP, func(ref any) { u.copyPGPPublic(vault, ref.(pgpRef).e.Item.Name) })
	p.rowAct('e', "Export it…", isPGP, func(ref any) { u.exportPGPKey(vault, ref.(pgpRef).e.Item.Name) })
	p.act('g', "Let gpg use the vault's keys…", func() { u.gpgSetup(vault) })
	p.act('m', "Import an S/MIME key (.p12)…", func() { u.importSMIME(vault, p.refresh) })
	p.act('k', "New age identity…", func() { u.newAgeIdentity(vault, p.refresh) })
	p.rowAct('r', "Copy the public key (recipient)", isAge, func(ref any) { u.copyAge(vault, ref.(ageRef).e.Item.Name, false) })
	p.rowAct('l', "Copy the identity line (for age and SOPS)", isAge, func(ref any) { u.copyAge(vault, ref.(ageRef).e.Item.Name, true) })
	p.act('f', "New identity file…", u.newIdentityFile)
	p.act('p', "Show an identity file's public key…", u.identityFileRecipient)
	p.enter = nil
	p.show()
}

// newPGPKey is 'secretvault pgp new'.
func (u *UI) newPGPKey(vault string, then func()) {
	f := u.newForm("New OpenPGP key in "+vault, "The key is made and kept in the vault. "+svops.PGPVersionNote)
	name := f.text("Your name", "", "as people will see it")
	emails := f.text("Your addresses", "", "several separated by commas")
	version := f.choice("Version", []string{"6", "4 (for GnuPG 2.4 and older)"}, 0)
	item := f.text("Item name", "", "Leave empty for pgp/ADDRESS")
	days := f.text("Expires after", "", "days (empty: never)")
	f.show("Make the key", func() string {
		p := svrpc.PGPGenerateParams{Vault: vault, Item: trimmed(item), Name: trimmed(name), Emails: splitList(trimmed(emails)), Version: 6}
		if p.Name == "" && len(p.Emails) == 0 {
			return "Give a name, or an address."
		}
		if i, _ := version.GetCurrentOption(); i == 1 {
			p.Version = 4
		}
		if s := trimmed(days); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return "The days are a number."
			}
			p.LifetimeDays = n
		}
		var k svrpc.PGPKey
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			k, err = c.GeneratePGP(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Made a version %d OpenPGP key, stored as %s: %s", k.Version, k.Item, svops.GroupFingerprint(k.Fingerprint))
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// importPGPKey is 'secretvault pgp import FILE' (svops.PGPImportItem,
// svops.StorePGPKey). A protected key's passphrase is asked for when the
// key turns out to need it.
func (u *UI) importPGPKey(vault string, then func()) {
	f := u.newForm("Import an OpenPGP key into "+vault, "One secret key of yours, from a file. Someone else's public key goes to Contacts instead.")
	path := f.path("Key file", "", "")
	item := f.text("Item name", "", "Leave empty for pgp/ADDRESS")
	f.show("Import the key", func() string {
		pth := filePath(path)
		if pth == "" {
			return "Give the key's file."
		}
		data, err := os.ReadFile(pth)
		if err != nil {
			return err.Error()
		}
		name := trimmed(item)
		var it svrpc.Item
		var fp string
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(data)
			it, fp, err = svops.PGPImportItem(data, pth, name, func() ([]byte, error) {
				return u.askFromWorker(ctx, "Passphrase of the key", "The key is protected: its passphrase unlocks it, and is kept beside it in the item.", "Passphrase", true)
			})
			if err != nil {
				return err
			}
			defer svops.Wipe(&it)
			return svops.StorePGPKey(ctx, c, vault, it)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Imported %s as %s", svops.GroupFingerprint(fp), it.Name)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// copyPGPPublic is 'secretvault pgp pub KEY', to the clipboard.
func (u *UI) copyPGPPublic(vault, key string) {
	var k svrpc.PGPKey
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		k, err = c.PGPPublicKey(ctx, vault, key)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.copyValue([]byte(k.PublicKey))
	})
}

// exportPGPKey is 'secretvault pgp export KEY [--secret [--unprotected]]
// -o FILE'.
func (u *UI) exportPGPKey(vault, key string) {
	f := u.newForm("Export "+key, "The public key is for anyone. A secret key taken out of the vault can be used by whoever gets the file, without asking you: it is protected with a new passphrase, unless you say otherwise.")
	what := f.choice("Export", []string{"the public key", "the secret key, under a new passphrase", "the secret key, unprotected"}, 0)
	path := f.path("To the file", "", "")
	replace := f.check("Replace the file if it is there", false)
	pass := f.secret("New passphrase")
	again := f.secret("Repeat it")
	f.show("Export the key", func() string {
		pth := filePath(path)
		if pth == "" {
			return "Give the file to write."
		}
		if problem := replaceProblem(pth, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		i, _ := what.GetCurrentOption()
		var newPass []byte
		if i == 1 {
			if problem := newPassphraseProblem(pass, again); problem != "" {
				return problem
			}
			newPass = pass.value()
		}
		note := ""
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			defer clear(newPass)
			k, err := c.PGPPublicKey(ctx, vault, key)
			if err != nil {
				return err
			}
			data := []byte(k.PublicKey)
			if i > 0 {
				e, err := c.Get(ctx, vault, k.Item)
				if err != nil {
					return err
				}
				defer svops.Wipe(&e.Item)
				f, ok := svops.Field(&e.Item, svrpc.PGPSecretField)
				if !ok {
					return fmt.Errorf("%s has no secret key", k.Item)
				}
				data = f.Value
				if i == 1 {
					if data, err = svops.ProtectPGPKey(&e.Item, func() ([]byte, error) { return append([]byte(nil), newPass...), nil }); err != nil {
						return err
					}
					defer clear(data)
				} else if _, protected := svops.Field(&e.Item, svrpc.PGPPassField); protected {
					note = fmt.Sprintf(" The key is protected by the passphrase in its item's %q field.", svrpc.PGPPassField)
				}
			}
			return writeOut(pth, data, 0o600, rep)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Wrote %s.%s", pth, note)
		})
		return ""
	})
}

// replaceProblem says when path is there and is not to be replaced.
func replaceProblem(path string, replace bool) string {
	if _, err := os.Lstat(path); err == nil && !replace {
		return path + " exists: tick Replace to write over it, or choose another name."
	}
	return ""
}

// writeOut writes data to path through a file that appears only once it
// is whole (svops.CreateAtomic), as the CLI's -o does; over a file that is
// there only with replace, even one that appeared meanwhile.
func writeOut(path string, data []byte, mode os.FileMode, replace bool) error {
	f, err := svops.CreateAtomic(path, mode)
	if err != nil {
		return err
	}
	defer f.Abort()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return commitOut(f, replace)
}

// commitOut puts a result in place: over what is there with replace,
// else only where nothing is.
func commitOut(f *svops.AtomicFile, replace bool) error {
	if replace {
		return f.Commit()
	}
	if err := f.CommitNew(); errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s appeared meanwhile: tick Replace to write over it, or choose another name", f.Name())
	} else if err != nil {
		return err
	}
	return nil
}

// importSMIME is 'secretvault smime import FILE.p12'.
func (u *UI) importSMIME(vault string, then func()) {
	f := u.newForm("Import an S/MIME key into "+vault, "A PKCS #12 file (.p12 or .pfx): your certificate and its private key, for signed and encrypted mail.")
	path := f.path("File", "", "")
	pass := f.secret("The file's password")
	item := f.text("Item name", "", "Leave empty for smime/ADDRESS")
	f.show("Import the key", func() string {
		pth := filePath(path)
		if pth == "" {
			return "Give the file."
		}
		data, err := os.ReadFile(pth)
		if err != nil {
			return err.Error()
		}
		params := svrpc.SMIMEImportParams{Vault: vault, Item: trimmed(item), PKCS12: data, Password: pass.value()}
		var k svrpc.SMIMEKey
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(params.PKCS12)
			defer clear(params.Password)
			k, err = c.ImportSMIME(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Imported %s: %s, for %s, until %s", k.Item, k.Subject, strings.Join(k.Emails, ", "), k.NotAfter.Local().Format("2006-01-02"))
			if len(k.Warnings) > 0 {
				u.showText("S/MIME key", "note: "+tview.Escape(strings.Join(k.Warnings, "\nnote: ")))
			}
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// newAgeIdentity is 'secretvault age keygen' (svops.GenerateAgeIdentity,
// svops.StoreAgeIdentity).
func (u *UI) newAgeIdentity(vault string, then func()) {
	f := u.newForm("New age identity in "+vault, svops.AgeNote)
	name := f.text("Item name", "", "like age/backups")
	pq := f.check("Post-quantum (ML-KEM-768 + X25519, age 1.3 or later)", false)
	out := f.path("Also write the identity line to", "", "a new file (optional)")
	f.show("Make the identity", func() string {
		r, err := svops.AgeItemRef(vault, trimmed(name))
		if err != nil {
			return err.Error()
		}
		outPath := filePath(out)
		postQuantum := pq.IsChecked()
		var k *svops.AgeKey
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			n, err := svops.GenerateAgeIdentity(postQuantum)
			if err != nil {
				return err
			}
			defer n.Wipe()
			if k, err = svops.StoreAgeIdentity(ctx, c, r, n); err != nil {
				return err
			}
			if outPath != "" {
				return svops.WriteNew(outPath, k.File)
			}
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Stored a new %s age identity as %s (revision %s)", k.Kind, r.Item, svops.Short(k.Entry.Rev))
			if then != nil {
				then()
			}
			u.showCode("age identity "+r.Item, []onceLine{
				{text: "Its public key (recipient), for anyone to encrypt to:"},
				{secret: []byte(k.Recipient)},
				{},
				{text: "Its identity line, for age -i and SOPS (it names the item; it holds no secret):"},
				{secret: []byte(k.Plugin)},
			}, nil)
		})
		return ""
	})
}

// copyAge is 'secretvault age recipient ITEM', or with plugin 'secretvault
// age identity ITEM', to the clipboard.
func (u *UI) copyAge(vault, item string, plugin bool) {
	var text string
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		r := svrpc.Ref{Vault: vault, Item: item}
		if !plugin {
			text, err = svops.AgeItemRecipient(ctx, c, r)
			return err
		}
		name, err := svops.VaultName(ctx, c, vault)
		if err != nil {
			return err
		}
		text, err = svops.AgePluginIdentity(name, item)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.copyValue([]byte(text))
	})
}

// newIdentityFile is 'secretvault identity new --out FILE'.
func (u *UI) newIdentityFile() {
	f := u.newForm("New identity file", svops.IdentityFileNote)
	out := f.path("File", "", "a new file")
	suites := make([]string, len(svops.IdentitySuites))
	for i, s := range svops.IdentitySuites {
		suites[i] = s.Text
	}
	suite := f.choice(svops.SuiteLabel, suites, 0)
	f.show("Make the file", func() string {
		pth := filePath(out)
		if pth == "" {
			return "Give the new file's path."
		}
		si, _ := suite.GetCurrentOption()
		rcpt, body, err := svops.NewIdentity(svops.IdentitySuites[max(0, si)].Name, "identity")
		if err != nil {
			return err.Error()
		}
		defer clear(body)
		if err := svops.WriteNew(pth, body); err != nil {
			return err.Error()
		}
		u.say("Wrote %s", pth)
		u.showCode("Identity file made", []onceLine{{text: svops.IdentityMadeNote}, {secret: []byte(rcpt)}}, nil)
		return ""
	})
}

// identityFileRecipient is 'secretvault identity pub FILE'.
func (u *UI) identityFileRecipient() {
	f := u.newForm("Public key of an identity file", "The public key (recipient) of the identity in a file, to give to people who share vaults with you.")
	path := f.path("Identity file", "", "")
	f.show("Show the public key", func() string {
		rcpt, err := svops.IdentityRecipient(filePath(path))
		if err != nil {
			return err.Error()
		}
		u.post(func() { u.showCode("Public key (recipient)", []onceLine{{secret: []byte(rcpt)}}, nil) })
		return ""
	})
}

// askFromWorker puts a question up from a goroutine other than the
// interface's (svops asking for a key's passphrase, an age plugin for a
// PIN), and waits for the answer. A secret is typed masked; the caller
// wipes it.
func (u *UI) askFromWorker(ctx context.Context, title, intro, label string, secret bool) ([]byte, error) {
	ch := make(chan []byte, 1)
	answer := func(v []byte) {
		select {
		case ch <- v:
		default:
			clear(v)
		}
	}
	var f *formDialog
	u.post(func() {
		f = u.newForm(title, intro)
		var s *secretInput
		var in *tview.InputField
		if secret {
			s = f.secret(label)
		} else {
			in = f.text(label, "", "")
		}
		f.onCancel = func() { answer(nil) }
		f.show("Continue", func() string {
			if secret {
				answer(s.value())
			} else {
				answer([]byte(trimmed(in)))
			}
			return ""
		})
	})
	select {
	case v := <-ch:
		if v == nil {
			return nil, svrpc.ErrCanceled
		}
		return v, nil
	case <-ctx.Done():
		// The question goes, whether it is up or still waiting.
		u.post(func() {
			if f != nil {
				f.cancel()
			}
			select {
			case v := <-ch: // answered as it went
				clear(v)
			default:
			}
		})
		return nil, ctx.Err()
	case <-u.done:
		return nil, svrpc.ErrCanceled
	}
}

// confirmFromWorker asks yes or no from another goroutine. No is first,
// and answers Enter: a question that comes while someone types is not
// taken for a yes.
func (u *UI) confirmFromWorker(ctx context.Context, title, text, yes string) bool {
	ch := make(chan bool, 1)
	answer := func(v bool) {
		select {
		case ch <- v:
		default:
		}
	}
	id := -1
	u.post(func() {
		m := tview.NewModal().SetText(text).AddButtons([]string{"Cancel", yes})
		m.SetTitle(" " + tview.Escape(title) + " ")
		m.SetDoneFunc(func(_ int, label string) {
			answer(label == yes)
			u.closeDialog(id)
		})
		id = u.openDialog(m, m, func() { answer(false) })
	})
	select {
	case v := <-ch:
		return v
	case <-ctx.Done():
		u.post(func() { u.closeDialog(id) })
		return false
	case <-u.done:
		return false
	}
}
