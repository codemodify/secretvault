package svtui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Tools, in the ':' menu: signing, decrypting and checking files with
// your OpenPGP keys ('secretvault pgp sign|decrypt|verify'), encrypting
// and decrypting age files ('secretvault age encrypt|decrypt'), and
// inspecting and composing mail ('secretvault mail'). Files are read and
// written here; a result appears only once it is whole (svops.CreateAtomic),
// and replaces a file only when that is ticked.

// trimExt drops one of exts from the end of path, or adds add.
func trimExt(path string, add string, exts ...string) string {
	for _, e := range exts {
		if s, ok := strings.CutSuffix(path, e); ok && s != "" {
			return s
		}
	}
	return path + add
}

// signFile is 'secretvault pgp sign'.
func (u *UI) signFile() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	f := u.newForm("Sign a file", svops.SignFileAbout)
	in := f.path("File to sign", "", "")
	key := f.text("Sign with", "", "default: your only key")
	modes := []string{svrpc.SignDetached, svrpc.SignInline, svrpc.SignCleartext}
	mode := f.choice("Make", []string{"a signature file (detached)", "the file, signed (inline)", "readable text, signed (cleartext)"}, 0)
	armor := f.check("As text (armored)", true)
	text := f.check("A text signature (ignores line endings)", false)
	out := f.path("Save the signature to", "", "default: beside the file")
	replace := f.check("Replace the file if it is there", false)
	f.show("Sign the file", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the file to sign."
		}
		i, _ := mode.GetCurrentOption()
		dst := filePath(out)
		if dst == "" {
			dst = src + ".sig"
			if armor.IsChecked() || modes[i] == svrpc.SignCleartext {
				dst = src + ".asc"
			}
		}
		if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		data, err := os.ReadFile(src)
		if err != nil {
			return err.Error()
		}
		p := svrpc.PGPSignParams{Vault: vault, Key: trimmed(key), Data: data, Mode: modes[i], Armor: armor.IsChecked(), Text: text.IsChecked()}
		var res svrpc.PGPSignResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if res, err = c.SignPGP(ctx, p); err != nil {
				return err
			}
			return writeOut(dst, res.Signature, 0o644, rep)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Signed %s with %s: the signature is in %s", filepath.Base(src), res.Item, dst)
		})
		return ""
	})
}

// decryptPGPFile is 'secretvault pgp decrypt'.
func (u *UI) decryptPGPFile() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	f := u.newForm("Decrypt a file (OpenPGP)", svops.DecryptPGPAbout)
	in := f.path("Encrypted file", "", "")
	key := f.text("Decrypt with", "", "default: the key it is for")
	verify := f.check("Check its signatures", false)
	from := f.text("Sent from", "", "its address (optional)")
	out := f.path("Save it decrypted to", "", "default: beside the file")
	replace := f.check("Replace the file if it is there", false)
	f.show("Decrypt the file", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the file to decrypt."
		}
		dst := filePath(out)
		if dst == "" {
			dst = trimExt(src, ".out", ".gpg", ".pgp", ".asc")
		}
		if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		data, err := os.ReadFile(src)
		if err != nil {
			return err.Error()
		}
		p := svrpc.PGPDecryptParams{Vault: vault, Key: trimmed(key), Data: data, Verify: verify.IsChecked() || trimmed(from) != "", From: trimmed(from)}
		var res svrpc.PGPDecryptResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if res, err = c.DecryptPGP(ctx, p); err != nil {
				return err
			}
			defer clear(res.Body)
			return writeOut(dst, res.Body, 0o600, rep)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Decrypted %s with %s into %s, which only you can read.\n", tview.Escape(filepath.Base(src)), tview.Escape(res.Item), tview.Escape(dst))
			for _, w := range res.Warnings {
				fmt.Fprintf(&b, "\n[yellow]warning:[-] %s", tview.Escape(w))
			}
			if lines := svops.SignatureLines(res.Signatures); len(lines) > 0 {
				b.WriteString("\n\n" + tview.Escape(strings.Join(lines, "\n")))
			}
			u.say("Decrypted %s into %s, which only you can read", filepath.Base(src), dst)
			u.showText("Decrypted", b.String())
		})
		return ""
	})
}

// verifyPGPFile is 'secretvault pgp verify'.
func (u *UI) verifyPGPFile() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	f := u.newForm("Check a signature", svops.CheckSignatureAbout)
	in := f.path("Signed file", "", "")
	sig := f.path("Signature file", "", "empty if inside the file")
	from := f.text("Sent from", "", "its address (optional)")
	out := f.path("Save its text to", "", "optional")
	replace := f.check("Replace the file if it is there", false)
	f.show("Check the signature", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the file."
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return err.Error()
		}
		p := svrpc.PGPVerifyParams{Vault: vault, Data: data, From: trimmed(from)}
		if s := filePath(sig); s != "" {
			if p.Signature, err = os.ReadFile(s); err != nil {
				return err.Error()
			}
		}
		dst := filePath(out)
		if dst != "" {
			if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
				return problem
			}
		}
		rep := replace.IsChecked()
		var res svrpc.PGPVerifyResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if res, err = c.VerifyPGP(ctx, p); err != nil {
				return err
			}
			if dst != "" && res.Body != nil {
				return writeOut(dst, res.Body, 0o644, rep)
			}
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			verdict := "[red]No valid signature.[-]"
			valid := false
			for _, s := range res.Signatures {
				switch {
				case s.Valid && s.Verdict != nil && s.Verdict.Trusted:
					verdict = "[green]Signed by someone you verified.[-]"
				case s.Valid:
					valid = true
				}
			}
			if valid && !strings.HasPrefix(verdict, "[green]") {
				verdict = "[yellow]A valid signature, by someone you have not verified.[-]"
			}
			text := verdict + "\n\n" + tview.Escape(strings.Join(svops.SignatureLines(res.Signatures), "\n"))
			if dst != "" && res.Body != nil {
				text += "\n\nWrote the message's text to " + tview.Escape(dst) + "."
			}
			u.showText("Signature checked", text)
		})
		return ""
	})
}

// pluginUI lets other age plugins (a YubiKey's) talk to the person here.
func (u *UI) pluginUI(ctx context.Context) *svage.PluginUI {
	return &svage.PluginUI{
		DisplayMessage: func(name, msg string) error {
			u.post(func() { u.say("age-plugin-%s: %s", name, msg) })
			return nil
		},
		RequestValue: func(name, prompt string, secret bool) ([]byte, error) {
			return u.askFromWorker(ctx, "age-plugin-"+name, strings.TrimSpace(prompt), "Answer", secret)
		},
		Confirm: func(name, prompt, yes, _ string) (bool, error) {
			return u.confirmFromWorker(ctx, "age-plugin-"+name, strings.TrimSpace(prompt), yes), nil
		},
	}
}

// encryptAge is 'secretvault age encrypt'.
func (u *UI) encryptAge() {
	f := u.newForm("Encrypt a file (age)", svops.EncryptAgeAbout+" Name one of your own as sv://vault/item.")
	in := f.path("File to encrypt", "", "")
	rcpts := f.area("Who can open it", "", 3)
	rcpts.SetPlaceholder("public keys, one per line")
	files := f.path("Or keys from a file", "", "optional")
	pass := f.secret("Or a passphrase instead")
	again := f.secret("Repeat it")
	armor := f.check("As text (armored)", false)
	mixed := f.check("Mix PQ and classical keys (weaker)", false)
	out := f.path("Save it encrypted to", "", "default: beside the file")
	replace := f.check("Replace the file if it is there", false)
	f.show("Encrypt the file", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the file to encrypt."
		}
		var args []string
		for _, l := range strings.Split(rcpts.GetText(), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				args = append(args, l)
			}
		}
		recipientsFile := filePath(files)
		usePass := len(pass.buf) > 0
		switch {
		case usePass && (len(args) > 0 || recipientsFile != ""):
			return "A file encrypted to a passphrase can have no keys besides: clear the keys, or the passphrase."
		case usePass && string(pass.buf) != string(again.buf):
			return "The two passphrases differ."
		case !usePass && len(args) == 0 && recipientsFile == "":
			return "Give the key of whoever is to open it, or a passphrase."
		}
		dst := filePath(out)
		if dst == "" {
			dst = src + ".age"
		}
		if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		var secret []byte
		if usePass {
			secret = pass.value()
		}
		armored, mixedPQ := armor.IsChecked(), mixed.IsChecked()
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			defer clear(secret)
			ui := u.pluginUI(ctx)
			itemRecipient := func(r svrpc.Ref) (string, error) { return svops.AgeItemRecipient(ctx, c, r) }
			var recipients []svage.Recipient
			for _, a := range args {
				r, err := svops.AgeRecipient(a, itemRecipient, ui)
				if err != nil {
					return fmt.Errorf("%.40s: %w", a, err)
				}
				recipients = append(recipients, r)
			}
			if recipientsFile != "" {
				b, err := os.ReadFile(recipientsFile)
				if err != nil {
					return err
				}
				err = svops.EachKeyLine(b, func(n int, line []byte) error {
					r, err := svops.AgeRecipient(string(line), itemRecipient, ui)
					if err != nil {
						return fmt.Errorf("%s:%d: %w", recipientsFile, n, err)
					}
					recipients = append(recipients, r)
					return nil
				})
				if err != nil {
					return err
				}
			}
			if secret != nil {
				sr, err := svage.NewScryptRecipient(secret)
				if err != nil {
					return err
				}
				defer sr.Wipe()
				recipients = append(recipients, sr)
			}
			src, err := os.Open(src)
			if err != nil {
				return err
			}
			defer src.Close()
			out, err := svops.CreateAtomic(dst, 0o644)
			if err != nil {
				return err
			}
			defer out.Abort()
			if err := svops.AgeEncrypt(out, src, recipients, armored, mixedPQ); err != nil {
				return err
			}
			return commitOut(out, rep)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Encrypted %s into %s", filepath.Base(src), dst)
		})
		return ""
	})
}

// decryptAge is 'secretvault age decrypt'.
func (u *UI) decryptAge() {
	f := u.newForm("Decrypt a file (age)", svops.DecryptAgeAbout+" Name one in the vault as sv://vault/item, or give a key file's path.")
	in := f.path("Encrypted file", "", "")
	ids := f.area("Your age keys", "", 3)
	ids.SetPlaceholder("one per line (none: a passphrase)")
	out := f.path("Save it decrypted to", "", "default: beside the file")
	replace := f.check("Replace the file if it is there", false)
	f.show("Decrypt the file", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the file to decrypt."
		}
		var args []string
		for _, l := range strings.Split(ids.GetText(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				args = append(args, expandHome(l))
			}
		}
		dst := filePath(out)
		if dst == "" {
			dst = trimExt(src, ".out", ".age")
		}
		if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			ui := u.pluginUI(ctx)
			opts := svops.AgeIdentityOptions{
				Vault: func(r svrpc.Ref) svage.Identity {
					return &svops.VaultIdentity{Ref: r, Fetch: func(r svrpc.Ref) (svage.Identity, error) {
						id, err := svops.LoadAgeIdentity(ctx, c, r)
						if err != nil {
							return nil, fmt.Errorf("sv://%s/%s: %s", r.Vault, r.Item, describeErr(err))
						}
						return id, nil
					}}
				},
				UI: ui,
				SSHPassphrase: func(path string) ([]byte, error) {
					return u.askFromWorker(ctx, "Passphrase", "The SSH key "+path+" is encrypted.", "Passphrase", true)
				},
			}
			var identities []svage.Identity
			for _, a := range args {
				more, err := svops.AgeIdentities(a, opts)
				if err != nil {
					return err
				}
				identities = append(identities, more...)
			}
			if len(identities) == 0 {
				identities = append(identities, svops.PassphraseIdentity{Ask: func() ([]byte, error) {
					return u.askFromWorker(ctx, "Passphrase", "The file is encrypted to a passphrase.", "Passphrase", true)
				}})
			}
			in, err := os.Open(src)
			if err != nil {
				return err
			}
			defer in.Close()
			r, err := svops.AgeDecrypt(in, identities)
			if err != nil {
				return err
			}
			out, err := svops.CreateAtomic(dst, 0o600)
			if err != nil {
				return err
			}
			defer out.Abort()
			if _, err := io.Copy(out, r); err != nil {
				return err
			}
			return commitOut(out, rep)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Decrypted %s into %s, which only you can read", filepath.Base(src), dst)
		})
		return ""
	})
}

// inspectMail is 'secretvault mail inspect'.
func (u *UI) inspectMail() {
	vault := u.vault
	f := u.newForm("Inspect a message", svops.InspectMessageAbout)
	in := f.path("Message", "", "")
	decrypt := f.check("Decrypt what is encrypted to your keys", false)
	levels := []string{"", "tofu", "logged", "organisation", "in-person"}
	minLevel := f.choice("Counts as verified", []string{"published (the default)", "accepted as it was, or seen before", "logged", "an organisation vouches", "compared in person"}, 0)
	contacts := f.text("Contacts vault", "", "default: the one set for them")
	f.show("Inspect the message", func() string {
		src := filePath(in)
		if src == "" {
			return "Give the message's file."
		}
		msg, err := svops.ReadMessage(src, nil)
		if err != nil {
			return err.Error()
		}
		p := svrpc.MailInspectParams{Message: msg, Decrypt: decrypt.IsChecked(), Vault: vault, Contacts: trimmed(contacts)}
		if i, _ := minLevel.GetCurrentOption(); i > 0 {
			p.MinLevel = levels[i]
		}
		var res svrpc.MailInspectResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.InspectMail(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			var rep svmail.Report
			if err := json.Unmarshal(res.Report, &rep); err != nil {
				u.fail(err)
				return
			}
			u.showText("Message", tview.Escape(svops.MailText(&rep, res.Verdicts)))
		})
		return ""
	})
}

// composeMail is 'secretvault mail compose'.
func (u *UI) composeMail() {
	vault := u.vault
	f := u.newForm("Sign and encrypt a message", svops.ComposeMessageAbout)
	in := f.path("Message", "", "")
	sign := f.check("Sign it with your key", true)
	encrypt := f.check("Encrypt it to everyone it is to, and you", true)
	formats := []string{"", "openpgp", "smime"}
	format := f.choice("Format", []string{"OpenPGP if all have a key, else S/MIME", "OpenPGP", "S/MIME"}, 0)
	key := f.text("Your key", "", "default: the one for From")
	out := f.path("Save the result to", "", "")
	replace := f.check("Replace the file if it is there", false)
	f.show("Sign and encrypt", func() string {
		src, dst := filePath(in), filePath(out)
		if src == "" || dst == "" {
			return "Give the message, and where to write the result."
		}
		if problem := replaceProblem(dst, replace.IsChecked()); problem != "" {
			return problem
		}
		rep := replace.IsChecked()
		msg, err := svops.ReadMessage(src, nil)
		if err != nil {
			return err.Error()
		}
		i, _ := format.GetCurrentOption()
		p := svrpc.MailComposeParams{Message: msg, Sign: sign.IsChecked(), Encrypt: encrypt.IsChecked(), Format: formats[i], Key: trimmed(key), Vault: vault}
		if !p.Sign && !p.Encrypt {
			return "Sign it, encrypt it, or both."
		}
		var res svrpc.MailComposeResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if res, err = c.ComposeMail(ctx, p); err != nil {
				return err
			}
			if !rep {
				return svops.WriteNew(dst, res.Message) // never over a file that appeared meanwhile
			}
			return svops.WriteMessage(dst, res.Message)
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			how := res.Format
			if res.SignedWith != "" {
				how += ", signed with " + res.SignedWith
			}
			if len(res.EncryptedTo) > 0 {
				how += ", encrypted to " + strings.Join(res.EncryptedTo, ", ")
			}
			u.say("Wrote %s (%s)", dst, how)
		})
		return ""
	})
}
