package svtui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	f := u.newForm("Sign a file", "With your OpenPGP key, inside the daemon: a detached signature (the default), the file with its signature, or readable text with its signature.")
	in := f.path("File", "", "")
	key := f.text("Key", "", "default: your only key")
	modes := []string{svrpc.SignDetached, svrpc.SignInline, svrpc.SignCleartext}
	mode := f.choice("Signature", []string{"detached", "inline (the file with its signature)", "cleartext (readable text)"}, 0)
	armor := f.check("Armored (text)", true)
	text := f.check("A text signature (ignores line endings)", false)
	out := f.path("Write to", "", "default: the file .asc or .sig")
	replace := f.check("Replace the file if it is there", false)
	f.show("Sign", func() string {
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
			u.say("Signed with %s: wrote %s", res.Item, dst)
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
	f := u.newForm("Decrypt a file (OpenPGP)", "With your OpenPGP key, inside the daemon. The signatures inside are checked against your contacts if asked.")
	in := f.path("File", "", "")
	key := f.text("Key", "", "default: the key it is for")
	verify := f.check("Check the signatures inside", false)
	from := f.text("From", "", "the address it claims to be from (optional)")
	out := f.path("Write to", "", "default: the file without .gpg, .pgp or .asc")
	replace := f.check("Replace the file if it is there", false)
	f.show("Decrypt", func() string {
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
			fmt.Fprintf(&b, "Decrypted with %s; wrote %s.\n", tview.Escape(res.Item), tview.Escape(dst))
			for _, w := range res.Warnings {
				fmt.Fprintf(&b, "\n[yellow]warning:[-] %s", tview.Escape(w))
			}
			if lines := svops.SignatureLines(res.Signatures); len(lines) > 0 {
				b.WriteString("\n\n" + tview.Escape(strings.Join(lines, "\n")))
			}
			u.say("Wrote %s", dst)
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
	f := u.newForm("Check a signature", "A signed message, or a file and its detached signature: the verdict on the signer, against your contacts.")
	in := f.path("File", "", "")
	sig := f.path("Detached signature", "", "(none: the file is a signed message)")
	from := f.text("From", "", "the address it claims to be from (optional)")
	out := f.path("Write a signed message's text to", "", "(optional)")
	replace := f.check("Replace the file if it is there", false)
	f.show("Check", func() string {
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
			u.showText("Signature", text)
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
	f := u.newForm("Encrypt a file (age)", "To recipients (age1…, age1pq1…, SSH public keys, other plugins', or sv://VAULT/ITEM for an identity kept in a vault), one per line; or to a passphrase instead.")
	in := f.path("File", "", "")
	rcpts := f.area("Recipients", "", 3)
	rcpts.SetPlaceholder("one per line")
	files := f.path("Recipients file", "", "one per line (optional)")
	pass := f.secret("Or a passphrase")
	again := f.secret("Repeat it")
	armor := f.check("Armored (text)", false)
	mixed := f.check("Let post-quantum and classical recipients share it", false)
	out := f.path("Write to", "", "default: the file .age")
	replace := f.check("Replace the file if it is there", false)
	f.show("Encrypt", func() string {
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
			return "A passphrase must be a file's only recipient."
		case usePass && string(pass.buf) != string(again.buf):
			return "The two passphrases differ."
		case !usePass && len(args) == 0 && recipientsFile == "":
			return "Give recipients, or a passphrase."
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
			u.say("Encrypted: wrote %s", dst)
		})
		return ""
	})
}

// decryptAge is 'secretvault age decrypt'.
func (u *UI) decryptAge() {
	f := u.newForm("Decrypt a file (age)", "With identities (sv://VAULT/ITEM for one kept in a vault, or files of identities or SSH private keys), one per line; with none, the passphrase it was encrypted to is asked for.")
	in := f.path("File", "", "")
	ids := f.area("Identities", "", 3)
	ids.SetPlaceholder("one per line (none: a passphrase)")
	out := f.path("Write to", "", "default: the file without .age")
	replace := f.check("Replace the file if it is there", false)
	f.show("Decrypt", func() string {
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
			u.say("Decrypted: wrote %s", dst)
		})
		return ""
	})
}

// inspectMail is 'secretvault mail inspect'.
func (u *UI) inspectMail() {
	vault := u.vault
	f := u.newForm("Inspect a message", "A message as received (.eml): who signed it, judged against your contacts, how it was encrypted, and its text.")
	in := f.path("Message", "", "")
	decrypt := f.check("Decrypt what is encrypted to your keys", false)
	levels := []string{"published (the default)", "tofu", "logged", "organisation", "in-person"}
	minLevel := f.choice("Weakest verification that counts", levels, 0)
	contacts := f.text("Contacts vault", "", "default: the configured one")
	f.show("Inspect", func() string {
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
	f := u.newForm("Sign and encrypt a message", "A plain message (RFC 5322) becomes one signed with your key for its From address, and encrypted to every recipient's key and yours.")
	in := f.path("Message", "", "")
	sign := f.check("Sign it", true)
	encrypt := f.check("Encrypt it", true)
	formats := []string{"", "openpgp", "smime"}
	format := f.choice("Format", []string{"OpenPGP where everyone has a key for it, else S/MIME", "OpenPGP", "S/MIME"}, 0)
	key := f.text("Your key", "", "default: the one for From")
	out := f.path("Write to", "", "")
	replace := f.check("Replace the file if it is there", false)
	f.show("Compose", func() string {
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
