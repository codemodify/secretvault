package svmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Tools: signing, checking and decrypting files with OpenPGP, encrypting
// and decrypting them with age, inspecting and composing mail, and the
// person's side of what programs read from vaults: what a reference
// names, and whether an env file's or a template's references resolve.
// The daemon signs and decrypts (the secret keys stay in it); what is
// written goes to a file that appears only once it is whole.

// signFile signs a file with one of your OpenPGP keys (the CLI's pgp
// sign): a detached signature, or the message with its signature.
func (m *Manager) signFile() {
	if m.gone || m.vault == "" {
		m.fail(errNoVault)
		return
	}
	vault := m.vault
	m.withPGPKeys(vault, func(keys []string) {
		f := m.newForm("Sign a file")
		in := f.path("File", PickOpen, "")
		key := f.choice("Key", append([]string{"your only key"}, keys...), 0)
		mode := f.choice("Write", []string{"the signature alone (detached)", "the file with its signature (inline)", "readable text with its signature (cleartext)"}, 0)
		armor := f.check("Armored (text) rather than binary", true)
		text := f.check("A text signature, which ignores line endings", false)
		out := f.path("Write to", PickSave, "")
		f.note("Write to: default the file's name with .sig, or .asc when armored.")
		f.show("Sign", func() {
			path := in.Path()
			if path == "" {
				f.fail("Choose the file.")
				return
			}
			params := svrpc.PGPSignParams{Vault: vault, Mode: []string{svrpc.SignDetached, svrpc.SignInline, svrpc.SignCleartext}[max(0, mode.Selected)],
				Armor: armor.Checked, Text: text.Checked}
			if i := key.Selected - 1; i >= 0 && i < len(keys) {
				params.Key = keys[i]
			}
			dst := out.Path()
			if dst == "" {
				dst = path + ".sig"
				if params.Armor || params.Mode == svrpc.SignCleartext {
					dst = path + ".asc"
				}
			}
			var res svrpc.PGPSignResult
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				if params.Data, err = os.ReadFile(path); err != nil {
					return err
				}
				if res, err = c.SignPGP(ctx, params); err != nil {
					return err
				}
				return writeAtomic(dst, 0o644, res.Signature)
			}, func() {
				m.say("Signed with %s; wrote %s.", res.Item, dst)
			})
		})
	})
}

// withPGPKeys lists the vault's OpenPGP keys, for choosing one.
func (m *Manager) withPGPKeys(vault string, then func([]string)) {
	var entries []svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.List(ctx, vault, "")
		return err
	}, func(err error) {
		if errors.Is(err, svrpc.ErrCanceled) {
			m.fail(err)
			return
		}
		var names []string
		for _, e := range svops.PGPKeyEntries(entries) {
			names = append(names, e.Item.Name)
		}
		then(names)
	})
}

// signaturesText says what each signature is, as the CLI's pgp verify and
// decrypt do.
func signaturesText(sigs []svrpc.PGPSignature) string {
	var b strings.Builder
	for _, s := range sigs {
		switch {
		case s.Verdict != nil:
			fmt.Fprintf(&b, "Signature: %s\n", s.Verdict.Status)
			if !s.Valid {
				fmt.Fprintf(&b, "  The signature is not valid: %s.\n", s.Error)
			}
			for _, r := range s.Verdict.Reasons {
				if !strings.HasPrefix(r, "The signature is not valid") {
					fmt.Fprintf(&b, "  %s\n", r)
				}
			}
		case s.Valid:
			fmt.Fprintf(&b, "Signature: valid, by %s (not checked against your contacts)\n", svops.GroupFingerprint(s.Signer))
		default:
			fmt.Fprintf(&b, "Signature: not checked (%s), by %s\n", s.Error, s.Issuer)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// verifyFile checks a file's OpenPGP signature against the contacts (the
// CLI's pgp verify).
func (m *Manager) verifyFile() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Check a signature")
	in := f.path("File", PickOpen, "")
	sig := f.path("Signature", PickOpen, "")
	f.note("Signature: its own file, for a detached one; leave it empty when the file is a signed message.")
	from := f.text("From", "", "the address the file claims to be from")
	out := f.path("Its text to", PickSave, "")
	f.note("Its text to: optional, for a signed message: where to write what it says.")
	f.show("Check", func() {
		path := in.Path()
		if path == "" {
			f.fail("Choose the file.")
			return
		}
		params := svrpc.PGPVerifyParams{From: strings.TrimSpace(from.Text)}
		sigPath, dst := sig.Path(), out.Path()
		var res svrpc.PGPVerifyResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Data, err = os.ReadFile(path); err != nil {
				return err
			}
			if sigPath != "" {
				if params.Signature, err = os.ReadFile(sigPath); err != nil {
					return err
				}
			}
			if res, err = c.VerifyPGP(ctx, params); err != nil {
				return err
			}
			if dst != "" && res.Body != nil {
				return writeAtomic(dst, 0o644, res.Body)
			}
			return nil
		}, func() {
			verdict := "No valid signature."
			valid := false
			for _, s := range res.Signatures {
				if s.Valid && s.Verdict != nil && s.Verdict.Trusted {
					verdict = "A valid signature, by a signer your contacts verify."
					break
				}
				valid = valid || s.Valid
			}
			if verdict == "No valid signature." && valid {
				verdict = "A valid signature, but by a signer your contacts do not verify."
			}
			m.showText("The signature", verdict, signaturesText(res.Signatures))
		})
	})
}

// decryptPGPFile decrypts an OpenPGP file with whichever of your keys it is
// for (the CLI's pgp decrypt), into a new file only you can read, and
// checks its signatures if asked.
func (m *Manager) decryptPGPFile() {
	if m.gone || m.vault == "" {
		m.fail(errNoVault)
		return
	}
	vault := m.vault
	m.withPGPKeys(vault, func(keys []string) {
		f := m.newForm("Decrypt a file (OpenPGP)")
		in := f.path("File", PickOpen, "")
		out := f.path("Write to", PickSave, "")
		key := f.choice("Key", append([]string{"the key it is encrypted to"}, keys...), 0)
		verify := f.check("Check the signatures inside against your contacts", false)
		from := f.text("From", "", "with the check: the address it claims to be from")
		f.show("Decrypt", func() {
			path, dst := in.Path(), out.Path()
			if path == "" || dst == "" {
				f.fail("Choose the file, and where its plaintext goes.")
				return
			}
			params := svrpc.PGPDecryptParams{Vault: vault, From: strings.TrimSpace(from.Text)}
			params.Verify = verify.Checked || params.From != ""
			if i := key.Selected - 1; i >= 0 && i < len(keys) {
				params.Key = keys[i]
			}
			var res svrpc.PGPDecryptResult
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				if params.Data, err = os.ReadFile(path); err != nil {
					return err
				}
				if res, err = c.DecryptPGP(ctx, params); err != nil {
					return err
				}
				defer clear(res.Body)
				return writeAtomic(dst, 0o600, res.Body)
			}, func() {
				text := signaturesText(res.Signatures)
				for _, w := range res.Warnings {
					text += "\nwarning: " + w
				}
				m.say("Decrypted with %s; wrote %s.", res.Item, dst)
				if strings.TrimSpace(text) != "" {
					m.showText("Decrypted", "Decrypted with "+res.Item+" into "+dst+", which only you can read.", strings.TrimSpace(text))
				}
			})
		})
	})
}

// pluginUI lets other age plugins (a YubiKey's, say) talk to the person
// here, from the goroutine the work runs on.
func (m *Manager) pluginUI() *svage.PluginUI {
	return &svage.PluginUI{
		DisplayMessage: func(name, msg string) error {
			m.post(func() { m.say("age-plugin-%s: %s", name, msg) })
			return nil
		},
		RequestValue: func(name, prompt string, _ bool) ([]byte, error) {
			return m.askSecret("age-plugin-"+name, strings.TrimSpace(prompt), "", false, 1)
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			return m.askYes("age-plugin-"+name, strings.TrimSpace(prompt), yes, no)
		},
	}
}

// encryptAgeFile encrypts a file with age (the CLI's age encrypt): to
// recipients typed, read from a file, the vault's identities and your
// contacts' SSH keys, or to a passphrase.
func (m *Manager) encryptAgeFile() {
	if m.gone {
		m.fail(errGone)
		return
	}
	vault := m.vault
	var ids []svrpc.Entry
	var contacts []svrpc.Contact
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		if vault != "" {
			if entries, err := c.List(ctx, vault, ""); err == nil {
				ids = svops.AgeKeyEntries(entries)
			} else if errors.Is(err, svrpc.ErrCanceled) {
				return err
			}
		}
		contacts, _ = c.Contacts(ctx, "", "")
		return nil
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		f := m.newForm("Encrypt a file (age)")
		in := f.path("File", PickOpen, "")
		out := f.path("Write to", PickSave, "")
		// The recipients, one a line: offered from the vault and the
		// contacts, and typed.
		var offers []string
		var lines []string
		for _, e := range ids {
			offers = append(offers, "my identity "+e.Item.Name)
			lines = append(lines, svrpc.Ref{Vault: vault, Item: e.Item.Name}.String())
		}
		for _, c := range contacts {
			for _, k := range c.Keys {
				if k.Type == "ssh" && k.State == "" && len(k.Material) > 0 {
					offers = append(offers, c.Name+"'s SSH key "+k.Label)
					lines = append(lines, strings.TrimSpace(string(k.Material)))
				}
			}
		}
		rcpts := widgets.NewMonoTextArea("", "age1…, ssh-ed25519 …, sv://VAULT/ITEM: one a line", nil)
		rcpts.SetAccessibleName("Recipients")
		rcpts.MinRows = 3
		f.row("Recipients", rcpts)
		if len(offers) > 0 {
			add := f.choice("Add", append([]string{"one of yours or a contact's…"}, offers...), 0)
			add.OnChange = func(i int) {
				if i > 0 && i-1 < len(lines) {
					t := strings.TrimRight(rcpts.Text, "\n")
					if t != "" {
						t += "\n"
					}
					rcpts.SetText(t + lines[i-1])
					add.Selected = 0
				}
			}
		}
		rfile := f.path("Recipients file", PickOpen, "")
		pass := f.check("To a passphrase instead (asked for twice)", false)
		armor := f.check("Armored (text) rather than binary", false)
		mixed := f.check("Let post-quantum and classical recipients share it (it is then only as safe as X25519)", false)
		f.show("Encrypt", func() {
			path, dst := in.Path(), out.Path()
			if path == "" || dst == "" {
				f.fail("Choose the file, and where it goes encrypted.")
				return
			}
			var args []string
			for _, l := range strings.Split(rcpts.Text, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					args = append(args, l)
				}
			}
			rf, usePass := rfile.Path(), pass.Checked
			switch {
			case usePass && (len(args) > 0 || rf != ""):
				f.fail("A passphrase must be a file's only recipient: clear the recipients, or untick the passphrase.")
				return
			case !usePass && len(args) == 0 && rf == "":
				f.fail("Give a recipient, or tick the passphrase.")
				return
			}
			armored, mix := armor.Checked, mixed.Checked
			f.call(func(ctx context.Context, c *secretvault.Client) error {
				itemRecipient := func(r svrpc.Ref) (string, error) { return svops.AgeItemRecipient(ctx, c, r) }
				var recipients []svage.Recipient
				for _, a := range args {
					r, err := svops.AgeRecipient(a, itemRecipient, m.pluginUI())
					if err != nil {
						return fmt.Errorf("%.40s: %w", a, err)
					}
					recipients = append(recipients, r)
				}
				if rf != "" {
					b, err := os.ReadFile(rf)
					if err != nil {
						return err
					}
					if err := svops.EachKeyLine(b, func(n int, line []byte) error {
						r, err := svops.AgeRecipient(string(line), itemRecipient, m.pluginUI())
						if err != nil {
							return fmt.Errorf("%s:%d: %w", rf, n, err)
						}
						recipients = append(recipients, r)
						return nil
					}); err != nil {
						return err
					}
				}
				if usePass {
					p, err := m.askSecret("The file's passphrase", "Passphrase", "Whoever has it opens the file.", true, minPassphrase)
					if err != nil {
						return err
					}
					sr, err := svage.NewScryptRecipient(p)
					clear(p)
					if err != nil {
						return err
					}
					defer sr.Wipe()
					recipients = append(recipients, sr)
				}
				src, err := os.Open(path)
				if err != nil {
					return err
				}
				defer src.Close()
				a, err := svops.CreateAtomic(dst, 0o644)
				if err != nil {
					return err
				}
				defer a.Abort()
				if err := svops.AgeEncrypt(a, src, recipients, armored, mix); err != nil {
					return err
				}
				return a.Commit()
			}, func() {
				m.say("Encrypted %s into %s.", filepath.Base(path), dst)
			})
		})
	})
}

// decryptAgeFile decrypts an age file (the CLI's age decrypt) with the
// vault's identities, an identity file, or a passphrase, into a new file
// only you can read.
func (m *Manager) decryptAgeFile() {
	if m.gone {
		m.fail(errGone)
		return
	}
	vault := m.vault
	var ids []svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		if vault == "" {
			return nil
		}
		entries, err := c.List(ctx, vault, "")
		if errors.Is(err, svrpc.ErrCanceled) {
			return err
		}
		ids = svops.AgeKeyEntries(entries)
		return nil
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		f := m.newForm("Decrypt a file (age)")
		in := f.path("File", PickOpen, "")
		out := f.path("Write to", PickSave, "")
		names := []string{"none of the vault's"}
		for _, e := range ids {
			names = append(names, e.Item.Name)
		}
		which := f.choice("Identity", names, min(1, len(ids)))
		idFile := f.path("Identity file", PickOpen, "")
		f.note("Identity file: optional: age's, a plugin's, or an SSH private key. With no identity, the file's passphrase is asked for.")
		f.show("Decrypt", func() {
			path, dst := in.Path(), out.Path()
			if path == "" || dst == "" {
				f.fail("Choose the file, and where its plaintext goes.")
				return
			}
			var args []string
			if i := which.Selected - 1; i >= 0 && i < len(ids) {
				args = append(args, svrpc.Ref{Vault: vault, Item: ids[i].Item.Name}.String())
			}
			if p := idFile.Path(); p != "" {
				args = append(args, p)
			}
			f.call(func(ctx context.Context, c *secretvault.Client) error {
				opts := svops.AgeIdentityOptions{
					Vault: func(r svrpc.Ref) svage.Identity {
						return &svops.VaultIdentity{Ref: r, Fetch: func(r svrpc.Ref) (svage.Identity, error) {
							return svops.LoadAgeIdentity(ctx, c, r)
						}}
					},
					UI: m.pluginUI(),
					SSHPassphrase: func(p string) ([]byte, error) {
						return m.askSecret("The SSH key's passphrase", "Passphrase", "The key in "+filepath.Base(p)+" is protected by a passphrase.", false, 1)
					},
				}
				var list []svage.Identity
				for _, a := range args {
					more, err := svops.AgeIdentities(a, opts)
					if err != nil {
						return err
					}
					list = append(list, more...)
				}
				byPassphrase := len(list) == 0
				if byPassphrase {
					list = append(list, svops.PassphraseIdentity{Ask: func() ([]byte, error) {
						return m.askSecret("The file's passphrase", "Passphrase", filepath.Base(path)+" is encrypted to a passphrase.", false, 1)
					}})
				}
				src, err := os.Open(path)
				if err != nil {
					return err
				}
				defer src.Close()
				r, err := svops.AgeDecrypt(src, list)
				if err != nil {
					if byPassphrase && errors.Is(err, svage.ErrIncorrectIdentity) {
						return errors.New("the file is not encrypted to a passphrase: choose an identity of the vault, or an identity file")
					}
					return err
				}
				a, err := svops.CreateAtomic(dst, 0o600)
				if err != nil {
					return err
				}
				defer a.Abort()
				if _, err := io.Copy(a, r); err != nil {
					return err
				}
				return a.Commit()
			}, func() {
				m.say("Decrypted %s into %s, which only you can read.", filepath.Base(path), dst)
			})
		})
	})
}

// inspectMessage says what a message is (the CLI's mail inspect): its
// signers, judged against the contacts, its encryption, and its text,
// decrypted if asked.
func (m *Manager) inspectMessage() {
	if m.gone {
		m.fail(errGone)
		return
	}
	vault := m.vault
	f := m.newForm("Inspect a message")
	in := f.path("Message", PickOpen, "")
	f.note("A message as it was received (.eml).")
	decrypt := f.check("Decrypt what is encrypted to your keys", false)
	levels := make([]string, len(minLevels))
	for i, l := range minLevels {
		levels[i] = l.text
	}
	least := f.choice("Signers count from", levels, 0)
	f.show("Inspect", func() {
		path := in.Path()
		if path == "" {
			f.fail("Choose the message.")
			return
		}
		params := svrpc.MailInspectParams{Decrypt: decrypt.Checked, Vault: vault, MinLevel: minLevels[max(0, least.Selected)].level}
		var rep svmail.Report
		var res svrpc.MailInspectResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Message, err = svops.ReadMessage(path, nil); err != nil {
				return err
			}
			if res, err = c.InspectMail(ctx, params); err != nil {
				return err
			}
			return json.Unmarshal(res.Report, &rep)
		}, func() {
			m.showMailReport(&rep, res.Verdicts)
		})
	})
}

// showMailReport shows what a message is: its headers, its layers and
// their signatures with the trust store's verdicts, its warnings, and its
// text parts, each masked until shown (a decrypted one is a secret).
func (m *Manager) showMailReport(rep *svmail.Report, verdicts []svrpc.MailVerdict) {
	h, where := rep.Headers, ""
	if rep.Protected != nil {
		h, where = rep.Protected.Headers, " (protected)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Signed: %s   Encrypted: %s\n", rep.Signed, rep.Encrypted)
	for _, l := range rep.Layers {
		fmt.Fprintf(&b, "\n%s %s, covering the %s", l.Format, l.Kind, l.Covers)
		if l.Part != "" {
			fmt.Fprintf(&b, " (part %s)", l.Part)
		}
		b.WriteString(":\n")
		if l.Error != "" {
			fmt.Fprintf(&b, "  could not be read: %s\n", l.Error)
		}
		if e := l.Encryption; e != nil {
			if e.Decrypted {
				fmt.Fprintf(&b, "  decrypted with %s (%s, integrity: %s)\n", e.DecryptedWith, e.Cipher, e.Integrity)
			} else {
				fmt.Fprintf(&b, "  not decrypted: %s\n", e.Error)
			}
		}
		for i, s := range l.Signatures {
			who := s.Fingerprint
			if who == "" && s.Certificate != nil {
				who = s.Certificate.Subject
			}
			if who == "" {
				who = s.Issuer
			}
			fmt.Fprintf(&b, "  signature: %s, by %s\n", s.Status, who)
			if s.Error != "" {
				fmt.Fprintf(&b, "    %s\n", s.Error)
			}
			for _, v := range verdicts {
				if v.Layer == l.ID && v.Index == i {
					fmt.Fprintf(&b, "    %s\n", v.Verdict.Status)
					for _, r := range v.Verdict.Reasons {
						fmt.Fprintf(&b, "    %s\n", r)
					}
				}
			}
		}
	}
	if len(rep.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range rep.Warnings {
			fmt.Fprintf(&b, "  %s\n", w.Message)
		}
	}
	col := widgets.NewColumn(m.facts([][2]string{{"From", h.From + where}, {"Subject", h.Subject + where}})).WithGap(12)
	view := widgets.NewMonoTextView(strings.TrimRight(b.String(), "\n"), "")
	view.SetAccessibleName("The message's layers")
	view.MinRows = 8
	col.Add(view)
	var texts []*secretText
	var held [][]byte
	for _, p := range rep.Parts {
		if p.Text == "" || p.LegacyDisplay {
			continue
		}
		v := []byte(p.Text)
		held = append(held, v)
		t := newSecretText(v)
		t.wrap = true
		t.SetAccessibleName(p.ContentType)
		texts = append(texts, t)
		show := widgets.NewButton("Show", nil)
		show.OnClick = func() {
			t.SetReveal(!t.Revealed())
			show.Text = showLabel(t.Revealed(), false)
			show.RequestLayout()
			m.syncCapture()
		}
		col.Add(widgets.NewRow(m.muted(p.ContentType), show).WithGap(gap))
		col.Add(t)
	}
	var d *dialog
	ok := widgets.NewButton("Close", func() { d.Close() })
	d = m.showDialog("The message", widgets.NewHeightBox(460, widgets.NewScrollView(col)), widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, func() {
		for _, t := range texts {
			t.Forget()
		}
		for _, v := range held {
			clear(v)
		}
	})
}

// composeMessage signs a message with your key and encrypts it to your
// contacts' (the CLI's mail compose), ready to send.
func (m *Manager) composeMessage() {
	if m.gone {
		m.fail(errGone)
		return
	}
	vault := m.vault
	f := m.newForm("Sign and encrypt a message")
	in := f.path("Message", PickOpen, "")
	f.note("A plain message as written (.eml), with its From and To.")
	sign := f.check("Sign it with your key for its From address", true)
	encrypt := f.check("Encrypt it to every recipient's key, and yours", true)
	format := f.choice("As", []string{"OpenPGP where everyone has a key for it, else S/MIME", "OpenPGP", "S/MIME"}, 0)
	key := f.text("Your key", "", "optional: the item, fingerprint or address to sign with")
	out := f.path("Write to", PickSave, "message.eml")
	f.show("Write", func() {
		path, dst := in.Path(), out.Path()
		if path == "" || dst == "" {
			f.fail("Choose the message, and where it goes.")
			return
		}
		if !sign.Checked && !encrypt.Checked {
			f.fail("Sign it, encrypt it, or both.")
			return
		}
		params := svrpc.MailComposeParams{Sign: sign.Checked, Encrypt: encrypt.Checked, Format: []string{"", "openpgp", "smime"}[max(0, format.Selected)],
			Key: strings.TrimSpace(key.Text), Vault: vault}
		var res svrpc.MailComposeResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Message, err = svops.ReadMessage(path, nil); err != nil {
				return err
			}
			if res, err = c.ComposeMail(ctx, params); err != nil {
				return err
			}
			return svops.WriteMessage(dst, res.Message)
		}, func() {
			how := res.Format
			if res.SignedWith != "" {
				how += ", signed with " + res.SignedWith
			}
			if len(res.EncryptedTo) > 0 {
				how += ", encrypted to " + strings.Join(res.EncryptedTo, ", ")
			}
			m.say("Wrote %s (%s).", dst, how)
		})
	})
}

// resolveReference shows what a reference names (the CLI's read): the
// value, masked until shown, and copied from its bytes.
func (m *Manager) resolveReference() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Resolve a reference")
	ref := f.text("Reference", "", "sv://VAULT/ITEM#FIELD, - for the default vault")
	f.note("What a program given this reference reads: the field it names, or the item's secret.")
	f.show("Resolve", func() {
		r, err := svrpc.ParseRef(ref.Text)
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		var v []byte
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			v, err = svops.Resolve(ctx, c, r)
			return err
		}, func() {
			t := newSecretText(v)
			t.wrap = true
			t.SetAccessibleName("Value")
			show := widgets.NewButton("Show", nil)
			show.OnClick = func() {
				t.SetReveal(!t.Revealed())
				show.Text = showLabel(t.Revealed(), false)
				show.RequestLayout()
				m.syncCapture()
			}
			vault := r.Vault
			copyBtn := widgets.NewButton("Copy", func() { m.copyValue(v, "The value", vault) })
			body := widgets.NewColumn(m.paragraph(r.String()+" names:"), widgets.NewRow(t, show, copyBtn).WithGap(gap)).WithGap(12)
			var d *dialog
			ok := widgets.NewButton("Close", func() { d.Close() })
			d = m.showDialog("Resolved", body, widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, func() {
				t.Forget()
				clear(v)
			})
		})
	})
}

// refCheck is one reference, and whether it resolves.
type refCheck struct {
	name, ref, result string
}

// checkRefs resolves each reference, as the program given them would,
// keeping no value: whether it resolves, or why not.
func checkRefs(ctx context.Context, c *secretvault.Client, names, refs []string) []refCheck {
	var out []refCheck
	for i, s := range refs {
		rc := refCheck{name: names[i], ref: s, result: "resolves"}
		r, err := svrpc.ParseRef(s)
		if err == nil {
			var v []byte
			if v, err = svops.Resolve(ctx, c, r); err == nil {
				clear(v)
			}
		}
		if err != nil {
			rc.result = err.Error()
		}
		out = append(out, rc)
	}
	return out
}

// showRefChecks shows what checkRefs found.
func (m *Manager) showRefChecks(title, intro string, checks []refCheck) {
	var b strings.Builder
	ok := 0
	for _, c := range checks {
		if c.name != "" {
			fmt.Fprintf(&b, "%s = %s: %s\n", c.name, c.ref, c.result)
		} else {
			fmt.Fprintf(&b, "%s: %s\n", c.ref, c.result)
		}
		if c.result == "resolves" {
			ok++
		}
	}
	m.showText(title, fmt.Sprintf("%s %d of %s resolve.", intro, ok, plural(len(checks), "reference")), strings.TrimRight(b.String(), "\n"))
}

// checkEnvFile reads env files as the CLI's run loads them
// (svops.Environ), and resolves each sv:// reference in them, keeping no
// value: the person's side of run.
func (m *Manager) checkEnvFile() {
	if m.gone {
		m.fail(errGone)
		return
	}
	m.pickFile(PickOpen, "", func(path string) {
		if path == "" {
			return
		}
		var checks []refCheck
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			env := svops.NewEnviron(nil)
			if err := env.LoadFiles([]string{path}); err != nil {
				return err
			}
			names := env.Refs()
			refs := make([]string, len(names))
			for i, k := range names {
				refs[i] = env.Get(k)
			}
			checks = checkRefs(ctx, c, names, refs)
			return nil
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.showRefChecks("References in "+filepath.Base(path), "secretvault run --env-file "+filepath.Base(path)+" resolves them as it starts a command:", checks)
		})
	})
}

// checkTemplate finds a template's {{ sv://… }} references as the CLI's
// inject does (svops.TemplateRefs), and resolves each, keeping no value;
// and fills the template into a new file if asked (svops.Inject).
func (m *Manager) checkTemplate() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Check a template")
	in := f.path("Template", PickOpen, "")
	out := f.path("Fill it into", PickSave, "")
	f.note("Fill it into: optional: a new file, only yours to read, with each reference replaced by what it names, as secretvault inject writes it.")
	f.show("Check", func() {
		path, dst := in.Path(), out.Path()
		if path == "" {
			f.fail("Choose the template.")
			return
		}
		var checks []refCheck
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			tmpl, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			refs := svops.TemplateRefs(tmpl)
			checks = checkRefs(ctx, c, make([]string, len(refs)), refs)
			if dst == "" {
				return nil
			}
			result, err := svops.Inject(tmpl, func(r svrpc.Ref) ([]byte, error) { return svops.Resolve(ctx, c, r) })
			if err != nil {
				return err
			}
			defer clear(result)
			return svops.WriteNew(dst, result)
		}, func() {
			intro := ""
			if dst != "" {
				intro = "Filled into " + dst + "."
			}
			m.showRefChecks("References in "+filepath.Base(path), intro, checks)
		})
	})
}
