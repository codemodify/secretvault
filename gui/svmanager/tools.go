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

	"github.com/codemodify/uitoolkit/widget"
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
		f.intro(svops.SignFileAbout)
		in := f.path("File to sign", PickOpen, "")
		key := f.choice("Sign with", append([]string{"your only key"}, keys...), 0)
		mode := f.choice("Make", []string{"a signature file (detached)", "the file, signed (inline)", "readable text, signed (cleartext)"}, 0)
		armor := f.check("As text (armored), not binary", true)
		text := f.check("A text signature, which ignores line endings", false)
		out := f.path("Save the signature to", PickSave, "")
		out.field.Placeholder = "Default: beside the file"
		f.show("Sign the file", func() {
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
			m.replacing(dst, func() {
				f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
					if params.Data, err = os.ReadFile(path); err != nil {
						return err
					}
					if res, err = c.SignPGP(ctx, params); err != nil {
						return err
					}
					return writeAtomic(dst, 0o644, res.Signature)
				}, func() {
					m.say("Signed %s with %s: the signature is in %s.", filepath.Base(path), res.Item, dst)
				})
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
	f.intro(svops.CheckSignatureAbout)
	in := f.path("Signed file", PickOpen, "")
	sig := f.path("Signature file", PickOpen, "")
	sig.field.Placeholder = "Empty if it is inside the file"
	from := f.text("Sent from", "", "optional: the address it claims to come from")
	out := f.path("Save its text to", PickSave, "")
	out.field.Placeholder = "Optional: where its text goes"
	f.show("Check the signature", func() {
		path := in.Path()
		if path == "" {
			f.fail("Choose the file.")
			return
		}
		params := svrpc.PGPVerifyParams{From: strings.TrimSpace(from.Text)}
		sigPath, dst := sig.Path(), out.Path()
		var res svrpc.PGPVerifyResult
		m.replacing(dst, func() {
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
				m.showText("Signature checked", verdict, signaturesText(res.Signatures))
			})
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
		f.intro(svops.DecryptPGPAbout)
		in := f.path("Encrypted file", PickOpen, "")
		out := f.path("Save it decrypted to", PickSave, "")
		key := f.choice("Decrypt with", append([]string{"the key it is encrypted to"}, keys...), 0)
		verify := f.check("Check the signatures inside against your contacts", false)
		from := f.text("Sent from", "", "with the check, optional: the address it claims to come from")
		f.show("Decrypt the file", func() {
			path, dst := in.Path(), out.Path()
			if path == "" || dst == "" {
				f.fail("Choose the file, and where it goes decrypted.")
				return
			}
			params := svrpc.PGPDecryptParams{Vault: vault, From: strings.TrimSpace(from.Text)}
			params.Verify = verify.Checked || params.From != ""
			if i := key.Selected - 1; i >= 0 && i < len(keys) {
				params.Key = keys[i]
			}
			var res svrpc.PGPDecryptResult
			m.replacing(dst, func() {
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
					m.say("Decrypted %s with %s into %s, which only you can read.", filepath.Base(path), res.Item, dst)
					if strings.TrimSpace(text) != "" {
						m.showText("Decrypted", "Decrypted "+filepath.Base(path)+" with "+res.Item+" into "+dst+", which only you can read. What its signatures say:", strings.TrimSpace(text))
					}
				})
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
		f.intro(svops.EncryptAgeAbout)
		in := f.path("File to encrypt", PickOpen, "")
		out := f.path("Save it encrypted to", PickSave, "")
		// The recipients, one a line: offered from the vault and the
		// contacts, and typed.
		var offers []string
		var lines []string
		for _, e := range ids {
			offers = append(offers, "my age key "+e.Item.Name)
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
		rcpts := widgets.NewMonoTextArea("", "Public keys, one a line: age1…, ssh-ed25519 …", nil)
		rcpts.SetAccessibleName("Who can open it")
		rcpts.MinRows = 3
		f.row("Who can open it", rcpts)
		if len(offers) > 0 {
			add := f.choice("Add a key", append([]string{"one of yours or a contact's…"}, offers...), 0)
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
		rfile := f.path("Or keys from a file", PickOpen, "")
		rfile.field.Placeholder = "Optional: a file of public keys, one a line"
		pass := f.check("Use a passphrase instead (asked for twice)", false)
		armor := f.check("As text (armored), not binary", false)
		mixed := f.check("Mix post-quantum and classical keys (less safe)", false)
		f.show("Encrypt the file", func() {
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
				f.fail("A file encrypted to a passphrase can have no keys besides: clear the keys, or untick the passphrase.")
				return
			case !usePass && len(args) == 0 && rf == "":
				f.fail("Add the key of whoever is to open it, or tick the passphrase.")
				return
			}
			armored, mix := armor.Checked, mixed.Checked
			m.replacing(dst, func() {
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
						p, err := m.askSecret("The file's passphrase", "Passphrase", "Whoever has it opens the file.", true, 1)
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
		f.intro(svops.DecryptAgeAbout)
		in := f.path("Encrypted file", PickOpen, "")
		out := f.path("Save it decrypted to", PickSave, "")
		// Any number of the vault's identities, and of identity files, as
		// the CLI's -i takes them, each tried in turn.
		boxes := make([]*widgets.Checkbox, len(ids))
		if len(ids) > 0 {
			list := widgets.NewColumn().WithGap(4)
			for i, e := range ids {
				boxes[i] = widgets.NewCheckbox(e.Item.Name, i == 0, nil)
				list.Add(boxes[i])
			}
			f.row("Your age keys", list)
		}
		idFile := f.path("Or key files", PickOpen, "")
		idFile.field.Placeholder = "Optional: age or SSH private key files, separated by commas"
		f.show("Decrypt the file", func() {
			path, dst := in.Path(), out.Path()
			if path == "" || dst == "" {
				f.fail("Choose the file, and where it goes decrypted.")
				return
			}
			var args []string
			for i, b := range boxes {
				if b.Checked {
					args = append(args, svrpc.Ref{Vault: vault, Item: ids[i].Item.Name}.String())
				}
			}
			args = append(args, splitList(idFile.Path())...)
			m.replacing(dst, func() {
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
							return errors.New("the file is not encrypted to a passphrase: choose one of your age keys, or a key file")
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
	f.intro(svops.InspectMessageAbout)
	in := f.path("Message", PickOpen, "")
	decrypt := f.check("Decrypt what is encrypted to your keys", false)
	levels := make([]string, len(minLevels))
	for i, l := range minLevels {
		levels[i] = l.text
	}
	least := f.choice("Counts as verified", levels, 0)
	contactVaults := []string{"the vault contacts are kept in"}
	for _, v := range m.vaults {
		contactVaults = append(contactVaults, v.Name)
	}
	contacts := f.choice("Contacts", contactVaults, 0)
	f.show("Inspect the message", func() {
		path := in.Path()
		if path == "" {
			f.fail("Choose the message.")
			return
		}
		params := svrpc.MailInspectParams{Decrypt: decrypt.Checked, Vault: vault, MinLevel: minLevels[max(0, least.Selected)].level}
		if i := contacts.Selected; i > 0 && i < len(contactVaults) {
			params.Contacts = contactVaults[i]
		}
		var rep svmail.Report
		var res svrpc.MailInspectResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Message, err = svops.ReadMessage(path, nil); err != nil {
				return err
			}
			if res, err = c.InspectMail(ctx, params); err != nil {
				return err
			}
			err = json.Unmarshal(res.Report, &rep)
			clear(res.Report) // it holds the decrypted text too
			return err
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
	var texts []*secretText
	var held [][]byte
	// masked shows a value masked until shown: a decrypted part, or the
	// header fields an encryption protected.
	masked := func(label string, v []byte) widget.Component {
		held = append(held, v)
		t := newSecretText(v)
		t.wrap = true
		t.SetAccessibleName(label)
		texts = append(texts, t)
		show := widgets.NewButton("Show", nil)
		show.SetAccessibleName("Show the " + strings.ToLower(label))
		show.OnClick = func() {
			t.SetReveal(!t.Revealed())
			show.Text = showLabel(t.Revealed(), false)
			show.RequestLayout()
			m.syncCapture()
		}
		return widgets.NewColumn(widgets.NewRow(m.muted(label), show).WithGap(gap), t).WithGap(4)
	}
	col := widgets.NewColumn().WithGap(12)
	if where != "" {
		col.Add(masked("From"+where, []byte(h.From)))
		col.Add(masked("Subject"+where, []byte(h.Subject)))
	} else {
		col.Add(m.facts([][2]string{{"From", h.From}, {"Subject", h.Subject}}))
	}
	// The layers, as tall as they are: no small box to scroll inside.
	view := newDetailText(strings.Split(strings.TrimRight(b.String(), "\n"), "\n"))
	view.name = "The message's layers"
	col.Add(view)
	for _, p := range rep.Parts {
		if p.Text == "" || p.LegacyDisplay {
			continue
		}
		col.Add(masked(p.ContentType, []byte(p.Text)))
	}
	var d *dialog
	ok := widgets.NewButton("Close", func() { d.Close() })
	// The dialog scrolls a message longer than the window (uitoolkit-gaps.md, 40).
	d = m.showDialog("The message", col, widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, func() {
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
	f.intro(svops.ComposeMessageAbout)
	in := f.path("Message", PickOpen, "")
	sign := f.check("Sign it with your key for its From address", true)
	encrypt := f.check("Encrypt it to the key of everyone it is to, and yours", true)
	format := f.choice("Format", []string{"OpenPGP if all have a key, else S/MIME", "OpenPGP", "S/MIME"}, 0)
	key := f.text("Your key", "", "optional: its item, fingerprint or address")
	out := f.path("Save the result to", PickSave, "message.eml")
	f.show("Sign and encrypt", func() {
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
		m.replacing(dst, func() {
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
	f.intro(svops.ResolveReferenceAbout)
	ref := f.text("Reference", "", "sv://vault/item or sv://vault/item#field; sv://-/… for the default vault")
	f.show("Show what it names", func() {
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
			// The value wraps to what its column is given, beside its
			// buttons.
			value := widgets.NewGrid()
			value.Cols = []widgets.Track{widgets.Share(1), widgets.Auto(), widgets.Auto()}
			value.ColGap = gap
			value.Place(t, 0, 0)
			value.Place(show, 0, 1)
			value.Place(copyBtn, 0, 2)
			body := widgets.NewColumn(m.paragraph(r.String()+" names:"), value).WithGap(12)
			var d *dialog
			ok := widgets.NewButton("Close", func() { d.Close() })
			d = m.showDialog("Resolved", body, widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, func() {
				t.Forget()
				clear(v)
			})
		})
	})
}

// refCheck is one reference, and whether it resolves: err is why not.
type refCheck struct {
	name, ref string
	err       error
}

// checkRefs resolves each reference, as the program given them would,
// keeping no value: whether it resolves, or why not.
func checkRefs(ctx context.Context, c *secretvault.Client, names, refs []string) []refCheck {
	var out []refCheck
	for i, s := range refs {
		rc := refCheck{name: names[i], ref: s}
		r, err := svrpc.ParseRef(s)
		if err == nil {
			var v []byte
			if v, err = svops.Resolve(ctx, c, r); err == nil {
				clear(v)
			}
		}
		rc.err = err
		out = append(out, rc)
	}
	return out
}

// showRefChecks shows what checkRefs found: how many can be read, then
// each, and why one cannot.
func (m *Manager) showRefChecks(title, intro string, checks []refCheck) {
	var b strings.Builder
	ok := 0
	for _, c := range checks {
		result := "can be read"
		if c.err != nil {
			result = "cannot be read: " + m.describe(c.err)
		} else {
			ok++
		}
		if c.name != "" {
			fmt.Fprintf(&b, "%s = %s: %s\n", c.name, c.ref, result)
		} else {
			fmt.Fprintf(&b, "%s: %s\n", c.ref, result)
		}
	}
	summary := strings.TrimSpace(intro + " " + svops.ReferencesChecked(ok, len(checks)))
	m.showText(title, summary, strings.TrimRight(b.String(), "\n"))
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
			m.showRefChecks("References in "+filepath.Base(path), "", checks)
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
	f.intro(svops.CheckTemplateAbout)
	in := f.path("Template", PickOpen, "")
	out := f.path("Fill it into", PickSave, "")
	out.field.Placeholder = "Optional: a new file, with the secrets filled in"
	f.show("Check the template", func() {
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
				intro = "Filled into " + dst + ", which only you can read."
			}
			m.showRefChecks("References in "+filepath.Base(path), intro, checks)
		})
	})
}
