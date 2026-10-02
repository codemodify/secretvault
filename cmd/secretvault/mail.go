package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// cmdMail is `secretvault mail inspect`: what a mail client would be told
// about a message.
func (c *cli) cmdMail(args []string) error {
	if len(args) > 0 && args[0] == "compose" {
		return c.mailCompose(args[1:])
	}
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(c.stderr, "secretvault mail: inspect FILE|- [--decrypt] [--json] [--min-level LEVEL]")
		fmt.Fprintln(c.stderr, "                  compose FILE|- [--sign] [--encrypt] [--format openpgp|smime] [-o OUT]")
		return errUsage
	}
	fs := c.flags("mail inspect")
	decrypt := fs.Bool("decrypt", false, "decrypt what is encrypted to your keys (asked about as decrypting)")
	asJSON := fs.Bool("json", false, "print the whole report and the verdicts as JSON")
	minLevel := fs.String("min-level", "", "the verification level a signer must have to be trusted")
	contacts := fs.String("contacts", "", "the contacts vault (default: the configured one)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args[1:], 1, 1, "FILE|- [--decrypt] [--json] [--min-level LEVEL]   (a message as received, .eml)")
	if err != nil {
		return err
	}
	msg, err := svops.ReadMessage(pos[0], c.stdin)
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.InspectMail(ctx, svrpc.MailInspectParams{Message: msg, Decrypt: *decrypt, Vault: c.vault, Contacts: *contacts, MinLevel: *minLevel})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	var rep svmail.Report
	if err := json.Unmarshal(res.Report, &rep); err != nil {
		return err
	}
	c.printMail(&rep, res.Verdicts)
	return nil
}

func (c *cli) printMail(rep *svmail.Report, verdicts []svrpc.MailVerdict) {
	w := c.stdout
	h, where := rep.Headers, ""
	if rep.Protected != nil {
		h, where = rep.Protected.Headers, " (protected)"
	}
	fmt.Fprintf(w, "From:    %s%s\nSubject: %s%s\n", h.From, where, h.Subject, where)
	fmt.Fprintf(w, "Signed: %s   Encrypted: %s\n", rep.Signed, rep.Encrypted)
	for _, l := range rep.Layers {
		fmt.Fprintf(w, "\n%s %s, covering the %s", l.Format, l.Kind, l.Covers)
		if l.Part != "" {
			fmt.Fprintf(w, " (part %s)", l.Part)
		}
		fmt.Fprintln(w, ":")
		if l.Error != "" {
			fmt.Fprintf(w, "  could not be read: %s\n", l.Error)
		}
		if e := l.Encryption; e != nil {
			if e.Decrypted {
				fmt.Fprintf(w, "  decrypted with %s (%s, integrity: %s)\n", e.DecryptedWith, e.Cipher, e.Integrity)
			} else {
				fmt.Fprintf(w, "  not decrypted: %s\n", e.Error)
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
			fmt.Fprintf(w, "  signature: %s, by %s\n", s.Status, who)
			if s.Error != "" {
				fmt.Fprintf(w, "    %s\n", s.Error)
			}
			for _, v := range verdicts {
				if v.Layer == l.ID && v.Index == i {
					fmt.Fprintf(w, "    %s\n", v.Verdict.Status)
					for _, r := range v.Verdict.Reasons {
						fmt.Fprintf(w, "    %s\n", r)
					}
				}
			}
		}
	}
	for _, p := range rep.Parts {
		if p.Text == "" || p.LegacyDisplay {
			continue
		}
		fmt.Fprintf(w, "\n--- %s ---\n%s", p.ContentType, p.Text)
		if !strings.HasSuffix(p.Text, "\n") {
			fmt.Fprintln(w)
		}
	}
	if len(rep.Warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		for _, wn := range rep.Warnings {
			fmt.Fprintf(w, "  %s\n", wn.Message)
		}
	}
}

// mailCompose is `secretvault mail compose`: a message signed with your
// key and encrypted to your contacts', ready to send.
func (c *cli) mailCompose(args []string) error {
	fs := c.flags("mail compose")
	sign := fs.Bool("sign", false, "sign with your key for the From address")
	encrypt := fs.Bool("encrypt", false, "encrypt to every recipient's key, and yours")
	format := fs.String("format", "", "openpgp or smime (default: OpenPGP where everyone has a key for it)")
	key := fs.String("key", "", "your key to sign with (default: the one for From)")
	out := fs.String("o", "-", "write the message to `FILE`")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE|- [--sign] [--encrypt] [--format openpgp|smime] [-o OUT]")
	if err != nil {
		return err
	}
	msg, err := svops.ReadMessage(pos[0], c.stdin)
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.ComposeMail(ctx, svrpc.MailComposeParams{Message: msg, Sign: *sign, Encrypt: *encrypt, Format: *format, Key: *key, Vault: c.vault})
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = c.stdout.Write(res.Message)
		return err
	}
	if err := svops.WriteMessage(*out, res.Message); err != nil {
		return err
	}
	how := res.Format
	if res.SignedWith != "" {
		how += ", signed with " + res.SignedWith
	}
	if len(res.EncryptedTo) > 0 {
		how += ", encrypted to " + strings.Join(res.EncryptedTo, ", ")
	}
	fmt.Fprintf(c.stderr, "Wrote %s (%s).\n", *out, how)
	return nil
}

// cmdSMIME is `secretvault smime import|ls`: your S/MIME keys.
func (c *cli) cmdSMIME(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	fs := c.flags("smime " + args[0])
	var u unlockFlags
	u.register(fs)
	switch args[0] {
	case "import":
		passFile := fs.String("password-file", "", "the file's password, in `FILE` (default: asked for)")
		item := fs.String("item", "", "the item to keep it in (default: smime/ADDRESS)")
		pos, err := parse(fs, args[1:], 1, 1, "FILE.p12 [--password-file F] [--item NAME]")
		if err != nil {
			return err
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		defer clear(data)
		var pass []byte
		switch {
		case *passFile != "":
			pass, err = svops.ReadSecretFile(*passFile)
		case c.canAsk:
			pass, err = c.ask("Password of " + filepath.Base(pos[0]) + ": ")
		}
		if err != nil {
			return err
		}
		defer clear(pass)
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		k, err := cl.ImportSMIME(ctx, svrpc.SMIMEImportParams{Vault: c.vault, Item: *item, PKCS12: data, Password: pass})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Imported %s: %s, for %s, until %s.\n", k.Item, k.Subject, strings.Join(k.Emails, ", "), k.NotAfter.Local().Format("2006-01-02"))
		for _, w := range k.Warnings {
			fmt.Fprintln(c.stdout, "  note: "+w)
		}
		return nil
	case "ls", "list":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		ks, err := cl.SMIMEKeys(ctx, c.vault)
		if err != nil {
			return err
		}
		if len(ks) == 0 {
			fmt.Fprintln(c.stdout, "No S/MIME keys: import one with 'secretvault smime import FILE.p12'.")
			return nil
		}
		for _, k := range ks {
			fmt.Fprintf(c.stdout, "%s  %s  %s  until %s\n", k.Item, strings.Join(k.Emails, ","), k.SHA256[:16], k.NotAfter.Local().Format("2006-01-02"))
		}
		return nil
	}
	fmt.Fprintln(c.stderr, "secretvault smime: import FILE.p12 | ls")
	return errUsage
}
