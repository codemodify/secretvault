package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svrpc"
)

// cmdMail is `secretvault mail inspect`: what a mail client would be told
// about a message.
func (c *cli) cmdMail(args []string) error {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(c.stderr, "secretvault mail: inspect FILE|- [--decrypt] [--json] [--min-level LEVEL]")
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
	var msg []byte
	if pos[0] == "-" {
		msg, err = io.ReadAll(io.LimitReader(c.stdin, svrpc.MaxMessage/2))
	} else {
		msg, err = os.ReadFile(pos[0])
	}
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
