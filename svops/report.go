package svops

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svrpc"
)

// What every interface says about a message the daemon took apart
// (mail.inspect) and about OpenPGP signatures (pgp.decrypt, pgp.verify).

// MailText says what a mail client would be told about a message: its
// headers, how it was signed and encrypted, each layer and signature with
// the verdict on its signer, its text, and the warnings.
func MailText(rep *svmail.Report, verdicts []svrpc.MailVerdict) string {
	var w strings.Builder
	h, where := rep.Headers, ""
	if rep.Protected != nil {
		h, where = rep.Protected.Headers, " (protected)"
	}
	fmt.Fprintf(&w, "From:    %s%s\nSubject: %s%s\n", h.From, where, h.Subject, where)
	fmt.Fprintf(&w, "Signed: %s   Encrypted: %s\n", rep.Signed, rep.Encrypted)
	for _, l := range rep.Layers {
		fmt.Fprintf(&w, "\n%s %s, covering the %s", l.Format, l.Kind, l.Covers)
		if l.Part != "" {
			fmt.Fprintf(&w, " (part %s)", l.Part)
		}
		fmt.Fprintln(&w, ":")
		if l.Error != "" {
			fmt.Fprintf(&w, "  could not be read: %s\n", l.Error)
		}
		if e := l.Encryption; e != nil {
			if e.Decrypted {
				fmt.Fprintf(&w, "  decrypted with %s (%s, integrity: %s)\n", e.DecryptedWith, e.Cipher, e.Integrity)
			} else {
				fmt.Fprintf(&w, "  not decrypted: %s\n", e.Error)
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
			fmt.Fprintf(&w, "  signature: %s, by %s\n", s.Status, who)
			if s.Error != "" {
				fmt.Fprintf(&w, "    %s\n", s.Error)
			}
			for _, v := range verdicts {
				if v.Layer == l.ID && v.Index == i {
					fmt.Fprintf(&w, "    %s\n", v.Verdict.Status)
					for _, r := range v.Verdict.Reasons {
						fmt.Fprintf(&w, "    %s\n", r)
					}
				}
			}
		}
	}
	for _, p := range rep.Parts {
		if p.Text == "" || p.LegacyDisplay {
			continue
		}
		fmt.Fprintf(&w, "\n--- %s ---\n%s", p.ContentType, p.Text)
		if !strings.HasSuffix(p.Text, "\n") {
			fmt.Fprintln(&w)
		}
	}
	if len(rep.Warnings) > 0 {
		fmt.Fprintln(&w, "\nWarnings:")
		for _, wn := range rep.Warnings {
			fmt.Fprintf(&w, "  %s\n", wn.Message)
		}
	}
	return w.String()
}

// SignatureLines say what each OpenPGP signature is: valid or not, by
// whom, and the verdict on its signer against the contacts.
func SignatureLines(sigs []svrpc.PGPSignature) []string {
	var out []string
	for _, s := range sigs {
		switch {
		case s.Verdict != nil:
			out = append(out, "Signature: "+s.Verdict.Status)
			if !s.Valid {
				out = append(out, fmt.Sprintf("  The signature is not valid: %s.", s.Error))
			}
			for _, r := range s.Verdict.Reasons {
				if !strings.HasPrefix(r, "The signature is not valid") {
					out = append(out, "  "+r)
				}
			}
		case s.Valid:
			out = append(out, fmt.Sprintf("Signature: valid, by %s (not checked against your contacts)", GroupFingerprint(s.Signer)))
		default:
			out = append(out, fmt.Sprintf("Signature: not checked (%s), by %s", s.Error, s.Issuer))
		}
	}
	return out
}
