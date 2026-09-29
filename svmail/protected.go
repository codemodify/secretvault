package svmail

import (
	"fmt"
	"slices"
	"strings"
)

// Header protection: RFC 9788, and the older "Memory Hole" draft it grew
// from. The header fields of the part below the signature and encryption
// layers (the cryptographic payload's root) are the protected ones when
// its Content-Type says so: hp="cipher" or hp="clear", or
// protected-headers="v1". An encrypted message records what the sender
// put outside in HP-Outer fields, so a changed outer field can be told
// from one the sender hid on purpose.

// ProtectedHeaders are header fields a signature or encryption protects.
type ProtectedHeaders struct {
	// Form is "rfc9788" or "memory-hole".
	Form string `json:"form"`
	// HP is RFC 9788's hp parameter: "cipher" for an encrypted message,
	// "clear" for one that is only signed. Empty for Memory Hole.
	HP string `json:"hp,omitempty"`

	// Headers are the protected fields decoded for showing, as
	// Report.Headers are; Fields are all of them.
	Headers Headers       `json:"headers"`
	Fields  []HeaderField `json:"fields"`

	// SignedBy and EncryptedBy are the layers protecting them. Signed
	// says a valid signature covers them; Encrypted, that they were
	// encrypted.
	SignedBy    []int `json:"signed_by,omitempty"`
	EncryptedBy []int `json:"encrypted_by,omitempty"`
	Signed      bool  `json:"signed"`
	Encrypted   bool  `json:"encrypted"`

	// Differences are where the message's own header fields differ from
	// the protected ones.
	Differences []HeaderDiff `json:"differences,omitempty"`

	// FromAddress is the protected From's bare address.
	FromAddress string `json:"from_address,omitempty"`
}

// HeaderField is one header field, decoded for showing.
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Kinds of difference between an outer and a protected header field.
const (
	// DiffMismatch: the outer field differs and nothing says the sender
	// made it so. It may have been changed on the way; show the
	// protected one, and warn.
	DiffMismatch = "mismatch"
	// DiffObscured: the sender replaced the field outside on purpose (an
	// HP-Outer field records it, or it is a known placeholder such as
	// "[...]").
	DiffObscured = "obscured"
	// DiffRemoved: the field is only inside; the sender left it out
	// outside.
	DiffRemoved = "removed"
	// DiffUnprotected: the field is only outside, where anyone could have
	// added it.
	DiffUnprotected = "unprotected"
)

// HeaderDiff is one difference.
type HeaderDiff struct {
	Name      string `json:"name"`
	Outer     string `json:"outer,omitempty"`
	Protected string `json:"protected,omitempty"`
	Kind      string `json:"kind"`
}

// The fields compared, and warned about when they differ.
var comparedFields = []string{"From", "Sender", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID"}

// Placeholders senders put in an encrypted message's outer Subject.
var subjectPlaceholders = []string{"...", "[...]", "…", "encrypted message", "encrypted subject", "pep", "p≡p"}

// structural fields describe the part, not the message.
func structural(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "content-") || n == "mime-version" || n == "hp-outer" || n == "autocrypt-gossip"
}

func (in *inspector) protectedHeaders() {
	p := in.payload
	if p == nil {
		return
	}
	c := in.payloadCtx
	hp := strings.ToLower(p.Params["hp"])
	ph := &ProtectedHeaders{Form: "rfc9788", HP: hp}
	switch {
	case hp == "cipher" || hp == "clear":
	case strings.EqualFold(p.Params["protected-headers"], "v1"):
		ph.Form, ph.HP = "memory-hole", ""
	default:
		in.gossip(p.Header, c)
		return
	}
	var fields Header
	hpOuter := map[string][]string{}
	for _, f := range p.Header {
		if strings.EqualFold(f.Name, "HP-Outer") {
			name, value, ok := strings.Cut(f.Value, ":")
			if ok {
				k := strings.ToLower(strings.TrimSpace(name))
				hpOuter[k] = append(hpOuter[k], strings.TrimSpace(value))
			}
			continue
		}
		if structural(f.Name) {
			continue
		}
		fields = append(fields, f)
		ph.Fields = append(ph.Fields, HeaderField{Name: f.Name, Value: DecodeHeader(f.Value)})
	}
	ph.Headers = decodeHeaders(fields)
	ph.FromAddress = ph.Headers.FromAddress
	ph.SignedBy, ph.EncryptedBy = c.signedBy, c.encryptedBy
	ph.Encrypted = len(c.encryptedBy) > 0
	for _, id := range c.signedBy {
		for _, s := range in.layer(id).Signatures {
			if s.Status == StatusValid {
				ph.Signed = true
			}
		}
	}
	in.r.Protected = ph

	names := slices.Clone(comparedFields)
	for _, f := range fields {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, f.Name) }) {
			names = append(names, f.Name)
		}
	}
	for _, name := range names {
		prot, outer := fields.Values(name), in.outer.Values(name)
		pv, ov := joinNorm(prot), joinNorm(outer)
		important := slices.ContainsFunc(comparedFields, func(n string) bool { return strings.EqualFold(n, name) })
		switch {
		case len(prot) == 0 && len(outer) == 0:
			continue
		case len(prot) == 0:
			// Only outside: worth saying for the fields people read.
			if important {
				ph.Differences = append(ph.Differences, HeaderDiff{Name: name, Outer: DecodeHeader(strings.Join(outer, ", ")), Kind: DiffUnprotected})
			}
			continue
		case len(outer) == 0:
			ph.Differences = append(ph.Differences, HeaderDiff{Name: name, Protected: DecodeHeader(strings.Join(prot, ", ")), Kind: DiffRemoved})
			continue
		case sameValue(name, pv, ov):
			continue
		}
		d := HeaderDiff{Name: name, Outer: DecodeHeader(strings.Join(outer, ", ")), Protected: DecodeHeader(strings.Join(prot, ", ")), Kind: DiffMismatch}
		if recorded, ok := hpOuter[strings.ToLower(name)]; ok {
			// The sender said what it put outside: it matches, or the
			// outer field was changed after sending.
			if sameValue(name, joinNorm(recorded), ov) {
				d.Kind = DiffObscured
			}
		} else if hp != "clear" && strings.EqualFold(name, "Subject") && slices.Contains(subjectPlaceholders, strings.ToLower(ov)) {
			d.Kind = DiffObscured
		}
		ph.Differences = append(ph.Differences, d)
		if d.Kind == DiffMismatch {
			in.warn(WarnHeaderMismatch, fmt.Sprintf("the message's %s (%q) differs from the protected %s (%q)", name, d.Outer, name, d.Protected), 0)
		}
	}
	in.gossip(p.Header, c)
}

// joinNorm joins a field's values, decoded, with white space collapsed.
func joinNorm(values []string) string {
	var parts []string
	for _, v := range values {
		parts = append(parts, strings.Join(strings.Fields(DecodeHeader(v)), " "))
	}
	return strings.Join(parts, ", ")
}

// sameValue compares two values of a field: address fields by their
// addresses and names, others as text.
func sameValue(name, a, b string) bool {
	if a == b {
		return true
	}
	switch strings.ToLower(name) {
	case "from", "sender", "reply-to", "to", "cc":
		la, err1 := addressParser.ParseList(a)
		lb, err2 := addressParser.ParseList(b)
		if err1 != nil || err2 != nil || len(la) != len(lb) {
			return false
		}
		for i := range la {
			if !strings.EqualFold(la[i].Address, lb[i].Address) || la[i].Name != lb[i].Name {
				return false
			}
		}
		return true
	}
	return false
}
