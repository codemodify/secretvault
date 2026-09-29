package svtrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Query asks about a message's signer.
type Query struct {
	// Fingerprint is the signer's key fingerprint, subkey fingerprint or
	// OpenPGP key ID, of any key type.
	Fingerprint string
	// Key is the signer's certificate or public key instead, in any form
	// ParseKeys reads.
	Key []byte
	// From is the address the message claims to be from (its From
	// header); "" asks about the key alone.
	From string
	// At is when to judge certificate chains; zero means now.
	At time.Time
}

// Verdict is what the store knows about a message's signer: facts, with
// no judgement of them (Policy judges). Reasons says it in plain words.
type Verdict struct {
	// Fingerprint is the signer's, as asked about.
	Fingerprint string
	// From is the claimed address, "" when none was given.
	From string

	// Contact holds the signer's key, and Key is that key; both are nil
	// when the store does not have it.
	Contact *Contact
	Key     *Key

	// Level is the best verification of the key for From (for the key as
	// a whole when From is ""), and Verification the event behind it.
	Level        Level
	Verification *Event
	// KeyLevel is the best verification of the key, whatever the
	// address, and KeyVerification the event behind it.
	KeyLevel        Level
	KeyVerification *Event
	// Bound says From is one of the key's addresses. Claimed says the key
	// names From itself (always true for keys that cannot name one).
	Bound, Claimed bool
	// Seen is how often the key was seen from From.
	Seen *Sighting
	// State says why the key cannot be used now ("revoked", "expired on
	// ..."), "" when it can.
	State string

	// Others are other contacts' keys bound to From.
	Others []Other

	// Reasons explain the verdict, one sentence each.
	Reasons []string
}

// Other is another contact's key bound to the address a message claims.
type Other struct {
	Contact *Contact
	Key     *Key
	Level   Level
	Event   *Event
}

// Check gives the verdict on a message's signer.
func (s *Store) Check(q Query) (*Verdict, error) {
	from := ""
	if strings.TrimSpace(q.From) != "" {
		if from = ParseAddress(q.From); from == "" {
			return nil, fmt.Errorf("svtrust: %q is not an email address", q.From)
		}
	}
	fp := NormalizeFingerprint(q.Fingerprint)
	if len(q.Key) > 0 {
		k, err := ParseKey(q.Key)
		if err != nil {
			return nil, err
		}
		if fp != "" && !k.matches(fp) {
			return nil, errors.New("svtrust: the fingerprint is not the key's")
		}
		fp = k.Fingerprint
	}
	if fp == "" {
		return nil, errors.New("svtrust: say whose signature: a fingerprint or a key")
	}
	s.mu.Lock()
	b, err := s.load()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	at := q.At
	if at.IsZero() {
		at = s.now()
	}
	v := &Verdict{Fingerprint: fp, From: from}
	c, k := b.holding(fp)
	v.Contact, v.Key = c, k
	if from != "" {
		for _, h := range b.boundTo(from, c) {
			l, e := h.Key.BestFor(from)
			v.Others = append(v.Others, Other{Contact: h.Contact, Key: h.Key, Level: l, Event: e})
		}
	}
	if k != nil {
		events := append(append([]Event(nil), k.Events...), b.vouchers(k, at)...)
		v.KeyLevel, v.KeyVerification = bestOf(k, events, "")
		v.Level, v.Verification = v.KeyLevel, v.KeyVerification
		if from != "" {
			v.Bound, v.Claimed = k.Bound(from), k.claims(from)
			v.Level, v.Verification = bestOf(k, events, from)
			v.Seen = k.Sighting(from)
		}
		v.State = k.State(at)
	}
	v.Reasons = v.explain()
	return v, nil
}

// vouchers are the events organisations give a key now: an X.509
// certificate whose chain leads to the CA of a contact marked as an
// organisation is vouched for by it, for the certificate's addresses.
func (b book) vouchers(k *Key, at time.Time) []Event {
	if k.Type != X509 {
		return nil
	}
	leaf, err := x509.ParseCertificate(k.Material)
	if err != nil {
		return nil
	}
	roots := x509.NewCertPool()
	orgOf := map[string]string{}
	for _, c := range b {
		if !c.Organisation {
			continue
		}
		for _, ck := range c.Keys {
			if ck.Type != X509 {
				continue
			}
			ca, err := x509.ParseCertificate(ck.Material)
			if err != nil || !ca.IsCA {
				continue
			}
			roots.AddCert(ca)
			orgOf[string(ca.Raw)] = c.Name
		}
	}
	if len(orgOf) == 0 {
		return nil
	}
	inter := x509.NewCertPool()
	for _, der := range k.Chain {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}})
	if err != nil || len(chains) == 0 {
		return nil
	}
	root := chains[0][len(chains[0])-1]
	return []Event{{Level: Organisation, Method: MethodOrgCA, At: at,
		Source: fmt.Sprintf("%s's CA %q", orgOf[string(root.Raw)], certLabel(root)), Addresses: certAddresses(leaf)}}
}

// explain says the verdict in sentences.
func (v *Verdict) explain() []string {
	var r []string
	if v.Key == nil {
		r = append(r, "Signed by a key you do not have.")
	} else {
		r = append(r, v.signedBy())
		if v.From != "" && !v.Bound {
			switch {
			case !v.Claimed:
				r = append(r, fmt.Sprintf("The key does not name %s, and it is not one of its addresses.", v.From))
			case len(v.Others) == 0:
				r = append(r, fmt.Sprintf("%s is not one of its addresses.", v.From))
			}
		}
		switch {
		case v.State == "revoked":
			r = append(r, "The key has been revoked.")
		case v.State != "":
			r = append(r, fmt.Sprintf("The key is %s.", v.State))
		}
	}
	if v.From != "" && !v.Bound && len(v.Others) > 0 {
		r = append(r, v.impostor())
	}
	return r
}

// signedBy is the first sentence: whose key, and how it was verified.
func (v *Verdict) signedBy() string {
	named := !v.Contact.Automatic()
	whose := "a key"
	if named {
		whose = v.Contact.Name + "'s key"
	}
	e := v.Verification
	if e == nil && v.From != "" && !v.Bound {
		e = v.KeyVerification // how the key was verified, at other addresses
	}
	switch {
	case e != nil && e.Level == TOFU:
		if s := v.seenFor(); s != nil {
			if named {
				return fmt.Sprintf("Signed by %s, which you have seen %s from %s since %s (not verified).", whose, times(s.Count), s.Address, day(s.First))
			}
			return fmt.Sprintf("Signed by a key you have seen %s from %s since %s (not verified).", times(s.Count), s.Address, day(s.First))
		}
		return fmt.Sprintf("Signed by %s, which you accepted on %s without verifying it.", whose, day(e.At))
	case e != nil:
		return fmt.Sprintf("Signed by %s, %s.", whose, describeVerification(e))
	}
	if !named {
		if s := v.seenFor(); s != nil {
			return fmt.Sprintf("Signed by a key first seen from %s on %s (not verified).", s.Address, day(s.First))
		}
	}
	return fmt.Sprintf("Signed by %s, which you have not verified.", whose)
}

// seenFor is the sighting behind a TOFU verdict: from the claimed
// address, else the key's first.
func (v *Verdict) seenFor() *Sighting {
	if v.Seen != nil {
		return v.Seen
	}
	if len(v.Key.Seen) > 0 {
		return &v.Key.Seen[0]
	}
	return nil
}

// impostor warns that the address belongs to someone else's key.
func (v *Verdict) impostor() string {
	best := v.Others[0]
	for _, o := range v.Others[1:] {
		if o.Level.Rank() > best.Level.Rank() {
			best = o
		}
	}
	whose := ""
	if !best.Contact.Automatic() {
		whose = best.Contact.Name + "'s, "
	}
	switch {
	case best.Level.Rank() > TOFU.Rank():
		return fmt.Sprintf("The address %s belongs to a different key you verified (%s%s). This may be an impostor.",
			v.From, whose, strings.TrimPrefix(describeVerification(best.Event), "which you verified "))
	case best.Level == TOFU:
		if s := best.Key.Sighting(v.From); s != nil {
			return fmt.Sprintf("The address %s belongs to a different key, %sseen %s since %s (not verified). The sender may have a new key, or this may be an impostor.",
				v.From, whose, times(s.Count), day(s.First))
		}
	}
	return fmt.Sprintf("The address %s belongs to a different key (%snot verified). The sender may have a new key, or this may be an impostor.",
		v.From, whose)
}

// describeVerification says how an event verified a key, as a clause
// after "Signed by Alice's key, ...".
func describeVerification(e *Event) string {
	switch e.Method {
	case MethodFingerprint:
		return "which you verified in person on " + day(e.At)
	case MethodQR:
		return "which you verified in person, by scanning their QR code, on " + day(e.At)
	case MethodOrgCA:
		return fmt.Sprintf("which %s vouches for", e.Source)
	case MethodOrgDirectory:
		return fmt.Sprintf("which the directory %s lists (checked on %s)", e.Source, day(e.At))
	case MethodLog:
		return fmt.Sprintf("which a transparency log records (checked on %s)", day(e.At))
	case MethodWKD:
		if len(e.Addresses) > 0 {
			_, domain, _ := strings.Cut(e.Addresses[0], "@")
			return fmt.Sprintf("which %s publishes for %s (WKD, checked on %s)", strings.ToLower(domain), e.Addresses[0], day(e.At))
		}
		return fmt.Sprintf("which its address's domain publishes (WKD, checked on %s)", day(e.At))
	case MethodKeyserver:
		host := e.Source
		if u, err := url.Parse(e.Source); err == nil && u.Host != "" {
			host = u.Host
		}
		return fmt.Sprintf("whose address %s checked by email (on %s)", host, day(e.At))
	case MethodTOFU:
		return "which you trusted on first use on " + day(e.At) + " (not verified)"
	}
	return fmt.Sprintf("which is %s (%s, on %s)", e.Level, e.Method, day(e.At))
}

func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// Describe says what an event is, for a list of a key's verifications.
func (e *Event) Describe() string {
	var s string
	switch e.Method {
	case MethodFingerprint:
		s = "fingerprint compared in person"
	case MethodQR:
		s = "QR code scanned in person"
	case MethodOrgCA:
		s = "vouched for by " + e.Source
	case MethodOrgDirectory:
		s = "listed in the directory " + e.Source
	case MethodLog:
		s = "recorded in a transparency log"
	case MethodWKD:
		s = "published by the address's domain (WKD)"
	case MethodKeyserver:
		s = "address checked by email by the keyserver"
	case MethodTOFU:
		s = "trusted on first use"
	default:
		s = e.Method
	}
	s += " on " + day(e.At)
	if len(e.Addresses) > 0 {
		s += ", for " + strings.Join(e.Addresses, ", ")
	}
	if e.By != "" {
		s += ", recorded by " + e.By
	}
	if e.Source != "" && e.Method != MethodOrgCA && e.Method != MethodOrgDirectory {
		s += " (" + e.Source + ")"
	}
	return s
}

// Policy decides what counts as trusted, from a Verdict's facts.
type Policy struct {
	// MinLevel is the weakest verification that counts as verified;
	// None means Published.
	MinLevel Level
}

// DefaultPolicy counts a key as verified when it is published by its
// address's domain or a keyserver that checked the address, or better:
// trust on first use alone is not verification.
var DefaultPolicy = Policy{MinLevel: Published}

// Judgement is a Policy's reading of a Verdict.
type Judgement struct {
	Trusted bool
	// Status is "verified", "unverified", "suspicious" (the address
	// belongs to another contact's key) or "unknown" (the key is not in
	// the store).
	Status string
}

// Judge reads a verdict by the policy.
func (p Policy) Judge(v *Verdict) Judgement {
	min := p.MinLevel
	if min.Rank() == 0 {
		min = Published
	}
	switch {
	case v.From != "" && !v.Bound && len(v.Others) > 0:
		return Judgement{Status: "suspicious"}
	case v.Key == nil:
		return Judgement{Status: "unknown"}
	case v.From != "" && !v.Bound, v.State != "", v.Level.Rank() < min.Rank():
		return Judgement{Status: "unverified"}
	}
	return Judgement{Trusted: true, Status: "verified"}
}
