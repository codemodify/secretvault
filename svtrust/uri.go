package svtrust

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Card is what a QR code shows about a person: a name, addresses and key
// fingerprints. It carries fingerprints, not keys, so it fits a QR code a
// phone reads from a screen: scanning it verifies keys you already have,
// or names the ones to fetch.
type Card struct {
	Name   string
	Emails []string
	Keys   []CardKey
}

// CardKey is a key a Card names.
type CardKey struct {
	Type        KeyType
	Fingerprint string
}

// ContactScheme is the scheme of secretvault's own contact URIs.
const ContactScheme = "secretvault-contact"

// The query parameter each key type goes under, in a secretvault-contact
// URI.
var cardParams = []struct {
	name string
	typ  KeyType
}{{"pgp", OpenPGP}, {"x509", X509}, {"ssh", SSH}, {"sv", Secretvault}}

// URI writes the card as a secretvault-contact URI:
//
//	secretvault-contact:v1?n=Alice+Example&e=alice%40example.org&pgp=FINGERPRINT&ssh=SHA256%3A...
//
// n is the name, e an address, and pgp, x509, ssh and sv fingerprints of
// each key type; e and the fingerprints may repeat. Readers ignore
// parameters they do not know.
func (c *Card) URI() string {
	var q []string
	if c.Name != "" {
		q = append(q, "n="+url.QueryEscape(c.Name))
	}
	for _, e := range c.Emails {
		q = append(q, "e="+url.QueryEscape(e))
	}
	for _, p := range cardParams {
		for _, k := range c.Keys {
			if k.Type == p.typ {
				q = append(q, p.name+"="+url.QueryEscape(k.Fingerprint))
			}
		}
	}
	return ContactScheme + ":v1?" + strings.Join(q, "&")
}

// ErrNotCard is text that is neither a secretvault-contact nor an
// openpgp4fpr URI.
var ErrNotCard = errors.New("svtrust: not a secretvault-contact or openpgp4fpr URI")

// ParseCard reads a secretvault-contact URI, or an openpgp4fpr URI as
// OpenKeychain and Delta Chat show it (OPENPGP4FPR:FINGERPRINT, with
// "#a=ADDRESS&n=NAME" after it or not).
func ParseCard(uri string) (*Card, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(uri), ":")
	if !ok {
		return nil, ErrNotCard
	}
	switch strings.ToLower(scheme) {
	case "openpgp4fpr":
		fp, frag, _ := strings.Cut(rest, "#")
		fp = NormalizeFingerprint(fp)
		if !openPGPFingerprint(fp) {
			return nil, fmt.Errorf("svtrust: %q is not an OpenPGP fingerprint", fp)
		}
		c := &Card{Keys: []CardKey{{OpenPGP, fp}}}
		if params, err := url.ParseQuery(frag); err == nil {
			c.Name = strings.TrimSpace(params.Get("n"))
			if addr := ParseAddress(params.Get("a")); addr != "" {
				c.Emails = []string{addr}
			}
		}
		return c, nil
	case ContactScheme:
	default:
		return nil, ErrNotCard
	}
	version, query, _ := strings.Cut(rest, "?")
	if version != "v1" {
		return nil, fmt.Errorf("svtrust: a %s URI of version %q, which this secretvault cannot read", ContactScheme, version)
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("svtrust: %s URI: %v", ContactScheme, err)
	}
	c := &Card{Name: strings.TrimSpace(params.Get("n"))}
	for _, e := range params["e"] {
		addr := ParseAddress(e)
		if addr == "" {
			return nil, fmt.Errorf("svtrust: %q is not an email address", e)
		}
		c.Emails = append(c.Emails, addr)
	}
	for _, p := range cardParams {
		for _, v := range params[p.name] {
			fp := NormalizeFingerprint(v)
			if !cardFingerprint(p.typ, fp) {
				return nil, fmt.Errorf("svtrust: %q is not a %s fingerprint", v, p.typ)
			}
			c.Keys = append(c.Keys, CardKey{p.typ, fp})
		}
	}
	if len(c.Keys) == 0 {
		return nil, errors.New("svtrust: the contact URI names no key")
	}
	return c, nil
}

func openPGPFingerprint(fp string) bool { return (len(fp) == 40 || len(fp) == 64) && isHex(fp) }

func cardFingerprint(t KeyType, fp string) bool {
	switch t {
	case OpenPGP:
		return openPGPFingerprint(fp)
	case X509, Secretvault:
		return len(fp) == 64 && isHex(fp)
	case SSH:
		return strings.HasPrefix(fp, "SHA256:") && len(fp) > len("SHA256:")
	}
	return false
}

// CardOf is the card for keys you hold: their fingerprints, the name
// given, and the addresses given.
func CardOf(name string, emails []string, keys []*Key) *Card {
	c := &Card{Name: name, Emails: emails}
	for _, k := range keys {
		c.Keys = append(c.Keys, CardKey{k.Type, k.Fingerprint})
	}
	return c
}

// ScanResult is what scanning a card did.
type ScanResult struct {
	Contact *Contact
	// Verified are the card's keys the store had or fetched, now verified
	// in person; Missing are those it could not find.
	Verified []*Key
	Missing  []CardKey
	Warnings []string
}

// Fetcher fetches an OpenPGP key by fingerprint (from a keyserver).
type Fetcher func(fingerprint string) ([]*Key, error)

// Scan records a card scanned in person: every key it names that the
// store has, or that fetch finds (OpenPGP only; fetch may be nil), is
// verified in person (MethodQR) and bound to the card's addresses. The
// keys end up in one contact: the one holding the first of them, else a
// new one named by the card. A contact made automatically takes the
// card's name.
func (s *Store) Scan(card *Card, by string, fetch Fetcher) (*ScanResult, error) {
	var fetched []*Key
	if fetch != nil {
		s.mu.Lock()
		b, err := s.load()
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		for _, ck := range card.Keys {
			if ck.Type != OpenPGP {
				continue
			}
			if c, _ := b.holding(ck.Fingerprint); c != nil {
				continue
			}
			keys, err := fetch(ck.Fingerprint)
			if err != nil {
				continue
			}
			for _, k := range keys {
				if k.Fingerprint == ck.Fingerprint {
					fetched = append(fetched, k)
					break
				}
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	now := s.now()
	res := &ScanResult{}
	var target *Contact
	var keys []*Key
	for _, ck := range card.Keys {
		c, k := b.holding(ck.Fingerprint)
		if k == nil {
			for _, f := range fetched {
				if f.Fingerprint == ck.Fingerprint {
					k = f
				}
			}
			if k == nil {
				res.Missing = append(res.Missing, ck)
				continue
			}
			k.Added = now
			k.Addresses = nil // bound below, to the card's addresses
		}
		if target == nil {
			target = c
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return res, nil
	}
	if target == nil {
		target = &Contact{Name: card.Name, Origin: OriginQR, Created: now}
	}
	if target.Automatic() && card.Name != "" {
		target.Name, target.Origin = card.Name, OriginQR
	}
	if target.Name == "" {
		target.Name = defaultName(&Contact{Emails: card.Emails, Keys: keys})
	}
	for _, k := range keys {
		if from, _ := b.holding(k.Fingerprint); from != nil && from.ID != target.ID {
			if err := s.move(from, target, k); err != nil {
				return nil, err
			}
		} else if from == nil {
			target.Keys = append(target.Keys, k)
		}
		ev := Event{Level: InPerson, Method: MethodQR, By: by, At: now, Source: "QR code"}
		for _, addr := range card.Emails {
			target.bind(k, addr)
		}
		k.addEvent(ev)
		res.Verified = append(res.Verified, k)
	}
	for _, addr := range card.Emails {
		if others := b.boundTo(addr, target); len(others) > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is also bound to %s", addr, describeHolders(others)))
		}
	}
	res.Contact = target
	return res, s.save(target)
}
