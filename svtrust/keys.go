package svtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpgp"
)

// ErrNoKey is input in which no public key could be read.
var ErrNoKey = errors.New("svtrust: no public key found")

// ErrPrivate is input holding private key material where a public key was
// wanted. Nothing of it is kept.
var ErrPrivate = errors.New("svtrust: that is a private key; give its public half")

// ParseKeys reads public keys in any form the trust store keeps:
//
//   - OpenPGP, armored or binary, one key or many (secret keys are read
//     for their public part only);
//   - X.509 certificates, PEM or DER: each certificate that is not a CA
//     becomes a key, with the others in the input as its chain; input of
//     CA certificates only (an organisation's) gives one key each;
//   - SSH public keys: a .pub file or authorized_keys lines;
//   - secretvault recipients (sv-recipient-1-..., what 'secretvault
//     identity pub' prints), one per line.
//
// Each key comes back with its fingerprint, label, the addresses it names
// itself (OpenPGP user IDs, certificate email addresses) in Addresses, and
// no verification. A secretvault identity, being private, is refused
// (ErrPrivate); PEM private keys beside certificates are skipped.
func ParseKeys(data []byte) ([]*Key, error) {
	text := bytes.TrimSpace(data)
	switch {
	case len(text) == 0:
		return nil, ErrNoKey
	case bytes.Contains(text, []byte("SV-IDENTITY-1-")):
		return nil, ErrPrivate
	case bytes.Contains(text, []byte("-----BEGIN PGP ")):
		return parseOpenPGP(text)
	case bytes.Contains(text, []byte("-----BEGIN ")):
		return parsePEM(text)
	case bytes.Contains(text, []byte("sv-recipient-1-")):
		return parseRecipients(text)
	}
	if keys, err := parseSSH(text); err == nil {
		return keys, nil
	}
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return fromCertificates(certs), nil
	}
	if keys, err := parseOpenPGP(data); err == nil {
		return keys, nil
	}
	return nil, ErrNoKey
}

// ParseKey reads exactly one key (or one certificate with its chain).
func ParseKey(data []byte) (*Key, error) {
	keys, err := ParseKeys(data)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("svtrust: %d keys where one was expected", len(keys))
	}
	return keys[0], nil
}

func parseOpenPGP(data []byte) ([]*Key, error) {
	pks, err := svpgp.ReadKeys(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoKey, err)
	}
	var out []*Key
	for _, pk := range pks {
		k, err := fromOpenPGP(pk.Public())
		pk.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// fromOpenPGP describes an OpenPGP key.
func fromOpenPGP(pk *svpgp.Key) (*Key, error) {
	var bin bytes.Buffer
	if err := pk.Serialize(&bin, false); err != nil {
		return nil, err
	}
	k := &Key{Type: OpenPGP, Fingerprint: hexFP(pk.Fingerprint()), Material: bin.Bytes(), Label: pk.PrimaryUserID()}
	for _, s := range pk.Subkeys() {
		k.Subkeys = append(k.Subkeys, hexFP(s.Fingerprint))
	}
	k.Addresses = claimedByOpenPGP(pk)
	return k, nil
}

// claimedByOpenPGP are the addresses in a key's valid user IDs.
func claimedByOpenPGP(pk *svpgp.Key) []string {
	var out []string
	for _, uid := range pk.UserIDs() {
		if _, addr := SplitUserID(uid); addr != "" && !containsAddr(out, addr) {
			out = append(out, addr)
		}
	}
	return out
}

func parsePEM(data []byte) ([]*Key, error) {
	var certs []*x509.Certificate
	private := false
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrNoKey, err)
			}
			certs = append(certs, c)
		case strings.Contains(block.Type, "PRIVATE KEY"):
			private = true
			clear(block.Bytes)
		}
	}
	if len(certs) == 0 {
		if private {
			return nil, ErrPrivate
		}
		return nil, ErrNoKey
	}
	return fromCertificates(certs), nil
}

// fromCertificates makes a key of each certificate that is not a CA, with
// the rest as its chain; with CA certificates only, a key of each.
func fromCertificates(certs []*x509.Certificate) []*Key {
	var leaves, cas []*x509.Certificate
	for _, c := range certs {
		if c.IsCA {
			cas = append(cas, c)
		} else {
			leaves = append(leaves, c)
		}
	}
	if len(leaves) == 0 {
		leaves, cas = cas, nil
	}
	var out []*Key
	for _, c := range leaves {
		k := &Key{Type: X509, Fingerprint: certFingerprint(c.Raw), Material: bytes.Clone(c.Raw), Label: certLabel(c), Addresses: certAddresses(c)}
		for _, ca := range cas {
			k.Chain = append(k.Chain, bytes.Clone(ca.Raw))
		}
		out = append(out, k)
	}
	return out
}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hexFP(sum[:])
}

func certLabel(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// certAddresses are a certificate's email addresses: its subject
// alternative names, and the subject's emailAddress of older certificates.
func certAddresses(c *x509.Certificate) []string {
	var out []string
	for _, a := range c.EmailAddresses {
		if addr := ParseAddress(a); addr != "" && !containsAddr(out, addr) {
			out = append(out, addr)
		}
	}
	for _, n := range c.Subject.Names {
		if s, ok := n.Value.(string); ok && n.Type.Equal(oidEmailAddress) {
			if addr := ParseAddress(s); addr != "" && !containsAddr(out, addr) {
				out = append(out, addr)
			}
		}
	}
	return out
}

func parseSSH(data []byte) ([]*Key, error) {
	var out []*Key
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, err
		}
		material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if comment != "" {
			material += " " + comment
		}
		out = append(out, &Key{Type: SSH, Fingerprint: ssh.FingerprintSHA256(pub), Material: []byte(material), Label: comment})
	}
	if len(out) == 0 {
		return nil, ErrNoKey
	}
	return out, nil
}

func parseRecipients(data []byte) ([]*Key, error) {
	var out []*Key
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "# recipient:"))
		if !strings.HasPrefix(line, "sv-recipient-1-") {
			continue
		}
		suite, pub, err := svformat.ParseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoKey, err)
		}
		text := svformat.EncodeRecipient(suite, pub)
		sum := sha256.Sum256([]byte(text))
		out = append(out, &Key{Type: Secretvault, Fingerprint: hexFP(sum[:]), Material: []byte(text), Label: "secretvault " + suite.String() + " recipient"})
	}
	if len(out) == 0 {
		return nil, ErrNoKey
	}
	return out, nil
}

func hexFP(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// NormalizeFingerprint puts a fingerprint or key ID as people write it
// (with spaces or colons, any case, a 0x prefix) in the form keys carry.
// SSH fingerprints ("SHA256:...") are kept as they are.
func NormalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "SHA256:") {
		return s
	}
	t := strings.NewReplacer(" ", "", ":", "", "\t", "").Replace(s)
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		t = t[2:]
	}
	if t != "" && isHex(t) {
		return strings.ToUpper(t)
	}
	return s
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// keyIDOf is the OpenPGP key ID of a fingerprint: its last 8 bytes for a
// version 4 key, its first 8 for version 6.
func keyIDOf(fp string) string {
	switch len(fp) {
	case 40:
		return fp[24:]
	case 64:
		return fp[:16]
	}
	return ""
}

// matches reports whether a normalised fingerprint or key ID names this
// key, or one of its subkeys.
func (k *Key) matches(fp string) bool {
	if fp == "" {
		return false
	}
	if k.Fingerprint == fp || slices.Contains(k.Subkeys, fp) {
		return true
	}
	if k.Type != OpenPGP || len(fp) != 16 {
		return false
	}
	if keyIDOf(k.Fingerprint) == fp {
		return true
	}
	return slices.ContainsFunc(k.Subkeys, func(s string) bool { return keyIDOf(s) == fp })
}

// Claimed are the addresses the key names itself, read from its material:
// an OpenPGP key's valid user IDs, a certificate's email addresses. SSH
// keys and recipients name none.
func (k *Key) Claimed() []string {
	switch k.Type {
	case OpenPGP:
		pk, err := svpgp.ReadKey(bytes.NewReader(k.Material))
		if err != nil {
			return nil
		}
		return claimedByOpenPGP(pk)
	case X509:
		c, err := x509.ParseCertificate(k.Material)
		if err != nil {
			return nil
		}
		return certAddresses(c)
	}
	return nil
}

// claims reports whether the key names addr itself, or cannot name any
// address (SSH keys and recipients), so that whoever gives it vouches.
func (k *Key) claims(addr string) bool {
	if k.Type != OpenPGP && k.Type != X509 {
		return true
	}
	return containsAddr(k.Claimed(), addr)
}

// State says whether the key can be used now: "" if so, else why not
// ("revoked", "expired on 2027-01-01"). Keys that cannot be read say so.
func (k *Key) State(now time.Time) string {
	switch k.Type {
	case OpenPGP:
		pk, err := svpgp.ReadKey(bytes.NewReader(k.Material))
		if err != nil {
			return "unreadable"
		}
		switch {
		case pk.Revoked():
			return "revoked"
		case !pk.ExpiresAt().IsZero() && !now.Before(pk.ExpiresAt()):
			return "expired on " + day(pk.ExpiresAt())
		}
	case X509:
		c, err := x509.ParseCertificate(k.Material)
		if err != nil {
			return "unreadable"
		}
		switch {
		case now.After(c.NotAfter):
			return "expired on " + day(c.NotAfter)
		case now.Before(c.NotBefore):
			return "not valid until " + day(c.NotBefore)
		}
	}
	return ""
}

// mergeMaterial takes what is new in another copy of the same key. An
// OpenPGP key is not merged packet by packet: the other copy replaces
// this one when it carries a revocation this one lacks, or user IDs where
// this one has none (as a keyserver's copy stripped of them would).
func (k *Key) mergeMaterial(other *Key) {
	if k.Type != OpenPGP || other.Type != OpenPGP || k.Fingerprint != other.Fingerprint {
		return
	}
	mine, err1 := svpgp.ReadKey(bytes.NewReader(k.Material))
	theirs, err2 := svpgp.ReadKey(bytes.NewReader(other.Material))
	switch {
	case err2 != nil:
		return
	case err1 != nil,
		theirs.Revoked() && !mine.Revoked(),
		len(mine.UserIDs()) == 0 && len(theirs.UserIDs()) > 0:
		k.Material, k.Subkeys, k.Label = other.Material, other.Subkeys, other.Label
	}
}

// Addresses.

// ParseAddress reads an email address as a From header or a user ID
// writes it ("Alice <alice@example.org>" or a bare address) and returns
// the bare address, or "" if there is none.
func ParseAddress(s string) string {
	s = strings.TrimSpace(s)
	if a, err := mail.ParseAddress(s); err == nil {
		s = a.Address
	} else if i, j := strings.LastIndexByte(s, '<'), strings.LastIndexByte(s, '>'); i >= 0 && j > i {
		s = strings.TrimSpace(s[i+1 : j])
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(s, " \t\r\n<>,;\"") || strings.Contains(domain, "@") {
		return ""
	}
	return s
}

// SplitUserID splits an OpenPGP user ID ("Name (comment) <address>") into
// the name and the address; either may be "".
func SplitUserID(uid string) (name, addr string) {
	uid = strings.TrimSpace(uid)
	if i := strings.LastIndexByte(uid, '<'); i >= 0 && strings.HasSuffix(uid, ">") {
		addr = ParseAddress(uid[i+1 : len(uid)-1])
		name = strings.TrimSpace(uid[:i])
		if j := strings.IndexByte(name, '('); j >= 0 && strings.HasSuffix(name, ")") {
			name = strings.TrimSpace(name[:j])
		}
		return strings.Trim(name, `"`), addr
	}
	if addr = ParseAddress(uid); addr != "" {
		return "", addr
	}
	return uid, ""
}

// sameAddr compares addresses as mail does in practice: ignoring case.
func sameAddr(a, b string) bool { return strings.EqualFold(a, b) }

func containsAddr(list []string, addr string) bool {
	return addr != "" && slices.ContainsFunc(list, func(s string) bool { return sameAddr(s, addr) })
}

// day writes a date as the reasons show it.
func day(t time.Time) string { return t.UTC().Format("2006-01-02") }
