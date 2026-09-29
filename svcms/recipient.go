package svcms

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RecipientKind is how a recipient's copy of the content key is protected.
type RecipientKind int

const (
	// KeyTransport is a KeyTransRecipientInfo: the content key encrypted
	// to an RSA key.
	KeyTransport RecipientKind = iota + 1
	// KeyAgreement is one recipient of a KeyAgreeRecipientInfo: the
	// content key wrapped with a key agreed by ephemeral-static ECDH.
	KeyAgreement
	// OtherRecipient is a kind this package does not read: a
	// previously distributed key, a password, or another.
	OtherRecipient
)

func (k RecipientKind) String() string {
	switch k {
	case KeyTransport:
		return "key transport"
	case KeyAgreement:
		return "key agreement"
	}
	return "other"
}

// Recipient is one recipient of an enveloped message, as the message
// names it.
type Recipient struct {
	Kind RecipientKind

	// The recipient's certificate is named by issuer and serial number,
	// or by subject key identifier: one of these is set (neither, for
	// OtherRecipient).
	IssuerAndSerial *IssuerAndSerial
	SubjectKeyID    []byte

	// KeyEncryption describes how the content key is protected, such as
	// "RSA-OAEP (SHA-256)" or "ECDH P-256 (X9.63 KDF with SHA-256, AES-256
	// key wrap)".
	KeyEncryption string

	// Err is why this recipient cannot be decrypted by this package (an
	// unsupported algorithm), or nil.
	Err error

	encryptedKey []byte
	keyLen       int // the content key's length, from the content cipher

	// Key transport.
	oaep *oaepParams // nil for PKCS #1 v1.5

	// Key agreement.
	originator      []byte                // the ephemeral public key, an uncompressed point
	originatorCurve asn1.ObjectIdentifier // nil when the parameters were absent
	ukm             []byte
	kdf             crypto.Hash
	wrap            algorithm
	wrapKeyLen      int
}

// Matches says whether cert is the certificate the recipient names.
func (r *Recipient) Matches(cert *x509.Certificate) bool {
	if r.IssuerAndSerial != nil {
		return r.IssuerAndSerial.matches(cert.RawIssuer, cert.SerialNumber)
	}
	return len(r.SubjectKeyID) > 0 && string(r.SubjectKeyID) == string(cert.SubjectKeyId)
}

// ECDHKey is the private key of a key agreement recipient.
// *ecdh.PrivateKey is one; an implementation may keep the key elsewhere
// and do only the ECDH operation.
type ECDHKey interface {
	PublicKey() *ecdh.PublicKey
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
}

// Unwrap recovers the content key from this recipient with a private key:
// for key transport a crypto.Decrypter holding an RSA key (such as
// *rsa.PrivateKey, or one that does the RSA operation elsewhere), for key
// agreement an ECDHKey or an *ecdsa.PrivateKey. It does not check that
// the key is this recipient's; Matches does.
//
// For RSA PKCS #1 v1.5 a wrong key or a tampered message yields a random
// key rather than an error (RFC 3218's countermeasure to Bleichenbacher's
// attack), so the failure shows only as ErrDecryption when the content is
// decrypted.
func (r *Recipient) Unwrap(key any) ([]byte, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	switch r.Kind {
	case KeyTransport:
		d, ok := key.(crypto.Decrypter)
		if !ok {
			return nil, fmt.Errorf("svcms: a key transport recipient needs a crypto.Decrypter, not a %T", key)
		}
		if _, ok := d.Public().(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("svcms: a key transport recipient needs an RSA key, not a %T", d.Public())
		}
		var opts crypto.DecrypterOpts
		if r.oaep != nil {
			opts = &rsa.OAEPOptions{Hash: r.oaep.hash, MGFHash: r.oaep.mgfHash, Label: r.oaep.label}
		} else {
			opts = &rsa.PKCS1v15DecryptOptions{SessionKeyLen: r.keyLen}
		}
		cek, err := d.Decrypt(rand.Reader, r.encryptedKey, opts)
		if err != nil {
			if errors.Is(err, rsa.ErrDecryption) || errors.Is(err, rsa.ErrVerification) {
				return nil, ErrDecryption
			}
			return nil, err
		}
		if len(cek) != r.keyLen {
			clear(cek)
			return nil, ErrDecryption
		}
		return cek, nil
	case KeyAgreement:
		var k ECDHKey
		switch kk := key.(type) {
		case ECDHKey:
			k = kk
		case *ecdsa.PrivateKey:
			ek, err := kk.ECDH()
			if err != nil {
				return nil, err
			}
			k = ek
		default:
			return nil, fmt.Errorf("svcms: a key agreement recipient needs an ECDH key, not a %T", key)
		}
		curve := k.PublicKey().Curve()
		if r.originatorCurve != nil {
			c, err := curveByOID(r.originatorCurve)
			if err != nil {
				return nil, err
			}
			if c != curve {
				return nil, ErrDecryption
			}
		}
		eph, err := curve.NewPublicKey(r.originator)
		if err != nil {
			return nil, ErrDecryption
		}
		z, err := k.ECDH(eph)
		if err != nil {
			return nil, ErrDecryption
		}
		kek := x963KDF(r.kdf, z, sharedInfo(r.wrap.raw, r.ukm, r.wrapKeyLen), r.wrapKeyLen)
		clear(z)
		cek, err := keyUnwrap(kek, r.encryptedKey)
		clear(kek)
		if err != nil {
			return nil, err
		}
		if len(cek) != r.keyLen {
			clear(cek)
			return nil, ErrDecryption
		}
		return cek, nil
	}
	return nil, unsupported("%v recipients", r.Kind)
}

// sharedInfo is the DER ECC-CMS-SharedInfo (RFC 5753, section 7.2) the
// KDF takes: the key wrap algorithm as the message gives it, the user
// keying material if any, and the wrapping key's length in bits.
func sharedInfo(wrapAlg, ukm []byte, keyLen int) []byte {
	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(wrapAlg)
			if ukm != nil {
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(ukm)
				})
			}
			b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				bits := uint32(keyLen * 8)
				b.AddASN1OctetString([]byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)})
			})
		})
	})
}

func curveByOID(oid asn1.ObjectIdentifier) (ecdh.Curve, error) {
	switch {
	case oid.Equal(oidCurveP256):
		return ecdh.P256(), nil
	case oid.Equal(oidCurveP384):
		return ecdh.P384(), nil
	case oid.Equal(oidCurveP521):
		return ecdh.P521(), nil
	}
	return nil, unsupported("curve %v", oid)
}

func curveOID(c ecdh.Curve) asn1.ObjectIdentifier {
	switch c {
	case ecdh.P256():
		return oidCurveP256
	case ecdh.P384():
		return oidCurveP384
	case ecdh.P521():
		return oidCurveP521
	}
	return nil
}

func curveName(c ecdh.Curve) string {
	switch c {
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	}
	return "an unknown curve"
}

// A Decrypter recovers content keys for the recipients whose private keys
// it holds. It may hold them elsewhere (in another process, behind a
// consent prompt): EnvelopedData.Decrypt only ever hands it a recipient
// and takes back the content key.
type Decrypter interface {
	// ContentKey returns the content key held for r, or an error wrapping
	// ErrNotRecipient if it holds no private key for r. Recipient.Unwrap
	// does the work, given the private key.
	ContentKey(r *Recipient) ([]byte, error)
}

// KeyDecrypter is a Decrypter for the one recipient whose certificate is
// cert, with its private key: a crypto.Decrypter holding an RSA key, an
// ECDHKey, or an *ecdsa.PrivateKey. Either may do the raw RSA or ECDH
// operation somewhere else; nothing else is asked of it.
func KeyDecrypter(cert *x509.Certificate, key any) (Decrypter, error) {
	switch key.(type) {
	case crypto.Decrypter, ECDHKey, *ecdsa.PrivateKey:
	default:
		return nil, fmt.Errorf("svcms: cannot decrypt with a %T", key)
	}
	return &keyDecrypter{cert: cert, key: key}, nil
}

type keyDecrypter struct {
	cert *x509.Certificate
	key  any
}

func (k *keyDecrypter) ContentKey(r *Recipient) ([]byte, error) {
	if !r.Matches(k.cert) {
		return nil, ErrNotRecipient
	}
	return r.Unwrap(k.key)
}

// Decrypters tries each Decrypter in turn.
type Decrypters []Decrypter

// ContentKey returns the first content key any of them has for r.
func (ds Decrypters) ContentKey(r *Recipient) ([]byte, error) {
	for _, d := range ds {
		key, err := d.ContentKey(r)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, ErrNotRecipient) {
			return nil, err
		}
	}
	return nil, ErrNotRecipient
}

// parseRecipientInfos reads a SET OF RecipientInfo, flattening key
// agreement infos into one Recipient per recipient.
func parseRecipientInfos(s cryptobyte.String, keyLen int, lim Limits) ([]*Recipient, error) {
	var out []*Recipient
	add := func(r *Recipient) error {
		if len(out) >= lim.MaxRecipients {
			return limit("more than %d recipients", lim.MaxRecipients)
		}
		r.keyLen = keyLen
		out = append(out, r)
		return nil
	}
	kariTag := cbasn1.Tag(1).Constructed().ContextSpecific()
	for !s.Empty() {
		var ri cryptobyte.String
		var tag cbasn1.Tag
		if !s.ReadAnyASN1(&ri, &tag) {
			return nil, malformed("RecipientInfo")
		}
		switch tag {
		case cbasn1.SEQUENCE:
			r, err := parseKTRI(ri)
			if err != nil {
				return nil, err
			}
			if err := add(r); err != nil {
				return nil, err
			}
		case kariTag:
			rs, err := parseKARI(ri, lim)
			if err != nil {
				return nil, err
			}
			for _, r := range rs {
				if err := add(r); err != nil {
					return nil, err
				}
			}
		default:
			kind := map[cbasn1.Tag]string{
				cbasn1.Tag(2).Constructed().ContextSpecific(): "a previously distributed key (KEKRecipientInfo)",
				cbasn1.Tag(3).Constructed().ContextSpecific(): "a password (PasswordRecipientInfo)",
				cbasn1.Tag(4).Constructed().ContextSpecific(): "another kind (OtherRecipientInfo)",
			}[tag]
			if kind == "" {
				return nil, malformed("RecipientInfo of unknown kind")
			}
			if err := add(&Recipient{Kind: OtherRecipient, KeyEncryption: kind, Err: unsupported("recipients of %s", kind)}); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, malformed("no recipients")
	}
	return out, nil
}

// readRecipientID reads a RecipientIdentifier (or a
// KeyAgreeRecipientIdentifier, whose rKeyId is a SEQUENCE).
func readRecipientID(s *cryptobyte.String, r *Recipient, kari bool) bool {
	if s.PeekASN1Tag(cbasn1.SEQUENCE) {
		is, ok := readIssuerAndSerial(s)
		r.IssuerAndSerial = is
		return ok
	}
	var ski cryptobyte.String
	if kari {
		var rkid cryptobyte.String
		if !s.ReadASN1(&rkid, cbasn1.Tag(0).Constructed().ContextSpecific()) || !rkid.ReadASN1(&ski, cbasn1.OCTET_STRING) {
			return false
		}
		// The date and other attribute that may follow do not change
		// which key is meant.
	} else if !s.ReadASN1(&ski, cbasn1.Tag(0).ContextSpecific()) {
		return false
	}
	r.SubjectKeyID = append([]byte{}, ski...)
	return true
}

func parseKTRI(s cryptobyte.String) (*Recipient, error) {
	r := &Recipient{Kind: KeyTransport}
	var version int
	var alg algorithm
	var key cryptobyte.String
	if !s.ReadASN1Integer(&version) || !readRecipientID(&s, r, false) || !readAlgorithm(&s, &alg) ||
		!s.ReadASN1(&key, cbasn1.OCTET_STRING) || !s.Empty() {
		return nil, malformed("KeyTransRecipientInfo")
	}
	r.encryptedKey = append([]byte{}, key...)
	switch {
	case alg.oid.Equal(oidRSAOAEP):
		p, err := parseOAEPParams(alg.params)
		if err != nil {
			r.Err = err
		}
		r.oaep = &p
		r.KeyEncryption = fmt.Sprintf("RSA-OAEP (%v)", p.hash)
	case alg.oid.Equal(oidRSAEncryption):
		r.KeyEncryption = "RSA PKCS#1 v1.5"
	default:
		r.KeyEncryption = alg.oid.String()
		r.Err = unsupported("key transport algorithm %v", alg.oid)
	}
	return r, nil
}

func parseKARI(s cryptobyte.String, lim Limits) ([]*Recipient, error) {
	bad := malformed("KeyAgreeRecipientInfo")
	var version int
	var orig cryptobyte.String
	if !s.ReadASN1Integer(&version) || !s.ReadASN1(&orig, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, bad
	}
	tmpl := Recipient{Kind: KeyAgreement}
	if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); orig.PeekASN1Tag(tag) {
		// originatorKey [1] IMPLICIT OriginatorPublicKey
		var opk cryptobyte.String
		var alg algorithm
		var point asn1.BitString
		if !orig.ReadASN1(&opk, tag) || !readAlgorithm(&opk, &alg) || !opk.ReadASN1BitString(&point) || !opk.Empty() || !orig.Empty() {
			return nil, bad
		}
		if !alg.oid.Equal(oidECPublicKey) {
			tmpl.Err = unsupported("key agreement with a %v originator key", alg.oid)
		} else if !alg.paramsEmpty() {
			p := cryptobyte.String(alg.params)
			var curve asn1.ObjectIdentifier
			if !p.ReadASN1ObjectIdentifier(&curve) || !p.Empty() {
				tmpl.Err = unsupported("explicit curve parameters")
			}
			tmpl.originatorCurve = curve
		}
		if point.BitLength%8 != 0 {
			return nil, bad
		}
		tmpl.originator = append([]byte{}, point.Bytes...)
	} else {
		// The originator's static key, named by certificate: not the
		// ephemeral-static scheme S/MIME uses.
		tmpl.Err = unsupported("key agreement with a static originator key")
	}
	if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); s.PeekASN1Tag(tag) {
		var explicit, ukm cryptobyte.String
		if !s.ReadASN1(&explicit, tag) || !explicit.ReadASN1(&ukm, cbasn1.OCTET_STRING) || !explicit.Empty() {
			return nil, bad
		}
		tmpl.ukm = append([]byte{}, ukm...)
	}
	var alg algorithm
	var keys cryptobyte.String
	if !readAlgorithm(&s, &alg) || !s.ReadASN1(&keys, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, bad
	}
	curve := "ECDH"
	if tmpl.originatorCurve != nil {
		if c, err := curveByOID(tmpl.originatorCurve); err == nil {
			curve = "ECDH " + curveName(c)
		}
	}
	h, err := kdfHash(alg.oid)
	if err != nil && tmpl.Err == nil {
		tmpl.Err = err
	}
	tmpl.kdf = h
	p := cryptobyte.String(alg.params)
	if err == nil {
		if !readAlgorithm(&p, &tmpl.wrap) || !p.Empty() {
			return nil, bad
		}
		n, err := keyWrapKeyLen(tmpl.wrap.oid)
		if err != nil && tmpl.Err == nil {
			tmpl.Err = err
		}
		tmpl.wrapKeyLen = n
		tmpl.KeyEncryption = fmt.Sprintf("%s (X9.63 KDF with %v, AES-%d key wrap)", curve, h, n*8)
	} else {
		tmpl.KeyEncryption = fmt.Sprintf("%s (%v)", curve, alg.oid)
	}
	var out []*Recipient
	for !keys.Empty() {
		if len(out) >= lim.MaxRecipients {
			return nil, limit("more than %d recipients", lim.MaxRecipients)
		}
		var rek, ek cryptobyte.String
		r := tmpl
		if !keys.ReadASN1(&rek, cbasn1.SEQUENCE) || !readRecipientID(&rek, &r, true) ||
			!rek.ReadASN1(&ek, cbasn1.OCTET_STRING) || !rek.Empty() {
			return nil, bad
		}
		r.encryptedKey = append([]byte{}, ek...)
		out = append(out, &r)
	}
	return out, nil
}
