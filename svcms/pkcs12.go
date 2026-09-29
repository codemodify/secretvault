package svcms

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKCS #12 (RFC 7292): the .p12 or .pfx file people move an S/MIME key
// and its certificates in.

var (
	oidKeyBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidSafeContentsBag    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidX509CertificateBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
)

// PKCS12 is what a PKCS #12 file holds.
type PKCS12 struct {
	// PrivateKey is the private key: an *rsa.PrivateKey,
	// *ecdsa.PrivateKey or ed25519.PrivateKey; nil if the file holds
	// none. PrivateKeyPKCS8 is the same key as PKCS #8 DER, for storing;
	// wipe it when done with it. The standard library's key object cannot
	// be wiped.
	PrivateKey      crypto.PrivateKey
	PrivateKeyPKCS8 []byte

	// Certificate is the certificate for the private key (matched by
	// local key ID, else by public key), or the first certificate if
	// there is no key. CACertificates are the others.
	Certificate    *x509.Certificate
	CACertificates []*x509.Certificate

	// FriendlyName is the name the file gives the key (or certificate).
	FriendlyName string

	// Warnings are things to tell the person: obsolete encryption, no
	// integrity check, parts of the file that were skipped.
	Warnings []string
}

type p12Bag struct {
	der     []byte // PKCS #8 or certificate DER
	keyID   []byte
	name    string
	isKey   bool
	warning string
}

type p12Reader struct {
	lim      Limits
	password *pbePassword
	macOK    bool // the MAC was checked: the password is right
	bags     []p12Bag
	warnings []string
	count    int
}

func (r *p12Reader) warn(s string) {
	for _, w := range r.warnings {
		if w == s {
			return
		}
	}
	r.warnings = append(r.warnings, s)
}

// DecodePKCS12 reads a PKCS #12 file, BER or DER, with its password (its
// UTF-8 bytes). It checks the MAC first, when the file has one, and fails
// with ErrPassword if the password does not match. It reads PBES2 with
// PBKDF2 (AES-CBC or Triple DES) and, for old files, PKCS #12's own
// Triple DES and RC2 schemes; files protected by a public key rather than
// a password are refused.
func DecodePKCS12(data, password []byte, lim *Limits) (*PKCS12, error) {
	l := lim.withDefaults()
	der, err := toDER(data, l)
	if err != nil {
		return nil, err
	}
	r := &p12Reader{lim: l, password: newPBEPassword(password)}
	defer r.password.wipe()
	s := cryptobyte.String(der)
	var pfx, authSafe, content, octets cryptobyte.String
	var version int
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&pfx, cbasn1.SEQUENCE) || !s.Empty() || !pfx.ReadASN1Integer(&version) ||
		!pfx.ReadASN1(&authSafe, cbasn1.SEQUENCE) || !authSafe.ReadASN1ObjectIdentifier(&oid) {
		return nil, malformed("PFX")
	}
	if version != 3 {
		return nil, unsupported("PKCS #12 version %d", version)
	}
	if !oid.Equal(OIDData) {
		return nil, unsupported("PKCS #12 in public-key integrity mode (%v)", oid)
	}
	if !authSafe.ReadASN1(&content, cbasn1.Tag(0).Constructed().ContextSpecific()) || !authSafe.Empty() ||
		!content.ReadASN1(&octets, cbasn1.OCTET_STRING) || !content.Empty() {
		return nil, malformed("PFX authSafe")
	}
	if pfx.Empty() {
		r.warn("the file has no integrity check (MAC): it could have been changed")
	} else {
		var macData cryptobyte.String
		if !pfx.ReadASN1(&macData, cbasn1.SEQUENCE) || !pfx.Empty() {
			return nil, malformed("PFX macData")
		}
		if err := r.checkMAC(macData, octets); err != nil {
			return nil, err
		}
		r.macOK = true
	}
	// What the octets hold is encoded on its own, and may be BER too.
	safesDER, err := toDER(octets, l)
	if err != nil {
		return nil, err
	}
	inner := cryptobyte.String(safesDER)
	var safes cryptobyte.String
	if !inner.ReadASN1(&safes, cbasn1.SEQUENCE) || !inner.Empty() {
		return nil, malformed("AuthenticatedSafe")
	}
	for !safes.Empty() {
		var ci, inner cryptobyte.String
		var typ asn1.ObjectIdentifier
		if !safes.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.ReadASN1ObjectIdentifier(&typ) ||
			!ci.ReadASN1(&inner, cbasn1.Tag(0).Constructed().ContextSpecific()) || !ci.Empty() {
			return nil, malformed("AuthenticatedSafe ContentInfo")
		}
		switch {
		case typ.Equal(OIDData):
			var sc cryptobyte.String
			if !inner.ReadASN1(&sc, cbasn1.OCTET_STRING) || !inner.Empty() {
				return nil, malformed("SafeContents")
			}
			if err := r.safeContents(sc, 0); err != nil {
				return nil, err
			}
		case typ.Equal(OIDEncryptedData):
			plain, err := r.encryptedData(inner)
			if err != nil {
				return nil, err
			}
			err = r.safeContents(plain, 0)
			clear(plain)
			if errors.Is(err, ErrMalformed) {
				// Content that decrypted but does not parse: with no MAC
				// to check the password first, a wrong password.
				return nil, ErrPassword
			}
			if err != nil {
				return nil, err
			}
		default:
			r.warn(fmt.Sprintf("a part of the file protected by a public key (%v) was skipped", typ))
		}
	}
	return r.result()
}

// checkMAC verifies the MAC over the authenticated safe (RFC 7292, section
// 5.1, or PBMAC1, RFC 9579), and learns which encoding of an empty
// password the writer used.
func (r *p12Reader) checkMAC(macData cryptobyte.String, authSafe []byte) error {
	var digestInfo, digest, salt cryptobyte.String
	var alg algorithm
	iter := 1
	if !macData.ReadASN1(&digestInfo, cbasn1.SEQUENCE) || !readAlgorithm(&digestInfo, &alg) ||
		!digestInfo.ReadASN1(&digest, cbasn1.OCTET_STRING) || !digestInfo.Empty() ||
		!macData.ReadASN1(&salt, cbasn1.OCTET_STRING) {
		return malformed("MacData")
	}
	if !macData.Empty() && (!macData.ReadASN1Integer(&iter) || !macData.Empty()) {
		return malformed("MacData iterations")
	}
	if alg.oid.Equal(oidPBMAC1) {
		p := cryptobyte.String(alg.params)
		var seq cryptobyte.String
		var kdf, mac algorithm
		if !p.ReadASN1(&seq, cbasn1.SEQUENCE) || !p.Empty() || !readAlgorithm(&seq, &kdf) || !readAlgorithm(&seq, &mac) || !seq.Empty() {
			return malformed("PBMAC1 parameters")
		}
		kp, err := parsePBKDF2(kdf, r.lim)
		if err != nil {
			return err
		}
		h, err := hmacHash(mac.oid)
		if err != nil {
			return err
		}
		if kp.keyLen == 0 {
			return malformed("PBMAC1 without a key length")
		}
		key, err := kp.derive(r.password.raw, kp.keyLen)
		if err != nil {
			return err
		}
		ok := hmac.Equal(pkcs12MAC(h, key, authSafe), digest)
		clear(key)
		if !ok {
			return ErrPassword
		}
		return nil
	}
	h, err := hashByOID(alg.oid)
	if err != nil {
		if errors.Is(err, ErrWeakAlgorithm) {
			return unsupported("a PKCS #12 MAC with MD5")
		}
		return err
	}
	if iter < 1 || iter > r.lim.MaxIterations {
		return limit("%d MAC iterations (the limit is %d)", iter, r.lim.MaxIterations)
	}
	for _, pw := range r.password.bmp {
		key := pkcs12KDF(h, 3, pw, salt, iter, h.Size())
		ok := hmac.Equal(pkcs12MAC(h, key, authSafe), digest)
		clear(key)
		if ok {
			// Only an empty password has two candidates, and neither is
			// secret: keep the one that worked.
			r.password.bmp = [][]byte{pw}
			return nil
		}
	}
	return ErrPassword
}

// encryptedData decrypts an EncryptedData (RFC 5652, section 8).
func (r *p12Reader) encryptedData(s cryptobyte.String) ([]byte, error) {
	var seq, eci cryptobyte.String
	var version int
	var typ asn1.ObjectIdentifier
	var alg algorithm
	var data []byte
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() || !seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1(&eci, cbasn1.SEQUENCE) || !eci.ReadASN1ObjectIdentifier(&typ) || !readAlgorithm(&eci, &alg) ||
		!readImplicitOctets(&eci, 0, &data) || !eci.Empty() {
		return nil, malformed("EncryptedData")
	}
	plain, legacy, err := pbeDecrypt(alg, r.password, data, r.lim)
	if err != nil {
		return nil, err
	}
	if legacy != "" {
		r.warn(fmt.Sprintf("the certificates are protected with %s, which is obsolete", legacy))
	}
	return plain, nil
}

// safeContents reads a SafeContents: a SEQUENCE OF SafeBag.
func (r *p12Reader) safeContents(der []byte, depth int) error {
	if depth > maxBagNesting {
		return limit("safe contents nested more than %d deep", maxBagNesting)
	}
	der, err := toDER(der, r.lim)
	if err != nil {
		return err
	}
	s := cryptobyte.String(der)
	var bags cryptobyte.String
	if !s.ReadASN1(&bags, cbasn1.SEQUENCE) || !s.Empty() {
		return malformed("SafeContents")
	}
	for !bags.Empty() {
		if r.count++; r.count > r.lim.MaxAttributes {
			return limit("more than %d bags", r.lim.MaxAttributes)
		}
		var bag, value cryptobyte.String
		var id asn1.ObjectIdentifier
		if !bags.ReadASN1(&bag, cbasn1.SEQUENCE) || !bag.ReadASN1ObjectIdentifier(&id) ||
			!bag.ReadASN1(&value, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return malformed("SafeBag")
		}
		var b p12Bag
		if !bag.Empty() {
			var set cryptobyte.String
			if !bag.ReadASN1(&set, cbasn1.SET) || !bag.Empty() {
				return malformed("SafeBag attributes")
			}
			attrs, err := readAttributes(set, r.lim)
			if err != nil {
				return err
			}
			for _, a := range attrs {
				if len(a.values) != 1 {
					continue
				}
				v := cryptobyte.String(a.values[0])
				switch {
				case a.oid.Equal(oidAttrLocalKeyID):
					var kid cryptobyte.String
					if v.ReadASN1(&kid, cbasn1.OCTET_STRING) {
						b.keyID = kid
					}
				case a.oid.Equal(oidAttrFriendlyName):
					var name cryptobyte.String
					if v.ReadASN1(&name, cbasn1.Tag(30)) && len(name)%2 == 0 {
						units := make([]uint16, len(name)/2)
						for i := range units {
							units[i] = uint16(name[2*i])<<8 | uint16(name[2*i+1])
						}
						b.name = string(utf16.Decode(units))
					}
				}
			}
		}
		switch {
		case id.Equal(oidKeyBag):
			var pk cryptobyte.String
			if !value.ReadASN1Element(&pk, cbasn1.SEQUENCE) || !value.Empty() {
				return malformed("KeyBag")
			}
			b.der, b.isKey = append([]byte{}, pk...), true
			r.warn("the private key is stored without encryption")
		case id.Equal(oidPKCS8ShroudedKey):
			var epki cryptobyte.String
			var alg algorithm
			var enc cryptobyte.String
			if !value.ReadASN1(&epki, cbasn1.SEQUENCE) || !value.Empty() || !readAlgorithm(&epki, &alg) ||
				!epki.ReadASN1(&enc, cbasn1.OCTET_STRING) || !epki.Empty() {
				return malformed("PKCS8ShroudedKeyBag")
			}
			plain, legacy, err := pbeDecrypt(alg, r.password, enc, r.lim)
			if err != nil {
				return err
			}
			if legacy != "" {
				r.warn(fmt.Sprintf("the private key is protected with %s, which is obsolete", legacy))
			}
			if d, err := toDER(plain, r.lim); err == nil && len(d) > 0 && &d[0] != &plain[0] {
				clear(plain)
				plain = d
			}
			b.der, b.isKey = plain, true
		case id.Equal(oidCertBag):
			var cb, certValue, octets cryptobyte.String
			var certType asn1.ObjectIdentifier
			if !value.ReadASN1(&cb, cbasn1.SEQUENCE) || !value.Empty() || !cb.ReadASN1ObjectIdentifier(&certType) ||
				!cb.ReadASN1(&certValue, cbasn1.Tag(0).Constructed().ContextSpecific()) || !cb.Empty() {
				return malformed("CertBag")
			}
			if !certType.Equal(oidX509CertificateBag) {
				r.warn("a certificate of another kind than X.509 was skipped")
				continue
			}
			if !certValue.ReadASN1(&octets, cbasn1.OCTET_STRING) || !certValue.Empty() {
				return malformed("CertBag value")
			}
			b.der = append([]byte{}, octets...)
		case id.Equal(oidSafeContentsBag):
			var inner cryptobyte.String
			if !value.ReadASN1Element(&inner, cbasn1.SEQUENCE) || !value.Empty() {
				return malformed("SafeContentsBag")
			}
			if err := r.safeContents(inner, depth+1); err != nil {
				return err
			}
			continue
		default:
			r.warn(fmt.Sprintf("a bag of type %v (a CRL or a secret) was skipped", id))
			continue
		}
		r.bags = append(r.bags, b)
	}
	return nil
}

func (r *p12Reader) result() (*PKCS12, error) {
	out := &PKCS12{}
	var certs []*x509.Certificate
	var certIDs [][]byte
	var keyBag *p12Bag
	keys := 0
	for i := range r.bags {
		b := &r.bags[i]
		if b.isKey {
			if keys++; keys == 1 {
				keyBag = b
			} else {
				clear(b.der)
			}
			continue
		}
		c, err := x509.ParseCertificate(b.der)
		if err != nil {
			r.warn(fmt.Sprintf("a certificate that does not parse was skipped: %v", err))
			continue
		}
		certs = append(certs, c)
		certIDs = append(certIDs, b.keyID)
		if out.FriendlyName == "" {
			out.FriendlyName = b.name
		}
	}
	if keys > 1 {
		r.warn(fmt.Sprintf("the file holds %d private keys; only the first was read", keys))
	}
	match := -1
	if keyBag != nil {
		key, err := x509.ParsePKCS8PrivateKey(keyBag.der)
		if err != nil {
			clear(keyBag.der)
			if !r.macOK {
				// Decrypted with the wrong password, and the padding
				// happened to look right: nothing checked the password.
				return nil, ErrPassword
			}
			return nil, fmt.Errorf("%w: the private key: %v", ErrUnsupported, err)
		}
		out.PrivateKey, out.PrivateKeyPKCS8 = key, keyBag.der
		if keyBag.name != "" {
			out.FriendlyName = keyBag.name
		}
		if len(keyBag.keyID) > 0 {
			for i, id := range certIDs {
				if bytes.Equal(id, keyBag.keyID) {
					match = i
					break
				}
			}
		}
		if match < 0 {
			type pub interface{ Public() crypto.PublicKey }
			if k, ok := key.(pub); ok {
				type equaler interface{ Equal(crypto.PublicKey) bool }
				for i, c := range certs {
					if e, ok := k.Public().(equaler); ok && e.Equal(c.PublicKey) {
						match = i
						break
					}
				}
			}
		}
		if match < 0 && len(certs) > 0 {
			r.warn("no certificate in the file is for its private key")
		}
	} else if len(certs) > 0 {
		match = 0
	}
	for i, c := range certs {
		if i == match {
			out.Certificate = c
		} else {
			out.CACertificates = append(out.CACertificates, c)
		}
	}
	out.Warnings = r.warnings
	return out, nil
}

// PKCS12Options choose how EncodePKCS12 writes.
type PKCS12Options struct {
	// Iterations is the PBKDF2 and MAC iteration count; zero means
	// 600,000.
	Iterations int
	// FriendlyName names the key in the importing program.
	FriendlyName string
}

// EncodePKCS12 writes a PKCS #12 file holding the private key, its
// certificate and the CA certificates, protected by password (its UTF-8
// bytes): the key and the certificates are each encrypted with PBES2
// (PBKDF2 with HMAC-SHA-256, AES-256-CBC), and the whole is checked by a
// SHA-256 MAC. That is what OpenSSL 3 writes by default and what Windows
// reads; very old readers (macOS before 15) need Triple DES, which is not
// written here.
func EncodePKCS12(key crypto.PrivateKey, cert *x509.Certificate, caCerts []*x509.Certificate, password []byte, opts *PKCS12Options) ([]byte, error) {
	var o PKCS12Options
	if opts != nil {
		o = *opts
	}
	iter := o.Iterations
	if iter == 0 {
		iter = 600_000
	}
	if iter < 1 {
		return nil, errors.New("svcms: iterations must be positive")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("svcms: %w", err)
	}
	defer clear(pkcs8)
	if cert != nil {
		type pub interface{ Public() crypto.PublicKey }
		type equaler interface{ Equal(crypto.PublicKey) bool }
		k, ok1 := key.(pub)
		if ok1 {
			if e, ok := k.Public().(equaler); !ok || !e.Equal(cert.PublicKey) {
				return nil, errors.New("svcms: the certificate is not for the private key")
			}
		}
	}
	rnd := func(b []byte) { rand.Read(b) }

	var keyID []byte
	if cert != nil {
		sum := sha1.Sum(cert.Raw) // an identifier only, as OpenSSL makes it
		keyID = sum[:]
	}
	attrs := func(withID bool) []byte {
		var list [][]byte
		if withID && keyID != nil {
			list = append(list, buildAttribute(oidAttrLocalKeyID, element(func(b *cryptobyte.Builder) { b.AddASN1OctetString(keyID) })))
		}
		if o.FriendlyName != "" {
			list = append(list, buildAttribute(oidAttrFriendlyName, element(func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(30), func(b *cryptobyte.Builder) {
					for _, u := range utf16.Encode([]rune(o.FriendlyName)) {
						b.AddUint16(u)
					}
				})
			})))
		}
		if len(list) == 0 {
			return nil
		}
		return derSet(list)
	}
	bag := func(id asn1.ObjectIdentifier, value []byte, attrSet []byte) []byte {
		return element(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(id)
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(value) })
				if attrSet != nil {
					b.AddBytes(attrSet)
				}
			})
		})
	}
	seqOf := func(elems [][]byte) []byte {
		return element(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, e := range elems {
					b.AddBytes(e)
				}
			})
		})
	}

	// The certificates, encrypted as one EncryptedData.
	var certBags [][]byte
	all := caCerts
	if cert != nil {
		all = append([]*x509.Certificate{cert}, caCerts...)
	}
	for i, c := range all {
		value := element(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidX509CertificateBag)
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddASN1OctetString(c.Raw) })
			})
		})
		certBags = append(certBags, bag(oidCertBag, value, attrs(i == 0 && cert != nil)))
	}
	var safes [][]byte
	if len(certBags) > 0 {
		alg, ct, err := pbes2Encrypt(password, seqOf(certBags), iter, rnd)
		if err != nil {
			return nil, err
		}
		encData := element(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(0)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(OIDData)
					b.AddBytes(alg)
					b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(ct) })
				})
			})
		})
		safes = append(safes, buildContentInfo(OIDEncryptedData, encData))
	}

	// The key, shrouded, in a plain SafeContents.
	alg, ct, err := pbes2Encrypt(password, pkcs8, iter, rnd)
	if err != nil {
		return nil, err
	}
	epki := element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(alg)
			b.AddASN1OctetString(ct)
		})
	})
	keySafe := seqOf([][]byte{bag(oidPKCS8ShroudedKey, epki, attrs(true))})
	safes = append(safes, buildContentInfo(OIDData, element(func(b *cryptobyte.Builder) { b.AddASN1OctetString(keySafe) })))

	authSafe := seqOf(safes)
	salt := make([]byte, 16)
	rnd(salt)
	bmp := bmpPassword(password)
	macKey := pkcs12KDF(crypto.SHA256, 3, bmp, salt, iter, 32)
	clear(bmp)
	mac := pkcs12MAC(crypto.SHA256, macKey, authSafe)
	clear(macKey)

	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(3)
			b.AddBytes(buildContentInfo(OIDData, element(func(b *cryptobyte.Builder) { b.AddASN1OctetString(authSafe) })))
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					addAlgorithm(b, oidSHA256, addNull)
					b.AddASN1OctetString(mac)
				})
				b.AddASN1OctetString(salt)
				b.AddASN1Int64(int64(iter))
			})
		})
	}), nil
}
