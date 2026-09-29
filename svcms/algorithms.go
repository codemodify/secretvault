package svcms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	_ "crypto/sha1" // registered for crypto.SHA1
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// sha1Cutoff is when SHA-1 stops being accepted in signatures, as in
// svpgp and other implementations.
var sha1Cutoff = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

// hashByOID maps a digest algorithm to the standard library's hash.
func hashByOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidMD5):
		return 0, fmt.Errorf("%w: MD5", ErrWeakAlgorithm)
	}
	return 0, unsupported("digest algorithm %v", oid)
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	case crypto.SHA224:
		return oidSHA224
	case crypto.SHA1:
		return oidSHA1
	}
	return nil
}

// hashPolicy says whether a signature made at signed (zero if unknown)
// with h is accepted.
func hashPolicy(h crypto.Hash, signed time.Time) error {
	switch h {
	case crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return nil
	case crypto.SHA1:
		if !signed.IsZero() && signed.Before(sha1Cutoff) {
			return nil
		}
		if signed.IsZero() {
			return fmt.Errorf("%w: SHA-1 in a signature with no signing time", ErrWeakAlgorithm)
		}
		return fmt.Errorf("%w: SHA-1 in a signature made %s", ErrWeakAlgorithm, signed.Format(time.DateOnly))
	}
	return fmt.Errorf("%w: %v", ErrWeakAlgorithm, h)
}

type sigKind int

const (
	sigRSA sigKind = iota + 1
	sigRSAPSS
	sigECDSA
	sigEd25519
)

// sigScheme is what a signature algorithm identifier says: the kind of
// signature, the hash it names (zero when it takes the digest algorithm's)
// and, for RSA-PSS, the salt length.
type sigScheme struct {
	kind    sigKind
	hash    crypto.Hash
	pssSalt int
}

func (s sigScheme) String() string {
	switch s.kind {
	case sigRSA:
		return "RSA PKCS#1 v1.5"
	case sigRSAPSS:
		return "RSA-PSS"
	case sigECDSA:
		return "ECDSA"
	case sigEd25519:
		return "Ed25519"
	}
	return "unknown"
}

func parseSignatureAlgorithm(a algorithm) (sigScheme, error) {
	o := a.oid
	switch {
	case o.Equal(oidRSAEncryption):
		return sigScheme{kind: sigRSA}, nil
	case o.Equal(oidSHA256WithRSA):
		return sigScheme{kind: sigRSA, hash: crypto.SHA256}, nil
	case o.Equal(oidSHA384WithRSA):
		return sigScheme{kind: sigRSA, hash: crypto.SHA384}, nil
	case o.Equal(oidSHA512WithRSA):
		return sigScheme{kind: sigRSA, hash: crypto.SHA512}, nil
	case o.Equal(oidSHA224WithRSA):
		return sigScheme{kind: sigRSA, hash: crypto.SHA224}, nil
	case o.Equal(oidSHA1WithRSA):
		return sigScheme{kind: sigRSA, hash: crypto.SHA1}, nil
	case o.Equal(oidMD5WithRSA):
		return sigScheme{}, fmt.Errorf("%w: MD5 with RSA", ErrWeakAlgorithm)
	case o.Equal(oidRSAPSS):
		return parsePSSParams(a.params)
	case o.Equal(oidECPublicKey):
		return sigScheme{kind: sigECDSA}, nil
	case o.Equal(oidECDSAWithSHA256):
		return sigScheme{kind: sigECDSA, hash: crypto.SHA256}, nil
	case o.Equal(oidECDSAWithSHA384):
		return sigScheme{kind: sigECDSA, hash: crypto.SHA384}, nil
	case o.Equal(oidECDSAWithSHA512):
		return sigScheme{kind: sigECDSA, hash: crypto.SHA512}, nil
	case o.Equal(oidECDSAWithSHA224):
		return sigScheme{kind: sigECDSA, hash: crypto.SHA224}, nil
	case o.Equal(oidECDSAWithSHA1):
		return sigScheme{kind: sigECDSA, hash: crypto.SHA1}, nil
	case o.Equal(oidEd25519):
		if a.params != nil {
			return sigScheme{}, fmt.Errorf("%w: Ed25519 with parameters", ErrSignatureMalformed)
		}
		return sigScheme{kind: sigEd25519}, nil
	}
	return sigScheme{}, unsupported("signature algorithm %v", o)
}

// parsePSSParams reads RSASSA-PSS-params (RFC 4055, section 3.1). The
// mask generation function must be MGF1 with the same hash, which is all
// the standard library does, and all anyone uses.
func parsePSSParams(params []byte) (sigScheme, error) {
	out := sigScheme{kind: sigRSAPSS, hash: crypto.SHA1, pssSalt: 20}
	if params == nil {
		return out, nil
	}
	bad := fmt.Errorf("%w: RSA-PSS parameters", ErrSignatureMalformed)
	s := cryptobyte.String(params)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return out, bad
	}
	mgfHash := crypto.SHA1
	if tag := cbasn1.Tag(0).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		var h algorithm
		if !seq.ReadASN1(&inner, tag) || !readAlgorithm(&inner, &h) || !inner.Empty() {
			return out, bad
		}
		hash, err := hashByOID(h.oid)
		if err != nil {
			return out, err
		}
		out.hash = hash
	}
	if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		var mgf, h algorithm
		if !seq.ReadASN1(&inner, tag) || !readAlgorithm(&inner, &mgf) || !inner.Empty() || !mgf.oid.Equal(oidMGF1) {
			return out, bad
		}
		p := cryptobyte.String(mgf.params)
		if !readAlgorithm(&p, &h) || !p.Empty() {
			return out, bad
		}
		hash, err := hashByOID(h.oid)
		if err != nil {
			return out, err
		}
		mgfHash = hash
	}
	if tag := cbasn1.Tag(2).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		if !seq.ReadASN1(&inner, tag) || !inner.ReadASN1Integer(&out.pssSalt) || !inner.Empty() || out.pssSalt < 0 || out.pssSalt > 1024 {
			return out, bad
		}
	}
	if tag := cbasn1.Tag(3).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		var trailer int
		if !seq.ReadASN1(&inner, tag) || !inner.ReadASN1Integer(&trailer) || !inner.Empty() || trailer != 1 {
			return out, bad
		}
	}
	if !seq.Empty() || !s.Empty() {
		return out, bad
	}
	if mgfHash != out.hash {
		return out, unsupported("RSA-PSS with MGF1 over another hash than the signature's")
	}
	return out, nil
}

// addPSSParams writes RSASSA-PSS-params for hash h, MGF1 with h, and a
// salt as long as the hash.
func addPSSParams(b *cryptobyte.Builder, h crypto.Hash) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			addAlgorithm(b, hashOID(h), nil)
		})
		b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidMGF1, func(b *cryptobyte.Builder) { addAlgorithm(b, hashOID(h), nil) })
		})
		b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(int64(h.Size()))
		})
	})
}

// oaepParams are RSAES-OAEP-params (RFC 4055, section 4.1).
type oaepParams struct {
	hash, mgfHash crypto.Hash
	label         []byte
}

func parseOAEPParams(params []byte) (oaepParams, error) {
	out := oaepParams{hash: crypto.SHA1, mgfHash: crypto.SHA1}
	if params == nil || (len(params) == 2 && params[0] == 0x05 && params[1] == 0) {
		return out, nil
	}
	bad := malformed("RSAES-OAEP parameters")
	s := cryptobyte.String(params)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return out, bad
	}
	if tag := cbasn1.Tag(0).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		var h algorithm
		if !seq.ReadASN1(&inner, tag) || !readAlgorithm(&inner, &h) || !inner.Empty() {
			return out, bad
		}
		hash, err := oaepHash(h.oid)
		if err != nil {
			return out, err
		}
		out.hash = hash
	}
	if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner cryptobyte.String
		var mgf, h algorithm
		if !seq.ReadASN1(&inner, tag) || !readAlgorithm(&inner, &mgf) || !inner.Empty() || !mgf.oid.Equal(oidMGF1) {
			return out, bad
		}
		p := cryptobyte.String(mgf.params)
		if !readAlgorithm(&p, &h) || !p.Empty() {
			return out, bad
		}
		hash, err := oaepHash(h.oid)
		if err != nil {
			return out, err
		}
		out.mgfHash = hash
	}
	if tag := cbasn1.Tag(2).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		var inner, label cryptobyte.String
		var src algorithm
		if !seq.ReadASN1(&inner, tag) || !readAlgorithm(&inner, &src) || !inner.Empty() || !src.oid.Equal(oidPSpecified) {
			return out, bad
		}
		p := cryptobyte.String(src.params)
		if !p.ReadASN1(&label, cbasn1.OCTET_STRING) || !p.Empty() {
			return out, bad
		}
		out.label = append([]byte{}, label...)
	}
	if !seq.Empty() {
		return out, bad
	}
	return out, nil
}

// oaepHash accepts SHA-1 as well: in OAEP it is only a mask and a label
// hash, where collisions do not matter, and it is the default.
func oaepHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	h, err := hashByOID(oid)
	if err != nil {
		return 0, fmt.Errorf("%w: OAEP with %v", ErrUnsupported, oid)
	}
	return h, nil
}

func addOAEPParams(b *cryptobyte.Builder, h crypto.Hash) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			addAlgorithm(b, hashOID(h), nil)
		})
		b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidMGF1, func(b *cryptobyte.Builder) { addAlgorithm(b, hashOID(h), nil) })
		})
	})
}

// contentCipher is a content encryption algorithm and its parameters.
type contentCipher struct {
	name   string
	keyLen int
	gcm    bool
	iv     []byte // the CBC IV or the GCM nonce
	tagLen int    // GCM only
	legacy bool   // Triple DES: decrypted, with a warning, never used to encrypt
}

func parseContentCipher(a algorithm) (*contentCipher, error) {
	c := &contentCipher{}
	o := a.oid
	switch {
	case o.Equal(oidAES128CBC):
		c.name, c.keyLen = "AES-128-CBC", 16
	case o.Equal(oidAES192CBC):
		c.name, c.keyLen = "AES-192-CBC", 24
	case o.Equal(oidAES256CBC):
		c.name, c.keyLen = "AES-256-CBC", 32
	case o.Equal(oidAES128GCM):
		c.name, c.keyLen, c.gcm = "AES-128-GCM", 16, true
	case o.Equal(oidAES192GCM):
		c.name, c.keyLen, c.gcm = "AES-192-GCM", 24, true
	case o.Equal(oidAES256GCM):
		c.name, c.keyLen, c.gcm = "AES-256-GCM", 32, true
	case o.Equal(oidDESEDE3CBC):
		c.name, c.keyLen, c.legacy = "3DES-CBC", 24, true
	case o.Equal(oidRC2CBC):
		return nil, unsupported("RC2 content encryption")
	case o.Equal(oidDESCBC):
		return nil, unsupported("DES content encryption")
	default:
		return nil, unsupported("content encryption algorithm %v", o)
	}
	s := cryptobyte.String(a.params)
	if c.gcm {
		var seq, nonce cryptobyte.String
		c.tagLen = 12
		if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() || !seq.ReadASN1(&nonce, cbasn1.OCTET_STRING) {
			return nil, malformed("GCM parameters")
		}
		if !seq.Empty() && (!seq.ReadASN1Integer(&c.tagLen) || !seq.Empty()) {
			return nil, malformed("GCM parameters")
		}
		if len(nonce) != 12 {
			return nil, unsupported("a %d-byte GCM nonce", len(nonce))
		}
		if c.tagLen < 12 || c.tagLen > 16 {
			return nil, unsupported("a %d-byte GCM tag", c.tagLen)
		}
		c.iv = append([]byte{}, nonce...)
		return c, nil
	}
	var iv cryptobyte.String
	if !s.ReadASN1(&iv, cbasn1.OCTET_STRING) || !s.Empty() {
		return nil, malformed("%s parameters", c.name)
	}
	want := aes.BlockSize
	if c.legacy {
		want = des.BlockSize
	}
	if len(iv) != want {
		return nil, malformed("%s IV of %d bytes", c.name, len(iv))
	}
	c.iv = append([]byte{}, iv...)
	return c, nil
}

func (c *contentCipher) block(key []byte) (cipher.Block, error) {
	if len(key) != c.keyLen {
		return nil, ErrDecryption
	}
	if c.legacy {
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}

// decrypt decrypts content, checking the GCM tag (with aad) or the CBC
// padding. Every failure is ErrDecryption.
func (c *contentCipher) decrypt(key, ciphertext, tag, aad []byte) ([]byte, error) {
	b, err := c.block(key)
	if err != nil {
		return nil, ErrDecryption
	}
	if c.gcm {
		if len(tag) != c.tagLen {
			return nil, ErrDecryption
		}
		g, err := cipher.NewGCMWithTagSize(b, c.tagLen)
		if err != nil {
			return nil, ErrDecryption
		}
		sealed := make([]byte, 0, len(ciphertext)+len(tag))
		sealed = append(append(sealed, ciphertext...), tag...)
		plain, err := g.Open(sealed[:0], c.iv, sealed, aad)
		if err != nil {
			return nil, ErrDecryption
		}
		return plain, nil
	}
	bs := b.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, ErrDecryption
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(b, c.iv).CryptBlocks(plain, ciphertext)
	n, ok := unpad(plain, bs)
	if !ok {
		clear(plain)
		return nil, ErrDecryption
	}
	return plain[:n], nil
}

// unpad checks PKCS #7 padding in time that does not depend on the
// padding's value, and returns the length of the content.
func unpad(b []byte, bs int) (int, bool) {
	p := int(b[len(b)-1])
	good := subtle.ConstantTimeLessOrEq(1, p) & subtle.ConstantTimeLessOrEq(p, bs)
	for i := 1; i <= bs && i <= len(b); i++ {
		inPad := subtle.ConstantTimeLessOrEq(i, p)
		same := subtle.ConstantTimeByteEq(b[len(b)-i], byte(p))
		good &= subtle.ConstantTimeSelect(inPad, same, 1)
	}
	if good != 1 {
		return 0, false
	}
	return len(b) - p, true
}

// pad appends PKCS #7 padding.
func pad(b []byte, bs int) []byte {
	p := bs - len(b)%bs
	for range p {
		b = append(b, byte(p))
	}
	return b
}

// keyWrapAlgorithm is an AES key wrap algorithm, by its key length.
func keyWrapKeyLen(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128Wrap):
		return 16, nil
	case oid.Equal(oidAES192Wrap):
		return 24, nil
	case oid.Equal(oidAES256Wrap):
		return 32, nil
	}
	return 0, unsupported("key wrap algorithm %v", oid)
}

// kdfHash is the hash of an ECDH key agreement scheme's X9.63 KDF.
func kdfHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidECDHSHA256KDF), oid.Equal(oidECDHCofactorSHA256KDF):
		return crypto.SHA256, nil
	case oid.Equal(oidECDHSHA384KDF), oid.Equal(oidECDHCofactorSHA384KDF):
		return crypto.SHA384, nil
	case oid.Equal(oidECDHSHA512KDF), oid.Equal(oidECDHCofactorSHA512KDF):
		return crypto.SHA512, nil
	case oid.Equal(oidECDHSHA224KDF), oid.Equal(oidECDHCofactorSHA224KDF):
		return crypto.SHA224, nil
	case oid.Equal(oidECDHSHA1KDF), oid.Equal(oidECDHCofactorSHA1KDF):
		// In a KDF SHA-1 is not open to collision attacks, and OpenSSL
		// used this scheme by default for years.
		return crypto.SHA1, nil
	}
	return 0, unsupported("key agreement algorithm %v", oid)
}
