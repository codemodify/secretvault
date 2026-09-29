package svpgp

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Signature packets (RFC 9580, section 5.2): versions 3, 4 and 6. Version 3
// is read for old data signatures only.

// Signature subpacket types (RFC 9580, section 5.2.3.8).
const (
	spCreationTime      = 2
	spSigExpiration     = 3
	spExportable        = 4
	spTrust             = 5
	spRegex             = 6
	spRevocable         = 7
	spKeyExpiration     = 9
	spPrefSymmetric     = 11
	spRevocationKey     = 12
	spIssuerKeyID       = 16
	spNotation          = 20
	spPrefHash          = 21
	spPrefCompression   = 22
	spKeyserverPrefs    = 23
	spPrefKeyserver     = 24
	spPrimaryUserID     = 25
	spPolicyURI         = 26
	spKeyFlags          = 27
	spSignerUserID      = 28
	spRevocationReason  = 29
	spFeatures          = 30
	spSignatureTarget   = 31
	spEmbeddedSignature = 32
	spIssuerFingerprint = 33
	spIntendedRecipient = 35
	spPrefAEAD          = 39
)

// The hash policy: SHA-1 is not accepted in signatures made on or after
// this date (see the package documentation).
var sha1Cutoff = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

type signature struct {
	version  int
	typ      SignatureType
	alg      PublicKeyAlgorithm
	hash     HashAlgorithm
	hashed   []byte // the hashed subpacket area
	unhashed []byte // the unhashed subpacket area
	left16   [2]byte
	salt     []byte // version 6
	material []byte // the algorithm-specific signature fields
	body     []byte // the whole packet body

	// From the hashed area (or the version 3 header).
	created       time.Time
	hasCreated    bool
	sigExpiry     uint32 // seconds after creation; 0 is never
	keyExpiry     uint32 // seconds after the key's creation; 0 is never
	keyFlags      []byte
	hasKeyFlags   bool
	prefSymmetric []byte
	prefHash      []byte
	prefCompress  []byte
	prefAEAD      []byte // pairs of cipher and AEAD mode
	features      []byte
	hasFeatures   bool
	primaryUserID bool
	revReason     byte
	revText       string
	hasRevReason  bool
	recipients    [][]byte // intended recipient fingerprints, each with its version octet
	exportable    bool

	// From either area: they only say where to look for the key.
	issuerKeyID    uint64
	hasIssuerKeyID bool
	issuerFP       []byte
	embedded       *signature // from either area: it verifies on its own

	// invalid says why this signature must not validate even though it
	// parses: an unknown critical subpacket, a salt of the wrong size, a
	// missing creation time (RFC 9580, section 5.2.5).
	invalid error

	// For self-signatures on keys: whether it was checked, and the result.
	checked  bool
	checkErr error
}

// parseSignature reads a signature packet body. depth counts embedded
// signatures, which may not nest.
func parseSignature(body []byte, depth int) (*signature, error) {
	p := newParser(body)
	s := &signature{version: int(p.u8()), body: body, exportable: true}
	switch s.version {
	case 3:
		if n := p.u8(); p.err == nil && n != 5 {
			return nil, malformed("version 3 signature with %d hashed bytes", n)
		}
		s.typ = SignatureType(p.u8())
		s.created, s.hasCreated = p.time(), true
		if id := p.bytes(8); p.err == nil {
			s.issuerKeyID, s.hasIssuerKeyID = binary.BigEndian.Uint64(id), true
		}
		s.alg = PublicKeyAlgorithm(p.u8())
		s.hash = HashAlgorithm(p.u8())
		copy(s.left16[:], p.bytes(2))
	case 4, 6:
		s.typ = SignatureType(p.u8())
		s.alg = PublicKeyAlgorithm(p.u8())
		s.hash = HashAlgorithm(p.u8())
		var n int
		if s.version == 4 {
			n = int(p.u16())
		} else {
			n = int(min(p.u32(), 1<<30))
		}
		s.hashed = p.bytes(n)
		if s.version == 4 {
			n = int(p.u16())
		} else {
			n = int(min(p.u32(), 1<<30))
		}
		s.unhashed = p.bytes(n)
		copy(s.left16[:], p.bytes(2))
		if s.version == 6 {
			s.salt = p.bytes(int(p.u8()))
		}
	default:
		if p.err != nil {
			return nil, p.err
		}
		return nil, unsupported("version %d signatures", s.version)
	}
	if p.err != nil {
		return nil, p.err
	}
	var err error
	if s.material, err = parseSignatureMaterial(p, s.alg, s.version == 6); err != nil {
		return nil, err
	}
	p.done()
	if p.err != nil {
		return nil, p.err
	}
	if s.version == 3 {
		// Version 3 signatures predate the elliptic curve algorithms,
		// which must not be used with them (RFC 9580, section 5.2.3).
		if s.alg != RSA && s.alg != RSASignOnly && s.alg != DSA {
			s.invalid = malformed("a version 3 signature with %v", s.alg)
		}
		return s, nil
	}
	if s.version == 6 && len(s.salt) != s.hash.saltSize() {
		s.invalid = malformed("a %d-byte salt with %v", len(s.salt), s.hash)
	}
	if err := s.parseSubpackets(s.hashed, true, depth); err != nil {
		return nil, err
	}
	if err := s.parseSubpackets(s.unhashed, false, depth); err != nil {
		return nil, err
	}
	if !s.hasCreated && s.invalid == nil {
		s.invalid = malformed("signature without a hashed creation time")
	}
	return s, nil
}

// parseSignatureMaterial reads and checks the shape of the algorithm-specific
// fields. Their values are checked when the signature is verified.
func parseSignatureMaterial(p *parser, alg PublicKeyAlgorithm, strict bool) ([]byte, error) {
	start := p.off
	switch alg {
	case RSA, RSASignOnly, RSAEncryptOnly:
		p.mpi(strict)
	case DSA, ECDSA, EdDSALegacy:
		p.mpi(strict)
		p.mpi(strict)
	case Ed25519:
		p.bytes(64)
	case Ed448:
		p.bytes(114)
	default:
		p.rest()
	}
	if p.err != nil {
		return nil, p.err
	}
	return p.b[start:p.off:p.off], nil
}

// parseSubpackets reads one subpacket area. Only a few subpackets are
// taken from the unhashed area: the issuer, which only says which key to
// try, and the embedded signature, which verifies on its own.
func (s *signature) parseSubpackets(area []byte, hashed bool, depth int) error {
	count := 0
	for len(area) > 0 {
		count++
		if count > maxSubpackets {
			return limit("more than %d subpackets", maxSubpackets)
		}
		n, hdr, ok := subpacketLength(area)
		if !ok || n == 0 || n > len(area)-hdr {
			return malformed("subpacket length runs past its area")
		}
		typ := area[hdr]
		data := area[hdr+1 : hdr+n : hdr+n]
		area = area[hdr+n:]
		critical := typ&0x80 != 0
		typ &= 0x7F
		if err := s.subpacket(typ, critical, hashed, data, depth); err != nil {
			if hashed && s.invalid == nil {
				s.invalid = err
			}
		}
	}
	return nil
}

func subpacketLength(b []byte) (n, hdr int, ok bool) {
	switch {
	case b[0] < 192:
		return int(b[0]), 1, true
	case b[0] < 255:
		if len(b) < 2 {
			return 0, 0, false
		}
		return (int(b[0])-192)<<8 + int(b[1]) + 192, 2, true
	default:
		if len(b) < 5 {
			return 0, 0, false
		}
		v := binary.BigEndian.Uint32(b[1:5])
		if v > 1<<30 {
			return 0, 0, false
		}
		return int(v), 5, true
	}
}

// subpacket takes in one subpacket. An error makes the signature invalid
// if the subpacket is hashed.
func (s *signature) subpacket(typ byte, critical, hashed bool, data []byte, depth int) error {
	size := func(want int) error {
		if len(data) != want {
			return malformed("subpacket %d of %d bytes, want %d", typ, len(data), want)
		}
		return nil
	}
	if !hashed {
		switch typ {
		case spIssuerKeyID:
			if size(8) == nil && !s.hasIssuerKeyID {
				s.issuerKeyID, s.hasIssuerKeyID = binary.BigEndian.Uint64(data), true
			}
		case spIssuerFingerprint:
			if len(data) > 1 && s.issuerFP == nil {
				if err := s.setIssuerFP(data); err != nil {
					return err
				}
			}
		case spEmbeddedSignature:
			if s.embedded == nil && depth == 0 {
				if e, err := parseSignature(bytes.Clone(data), depth+1); err == nil {
					s.embedded = e
				}
			}
		}
		return nil
	}
	switch typ {
	case spCreationTime:
		if err := size(4); err != nil {
			return err
		}
		s.created, s.hasCreated = unixTime(binary.BigEndian.Uint32(data)), true
	case spSigExpiration:
		if err := size(4); err != nil {
			return err
		}
		s.sigExpiry = binary.BigEndian.Uint32(data)
	case spKeyExpiration:
		if err := size(4); err != nil {
			return err
		}
		s.keyExpiry = binary.BigEndian.Uint32(data)
	case spExportable:
		if err := size(1); err != nil {
			return err
		}
		s.exportable = data[0] != 0
	case spRevocable, spTrust, spRegex, spRevocationKey, spKeyserverPrefs, spPrefKeyserver, spPolicyURI, spSignerUserID, spSignatureTarget:
		// Recognised, and not needed to decide validity here.
	case spPrefSymmetric:
		s.prefSymmetric = data
	case spPrefHash:
		s.prefHash = data
	case spPrefCompression:
		s.prefCompress = data
	case spPrefAEAD:
		if len(data)%2 != 0 {
			return malformed("preferred AEAD ciphersuites of odd length")
		}
		s.prefAEAD = data
	case spFeatures:
		s.features, s.hasFeatures = data, true
	case spKeyFlags:
		s.keyFlags, s.hasKeyFlags = data, true
	case spPrimaryUserID:
		if err := size(1); err != nil {
			return err
		}
		s.primaryUserID = data[0] != 0
	case spRevocationReason:
		if len(data) < 1 {
			return malformed("empty reason for revocation")
		}
		s.revReason, s.revText, s.hasRevReason = data[0], string(data[1:]), true
	case spIssuerKeyID:
		if err := size(8); err != nil {
			return err
		}
		s.issuerKeyID, s.hasIssuerKeyID = binary.BigEndian.Uint64(data), true
	case spIssuerFingerprint:
		return s.setIssuerFP(data)
	case spIntendedRecipient:
		if len(data) < 1 || (data[0] == 4 && len(data) != 21) || (data[0] == 6 && len(data) != 33) {
			return malformed("intended recipient fingerprint of %d bytes", len(data))
		}
		s.recipients = append(s.recipients, data)
	case spEmbeddedSignature:
		if depth > 0 {
			return malformed("nested embedded signature")
		}
		e, err := parseSignature(bytes.Clone(data), depth+1)
		if err != nil {
			return err
		}
		s.embedded = e
	case spNotation:
		if critical {
			// No notation is understood, so a critical one is unknown.
			return unsupported("a critical notation")
		}
	default:
		if critical {
			return unsupported("critical subpacket type %d", typ)
		}
	}
	return nil
}

func (s *signature) setIssuerFP(data []byte) error {
	if len(data) == 0 {
		return malformed("empty issuer fingerprint")
	}
	v := int(data[0])
	if (v == 4 && len(data) != 21) || (v == 6 && len(data) != 33) || (v != 4 && v != 6) {
		return malformed("issuer fingerprint of version %d and %d bytes", v, len(data)-1)
	}
	if v != s.version {
		return malformed("a version %d issuer fingerprint in a version %d signature", v, s.version)
	}
	s.issuerFP = data[1:]
	return nil
}

// expiresAt is when the signature expires, or zero for never.
func (s *signature) expiresAt() time.Time {
	if s.sigExpiry == 0 {
		return time.Time{}
	}
	return s.created.Add(time.Duration(s.sigExpiry) * time.Second)
}

// expiredAt reports whether the signature has expired at t.
func (s *signature) expiredAt(t time.Time) bool {
	e := s.expiresAt()
	return !e.IsZero() && !t.Before(e)
}

func (s *signature) flags() byte {
	if len(s.keyFlags) == 0 {
		return 0
	}
	return s.keyFlags[0]
}

// hardRevocation reports whether a key revocation invalidates the key for
// all time: when it was compromised, or for any reason but these two.
// Superseded and retired keys stay good for what they signed before.
func (s *signature) hardRevocation() bool {
	return !s.hasRevReason || s.revReason != byte(RevocationSuperseded) && s.revReason != byte(RevocationRetired)
}

// hashPolicy says whether the signature's hash is accepted, given when the
// signature says it was made.
func (s *signature) hashPolicy() error {
	switch s.hash {
	case SHA256, SHA384, SHA512, SHA224, SHA3_256, SHA3_512:
		return nil
	case SHA1:
		if s.version == 6 {
			return ErrWeakAlgorithm
		}
		if s.created.Before(sha1Cutoff) {
			return nil
		}
		return ErrWeakAlgorithm
	}
	return ErrWeakAlgorithm
}

// newHash starts the hash for this signature: the salt comes first in
// version 6 (RFC 9580, section 5.2.4).
func (s *signature) newHash() (hash.Hash, error) {
	h, err := s.hash.newHash()
	if err != nil {
		return nil, err
	}
	if s.version == 6 {
		h.Write(s.salt)
	}
	return h, nil
}

// writeTrailer hashes the signature's own fields after the signed data.
func (s *signature) writeTrailer(h hash.Hash) {
	if s.version == 3 {
		var t [5]byte
		t[0] = byte(s.typ)
		binary.BigEndian.PutUint32(t[1:], timeField(s.created))
		h.Write(t[:])
		return
	}
	prefix := s.hashedPrefix()
	h.Write(prefix)
	var t [6]byte
	t[0], t[1] = byte(s.version), 0xFF
	binary.BigEndian.PutUint32(t[2:], uint32(len(prefix)))
	h.Write(t[:])
}

// hashedPrefix is the part of a version 4 or 6 signature that is hashed:
// from the version through the hashed subpackets.
func (s *signature) hashedPrefix() []byte {
	out := []byte{byte(s.version), byte(s.typ), byte(s.alg), byte(s.hash)}
	if s.version == 4 {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s.hashed)))
	} else {
		out = binary.BigEndian.AppendUint32(out, uint32(len(s.hashed)))
	}
	return append(out, s.hashed...)
}

// verifyDigest checks the signature over a finished digest with a public
// key: the quick-check bits, the key's algorithm and hash strength, and the
// signature itself.
func (s *signature) verifyDigest(pk *publicKey, digest []byte) error {
	if pk.unusable != nil {
		return pk.unusable
	}
	if !sameSigningAlgorithm(s.alg, pk.alg) {
		return malformed("a %v signature from a %v key", s.alg, pk.alg)
	}
	if s.version == 6 && pk.version != 6 || s.version != 6 && pk.version == 6 {
		return malformed("a version %d signature from a version %d key", s.version, pk.version)
	}
	if err := pk.signingHashOK(s.hash); err != nil {
		return err
	}
	if len(digest) < 2 || subtle.ConstantTimeCompare(digest[:2], s.left16[:]) != 1 {
		return ErrBadSignature
	}
	p := newParser(s.material)
	switch pk.alg {
	case RSA, RSASignOnly:
		sig := p.mpi(s.version == 6)
		k := pk.rsa.Size()
		if p.err != nil || len(sig) > k {
			return ErrBadSignature
		}
		padded, _ := fixedOctets(sig, k)
		ch, _ := s.hash.cryptoHash()
		if rsa.VerifyPKCS1v15(pk.rsa, ch, digest, padded) != nil {
			return ErrBadSignature
		}
		return nil
	case DSA:
		r, ss := p.mpi(s.version == 6), p.mpi(s.version == 6)
		if p.err != nil {
			return ErrBadSignature
		}
		// DSA uses the leftmost bits of the digest, as many as q has.
		z := new(big.Int).SetBytes(digest)
		if excess := len(digest)*8 - pk.dsa.Q.BitLen(); excess > 0 {
			z.Rsh(z, uint(excess))
		}
		if !dsa.Verify(pk.dsa, z.Bytes(), new(big.Int).SetBytes(r), new(big.Int).SetBytes(ss)) {
			return ErrBadSignature
		}
		return nil
	case ECDSA:
		r, ss := p.mpi(s.version == 6), p.mpi(s.version == 6)
		if p.err != nil {
			return ErrBadSignature
		}
		if !ecdsa.VerifyASN1(pk.ecdsa, digest, asn1Signature(r, ss)) {
			return ErrBadSignature
		}
		return nil
	case EdDSALegacy:
		r, ss := p.mpi(s.version == 6), p.mpi(s.version == 6)
		if p.err != nil {
			return ErrBadSignature
		}
		rr, ok1 := fixedOctets(r, 32)
		sb, ok2 := fixedOctets(ss, 32)
		if !ok1 || !ok2 || !ed25519.Verify(pk.ed, digest, append(rr, sb...)) {
			return ErrBadSignature
		}
		return nil
	case Ed25519:
		if len(s.material) != 64 || !ed25519.Verify(pk.ed, digest, s.material) {
			return ErrBadSignature
		}
		return nil
	}
	return unsupported("%v signatures", pk.alg)
}

func sameSigningAlgorithm(sig, key PublicKeyAlgorithm) bool {
	if sig == key {
		return true
	}
	return (sig == RSA || sig == RSASignOnly) && (key == RSA || key == RSASignOnly)
}

// asn1Signature encodes r and s as the DER SEQUENCE the standard library's
// ECDSA takes.
func asn1Signature(r, s []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(r))
		b.AddASN1BigInt(new(big.Int).SetBytes(s))
	})
	out, _ := b.Bytes()
	return out
}

// parseASN1Signature decodes an ECDSA signature from the standard library.
func parseASN1Signature(der []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	in := cryptobyte.String(der)
	rr, ss := new(big.Int), new(big.Int)
	if !in.ReadASN1(&inner, cbasn1.SEQUENCE) || !in.Empty() ||
		!inner.ReadASN1Integer(rr) || !inner.ReadASN1Integer(ss) || !inner.Empty() {
		return nil, nil, malformed("ECDSA signature encoding")
	}
	return rr.Bytes(), ss.Bytes(), nil
}

// subpacketBuilder assembles a subpacket area.
type subpacketBuilder []byte

func (b *subpacketBuilder) add(typ byte, critical bool, data ...byte) {
	if critical {
		typ |= 0x80
	}
	*b = appendLength(*b, len(data)+1)
	*b = append(append(*b, typ), data...)
}

func (b *subpacketBuilder) addTime(typ byte, critical bool, t uint32) {
	b.add(typ, critical, byte(t>>24), byte(t>>16), byte(t>>8), byte(t))
}

// assemble builds a version 4 or 6 signature body from its parts and parses
// it back, so a new signature goes through the same checks as a read one.
func assembleSignature(version int, typ SignatureType, alg PublicKeyAlgorithm, h HashAlgorithm, hashed, unhashed, salt []byte, left16 []byte, material []byte) (*signature, error) {
	body := []byte{byte(version), byte(typ), byte(alg), byte(h)}
	if version == 4 {
		body = binary.BigEndian.AppendUint16(body, uint16(len(hashed)))
		body = append(body, hashed...)
		body = binary.BigEndian.AppendUint16(body, uint16(len(unhashed)))
		body = append(body, unhashed...)
	} else {
		body = binary.BigEndian.AppendUint32(body, uint32(len(hashed)))
		body = append(body, hashed...)
		body = binary.BigEndian.AppendUint32(body, uint32(len(unhashed)))
		body = append(body, unhashed...)
	}
	body = append(body, left16...)
	if version == 6 {
		body = append(append(body, byte(len(salt))), salt...)
	}
	body = append(body, material...)
	return parseSignature(body, 0)
}
