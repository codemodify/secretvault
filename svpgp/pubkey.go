package svpgp

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"time"
)

// Public key packets (RFC 9580, section 5.5.2): version 4 and 6. Versions
// 2 and 3 (PGP 2) and 5 (LibrePGP) are refused.

const (
	minRSABits = 2048
	maxRSABits = 8192
)

type publicKey struct {
	version int
	created time.Time
	alg     PublicKeyAlgorithm
	body    []byte // the public key packet body, from the version on
	fp      []byte // fingerprint: SHA-1 for v4, SHA-256 for v6
	keyID   uint64

	// The parsed key material; what is set depends on alg.
	rsa       *rsa.PublicKey
	dsa       *dsa.PublicKey
	elg       *elGamalKey
	curve     *curve
	point     []byte // the EC point as the wire carries it inside its MPI
	ecdsa     *ecdsa.PublicKey
	ecdh      *ecdh.PublicKey // ECDH (NIST curves, Curve25519Legacy) and X25519
	kdfHash   HashAlgorithm   // ECDH
	kdfCipher CipherAlgorithm // ECDH
	ed        ed25519.PublicKey

	// unusable says why the key cannot be used, for a key that parses but
	// uses an algorithm, curve or size this package refuses.
	unusable error
}

type elGamalKey struct{ p, g, y *big.Int }

// fingerprint is the key's fingerprint.
func (pk *publicKey) fingerprint() []byte { return pk.fp }

// parsePublicKey reads the public part of a key packet. For a secret key
// packet, the bytes after the public part are returned.
func parsePublicKey(body []byte, secret bool) (*publicKey, []byte, error) {
	p := newParser(body)
	pk := &publicKey{version: int(p.u8())}
	if p.err != nil {
		return nil, nil, p.err
	}
	switch pk.version {
	case 4, 6:
	case 2, 3:
		return nil, nil, unsupported("version %d keys (PGP 2)", pk.version)
	default:
		return nil, nil, unsupported("version %d keys", pk.version)
	}
	pk.created = p.time()
	pk.alg = PublicKeyAlgorithm(p.u8())
	var material *parser
	if pk.version == 6 {
		n := p.u32()
		m := p.bytes(int(min(n, 1<<30)))
		if p.err == nil && int64(n) != int64(len(m)) {
			return nil, nil, malformed("key material length %d", n)
		}
		if p.err != nil {
			return nil, nil, p.err
		}
		material = newParser(m)
	} else {
		if p.err != nil {
			return nil, nil, p.err
		}
		material = newParser(p.rest())
	}
	if err := pk.parseMaterial(material, secret); err != nil {
		return nil, nil, err
	}
	var rest []byte
	if pk.version == 6 {
		material.done()
		if material.err != nil {
			return nil, nil, material.err
		}
		rest = p.rest()
	} else {
		rest = material.rest()
	}
	if !secret && len(rest) != 0 {
		return nil, nil, malformed("%d unexpected bytes after the public key material", len(rest))
	}
	pk.body = body[:len(body)-len(rest)]
	pk.computeFingerprint()
	return pk, rest, nil
}

// parseMaterial reads the algorithm-specific public key fields. A key it
// can delimit but not use gets pk.unusable rather than an error.
func (pk *publicKey) parseMaterial(p *parser, secret bool) error {
	strict := pk.version == 6
	switch pk.alg {
	case RSA, RSAEncryptOnly, RSASignOnly:
		n, e := p.mpi(strict), p.mpi(strict)
		if p.err != nil {
			return p.err
		}
		pk.parseRSA(n, e)
	case DSA:
		pp, q, g, y := p.mpi(strict), p.mpi(strict), p.mpi(strict), p.mpi(strict)
		if p.err != nil {
			return p.err
		}
		pk.parseDSA(pp, q, g, y)
	case ElGamal:
		pp, g, y := p.mpi(strict), p.mpi(strict), p.mpi(strict)
		if p.err != nil {
			return p.err
		}
		pk.elg = &elGamalKey{new(big.Int).SetBytes(pp), new(big.Int).SetBytes(g), new(big.Int).SetBytes(y)}
		if bits := pk.elg.p.BitLen(); bits < 1024 || bits > 4096 {
			pk.unusable = unsupported("an ElGamal key of %d bits", bits)
		}
		if pk.version == 6 {
			pk.unusable = unsupported("ElGamal in a version 6 key")
		}
	case ECDSA, EdDSALegacy, ECDH:
		c, cerr := parseCurveOID(p)
		point := p.mpi(strict)
		var kdf []byte
		if pk.alg == ECDH {
			n := int(p.u8())
			if p.err == nil && (n == 0 || n == 0xFF) {
				return malformed("reserved ECDH KDF parameter length %d", n)
			}
			kdf = p.bytes(n)
		}
		if p.err != nil {
			return p.err
		}
		pk.curve, pk.point = c, point
		if cerr != nil {
			pk.unusable = cerr
			return nil
		}
		pk.parseEC(kdf)
	case X25519:
		b := p.bytes(32)
		if p.err != nil {
			return p.err
		}
		pk.point = b
		k, err := ecdh.X25519().NewPublicKey(b)
		if err != nil {
			pk.unusable = malformed("X25519 public key: %v", err)
		} else {
			pk.ecdh = k
		}
	case Ed25519:
		b := p.bytes(32)
		if p.err != nil {
			return p.err
		}
		pk.point = b
		pk.ed = ed25519.PublicKey(b)
	case X448:
		pk.point = p.bytes(56)
		pk.unusable = unsupported("X448 keys")
	case Ed448:
		pk.point = p.bytes(57)
		pk.unusable = unsupported("Ed448 keys")
	default:
		if pk.version == 4 && secret {
			// Without a length, the public part of a version 4 secret key
			// of an unknown algorithm cannot be told apart from the secret
			// part that follows it.
			return unsupported("%v keys", pk.alg)
		}
		p.rest()
		pk.unusable = unsupported("%v keys", pk.alg)
	}
	return p.err
}

func (pk *publicKey) parseRSA(n, e []byte) {
	nn := new(big.Int).SetBytes(n)
	ee := new(big.Int).SetBytes(e)
	if nn.Sign() == 0 || nn.Bit(0) == 0 || !ee.IsInt64() || ee.Int64() < 3 || ee.Int64() > 1<<31-1 || ee.Bit(0) == 0 {
		pk.unusable = malformed("RSA public key parameters")
		return
	}
	pk.rsa = &rsa.PublicKey{N: nn, E: int(ee.Int64())}
	if bits := nn.BitLen(); bits < minRSABits || bits > maxRSABits {
		pk.unusable = unsupported("an RSA key of %d bits (the minimum is %d)", bits, minRSABits)
	}
}

func (pk *publicKey) parseDSA(p, q, g, y []byte) {
	key := &dsa.PublicKey{
		Parameters: dsa.Parameters{P: new(big.Int).SetBytes(p), Q: new(big.Int).SetBytes(q), G: new(big.Int).SetBytes(g)},
		Y:          new(big.Int).SetBytes(y),
	}
	pk.dsa = key
	pb, qb := key.P.BitLen(), key.Q.BitLen()
	if pb < 1024 || pb > 3072 || (qb != 160 && qb != 224 && qb != 256) || key.G.Sign() <= 0 || key.Y.Sign() <= 0 {
		pk.unusable = unsupported("a DSA key of %d/%d bits", pb, qb)
	}
	if pk.version == 6 {
		pk.unusable = unsupported("DSA in a version 6 key")
	}
}

// parseEC finishes an ECDSA, EdDSALegacy or ECDH key on a supported curve.
func (pk *publicKey) parseEC(kdf []byte) {
	c := pk.curve
	switch pk.alg {
	case ECDSA:
		if c.ecdsa == nil {
			pk.unusable = unsupported("ECDSA on %v", c)
			return
		}
		key, err := ecdsa.ParseUncompressedPublicKey(c.ecdsa, pk.point)
		if err != nil {
			pk.unusable = malformed("ECDSA public key: %v", err)
			return
		}
		pk.ecdsa = key
	case EdDSALegacy:
		if c != curveEd25519Legacy {
			pk.unusable = unsupported("EdDSA on %v", c)
			return
		}
		if pk.version == 6 {
			pk.unusable = malformed("EdDSALegacy in a version 6 key")
			return
		}
		native, ok := prefixedOctets(pk.point, 32)
		if !ok {
			pk.unusable = malformed("Ed25519Legacy public key encoding")
			return
		}
		pk.ed = ed25519.PublicKey(native)
	case ECDH:
		if c.ecdh == nil {
			pk.unusable = unsupported("ECDH on %v", c)
			return
		}
		if len(kdf) != 3 || kdf[0] != 1 {
			pk.unusable = unsupported("ECDH KDF parameters % X", kdf)
			return
		}
		pk.kdfHash, pk.kdfCipher = HashAlgorithm(kdf[1]), CipherAlgorithm(kdf[2])
		switch pk.kdfHash {
		case SHA256, SHA384, SHA512:
		default:
			pk.unusable = unsupported("ECDH with a %v KDF", pk.kdfHash)
			return
		}
		if !pk.kdfCipher.isAES() {
			pk.unusable = unsupported("ECDH wrapping keys with %v", pk.kdfCipher)
			return
		}
		native := pk.point
		if c == curveCurve25519Legacy {
			if pk.version == 6 {
				pk.unusable = malformed("Curve25519Legacy in a version 6 key")
				return
			}
			var ok bool
			if native, ok = prefixedOctets(pk.point, 32); !ok {
				pk.unusable = malformed("Curve25519Legacy public key encoding")
				return
			}
		} else if pk.version == 6 && (pk.kdfHash != c.kdfHash || pk.kdfCipher != c.kek) {
			pk.unusable = unsupported("a version 6 ECDH key with KDF parameters other than %v and %v", c.kdfHash, c.kek)
			return
		}
		key, err := c.ecdh.NewPublicKey(native)
		if err != nil {
			pk.unusable = malformed("ECDH public key: %v", err)
			return
		}
		pk.ecdh = key
	}
}

func (pk *publicKey) computeFingerprint() {
	if pk.version == 6 {
		h := sha256.New()
		h.Write([]byte{0x9B})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(pk.body))))
		h.Write(pk.body)
		pk.fp = h.Sum(nil)
		pk.keyID = binary.BigEndian.Uint64(pk.fp[:8])
		return
	}
	h := sha1.New()
	h.Write([]byte{0x99, byte(len(pk.body) >> 8), byte(len(pk.body))})
	h.Write(pk.body)
	pk.fp = h.Sum(nil)
	pk.keyID = binary.BigEndian.Uint64(pk.fp[12:])
}

// hashFraming writes the key into a signature hash, framed as a signature
// of the given version wants it (RFC 9580, section 5.2.4).
func (pk *publicKey) appendForHash(dst []byte, sigVersion int) []byte {
	if sigVersion == 6 {
		dst = append(dst, 0x9B)
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(pk.body)))
	} else {
		dst = append(dst, 0x99, byte(len(pk.body)>>8), byte(len(pk.body)))
	}
	return append(dst, pk.body...)
}

// newPublicKey builds a key packet body from its fields and parses it back,
// so a generated key goes through the same checks as a read one.
func newPublicKey(version int, created time.Time, alg PublicKeyAlgorithm, material []byte) (*publicKey, error) {
	body := []byte{byte(version)}
	body = appendU32(body, timeField(created))
	body = append(body, byte(alg))
	if version == 6 {
		body = appendU32(body, uint32(len(material)))
	}
	body = append(body, material...)
	pk, _, err := parsePublicKey(body, false)
	if err != nil {
		return nil, err
	}
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	return pk, nil
}

// signingHashOK reports whether a hash is strong enough for signatures by
// this key: the digest must cover the key's security level (RFC 9580,
// sections 5.2.3.2 to 5.2.3.5).
func (pk *publicKey) signingHashOK(h HashAlgorithm) error {
	size := h.Size()
	need := 0
	switch pk.alg {
	case ECDSA:
		need = pk.curve.fsize
		if pk.curve == curveP521 {
			need = 64
		}
	case EdDSALegacy, Ed25519:
		need = 32
	case DSA:
		need = (pk.dsa.Q.BitLen() + 7) / 8
	}
	if size < need {
		return unsupported("a %v signature by a %v key needs a hash of at least %d bits", h, pk.alg, need*8)
	}
	return nil
}
