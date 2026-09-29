package svpgp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rsa"
	"math/big"
	"slices"
	"time"
)

// Keys as GnuPG's agent protocol uses them (svgpgagent, and the gpg-agent
// face in svd). gpg makes and reads the OpenPGP packets itself, and asks
// its agent only for what needs a secret key, naming the (sub)key by its
// keygrip: sign this digest, or undo this public-key encryption. Parts
// describes each (sub)key's public key material, which keygrips are
// computed from; SignDigest, DecryptPKCS1 and SharedPoint are those
// operations, on one (sub)key named by its fingerprint.
//
// A part is used only for what it may do: signing with the primary key
// (which certifies, and signs if it may) or a subkey bound to sign, and
// decrypting with a part bound to encrypt. Expiry and revocation are not
// checked here: gpg signs with an expired primary key to extend it, and
// decrypts old messages with expired or revoked subkeys.

// KeyPart is the primary key or one of its subkeys.
type KeyPart struct {
	Fingerprint []byte
	KeyID       uint64
	Algorithm   PublicKeyAlgorithm
	Primary     bool
	// HasSecret says the part's secret key material is in this copy,
	// locked or not: not a GnuPG stub, nor a protection this package
	// refuses.
	HasSecret bool
	// CanSign and CanEncrypt say what its self-signatures let it do,
	// whether or not it has expired since (see above).
	CanSign, CanEncrypt bool
	// Public is its public key material.
	Public PublicMaterial
}

// PublicMaterial is a (sub)key's public key material, as its key packet
// carries it.
type PublicMaterial struct {
	// N and E are an RSA key's modulus and public exponent, big-endian.
	N, E []byte
	// CurveOID names the curve of an ECDSA, ECDH or EdDSALegacy key.
	CurveOID []byte
	// Point is an elliptic-curve key's public point: 0x04 || x || y on
	// the NIST curves, 0x40 and the native octets for Ed25519Legacy and
	// Curve25519Legacy, the 32 native octets of Ed25519 and X25519.
	Point []byte
}

// Parts lists the primary key and its subkeys.
func (k *Key) Parts() []KeyPart {
	var out []KeyPart
	for _, c := range k.components() {
		pk := c.pub
		flags := k.partFlags(c)
		part := KeyPart{
			Fingerprint: slices.Clone(pk.fp),
			KeyID:       pk.keyID,
			Algorithm:   pk.alg,
			Primary:     c == k.primary,
			HasSecret:   c.sec != nil && c.sec.unavailable == nil,
			CanSign:     pk.alg.canSign() && (c == k.primary || flags&flagSign != 0),
			CanEncrypt:  pk.alg.canEncrypt() && flags&(flagEncryptComms|flagEncryptStorage) != 0,
		}
		switch pk.alg {
		case RSA, RSAEncryptOnly, RSASignOnly:
			if pk.rsa != nil {
				part.Public.N = pk.rsa.N.Bytes()
				part.Public.E = big.NewInt(int64(pk.rsa.E)).Bytes()
			}
		case ECDSA, ECDH, EdDSALegacy:
			if pk.curve != nil {
				part.Public.CurveOID = slices.Clone(pk.curve.oid)
			}
			part.Public.Point = slices.Clone(pk.point)
		case Ed25519, X25519:
			part.Public.Point = slices.Clone(pk.point)
		}
		out = append(out, part)
	}
	return out
}

// partFlags is what a part's newest good self-signature lets it do, or
// what its algorithm can do when nothing says (a primary key that
// predates key flags). A subkey no good signature binds may do nothing.
func (k *Key) partFlags(c *keyComponent) byte {
	now := time.Now()
	if c == k.primary {
		binding, _ := k.primaryBindings(now, now)
		if binding == nil {
			return inferredFlags(c.pub.alg)
		}
		return k.primaryFlags(binding, now, now)
	}
	for _, sub := range k.subkeys {
		if &sub.keyComponent == c {
			if b := latestGood(sub.sigs, now, SigSubkeyBinding); b != nil {
				return subkeyFlags(sub, b)
			}
		}
	}
	return 0
}

// part finds the (sub)key with the fingerprint and checks that its secret
// key material can be used.
func (k *Key) part(fp []byte) (*keyComponent, error) {
	for _, c := range k.components() {
		if !bytes.Equal(c.pub.fp, fp) {
			continue
		}
		if c.sec == nil {
			return nil, ErrKeyLocked
		}
		if err := c.sec.usable(); err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, ErrNoUsableKey
}

// SignDigest signs a digest the caller made, with the (sub)key whose
// fingerprint is fp, as an OpenPGP signature signs its hash: RSA PKCS #1
// v1.5 over the digest's DigestInfo, ECDSA over the digest, or EdDSA over
// the digest itself. It returns the algorithm's values: RSA's s; ECDSA's
// r and s, big-endian without leading zeros; EdDSA's R and S, 32 bytes
// each. SHA-1, MD5 and RIPEMD-160 are refused, as is a hash shorter than
// the key's strength.
func (k *Key) SignDigest(fp []byte, h HashAlgorithm, digest []byte) ([][]byte, error) {
	switch h {
	case SHA224, SHA256, SHA384, SHA512, SHA3_256, SHA3_512:
	default:
		return nil, unsupported("signatures over %v digests are not made", h)
	}
	if len(digest) != h.Size() {
		return nil, malformed("a %v digest of %d bytes", h, len(digest))
	}
	c, err := k.part(fp)
	if err != nil {
		return nil, err
	}
	if !c.pub.alg.canSign() || c != k.primary && k.partFlags(c)&flagSign == 0 {
		return nil, unsupported("the %v (sub)key %X may not sign", c.pub.alg, c.pub.fp)
	}
	material, err := c.sec.sign(h, digest)
	if err != nil {
		return nil, err
	}
	switch c.pub.alg {
	case Ed25519:
		return [][]byte{material[:32], material[32:]}, nil
	case RSA, RSASignOnly:
		p := newParser(material)
		s := p.mpi(false)
		return [][]byte{s}, p.err
	}
	p := newParser(material)
	r, s := p.mpi(false), p.mpi(false)
	if p.err != nil {
		return nil, p.err
	}
	if c.pub.alg == EdDSALegacy {
		r, _ = fixedOctets(r, 32)
		s, _ = fixedOctets(s, 32)
	}
	return [][]byte{r, s}, nil
}

// decryptionPart finds a part that may decrypt, with one of the
// algorithms given.
func (k *Key) decryptionPart(fp []byte, algs ...PublicKeyAlgorithm) (*keyComponent, error) {
	c, err := k.part(fp)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(algs, c.pub.alg) {
		return nil, unsupported("this is for %v keys, and %X is a %v key", algs[0], c.pub.fp, c.pub.alg)
	}
	if k.partFlags(c)&(flagEncryptComms|flagEncryptStorage) == 0 {
		return nil, unsupported("the %v (sub)key %X may not decrypt", c.pub.alg, c.pub.fp)
	}
	return c, nil
}

// DecryptPKCS1 undoes RSA encryption with the (sub)key whose fingerprint
// is fp: c is the ciphertext (as an MPI carries it), and the result is
// the message inside its PKCS #1 v1.5 padding, which in OpenPGP is the
// session key with its cipher and checksum. Only a well-padded message
// comes back: this is not raw RSA, which would sign whatever it is
// given. Every failure to decrypt is ErrDecryption.
func (k *Key) DecryptPKCS1(fp, c []byte) ([]byte, error) {
	part, err := k.decryptionPart(fp, RSA, RSAEncryptOnly)
	if err != nil {
		return nil, err
	}
	sp, err := part.sec.parts()
	if err != nil {
		return nil, err
	}
	defer sp.wipe()
	for len(c) > 0 && c[0] == 0 {
		c = c[1:]
	}
	size := part.pub.rsa.Size()
	padded, ok := fixedOctets(c, size)
	if !ok || len(c) == 0 {
		return nil, ErrDecryption
	}
	msg, err := rsa.DecryptPKCS1v15(nil, sp.rsa, padded)
	if err != nil {
		return nil, ErrDecryption
	}
	return msg, nil
}

// SharedPoint does the recipient's half of ECDH with the (sub)key whose
// fingerprint is fp: ephemeral is the sender's public point as OpenPGP
// carries it (0x04 || x || y on the NIST curves, 0x40 || u for
// Curve25519Legacy, the 32 octets of u for X25519), and the result is the
// shared point: 0x04 || x || y on the NIST curves, the 32 octets of u on
// Curve25519. What follows (the KDF and the key unwrap) is the caller's.
// Points that are not on the curve, not canonical, or give the neutral
// element are refused, as ErrDecryption.
func (k *Key) SharedPoint(fp, ephemeral []byte) ([]byte, error) {
	part, err := k.decryptionPart(fp, ECDH, X25519)
	if err != nil {
		return nil, err
	}
	pk := part.pub
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	sp, err := part.sec.parts()
	if err != nil {
		return nil, err
	}
	defer sp.wipe()
	if pk.alg == X25519 || pk.curve == curveCurve25519Legacy {
		u := ephemeral
		if pk.alg == ECDH {
			var ok bool
			if u, ok = prefixedOctets(ephemeral, 32); !ok {
				return nil, ErrDecryption
			}
		}
		if !canonicalX25519(u) {
			return nil, ErrDecryption
		}
		eph, err := ecdh.X25519().NewPublicKey(u)
		if err != nil {
			return nil, ErrDecryption
		}
		shared, err := sp.ecdh.ECDH(eph) // refuses the all-zero result
		if err != nil {
			return nil, ErrDecryption
		}
		return shared, nil
	}
	return nistSharedPoint(pk.curve, sp.ecdh, ephemeral)
}

// nistSharedPoint multiplies a point on a NIST curve by the private
// scalar, and returns the whole product, uncompressed: crypto/ecdh gives
// only its x, and GnuPG's agent answers with the point.
func nistSharedPoint(c *curve, priv *ecdh.PrivateKey, ephemeral []byte) ([]byte, error) {
	if _, err := c.ecdh.NewPublicKey(ephemeral); err != nil { // on the curve, uncompressed
		return nil, ErrDecryption
	}
	n := c.fsize
	ex, ey := new(big.Int).SetBytes(ephemeral[1:1+n]), new(big.Int).SetBytes(ephemeral[1+n:])
	scalar := priv.Bytes()
	defer clear(scalar)
	// crypto/elliptic's ScalarMult is deprecated for new protocols, not
	// unsafe: on these curves it runs on the same constant-time code as
	// crypto/ecdh.
	x, y := c.ecdsa.ScalarMult(ex, ey, scalar)
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, ErrDecryption
	}
	out := make([]byte, 1+2*n)
	out[0] = 4
	x.FillBytes(out[1 : 1+n])
	y.FillBytes(out[1+n:])
	clearBig(x)
	clearBig(y)
	return out, nil
}
