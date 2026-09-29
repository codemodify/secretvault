package svgpgagent

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/codemodify/secretvault/svpgp"
)

// Keygrips. gpg names a key to its agent by its keygrip: libgcrypt's
// SHA-1 over the key's public parameters, which, unlike a fingerprint,
// depends on nothing but the key material (gcry_pk_get_keygrip). For
// RSA it is the hash of the modulus as the S-expression carries it, with
// a zero byte in front when its top bit is set. For elliptic curves it is
// the hash of "(1:p<len>:<p>)" and so on for the curve's p, a, b, g and
// n, as libgcrypt's curve table holds them, and the public point q:
// Ed25519 and Curve25519 points without their 0x40 prefix, the NIST
// curves' uncompressed. libgcrypt keeps Ed25519's a and b negative, and
// hashes their magnitudes.

// ecParams are one curve's parameters as libgcrypt hashes them, and its
// name in S-expressions.
type ecParams struct {
	name          string
	p, a, b, g, n []byte
	// compact: the key's point is hashed without its 0x40 prefix (EdDSA,
	// and ECDH with the djb-tweak flag); flags is that flag.
	compact bool
	flags   string
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	// Ed25519, from libgcrypt's cipher/ecc-curves.c.
	ed25519Params = &ecParams{
		name:    "Ed25519",
		p:       mustHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
		a:       mustHex("01"),
		b:       mustHex("2dfc9311d490018c7338bf8688861767ff8ff5b2bebe27548a14b235eca6874a"),
		g:       mustHex("04216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a6666666666666666666666666666666666666666666666666666666666666658"),
		n:       mustHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
		compact: true,
		flags:   "eddsa",
	}
	// Curve25519, likewise. Its g carries the y that libgcrypt keeps for
	// the keygrip's sake (see its table).
	curve25519Params = &ecParams{
		name:    "Curve25519",
		p:       mustHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
		a:       mustHex("01db41"),
		b:       mustHex("01"),
		g:       mustHex("04000000000000000000000000000000000000000000000000000000000000000920ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9"),
		n:       mustHex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
		compact: true,
		flags:   "djb-tweak",
	}
	p256Params = nistParams("NIST P-256", elliptic.P256())
	p384Params = nistParams("NIST P-384", elliptic.P384())
	p521Params = nistParams("NIST P-521", elliptic.P521())
)

// nistParams takes a NIST curve's parameters from the standard library:
// they are the same numbers as libgcrypt's table, with a = p - 3, and g
// as the uncompressed point with coordinates of the field's size.
func nistParams(name string, c elliptic.Curve) *ecParams {
	cp := c.Params()
	size := (cp.BitSize + 7) / 8
	g := make([]byte, 1+2*size)
	g[0] = 4
	cp.Gx.FillBytes(g[1 : 1+size])
	cp.Gy.FillBytes(g[1+size:])
	return &ecParams{
		name: name,
		p:    cp.P.Bytes(),
		a:    new(big.Int).Sub(cp.P, big.NewInt(3)).Bytes(),
		b:    cp.B.Bytes(),
		g:    g,
		n:    cp.N.Bytes(),
	}
}

// OpenPGP's curve OIDs (RFC 9580, table 27).
var curvesByOID = []struct {
	oid    []byte
	params *ecParams
}{
	{[]byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, p256Params},
	{[]byte{0x2B, 0x81, 0x04, 0x00, 0x22}, p384Params},
	{[]byte{0x2B, 0x81, 0x04, 0x00, 0x23}, p521Params},
	{[]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}, ed25519Params},
	{[]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}, curve25519Params},
}

// ErrNoKeygrip is a key whose algorithm or curve has no keygrip here.
var ErrNoKeygrip = errors.New("svgpgagent: no keygrip for this kind of key")

// curveOf finds the curve of an elliptic-curve key.
func curveOf(alg svpgp.PublicKeyAlgorithm, pub svpgp.PublicMaterial) (*ecParams, error) {
	switch alg {
	case svpgp.Ed25519:
		return ed25519Params, nil
	case svpgp.X25519:
		return curve25519Params, nil
	case svpgp.ECDSA, svpgp.ECDH, svpgp.EdDSALegacy:
		for _, c := range curvesByOID {
			if !bytes.Equal(c.oid, pub.CurveOID) {
				continue
			}
			// EdDSA is on Ed25519 alone; ECDH on anything but Ed25519;
			// ECDSA on the NIST curves.
			ed, cv := c.params == ed25519Params, c.params == curve25519Params
			if alg == svpgp.EdDSALegacy && ed || alg == svpgp.ECDH && !ed || alg == svpgp.ECDSA && !ed && !cv {
				return c.params, nil
			}
		}
	}
	return nil, fmt.Errorf("%w (%v)", ErrNoKeygrip, alg)
}

// point is a key's public point as the keygrip and READKEY use it: the
// native octets for the compact curves, with (prefixed) or without the
// 0x40 in front, and the NIST curves' as they are.
func point(c *ecParams, pub svpgp.PublicMaterial, prefixed bool) ([]byte, error) {
	q := pub.Point
	if !c.compact {
		if len(q) == 0 || q[0] != 4 {
			return nil, fmt.Errorf("%w: a compressed or malformed point", ErrNoKeygrip)
		}
		return q, nil
	}
	switch {
	case len(q) == 33 && q[0] == 0x40:
		q = q[1:]
	case len(q) != 32:
		return nil, fmt.Errorf("%w: a malformed point", ErrNoKeygrip)
	}
	if prefixed {
		return append([]byte{0x40}, q...), nil
	}
	return q, nil
}

// Keygrip is libgcrypt's keygrip of a (sub)key: RSA, ECDSA and ECDH on the
// NIST curves, EdDSA on Ed25519 and ECDH on Curve25519 (the legacy
// algorithms of version 4 keys, and the native Ed25519 and X25519 ones).
func Keygrip(alg svpgp.PublicKeyAlgorithm, pub svpgp.PublicMaterial) ([]byte, error) {
	switch alg {
	case svpgp.RSA, svpgp.RSAEncryptOnly, svpgp.RSASignOnly:
		if len(pub.N) == 0 {
			return nil, fmt.Errorf("%w: an RSA key without its modulus", ErrNoKeygrip)
		}
		sum := sha1.Sum(mpi(pub.N))
		return sum[:], nil
	}
	c, err := curveOf(alg, pub)
	if err != nil {
		return nil, err
	}
	q, err := point(c, pub, false)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	for _, e := range []struct {
		name string
		v    []byte
	}{{"p", c.p}, {"a", c.a}, {"b", c.b}, {"g", c.g}, {"n", c.n}, {"q", q}} {
		fmt.Fprintf(h, "(1:%s%d:", e.name, len(e.v))
		h.Write(e.v)
		h.Write([]byte{')'})
	}
	return h.Sum(nil), nil
}

// publicKey is the key as READKEY answers with it, in the form gpg-agent
// writes: (public-key(rsa(n N)(e E))), or (public-key(ecc(curve NAME)
// [(flags FLAG)](q Q))).
func publicKey(alg svpgp.PublicKeyAlgorithm, pub svpgp.PublicMaterial) ([]byte, error) {
	switch alg {
	case svpgp.RSA, svpgp.RSAEncryptOnly, svpgp.RSASignOnly:
		return list(atom([]byte("public-key")), list(atom([]byte("rsa")), param("n", mpi(pub.N)), param("e", mpi(pub.E)))), nil
	}
	c, err := curveOf(alg, pub)
	if err != nil {
		return nil, err
	}
	q, err := point(c, pub, true)
	if err != nil {
		return nil, err
	}
	elems := [][]byte{atom([]byte("ecc")), param("curve", []byte(c.name))}
	if c.flags != "" {
		elems = append(elems, param("flags", []byte(c.flags)))
	}
	elems = append(elems, param("q", q))
	return list(atom([]byte("public-key")), list(elems...)), nil
}

// isCurve25519 reports whether a key does ECDH on Curve25519, whose
// shared point libgcrypt writes as 0x40 and the u coordinate.
func isCurve25519(alg svpgp.PublicKeyAlgorithm, pub svpgp.PublicMaterial) bool {
	c, err := curveOf(alg, pub)
	return err == nil && c == curve25519Params
}
