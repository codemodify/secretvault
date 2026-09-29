package svpgp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// curve is an elliptic curve named by an OID in ECDSA, ECDH and EdDSALegacy
// keys (RFC 9580, section 9.2).
type curve struct {
	name  string
	oid   []byte
	fsize int
	ecdh  ecdh.Curve     // for ECDH; nil for Ed25519Legacy
	ecdsa elliptic.Curve // for ECDSA; nil for the 25519 curves
	// The KDF hash and key-wrap cipher RFC 9580 table 30 gives the curve:
	// what version 6 ECDH keys must use and new keys are made with.
	kdfHash HashAlgorithm
	kek     CipherAlgorithm
	// supported is false for curves that are recognised but refused.
	supported bool
}

var (
	curveP256             = &curve{"NIST P-256", []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, 32, ecdh.P256(), elliptic.P256(), SHA256, AES128, true}
	curveP384             = &curve{"NIST P-384", []byte{0x2B, 0x81, 0x04, 0x00, 0x22}, 48, ecdh.P384(), elliptic.P384(), SHA384, AES192, true}
	curveP521             = &curve{"NIST P-521", []byte{0x2B, 0x81, 0x04, 0x00, 0x23}, 66, ecdh.P521(), elliptic.P521(), SHA512, AES256, true}
	curveEd25519Legacy    = &curve{"Ed25519Legacy", []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}, 32, nil, nil, 0, 0, true}
	curveCurve25519Legacy = &curve{"Curve25519Legacy", []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}, 32, ecdh.X25519(), nil, SHA256, AES128, true}

	curves = []*curve{
		curveP256, curveP384, curveP521, curveEd25519Legacy, curveCurve25519Legacy,
		{name: "brainpoolP256r1", oid: []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}},
		{name: "brainpoolP384r1", oid: []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}},
		{name: "brainpoolP512r1", oid: []byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D}},
		{name: "secp256k1", oid: []byte{0x2B, 0x81, 0x04, 0x00, 0x0A}},
		{name: "Ed448 (LibrePGP)", oid: []byte{0x2B, 0x65, 0x71}},
		{name: "X448 (LibrePGP)", oid: []byte{0x2B, 0x65, 0x6F}},
	}
)

// parseCurveOID reads the length-prefixed curve OID field of an EC key.
func parseCurveOID(p *parser) (*curve, error) {
	n := int(p.u8())
	if p.err == nil && (n == 0 || n == 0xFF) {
		return nil, malformed("reserved curve OID length %d", n)
	}
	oid := p.bytes(n)
	if p.err != nil {
		return nil, p.err
	}
	for _, c := range curves {
		if bytes.Equal(c.oid, oid) {
			if !c.supported {
				return c, unsupported("the %s curve", c.name)
			}
			return c, nil
		}
	}
	return nil, unsupported("the elliptic curve with OID % X", oid)
}

func (c *curve) appendOID(dst []byte) []byte {
	return append(append(dst, byte(len(c.oid))), c.oid...)
}

// anonymousSender is the fixed "sender" in the ECDH KDF parameters.
var anonymousSender = []byte("Anonymous Sender    ")

// ecdhKDFParams builds the parameters mixed into the ECDH KDF (RFC 9580,
// section 11.5): the curve, the algorithm, the KDF parameters from the
// key, the anonymous sender and the recipient's fingerprint.
func ecdhKDFParams(pk *publicKey) []byte {
	p := pk.curve.appendOID(nil)
	p = append(p, byte(ECDH), 3, 1, byte(pk.kdfHash), byte(pk.kdfCipher))
	p = append(p, anonymousSender...)
	return append(p, pk.fp...)
}

// ecdhKDF derives the key-wrap key from the shared secret (RFC 9580,
// section 11.4): one block of the hash over a counter of 1, the secret and
// the parameters.
func ecdhKDF(pk *publicKey, shared []byte) ([]byte, error) {
	h, err := pk.kdfHash.newHash()
	if err != nil {
		return nil, err
	}
	h.Write([]byte{0, 0, 0, 1})
	h.Write(shared)
	h.Write(ecdhKDFParams(pk))
	sum := h.Sum(nil)
	n := pk.kdfCipher.KeySize()
	if n == 0 || n > len(sum) {
		return nil, unsupported("ECDH with %v and %v", pk.kdfHash, pk.kdfCipher)
	}
	defer clear(sum[n:])
	return sum[:n], nil
}

// x25519KEK derives the key-wrap key for the native X25519 algorithm (RFC
// 9580, section 5.1.6): HKDF-SHA256 over the ephemeral key, the recipient
// key and the shared secret, with no salt.
func x25519KEK(ephemeral, recipient, shared []byte) ([]byte, error) {
	ikm := make([]byte, 0, 96)
	ikm = append(append(append(ikm, ephemeral...), recipient...), shared...)
	defer clear(ikm)
	return hkdf.Key(sha256.New, ikm, nil, "OpenPGP X25519", 16)
}

// pkcs5Pad pads to a multiple of 8 as RFC 8018 does, for ECDH session keys.
func pkcs5Pad(b []byte) []byte {
	n := 8 - len(b)%8
	for range n {
		b = append(b, byte(n))
	}
	return b
}

// pkcs5Unpad removes that padding, which may be longer than 8 bytes when
// the sender hid the session key size (RFC 9580, section 11.5).
func pkcs5Unpad(b []byte) ([]byte, bool) {
	if len(b) == 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n == 0 || n > len(b) {
		return nil, false
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, false
		}
	}
	return b[:len(b)-n], true
}

func (c *curve) String() string { return fmt.Sprint(c.name) }
