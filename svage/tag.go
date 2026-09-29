package svage

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Tagged recipients, for keys on hardware tokens (c2sp.org/age, "The
// tagged recipient types"): HPKE to a P-256 key (age1tag1..., the point
// compressed) or to an MLKEM768-P256 hybrid (age1tagpq1...), with a
// four-byte tag naming the recipient so a token is asked only for its own
// stanzas. Only encryption is here: the identities live on the tokens,
// behind their plugins.
//
//	-> p256tag <tag> <enc>
//	-> mlkem768p256tag <tag> <enc>
//	tag = HKDF-Extract-SHA-256(enc || SHA-256(recipient point)[:4], salt = label)[:4]

const (
	p256TagLabel       = "age-encryption.org/p256tag"
	mlkem768P256Label  = "age-encryption.org/mlkem768p256tag"
	mlkem768EncapsSize = 1184 // the ML-KEM-768 part of a tagpq recipient
)

// TagRecipient is an age1tag1... or age1tagpq1... recipient.
type TagRecipient struct {
	pub     hpke.PublicKey
	encoded []byte // what the Bech32 string holds
	hybrid  bool
}

// ParseTagRecipient reads an age1tag1... or age1tagpq1... recipient.
func ParseTagRecipient(s string) (*TagRecipient, error) {
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("svage: malformed recipient: %v", err)
	}
	switch hrp {
	case "age1tag":
		point, err := decompressP256(data)
		if err != nil {
			return nil, err
		}
		pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(point)
		if err != nil {
			return nil, fmt.Errorf("svage: invalid tag recipient: %v", err)
		}
		return &TagRecipient{pub: pk, encoded: data}, nil
	case "age1tagpq":
		pk, err := hpke.MLKEM768P256().NewPublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("svage: invalid tagpq recipient: %v", err)
		}
		return &TagRecipient{pub: pk, encoded: data, hybrid: true}, nil
	}
	return nil, errors.New("svage: not a tag recipient")
}

// String is the recipient's Bech32 form.
func (r *TagRecipient) String() string {
	hrp := "age1tag"
	if r.hybrid {
		hrp = "age1tagpq"
	}
	s, _ := bech32Encode(hrp, r.encoded)
	return s
}

// Wrap implements Recipient.
func (r *TagRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements RecipientWithLabels: a hybrid tag is
// "postquantum", a P-256 one is classical.
func (r *TagRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	// The tag hashes the compressed point, or a hybrid's uncompressed one.
	typ, label, point := "p256tag", p256TagLabel, r.encoded
	if r.hybrid {
		typ, label, point = "mlkem768p256tag", mlkem768P256Label, r.encoded[mlkem768EncapsSize:]
	}
	enc, sender, err := hpke.NewSender(r.pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(label))
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(nil, fileKey)
	if err != nil {
		return nil, nil, err
	}
	tag, err := stanzaTag(label, point, enc)
	if err != nil {
		return nil, nil, err
	}
	s := &Stanza{Type: typ, Args: []string{encodeB64(tag), encodeB64(enc)}, Body: ct}
	if r.hybrid {
		return []*Stanza{s}, []string{"postquantum"}, nil
	}
	return []*Stanza{s}, nil, nil
}

// stanzaTag is the four-byte tag naming the recipient whose point is
// point in a stanza whose encapsulated key is enc.
func stanzaTag(label string, point, enc []byte) ([]byte, error) {
	h := sha256.Sum256(point)
	tag, err := hkdf.Extract(sha256.New, append(append([]byte(nil), enc...), h[:4]...), []byte(label))
	if err != nil {
		return nil, err
	}
	return tag[:4], nil
}

// decompressP256 turns a compressed P-256 point (SEC 1) into the
// uncompressed form HPKE takes. y^2 = x^3 - 3x + b; p is 3 mod 4, so the
// square root is a single exponentiation. The point is public.
func decompressP256(c []byte) ([]byte, error) {
	if len(c) != 33 || (c[0] != 2 && c[0] != 3) {
		return nil, errors.New("svage: a tag recipient must be a compressed P-256 point")
	}
	p, _ := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	b, _ := new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	x := new(big.Int).SetBytes(c[1:])
	if x.Cmp(p) >= 0 {
		return nil, errors.New("svage: invalid P-256 point")
	}
	y2 := new(big.Int).Exp(x, big.NewInt(3), p)
	y2.Sub(y2, new(big.Int).Mul(big.NewInt(3), x))
	y2.Add(y2, b).Mod(y2, p)
	y := new(big.Int).Exp(y2, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2), p)
	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(y2) != 0 {
		return nil, errors.New("svage: invalid P-256 point")
	}
	if y.Bit(0) != uint(c[0]&1) {
		y.Sub(p, y)
	}
	out := make([]byte, 65)
	out[0] = 4
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:])
	return out, nil
}
