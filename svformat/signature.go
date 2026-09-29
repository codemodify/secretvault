package svformat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/codemodify/secretvault/svcrypto"
)

// Revision signatures (docs/format.md, "Signatures").
//
// Everyone who can open a vault holds the same master key, so the key
// alone cannot say which of them wrote a revision. A revision may
// therefore carry a signature by the writing device's own Ed25519 key, in
// an optional header field:
//
//	0x82 signature   alg (1) || key id (16) || signature (64 for Ed25519)
//
// The field is in the header, so it is part of the prefix, which is the
// body's associated data, and of the file, whose SHA-256 is the revision's
// ID: the signature can be neither stripped nor swapped without the
// revision failing to open and its ID changing. Tag 0x82 is optional, so
// a reader that predates signatures skips it and opens the revision as
// before.
//
// The signature cannot cover the body, which is sealed with the signature
// already in its associated data. It covers instead the prefix without
// the signature, and a commitment to the payload made under the
// revision's content key:
//
//	signed   = "secretvault sv1 revision signature" || TLV {
//	    0x01 alg (1)
//	    0x02 key id (16)
//	    0x03 SHA-256(unsigned prefix)
//	    0x04 commit (32)
//	}
//	unsigned prefix = the prefix with the 0x82 field left out of the header
//	commit   = HMAC-SHA-256(Derive(content key, vault id, "sv1 revision commit", 32), payload)
//	key id   = SHA-256("secretvault sv1 device key" || alg (1) || public key)[0:16]
//
// The unsigned prefix holds the wrapped content key, which pins the
// content key, which with the commitment pins the payload. The
// commitment is keyed so that checking a signature needs the content key:
// someone who knows a device's public key but cannot open the vault (a
// person cut off by a rotation, say) cannot test guesses at a revision's
// contents against its signature.

// SigEd25519 is the only signature algorithm of format v1.
const SigEd25519 = 1

// ErrUnsigned is a revision that carries no signature.
var ErrUnsigned = errors.New("svformat: the revision is not signed")

// RevisionSignature is a revision's signature field.
type RevisionSignature struct {
	Alg uint8
	Key ID // DeviceKeyID of the key that made it
	Sig []byte
}

// DeviceKeyID names a device's Ed25519 signing key. A device's record in
// a vault's registry has it for its object ID (docs/format.md, "Device
// records").
func DeviceKeyID(pub ed25519.PublicKey) ID {
	h := sha256.New()
	h.Write([]byte("secretvault sv1 device key"))
	h.Write([]byte{SigEd25519})
	h.Write(pub)
	var id ID
	copy(id[:], h.Sum(nil))
	return id
}

// SealSignedRevision is SealRevision, signed with a device's key. The
// header must name the device (h.Device), which the signature covers.
func SealSignedRevision(h RevisionHeader, wrapKey, dek, payload []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: not an Ed25519 key", ErrRevision)
	}
	if h.Device.IsZero() {
		return nil, fmt.Errorf("%w: a signed revision must name its device", ErrRevision)
	}
	return sealRevision(h, wrapKey, dek, payload, key)
}

// SignedData is what a revision's signature signs. It needs the content
// key and the payload (from OpenRevision), so only someone who can open
// the vault can check a signature.
func SignedData(file, dek, payload []byte) ([]byte, error) {
	h, prefix, _, err := parseRevision(file)
	if err != nil {
		return nil, err
	}
	if h.Signature == nil {
		return nil, ErrUnsigned
	}
	fields, err := DecodeTLV(prefix[8:])
	if err != nil {
		return nil, err
	}
	unsigned, err := unsignedPrefix(h.Suite, fields)
	if err != nil {
		return nil, err
	}
	return signedData(h.Signature.Alg, h.Signature.Key, unsigned, revisionCommit(h.Vault, dek, payload)), nil
}

// Verify reports whether s is pub's signature over data (SignedData).
func (s *RevisionSignature) Verify(pub ed25519.PublicKey, data []byte) bool {
	return s != nil && s.Alg == SigEd25519 && len(pub) == ed25519.PublicKeySize &&
		DeviceKeyID(pub) == s.Key && ed25519.Verify(pub, data, s.Sig)
}

// sign adds the signature field to a header's fields, which are in tag
// order and hold every other field.
func sign(suite svcrypto.Suite, fields []Field, vault ID, dek, payload []byte, key ed25519.PrivateKey) ([]Field, error) {
	unsigned, err := unsignedPrefix(suite, fields)
	if err != nil {
		return nil, err
	}
	kid := DeviceKeyID(key.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(key, signedData(SigEd25519, kid, unsigned, revisionCommit(vault, dek, payload)))
	value := append([]byte{SigEd25519}, kid[:]...)
	value = append(value, sig...)
	var out []Field
	placed := false
	for _, f := range fields {
		if !placed && f.Tag > tagSignature {
			out = append(out, Field{tagSignature, value})
			placed = true
		}
		out = append(out, f)
	}
	if !placed {
		out = append(out, Field{tagSignature, value})
	}
	return out, nil
}

// unsignedPrefix is the prefix a header's fields make without the
// signature field.
func unsignedPrefix(suite svcrypto.Suite, fields []Field) ([]byte, error) {
	var kept []Field
	for _, f := range fields {
		if f.Tag != tagSignature {
			kept = append(kept, f)
		}
	}
	hdr, err := EncodeTLV(kept)
	if err != nil {
		return nil, err
	}
	if len(hdr) > 0xFFFF {
		return nil, fmt.Errorf("%w: header is %d bytes", ErrRevision, len(hdr))
	}
	prefix := append([]byte(revisionMagic), byte(suite), 0)
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(hdr)))
	return append(prefix, hdr...), nil
}

func signedData(alg uint8, key ID, unsigned, commit []byte) []byte {
	sum := sha256.Sum256(unsigned)
	var t tlvBuilder
	t.add(0x01, []byte{alg})
	t.add(0x02, key[:])
	t.add(0x03, sum[:])
	t.add(0x04, commit)
	b, err := t.encode()
	if err != nil {
		panic(err) // every part is short
	}
	return append([]byte("secretvault sv1 revision signature"), b...)
}

// revisionCommit binds a signature to a payload, under a key only the
// content key gives.
func revisionCommit(vault ID, dek, payload []byte) []byte {
	key := svcrypto.Derive(dek, vault[:], "sv1 revision commit", svcrypto.KeySize)
	defer clear(key)
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}

// parseSignature reads a signature field's value.
func parseSignature(v []byte) (*RevisionSignature, error) {
	if len(v) < 1+len(ID{}) {
		return nil, fmt.Errorf("%w: signature field is %d bytes", ErrRevision, len(v))
	}
	s := &RevisionSignature{Alg: v[0], Sig: bytes.Clone(v[1+len(ID{}):])}
	copy(s.Key[:], v[1:])
	if s.Alg == SigEd25519 && len(s.Sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: an Ed25519 signature of %d bytes", ErrRevision, len(s.Sig))
	}
	return s, nil
}
