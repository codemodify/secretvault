package svage

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// X25519 recipients (age1...) and identities (AGE-SECRET-KEY-1...).
//
// A stanza is "-> X25519 <ephemeral share>" with the file key sealed
// under HKDF-SHA-256(X25519(ephemeral, recipient),
// salt = share || recipient, info = "age-encryption.org/v1/X25519").

const x25519Label = "age-encryption.org/v1/X25519"

func newChaCha(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }

// X25519Recipient is an age1... public key.
type X25519Recipient struct {
	pub *ecdh.PublicKey
}

// NewX25519Recipient makes a recipient of a 32-byte X25519 public key.
func NewX25519Recipient(pub []byte) (*X25519Recipient, error) {
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, errors.New("svage: an X25519 recipient must be 32 bytes")
	}
	return &X25519Recipient{pub: pk}, nil
}

// ParseX25519Recipient reads an age1... recipient.
func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("svage: malformed recipient: %v", err)
	}
	if hrp != "age" {
		return nil, fmt.Errorf("svage: %q is not an X25519 recipient", hrp+"1...")
	}
	return NewX25519Recipient(data)
}

// String is the recipient's age1... form.
func (r *X25519Recipient) String() string {
	s, _ := bech32Encode("age", r.pub.Bytes())
	return s
}

// Wrap implements Recipient.
func (r *X25519Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(r.pub)
	if err != nil {
		return nil, fmt.Errorf("svage: unusable X25519 recipient: %v", err)
	}
	defer clear(shared)
	share := eph.PublicKey().Bytes()
	key, err := hkdf.Key(sha256.New, shared, append(share[:len(share):len(share)], r.pub.Bytes()...), x25519Label, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	body, err := sealKey(key, fileKey)
	if err != nil {
		return nil, err
	}
	return []*Stanza{{Type: "X25519", Args: []string{encodeB64(share)}, Body: body}}, nil
}

// X25519Identity is an AGE-SECRET-KEY-1... private key.
type X25519Identity struct {
	priv *ecdh.PrivateKey
}

func (*X25519Identity) native() {}

// GenerateX25519Identity makes a new random identity.
func GenerateX25519Identity() (*X25519Identity, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &X25519Identity{priv: k}, nil
}

// NewX25519Identity makes an identity of a 32-byte X25519 private key.
func NewX25519Identity(priv []byte) (*X25519Identity, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, errors.New("svage: an X25519 identity must be 32 bytes")
	}
	return &X25519Identity{priv: k}, nil
}

// ParseX25519Identity reads an AGE-SECRET-KEY-1... identity.
func ParseX25519Identity(s string) (*X25519Identity, error) {
	b := []byte(s)
	defer clear(b)
	return parseX25519Identity(b)
}

func parseX25519Identity(b []byte) (*X25519Identity, error) {
	hrp, data, err := bech32DecodeBytes(b)
	if err != nil {
		return nil, fmt.Errorf("svage: malformed identity: %v", err)
	}
	defer clear(data)
	if hrp != "AGE-SECRET-KEY-" {
		return nil, errors.New("svage: not an X25519 identity")
	}
	return NewX25519Identity(data)
}

// Recipient is the identity's public half.
func (id *X25519Identity) Recipient() *X25519Recipient {
	return &X25519Recipient{pub: id.priv.PublicKey()}
}

// String is the identity's AGE-SECRET-KEY-1... form. Treat it like a
// passphrase; AppendText gives it in memory that can be wiped.
func (id *X25519Identity) String() string {
	b, _ := id.AppendText(nil)
	defer clear(b)
	return string(b)
}

// AppendText appends the identity's AGE-SECRET-KEY-1... form to b.
func (id *X25519Identity) AppendText(b []byte) ([]byte, error) {
	k := id.priv.Bytes() // a copy
	defer clear(k)
	return bech32Append(b, "AGE-SECRET-KEY-", k)
}

// Unwrap implements Identity.
func (id *X25519Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(id.unwrap, stanzas)
}

func (id *X25519Identity) unwrap(s *Stanza) ([]byte, error) {
	if s.Type != "X25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(s.Args) != 1 {
		return nil, errors.New("an X25519 stanza has one argument")
	}
	share, err := decodeB64(s.Args[0])
	if err != nil || len(share) != 32 {
		return nil, errors.New("the ephemeral share is not 32 bytes of canonical base64")
	}
	if len(s.Body) != FileKeySize+chacha20poly1305.Overhead {
		return nil, errBodySize
	}
	pk, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return nil, err
	}
	shared, err := id.priv.ECDH(pk)
	if err != nil {
		// The all-zero shared secret of a low-order share.
		return nil, errors.New("the ephemeral share is a low-order point")
	}
	defer clear(shared)
	key, err := hkdf.Key(sha256.New, shared, append(share, id.priv.PublicKey().Bytes()...), x25519Label, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	fileKey, err := openKey(key, s.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}
