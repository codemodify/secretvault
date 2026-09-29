package svage

import (
	"crypto/hpke"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Post-quantum hybrid recipients (age1pq1...) and identities
// (AGE-SECRET-KEY-PQ-1...), added in age v1.3.0: HPKE with the
// MLKEM768-X25519 KEM (X-Wing), HKDF-SHA256 and ChaCha20Poly1305, info
// "age-encryption.org/mlkem768x25519". The identity is the KEM's 32-byte
// seed; the recipient is its 1,216-byte public key. The same KEM protects
// secretvault's own recipient keyslots (svcrypto, sv1-modern).
//
// A stanza is "-> mlkem768x25519 <enc>", enc being the 1,120-byte HPKE
// encapsulated key, with the sealed file key as its body.

const hybridLabel = "age-encryption.org/mlkem768x25519"

const hybridEncSize = 1120

func hybridSuite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305()
}

// HybridRecipient is an age1pq1... public key.
type HybridRecipient struct {
	pub hpke.PublicKey
}

// NewHybridRecipient makes a recipient of an MLKEM768-X25519 public key.
func NewHybridRecipient(pub []byte) (*HybridRecipient, error) {
	kem, _, _ := hybridSuite()
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, errors.New("svage: not an MLKEM768-X25519 public key")
	}
	return &HybridRecipient{pub: pk}, nil
}

// ParseHybridRecipient reads an age1pq1... recipient.
func ParseHybridRecipient(s string) (*HybridRecipient, error) {
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("svage: malformed recipient: %v", err)
	}
	if hrp != "age1pq" {
		return nil, errors.New("svage: not a post-quantum recipient")
	}
	return NewHybridRecipient(data)
}

// String is the recipient's age1pq1... form.
func (r *HybridRecipient) String() string {
	s, _ := bech32Encode("age1pq", r.pub.Bytes())
	return s
}

// Wrap implements Recipient.
func (r *HybridRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements RecipientWithLabels: the stanza is labelled
// "postquantum".
func (r *HybridRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	_, kdf, aead := hybridSuite()
	enc, sender, err := hpke.NewSender(r.pub, kdf, aead, []byte(hybridLabel))
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(nil, fileKey)
	if err != nil {
		return nil, nil, err
	}
	return []*Stanza{{Type: "mlkem768x25519", Args: []string{encodeB64(enc)}, Body: ct}}, []string{"postquantum"}, nil
}

// HybridIdentity is an AGE-SECRET-KEY-PQ-1... private key.
type HybridIdentity struct {
	priv hpke.PrivateKey
}

func (*HybridIdentity) native() {}

// GenerateHybridIdentity makes a new random post-quantum identity.
func GenerateHybridIdentity() (*HybridIdentity, error) {
	kem, _, _ := hybridSuite()
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &HybridIdentity{priv: k}, nil
}

// NewHybridIdentity makes an identity of a 32-byte MLKEM768-X25519 seed.
func NewHybridIdentity(seed []byte) (*HybridIdentity, error) {
	kem, _, _ := hybridSuite()
	k, err := kem.NewPrivateKey(seed)
	if err != nil {
		return nil, errors.New("svage: a post-quantum identity must be a 32-byte seed")
	}
	return &HybridIdentity{priv: k}, nil
}

// ParseHybridIdentity reads an AGE-SECRET-KEY-PQ-1... identity.
func ParseHybridIdentity(s string) (*HybridIdentity, error) {
	b := []byte(s)
	defer clear(b)
	return parseHybridIdentity(b)
}

func parseHybridIdentity(b []byte) (*HybridIdentity, error) {
	hrp, data, err := bech32DecodeBytes(b)
	if err != nil {
		return nil, fmt.Errorf("svage: malformed identity: %v", err)
	}
	defer clear(data)
	if hrp != "AGE-SECRET-KEY-PQ-" {
		return nil, errors.New("svage: not a post-quantum identity")
	}
	return NewHybridIdentity(data)
}

// Recipient is the identity's public half.
func (id *HybridIdentity) Recipient() *HybridRecipient {
	return &HybridRecipient{pub: id.priv.PublicKey()}
}

// String is the identity's AGE-SECRET-KEY-PQ-1... form. Treat it like a
// passphrase; AppendText gives it in memory that can be wiped.
func (id *HybridIdentity) String() string {
	b, _ := id.AppendText(nil)
	defer clear(b)
	return string(b)
}

// AppendText appends the identity's AGE-SECRET-KEY-PQ-1... form to b.
func (id *HybridIdentity) AppendText(b []byte) ([]byte, error) {
	// Bytes returns the key's own seed, not a copy: not to be cleared.
	seed, err := id.priv.Bytes()
	if err != nil {
		return nil, err
	}
	return bech32Append(b, "AGE-SECRET-KEY-PQ-", seed)
}

// Unwrap implements Identity.
func (id *HybridIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(id.unwrap, stanzas)
}

func (id *HybridIdentity) unwrap(s *Stanza) ([]byte, error) {
	if s.Type != "mlkem768x25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(s.Args) != 1 {
		return nil, errors.New("an mlkem768x25519 stanza has one argument")
	}
	enc, err := decodeB64(s.Args[0])
	if err != nil || len(enc) != hybridEncSize {
		return nil, fmt.Errorf("the encapsulated key is not %d bytes of canonical base64", hybridEncSize)
	}
	if len(s.Body) != FileKeySize+chacha20poly1305.Overhead {
		return nil, errBodySize
	}
	_, kdf, aead := hybridSuite()
	r, err := hpke.NewRecipient(enc, id.priv, kdf, aead, []byte(hybridLabel))
	if err != nil {
		// ML-KEM rejects implicitly, so a key for someone else fails
		// below, not here: this is an invalid X25519 share.
		return nil, fmt.Errorf("invalid encapsulated key: %v", err)
	}
	fileKey, err := r.Open(nil, s.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}
