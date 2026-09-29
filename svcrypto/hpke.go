package svcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
)

// An Identity is a private key that sealed messages can be addressed to: a
// device, a person, a server's unseal key. Its public half is a recipient.
// Both are post-quantum hybrids, so what is sealed today stays sealed if a
// quantum computer later breaks the classical half.
type Identity struct {
	suite Suite
	priv  hpke.PrivateKey
}

// ErrRecipient is a public key that does not parse for the suite.
var ErrRecipient = errors.New("svcrypto: bad recipient public key")

// kem, kdf and aead are the suite's HPKE ciphersuite.
func (s Suite) hpke() (hpke.KEM, hpke.KDF, hpke.AEAD, error) {
	switch s {
	case Modern:
		return hpke.MLKEM768X25519(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil
	case NIST:
		return hpke.MLKEM768P256(), hpke.HKDFSHA256(), hpke.AES256GCM(), nil
	}
	return nil, nil, nil, ErrSuite
}

// NewIdentity generates a fresh identity for the suite.
func (s Suite) NewIdentity() (*Identity, error) {
	kem, _, _, err := s.hpke()
	if err != nil {
		return nil, err
	}
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Identity{suite: s, priv: priv}, nil
}

// ParseIdentity reads a private key written by Identity.Bytes.
func (s Suite) ParseIdentity(b []byte) (*Identity, error) {
	kem, _, _, err := s.hpke()
	if err != nil {
		return nil, err
	}
	priv, err := kem.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("svcrypto: bad identity: %w", err)
	}
	return &Identity{suite: s, priv: priv}, nil
}

// Suite is the suite the identity belongs to.
func (id *Identity) Suite() Suite { return id.suite }

// Bytes is the serialized private key. Handle it like a passphrase: the
// result is a copy the caller may, and should, clear.
func (id *Identity) Bytes() ([]byte, error) {
	b, err := id.priv.Bytes()
	if err != nil {
		return nil, err
	}
	// crypto/hpke's hybrid keys hand out their own seed, so clearing
	// what they return would break the identity.
	return bytes.Clone(b), nil
}

// Recipient is the serialized public key that SealTo addresses.
func (id *Identity) Recipient() []byte { return id.priv.PublicKey().Bytes() }

// CheckRecipient reports whether pub is a public key of the suite.
func (s Suite) CheckRecipient(pub []byte) error {
	kem, _, _, err := s.hpke()
	if err != nil {
		return err
	}
	if _, err := kem.NewPublicKey(pub); err != nil {
		return fmt.Errorf("%w: %v", ErrRecipient, err)
	}
	return nil
}

// SealTo encrypts plaintext so only the holder of the identity behind pub
// can read it. info binds context, the way aad does for Seal. The result is
// len(enc) as 2 bytes big-endian || enc || ciphertext.
func (s Suite) SealTo(pub, plaintext, info []byte) ([]byte, error) {
	kem, kdf, aead, err := s.hpke()
	if err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipient, err)
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(enc)+len(ct)), uint16(len(enc)))
	out = append(out, enc...)
	return append(out, ct...), nil
}

// Open reverses SealTo. Anything wrong is ErrOpen.
func (id *Identity) Open(sealed, info []byte) ([]byte, error) {
	_, kdf, aead, err := id.suite.hpke()
	if err != nil {
		return nil, err
	}
	if len(sealed) < 2 {
		return nil, ErrOpen
	}
	n := int(binary.BigEndian.Uint16(sealed))
	if len(sealed) < 2+n {
		return nil, ErrOpen
	}
	r, err := hpke.NewRecipient(sealed[2:2+n], id.priv, kdf, aead, info)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := r.Open(nil, sealed[2+n:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Log keys seal append-only records (the audit log) that must be
// writable while a vault is locked and readable only once it is unlocked:
// the public half is kept in the clear, the private half is re-derived
// from the vault key when needed. They use a classical KEM (X25519, or
// P-256 in sv1-nist): a log entry costs tens of bytes of key material
// instead of the hybrid's 1,120, and what it protects (which program read
// which item, when) is not the kind of secret that must outlive a future
// quantum computer.
func (s Suite) logKEM() (hpke.KEM, error) {
	switch s {
	case Modern:
		return hpke.DHKEM(ecdh.X25519()), nil
	case NIST:
		return hpke.DHKEM(ecdh.P256()), nil
	}
	return nil, ErrSuite
}

// DeriveLogKey derives a log key pair deterministically from seed (at
// least 32 bytes of secret keying material).
func (s Suite) DeriveLogKey(seed []byte) (*Identity, error) {
	kem, err := s.logKEM()
	if err != nil {
		return nil, err
	}
	priv, err := kem.DeriveKeyPair(seed)
	if err != nil {
		return nil, err
	}
	return &Identity{suite: s, priv: priv}, nil
}

// SealToLog is SealTo for a log key's public half.
func (s Suite) SealToLog(pub, plaintext, info []byte) ([]byte, error) {
	kem, err := s.logKEM()
	if err != nil {
		return nil, err
	}
	_, kdf, aead, err := s.hpke()
	if err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecipient, err)
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(nil, plaintext)
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(enc)+len(ct)), uint16(len(enc)))
	out = append(out, enc...)
	return append(out, ct...), nil
}
