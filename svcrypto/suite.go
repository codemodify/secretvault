// Package svcrypto holds the cryptography of secretvault's own formats, and
// nothing else: the two cipher suites, passphrase key derivation, HPKE
// recipients, Shamir secret sharing, chunked stream encryption and locked
// memory for keys. The vault format (svformat, svcore) uses nothing but
// what this package exports, so the algorithms a vault depends on are
// exactly these.
//
// Packages that speak other formats use what those formats name, from the
// standard library and x/crypto: OpenPGP (svpgp), age (svage), S/MIME, the
// Secret Service's DH sessions (svsecret), TLS and request signing for sync
// (svserver, svsync), FIDO2 (svfido) and the importers (svimport).
//
// Everything here works on 32-byte keys. The suite chooses the algorithms;
// the caller chooses the key and the associated data. See docs/format.md for
// how the rest of the system uses these.
package svcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size of every symmetric key: vault master keys, object
// keys, key-encryption keys and stream keys.
const KeySize = 32

// Suite names a cipher suite. A vault picks one when it is created and uses
// it for everything it ever stores; the suite's number is written into every
// envelope so a reader never has to guess.
type Suite uint8

const (
	// Modern is sv1-modern: Argon2id for passphrases, HKDF-SHA256,
	// XChaCha20-Poly1305 with random 192-bit nonces, ChaCha20-Poly1305 for
	// streams, and HPKE with the ML-KEM-768 + X25519 hybrid KEM.
	Modern Suite = 1

	// NIST is sv1-nist: only NIST-approved primitives, so a vault can be
	// used by a process running in Go's FIPS 140-3 mode. PBKDF2-HMAC-SHA256
	// for passphrases, HKDF-SHA256, AES-256-GCM under a per-message key
	// derived from a random 256-bit salt, and HPKE with the ML-KEM-768 +
	// P-256 hybrid KEM.
	NIST Suite = 2
)

// ErrOpen is any failure to authenticate and decrypt: a wrong key, changed
// ciphertext, changed associated data, or a truncated input. It deliberately
// says nothing about which.
var ErrOpen = errors.New("svcrypto: message authentication failed")

// ErrSuite is a suite number this build does not know.
var ErrSuite = errors.New("svcrypto: unknown cipher suite")

// String gives the suite's name as it is written in files.
func (s Suite) String() string {
	switch s {
	case Modern:
		return "sv1-modern"
	case NIST:
		return "sv1-nist"
	}
	return fmt.Sprintf("sv1-unknown(%d)", uint8(s))
}

// ParseSuite reads a suite name as String writes it. The short names
// "modern" and "nist" are accepted too.
func ParseSuite(name string) (Suite, error) {
	switch name {
	case "sv1-modern", "modern":
		return Modern, nil
	case "sv1-nist", "nist":
		return NIST, nil
	}
	return 0, fmt.Errorf("%w: %q", ErrSuite, name)
}

// Valid reports whether the suite is one this build implements.
func (s Suite) Valid() bool { return s == Modern || s == NIST }

// nonceSize is the random prefix Seal puts in front of the ciphertext.
func (s Suite) nonceSize() int {
	if s == NIST {
		return 32 // the salt the per-message key is derived from
	}
	return chacha20poly1305.NonceSizeX
}

// Overhead is how many bytes Seal adds to a plaintext.
func (s Suite) Overhead() int { return s.nonceSize() + 16 }

// Seal encrypts and authenticates plaintext under a KeySize key, binding
// aad. The result is nonce || ciphertext || tag, with a fresh random nonce
// each call, so the same key may seal any number of messages.
func (s Suite) Seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("svcrypto: key is %d bytes, want %d", len(key), KeySize)
	}
	nonce := make([]byte, s.nonceSize(), s.nonceSize()+len(plaintext)+16)
	rand.Read(nonce)
	aead, iv, err := s.messageAEAD(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, iv, plaintext, aad), nil
}

// Open reverses Seal. Any mismatch in key, ciphertext or aad is ErrOpen.
func (s Suite) Open(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("svcrypto: key is %d bytes, want %d", len(key), KeySize)
	}
	if len(sealed) < s.Overhead() {
		return nil, ErrOpen
	}
	nonce, ct := sealed[:s.nonceSize()], sealed[s.nonceSize():]
	aead, iv, err := s.messageAEAD(key, nonce)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, iv, ct, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// messageAEAD returns the AEAD and IV for one message. For Modern that is
// XChaCha20-Poly1305 under the key itself with the random nonce. For NIST it
// is AES-256-GCM under a key and IV derived from the key and the random
// salt, which keeps GCM far away from its 96-bit random-nonce limits.
func (s Suite) messageAEAD(key, nonce []byte) (cipher.AEAD, []byte, error) {
	switch s {
	case Modern:
		aead, err := chacha20poly1305.NewX(key)
		return aead, nonce, err
	case NIST:
		okm, err := hkdf.Key(sha256.New, key, nonce, "secretvault sv1-nist message", KeySize+12)
		if err != nil {
			return nil, nil, err
		}
		defer clear(okm[:KeySize])
		block, err := aes.NewCipher(okm[:KeySize])
		if err != nil {
			return nil, nil, err
		}
		aead, err := cipher.NewGCM(block)
		return aead, okm[KeySize:], err
	}
	return nil, nil, ErrSuite
}

// Derive expands a key into n bytes of keying material for one purpose,
// with HKDF-SHA256. salt scopes the result (a vault ID, say) and label names
// the purpose; different labels give independent keys.
func Derive(key, salt []byte, label string, n int) []byte {
	out, err := hkdf.Key(sha256.New, key, salt, "secretvault "+label, n)
	if err != nil {
		// Only possible for n beyond 255*32 bytes, which is a programming
		// error, never an input error.
		panic(err)
	}
	return out
}

// RandomKey returns a fresh KeySize key.
func RandomKey() []byte { return RandomBytes(KeySize) }

// RandomBytes returns n bytes from the operating system's CSPRNG.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
