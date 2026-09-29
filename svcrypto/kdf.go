package svcrypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDF algorithm names, as written in keyslot files.
const (
	Argon2id     = "argon2id"
	PBKDF2SHA256 = "pbkdf2-sha256"
)

// KDFParams says how a passphrase becomes a key-encryption key. It is
// stored in the clear next to what it protects; only the passphrase is
// secret.
type KDFParams struct {
	Alg  string `json:"alg"`
	Salt []byte `json:"salt"`

	// Argon2id.
	Time      uint32 `json:"time,omitempty"`
	MemoryKiB uint32 `json:"memory_kib,omitempty"`
	Threads   uint8  `json:"threads,omitempty"`

	// PBKDF2.
	Iterations uint32 `json:"iterations,omitempty"`
}

// Default costs for new passphrase keyslots. Argon2id is RFC 9106's second
// recommended setting (3 passes over 64 MiB, 4 lanes); PBKDF2 is OWASP's
// 600,000 iterations of HMAC-SHA256. Tests lower these; an existing slot is
// always opened with the cost it records.
var (
	DefaultArgon2 = KDFParams{Alg: Argon2id, Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
	DefaultPBKDF2 = KDFParams{Alg: PBKDF2SHA256, Iterations: 600_000}
)

// Upper bounds on what a stored slot may ask for. They stop a planted slot
// file from turning an unlock attempt into a memory or CPU exhaustion.
const (
	maxArgon2Time      = 64
	maxArgon2MemoryKiB = 4 * 1024 * 1024 // 4 GiB
	maxArgon2Threads   = 64
	maxPBKDF2Iter      = 50_000_000
	saltSize           = 16
)

// ErrKDFParams is a KDF description that is unknown, incomplete or beyond
// the bounds above.
var ErrKDFParams = errors.New("svcrypto: bad key-derivation parameters")

// NewKDFParams returns the suite's default passphrase KDF with a fresh salt.
func (s Suite) NewKDFParams() KDFParams {
	p := DefaultArgon2
	if s == NIST {
		p = DefaultPBKDF2
	}
	p.Salt = RandomBytes(saltSize)
	return p
}

// Check reports whether p is complete and within bounds.
func (p KDFParams) Check() error {
	if len(p.Salt) < saltSize {
		return fmt.Errorf("%w: salt is %d bytes, want at least %d", ErrKDFParams, len(p.Salt), saltSize)
	}
	switch p.Alg {
	case Argon2id:
		if p.Time < 1 || p.Time > maxArgon2Time ||
			p.Threads < 1 || p.Threads > maxArgon2Threads ||
			p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxArgon2MemoryKiB {
			return fmt.Errorf("%w: argon2id t=%d m=%dKiB p=%d", ErrKDFParams, p.Time, p.MemoryKiB, p.Threads)
		}
	case PBKDF2SHA256:
		if p.Iterations < 1 || p.Iterations > maxPBKDF2Iter {
			return fmt.Errorf("%w: pbkdf2 iterations=%d", ErrKDFParams, p.Iterations)
		}
	default:
		return fmt.Errorf("%w: algorithm %q", ErrKDFParams, p.Alg)
	}
	return nil
}

// DeriveKey turns a passphrase into a KeySize key-encryption key.
func (p KDFParams) DeriveKey(passphrase []byte) ([]byte, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	switch p.Alg {
	case Argon2id:
		return argon2.IDKey(passphrase, p.Salt, p.Time, p.MemoryKiB, p.Threads, KeySize), nil
	default: // PBKDF2SHA256, per Check
		return pbkdf2.Key(sha256.New, string(passphrase), p.Salt, int(p.Iterations), KeySize)
	}
}
