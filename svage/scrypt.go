package svage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Passphrase recipients: "-> scrypt <salt> <log2 N>", the file key sealed
// under scrypt(N, r = 8, p = 1) of the passphrase with the salt
// "age-encryption.org/v1/scrypt" || salt. A passphrase is always a file's
// only recipient: a file anyone else can also open says nothing about who
// wrote it, which people expect a passphrase to say.

const scryptLabel = "age-encryption.org/v1/scrypt"

const (
	// DefaultScryptWorkFactor is log2 N for new files: about a second.
	DefaultScryptWorkFactor = 18
	// MaxScryptWorkFactor is the largest log2 N an identity accepts by
	// default: about fifteen seconds. A file demanding more is refused
	// rather than left to keep a machine busy.
	MaxScryptWorkFactor = 22
)

// ScryptRecipient encrypts to a passphrase.
type ScryptRecipient struct {
	passphrase []byte
	workFactor int
}

// NewScryptRecipient makes a recipient of a passphrase, which it copies.
func NewScryptRecipient(passphrase []byte) (*ScryptRecipient, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("svage: the passphrase is empty")
	}
	return &ScryptRecipient{passphrase: append([]byte(nil), passphrase...), workFactor: DefaultScryptWorkFactor}, nil
}

// SetWorkFactor sets log2 N (1 to 30) for the files it wraps.
func (r *ScryptRecipient) SetWorkFactor(logN int) error {
	if logN < 1 || logN > 30 {
		return fmt.Errorf("svage: scrypt work factor %d out of range", logN)
	}
	r.workFactor = logN
	return nil
}

// Wipe zeroes the recipient's copy of the passphrase.
func (r *ScryptRecipient) Wipe() { clear(r.passphrase) }

// Wrap implements Recipient.
func (r *ScryptRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements RecipientWithLabels with a random label, so
// that nothing else can share the file.
func (r *ScryptRecipient) WrapWithLabels(fileKey []byte) ([]*Stanza, []string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := scrypt.Key(r.passphrase, append([]byte(scryptLabel), salt...), 1<<r.workFactor, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	body, err := sealKey(key, fileKey)
	if err != nil {
		return nil, nil, err
	}
	label := make([]byte, 16)
	rand.Read(label)
	s := &Stanza{Type: "scrypt", Args: []string{encodeB64(salt), strconv.Itoa(r.workFactor)}, Body: body}
	return []*Stanza{s}, []string{hex.EncodeToString(label)}, nil
}

// ScryptIdentity decrypts files encrypted to a passphrase.
type ScryptIdentity struct {
	passphrase    []byte
	maxWorkFactor int
}

func (*ScryptIdentity) native() {}

// NewScryptIdentity makes an identity of a passphrase, which it copies.
func NewScryptIdentity(passphrase []byte) (*ScryptIdentity, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("svage: the passphrase is empty")
	}
	return &ScryptIdentity{passphrase: append([]byte(nil), passphrase...), maxWorkFactor: MaxScryptWorkFactor}, nil
}

// SetMaxWorkFactor sets the largest log2 N (1 to 30) it will compute.
func (id *ScryptIdentity) SetMaxWorkFactor(logN int) error {
	if logN < 1 || logN > 30 {
		return fmt.Errorf("svage: scrypt work factor %d out of range", logN)
	}
	id.maxWorkFactor = logN
	return nil
}

// Wipe zeroes the identity's copy of the passphrase.
func (id *ScryptIdentity) Wipe() { clear(id.passphrase) }

// Unwrap implements Identity.
func (id *ScryptIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	for i, s := range stanzas {
		if s.Type != "scrypt" {
			continue
		}
		if len(stanzas) != 1 {
			return nil, &StanzaError{Index: i, Type: s.Type, Err: errors.New("a passphrase stanza must be the only one")}
		}
		fileKey, err := id.unwrap(s)
		if err != nil && !errors.Is(err, ErrIncorrectIdentity) {
			return nil, &StanzaError{Index: i, Type: s.Type, Err: err}
		}
		return fileKey, err
	}
	return nil, fmt.Errorf("%w: the file is not encrypted to a passphrase", ErrIncorrectIdentity)
}

func (id *ScryptIdentity) unwrap(s *Stanza) ([]byte, error) {
	if len(s.Args) != 2 {
		return nil, errors.New("a scrypt stanza has two arguments")
	}
	salt, err := decodeB64(s.Args[0])
	if err != nil || len(salt) != 16 {
		return nil, errors.New("the salt is not 16 bytes of canonical base64")
	}
	logN, err := workFactor(s.Args[1])
	if err != nil {
		return nil, err
	}
	if logN > id.maxWorkFactor {
		return nil, fmt.Errorf("the work factor 2^%d is larger than the limit 2^%d", logN, id.maxWorkFactor)
	}
	if len(s.Body) != FileKeySize+chacha20poly1305.Overhead {
		return nil, errBodySize
	}
	key, err := scrypt.Key(id.passphrase, append([]byte(scryptLabel), salt...), 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	fileKey, err := openKey(key, s.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: wrong passphrase", ErrIncorrectIdentity)
	}
	return fileKey, nil
}

// workFactor parses log2 N: decimal digits without a leading zero, as the
// spec's ^[1-9][0-9]*$ allows, and small enough to mean something.
func workFactor(s string) (int, error) {
	if s == "" || s[0] == '0' {
		return 0, errors.New("the work factor is not a decimal number without leading zeros")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("the work factor is not a decimal number without leading zeros")
		}
	}
	if n, err := strconv.Atoi(s); err == nil && n <= 30 {
		return n, nil
	}
	return 0, errors.New("the work factor is out of range")
}
