package svmail

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Keys is where Inspect gets keys: public keys to verify with, roots to
// build chains to, and decryption, which may happen somewhere else (the
// daemon keeps private keys in the vault and asks the person before
// using one). svmail decides nothing about trust in people: it reports
// which key or certificate did what, and the caller maps that to people.
//
// A lookup that finds nothing returns no keys and no error; an error is
// for a lookup that could not be made (a locked vault, say), and is
// reported in the Report.
type Keys interface {
	// PGPKeysByFingerprint returns the OpenPGP keys with this primary key
	// or subkey fingerprint.
	PGPKeysByFingerprint(fp []byte) ([]*svpgp.Key, error)
	// PGPKeysByKeyID returns the OpenPGP keys with this primary key or
	// subkey ID.
	PGPKeysByKeyID(id uint64) ([]*svpgp.Key, error)
	// PGPKeysByEmail returns the OpenPGP keys with a user ID for this
	// address.
	PGPKeysByEmail(addr string) ([]*svpgp.Key, error)
	// DecryptPGP decrypts an OpenPGP message. See PGPDecryptRequest.
	DecryptPGP(req *PGPDecryptRequest) (*svpgp.Message, error)

	// SMIMERoots are the trusted S/MIME roots, and SMIMEIntermediates
	// further certificates to build chains with (and to find signers
	// among, for signatures that carry no certificates).
	SMIMERoots() ([]*x509.Certificate, error)
	SMIMEIntermediates() ([]*x509.Certificate, error)
	// SMIMEContentKey returns the content key of an S/MIME message held
	// for this recipient, as svcms.Decrypter's ContentKey does: an error
	// wrapping svcms.ErrNotRecipient when no private key here is the
	// recipient's.
	SMIMEContentKey(r *svcms.Recipient) ([]byte, error)
}

// PGPDecryptRequest is an OpenPGP message to decrypt.
type PGPDecryptRequest struct {
	// Message is the encrypted OpenPGP message, armored or binary.
	Message []byte
	// Recipients are the keys it says it is encrypted to, read from its
	// session key packets, so the implementation can pick the key (and
	// tell the person which) before decrypting anything.
	Recipients []PGPRecipient
	// Verify holds public keys to check signatures inside the message
	// with: those Inspect found for the sender. The implementation should
	// add every key it knows, as svpgp.ReadMessage checks signatures
	// against its keyring only. If a signature turns out to be by a known
	// key that was not given, Inspect asks once more with it added.
	Verify []*svpgp.Key
	// Time is when signatures are judged.
	Time time.Time
}

// PGPRecipient is one recipient an OpenPGP message names.
type PGPRecipient struct {
	// KeyID is the recipient key's ID (zero when the message hides it);
	// Fingerprint its fingerprint, which version 6 session key packets
	// carry instead.
	KeyID       uint64
	Fingerprint []byte
	Algorithm   svpgp.PublicKeyAlgorithm
	// Passphrase marks a symmetric session key packet: the message can
	// also be decrypted with a passphrase.
	Passphrase bool
}

// NoKeys has no keys: every lookup finds nothing, and every decryption
// fails with ErrNoKeys. Inspect with it reports structure and who signed,
// without verifying or decrypting.
type NoKeys struct{}

func (NoKeys) PGPKeysByFingerprint([]byte) ([]*svpgp.Key, error) { return nil, nil }
func (NoKeys) PGPKeysByKeyID(uint64) ([]*svpgp.Key, error)       { return nil, nil }
func (NoKeys) PGPKeysByEmail(string) ([]*svpgp.Key, error)       { return nil, nil }
func (NoKeys) DecryptPGP(*PGPDecryptRequest) (*svpgp.Message, error) {
	return nil, ErrNoKeys
}
func (NoKeys) SMIMERoots() ([]*x509.Certificate, error)         { return nil, nil }
func (NoKeys) SMIMEIntermediates() ([]*x509.Certificate, error) { return nil, nil }
func (NoKeys) SMIMEContentKey(*svcms.Recipient) ([]byte, error) {
	return nil, fmt.Errorf("%w: %w", ErrNoKeys, svcms.ErrNotRecipient)
}

// LocalKeys holds keys in this process: for tools, tests, and callers
// with unlocked keys at hand. The daemon implements Keys over the trust
// store and the vault instead.
type LocalKeys struct {
	// PGP holds OpenPGP keys: public keys to verify with, and unlocked
	// secret keys to decrypt with.
	PGP []*svpgp.Key
	// Roots and Intermediates are S/MIME certificates.
	Roots, Intermediates []*x509.Certificate
	// SMIME decrypts S/MIME messages; svcms.KeyDecrypter makes one from a
	// certificate and its key.
	SMIME []svcms.Decrypter
}

func (l *LocalKeys) PGPKeysByFingerprint(fp []byte) ([]*svpgp.Key, error) {
	var out []*svpgp.Key
	for _, k := range l.PGP {
		if bytes.Equal(k.Fingerprint(), fp) {
			out = append(out, k)
			continue
		}
		for _, s := range k.Subkeys() {
			if bytes.Equal(s.Fingerprint, fp) {
				out = append(out, k)
				break
			}
		}
	}
	return out, nil
}

func (l *LocalKeys) PGPKeysByKeyID(id uint64) ([]*svpgp.Key, error) {
	var out []*svpgp.Key
	for _, k := range l.PGP {
		if k.KeyID() == id {
			out = append(out, k)
			continue
		}
		for _, s := range k.Subkeys() {
			if s.KeyID == id {
				out = append(out, k)
				break
			}
		}
	}
	return out, nil
}

func (l *LocalKeys) PGPKeysByEmail(addr string) ([]*svpgp.Key, error) {
	var out []*svpgp.Key
	for _, k := range l.PGP {
		if keyHasAddress(k, addr) {
			out = append(out, k)
		}
	}
	return out, nil
}

// DecryptPGP decrypts with the unlocked secret keys among PGP, checking
// signatures against PGP and the request's keys.
func (l *LocalKeys) DecryptPGP(req *PGPDecryptRequest) (*svpgp.Message, error) {
	keyring := append(append([]*svpgp.Key{}, l.PGP...), req.Verify...)
	msg, err := svpgp.ReadMessage(bytes.NewReader(req.Message), svpgp.ReadOptions{Keyring: keyring, Time: req.Time})
	if err != nil {
		return nil, err
	}
	if !msg.Encrypted {
		clear(msg.Body)
		return nil, svpgp.ErrNotEncrypted
	}
	return msg, nil
}

func (l *LocalKeys) SMIMERoots() ([]*x509.Certificate, error)         { return l.Roots, nil }
func (l *LocalKeys) SMIMEIntermediates() ([]*x509.Certificate, error) { return l.Intermediates, nil }

func (l *LocalKeys) SMIMEContentKey(r *svcms.Recipient) ([]byte, error) {
	return svcms.Decrypters(l.SMIME).ContentKey(r)
}

// keyHasAddress says whether one of the key's valid user IDs is for addr.
func keyHasAddress(k *svpgp.Key, addr string) bool {
	for _, uid := range k.UserIDs() {
		if strings.EqualFold(uidAddress(uid), addr) && addr != "" {
			return true
		}
	}
	return false
}

// uidAddress is the address in an OpenPGP user ID: "Name <addr>", or a
// bare address.
func uidAddress(uid string) string {
	if a, err := mail.ParseAddress(uid); err == nil {
		return a.Address
	}
	if i, j := strings.LastIndexByte(uid, '<'), strings.LastIndexByte(uid, '>'); i >= 0 && j > i {
		return strings.TrimSpace(uid[i+1 : j])
	}
	if strings.Contains(uid, "@") && !strings.ContainsAny(uid, " <>") {
		return uid
	}
	return ""
}
