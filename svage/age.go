// Package svage reads and writes age files (https://c2sp.org/age), and
// speaks the age plugin protocol (https://c2sp.org/age-plugin) from both
// ends. It is secretvault's own implementation, built on the standard
// library and golang.org/x/crypto, so that vault-held keys can decrypt
// what age, rage, SOPS, gopass and chezmoi encrypt.
//
// A file is a header, which wraps a random 16-byte file key once for each
// recipient, and a payload encrypted with that key:
//
//	w, err := svage.Encrypt(out, recipient)
//	io.Copy(w, in)
//	w.Close()
//
//	r, err := svage.Decrypt(in, identity)
//	io.Copy(out, r)
//
// Recipients and identities come in these kinds:
//
//	X25519        age1...            AGE-SECRET-KEY-1...
//	hybrid (PQ)   age1pq1...         AGE-SECRET-KEY-PQ-1...     ML-KEM-768 + X25519, age v1.3
//	passphrase    (scrypt)           (scrypt)
//	SSH           ssh-ed25519 AAAA…  an OpenSSH private key
//	              ssh-rsa AAAA…
//	hardware tag  age1tag1...        (the token's plugin)       encryption only
//	              age1tagpq1...
//	plugins       age1NAME1...       AGE-PLUGIN-NAME-1...       run as age-plugin-NAME
//
// Post-quantum recipients do not share a file with classical ones unless
// the caller says so (Options.AllowMixedPostQuantum): the classical
// stanza would let a future quantum computer open the file anyway. A
// passphrase is always a file's only recipient.
//
// Parsing is strict wherever the format allows only one encoding, and
// the limits age v1.3.2 sets on headers apply. Secrets are wiped from
// memory where Go lets us reach them; keys held inside crypto/ecdh and
// crypto/hpke values cannot be, which makes the wiping best effort.
package svage

import (
	"bufio"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// FileKeySize is the size of the key each file is encrypted with.
const FileKeySize = 16

// A Recipient wraps a file key for one party, as one or more stanzas.
type Recipient interface {
	Wrap(fileKey []byte) ([]*Stanza, error)
}

// RecipientWithLabels is a Recipient that also says what it may be
// combined with. Encrypt succeeds only if every recipient of a file
// reports the same set of labels (the empty set for recipients without
// this method). Post-quantum recipients report "postquantum"; a
// passphrase reports a random label of its own, so that it stands alone.
type RecipientWithLabels interface {
	WrapWithLabels(fileKey []byte) (stanzas []*Stanza, labels []string, err error)
}

// An Identity unwraps a file key from a header's stanzas. It returns an
// error wrapping ErrIncorrectIdentity when no stanza is for it; any other
// error stops decryption.
type Identity interface {
	Unwrap(stanzas []*Stanza) (fileKey []byte, err error)
}

// ErrIncorrectIdentity is an identity that none of a header's stanzas is
// addressed to.
var ErrIncorrectIdentity = errors.New("svage: no stanza is addressed to this identity")

// ErrHeaderMAC is a header whose MAC does not match its file key: it was
// altered after it was written.
var ErrHeaderMAC = errors.New("svage: the header MAC does not match")

// ErrIncompatibleRecipients is a set of recipients that must not share a
// file (see RecipientWithLabels).
var ErrIncompatibleRecipients = errors.New("svage: these recipients cannot share a file")

// NoIdentityMatchError is returned by Decrypt when no identity unwraps
// the file key.
type NoIdentityMatchError struct {
	// Errors are the identities' errors, each wrapping ErrIncorrectIdentity.
	Errors []error
	// StanzaTypes are the types of the header's stanzas, in order.
	StanzaTypes []string
}

func (e *NoIdentityMatchError) Error() string {
	return fmt.Sprintf("svage: no identity matches any of the recipients (the file has %s stanzas)", strings.Join(e.StanzaTypes, ", "))
}

func (e *NoIdentityMatchError) Unwrap() []error { return e.Errors }

// native is implemented by identities that need no interaction and no
// other process; Decrypt tries them first.
type native interface{ native() }

// Options tune encryption.
type Options struct {
	// AllowMixedPostQuantum lets post-quantum recipients share a file with
	// classical ones. The file is then only as safe as its weakest
	// recipient: a quantum computer that breaks X25519 opens it.
	AllowMixedPostQuantum bool
}

// Encrypt starts an age file to recipients on dst, and returns the writer
// the plaintext goes to. Close must be called to seal the final chunk; it
// does not close dst.
func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	return Options{}.Encrypt(dst, recipients...)
}

// Encrypt is Encrypt with these options.
func (o Options) Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	fileKey := make([]byte, FileKeySize)
	rand.Read(fileKey)
	defer clear(fileKey)
	hdr, err := o.header(fileKey, recipients)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	rand.Read(nonce)
	aead, err := payloadAEAD(fileKey, nonce)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(append(hdr, nonce...)); err != nil {
		return nil, err
	}
	return newStreamWriter(aead, dst), nil
}

// header wraps fileKey for every recipient and writes the header.
func (o Options) header(fileKey []byte, recipients []Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("svage: no recipients")
	}
	var stanzas []*Stanza
	var first []string
	for i, r := range recipients {
		ss, labels, err := wrap(r, fileKey)
		if err != nil {
			return nil, fmt.Errorf("svage: recipient %d: %w", i+1, err)
		}
		if len(ss) == 0 {
			return nil, fmt.Errorf("svage: recipient %d made no stanza", i+1)
		}
		labels = slices.Clone(labels)
		if o.AllowMixedPostQuantum {
			labels = slices.DeleteFunc(labels, func(l string) bool { return l == "postquantum" })
		}
		slices.Sort(labels)
		if i == 0 {
			first = labels
		} else if !slices.Equal(first, labels) {
			return nil, incompatible(first, labels)
		}
		stanzas = append(stanzas, ss...)
	}
	return marshalHeader(stanzas, func(b []byte) []byte { return headerMAC(fileKey, b) })
}

func wrap(r Recipient, fileKey []byte) ([]*Stanza, []string, error) {
	if rl, ok := r.(RecipientWithLabels); ok {
		return rl.WrapWithLabels(fileKey)
	}
	ss, err := r.Wrap(fileKey)
	return ss, nil, err
}

func incompatible(a, b []string) error {
	if slices.Contains(a, "postquantum") != slices.Contains(b, "postquantum") {
		return fmt.Errorf("%w: post-quantum and classical recipients would leave the file open to a quantum computer", ErrIncompatibleRecipients)
	}
	return fmt.Errorf("%w: %q and %q (a passphrase must be the only recipient)", ErrIncompatibleRecipients, a, b)
}

// headerMAC is HMAC-SHA-256 over the header up to "---", keyed with
// HKDF-SHA-256(file key, "", "header").
func headerMAC(fileKey, macked []byte) []byte {
	key, err := hkdf.Key(sha256.New, fileKey, nil, "header", 32)
	if err != nil {
		panic("svage: HKDF: " + err.Error())
	}
	defer clear(key)
	h := hmac.New(sha256.New, key)
	h.Write(macked)
	return h.Sum(nil)
}

// Decrypt reads an age file's header from src, unwraps its file key with
// the first identity that can, and returns a reader of the plaintext.
// Each 64 KiB chunk is authenticated before any of it is returned; an
// error wrapping ErrPayload from the reader means the file was damaged or
// tampered with, and nothing read from it should be trusted.
//
// Errors from Decrypt itself: *NoIdentityMatchError, ErrHeaderMAC,
// ErrHeader (a malformed header), or *ArmorError when src is armored.
func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	br := bufio.NewReader(src)
	hdr, err := parseHeader(br)
	if err != nil {
		return nil, err
	}
	fileKey, err := unwrapHeader(hdr, identities)
	if err != nil {
		return nil, err
	}
	defer clear(fileKey)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(br, nonce); err != nil {
		var ae *ArmorError
		if errors.As(err, &ae) {
			return nil, err
		}
		return nil, headerErrorf("the file ends before the payload nonce")
	}
	aead, err := payloadAEAD(fileKey, nonce)
	if err != nil {
		return nil, err
	}
	return newStreamReader(aead, br), nil
}

// DecryptReaderAt is Decrypt for a file that can be read at random: src
// holds size bytes. It returns a ReaderAt of the plaintext and the
// plaintext's size, which it fixes by authenticating the final chunk
// first. The ReaderAt is safe for concurrent use.
func DecryptReaderAt(src io.ReaderAt, size int64, identities ...Identity) (io.ReaderAt, int64, error) {
	br := bufio.NewReader(io.NewSectionReader(src, 0, size))
	hdr, err := parseHeader(br)
	if err != nil {
		return nil, 0, err
	}
	fileKey, err := unwrapHeader(hdr, identities)
	if err != nil {
		return nil, 0, err
	}
	defer clear(fileKey)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(br, nonce); err != nil {
		return nil, 0, headerErrorf("the file ends before the payload nonce")
	}
	aead, err := payloadAEAD(fileKey, nonce)
	if err != nil {
		return nil, 0, err
	}
	off := hdr.size + nonceSize
	r, err := newReaderAt(aead, io.NewSectionReader(src, off, size-off), size-off)
	if err != nil {
		return nil, 0, err
	}
	return r, r.size, nil
}

// unwrapHeader finds the file key and checks the header's MAC with it.
func unwrapHeader(hdr *header, identities []Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, errors.New("svage: no identities")
	}
	for _, s := range hdr.stanzas {
		if s.Type == "scrypt" && len(hdr.stanzas) != 1 {
			return nil, headerErrorf("a passphrase (scrypt) stanza must be the only one in a header")
		}
	}
	ids := slices.Clone(identities)
	slices.SortStableFunc(ids, func(a, b Identity) int {
		_, an := a.(native)
		_, bn := b.(native)
		switch {
		case an && !bn:
			return -1
		case bn && !an:
			return 1
		}
		return 0
	})
	noMatch := &NoIdentityMatchError{}
	for _, s := range hdr.stanzas {
		noMatch.StanzaTypes = append(noMatch.StanzaTypes, s.Type)
	}
	stanzas := copyStanzas(hdr.stanzas)
	for _, id := range ids {
		fileKey, err := id.Unwrap(stanzas)
		if errors.Is(err, ErrIncorrectIdentity) {
			noMatch.Errors = append(noMatch.Errors, err)
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(fileKey) != FileKeySize {
			clear(fileKey)
			return nil, headerErrorf("an identity unwrapped a file key of %d bytes", len(fileKey))
		}
		if !hmac.Equal(headerMAC(fileKey, hdr.macked), hdr.mac) {
			clear(fileKey)
			return nil, ErrHeaderMAC
		}
		return fileKey, nil
	}
	return nil, noMatch
}

// copyStanzas gives identities their own copies, so none can change what
// the next one sees.
func copyStanzas(in []*Stanza) []*Stanza {
	out := make([]*Stanza, len(in))
	for i, s := range in {
		out[i] = &Stanza{Type: s.Type, Args: slices.Clone(s.Args), Body: slices.Clone(s.Body)}
	}
	return out
}

// Helpers the stanza types share.

// sealKey and openKey wrap a file key under a one-time key, with the
// all-zero nonce the format fixes (every wrap key is fresh).
func sealKey(key, fileKey []byte) ([]byte, error) {
	aead, err := newChaCha(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, make([]byte, aead.NonceSize()), fileKey, nil), nil
}

// errBodySize is a stanza body of the wrong size. Checking the size
// before trying to open it blocks partitioning oracle attacks, where one
// crafted ciphertext opens under many keys.
var errBodySize = errors.New("the wrapped file key has the wrong size")

func openKey(key, body []byte) ([]byte, error) {
	aead, err := newChaCha(key)
	if err != nil {
		return nil, err
	}
	if len(body) != FileKeySize+aead.Overhead() {
		return nil, errBodySize
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), body, nil)
}

// multiUnwrap tries unwrap on each stanza in turn.
func multiUnwrap(unwrap func(*Stanza) ([]byte, error), stanzas []*Stanza) ([]byte, error) {
	for i, s := range stanzas {
		fileKey, err := unwrap(s)
		if errors.Is(err, ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, &StanzaError{Index: i, Type: s.Type, Err: err}
		}
		return fileKey, nil
	}
	return nil, ErrIncorrectIdentity
}

// StanzaError is a stanza an identity recognised but found malformed.
type StanzaError struct {
	Index int    // its position in the header
	Type  string // its type
	Err   error
}

func (e *StanzaError) Error() string {
	return fmt.Sprintf("svage: malformed header: %s stanza %d: %v", e.Type, e.Index+1, e.Err)
}

func (e *StanzaError) Unwrap() []error { return []error{ErrHeader, e.Err} }
