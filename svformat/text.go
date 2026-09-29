package svformat

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svcrypto"
)

// Text forms of keys that people copy, print or paste.
//
//	recovery key   SVRK1-XXXXX-XXXXX-...    32 key bytes + 2 checksum bytes, base32
//	recovery share SVRS1-XXXXX-XXXXX-...    threshold, x, 32 y bytes + 2 checksum bytes
//	unseal key     SVUK1-XXXXX-XXXXX-...    a delivery server's key, as the recovery key
//	unseal share   SVUS1-XXXXX-XXXXX-...    a share of a delivery server's unseal key
//	identity       SV-IDENTITY-1-MODERN-... private key, base32
//	recipient      sv-recipient-1-modern-... public key, base64url
//
// The recovery key is meant to be written on paper and typed back, so it
// carries a checksum that catches a mistyped character before any
// decryption is tried, and its reader forgives case, spaces and the
// letters people confuse with digits. Unseal keys and shares
// (secretvault-server, svdeliver) have the same form under their own
// prefixes, so one is never taken for the other.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const recoveryPrefix = "SVRK1-"

// ErrRecoveryKey is a recovery key that does not parse or fails its
// checksum.
var ErrRecoveryKey = errors.New("svformat: that is not a valid recovery key (check for a typo)")

// EncodeRecoveryKey writes a 32-byte recovery key for printing.
func EncodeRecoveryKey(key []byte) string { return encodeChecked(recoveryPrefix, key) }

const sharePrefix = "SVRS1-"

// ErrRecoveryShare is a recovery share that does not parse or fails its
// checksum.
var ErrRecoveryShare = errors.New("svformat: that is not a valid recovery share (check for a typo)")

// EncodeRecoveryShare writes one Shamir share of a recovery key (as
// svcrypto.SplitSecret makes it: x, then 32 y bytes) for printing. It
// carries the threshold, so whoever gathers shares knows how many to ask
// for, and a checksum, like the key itself.
func EncodeRecoveryShare(share []byte, threshold int) string {
	return encodeShare(sharePrefix, share, threshold)
}

// ParseRecoveryShare reads a share as typed by a person, returning it in
// svcrypto.CombineShares' form, and the threshold it was made with.
func ParseRecoveryShare(s string) (share []byte, threshold int, err error) {
	return parseShare(sharePrefix, s, ErrRecoveryShare)
}

// ParseRecoveryKey reads a recovery key as typed by a person.
func ParseRecoveryKey(s string) ([]byte, error) {
	key, ok := decodeChecked(recoveryPrefix, s, true, svcrypto.KeySize)
	if !ok {
		return nil, ErrRecoveryKey
	}
	return key, nil
}

const (
	unsealKeyPrefix   = "SVUK1-"
	unsealSharePrefix = "SVUS1-"
)

var (
	// ErrUnsealKey is an unseal key that does not parse or fails its
	// checksum.
	ErrUnsealKey = errors.New("svformat: that is not a valid unseal key (check for a typo)")

	// ErrUnsealShare is an unseal share that does not parse or fails its
	// checksum.
	ErrUnsealShare = errors.New("svformat: that is not a valid unseal share (check for a typo)")
)

// EncodeUnsealKey writes a delivery server's 32-byte unseal key (or its
// auto-unseal credential key) as text.
func EncodeUnsealKey(key []byte) string { return encodeChecked(unsealKeyPrefix, key) }

// ParseUnsealKey reads a key written by EncodeUnsealKey. The prefix is
// required: a recovery key is never taken for one.
func ParseUnsealKey(s string) ([]byte, error) {
	key, ok := decodeChecked(unsealKeyPrefix, s, false, svcrypto.KeySize)
	if !ok {
		return nil, ErrUnsealKey
	}
	return key, nil
}

// EncodeUnsealShare writes one Shamir share of a delivery server's unseal
// key, with its threshold and a checksum, as EncodeRecoveryShare does.
func EncodeUnsealShare(share []byte, threshold int) string {
	return encodeShare(unsealSharePrefix, share, threshold)
}

// ParseUnsealShare reads an unseal share as typed by a person, returning
// it in svcrypto.CombineShares' form, and the threshold it was made with.
func ParseUnsealShare(s string) (share []byte, threshold int, err error) {
	return parseShare(unsealSharePrefix, s, ErrUnsealShare)
}

// encodeChecked writes body and the first two bytes of its SHA-256 in
// base32, in groups of five, after prefix.
func encodeChecked(prefix string, body []byte) string {
	sum := sha256.Sum256(body)
	raw := append(append([]byte{}, body...), sum[:2]...)
	s := b32.EncodeToString(raw)
	clear(raw)
	return prefix + group5(s)
}

// decodeChecked reverses encodeChecked for a body of size bytes,
// forgiving case, spaces, dashes and the digits people type for the
// letters O, I and B. The prefix may be left out only when optional.
func decodeChecked(prefix, s string, optional bool, size int) ([]byte, bool) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(s))
	rest, ok := strings.CutPrefix(s, strings.TrimSuffix(prefix, "-"))
	if !ok && !optional {
		return nil, false
	}
	rest = strings.NewReplacer("0", "O", "1", "I", "8", "B").Replace(rest)
	raw, err := b32.DecodeString(rest)
	if err != nil || len(raw) != size+2 {
		return nil, false
	}
	body, check := raw[:size], raw[size:]
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:2], check) != 1 {
		clear(raw)
		return nil, false
	}
	return body, true
}

func encodeShare(prefix string, share []byte, threshold int) string {
	body := append([]byte{byte(threshold)}, share...)
	defer clear(body)
	return encodeChecked(prefix, body)
}

func parseShare(prefix, s string, bad error) ([]byte, int, error) {
	body, ok := decodeChecked(prefix, s, false, 2+svcrypto.KeySize)
	if !ok {
		return nil, 0, bad
	}
	if body[0] < 2 || body[1] == 0 {
		clear(body)
		return nil, 0, bad
	}
	return body[1:], int(body[0]), nil
}

func group5(s string) string {
	var groups []string
	for len(s) > 5 {
		groups = append(groups, s[:5])
		s = s[5:]
	}
	return strings.Join(append(groups, s), "-")
}

const (
	identityPrefix  = "SV-IDENTITY-1-"
	recipientPrefix = "sv-recipient-1-"
)

func suiteTag(s svcrypto.Suite) string { return strings.TrimPrefix(s.String(), "sv1-") }

// EncodeIdentity writes a private key as text.
func EncodeIdentity(suite svcrypto.Suite, priv []byte) string {
	return identityPrefix + strings.ToUpper(suiteTag(suite)) + "-" + b32.EncodeToString(priv)
}

// ParseIdentity reads a private key written by EncodeIdentity.
func ParseIdentity(s string) (svcrypto.Suite, []byte, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, identityPrefix)
	tag, body, ok2 := strings.Cut(rest, "-")
	if !ok || !ok2 {
		return 0, nil, errors.New("svformat: not a secretvault identity")
	}
	suite, err := svcrypto.ParseSuite(strings.ToLower(tag))
	if err != nil {
		return 0, nil, err
	}
	priv, err := b32.DecodeString(body)
	if err != nil {
		return 0, nil, fmt.Errorf("svformat: identity: %w", err)
	}
	return suite, priv, nil
}

// EncodeRecipient writes a public key as text.
func EncodeRecipient(suite svcrypto.Suite, pub []byte) string {
	return recipientPrefix + suiteTag(suite) + "-" + base64.RawURLEncoding.EncodeToString(pub)
}

// ParseRecipient reads a public key written by EncodeRecipient.
func ParseRecipient(s string) (svcrypto.Suite, []byte, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, recipientPrefix)
	tag, body, ok2 := strings.Cut(rest, "-")
	if !ok || !ok2 {
		return 0, nil, errors.New("svformat: not a secretvault recipient")
	}
	suite, err := svcrypto.ParseSuite(tag)
	if err != nil {
		return 0, nil, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return 0, nil, fmt.Errorf("svformat: recipient: %w", err)
	}
	if err := suite.CheckRecipient(pub); err != nil {
		return 0, nil, err
	}
	return suite, pub, nil
}
