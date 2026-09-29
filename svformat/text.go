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
//	identity       SV-IDENTITY-1-MODERN-... private key, base32
//	recipient      sv-recipient-1-modern-... public key, base64url
//
// The recovery key is meant to be written on paper and typed back, so it
// carries a checksum that catches a mistyped character before any
// decryption is tried, and its reader forgives case, spaces and the
// letters people confuse with digits.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const recoveryPrefix = "SVRK1-"

// ErrRecoveryKey is a recovery key that does not parse or fails its
// checksum.
var ErrRecoveryKey = errors.New("svformat: that is not a valid recovery key (check for a typo)")

// EncodeRecoveryKey writes a 32-byte recovery key for printing.
func EncodeRecoveryKey(key []byte) string {
	sum := sha256.Sum256(key)
	raw := append(append([]byte{}, key...), sum[:2]...)
	s := b32.EncodeToString(raw)
	clear(raw)
	return recoveryPrefix + group5(s)
}

const sharePrefix = "SVRS1-"

// ErrRecoveryShare is a recovery share that does not parse or fails its
// checksum.
var ErrRecoveryShare = errors.New("svformat: that is not a valid recovery share (check for a typo)")

// EncodeRecoveryShare writes one Shamir share of a recovery key (as
// svcrypto.SplitSecret makes it: x, then 32 y bytes) for printing. It
// carries the threshold, so whoever gathers shares knows how many to ask
// for, and a checksum, like the key itself.
func EncodeRecoveryShare(share []byte, threshold int) string {
	raw := append([]byte{byte(threshold)}, share...)
	sum := sha256.Sum256(raw)
	raw = append(raw, sum[:2]...)
	s := b32.EncodeToString(raw)
	clear(raw)
	return sharePrefix + group5(s)
}

// ParseRecoveryShare reads a share as typed by a person, returning it in
// svcrypto.CombineShares' form, and the threshold it was made with.
func ParseRecoveryShare(s string) (share []byte, threshold int, err error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(s))
	rest, ok := strings.CutPrefix(s, strings.TrimSuffix(sharePrefix, "-"))
	if !ok {
		return nil, 0, ErrRecoveryShare
	}
	rest = strings.NewReplacer("0", "O", "1", "I", "8", "B").Replace(rest)
	raw, err := b32.DecodeString(rest)
	if err != nil || len(raw) != 2+svcrypto.KeySize+2 {
		return nil, 0, ErrRecoveryShare
	}
	body, check := raw[:len(raw)-2], raw[len(raw)-2:]
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:2], check) != 1 || body[0] < 2 || body[1] == 0 {
		clear(raw)
		return nil, 0, ErrRecoveryShare
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

// ParseRecoveryKey reads a recovery key as typed by a person.
func ParseRecoveryKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(s))
	s = strings.TrimPrefix(s, strings.TrimSuffix(recoveryPrefix, "-"))
	s = strings.NewReplacer("0", "O", "1", "I", "8", "B").Replace(s)
	raw, err := b32.DecodeString(s)
	if err != nil || len(raw) != svcrypto.KeySize+2 {
		return nil, ErrRecoveryKey
	}
	key, check := raw[:svcrypto.KeySize], raw[svcrypto.KeySize:]
	sum := sha256.Sum256(key)
	if subtle.ConstantTimeCompare(sum[:2], check) != 1 {
		clear(raw)
		return nil, ErrRecoveryKey
	}
	return key, nil
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
