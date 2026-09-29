// Package svotp generates one-time passwords: HOTP (RFC 4226), TOTP
// (RFC 6238) and Steam Guard codes, from keys written as otpauth:// URIs,
// the form authenticator apps, QR codes and exports use
// (https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
// secretvault stores a key as an item field of type "otp" holding the URI.
package svotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Key is one OTP secret and how to use it.
type Key struct {
	Type      string // "totp" or "hotp"
	Issuer    string
	Account   string
	Secret    []byte
	Algorithm string // "SHA1", "SHA256", "SHA512"
	Digits    int    // 6 or 8 usually; Steam uses 5 characters
	Period    int    // seconds, for TOTP
	Counter   uint64 // for HOTP
	Steam     bool   // Steam Guard: 5 characters from Steam's alphabet
}

// ErrKey is a key or URI that cannot be used.
var ErrKey = errors.New("svotp: not a usable OTP key")

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// DecodeSecret reads a base32 secret as people and apps write it: any
// case, with or without spaces, dashes and padding.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	b, err := b32.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("%w: the secret is not base32", ErrKey)
	}
	return b, nil
}

// Parse reads an otpauth:// URI.
func Parse(uri string) (*Key, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil || u.Scheme != "otpauth" {
		return nil, fmt.Errorf("%w: not an otpauth URI", ErrKey)
	}
	k := &Key{Type: strings.ToLower(u.Host), Algorithm: "SHA1", Digits: 6, Period: 30}
	if k.Type != "totp" && k.Type != "hotp" {
		return nil, fmt.Errorf("%w: type %q", ErrKey, u.Host)
	}
	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		k.Issuer, k.Account = strings.TrimSpace(issuer), strings.TrimSpace(account)
	} else {
		k.Account = label
	}
	q := u.Query()
	if k.Secret, err = DecodeSecret(q.Get("secret")); err != nil {
		return nil, err
	}
	if v := q.Get("issuer"); v != "" {
		k.Issuer = v
	}
	if v := q.Get("algorithm"); v != "" {
		k.Algorithm = strings.ToUpper(v)
	}
	if v := q.Get("digits"); v != "" {
		if k.Digits, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("%w: digits %q", ErrKey, v)
		}
	}
	if v := q.Get("period"); v != "" {
		if k.Period, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("%w: period %q", ErrKey, v)
		}
	}
	if v := q.Get("counter"); v != "" {
		if k.Counter, err = strconv.ParseUint(v, 10, 64); err != nil {
			return nil, fmt.Errorf("%w: counter %q", ErrKey, v)
		}
	}
	// Steam Guard keys: by issuer (as Aegis and others write them) or an
	// explicit encoder parameter.
	if strings.EqualFold(k.Issuer, "Steam") || strings.EqualFold(q.Get("encoder"), "steam") {
		k.Steam, k.Digits = true, 5
	}
	return k, k.check()
}

func (k *Key) check() error {
	switch {
	case len(k.Secret) == 0:
		return fmt.Errorf("%w: no secret", ErrKey)
	case k.Algorithm != "SHA1" && k.Algorithm != "SHA256" && k.Algorithm != "SHA512":
		return fmt.Errorf("%w: algorithm %q", ErrKey, k.Algorithm)
	case k.Digits < 5 || k.Digits > 10:
		return fmt.Errorf("%w: %d digits", ErrKey, k.Digits)
	case k.Type == "totp" && (k.Period < 1 || k.Period > 3600):
		return fmt.Errorf("%w: period %d", ErrKey, k.Period)
	}
	return nil
}

// URI writes the key as an otpauth:// URI.
func (k *Key) URI() string {
	label := k.Account
	if k.Issuer != "" {
		label = k.Issuer + ":" + k.Account
	}
	q := url.Values{}
	q.Set("secret", b32.EncodeToString(k.Secret))
	if k.Issuer != "" {
		q.Set("issuer", k.Issuer)
	}
	if k.Algorithm != "SHA1" {
		q.Set("algorithm", k.Algorithm)
	}
	if k.Digits != 6 && !k.Steam {
		q.Set("digits", strconv.Itoa(k.Digits))
	}
	if k.Type == "totp" && k.Period != 30 {
		q.Set("period", strconv.Itoa(k.Period))
	}
	if k.Type == "hotp" {
		q.Set("counter", strconv.FormatUint(k.Counter, 10))
	}
	if k.Steam {
		q.Set("encoder", "steam")
	}
	u := url.URL{Scheme: "otpauth", Host: k.Type, Path: "/" + label, RawQuery: q.Encode()}
	return u.String()
}

func (k *Key) hash() func() hash.Hash {
	switch k.Algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	}
	return sha1.New
}

const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

// HOTP is the code for a counter value (RFC 4226 section 5).
func (k *Key) HOTP(counter uint64) string {
	mac := hmac.New(k.hash(), k.Secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	if k.Steam {
		out := make([]byte, 5)
		for i := range out {
			out[i] = steamAlphabet[v%uint32(len(steamAlphabet))]
			v /= uint32(len(steamAlphabet))
		}
		return string(out)
	}
	mod := uint32(1)
	for range k.Digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", k.Digits, v%mod)
}

// Code is the TOTP code at time t (or, for an HOTP key, the code for its
// counter), and how long it stays valid.
func (k *Key) Code(t time.Time) (code string, remaining time.Duration) {
	if k.Type == "hotp" {
		return k.HOTP(k.Counter), 0
	}
	step := uint64(t.Unix()) / uint64(k.Period)
	next := time.Unix(int64((step+1)*uint64(k.Period)), 0)
	return k.HOTP(step), next.Sub(t)
}

// Wipe zeroes the secret.
func (k *Key) Wipe() { clear(k.Secret) }
