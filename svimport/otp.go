package svimport

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/codemodify/secretvault/svotp"
)

// otpURI turns an OTP key, as password managers store one, into an
// otpauth:// URI:
//   - an otpauth URI, re-written in svotp's normal form;
//   - Bitwarden's steam://SECRET;
//   - KeeOTP's key=SECRET&size=6&step=30&otpHashMode=Sha256, which
//     KeePassXC also reads;
//   - a bare base32 secret: TOTP, SHA-1, 6 digits, 30 seconds, labelled
//     with the issuer and account given.
func otpURI(value, issuer, account string) (string, error) {
	s := strings.TrimSpace(value)
	lower := strings.ToLower(s)
	var k *svotp.Key
	var err error
	switch {
	case strings.HasPrefix(lower, "otpauth://"):
		if k, err = svotp.Parse(s); err != nil {
			return "", err
		}
	case strings.HasPrefix(lower, "steam://"):
		k = &svotp.Key{Type: "totp", Issuer: "Steam", Account: account, Algorithm: "SHA1", Digits: 5, Period: 30, Steam: true}
		if k.Secret, err = svotp.DecodeSecret(s[len("steam://"):]); err != nil {
			return "", err
		}
	case strings.Contains(s, "key="):
		if k, err = keeOTP(s, issuer, account); err != nil {
			return "", err
		}
	default:
		k = &svotp.Key{Type: "totp", Issuer: issuer, Account: account, Algorithm: "SHA1", Digits: 6, Period: 30}
		if k.Secret, err = svotp.DecodeSecret(s); err != nil {
			return "", err
		}
	}
	defer k.Wipe()
	return checkedURI(k)
}

// checkedURI writes a key as a URI and reads it back, so only keys svotp
// can use are stored.
func checkedURI(k *svotp.Key) (string, error) {
	uri := k.URI()
	back, err := svotp.Parse(uri)
	if err != nil {
		return "", err
	}
	back.Wipe()
	return uri, nil
}

// keeOTP reads the KeeOTP plugin's query-string form.
func keeOTP(s, issuer, account string) (*svotp.Key, error) {
	q, err := url.ParseQuery(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not a KeeOTP string", svotp.ErrKey)
	}
	k := &svotp.Key{Type: "totp", Issuer: issuer, Account: account, Algorithm: "SHA1", Digits: 6, Period: 30}
	if k.Secret, err = svotp.DecodeSecret(q.Get("key")); err != nil {
		return nil, err
	}
	if v := q.Get("size"); v != "" {
		k.Digits, _ = strconv.Atoi(v)
	}
	if v := q.Get("step"); v != "" {
		k.Period, _ = strconv.Atoi(v)
	}
	if v := q.Get("otpHashMode"); v != "" {
		k.Algorithm = hashName(v)
	}
	if strings.EqualFold(q.Get("type"), "hotp") {
		k.Type = "hotp"
		k.Counter, _ = strconv.ParseUint(q.Get("counter"), 10, 64)
	}
	return k, nil
}

// hashName normalises the ways formats name OTP hash algorithms:
// "sha1", "SHA-256", "HMAC-SHA-512", "Sha256".
func hashName(s string) string {
	s = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "HMAC-"))
	return strings.ReplaceAll(s, "-", "")
}

// otpKeyURI builds a URI from a raw secret and parameters, as the
// authenticator formats (Aegis, Google Authenticator, CXF) hold them.
func otpKeyURI(k *svotp.Key) (string, error) {
	if k.Algorithm == "" {
		k.Algorithm = "SHA1"
	}
	if k.Digits == 0 {
		k.Digits = 6
	}
	if k.Period == 0 {
		k.Period = 30
	}
	return checkedURI(k)
}

// otpTitle is how authenticator entries are titled: "Issuer (account)".
func otpTitle(issuer, account string) string {
	issuer, account = strings.TrimSpace(issuer), strings.TrimSpace(account)
	switch {
	case issuer == "":
		return account
	case account == "" || strings.EqualFold(issuer, account):
		return issuer
	}
	return issuer + " (" + account + ")"
}
