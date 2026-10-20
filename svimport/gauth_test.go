package svimport

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

// A migration payload as Google Authenticator's QR code carries it, decoded
// by hand:
//
//	0a 31                      otp_parameters, 49 bytes
//	   0a 0a 48656c6c6f21deadbeef   secret "Hello!\xde\xad\xbe\xef" (JBSWY3DPEHPK3PXP)
//	   12 18 "Example:alice@google.com"
//	   1a 07 "Example"
//	   30 02                   type TOTP
const gaExample = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC"

// protoBytes and protoVarint write protobuf by hand for the tests.
func protoBytes(field int, b []byte) []byte {
	return append(append(protoKey(field, 2), protoUvarint(uint64(len(b)))...), b...)
}

func protoVarint(field int, v uint64) []byte { return append(protoKey(field, 0), protoUvarint(v)...) }

func protoKey(field, wire int) []byte { return protoUvarint(uint64(field<<3 | wire)) }

func protoUvarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func migrationURI(params ...[]byte) string {
	var payload []byte
	for _, p := range params {
		payload = append(payload, protoBytes(1, p)...)
	}
	payload = append(payload, protoVarint(2, 1)...) // version
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(payload))
}

func TestGoogleAuthenticatorExportsImport(t *testing.T) {
	hotp := append(append(append(append(append(append(
		protoBytes(1, []byte("12345678901234567890")),
		protoBytes(2, []byte("ada@example.org"))...),
		protoBytes(3, []byte("Bank"))...),
		protoVarint(4, 3)...), // SHA512
		protoVarint(5, 2)...), // eight digits
		protoVarint(6, 1)...), // HOTP
		protoVarint(7, 42)...)
	md5 := append(protoBytes(1, []byte("secret")), append(protoBytes(2, []byte("old")), protoVarint(4, 4)...)...)
	unknown := append(protoBytes(1, []byte("abcdefghij")), append(protoBytes(2, []byte("Future:x")), protoVarint(99, 5)...)...)
	input := gaExample + "\n\n# a second QR code of the batch\n" + migrationURI(hotp, md5, unknown) + "\n"

	res := mustImport(t, FormatGoogleAuthenticator, []byte(input), Options{})
	ex := item(t, res, "Example (alice@google.com)")
	if ex.Kind != "otp" {
		t.Errorf("kind %q", ex.Kind)
	}
	has(t, ex, "otp", svcore.FieldOTP, "otpauth://totp/Example:alice@google.com?issuer=Example&secret=JBSWY3DPEHPK3PXP")
	has(t, item(t, res, "Bank (ada@example.org)"), "otp", svcore.FieldOTP,
		"otpauth://hotp/Bank:ada@example.org?algorithm=SHA512&counter=42&digits=8&issuer=Bank&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	has(t, item(t, res, "Future (x)"), "otp", svcore.FieldOTP, "otpauth://totp/Future:x?issuer=Future&secret=MFRGGZDFMZTWQ2LK")
	warned(t, res, "old", "MD5")
	if len(res.Items) != 3 {
		t.Errorf("%d items", len(res.Items))
	}

	// A '+' left unescaped by whoever copied the URI is still base64's '+'.
	plus := migrationURI(append(protoBytes(1, []byte{0xef, 0xbe, 0xfb}), protoBytes(2, []byte("p"))...))
	unescaped, _ := url.QueryUnescape(plus)
	if !strings.Contains(unescaped, "+") {
		t.Fatalf("the test URI has no '+': %s", unescaped)
	}
	res = mustImport(t, FormatGoogleAuthenticator, []byte(unescaped), Options{})
	has(t, item(t, res, "p"), "otp", svcore.FieldOTP, "otpauth://totp/p?secret=567PW")
}

func TestMalformedMigrationPayloadsAreRefused(t *testing.T) {
	for name, in := range map[string]string{
		"not a migration URI":   "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
		"no data":               "otpauth-migration://offline?",
		"not base64":            "otpauth-migration://offline?data=%%%",
		"truncated protobuf":    "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString([]byte{0x0a, 0x31, 0x0a}),
		"a group wire type":     "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString([]byte{0x0b}),
		"a varint that runs on": "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString([]byte{0x10, 0xff, 0xff}),
		"nothing":               "\n# only a comment\n",
	} {
		if _, err := Import(FormatGoogleAuthenticator, []byte(in), Options{}); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
