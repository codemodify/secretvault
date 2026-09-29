package svimport

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svotp"
)

// Google Authenticator's "Transfer accounts" QR codes, as their text:
// otpauth-migration://offline?data=BASE64, one per code, where data is a
// protobuf MigrationPayload:
//
//	message MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
//	message OtpParameters {
//	  bytes secret = 1; string name = 2; string issuer = 3;
//	  Algorithm algorithm = 4;  // 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//	  DigitCount digits = 5;    // 1 six, 2 eight
//	  OtpType type = 6;         // 1 HOTP, 2 TOTP
//	  int64 counter = 7;
//	}
//
// The input is one URI or several, one per line (a batch of QR codes).
// Every key becomes an "otp" item.

func readGoogleAuthenticator(b *builder, data []byte) error {
	n := 0
	for _, line := range strings.Split(string(bytes.TrimPrefix(data, utf8BOM)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		payload, err := migrationData(line)
		if err != nil {
			return err
		}
		err = gaPayload(b, payload)
		clear(payload)
		if err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("%w: no otpauth-migration:// URI", ErrFormat)
	}
	return nil
}

// migrationData extracts and decodes the data parameter. The base64 in it
// is URL-escaped; a '+' left unescaped is kept as '+', not read as a space.
func migrationData(uri string) ([]byte, error) {
	u, err := url.Parse(uri)
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth-migration") {
		return nil, fmt.Errorf("%w: not an otpauth-migration:// URI", ErrFormat)
	}
	var raw string
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if k, v, _ := strings.Cut(kv, "="); k == "data" {
			raw = v
		}
	}
	s, err := url.PathUnescape(raw)
	if err != nil || s == "" {
		return nil, fmt.Errorf("%w: the migration URI has no data", ErrFormat)
	}
	s = strings.NewReplacer(" ", "+", "-", "+", "_", "/", "=", "").Replace(s)
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: the migration data is not base64", ErrFormat)
	}
	return b, nil
}

func gaPayload(b *builder, payload []byte) error {
	return protoFields(payload, func(num int, _ int, v uint64, bs []byte) error {
		if num != 1 || bs == nil {
			return nil
		}
		return gaParameters(b, bs)
	})
}

func gaParameters(b *builder, msg []byte) error {
	k := &svotp.Key{Type: "totp", Algorithm: "SHA1", Digits: 6, Period: 30}
	defer k.Wipe()
	algo := uint64(1)
	name := ""
	err := protoFields(msg, func(num, wire int, v uint64, bs []byte) error {
		switch num {
		case 1:
			k.Secret = append([]byte(nil), bs...)
		case 2:
			name = string(bs)
		case 3:
			k.Issuer = string(bs)
		case 4:
			algo = v
		case 5:
			if v == 2 {
				k.Digits = 8
			}
		case 6:
			if v == 1 {
				k.Type = "hotp"
			}
		case 7:
			k.Counter = v
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The name is "Issuer:account" or just the account.
	if iss, acct, ok := strings.Cut(name, ":"); ok && (k.Issuer == "" || strings.EqualFold(strings.TrimSpace(iss), k.Issuer)) {
		if k.Issuer == "" {
			k.Issuer = strings.TrimSpace(iss)
		}
		name = acct
	}
	k.Account = strings.TrimSpace(name)
	title := otpTitle(k.Issuer, k.Account)
	switch algo {
	case 0, 1:
	case 2:
		k.Algorithm = "SHA256"
	case 3:
		k.Algorithm = "SHA512"
	default:
		b.warn("%s: not imported: its key uses MD5, which secretvault refuses", title)
		return nil
	}
	uri, err := otpKeyURI(k)
	if err != nil {
		b.warn("%s: not imported: its key could not be read", title)
		return nil
	}
	d := &draft{kind: kOTP, title: title}
	d.set(fOTP, svcore.FieldOTP, uri)
	b.add(d)
	return nil
}

// errProto is protobuf that does not parse.
var errProto = errors.New("malformed protobuf")

// protoFields walks a protobuf message's fields, calling f with each
// field's number, wire type, and value: v for varint and fixed-size
// fields, bs for length-delimited ones. It knows the wire format only
// (https://protobuf.dev/programming-guides/encoding/), which is all a
// decoder of known messages needs.
func protoFields(msg []byte, f func(num, wire int, v uint64, bs []byte) error) error {
	for len(msg) > 0 {
		key, n := binary.Uvarint(msg)
		if n <= 0 {
			return fmt.Errorf("%w: %v", ErrFormat, errProto)
		}
		msg = msg[n:]
		num, wire := int(key>>3), int(key&7)
		if num == 0 {
			return fmt.Errorf("%w: %v: field 0", ErrFormat, errProto)
		}
		var v uint64
		var bs []byte
		switch wire {
		case 0:
			if v, n = binary.Uvarint(msg); n <= 0 {
				return fmt.Errorf("%w: %v", ErrFormat, errProto)
			}
			msg = msg[n:]
		case 1:
			if len(msg) < 8 {
				return fmt.Errorf("%w: %v", ErrFormat, errProto)
			}
			v, msg = binary.LittleEndian.Uint64(msg), msg[8:]
		case 2:
			l, n := binary.Uvarint(msg)
			if n <= 0 || l > uint64(len(msg)-n) {
				return fmt.Errorf("%w: %v", ErrFormat, errProto)
			}
			bs, msg = msg[n:n+int(l)], msg[n+int(l):]
			if bs == nil {
				bs = []byte{}
			}
		case 5:
			if len(msg) < 4 {
				return fmt.Errorf("%w: %v", ErrFormat, errProto)
			}
			v, msg = uint64(binary.LittleEndian.Uint32(msg)), msg[4:]
		default: // 3 and 4, groups, are long deprecated and unused here
			return fmt.Errorf("%w: %v: wire type %d", ErrFormat, errProto, wire)
		}
		if err := f(num, wire, v, bs); err != nil {
			return err
		}
	}
	return nil
}
