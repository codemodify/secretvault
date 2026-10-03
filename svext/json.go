package svext

import (
	"encoding/json"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// Messages carry passwords, so a password is written into a message and
// read out of one here, in buffers the caller wipes, and never becomes a
// Go string (which could not be wiped). What encoding/json handles (names,
// URLs, IDs) is not secret. As everywhere in Go, this is hygiene, not a
// guarantee: see docs/security.md.

// appendSecret writes v as a JSON string. Bytes that are not UTF-8 become
// U+FFFD, as encoding/json does. The caller has made room (appending may
// still grow b, leaving a copy behind, when v needs much escaping).
func appendSecret(b, v []byte) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(v); {
		c := v[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b = append(b, '\\', c)
			case c < 0x20:
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			default:
				b = append(b, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, `�`...)
		} else {
			b = append(b, v[i:i+size]...)
		}
		i += size
	}
	return append(b, '"')
}

var errNotString = errors.New("svext: not a JSON string")

// decodeSecret reads a JSON string into bytes the caller wipes, without
// making a Go string of it.
func decodeSecret(raw json.RawMessage) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errNotString
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c == '"' || c < 0x20 {
			clear(out)
			return nil, errNotString
		}
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i == len(in) {
			clear(out)
			return nil, errNotString
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, n := hex4(in[i+1:])
			if n == 0 {
				clear(out)
				return nil, errNotString
			}
			i += n
			if utf16.IsSurrogate(r) {
				// A pair: 😀.
				if i+2 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
					if r2, n2 := hex4(in[i+3:]); n2 > 0 {
						if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
							r = dec
							i += 2 + n2
						}
					}
				}
				if utf16.IsSurrogate(r) {
					r = utf8.RuneError
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			clear(out)
			return nil, errNotString
		}
	}
	return out, nil
}

// hex4 reads the four hex digits of a \u escape: the rune and 4, or 0.
func hex4(b []byte) (rune, int) {
	if len(b) < 4 {
		return 0, 0
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, 0
		}
	}
	return r, 4
}
