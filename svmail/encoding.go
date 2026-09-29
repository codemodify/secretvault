package svmail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"strings"
	"unicode/utf8"
)

// Transfer encodings (RFC 2045, section 6), charsets for text that is
// shown, and encoded words in header fields (RFC 2047).

// Decoded returns the part's body with its Content-Transfer-Encoding
// undone: base64, quoted-printable, or 7bit, 8bit and binary (which are
// the body as it is). An unknown encoding is an error, with the body
// returned as it is.
func (p *Part) Decoded() ([]byte, error) {
	cte := strings.ToLower(strings.TrimSpace(p.Header.Get("Content-Transfer-Encoding")))
	switch cte {
	case "", "7bit", "8bit", "binary":
		return p.Body, nil
	case "base64":
		return decodeBase64(p.Body)
	case "quoted-printable":
		return decodeQP(p.Body), nil
	}
	return p.Body, fmt.Errorf("svmail: unknown Content-Transfer-Encoding %q", cte)
}

// decodeBase64 decodes base64 with any white space in it, as mail
// carries it, padded or not.
func decodeBase64(b []byte) ([]byte, error) {
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			clean = append(clean, c)
		}
	}
	out := make([]byte, len(clean)*3/4+3)
	n, err := base64.StdEncoding.Decode(out, clean)
	if err != nil {
		trimmed := bytes.TrimRight(clean, "=")
		n, err = base64.RawStdEncoding.Decode(out, trimmed)
		if err != nil {
			return nil, fmt.Errorf("svmail: bad base64: %w", err)
		}
	}
	return out[:n], nil
}

// decodeQP decodes quoted-printable leniently, as mail clients do: "=XX"
// is a byte, "=" at the end of a line joins it to the next, white space
// before a line break is dropped, and anything else is kept as it is.
func decodeQP(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		line, next, eol := nextLine(b, i)
		i = next
		// Trailing white space was added in transport (RFC 2045, section
		// 6.7, rule 3).
		line = bytes.TrimRight(line, " \t")
		soft := false
		if len(line) > 0 && line[len(line)-1] == '=' {
			soft = true
			line = line[:len(line)-1]
		}
		for j := 0; j < len(line); j++ {
			c := line[j]
			if c == '=' && j+2 < len(line) && isHex(line[j+1]) && isHex(line[j+2]) {
				out = append(out, unhex(line[j+1])<<4|unhex(line[j+2]))
				j += 2
				continue
			}
			out = append(out, c)
		}
		if !soft && eol > 0 {
			out = append(out, "\r\n"[2-eol:]...)
		}
	}
	return out
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}

// win1252 maps the bytes 0x80 to 0x9F of Windows-1252 to Unicode; the
// rest are the same as ISO-8859-1. Undefined bytes map to U+FFFD.
var win1252 = [32]rune{
	0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD,
	0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178,
}

func decodeWindows1252(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch {
		case c < 0x80:
			sb.WriteByte(c)
		case c < 0xa0:
			sb.WriteRune(win1252[c-0x80])
		default:
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

// charsetKind names the charsets this package decodes; "" means one it
// does not.
func charsetKind(name string) string {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(name), `"`)) {
	case "", "utf-8", "utf8":
		return "utf-8"
	case "us-ascii", "ascii", "ansi_x3.4-1968", "iso646-us", "us":
		return "us-ascii"
	// ISO-8859-1 is read as Windows-1252, as browsers and mail clients
	// do (WHATWG): the two differ only where ISO-8859-1 has control
	// characters nobody means.
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "l1", "iso_8859-1", "cp819", "ibm819",
		"windows-1252", "cp1252", "x-cp1252":
		return "windows-1252"
	}
	return ""
}

// decodeText turns text in a charset into a string. ok is false for a
// charset this package does not decode; problem says what was wrong with
// text it did decode (bytes invalid in the charset, replaced with U+FFFD).
func decodeText(charset string, b []byte) (text string, ok bool, problem string) {
	switch charsetKind(charset) {
	case "utf-8", "us-ascii":
		if utf8.Valid(b) {
			return string(b), true, ""
		}
		if charsetKind(charset) == "us-ascii" {
			// Unlabelled 8-bit text: most likely Windows-1252 from an
			// old client. Say so rather than guess silently.
			return decodeWindows1252(b), true, "text labelled US-ASCII has 8-bit bytes; read as Windows-1252"
		}
		return strings.ToValidUTF8(string(b), "�"), true, "text labelled UTF-8 is not valid UTF-8"
	case "windows-1252":
		return decodeWindows1252(b), true, ""
	}
	return "", false, fmt.Sprintf("the charset %q is not supported; the text is not shown", charset)
}

var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		if charsetKind(charset) == "windows-1252" {
			b, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}
			return strings.NewReader(decodeWindows1252(b)), nil
		}
		return nil, fmt.Errorf("svmail: charset %q in an encoded word is not supported", charset)
	},
}

// DecodeHeader decodes the encoded words (RFC 2047) in a header value,
// for showing it. A value it cannot decode comes back as it is.
func DecodeHeader(v string) string {
	d, err := wordDecoder.DecodeHeader(v)
	if err != nil {
		return v
	}
	if !utf8.ValidString(d) {
		return decodeWindows1252([]byte(d))
	}
	return d
}

// normalizeNewlines turns CR LF into LF, for text that is shown.
func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}
