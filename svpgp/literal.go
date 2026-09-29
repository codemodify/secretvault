package svpgp

import (
	"bytes"
	"io"
	"time"
)

// Literal data packets (RFC 9580, section 5.9), and the canonical text form
// that text signatures hash.

// literalHeader encodes the fields before the data: the format, the file
// name and the date. None of them is covered by signatures.
func literalHeader(format byte, name string, date time.Time) []byte {
	if len(name) > 255 {
		name = name[:255]
	}
	h := []byte{format, byte(len(name))}
	h = append(h, name...)
	var t uint32
	if !date.IsZero() {
		t = timeField(date)
	}
	return appendU32(h, t)
}

// readLiteralHeader reads the fields before the data.
func readLiteralHeader(r io.Reader) (format byte, name string, date time.Time, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", time.Time{}, truncated(err)
	}
	switch hdr[0] {
	case 'b', 't', 'u', 'm', 'l', '1':
	default:
		return 0, "", time.Time{}, malformed("literal data format 0x%02x", hdr[0])
	}
	nameAndDate := make([]byte, int(hdr[1])+4)
	if _, err := io.ReadFull(r, nameAndDate); err != nil {
		return 0, "", time.Time{}, truncated(err)
	}
	name = string(nameAndDate[:hdr[1]])
	d := nameAndDate[hdr[1]:]
	if t := uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3]); t != 0 {
		date = unixTime(t)
	}
	return hdr[0], name, date, nil
}

// canonicalWriter converts line endings to CR LF as it writes, for text
// signatures (RFC 9580, section 5.2.1.2): a LF not preceded by CR becomes
// CR LF; CR LF and lone CRs pass through.
type canonicalWriter struct {
	w      io.Writer
	lastCR bool
}

func (c *canonicalWriter) Write(p []byte) (int, error) {
	start := 0
	for i, b := range p {
		if b == '\n' && !c.lastCR {
			if _, err := c.w.Write(p[start:i]); err != nil {
				return 0, err
			}
			if _, err := c.w.Write([]byte{'\r', '\n'}); err != nil {
				return 0, err
			}
			start = i + 1
		}
		c.lastCR = b == '\r'
	}
	if _, err := c.w.Write(p[start:]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// cleartextLines splits text for the cleartext signature framework (RFC
// 9580, section 7): lines end at LF, with an optional CR before it, and
// lose their trailing spaces and tabs. A final line ending is kept, as an
// empty last line, so what is signed and verified is the whole text; the
// line ending that the framework puts before the signature is not part of
// it.
func cleartextLines(text []byte) [][]byte {
	lines := bytes.Split(text, []byte("\n"))
	for i, l := range lines {
		l = bytes.TrimSuffix(l, []byte("\r"))
		lines[i] = bytes.TrimRight(l, " \t")
	}
	return lines
}
