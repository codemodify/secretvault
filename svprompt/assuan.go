// Package svprompt is the pinentry protocol (Assuan) in both directions:
// Pinentry drives a pinentry program, Serve makes a program one, with its
// UI supplied by the caller (svterm.TerminalUI on a terminal, windows in
// secretvault-gui-prompt). secretvaultd uses the driving side; it reads
// no terminal itself.
// docs/architecture.md, "Prompts", says who asks when.
package svprompt

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The pinentry protocol is Assuan (https://www.gnupg.org/documentation/
// manuals/assuan/): line-based, each line at most 1000 bytes, commands
// answered by OK or ERR, data sent on D lines, status on S lines, comments
// on # lines. Arguments and data escape '%', CR and LF as %25, %0D, %0A.
//
// secretvault speaks it both ways: secretvaultd drives any pinentry
// program (its own prompts, or the system's pinentry-gnome3/-qt/-gtk), and
// secretvault-tui-prompt and secretvault-gui-prompt serve it, so they also
// work as gpg-agent's pinentry.

// maxLine is Assuan's line limit, without the newline.
const maxLine = 1000

// Error codes pinentry returns, as the low 16 bits of the ERR code (the
// high bits name the error source).
const (
	errTimeout      = 62
	errCanceled     = 99
	errNotConfirmed = 114
	errUnknownCmd   = 275
	errNotSupported = 60
)

// AssuanError is an ERR line.
type AssuanError struct {
	Code    int
	Message string
}

func (e *AssuanError) Error() string {
	return fmt.Sprintf("pinentry: %s (%d)", e.Message, e.Code)
}

// ErrCanceled is the person dismissing a prompt.
var ErrCanceled = errors.New("svprompt: canceled")

// ErrTimeout is a prompt nobody answered in time.
var ErrTimeout = errors.New("svprompt: the prompt timed out")

// kind classifies an ERR code.
func (e *AssuanError) kind() int { return e.Code & 0xffff }

func parseErr(line string) *AssuanError {
	rest := strings.TrimPrefix(line, "ERR")
	rest = strings.TrimSpace(rest)
	code, msg, _ := strings.Cut(rest, " ")
	n, _ := strconv.Atoi(code)
	return &AssuanError{Code: n, Message: unescape(msg)}
}

// escape percent-encodes an argument or data for an Assuan line.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%', '\r', '\n':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// hexDigits spell a byte in an escape.
const hexDigits = "0123456789ABCDEF"

// appendData appends p to dst percent-escaped for a D line, which must
// also not end in a backslash-newline and may carry any byte. It works on
// bytes, never a string, because what it escapes is usually a secret.
func appendData(dst, p []byte) []byte {
	for _, c := range p {
		switch c {
		case '%', '\r', '\n', '\\':
			dst = append(dst, '%', hexDigits[c>>4], hexDigits[c&15])
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// writeData sends p on w as D lines, as many as Assuan's line limit
// needs, never splitting an escape. The lines are built in one array that
// is wiped once they are written, and nothing on the way is a string, so
// a secret sent this way leaves no copy of itself behind.
func writeData(w io.Writer, p []byte) error {
	// One byte of room past the limit for the newline, so the array is
	// never outgrown: an outgrown array would be dropped unwiped.
	line := make([]byte, 0, maxLine+1)
	defer func() { clear(line[:cap(line)]) }()
	var one [1]byte
	var esc [3]byte
	defer func() { clear(one[:]); clear(esc[:]) }()
	line = append(line, 'D', ' ')
	for _, c := range p {
		one[0] = c
		e := appendData(esc[:0], one[:])
		if len(line)+len(e) > maxLine {
			line = append(line, '\n')
			if _, err := w.Write(line); err != nil {
				return err
			}
			clear(line)
			line = append(line[:0], 'D', ' ')
		}
		line = append(line, e...)
	}
	if len(line) == 2 {
		return nil
	}
	line = append(line, '\n')
	_, err := w.Write(line)
	return err
}

// unescape decodes %XX sequences; malformed ones are kept as they are.
func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// appendUnescaped decodes the %XX sequences of src onto dst, keeping
// malformed ones as they are. dst is a secret being gathered from D
// lines, so when it has to grow, the array it outgrew is wiped before it
// is dropped. The caller wipes the result.
func appendUnescaped(dst, src []byte) []byte {
	if need := len(dst) + len(src); need > cap(dst) {
		grown := make([]byte, len(dst), max(need, 2*cap(dst), 64))
		copy(grown, dst)
		clear(dst[:cap(dst)])
		dst = grown
	}
	for i := 0; i < len(src); i++ {
		if src[i] == '%' && i+2 < len(src) {
			hi, ok1 := unhex(src[i+1])
			lo, ok2 := unhex(src[i+2])
			if ok1 && ok2 {
				dst = append(dst, hi<<4|lo)
				i += 2
				continue
			}
		}
		dst = append(dst, src[i])
	}
	return dst
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// label makes a button label safe for pinentry, where '_' marks the
// keyboard mnemonic: a literal underscore is doubled.
func label(s string) string { return strings.ReplaceAll(s, "_", "__") }

// plainLabel undoes label for display: a lone '_' marks the mnemonic
// ("_OK", as gpg-agent sends it) and goes, and "__" is a literal
// underscore. secretvault's prompts show no mnemonics.
func plainLabel(s string) string {
	if !strings.Contains(s, "_") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			if i+1 < len(s) && s[i+1] == '_' {
				b.WriteByte('_')
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
