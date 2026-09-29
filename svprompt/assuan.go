// Package svprompt is the pinentry protocol (Assuan) in both directions:
// Pinentry drives a pinentry program, Serve makes a program one, with its
// UI supplied by the caller (svterm.TerminalUI on a terminal). secretvaultd
// uses the driving side; it reads no terminal itself.
// docs/architecture.md, "Prompts", says who asks when.
package svprompt

import (
	"errors"
	"fmt"
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
// secretvault-tui-prompt serves it, so it also works as gpg-agent's
// pinentry.

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

// escapeData is escape for D lines, which must also not end in a
// backslash-newline and may carry any byte.
func escapeData(p []byte) string {
	var b strings.Builder
	for _, c := range p {
		switch c {
		case '%', '\r', '\n', '\\':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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

// unescapeBytes is unescape into a byte slice the caller can wipe.
func unescapeBytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(v))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

// label makes a button label safe for pinentry, where '_' marks the
// keyboard mnemonic: a literal underscore is doubled.
func label(s string) string { return strings.ReplaceAll(s, "_", "__") }
