package svage

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// ASCII armor: the whole age file as strict PEM (RFC 7468, section 3),
// with the label "AGE ENCRYPTED FILE" and standard padded base64 at 64
// columns. Armor is malleable unless read strictly, so the reader accepts
// only the canonical encoding, with two allowances age makes: CRLF line
// endings, and whitespace before and after the block.
//
//	-----BEGIN AGE ENCRYPTED FILE-----
//	YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBTVUkxUktwREZLR0tYaEk2
//	...
//	-----END AGE ENCRYPTED FILE-----

const (
	armorBegin = "-----BEGIN AGE ENCRYPTED FILE-----"
	armorEnd   = "-----END AGE ENCRYPTED FILE-----"

	// maxArmorSpace bounds the whitespace allowed around the block.
	maxArmorSpace = 1024
)

// ArmorError is armor that is not canonical.
type ArmorError struct{ err error }

func (e *ArmorError) Error() string { return "svage: invalid armor: " + e.err.Error() }
func (e *ArmorError) Unwrap() error { return e.err }

// IsArmored reports whether b, the start of a file, looks like armor:
// optional whitespace, then the BEGIN line.
func IsArmored(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(b, " \t\r\n"), []byte(armorBegin))
}

// NewArmorWriter returns a writer that armors what is written to it into
// w. Close writes the END line; it does not close w.
func NewArmorWriter(w io.Writer) io.WriteCloser {
	return &armorWriter{w: w}
}

type armorWriter struct {
	w       io.Writer
	pending []byte // bytes not yet making up a full line
	started bool
	closed  bool
	err     error
}

func (a *armorWriter) begin() error {
	if !a.started {
		a.started = true
		if _, err := io.WriteString(a.w, armorBegin+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func (a *armorWriter) Write(p []byte) (int, error) {
	if a.closed {
		return 0, errors.New("svage: write to a closed armor writer")
	}
	if a.err != nil {
		return 0, a.err
	}
	if a.err = a.begin(); a.err != nil {
		return 0, a.err
	}
	a.pending = append(a.pending, p...)
	var out []byte
	for len(a.pending) >= bytesPerLine {
		out = base64.StdEncoding.AppendEncode(out, a.pending[:bytesPerLine])
		out = append(out, '\n')
		a.pending = a.pending[bytesPerLine:]
	}
	a.pending = append([]byte(nil), a.pending...)
	if len(out) > 0 {
		if _, a.err = a.w.Write(out); a.err != nil {
			return 0, a.err
		}
	}
	return len(p), nil
}

func (a *armorWriter) Close() error {
	if a.closed {
		return errors.New("svage: armor writer closed twice")
	}
	a.closed = true
	if a.err != nil {
		return a.err
	}
	if err := a.begin(); err != nil {
		return err
	}
	var out []byte
	if len(a.pending) > 0 {
		out = base64.StdEncoding.AppendEncode(out, a.pending)
		out = append(out, '\n')
	}
	out = append(out, armorEnd+"\n"...)
	_, err := a.w.Write(out)
	return err
}

// NewArmorReader returns a reader of the file armored in r. Every
// deviation from the canonical encoding is an *ArmorError.
func NewArmorReader(r io.Reader) io.Reader {
	return &armorReader{r: bufio.NewReader(r)}
}

type armorReader struct {
	r       *bufio.Reader
	started bool
	out     []byte
	buf     [bytesPerLine]byte
	err     error
}

func (a *armorReader) fail(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// Not the sentinel itself: an armor error must not pass for a
		// short read of what is inside.
		err = errors.New("the armor ends without its END line")
	}
	if err != io.EOF {
		err = &ArmorError{err}
	}
	a.err = err
	return err
}

// line reads one line without its LF (or CRLF).
func (a *armorReader) line() ([]byte, error) {
	line, err := a.r.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return nil, errors.New("line too long")
	case errors.Is(err, io.EOF) && len(line) == 0:
		return nil, io.ErrUnexpectedEOF
	case err != nil && !errors.Is(err, io.EOF):
		return nil, err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	return bytes.TrimSuffix(line, []byte("\r")), nil
}

// trailer checks that only a little whitespace follows the END line.
func (a *armorReader) trailer() error {
	rest, err := io.ReadAll(io.LimitReader(a.r, maxArmorSpace))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("data after the END line")
	}
	if len(rest) == maxArmorSpace {
		return errors.New("too much whitespace after the END line")
	}
	return io.EOF
}

func (a *armorReader) Read(p []byte) (int, error) {
	if len(a.out) > 0 {
		n := copy(p, a.out)
		a.out = a.out[n:]
		return n, nil
	}
	if a.err != nil {
		return 0, a.err
	}
	space := 0
	for !a.started {
		line, err := a.line()
		if err != nil {
			return 0, a.fail(err)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			if space += len(line) + 1; space > maxArmorSpace {
				return 0, a.fail(errors.New("too much whitespace before the BEGIN line"))
			}
			continue
		}
		if string(line) != armorBegin {
			return 0, a.fail(fmt.Errorf("the first line is not %q", armorBegin))
		}
		a.started = true
	}
	line, err := a.line()
	if err != nil {
		return 0, a.fail(err)
	}
	if string(line) == armorEnd {
		return 0, a.fail(a.trailer())
	}
	switch {
	case len(line) == 0:
		return 0, a.fail(errors.New("an empty line"))
	case len(line) > columns:
		return 0, a.fail(errors.New("a line longer than 64 columns"))
	case bytes.ContainsAny(line, "\r\n"):
		return 0, a.fail(errors.New("a stray carriage return"))
	}
	n, err := base64.StdEncoding.Strict().Decode(a.buf[:], line)
	if err != nil {
		return 0, a.fail(fmt.Errorf("a line that is not canonical base64: %v", err))
	}
	a.out = a.buf[:n]
	if n < bytesPerLine {
		// A short line is the last one.
		end, err := a.line()
		if err != nil {
			return 0, a.fail(err)
		}
		if string(end) != armorEnd {
			return 0, a.fail(errors.New("a short line before the end"))
		}
		a.fail(a.trailer())
	}
	c := copy(p, a.out)
	a.out = a.out[c:]
	return c, nil
}
