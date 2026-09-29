package svage

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The header, as c2sp.org/age defines it:
//
//	age-encryption.org/v1
//	-> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE
//	qRS0AMjdjPvZ/WT08U2KL4G+PIooA3hy38SvLpvaC1E
//	--- HK2NmOBN9Dpq0Gw6xMCuhFcQlQLvZ/wQUi/2scLG75s
//
// A version line, one or more recipient stanzas, and the MAC line. A
// stanza's arguments are runs of printable ASCII separated by single
// spaces; its body is base64 without padding, 64 columns to the line,
// ending with a shorter (possibly empty) line. Parsing is strict: anything
// the ABNF does not allow, and any non-canonical base64, is refused, so
// that a header has exactly one encoding and the MAC covers it.

// A Stanza is one recipient stanza: a file key wrapped for one recipient.
// Most users never see one; they pass recipients to Encrypt and identities
// to Decrypt.
type Stanza struct {
	Type string
	Args []string
	Body []byte
}

// Limits on what a header may hold, as age v1.3.2 sets them: they bound
// the memory and work a hostile file can demand before its MAC is checked.
const (
	MaxHeaderSize = 2 << 20 // bytes, including the MAC line
	MaxStanzas    = 1024    // recipient stanzas in one header
	MaxStanzaArgs = 128     // arguments after a stanza's type
)

const (
	versionLine   = "age-encryption.org/v1\n"
	versionPrefix = "age-encryption.org/"
	columns       = 64              // base64 characters per body line
	bytesPerLine  = columns / 4 * 3 // 48 bytes of body per full line
	macSize       = 32              // HMAC-SHA-256
	macLineLen    = len("--- ") + 43 + 1
)

// ErrHeader is a header that does not parse, or that holds a stanza an
// identity recognises but finds malformed. Errors wrapping it say which.
var ErrHeader = errors.New("svage: malformed header")

func headerErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrHeader}, args...)...)
}

// b64 is the header's base64: standard alphabet, no padding, and only the
// canonical encoding of each value.
var b64 = base64.RawStdEncoding.Strict()

// decodeB64 decodes canonical unpadded base64. Go's decoder skips CR and
// LF even in strict mode; here they are errors, like any other stray byte.
func decodeB64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !isB64Char(s[i]) {
			return nil, errors.New("invalid base64 character")
		}
	}
	return b64.DecodeString(s)
}

func isB64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// encodeB64 is the canonical encoding decodeB64 accepts.
func encodeB64(b []byte) string { return b64.EncodeToString(b) }

// validArg reports whether s is a stanza argument: one or more VCHARs.
func validArg(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// lineReader reads LF-terminated lines, refusing to hand out more than
// budget bytes in total. It keeps everything it read, for the MAC.
type lineReader struct {
	r      *bufio.Reader
	budget int
	raw    []byte
	keep   bool
}

var errBudget = errors.New("too long")

// line returns the next line with its LF. A read error is returned as
// is; running out of input before the LF is io.ErrUnexpectedEOF (or
// io.EOF when nothing at all was left).
func (lr *lineReader) line() ([]byte, error) {
	var line []byte
	for {
		frag, err := lr.r.ReadSlice('\n')
		if len(frag) > lr.budget-len(line) {
			return nil, errBudget
		}
		line = append(line, frag...)
		switch {
		case err == nil:
			lr.budget -= len(line)
			if lr.keep {
				lr.raw = append(lr.raw, line...)
			}
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, io.ErrUnexpectedEOF
		default:
			return nil, err
		}
	}
}

// readStanza reads one stanza: its argument line and its body. It serves
// both the header and the plugin protocol, which frames its messages the
// same way; maxArgs is how many arguments may follow the type.
func readStanza(lr *lineReader, maxArgs int) (*Stanza, error) {
	line, err := lr.line()
	if err != nil {
		return nil, err
	}
	rest, ok := bytes.CutPrefix(line, []byte("-> "))
	if !ok {
		return nil, fmt.Errorf("a stanza starts with %q", shorten(line))
	}
	rest = rest[:len(rest)-1]
	if bytes.Count(rest, []byte(" ")) > maxArgs {
		return nil, fmt.Errorf("a stanza has more than %d arguments", maxArgs)
	}
	args := strings.Split(string(rest), " ")
	for _, a := range args {
		if !validArg(a) {
			return nil, fmt.Errorf("a stanza has an invalid argument line %q", shorten(line))
		}
	}
	s := &Stanza{Type: args[0], Args: args[1:]}
	for {
		line, err := lr.line()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		text := string(line[:len(line)-1])
		if len(text) > columns {
			return nil, errors.New("a stanza body line is longer than 64 columns")
		}
		b, err := decodeB64(text)
		if err != nil {
			if strings.HasPrefix(text, "-") {
				return nil, errors.New("a stanza ends without a short body line")
			}
			return nil, fmt.Errorf("a stanza body line is not canonical base64: %v", err)
		}
		s.Body = append(s.Body, b...)
		if len(text) < columns {
			return s, nil
		}
	}
}

// shorten quotes at most a little of a bad line, so errors neither flood
// a terminal nor repeat much of what might be key material.
func shorten(line []byte) string {
	if len(line) > 24 {
		return string(line[:24]) + "..."
	}
	return string(line)
}

// marshal writes the stanza in its canonical form.
func (s *Stanza) marshal(w *bytes.Buffer) error {
	if !validArg(s.Type) {
		return fmt.Errorf("svage: invalid stanza type %q", s.Type)
	}
	if len(s.Args) > MaxStanzaArgs {
		return fmt.Errorf("svage: a stanza has more than %d arguments", MaxStanzaArgs)
	}
	for _, a := range s.Args {
		if !validArg(a) {
			return fmt.Errorf("svage: invalid stanza argument %q", a)
		}
	}
	w.WriteString("-> ")
	w.WriteString(s.Type)
	for _, a := range s.Args {
		w.WriteByte(' ')
		w.WriteString(a)
	}
	w.WriteByte('\n')
	body := encodeB64(s.Body)
	for len(body) >= columns {
		w.WriteString(body[:columns])
		w.WriteByte('\n')
		body = body[columns:]
	}
	w.WriteString(body) // the short final line, possibly empty
	w.WriteByte('\n')
	return nil
}

// header is a parsed header.
type header struct {
	stanzas []*Stanza
	mac     []byte
	macked  []byte // what the MAC covers: everything up to and including "---"
	size    int64  // the whole header, MAC line included
}

// parseHeader reads a header from br, leaving br at the payload.
func parseHeader(br *bufio.Reader) (*header, error) {
	lr := &lineReader{r: br, budget: MaxHeaderSize, keep: true}
	fail := func(err error) (*header, error) {
		var ae *ArmorError
		switch {
		case errors.As(err, &ae):
			return nil, err
		case errors.Is(err, errBudget):
			return nil, headerErrorf("the header is larger than %d bytes", MaxHeaderSize)
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return nil, headerErrorf("the file ends inside the header")
		case errors.Is(err, ErrHeader):
			return nil, err
		}
		return nil, fmt.Errorf("svage: reading the header: %w", err)
	}

	line, err := lr.line()
	switch {
	case errors.Is(err, io.EOF):
		return nil, headerErrorf("the file is empty")
	case err != nil && !errors.Is(err, io.ErrUnexpectedEOF):
		return fail(err)
	case string(line) == versionLine:
	case bytes.HasPrefix(line, []byte(versionPrefix)):
		return nil, headerErrorf("unsupported age format version %q", shorten(bytes.TrimSpace(line)))
	default:
		return nil, headerErrorf("not an age file")
	}

	h := &header{}
	for {
		peek, err := br.Peek(3)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return fail(err)
		}
		if string(peek) == "---" {
			break
		}
		if len(h.stanzas) == MaxStanzas {
			return nil, headerErrorf("more than %d recipient stanzas", MaxStanzas)
		}
		s, err := readStanza(lr, MaxStanzaArgs)
		if err != nil {
			var ae *ArmorError
			if errors.As(err, &ae) || errors.Is(err, errBudget) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fail(err)
			}
			return nil, headerErrorf("%v", err)
		}
		h.stanzas = append(h.stanzas, s)
	}
	if len(h.stanzas) == 0 {
		return nil, headerErrorf("no recipient stanzas")
	}

	start := len(lr.raw)
	line, err = lr.line()
	if err != nil {
		return fail(err)
	}
	if len(line) != macLineLen || !bytes.HasPrefix(line, []byte("--- ")) {
		return nil, headerErrorf("malformed MAC line")
	}
	h.mac, err = decodeB64(string(line[4 : len(line)-1]))
	if err != nil || len(h.mac) != macSize {
		return nil, headerErrorf("malformed MAC line")
	}
	h.macked = lr.raw[:start+3]
	h.size = int64(len(lr.raw))
	return h, nil
}

// marshalHeader writes a header for stanzas, with the MAC that macKey
// makes of it.
func marshalHeader(stanzas []*Stanza, mac func([]byte) []byte) ([]byte, error) {
	if len(stanzas) == 0 {
		return nil, errors.New("svage: no recipient stanzas")
	}
	if len(stanzas) > MaxStanzas {
		return nil, fmt.Errorf("svage: more than %d recipient stanzas", MaxStanzas)
	}
	var b bytes.Buffer
	b.WriteString(versionLine)
	for _, s := range stanzas {
		if err := s.marshal(&b); err != nil {
			return nil, err
		}
	}
	b.WriteString("---")
	sum := mac(b.Bytes())
	b.WriteByte(' ')
	b.WriteString(encodeB64(sum))
	b.WriteByte('\n')
	if b.Len() > MaxHeaderSize {
		return nil, fmt.Errorf("svage: the header would be larger than %d bytes", MaxHeaderSize)
	}
	return b.Bytes(), nil
}
