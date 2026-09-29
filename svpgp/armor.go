package svpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// ASCII armor (RFC 9580, section 6).

// Armor block types.
const (
	BlockMessage       = "PGP MESSAGE"
	BlockPublicKey     = "PGP PUBLIC KEY BLOCK"
	BlockPrivateKey    = "PGP PRIVATE KEY BLOCK"
	BlockSignature     = "PGP SIGNATURE"
	BlockSignedMessage = "PGP SIGNED MESSAGE" // the cleartext signature framework
)

const (
	maxArmorLine     = 64 << 10 // longer lines are refused
	maxArmorPreamble = 1 << 20  // text skipped before the BEGIN line
)

// crc24 is the armor checksum (RFC 9580, section 6.1).
func crc24(crc uint32, data []byte) uint32 {
	for _, b := range data {
		crc ^= uint32(b) << 16
		for range 8 {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}

const crc24Init = 0xB704CE

// ArmorBlock is a decoded armor block.
type ArmorBlock struct {
	Type    string              // "PGP MESSAGE", "PGP PUBLIC KEY BLOCK", ...
	Headers map[string][]string // the armor headers, which nothing signs
	// Body is the binary data. It is streamed: a bad checksum or a
	// missing END line is reported as an error at the end of Body.
	Body io.Reader
}

// Dearmor decodes the first armor block in r, skipping any text before
// its BEGIN line. The CRC24 checksum is checked when present, and the
// block is refused if it does not match (as GnuPG does; RFC 9580 lets a
// reader ignore it). A cleartext signed message is not armor; use
// VerifyInline for those.
func Dearmor(r io.Reader) (*ArmorBlock, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	typ, err := findArmor(br)
	if err != nil {
		return nil, err
	}
	if typ == BlockSignedMessage {
		return nil, malformed("a cleartext signed message is not an armor block")
	}
	return armorBody(br, typ)
}

// readArmorLine reads one line, without its line ending, refusing lines
// longer than maxArmorLine.
func readArmorLine(br *bufio.Reader) (string, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > maxArmorLine {
			return "", limit("an armor line over %d bytes", maxArmorLine)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			return "", err
		}
		break
	}
	return strings.TrimRight(string(buf), "\r\n"), nil
}

// findArmor reads up to and including the next BEGIN line and returns the
// block type it names.
func findArmor(br *bufio.Reader) (string, error) {
	skipped := 0
	for {
		line, err := readArmorLine(br)
		if err == io.EOF {
			return "", malformed("no OpenPGP armor found")
		}
		if err != nil {
			return "", err
		}
		skipped += len(line) + 1
		if skipped > maxArmorPreamble {
			return "", limit("more than %d bytes before the armor", maxArmorPreamble)
		}
		if typ, ok := armorLine(line, "BEGIN"); ok {
			if strings.Contains(typ, ", PART ") {
				return "", unsupported("multi-part armor")
			}
			return typ, nil
		}
	}
}

// armorLine parses "-----BEGIN X-----" or "-----END X-----", with nothing
// but whitespace after it.
func armorLine(line, word string) (string, bool) {
	line = strings.TrimRight(line, " \t")
	prefix := "-----" + word + " "
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "-----") || len(line) < len(prefix)+5 {
		return "", false
	}
	typ := line[len(prefix) : len(line)-5]
	if !strings.HasPrefix(typ, "PGP ") {
		return "", false
	}
	return typ, true
}

// armorBody reads the headers after a BEGIN line and returns the block,
// whose body is decoded as it is read.
func armorBody(br *bufio.Reader, typ string) (*ArmorBlock, error) {
	headers := map[string][]string{}
	for {
		line, err := readArmorLine(br)
		if err != nil {
			return nil, truncatedArmor(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return nil, malformed("armor header line %q", line)
		}
		headers[key] = append(headers[key], value)
	}
	return &ArmorBlock{Type: typ, Headers: headers, Body: &armorDecoder{br: br, typ: typ, crc: crc24Init}}, nil
}

func truncatedArmor(err error) error {
	if err == io.EOF {
		return malformed("armor ends without its END line")
	}
	return err
}

// armorDecoder decodes an armor body line by line.
type armorDecoder struct {
	br      *bufio.Reader
	typ     string
	pending []byte // base64 characters not yet decoded (fewer than 4)
	out     []byte // decoded bytes not yet returned
	crc     uint32
	padded  bool // a padded group was seen: only the checksum or END may follow
	err     error
}

func (d *armorDecoder) Read(p []byte) (int, error) {
	for len(d.out) == 0 && d.err == nil {
		d.err = d.line()
	}
	if len(d.out) > 0 {
		n := copy(p, d.out)
		d.out = d.out[n:]
		return n, nil
	}
	return 0, d.err
}

// line reads and decodes one more line of the body.
func (d *armorDecoder) line() error {
	line, err := d.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return limit("an armor line over %d bytes", d.br.Size())
	}
	if err != nil && (err != io.EOF || len(line) == 0) {
		return truncatedArmor(err)
	}
	text := strings.TrimSpace(string(line))
	if typ, ok := armorLine(text, "END"); ok {
		return d.finish(typ, false, 0)
	}
	if strings.HasPrefix(text, "=") && len(text) == 5 {
		sum, err := base64.StdEncoding.DecodeString(text[1:])
		if err != nil || len(sum) != 3 {
			return malformed("armor checksum line %q", text)
		}
		end, err := readArmorLine(d.br)
		if err != nil {
			return truncatedArmor(err)
		}
		typ, ok := armorLine(strings.TrimSpace(end), "END")
		if !ok {
			return malformed("armor checksum not followed by the END line")
		}
		return d.finish(typ, true, uint32(sum[0])<<16|uint32(sum[1])<<8|uint32(sum[2]))
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == ' ' || c == '\t':
			continue
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
			if d.padded {
				return malformed("armor data after padding")
			}
			d.pending = append(d.pending, c)
		default:
			return malformed("character %q in armor data", c)
		}
		if len(d.pending) == 4 {
			var group [3]byte
			n, err := base64.StdEncoding.Decode(group[:], d.pending)
			if err != nil {
				return malformed("armor base64 data")
			}
			if n < 3 {
				d.padded = true
			}
			d.out = append(d.out, group[:n]...)
			d.crc = crc24(d.crc, group[:n])
			d.pending = d.pending[:0]
		}
	}
	return nil
}

func (d *armorDecoder) finish(typ string, haveSum bool, sum uint32) error {
	if typ != d.typ {
		return malformed("armor END line for %q after BEGIN %q", typ, d.typ)
	}
	if len(d.pending) != 0 {
		return malformed("armor base64 data is cut short")
	}
	if haveSum && sum != d.crc {
		return malformed("armor checksum mismatch")
	}
	return io.EOF
}

// ArmorWriter returns a writer that armors what is written to it as a block
// of the given type. Close writes the END line; it does not close w. With
// checksum set, the CRC24 line is written too, which RFC 9580 reserves for
// readers that need it (it forbids it for version 6 data).
func ArmorWriter(w io.Writer, blockType string, checksum bool) (io.WriteCloser, error) {
	if _, err := io.WriteString(w, "-----BEGIN "+blockType+"-----\n\n"); err != nil {
		return nil, err
	}
	return &armorEncoder{w: w, typ: blockType, buf: make([]byte, 0, 48), crc: crc24Init, withCRC: checksum}, nil
}

type armorEncoder struct {
	w       io.Writer
	typ     string
	buf     []byte // up to one line of input (48 bytes)
	crc     uint32
	withCRC bool
	closed  bool
}

func (e *armorEncoder) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("svpgp: write after close")
	}
	e.crc = crc24(e.crc, p)
	n := len(p)
	for len(p) > 0 {
		k := copy(e.buf[len(e.buf):cap(e.buf)], p)
		e.buf = e.buf[:len(e.buf)+k]
		p = p[k:]
		if len(e.buf) == 48 {
			if err := e.flushLine(); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

func (e *armorEncoder) flushLine() error {
	line := make([]byte, base64.StdEncoding.EncodedLen(len(e.buf))+1)
	base64.StdEncoding.Encode(line, e.buf)
	line[len(line)-1] = '\n'
	e.buf = e.buf[:0]
	_, err := e.w.Write(line)
	return err
}

func (e *armorEncoder) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	if len(e.buf) > 0 {
		if err := e.flushLine(); err != nil {
			return err
		}
	}
	var tail bytes.Buffer
	if e.withCRC {
		sum := []byte{byte(e.crc >> 16), byte(e.crc >> 8), byte(e.crc)}
		tail.WriteString("=" + base64.StdEncoding.EncodeToString(sum) + "\n")
	}
	tail.WriteString("-----END " + e.typ + "-----\n")
	_, err := e.w.Write(tail.Bytes())
	return err
}

// armorBytes armors data in one go.
func armorBytes(blockType string, data []byte, checksum bool) []byte {
	var out bytes.Buffer
	w, _ := ArmorWriter(&out, blockType, checksum)
	w.Write(data)
	w.Close()
	return out.Bytes()
}

// openInput looks at the start of r: binary OpenPGP packets, or armor. For
// armor it consumes the BEGIN line and returns the block type, with the
// reader positioned after it.
func openInput(r io.Reader) (*bufio.Reader, string, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		b, err := br.Peek(1)
		if err == io.EOF {
			return nil, "", malformed("empty input")
		}
		if err != nil {
			return nil, "", err
		}
		if b[0]&0x80 != 0 {
			return br, "", nil
		}
		if b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n' {
			br.ReadByte()
			continue
		}
		break
	}
	typ, err := findArmor(br)
	if err != nil {
		return nil, "", err
	}
	return br, typ, nil
}
