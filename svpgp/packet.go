package svpgp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// packetType is an OpenPGP packet type ID (RFC 9580, section 5).
type packetType uint8

const (
	ptPKESK          packetType = 1
	ptSignature      packetType = 2
	ptSKESK          packetType = 3
	ptOnePass        packetType = 4
	ptSecretKey      packetType = 5
	ptPublicKey      packetType = 6
	ptSecretSubkey   packetType = 7
	ptCompressed     packetType = 8
	ptSED            packetType = 9
	ptMarker         packetType = 10
	ptLiteral        packetType = 11
	ptTrust          packetType = 12
	ptUserID         packetType = 13
	ptPublicSubkey   packetType = 14
	ptUserAttribute  packetType = 17
	ptSEIPD          packetType = 18
	ptPadding        packetType = 21
	firstNonCritical packetType = 40
)

// critical reports whether a packet of this type that is not understood
// must fail the whole sequence (RFC 9580, section 4.3).
func (t packetType) critical() bool { return t < firstNonCritical }

// streamed reports whether the packet type may use partial or indeterminate
// lengths, and so is read as a stream rather than all at once.
func (t packetType) streamed() bool {
	return t == ptLiteral || t == ptCompressed || t == ptSED || t == ptSEIPD
}

func (t packetType) String() string {
	switch t {
	case ptPKESK:
		return "PKESK"
	case ptSignature:
		return "signature"
	case ptSKESK:
		return "SKESK"
	case ptOnePass:
		return "one-pass signature"
	case ptSecretKey:
		return "secret key"
	case ptPublicKey:
		return "public key"
	case ptSecretSubkey:
		return "secret subkey"
	case ptCompressed:
		return "compressed data"
	case ptSED:
		return "symmetrically encrypted data"
	case ptMarker:
		return "marker"
	case ptLiteral:
		return "literal data"
	case ptTrust:
		return "trust"
	case ptUserID:
		return "user ID"
	case ptPublicSubkey:
		return "public subkey"
	case ptUserAttribute:
		return "user attribute"
	case ptSEIPD:
		return "SEIPD"
	case 19:
		return "MDC"
	case 20:
		return "AEAD encrypted data (LibrePGP)"
	case ptPadding:
		return "padding"
	}
	return "packet type " + itoa(int(t))
}

// maxPacketSize bounds every packet that is read whole: keys, signatures,
// user IDs and attributes, session key packets. Streamed packets (literal,
// compressed and encrypted data) are bounded by the message limits instead.
const maxPacketSize = 8 << 20

// packetReader reads a sequence of packets from a stream. Each call to next
// finishes (skips the rest of) the previous packet first.
type packetReader struct {
	r   *bufio.Reader
	cur *bodyReader
}

func newPacketReader(r io.Reader) *packetReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64<<10)
	}
	return &packetReader{r: br}
}

// next reads the next packet header. It returns io.EOF at a clean end of
// the stream, between packets.
func (pr *packetReader) next() (packetType, *bodyReader, error) {
	if pr.cur != nil {
		if _, err := io.Copy(io.Discard, pr.cur); err != nil {
			return 0, nil, err
		}
		pr.cur = nil
	}
	b0, err := pr.r.ReadByte()
	if err == io.EOF {
		return 0, nil, io.EOF
	}
	if err != nil {
		return 0, nil, err
	}
	if b0&0x80 == 0 {
		return 0, nil, malformed("not an OpenPGP packet (first octet 0x%02x)", b0)
	}
	body := &bodyReader{r: pr.r}
	var tag packetType
	if b0&0x40 != 0 {
		tag = packetType(b0 & 0x3F)
		n, partial, err := readNewLength(pr.r, true)
		if err != nil {
			return 0, nil, err
		}
		body.remaining, body.partial = n, partial
	} else {
		tag = packetType(b0>>2) & 0x0F
		body.legacy = true
		switch b0 & 3 {
		case 0, 1, 2:
			size := 1 << (b0 & 3)
			var buf [4]byte
			if _, err := io.ReadFull(pr.r, buf[:size]); err != nil {
				return 0, nil, truncated(err)
			}
			var n uint32
			for _, c := range buf[:size] {
				n = n<<8 | uint32(c)
			}
			body.remaining = int64(n)
		case 3:
			body.indeterminate = true
		}
	}
	if tag == 0 {
		return 0, nil, malformed("packet type 0 is reserved")
	}
	if (body.partial || body.indeterminate) && !tag.streamed() {
		return 0, nil, malformed("a %v packet may not have a partial or indeterminate length", tag)
	}
	pr.cur = body
	return tag, body, nil
}

// readNewLength reads an OpenPGP-format body length. Partial lengths are
// accepted only where allowed.
func readNewLength(r io.ByteReader, allowPartial bool) (n int64, partial bool, err error) {
	l0, err := r.ReadByte()
	if err != nil {
		return 0, false, truncated(err)
	}
	switch {
	case l0 < 192:
		return int64(l0), false, nil
	case l0 < 224:
		l1, err := r.ReadByte()
		if err != nil {
			return 0, false, truncated(err)
		}
		return int64(l0-192)<<8 + int64(l1) + 192, false, nil
	case l0 == 255:
		var n uint32
		for range 4 {
			c, err := r.ReadByte()
			if err != nil {
				return 0, false, truncated(err)
			}
			n = n<<8 | uint32(c)
		}
		return int64(n), false, nil
	default:
		if !allowPartial {
			return 0, false, malformed("unexpected partial body length")
		}
		return int64(1) << (l0 & 0x1F), true, nil
	}
}

func truncated(err error) error {
	if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
		return malformed("truncated packet")
	}
	return err
}

// bodyReader reads one packet body, following partial body lengths. It
// never reads beyond the body, and reports a body cut short by the end of
// the stream as malformed.
type bodyReader struct {
	r             *bufio.Reader
	remaining     int64 // left in the current chunk
	partial       bool  // another length header follows the current chunk
	indeterminate bool  // legacy format: the body runs to the end of the stream
	legacy        bool
	n             int64 // bytes read so far
	err           error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.indeterminate {
		n, err := b.r.Read(p)
		b.n += int64(n)
		if err != nil {
			b.err = err
		}
		return n, err
	}
	for b.remaining == 0 && b.partial {
		n, partial, err := readNewLength(b.r, true)
		if err != nil {
			b.err = err
			return 0, err
		}
		b.remaining, b.partial = n, partial
	}
	if b.remaining == 0 {
		b.err = io.EOF
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	b.n += int64(n)
	if err == io.EOF {
		if b.remaining > 0 || b.partial {
			err = malformed("truncated packet")
		} else {
			err = nil
		}
	}
	if err != nil {
		b.err = err
	}
	return n, err
}

// readAll reads a whole body that must be at most max bytes.
func (b *bodyReader) readAll(max int) ([]byte, error) {
	if !b.partial && !b.indeterminate {
		if b.remaining > int64(max) {
			return nil, limit("a %d-byte packet (the limit is %d)", b.remaining, max)
		}
		buf := make([]byte, b.remaining)
		if _, err := io.ReadFull(b, buf); err != nil {
			return nil, truncated(err)
		}
		return buf, nil
	}
	buf, err := io.ReadAll(io.LimitReader(b, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > max {
		return nil, limit("a packet over %d bytes", max)
	}
	return buf, nil
}

// appendHeader appends an OpenPGP-format packet header for a body of n
// bytes.
func appendHeader(dst []byte, tag packetType, n int) []byte {
	return appendLength(append(dst, 0xC0|byte(tag)), n)
}

// writePacket writes a whole packet.
func writePacket(w io.Writer, tag packetType, body []byte) error {
	hdr := appendHeader(make([]byte, 0, 6), tag, len(body))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// partialChunk is the size of the chunks a partialWriter writes: a power
// of two, and at least the 512 bytes the first partial length must have.
const partialChunk = 1 << 16

// partialWriter streams a packet body of unknown length with partial body
// lengths. Close writes the final length header; it does not close the
// underlying writer.
type partialWriter struct {
	w   io.Writer
	buf []byte
	err error
}

func newPartialWriter(w io.Writer, tag packetType) (*partialWriter, error) {
	if _, err := w.Write([]byte{0xC0 | byte(tag)}); err != nil {
		return nil, err
	}
	return &partialWriter{w: w, buf: make([]byte, 0, partialChunk)}, nil
}

func (pw *partialWriter) Write(p []byte) (int, error) {
	if pw.err != nil {
		return 0, pw.err
	}
	written := 0
	for len(p) > 0 {
		if len(pw.buf) == partialChunk {
			// Only flush a full chunk once more data is known to follow,
			// so the final length header is never a partial one.
			if _, err := pw.w.Write([]byte{0xE0 | 16}); err != nil {
				pw.err = err
				return written, err
			}
			if _, err := pw.w.Write(pw.buf); err != nil {
				pw.err = err
				return written, err
			}
			pw.buf = pw.buf[:0]
		}
		n := copy(pw.buf[len(pw.buf):partialChunk], p)
		pw.buf = pw.buf[:len(pw.buf)+n]
		p = p[n:]
		written += n
	}
	return written, nil
}

func (pw *partialWriter) Close() error {
	if pw.err != nil {
		return pw.err
	}
	hdr := appendLength(nil, len(pw.buf))
	if _, err := pw.w.Write(hdr); err != nil {
		pw.err = err
		return err
	}
	_, err := pw.w.Write(pw.buf)
	clear(pw.buf)
	pw.err = errors.New("svpgp: write after close")
	return err
}

// packetBytes encodes a whole packet.
func packetBytes(tag packetType, body []byte) []byte {
	return append(appendHeader(make([]byte, 0, len(body)+6), tag, len(body)), body...)
}

func appendU32(dst []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(dst, v) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
