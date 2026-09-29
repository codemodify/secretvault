package svpgp

import (
	"encoding/binary"
	"math/big"
	"math/bits"
	"time"
)

// parser reads fields from one packet body. It never reads outside the
// body: a field that would run past the end is an error, and the first
// error sticks, so a sequence of reads can be checked once at the end.
type parser struct {
	b   []byte
	off int
	err error
}

func newParser(b []byte) *parser { return &parser{b: b} }

func (p *parser) fail(format string, args ...any) {
	if p.err == nil {
		p.err = malformed(format, args...)
	}
}

func (p *parser) left() int { return len(p.b) - p.off }

// bytes returns the next n bytes, a slice of the body.
func (p *parser) bytes(n int) []byte {
	if p.err != nil {
		return nil
	}
	if n < 0 || n > p.left() {
		p.fail("truncated field (%d bytes wanted, %d left)", n, p.left())
		return nil
	}
	b := p.b[p.off : p.off+n : p.off+n]
	p.off += n
	return b
}

func (p *parser) u8() byte {
	b := p.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (p *parser) u16() uint16 {
	b := p.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (p *parser) u32() uint32 {
	b := p.bytes(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (p *parser) time() time.Time { return unixTime(p.u32()) }

// rest returns everything not yet read.
func (p *parser) rest() []byte { return p.bytes(p.left()) }

// done fails unless the whole body has been read.
func (p *parser) done() {
	if p.err == nil && p.left() != 0 {
		p.fail("%d unexpected bytes at the end of a packet", p.left())
	}
}

// mpi reads a multiprecision integer and returns its value octets. In a
// version 6 packet the bit count must be exact, counted from the most
// significant set bit (RFC 9580, section 3.2). Older packets are held to
// less: the count may overstate the value's length (GnuPG writes 32-byte
// EdDSA and Curve25519 secrets as 256-bit MPIs whatever their value), but
// never understate it, and the octets must be exactly as many as it says.
func (p *parser) mpi(strict bool) []byte {
	n := p.u16()
	if p.err != nil {
		return nil
	}
	b := p.bytes((int(n) + 7) / 8)
	if p.err != nil {
		return nil
	}
	if got := bitLen(b); got != int(n) && (strict || got > int(n)) {
		p.fail("MPI bit count %d does not match its value (%d bits)", n, got)
		return nil
	}
	return b
}

// bitLen is the length in bits of a big-endian number.
func bitLen(b []byte) int {
	for i, c := range b {
		if c != 0 {
			return (len(b)-i-1)*8 + bits.Len8(c)
		}
	}
	return 0
}

// appendMPI encodes a big-endian number as an MPI, stripping leading zeros.
func appendMPI(dst, b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	n := bitLen(b)
	dst = binary.BigEndian.AppendUint16(dst, uint16(n))
	return append(dst, b...)
}

// appendBigMPI encodes a big.Int as an MPI.
func appendBigMPI(dst []byte, x *big.Int) []byte { return appendMPI(dst, x.Bytes()) }

// fixedOctets pads an octet string read from an MPI back to its fixed size
// (the "EC octet string" wire format, RFC 9580 section 11.3.1).
func fixedOctets(b []byte, size int) ([]byte, bool) {
	if len(b) > size {
		return nil, false
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out, true
}

// prefixedOctets reads the "prefixed native" form: 0x40 followed by exactly
// size octets (RFC 9580, sections 11.2.2 and 11.3.2).
func prefixedOctets(b []byte, size int) ([]byte, bool) {
	if len(b) != size+1 || b[0] != 0x40 {
		return nil, false
	}
	return b[1:], true
}

// unixTime converts an OpenPGP time field.
func unixTime(t uint32) time.Time { return time.Unix(int64(t), 0).UTC() }

// timeField converts a time to an OpenPGP time field, clamping to its range.
func timeField(t time.Time) uint32 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	if s > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return uint32(s)
}

// appendLength appends a body length in the OpenPGP format's 1-, 2- or
// 5-octet form, which subpackets use too.
func appendLength(dst []byte, n int) []byte {
	switch {
	case n < 192:
		return append(dst, byte(n))
	case n < 8384:
		n -= 192
		return append(dst, byte(n>>8)+192, byte(n))
	default:
		dst = append(dst, 255)
		return binary.BigEndian.AppendUint32(dst, uint32(n))
	}
}

// checksum16 is the 2-octet sum used by old secret keys and session keys.
func checksum16(b []byte) uint16 {
	var s uint16
	for _, c := range b {
		s += uint16(c)
	}
	return s
}
