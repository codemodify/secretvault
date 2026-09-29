package svluks

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"unicode/utf8"
)

// The binary header (specification section 2.1): one 4096-byte sector at
// the start of each copy of the header, big-endian, followed by the JSON
// area. The primary copy is at offset 0 and the secondary right after it.

const (
	binSize     = 4096
	magicLen    = 6
	labelLen    = 48
	csumAlgLen  = 32
	saltLen     = 64
	uuidLen     = 40
	csumLen     = 64
	offMagic    = 0
	offVersion  = 6
	offHdrSize  = 8
	offSeqid    = 16
	offLabel    = 24
	offCsumAlg  = 72
	offSalt     = 104
	offUUID     = 168
	offSubsys   = 208
	offHdrOff   = 256
	offCsum     = 448
	defHdrSize  = 16 << 10
	sectorBytes = 512
)

var (
	magicPrimary   = []byte("LUKS\xba\xbe")
	magicSecondary = []byte("SKUL\xba\xbe")
)

// hdrSizes are the sizes a header copy (binary header and JSON area) may
// have, and so the offsets at which the secondary copy may start (Table 1).
var hdrSizes = []uint64{16 << 10, 32 << 10, 64 << 10, 128 << 10, 256 << 10, 512 << 10, 1 << 20, 2 << 20, 4 << 20}

// Errors. Every error this package returns about an image wraps one of
// these.
var (
	// ErrNotLUKS is data with no LUKS header at all.
	ErrNotLUKS = errors.New("svluks: not a LUKS image")

	// ErrHeader is a LUKS2 header that is damaged, or that breaks the
	// specification or the bounds this package keeps.
	ErrHeader = errors.New("svluks: bad LUKS2 header")

	// ErrUnsupported is a sound header that asks for something this
	// package does not do (LUKS1, another cipher, integrity protection,
	// a re-encryption in progress, ...).
	ErrUnsupported = errors.New("svluks: not supported")

	// ErrWrongKey is a passphrase or key that no keyslot accepts.
	ErrWrongKey = errors.New("svluks: no keyslot opens with that key")
)

func headerErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrHeader}, args...)...)
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsupported}, args...)...)
}

// binHeader is one copy's binary header, decoded.
type binHeader struct {
	hdrSize   uint64
	seqid     uint64
	label     string
	csumAlg   string
	salt      [saltLen]byte
	uuid      string
	subsystem string
	hdrOffset uint64
}

// checksums are the header checksum algorithms accepted. cryptsetup
// writes sha256.
var checksums = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
	"sha1":   sha1.New,
}

// cString reads a NUL-terminated string from a fixed field. A field with
// no NUL is not a C string, which the specification forbids.
func cString(field []byte, name string) (string, error) {
	i := bytes.IndexByte(field, 0)
	if i < 0 {
		return "", headerErr("the %s field is not terminated", name)
	}
	s := field[:i]
	if !utf8.Valid(s) {
		return "", headerErr("the %s field is not text", name)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", headerErr("the %s field holds control characters", name)
		}
	}
	return string(s), nil
}

func putString(dst []byte, s string) { copy(dst[:len(dst)-1], s) }

// readCopy reads the header copy at off: its binary header, checked, and
// the JSON text of its area. It reads at most 4 MiB, and only as much as
// the header's (bounded) size says.
func readCopy(r io.ReaderAt, off uint64, magic []byte) (*binHeader, []byte, error) {
	bin := make([]byte, binSize)
	if _, err := r.ReadAt(bin, int64(off)); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, fmt.Errorf("%w: too short", ErrNotLUKS)
		}
		return nil, nil, err
	}
	if !bytes.Equal(bin[offMagic:offMagic+magicLen], magic) {
		return nil, nil, ErrNotLUKS
	}
	b := &binHeader{
		hdrSize:   binary.BigEndian.Uint64(bin[offHdrSize:]),
		seqid:     binary.BigEndian.Uint64(bin[offSeqid:]),
		hdrOffset: binary.BigEndian.Uint64(bin[offHdrOff:]),
	}
	switch v := binary.BigEndian.Uint16(bin[offVersion:]); v {
	case 2:
	case 1:
		return nil, nil, unsupported("this is a LUKS1 image; convert it with 'cryptsetup convert --type luks2'")
	default:
		return nil, nil, unsupported("LUKS version %d", v)
	}
	if !slices.Contains(hdrSizes, b.hdrSize) {
		return nil, nil, headerErr("header size %d is not one the specification allows", b.hdrSize)
	}
	if b.hdrOffset != off {
		return nil, nil, headerErr("the header at %d says it belongs at %d", off, b.hdrOffset)
	}
	var err error
	if b.label, err = cString(bin[offLabel:offLabel+labelLen], "label"); err != nil {
		return nil, nil, err
	}
	if b.csumAlg, err = cString(bin[offCsumAlg:offCsumAlg+csumAlgLen], "checksum algorithm"); err != nil {
		return nil, nil, err
	}
	if b.uuid, err = cString(bin[offUUID:offUUID+uuidLen], "UUID"); err != nil {
		return nil, nil, err
	}
	if b.subsystem, err = cString(bin[offSubsys:offSubsys+labelLen], "subsystem"); err != nil {
		return nil, nil, err
	}
	copy(b.salt[:], bin[offSalt:])
	newHash, ok := checksums[b.csumAlg]
	if !ok {
		return nil, nil, unsupported("header checksum %q", b.csumAlg)
	}

	area := make([]byte, b.hdrSize-binSize)
	if _, err := r.ReadAt(area, int64(off)+binSize); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, headerErr("the image ends inside the header")
		}
		return nil, nil, err
	}
	want := append([]byte(nil), bin[offCsum:offCsum+csumLen]...)
	clear(bin[offCsum : offCsum+csumLen])
	h := newHash()
	h.Write(bin)
	h.Write(area)
	sum := h.Sum(nil)
	if !bytes.Equal(want[:len(sum)], sum) || !allZero(want[len(sum):]) {
		return nil, nil, headerErr("the checksum of the header at %d does not match", off)
	}
	end := bytes.IndexByte(area, 0)
	if end < 0 {
		return nil, nil, headerErr("the JSON area is not terminated")
	}
	return b, area[:end], nil
}

// encodeCopy builds one header copy: the binary header with its checksum,
// then the JSON text padded with zeros to the header size.
func encodeCopy(b *binHeader, magic, json []byte) ([]byte, error) {
	if uint64(len(json))+1 > b.hdrSize-binSize {
		return nil, fmt.Errorf("svluks: the metadata (%d bytes) does not fit the %d-byte JSON area", len(json), b.hdrSize-binSize)
	}
	out := make([]byte, b.hdrSize)
	copy(out[offMagic:], magic)
	binary.BigEndian.PutUint16(out[offVersion:], 2)
	binary.BigEndian.PutUint64(out[offHdrSize:], b.hdrSize)
	binary.BigEndian.PutUint64(out[offSeqid:], b.seqid)
	putString(out[offLabel:offLabel+labelLen], b.label)
	putString(out[offCsumAlg:offCsumAlg+csumAlgLen], b.csumAlg)
	copy(out[offSalt:offSalt+saltLen], b.salt[:])
	putString(out[offUUID:offUUID+uuidLen], b.uuid)
	putString(out[offSubsys:offSubsys+labelLen], b.subsystem)
	binary.BigEndian.PutUint64(out[offHdrOff:], b.hdrOffset)
	copy(out[binSize:], json)
	h := checksums[b.csumAlg]()
	h.Write(out)
	copy(out[offCsum:], h.Sum(nil))
	return out, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
