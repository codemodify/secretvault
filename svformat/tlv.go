package svformat

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TLV is the binary encoding for everything that is authenticated as
// associated data. It is canonical: one value has exactly one encoding, so
// the bytes that are MACed are the bytes that were meant.
//
//	field = tag(1) || length(2, big-endian) || value(length)
//
// Fields appear in strictly increasing tag order, each at most once.
// Tags 0x00-0x7F are critical: a reader that does not know one must refuse
// the whole record. Tags 0x80-0xFF are optional and may be skipped.

// Field is one TLV field.
type Field struct {
	Tag   uint8
	Value []byte
}

// ErrTLV is a TLV encoding that is malformed or not canonical.
var ErrTLV = errors.New("svformat: malformed TLV")

// Critical reports whether a reader must understand the tag.
func Critical(tag uint8) bool { return tag < 0x80 }

// EncodeTLV writes fields, which must already be in strictly increasing tag
// order.
func EncodeTLV(fields []Field) ([]byte, error) {
	var out []byte
	for i, f := range fields {
		if i > 0 && f.Tag <= fields[i-1].Tag {
			return nil, fmt.Errorf("%w: tag 0x%02x after 0x%02x", ErrTLV, f.Tag, fields[i-1].Tag)
		}
		if len(f.Value) > 0xFFFF {
			return nil, fmt.Errorf("%w: tag 0x%02x value is %d bytes", ErrTLV, f.Tag, len(f.Value))
		}
		out = append(out, f.Tag)
		out = binary.BigEndian.AppendUint16(out, uint16(len(f.Value)))
		out = append(out, f.Value...)
	}
	return out, nil
}

// DecodeTLV reads fields, refusing anything EncodeTLV would not have
// written. Values alias b.
func DecodeTLV(b []byte) ([]Field, error) {
	var fields []Field
	for len(b) > 0 {
		if len(b) < 3 {
			return nil, fmt.Errorf("%w: truncated field", ErrTLV)
		}
		tag, n := b[0], int(binary.BigEndian.Uint16(b[1:3]))
		if len(b) < 3+n {
			return nil, fmt.Errorf("%w: tag 0x%02x runs past the end", ErrTLV, tag)
		}
		if len(fields) > 0 && tag <= fields[len(fields)-1].Tag {
			return nil, fmt.Errorf("%w: tag 0x%02x out of order", ErrTLV, tag)
		}
		fields = append(fields, Field{Tag: tag, Value: b[3 : 3+n : 3+n]})
		b = b[3+n:]
	}
	return fields, nil
}

// tlvBuilder collects fields in any order and encodes them sorted.
type tlvBuilder struct{ fields []Field }

func (t *tlvBuilder) add(tag uint8, v []byte) { t.fields = append(t.fields, Field{tag, v}) }

func (t *tlvBuilder) u32(tag uint8, v uint32) { t.add(tag, binary.BigEndian.AppendUint32(nil, v)) }

func (t *tlvBuilder) u64(tag uint8, v uint64) { t.add(tag, binary.BigEndian.AppendUint64(nil, v)) }

func (t *tlvBuilder) encode() ([]byte, error) {
	// Insertion sort: a handful of fields.
	f := t.fields
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && f[j].Tag < f[j-1].Tag; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
	return EncodeTLV(f)
}
