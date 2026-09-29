// Package cbor is the part of CBOR (RFC 8949) that CTAP2 speaks: unsigned
// and negative integers, byte and text strings, arrays, maps, booleans and
// null, all of definite length. It writes CTAP2's canonical form (CTAP 2.1
// §8, "Message Encoding") and reads within fixed bounds.
//
// Values are plain Go values:
//
//	integers      int64 (int, int64 and uint64 are accepted when writing)
//	byte strings  []byte
//	text strings  string (valid UTF-8)
//	arrays        []any
//	maps          Map, keyed by int64 or string
//	true, false   bool
//	null          nil
//
// Reading refuses tags, floating-point numbers, undefined, simple values,
// indefinite lengths, integers beyond int64, map keys that are not
// integers or text, duplicate keys, trailing bytes, and nesting deeper
// than MaxDepth. Every length is checked against what is left of the
// input before anything is allocated, so a hostile message can make no
// allocation larger than itself. UnmarshalCanonical also refuses anything
// that is not in CTAP2 canonical form.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Map is a CBOR map. Keys are int64 or string.
type Map map[any]any

// MaxDepth is how deeply arrays and maps may nest. CTAP2's deepest
// messages (GetInfo's algorithm list) nest three levels.
const MaxDepth = 8

// ErrMalformed is input that is not CBOR, or not the CBOR this package
// reads.
var ErrMalformed = errors.New("cbor: malformed")

// ErrNotCanonical is well-formed input that is not in CTAP2 canonical form.
var ErrNotCanonical = errors.New("cbor: not in canonical form")

// Major types.
const (
	majorUnsigned = 0
	majorNegative = 1
	majorBytes    = 2
	majorText     = 3
	majorArray    = 4
	majorMap      = 5
	majorTag      = 6
	majorSimple   = 7
)

// Marshal encodes v in CTAP2 canonical form: the shortest encoding of
// every integer and length, and map keys sorted by major type, then by
// the length of their encoding, then bytewise.
func Marshal(v any) ([]byte, error) {
	return appendValue(nil, v, 0)
}

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= math.MaxUint8:
		return append(b, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), n)
}

func appendInt(b []byte, n int64) []byte {
	if n >= 0 {
		return appendHead(b, majorUnsigned, uint64(n))
	}
	return appendHead(b, majorNegative, uint64(-(n + 1)))
}

func appendValue(b []byte, v any, depth int) ([]byte, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("cbor: nested more than %d deep", MaxDepth)
	}
	switch v := v.(type) {
	case nil:
		return append(b, majorSimple<<5|22), nil
	case bool:
		if v {
			return append(b, majorSimple<<5|21), nil
		}
		return append(b, majorSimple<<5|20), nil
	case int:
		return appendInt(b, int64(v)), nil
	case int64:
		return appendInt(b, v), nil
	case uint64:
		return appendHead(b, majorUnsigned, v), nil
	case []byte:
		return append(appendHead(b, majorBytes, uint64(len(v))), v...), nil
	case string:
		if !utf8.ValidString(v) {
			return nil, errors.New("cbor: text is not UTF-8")
		}
		return append(appendHead(b, majorText, uint64(len(v))), v...), nil
	case []any:
		b = appendHead(b, majorArray, uint64(len(v)))
		for _, e := range v {
			var err error
			if b, err = appendValue(b, e, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case Map:
		type pair struct{ k, v []byte }
		pairs := make([]pair, 0, len(v))
		for k, e := range v {
			switch k := k.(type) {
			case int:
				pairs = append(pairs, pair{k: appendInt(nil, int64(k))})
			case int64:
				pairs = append(pairs, pair{k: appendInt(nil, k)})
			case string:
				kb, err := appendValue(nil, k, depth+1)
				if err != nil {
					return nil, err
				}
				pairs = append(pairs, pair{k: kb})
			default:
				return nil, fmt.Errorf("cbor: map key of type %T", k)
			}
			vb, err := appendValue(nil, e, depth+1)
			if err != nil {
				return nil, err
			}
			pairs[len(pairs)-1].v = vb
		}
		sort.Slice(pairs, func(i, j int) bool { return keyLess(pairs[i].k, pairs[j].k) })
		for i := 1; i < len(pairs); i++ {
			if bytes.Equal(pairs[i].k, pairs[i-1].k) {
				return nil, errors.New("cbor: a map key appears twice") // int 1 and int64 1
			}
		}
		b = appendHead(b, majorMap, uint64(len(pairs)))
		for _, p := range pairs {
			b = append(append(b, p.k...), p.v...)
		}
		return b, nil
	}
	return nil, fmt.Errorf("cbor: cannot encode %T", v)
}

// keyLess is CTAP2's canonical order of two encoded keys: lower major type
// first, then the shorter encoding, then bytewise.
func keyLess(a, b []byte) bool {
	if ma, mb := a[0]>>5, b[0]>>5; ma != mb {
		return ma < mb
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return bytes.Compare(a, b) < 0
}

// Unmarshal decodes exactly one value that fills all of b.
func Unmarshal(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, fmt.Errorf("%w: %d bytes after the value", ErrMalformed, len(b)-d.off)
	}
	return v, nil
}

// UnmarshalCanonical is Unmarshal that also refuses anything not in CTAP2
// canonical form: longer encodings than needed, and map keys out of order.
func UnmarshalCanonical(b []byte) (any, error) {
	d := decoder{b: b, canonical: true}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, fmt.Errorf("%w: %d bytes after the value", ErrMalformed, len(b)-d.off)
	}
	return v, nil
}

// UnmarshalFirst decodes the value at the start of b and returns what
// follows it (authenticator data carries a public key followed by more).
func UnmarshalFirst(b []byte) (any, []byte, error) {
	d := decoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, nil, err
	}
	return v, b[d.off:], nil
}

// minArg is, by the size of an argument, the smallest value that needs it.
var minArg = [9]uint64{1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}

type decoder struct {
	b         []byte
	off       int
	canonical bool
}

func (d *decoder) left() int { return len(d.b) - d.off }

// head reads an initial byte and its argument.
func (d *decoder) head() (major byte, info byte, arg uint64, err error) {
	if d.left() < 1 {
		return 0, 0, 0, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	ib := d.b[d.off]
	d.off++
	major, info = ib>>5, ib&0x1f
	var n int
	switch {
	case info < 24:
		return major, info, uint64(info), nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	default: // 28-30 are reserved, 31 is an indefinite length
		return 0, 0, 0, fmt.Errorf("%w: additional information %d", ErrMalformed, info)
	}
	if d.left() < n {
		return 0, 0, 0, fmt.Errorf("%w: truncated", ErrMalformed)
	}
	for _, c := range d.b[d.off : d.off+n] {
		arg = arg<<8 | uint64(c)
	}
	d.off += n
	if d.canonical && arg < minArg[n] {
		return 0, 0, 0, fmt.Errorf("%w: a longer encoding than needed", ErrNotCanonical)
	}
	return major, info, arg, nil
}

func (d *decoder) value(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: nested more than %d deep", ErrMalformed, MaxDepth)
	}
	major, info, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case majorUnsigned:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", ErrMalformed)
		}
		return int64(arg), nil
	case majorNegative:
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("%w: integer out of range", ErrMalformed)
		}
		return -1 - int64(arg), nil
	case majorBytes, majorText:
		if arg > uint64(d.left()) {
			return nil, fmt.Errorf("%w: a string runs past the end", ErrMalformed)
		}
		s := d.b[d.off : d.off+int(arg)]
		d.off += int(arg)
		if major == majorText {
			if !utf8.Valid(s) {
				return nil, fmt.Errorf("%w: text is not UTF-8", ErrMalformed)
			}
			return string(s), nil
		}
		return bytes.Clone(s), nil
	case majorArray:
		// Every element takes at least a byte: a count beyond what is left
		// is a lie, refused before anything is allocated.
		if arg > uint64(d.left()) {
			return nil, fmt.Errorf("%w: an array runs past the end", ErrMalformed)
		}
		out := make([]any, 0, arg)
		for range arg {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case majorMap:
		if arg > uint64(d.left()/2) {
			return nil, fmt.Errorf("%w: a map runs past the end", ErrMalformed)
		}
		out := make(Map, arg)
		var prev []byte
		for range arg {
			start := d.off
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("%w: a map key of type %T", ErrMalformed, k)
			}
			if _, dup := out[k]; dup {
				return nil, fmt.Errorf("%w: map key %v appears twice", ErrMalformed, k)
			}
			if d.canonical {
				enc := d.b[start:d.off]
				if prev != nil && !keyLess(prev, enc) {
					return nil, fmt.Errorf("%w: map key %v out of order", ErrNotCanonical, k)
				}
				prev = enc
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case majorTag:
		return nil, fmt.Errorf("%w: tags are not allowed", ErrMalformed)
	default: // majorSimple
		if info >= 24 {
			return nil, fmt.Errorf("%w: floating-point and extended simple values are not allowed", ErrMalformed)
		}
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, fmt.Errorf("%w: simple value %d", ErrMalformed, arg)
	}
}
