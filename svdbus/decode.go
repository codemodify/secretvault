package svdbus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
)

// Unmarshal decodes a message body of signature sig from data, in the given
// byte order, into generic Go values (see the package documentation). fds
// are the descriptors that came with the body; UnixFD values are taken from
// them by index, and each may be referenced once. Unmarshal does not close
// them. data must hold exactly the body, aligned as if it started at the
// beginning of a message.
func Unmarshal(data []byte, order binary.ByteOrder, sig Signature, fds []UnixFD) ([]any, error) {
	types, err := parseSignature(string(sig))
	if err != nil {
		return nil, err
	}
	d := &decoder{buf: data, order: order}
	d.setFDs(fds)
	return d.body(types)
}

// decoder reads D-Bus data from buf. Positions are absolute, from the start
// of the message, since alignment is relative to it.
type decoder struct {
	buf   []byte
	pos   int
	order binary.ByteOrder
	fds   []UnixFD
	used  []bool // which of fds the data has referenced
}

func (d *decoder) setFDs(fds []UnixFD) {
	d.fds = fds
	d.used = make([]bool, len(fds))
}

func (d *decoder) errorf(format string, args ...any) error {
	return invalidf("%s at byte %d", fmt.Sprintf(format, args...), d.pos)
}

// body decodes a whole sequence of values, which must use up buf.
func (d *decoder) body(types []*sigType) ([]any, error) {
	out := make([]any, len(types))
	for i, t := range types {
		v, err := d.value(t, 0)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	if d.pos != len(d.buf) {
		return nil, d.errorf("%d bytes left over after the body", len(d.buf)-d.pos)
	}
	return out, nil
}

// align skips padding to a multiple of n, which must be zero bytes.
func (d *decoder) align(n int) error {
	next := (d.pos + n - 1) &^ (n - 1)
	if next > len(d.buf) {
		return d.errorf("truncated")
	}
	for _, b := range d.buf[d.pos:next] {
		if b != 0 {
			return d.errorf("padding is not zero")
		}
	}
	d.pos = next
	return nil
}

func (d *decoder) need(n int) error {
	if n > len(d.buf)-d.pos {
		return d.errorf("truncated")
	}
	return nil
}

func (d *decoder) u8() (byte, error) {
	if err := d.need(1); err != nil {
		return 0, err
	}
	d.pos++
	return d.buf[d.pos-1], nil
}

func (d *decoder) u16() (uint16, error) {
	if err := d.align(2); err != nil {
		return 0, err
	}
	if err := d.need(2); err != nil {
		return 0, err
	}
	d.pos += 2
	return d.order.Uint16(d.buf[d.pos-2:]), nil
}

func (d *decoder) u32() (uint32, error) {
	if err := d.align(4); err != nil {
		return 0, err
	}
	if err := d.need(4); err != nil {
		return 0, err
	}
	d.pos += 4
	return d.order.Uint32(d.buf[d.pos-4:]), nil
}

func (d *decoder) u64() (uint64, error) {
	if err := d.align(8); err != nil {
		return 0, err
	}
	if err := d.need(8); err != nil {
		return 0, err
	}
	d.pos += 8
	return d.order.Uint64(d.buf[d.pos-8:]), nil
}

// text checks the n bytes at pos and the NUL after them, and returns them.
func (d *decoder) text(n uint64) ([]byte, error) {
	if n >= uint64(len(d.buf)-d.pos) {
		return nil, d.errorf("string runs past the end")
	}
	s := d.buf[d.pos : d.pos+int(n)]
	if d.buf[d.pos+int(n)] != 0 {
		return nil, d.errorf("string is not NUL-terminated")
	}
	if bytes.IndexByte(s, 0) >= 0 {
		return nil, d.errorf("string contains a NUL byte")
	}
	if !utf8.Valid(s) {
		return nil, d.errorf("string is not UTF-8")
	}
	d.pos += int(n) + 1
	return s, nil
}

func (d *decoder) str() (string, error) {
	n, err := d.u32()
	if err != nil {
		return "", err
	}
	s, err := d.text(uint64(n))
	return string(s), err
}

func (d *decoder) sig() (string, error) {
	n, err := d.u8()
	if err != nil {
		return "", err
	}
	s, err := d.text(uint64(n))
	return string(s), err
}

func (d *decoder) fd() (UnixFD, error) {
	i, err := d.u32()
	if err != nil {
		return 0, err
	}
	if uint64(i) >= uint64(len(d.fds)) {
		return 0, d.errorf("descriptor %d, but the message carries %d", i, len(d.fds))
	}
	if d.used[i] {
		// Two values holding one descriptor would be closed twice.
		return 0, d.errorf("descriptor %d is referenced twice", i)
	}
	d.used[i] = true
	return d.fds[i], nil
}

// value decodes one value of type t. depth counts the containers around it.
func (d *decoder) value(t *sigType, depth int) (any, error) {
	switch t.code {
	case 'y':
		return d.u8()
	case 'b':
		v, err := d.u32()
		if err == nil && v > 1 {
			err = d.errorf("boolean is %d", v)
		}
		return v == 1, err
	case 'n':
		v, err := d.u16()
		return int16(v), err
	case 'q':
		return d.u16()
	case 'i':
		v, err := d.u32()
		return int32(v), err
	case 'u':
		return d.u32()
	case 'x':
		v, err := d.u64()
		return int64(v), err
	case 't':
		return d.u64()
	case 'd':
		v, err := d.u64()
		return math.Float64frombits(v), err
	case 's':
		return d.str()
	case 'o':
		s, err := d.str()
		if err == nil {
			err = validateObjectPath(s)
		}
		return ObjectPath(s), err
	case 'g':
		s, err := d.sig()
		if err == nil {
			_, err = parseSignature(s)
		}
		return Signature(s), err
	case 'h':
		return d.fd()
	case 'v':
		if depth+1 > MaxDepth {
			return nil, d.errorf("more than %d nested containers", MaxDepth)
		}
		s, err := d.sig()
		if err != nil {
			return nil, err
		}
		inner, err := parseSingle(s)
		if err != nil {
			return nil, err
		}
		v, err := d.value(inner, depth+1)
		if err != nil {
			return nil, err
		}
		return Variant{Signature: Signature(s), Value: v}, nil
	case '(':
		if depth+1 > MaxDepth {
			return nil, d.errorf("more than %d nested containers", MaxDepth)
		}
		if err := d.align(8); err != nil {
			return nil, err
		}
		out := make([]any, len(t.fields))
		for i, f := range t.fields {
			v, err := d.value(f, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case 'a':
		return d.array(t, depth)
	}
	return nil, d.errorf("unknown type %q", t.text)
}

func (d *decoder) array(t *sigType, depth int) (any, error) {
	if depth+1 > MaxDepth {
		return nil, d.errorf("more than %d nested containers", MaxDepth)
	}
	n, err := d.u32()
	if err != nil {
		return nil, err
	}
	if n > MaxArraySize {
		return nil, d.errorf("array of %d bytes is larger than %d", n, MaxArraySize)
	}
	elem := t.elem
	if err := d.align(alignOf(elem.code)); err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(d.buf)-d.pos) {
		return nil, d.errorf("array runs past the end")
	}
	// Elements are read from a buffer that ends where the array does, so
	// none can run over into what follows.
	end := d.pos + int(n)
	outer := d.buf
	d.buf = d.buf[:end]
	defer func() { d.buf = outer }()

	switch elem.code {
	case 'y':
		b := bytes.Clone(d.buf[d.pos:end])
		if b == nil {
			b = []byte{}
		}
		d.pos = end
		return b, nil
	case '{':
		return d.dict(elem, depth)
	case 'b':
		return arrayOf[bool](d, elem, depth)
	case 'n':
		return arrayOf[int16](d, elem, depth)
	case 'q':
		return arrayOf[uint16](d, elem, depth)
	case 'i':
		return arrayOf[int32](d, elem, depth)
	case 'u':
		return arrayOf[uint32](d, elem, depth)
	case 'x':
		return arrayOf[int64](d, elem, depth)
	case 't':
		return arrayOf[uint64](d, elem, depth)
	case 'd':
		return arrayOf[float64](d, elem, depth)
	case 's':
		return arrayOf[string](d, elem, depth)
	case 'o':
		return arrayOf[ObjectPath](d, elem, depth)
	case 'g':
		return arrayOf[Signature](d, elem, depth)
	case 'h':
		return arrayOf[UnixFD](d, elem, depth)
	case 'v':
		return arrayOf[Variant](d, elem, depth)
	}
	return arrayOf[any](d, elem, depth)
}

// arrayOf decodes the elements of an array up to the end of d.buf, which
// array has set to the array's end.
func arrayOf[T any](d *decoder, elem *sigType, depth int) ([]T, error) {
	out := []T{}
	for d.pos < len(d.buf) {
		v, err := d.value(elem, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v.(T))
	}
	return out, nil
}

func (d *decoder) dict(entry *sigType, depth int) (any, error) {
	if depth+2 > MaxDepth {
		return nil, d.errorf("more than %d nested containers", MaxDepth)
	}
	kt, vt := entry.fields[0], entry.fields[1]
	// The two dicts almost every interface uses, without reflection.
	if kt.code == 's' && vt.code == 'v' {
		return dictOf[string, Variant](d, kt, vt, depth)
	}
	if kt.code == 's' && vt.code == 's' {
		return dictOf[string, string](d, kt, vt, depth)
	}
	m := reflect.MakeMap(reflect.MapOf(basicGoType[kt.code], genericElemType(vt)))
	for d.pos < len(d.buf) {
		k, v, err := d.entry(kt, vt, depth)
		if err != nil {
			return nil, err
		}
		kv := reflect.ValueOf(k)
		if m.MapIndex(kv).IsValid() {
			return nil, d.errorf("dict key %v appears twice", k)
		}
		m.SetMapIndex(kv, reflect.ValueOf(v))
	}
	return m.Interface(), nil
}

func dictOf[K comparable, V any](d *decoder, kt, vt *sigType, depth int) (map[K]V, error) {
	m := map[K]V{}
	for d.pos < len(d.buf) {
		k, v, err := d.entry(kt, vt, depth)
		if err != nil {
			return nil, err
		}
		key := k.(K)
		if _, dup := m[key]; dup {
			return nil, d.errorf("dict key %v appears twice", k)
		}
		m[key] = v.(V)
	}
	return m, nil
}

func (d *decoder) entry(kt, vt *sigType, depth int) (k, v any, err error) {
	if err := d.align(8); err != nil {
		return nil, nil, err
	}
	if k, err = d.value(kt, depth+2); err != nil {
		return nil, nil, err
	}
	if f, ok := k.(float64); ok && math.IsNaN(f) {
		// A NaN key could never be looked up, nor told from another.
		return nil, nil, d.errorf("dict key is NaN")
	}
	if v, err = d.value(vt, depth+2); err != nil {
		return nil, nil, err
	}
	return k, v, nil
}

// basicGoType is the Go type each basic D-Bus type decodes to.
var basicGoType = map[byte]reflect.Type{
	'y': reflect.TypeFor[byte](),
	'b': reflect.TypeFor[bool](),
	'n': reflect.TypeFor[int16](),
	'q': reflect.TypeFor[uint16](),
	'i': reflect.TypeFor[int32](),
	'u': reflect.TypeFor[uint32](),
	'x': reflect.TypeFor[int64](),
	't': reflect.TypeFor[uint64](),
	'd': reflect.TypeFor[float64](),
	's': reflect.TypeFor[string](),
	'o': objectPathType,
	'g': signatureType,
	'h': unixFDType,
}

// genericElemType is the Go type of a dict's values: the basic type, Variant,
// or any. Keeping to this fixed set means a peer cannot make the process
// create new Go types, which reflect would keep forever.
func genericElemType(t *sigType) reflect.Type {
	if g, ok := basicGoType[t.code]; ok {
		return g
	}
	if t.code == 'v' {
		return variantType
	}
	return anyType
}
