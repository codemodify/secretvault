package svdbus

import (
	"cmp"
	"encoding/binary"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

// Marshal encodes values as a message body: little-endian, aligned as if
// it started at the beginning of a message (bodies always start 8-aligned).
// With an empty sig the signature is inferred from the values. It returns
// the bytes and the descriptors that UnixFD values refer to, in index order.
func Marshal(sig Signature, values ...any) ([]byte, []UnixFD, error) {
	var e encoder
	if _, err := e.values(sig, values); err != nil {
		return nil, nil, err
	}
	return e.buf, e.fds, nil
}

// encoder appends D-Bus data to buf: little-endian unless order says
// otherwise (only tests do, to produce big-endian input).
type encoder struct {
	buf   []byte
	fds   []UnixFD
	order byteOrder
}

type byteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

func (e *encoder) byteOrder() byteOrder {
	if e.order == nil {
		return binary.LittleEndian
	}
	return e.order
}

func (e *encoder) pad(n int) {
	for len(e.buf)%n != 0 {
		e.buf = append(e.buf, 0)
	}
}

func (e *encoder) u16(v uint16) {
	e.pad(2)
	e.buf = e.byteOrder().AppendUint16(e.buf, v)
}

func (e *encoder) u32(v uint32) {
	e.pad(4)
	e.buf = e.byteOrder().AppendUint32(e.buf, v)
}

func (e *encoder) u64(v uint64) {
	e.pad(8)
	e.buf = e.byteOrder().AppendUint64(e.buf, v)
}

// str writes a STRING or OBJECT_PATH that has already been validated.
func (e *encoder) str(s string) {
	e.u32(uint32(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
}

// sig writes a SIGNATURE that has already been validated.
func (e *encoder) sig(s string) {
	e.buf = append(e.buf, byte(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
}

// values encodes a sequence of values by sig (inferred when empty) and
// returns the signature used.
func (e *encoder) values(sig Signature, values []any) (Signature, error) {
	if sig == "" && len(values) > 0 {
		s, err := SignatureOf(values...)
		if err != nil {
			return "", err
		}
		sig = s
	}
	types, err := parseSignature(string(sig))
	if err != nil {
		return "", err
	}
	if len(types) != len(values) {
		return "", invalidf("signature %q has %d types for %d values", sig, len(types), len(values))
	}
	for i, t := range types {
		if err := e.value(t, reflect.ValueOf(values[i]), 0); err != nil {
			return "", err
		}
	}
	return sig, nil
}

func mismatch(v reflect.Value, t *sigType) error {
	return invalidf("cannot encode Go %s as D-Bus %q", v.Type(), t.text)
}

// value encodes v as type t. depth counts the containers around it.
func (e *encoder) value(t *sigType, v reflect.Value, depth int) error {
	for v.IsValid() && (v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer) {
		if v.IsNil() {
			return invalidf("cannot encode a nil %s as D-Bus %q", v.Type(), t.text)
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return invalidf("cannot encode nil as D-Bus %q", t.text)
	}
	if len(e.buf) > MaxMessageSize {
		return invalidf("message is larger than %d bytes", MaxMessageSize)
	}
	if v.Type() == variantType && t.code != 'v' {
		// A Variant where a concrete type is expected: take its value if
		// the types agree.
		if s := v.Field(0).String(); s != "" && s != t.text {
			return invalidf("cannot encode a variant of %q as D-Bus %q", s, t.text)
		}
		return e.value(t, v.Field(1), depth)
	}
	if t.code != 'v' && (v.Type() == unixFDType) != (t.code == 'h') {
		// Descriptors are never confused with integers, either way round.
		return mismatch(v, t)
	}
	switch t.code {
	case 'y':
		n, ok := uintOf(v, math.MaxUint8)
		if !ok {
			return mismatch(v, t)
		}
		e.buf = append(e.buf, byte(n))
	case 'b':
		if v.Kind() != reflect.Bool {
			return mismatch(v, t)
		}
		var b uint32
		if v.Bool() {
			b = 1
		}
		e.u32(b)
	case 'n':
		n, ok := intOf(v, math.MinInt16, math.MaxInt16)
		if !ok {
			return mismatch(v, t)
		}
		e.u16(uint16(n))
	case 'q':
		n, ok := uintOf(v, math.MaxUint16)
		if !ok {
			return mismatch(v, t)
		}
		e.u16(uint16(n))
	case 'i':
		n, ok := intOf(v, math.MinInt32, math.MaxInt32)
		if !ok {
			return mismatch(v, t)
		}
		e.u32(uint32(n))
	case 'u':
		n, ok := uintOf(v, math.MaxUint32)
		if !ok {
			return mismatch(v, t)
		}
		e.u32(uint32(n))
	case 'x':
		n, ok := intOf(v, math.MinInt64, math.MaxInt64)
		if !ok {
			return mismatch(v, t)
		}
		e.u64(uint64(n))
	case 't':
		n, ok := uintOf(v, math.MaxUint64)
		if !ok {
			return mismatch(v, t)
		}
		e.u64(n)
	case 'd':
		if v.Kind() != reflect.Float64 && v.Kind() != reflect.Float32 {
			return mismatch(v, t)
		}
		e.u64(math.Float64bits(v.Float()))
	case 's':
		if v.Kind() != reflect.String {
			return mismatch(v, t)
		}
		s := v.String()
		if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return invalidf("string is not UTF-8 without NUL bytes")
		}
		e.str(s)
	case 'o':
		if v.Kind() != reflect.String {
			return mismatch(v, t)
		}
		if err := validateObjectPath(v.String()); err != nil {
			return err
		}
		e.str(v.String())
	case 'g':
		if v.Kind() != reflect.String {
			return mismatch(v, t)
		}
		if _, err := parseSignature(v.String()); err != nil {
			return err
		}
		e.sig(v.String())
	case 'h':
		fd := v.Int()
		if fd < 0 || fd > math.MaxInt32 {
			return invalidf("file descriptor %d", fd)
		}
		if len(e.fds) >= MaxUnixFDs {
			return invalidf("more than %d file descriptors in one message", MaxUnixFDs)
		}
		e.u32(uint32(len(e.fds)))
		e.fds = append(e.fds, UnixFD(fd))
	case 'v':
		return e.variant(v, depth)
	case 'a':
		return e.array(t, v, depth)
	case '(':
		return e.structure(t, v, depth)
	default:
		return invalidf("cannot encode D-Bus type %q", t.text)
	}
	return nil
}

func (e *encoder) variant(v reflect.Value, depth int) error {
	if depth+1 > MaxDepth {
		return invalidf("value nests more than %d containers", MaxDepth)
	}
	var sig string
	inner := v
	if v.Type() == variantType {
		sig, inner = v.Field(0).String(), v.Field(1)
		if sig == "" {
			if inner.IsNil() {
				return invalidf("cannot encode a variant of nil")
			}
			s, err := SignatureOfType(inner.Elem().Type())
			if err != nil {
				return err
			}
			sig = string(s)
		}
	} else {
		s, err := SignatureOfType(v.Type())
		if err != nil {
			return err
		}
		sig = string(s)
	}
	t, err := parseSingle(sig)
	if err != nil {
		return err
	}
	e.sig(sig)
	return e.value(t, inner, depth+1)
}

func (e *encoder) array(t *sigType, v reflect.Value, depth int) error {
	if depth+1 > MaxDepth {
		return invalidf("value nests more than %d containers", MaxDepth)
	}
	elem := t.elem
	e.pad(4)
	lenAt := len(e.buf)
	e.buf = append(e.buf, 0, 0, 0, 0)
	// The padding to the first element is there even when there is none.
	e.pad(alignOf(elem.code))
	start := len(e.buf)
	switch {
	case elem.code == '{':
		if v.Kind() != reflect.Map {
			return mismatch(v, t)
		}
		if depth+2 > MaxDepth {
			return invalidf("value nests more than %d containers", MaxDepth)
		}
		// MapRange, not MapIndex: a NaN key can never be looked up again.
		entries := make([][2]reflect.Value, 0, v.Len())
		for it := v.MapRange(); it.Next(); {
			entries = append(entries, [2]reflect.Value{it.Key(), it.Value()})
		}
		sortEntries(entries)
		for _, kv := range entries {
			e.pad(8)
			if err := e.value(elem.fields[0], kv[0], depth+2); err != nil {
				return err
			}
			if err := e.value(elem.fields[1], kv[1], depth+2); err != nil {
				return err
			}
			if len(e.buf)-start > MaxArraySize {
				return invalidf("array is larger than %d bytes", MaxArraySize)
			}
		}
	case elem.code == 'y' && v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8:
		if v.Len() > MaxArraySize {
			return invalidf("array is larger than %d bytes", MaxArraySize)
		}
		e.buf = append(e.buf, v.Bytes()...)
	case v.Kind() == reflect.Slice || v.Kind() == reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := e.value(elem, v.Index(i), depth+1); err != nil {
				return err
			}
			if len(e.buf)-start > MaxArraySize {
				return invalidf("array is larger than %d bytes", MaxArraySize)
			}
		}
	default:
		return mismatch(v, t)
	}
	e.byteOrder().PutUint32(e.buf[lenAt:], uint32(len(e.buf)-start))
	return nil
}

func (e *encoder) structure(t *sigType, v reflect.Value, depth int) error {
	if depth+1 > MaxDepth {
		return invalidf("value nests more than %d containers", MaxDepth)
	}
	e.pad(8)
	switch v.Kind() {
	case reflect.Struct:
		fields := structFields(v.Type())
		if len(fields) != len(t.fields) {
			return mismatch(v, t)
		}
		for i, fi := range fields {
			if err := e.value(t.fields[i], v.Field(fi), depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Len() != len(t.fields) {
			return mismatch(v, t)
		}
		for i, f := range t.fields {
			if err := e.value(f, v.Index(i), depth+1); err != nil {
				return err
			}
		}
	default:
		return mismatch(v, t)
	}
	return nil
}

// intOf reads any integer kind as an int64 within [lo, hi].
func intOf(v reflect.Value, lo, hi int64) (int64, bool) {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		return n, n >= lo && n <= hi
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n := v.Uint()
		return int64(n), n <= math.MaxInt64 && int64(n) <= hi
	}
	return 0, false
}

// uintOf reads any integer kind as a uint64 no greater than hi.
func uintOf(v reflect.Value, hi uint64) (uint64, bool) {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		return uint64(n), n >= 0 && uint64(n) <= hi
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		n := v.Uint()
		return n, n <= hi
	}
	return 0, false
}

// sortEntries orders map entries by key, so that encoding a map is
// deterministic.
func sortEntries(entries [][2]reflect.Value) {
	if len(entries) < 2 {
		return
	}
	var less func(a, b reflect.Value) int
	switch entries[0][0].Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		less = func(a, b reflect.Value) int { return cmp.Compare(a.Int(), b.Int()) }
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		less = func(a, b reflect.Value) int { return cmp.Compare(a.Uint(), b.Uint()) }
	case reflect.Float32, reflect.Float64:
		less = func(a, b reflect.Value) int { return cmp.Compare(a.Float(), b.Float()) }
	case reflect.String:
		less = func(a, b reflect.Value) int { return cmp.Compare(a.String(), b.String()) }
	case reflect.Bool:
		less = func(a, b reflect.Value) int { return cmp.Compare(boolInt(a.Bool()), boolInt(b.Bool())) }
	default:
		return
	}
	slices.SortFunc(entries, func(a, b [2]reflect.Value) int { return less(a[0], b[0]) })
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
