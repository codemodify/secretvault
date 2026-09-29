package svdbus

import (
	"reflect"
	"sync"
)

// sigType is one parsed complete type of a signature.
type sigType struct {
	code   byte
	elem   *sigType   // 'a': the element type, which is '{' for a dict
	fields []*sigType // '(': the fields; '{': the key and the value
	text   string     // the signature of this type alone
}

const (
	maxArrayNesting  = 32
	maxStructNesting = 32
)

func isBasicCode(c byte) bool {
	switch c {
	case 'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h':
		return true
	}
	return false
}

// alignOf is the alignment of a type on the wire, by its first code.
func alignOf(c byte) int {
	switch c {
	case 'n', 'q':
		return 2
	case 'b', 'i', 'u', 'h', 's', 'o', 'a':
		return 4
	case 'x', 't', 'd', '(', '{':
		return 8
	}
	return 1 // y, g, v
}

// parseSignature parses and validates a signature of any number of complete
// types.
func parseSignature(s string) ([]*sigType, error) {
	if len(s) > MaxSignatureLength {
		return nil, invalidf("signature of %d bytes is longer than %d", len(s), MaxSignatureLength)
	}
	p := sigParser{s: s}
	var out []*sigType
	for p.i < len(s) {
		t, err := p.parse(0, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// parseSingle parses a signature that must be exactly one complete type, as
// a variant's is.
func parseSingle(s string) (*sigType, error) {
	ts, err := parseSignature(s)
	if err != nil {
		return nil, err
	}
	if len(ts) != 1 {
		return nil, invalidf("signature %q is not a single complete type", s)
	}
	return ts[0], nil
}

type sigParser struct {
	s string
	i int
}

func (p *sigParser) parse(arrays, structs int) (*sigType, error) {
	if p.i >= len(p.s) {
		return nil, invalidf("signature %q ends inside a type", p.s)
	}
	start := p.i
	c := p.s[p.i]
	p.i++
	t := &sigType{code: c}
	switch {
	case isBasicCode(c) || c == 'v':
	case c == 'a':
		if arrays == maxArrayNesting {
			return nil, invalidf("signature %q nests more than %d arrays", p.s, maxArrayNesting)
		}
		if p.i < len(p.s) && p.s[p.i] == '{' {
			p.i++
			key, err := p.parse(arrays+1, structs)
			if err != nil {
				return nil, err
			}
			if !isBasicCode(key.code) {
				return nil, invalidf("signature %q has a dict key that is not a basic type", p.s)
			}
			val, err := p.parse(arrays+1, structs)
			if err != nil {
				return nil, err
			}
			if p.i >= len(p.s) || p.s[p.i] != '}' {
				return nil, invalidf("signature %q has a dict entry that is not a key and a value", p.s)
			}
			p.i++
			t.elem = &sigType{code: '{', fields: []*sigType{key, val}, text: p.s[start+1 : p.i]}
		} else {
			elem, err := p.parse(arrays+1, structs)
			if err != nil {
				return nil, err
			}
			t.elem = elem
		}
	case c == '(':
		if structs == maxStructNesting {
			return nil, invalidf("signature %q nests more than %d structs", p.s, maxStructNesting)
		}
		for {
			if p.i >= len(p.s) {
				return nil, invalidf("signature %q has an unclosed struct", p.s)
			}
			if p.s[p.i] == ')' {
				p.i++
				break
			}
			f, err := p.parse(arrays, structs+1)
			if err != nil {
				return nil, err
			}
			t.fields = append(t.fields, f)
		}
		if len(t.fields) == 0 {
			return nil, invalidf("signature %q has an empty struct", p.s)
		}
	default:
		return nil, invalidf("signature %q has an unexpected %q", p.s, c)
	}
	t.text = p.s[start:p.i]
	return t, nil
}

// SignatureOf returns the signature of values, inferred from their Go types
// as the package documentation describes.
func SignatureOf(values ...any) (Signature, error) {
	var b []byte
	for _, v := range values {
		if v == nil {
			return "", invalidf("cannot infer the D-Bus type of nil")
		}
		if err := appendTypeSig(&b, reflect.TypeOf(v), 0); err != nil {
			return "", err
		}
	}
	if _, err := parseSignature(string(b)); err != nil {
		return "", err
	}
	return Signature(b), nil
}

// SignatureOfType returns the signature inferred for values of Go type t.
func SignatureOfType(t reflect.Type) (Signature, error) {
	var b []byte
	if err := appendTypeSig(&b, t, 0); err != nil {
		return "", err
	}
	if _, err := parseSingle(string(b)); err != nil {
		return "", err
	}
	return Signature(b), nil
}

func appendTypeSig(b *[]byte, t reflect.Type, depth int) error {
	if depth > MaxDepth || len(*b) > MaxSignatureLength {
		return invalidf("Go type %s nests too deeply for D-Bus", t)
	}
	switch t {
	case variantType:
		*b = append(*b, 'v')
		return nil
	case objectPathType:
		*b = append(*b, 'o')
		return nil
	case signatureType:
		*b = append(*b, 'g')
		return nil
	case unixFDType:
		*b = append(*b, 'h')
		return nil
	}
	var c byte
	switch t.Kind() {
	case reflect.Uint8:
		c = 'y'
	case reflect.Bool:
		c = 'b'
	case reflect.Int16:
		c = 'n'
	case reflect.Uint16:
		c = 'q'
	case reflect.Int32:
		c = 'i'
	case reflect.Uint32:
		c = 'u'
	case reflect.Int64:
		c = 'x'
	case reflect.Uint64:
		c = 't'
	case reflect.Float64:
		c = 'd'
	case reflect.String:
		c = 's'
	case reflect.Interface:
		c = 'v'
	case reflect.Pointer:
		return appendTypeSig(b, t.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		*b = append(*b, 'a')
		return appendTypeSig(b, t.Elem(), depth+1)
	case reflect.Map:
		*b = append(*b, 'a', '{')
		at := len(*b)
		if err := appendTypeSig(b, t.Key(), depth+1); err != nil {
			return err
		}
		if len(*b) != at+1 || !isBasicCode((*b)[at]) {
			return invalidf("Go map key type %s is not a D-Bus basic type", t.Key())
		}
		if err := appendTypeSig(b, t.Elem(), depth+1); err != nil {
			return err
		}
		*b = append(*b, '}')
		return nil
	case reflect.Struct:
		fields := structFields(t)
		if len(fields) == 0 {
			return invalidf("Go struct %s has no exported fields to encode", t)
		}
		*b = append(*b, '(')
		for _, i := range fields {
			if err := appendTypeSig(b, t.Field(i).Type, depth+1); err != nil {
				return err
			}
		}
		*b = append(*b, ')')
		return nil
	default:
		return invalidf("Go type %s has no D-Bus type: use a sized type or give a signature", t)
	}
	*b = append(*b, c)
	return nil
}

var fieldCache sync.Map // reflect.Type -> []int

// structFields lists the indices of a struct's encoded fields: exported,
// and not tagged `dbus:"-"`.
func structFields(t reflect.Type) []int {
	if f, ok := fieldCache.Load(t); ok {
		return f.([]int)
	}
	var out []int
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Tag.Get("dbus") == "-" {
			continue
		}
		out = append(out, i)
	}
	fieldCache.Store(t, out)
	return out
}
