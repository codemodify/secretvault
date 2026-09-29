package svgpgagent

import (
	"bytes"
	"errors"
	"strconv"
)

// S-expressions, as libgcrypt writes them in canonical form
// (https://people.csail.mit.edu/rivest/Sexp.txt): a list is '(' its
// elements ')', and an atom is its length in decimal, ':', and its bytes.
// gpg sends ciphertexts this way and reads keys and signatures back the
// same way. Only the canonical form is read: no display hints, no
// advanced (text) form, no leading zeros in a length, and nothing after
// the one expression.

// maxDepth bounds how deeply lists nest; gpg's deepest is three.
const maxDepth = 8

var errSexp = errors.New("svgpgagent: not a canonical S-expression")

// sexp is an atom (list == nil and !isList) or a list.
type sexp struct {
	atom   []byte
	list   []*sexp
	isList bool
}

// parseSexp reads one canonical S-expression that fills b exactly.
func parseSexp(b []byte) (*sexp, error) {
	e, rest, err := parseElem(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errSexp
	}
	return e, nil
}

func parseElem(b []byte, depth int) (*sexp, []byte, error) {
	if len(b) == 0 {
		return nil, nil, errSexp
	}
	if b[0] != '(' {
		atom, rest, err := parseAtom(b)
		if err != nil {
			return nil, nil, err
		}
		return &sexp{atom: atom}, rest, nil
	}
	if depth >= maxDepth {
		return nil, nil, errSexp
	}
	e := &sexp{isList: true}
	b = b[1:]
	for {
		if len(b) == 0 {
			return nil, nil, errSexp
		}
		if b[0] == ')' {
			return e, b[1:], nil
		}
		child, rest, err := parseElem(b, depth+1)
		if err != nil {
			return nil, nil, err
		}
		e.list = append(e.list, child)
		b = rest
	}
}

// parseAtom reads "<length>:<bytes>".
func parseAtom(b []byte) ([]byte, []byte, error) {
	i := bytes.IndexByte(b, ':')
	if i <= 0 || i > 9 || b[0] == '0' && i > 1 {
		return nil, nil, errSexp
	}
	n, err := strconv.Atoi(string(b[:i]))
	if err != nil || n < 0 || n > len(b)-i-1 {
		return nil, nil, errSexp
	}
	for _, c := range b[:i] {
		if c < '0' || c > '9' {
			return nil, nil, errSexp
		}
	}
	return b[i+1 : i+1+n], b[i+1+n:], nil
}

// name is a list's first element, when it is an atom.
func (e *sexp) name() string {
	if e == nil || !e.isList || len(e.list) == 0 || e.list[0].isList {
		return ""
	}
	return string(e.list[0].atom)
}

// find returns the first sublist named n.
func (e *sexp) find(n string) *sexp {
	if e == nil || len(e.list) == 0 {
		return nil
	}
	for _, c := range e.list[1:] {
		if c.name() == n {
			return c
		}
	}
	return nil
}

// value is the atom after a (name value) list's name.
func (e *sexp) value() ([]byte, bool) {
	if e == nil || len(e.list) != 2 || e.list[1].isList {
		return nil, false
	}
	return e.list[1].atom, true
}

// Canonical S-expressions are written with these.

func atom(b []byte) []byte {
	return append(strconv.AppendInt(nil, int64(len(b)), 10), append([]byte{':'}, b...)...)
}

func list(elems ...[]byte) []byte {
	out := []byte{'('}
	for _, e := range elems {
		out = append(out, e...)
	}
	return append(out, ')')
}

// param is (name value).
func param(name string, value []byte) []byte { return list(atom([]byte(name)), atom(value)) }

// mpi is a value as libgcrypt's %m writes an integer: big-endian, without
// leading zeros, and with one zero byte in front when the top bit is set
// (a signed, two's complement number that is positive).
func mpi(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		return append([]byte{0}, b...)
	}
	return b
}
