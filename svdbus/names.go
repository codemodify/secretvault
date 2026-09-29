package svdbus

import "strings"

// Name rules from the specification's "Valid names" section. Every check
// here runs on names from the wire before anything relies on them.

func isAlpha(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// validateObjectPath: "/" or "/"-separated non-empty elements of
// [A-Za-z0-9_], with no trailing slash.
func validateObjectPath(p string) error {
	if p == "/" {
		return nil
	}
	if p == "" || p[0] != '/' || p[len(p)-1] == '/' {
		return invalidf("object path %.80q", p)
	}
	prev := byte('/')
	for i := 1; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/':
			if prev == '/' {
				return invalidf("object path %.80q has an empty element", p)
			}
		case isAlpha(c) || isDigit(c):
		default:
			return invalidf("object path %.80q", p)
		}
		prev = c
	}
	return nil
}

// dottedName checks names made of '.'-separated elements, as interface,
// error and bus names are. digitsFirst allows elements to start with a
// digit (unique names only); dash allows '-' (bus names only).
func dottedName(s string, digitsFirst, dash bool) bool {
	if s == "" || len(s) > MaxNameLength {
		return false
	}
	elems := 0
	start := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if start {
				return false // leading '.', or ".."
			}
			start = true
			continue
		case isAlpha(c) || dash && c == '-':
		case isDigit(c):
			if start && !digitsFirst {
				return false
			}
		default:
			return false
		}
		if start {
			elems++
			start = false
		}
	}
	return !start && elems >= 2
}

// ValidateInterfaceName checks an interface name such as
// org.freedesktop.Secret.Service.
func ValidateInterfaceName(s string) error {
	if !dottedName(s, false, false) {
		return invalidf("interface name %.80q", s)
	}
	return nil
}

// ValidateErrorName checks an error name; the rules are those of interface
// names.
func ValidateErrorName(s string) error {
	if !dottedName(s, false, false) {
		return invalidf("error name %.80q", s)
	}
	return nil
}

// ValidateMemberName checks a method or signal name: [A-Za-z_][A-Za-z0-9_]*.
func ValidateMemberName(s string) error {
	if s == "" || len(s) > MaxNameLength || isDigit(s[0]) {
		return invalidf("member name %.80q", s)
	}
	for i := 0; i < len(s); i++ {
		if !isAlpha(s[i]) && !isDigit(s[i]) {
			return invalidf("member name %.80q", s)
		}
	}
	return nil
}

// ValidateBusName checks a unique name (":1.42") or a well-known name
// ("org.freedesktop.secrets").
func ValidateBusName(s string) error {
	if strings.HasPrefix(s, ":") {
		if len(s) > MaxNameLength || !dottedName(s[1:], true, true) {
			return invalidf("unique name %.80q", s)
		}
		return nil
	}
	if !dottedName(s, false, true) {
		return invalidf("bus name %.80q", s)
	}
	return nil
}

// isUniqueName reports whether a valid bus name is a unique connection name.
func isUniqueName(s string) bool { return strings.HasPrefix(s, ":") }

// EscapePathElement turns any string into a valid object path element:
// ASCII letters and digits stay, every other byte becomes _xx (lowercase
// hex), and the empty string becomes "_". It is reversible, so services can
// name objects after labels or IDs chosen by users.
func EscapePathElement(s string) string {
	if s == "" {
		return "_"
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('_')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// UnescapePathElement reverses EscapePathElement. It fails on anything
// EscapePathElement would not have produced.
func UnescapePathElement(e string) (string, error) {
	if e == "_" {
		return "", nil
	}
	if e == "" {
		return "", invalidf("empty escaped path element")
	}
	var b strings.Builder
	for i := 0; i < len(e); i++ {
		c := e[i]
		if c != '_' {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return "", invalidf("escaped path element %.80q", e)
			}
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(e) {
			return "", invalidf("escaped path element %.80q", e)
		}
		hi, ok1 := unhexLower(e[i+1])
		lo, ok2 := unhexLower(e[i+2])
		v := hi<<4 | lo
		if !ok1 || !ok2 || v >= 'A' && v <= 'Z' || v >= 'a' && v <= 'z' || v >= '0' && v <= '9' {
			return "", invalidf("escaped path element %.80q", e)
		}
		b.WriteByte(v)
		i += 2
	}
	return b.String(), nil
}

func unhexLower(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}
