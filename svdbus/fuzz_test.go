package svdbus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Whatever the decoder accepts must encode again, and encoding what that
// decodes to must be stable: the decoder never hands out a value the rest of
// the package cannot handle. Neither may ever panic.

func FuzzUnmarshalMessage(f *testing.F) {
	f.Add([]byte(helloBytes))
	f.Add([]byte(signalBytes))
	for _, c := range roundTripCases {
		m := NewSignal("/a/b", "org.example.I", "S", c.vals...)
		m.Signature, m.Serial = c.sig, 9
		if data, fds, err := m.Marshal(); err == nil && len(fds) == 0 {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := UnmarshalMessage(data, nil)
		if err != nil {
			return
		}
		switch m.Type {
		case TypeMethodCall, TypeMethodReturn, TypeError, TypeSignal:
		default:
			return
		}
		once, fds, err := m.Marshal()
		if err != nil {
			t.Fatalf("an accepted message does not encode: %v (%v)", err, m)
		}
		back, err := UnmarshalMessage(once, fds)
		if err != nil {
			t.Fatalf("an encoded message does not decode: %v", err)
		}
		twice, _, err := back.Marshal()
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("encoding is not stable: %v\n% x\n% x", err, once, twice)
		}
	})
}

func FuzzUnmarshalBody(f *testing.F) {
	for _, c := range roundTripCases {
		if data, fds, err := Marshal(c.sig, c.vals...); err == nil && len(fds) == 0 {
			f.Add(string(c.sig), data, false)
		}
	}
	f.Fuzz(func(t *testing.T, sig string, data []byte, bigEndian bool) {
		var order binary.ByteOrder = binary.LittleEndian
		if bigEndian {
			order = binary.BigEndian
		}
		fds := []UnixFD{100, 101, 102}
		vals, err := Unmarshal(data, order, Signature(sig), fds)
		if err != nil {
			return
		}
		once, fds1, err := Marshal(Signature(sig), vals...)
		if err != nil {
			t.Fatalf("accepted values do not encode as %q: %v", sig, err)
		}
		back, err := Unmarshal(once, binary.LittleEndian, Signature(sig), fds1)
		if err != nil {
			t.Fatalf("encoded values do not decode: %v", err)
		}
		twice, _, err := Marshal(Signature(sig), back...)
		if err != nil || !bytes.Equal(once, twice) {
			t.Fatalf("encoding is not stable: %v", err)
		}
	})
}

func FuzzSignature(f *testing.F) {
	for _, s := range []string{"a{sv}", "(ii)", "aaa(y)", "v", "a{s(ia{sv})}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		types, err := parseSignature(s)
		if err != nil {
			return
		}
		var joined string
		for _, ty := range types {
			joined += ty.text
		}
		if joined != s {
			t.Fatalf("%q parsed into %q", s, joined)
		}
	})
}

func FuzzParseAddresses(f *testing.F) {
	f.Add("unix:path=/run/user/1000/bus,guid=0123456789abcdef0123456789abcdef;unix:abstract=/tmp/x%20y")
	f.Fuzz(func(t *testing.T, s string) {
		addrs, err := ParseAddresses(s)
		if err != nil {
			return
		}
		for _, a := range addrs {
			back, err := ParseAddresses(a.String())
			if err != nil || len(back) != 1 || back[0].String() != a.String() {
				t.Fatalf("%q does not round-trip: %v", a.String(), err)
			}
			_, _ = a.unixSocket()
		}
	})
}
