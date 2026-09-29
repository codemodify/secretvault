package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8949 Appendix A, for the types CTAP2 uses. Each encodes back to the
// same bytes, since the appendix's encodings are all preferred ones.
var appendixA = []struct {
	hex string
	v   any
}{
	{"00", int64(0)},
	{"01", int64(1)},
	{"0a", int64(10)},
	{"17", int64(23)},
	{"1818", int64(24)},
	{"1819", int64(25)},
	{"1864", int64(100)},
	{"1903e8", int64(1000)},
	{"1a000f4240", int64(1000000)},
	{"1b000000e8d4a51000", int64(1000000000000)},
	{"20", int64(-1)},
	{"29", int64(-10)},
	{"3863", int64(-100)},
	{"3903e7", int64(-1000)},
	{"f4", false},
	{"f5", true},
	{"f6", nil},
	{"40", []byte{}},
	{"4401020304", []byte{1, 2, 3, 4}},
	{"60", ""},
	{"6161", "a"},
	{"6449455446", "IETF"},
	{"62225c", "\"\\"},
	{"62c3bc", "ü"},
	{"63e6b0b4", "水"},
	{"64f0908591", "\U00010151"},
	{"80", []any{}},
	{"83010203", []any{int64(1), int64(2), int64(3)}},
	{"8301820203820405", []any{int64(1), []any{int64(2), int64(3)}, []any{int64(4), int64(5)}}},
	{"a0", Map{}},
	{"a201020304", Map{int64(1): int64(2), int64(3): int64(4)}},
	{"a26161016162820203", Map{"a": int64(1), "b": []any{int64(2), int64(3)}}},
	{"826161a161626163", []any{"a", Map{"b": "c"}}},
}

func TestAppendixAVectors(t *testing.T) {
	for _, c := range appendixA {
		b := unhex(t, c.hex)
		v, err := UnmarshalCanonical(b)
		if err != nil {
			t.Errorf("%s: %v", c.hex, err)
			continue
		}
		if !reflect.DeepEqual(v, c.v) {
			t.Errorf("%s decoded to %#v, want %#v", c.hex, v, c.v)
		}
		enc, err := Marshal(c.v)
		if err != nil || !bytes.Equal(enc, b) {
			t.Errorf("%#v encoded to %x (%v), want %s", c.v, enc, err, c.hex)
		}
	}
}

// CTAP2 §8: keys sort by major type, then encoded length, then bytes. A
// COSE key is the classic case: 1, 3, then -1, -2, -3.
func TestMapsAreWrittenInCTAP2CanonicalOrder(t *testing.T) {
	cose := Map{-3: []byte{3}, -1: int64(1), 3: int64(-25), 1: int64(2), -2: []byte{2}}
	b, err := Marshal(cose)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a5 01 02 03 38 18 20 01 21 41 02 22 41 03"; !bytes.Equal(b, unhex(t, want)) {
		t.Fatalf("COSE key = % x, want %s", b, want)
	}
	// Longer keys after shorter ones, integers before text.
	m := Map{"up": true, "rk": false, 24: int64(0), 23: int64(0), "alg": int64(-7)}
	b, err = Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if want := "a5 17 00 18 18 00 62 726b f4 62 7570 f5 63 616c67 26"; !bytes.Equal(b, unhex(t, want)) {
		t.Fatalf("map = % x, want %s", b, want)
	}
	if _, err := UnmarshalCanonical(b); err != nil {
		t.Fatal(err)
	}
}

func TestNonCanonicalInputIsReadButNotAsCanonical(t *testing.T) {
	for _, h := range []string{
		"1817",             // 23 in two bytes
		"190001",           // 1 in three bytes
		"5801ff",           // a one-byte string with a two-byte length
		"a2 03 04 01 02",   // keys out of order
		"a2 6161 01 01 02", // text key before an integer key
	} {
		b := unhex(t, h)
		if _, err := Unmarshal(b); err != nil {
			t.Errorf("%s: Unmarshal: %v", h, err)
		}
		if _, err := UnmarshalCanonical(b); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s: UnmarshalCanonical = %v, want ErrNotCanonical", h, err)
		}
	}
}

func TestWhatCTAP2DoesNotSpeakIsRefused(t *testing.T) {
	for name, h := range map[string]string{
		"a tag":                    "c11a514b67b0",
		"a half float":             "f93c00",
		"a double":                 "fb3ff199999999999a",
		"undefined":                "f7",
		"a simple value":           "f0",
		"an indefinite string":     "5f42010243030405ff",
		"an indefinite array":      "9f0102ff",
		"an indefinite map":        "bf6161 01ff",
		"a reserved length":        "1c",
		"an integer beyond int64":  "1bffffffffffffffff",
		"a negative beyond int64":  "3bffffffffffffffff",
		"a byte-string key":        "a1 4101 01",
		"an array key":             "a1 80 01",
		"a duplicate key":          "a2 01 01 01 02",
		"bad UTF-8":                "62 c328",
		"a truncated string":       "45 0102",
		"a truncated argument":     "19 01",
		"an empty input":           "",
		"trailing bytes":           "01 02",
		"an array longer than all": "9b 00000000ffffffff 01",
		"a map longer than all":    "bb 00000000ffffffff 01",
	} {
		if _, err := Unmarshal(unhex(t, h)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s (%s): %v, want ErrMalformed", name, h, err)
		}
	}
}

func TestNestingIsBounded(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, MaxDepth+1)
	deep = append(deep, 0x01)
	if _, err := Unmarshal(deep); !errors.Is(err, ErrMalformed) {
		t.Fatalf("%d levels: %v", MaxDepth+1, err)
	}
	ok := append(bytes.Repeat([]byte{0x81}, MaxDepth), 0x01)
	if _, err := Unmarshal(ok); err != nil {
		t.Fatalf("%d levels: %v", MaxDepth, err)
	}
	var v any = int64(1)
	for range MaxDepth + 1 {
		v = []any{v}
	}
	if _, err := Marshal(v); err == nil {
		t.Fatal("Marshal wrote nesting it would refuse to read")
	}
}

func TestUnmarshalFirstLeavesTheRest(t *testing.T) {
	v, rest, err := UnmarshalFirst(unhex(t, "a1 01 02 ff ee"))
	if err != nil || !reflect.DeepEqual(v, Map{int64(1): int64(2)}) || !bytes.Equal(rest, []byte{0xff, 0xee}) {
		t.Fatalf("UnmarshalFirst = %v, %x, %v", v, rest, err)
	}
}

func TestDecodedBytesDoNotAliasTheInput(t *testing.T) {
	in := unhex(t, "42 0102")
	v, _ := Unmarshal(in)
	in[1] = 9
	if v.([]byte)[0] != 1 {
		t.Fatal("a decoded byte string aliases the input")
	}
}

func TestMarshalRefusesWhatItCannotWrite(t *testing.T) {
	for _, v := range []any{1.5, Map{1.5: 1}, Map{1: int64(1), int64(1): 2}, "\xff", struct{}{}} {
		if _, err := Marshal(v); err == nil {
			t.Errorf("Marshal(%#v) succeeded", v)
		}
	}
}

// FuzzUnmarshal: no input panics or allocates beyond reason, and whatever
// decodes also encodes, to bytes that decode to the same value.
func FuzzUnmarshal(f *testing.F) {
	for _, c := range appendixA {
		f.Add(unhex(f, c.hex))
	}
	f.Add(unhex(f, "a5 01 02 03 38 18 20 01 21 41 02 22 41 03"))
	f.Add(unhex(f, "9b 00000000ffffffff 01"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Unmarshal(b)
		if err != nil {
			return
		}
		enc, err := Marshal(v)
		if err != nil {
			t.Fatalf("decoded %#v but cannot encode it: %v", v, err)
		}
		v2, err := UnmarshalCanonical(enc)
		if err != nil {
			t.Fatalf("our own encoding % x is refused: %v", enc, err)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Fatalf("round trip changed %#v to %#v", v, v2)
		}
		if _, err := UnmarshalCanonical(b); err == nil && !bytes.Equal(enc, b) {
			t.Fatalf("canonical input % x encodes back as % x", b, enc)
		}
	})
}
