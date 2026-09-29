package svdbus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// roundTrip encodes values by sig in the given byte order and decodes them
// back.
func roundTrip(t *testing.T, order byteOrder, sig Signature, vals ...any) []any {
	t.Helper()
	e := encoder{order: order}
	if _, err := e.values(sig, vals); err != nil {
		t.Fatalf("encode %q: %v", sig, err)
	}
	got, err := Unmarshal(e.buf, order, sig, e.fds)
	if err != nil {
		t.Fatalf("decode %q: %v\n% x", sig, err, e.buf)
	}
	return got
}

// Every value here is already in the generic form decoding produces, so a
// round trip must give it back exactly.
var roundTripCases = []struct {
	sig  Signature
	vals []any
}{
	{"y", []any{byte(200)}},
	{"b", []any{true}},
	{"b", []any{false}},
	{"n", []any{int16(-12345)}},
	{"q", []any{uint16(54321)}},
	{"i", []any{int32(math.MinInt32)}},
	{"u", []any{uint32(math.MaxUint32)}},
	{"x", []any{int64(math.MinInt64)}},
	{"t", []any{uint64(math.MaxUint64)}},
	{"d", []any{3.25}},
	{"d", []any{math.Inf(-1)}},
	{"s", []any{"héllo wörld ✓"}},
	{"s", []any{""}},
	{"o", []any{ObjectPath("/")}},
	{"o", []any{ObjectPath("/org/freedesktop/secrets/collection/login/1")}},
	{"g", []any{Signature("a{sv}(ii)")}},
	{"g", []any{Signature("")}},
	{"h", []any{UnixFD(7)}},
	{"hh", []any{UnixFD(9), UnixFD(9)}}, // one descriptor sent twice gets two indices
	{"ay", []any{[]byte{1, 2, 3}}},
	{"ay", []any{[]byte{}}},
	{"ab", []any{[]bool{true, false}}},
	{"an", []any{[]int16{-1, 2}}},
	{"aq", []any{[]uint16{1, 65535}}},
	{"ai", []any{[]int32{-7, 0, 7}}},
	{"au", []any{[]uint32{}}},
	{"ax", []any{[]int64{math.MaxInt64}}},
	{"at", []any{[]uint64{5}}},
	{"ad", []any{[]float64{0.5, -2}}},
	{"as", []any{[]string{"a", "", "c"}}},
	{"ao", []any{[]ObjectPath{"/a", "/b/c"}}},
	{"ag", []any{[]Signature{"i", ""}}},
	{"ah", []any{[]UnixFD{3, 4}}},
	{"av", []any{[]Variant{{"s", "x"}, {"u", uint32(1)}}}},
	{"a{sv}", []any{map[string]Variant{"a": {"s", "x"}, "b": {"ay", []byte{0}}, "c": {"a{ss}", map[string]string{"k": "v"}}}}},
	{"a{ss}", []any{map[string]string{"xdg:schema": "org.example.Password", "user": "ada"}}},
	{"a{ys}", []any{map[byte]string{1: "one", 2: "two"}}},
	{"a{bd}", []any{map[bool]float64{true: 1, false: 0}}},
	{"a{ov}", []any{map[ObjectPath]Variant{"/x": {"b", true}}}},
	{"a{ia{sv}}", []any{map[int32]any{1: map[string]Variant{"k": {"n", int16(3)}}}}},
	{"a{sa{sv}}", []any{map[string]any{}}},
	{"(ybnqiuxtdsog)", []any{[]any{byte(1), true, int16(2), uint16(3), int32(4), uint32(5), int64(6), uint64(7), 8.5, "nine", ObjectPath("/ten"), Signature("s")}}},
	{"(oayays)", []any{[]any{ObjectPath("/s/1"), []byte{}, []byte("secret"), "text/plain"}}},
	{"a(sa{sv})", []any{[]any{[]any{"x", map[string]Variant{}}, []any{"y", map[string]Variant{"z": {"x", int64(-1)}}}}}},
	{"aas", []any{[]any{[]string{"a"}, []string{}}}},
	{"aay", []any{[]any{[]byte("ab"), []byte{}}}},
	{"a{oa{sa{sv}}}", []any{map[ObjectPath]any{"/o": map[string]any{"i.f": map[string]Variant{"P": {"u", uint32(1)}}}}}},
	{"v", []any{Variant{"(is)", []any{int32(1), "x"}}}},
	{"v", []any{Variant{"v", Variant{"v", Variant{"t", uint64(5)}}}}},
	{"yvyv", []any{byte(1), Variant{"t", uint64(2)}, byte(3), Variant{"ai", []int32{4}}}},
	{"", []any{}},
}

func TestEveryTypeAndNestingRoundTripsInBothByteOrders(t *testing.T) {
	for _, order := range []byteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, c := range roundTripCases {
			got := roundTrip(t, order, c.sig, c.vals...)
			if !reflect.DeepEqual(got, c.vals) {
				t.Errorf("%v %q: got %#v, want %#v", order, c.sig, got, c.vals)
			}
		}
	}
}

func TestInferredSignaturesMatchTheGoTypes(t *testing.T) {
	type secret struct {
		Session     ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	type skipping struct {
		A int32
		b int32
		C string `dbus:"-"`
		D uint64
	}
	cases := []struct {
		v    any
		want Signature
	}{
		{byte(1), "y"}, {true, "b"}, {int16(1), "n"}, {uint16(1), "q"}, {int32(1), "i"}, {uint32(1), "u"},
		{int64(1), "x"}, {uint64(1), "t"}, {1.5, "d"}, {"s", "s"}, {ObjectPath("/"), "o"}, {Signature(""), "g"},
		{UnixFD(0), "h"}, {Variant{}, "v"}, {[]byte{}, "ay"}, {[3]int32{}, "ai"}, {[]any{}, "av"},
		{map[string]any{}, "a{sv}"}, {map[string]Variant{}, "a{sv}"}, {map[string]string{}, "a{ss}"},
		{secret{}, "(oayays)"}, {&secret{}, "(oayays)"}, {map[ObjectPath]secret{}, "a{o(oayays)}"},
		{skipping{}, "(it)"}, {[][]string{}, "aas"}, {map[string][]map[uint32]bool{}, "a{saa{ub}}"},
	}
	for _, c := range cases {
		got, err := SignatureOf(c.v)
		if err != nil || got != c.want {
			t.Errorf("SignatureOf(%T) = %q, %v; want %q", c.v, got, err, c.want)
		}
	}
	type recursive []recursive
	for _, bad := range []any{1, uint(1), float32(1), int8(1), nil, struct{}{}, map[[2]byte]string{}, recursive{},
		map[any]string{}, make(chan int), func() {}} {
		if sig, err := SignatureOf(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("SignatureOf(%T) = %q, %v; want an error", bad, sig, err)
		}
	}
	if sig, err := SignatureOf(int32(1), "x", []string{}); err != nil || sig != "isas" {
		t.Errorf("SignatureOf of several values = %q, %v", sig, err)
	}
}

func TestAnEmptyArrayStillAlignsItsFirstElement(t *testing.T) {
	// The length is followed by padding to the element's alignment even
	// when there is no element, so the byte after it lands at offset 8.
	data, _, err := Marshal("aty", []uint64{}, byte(7))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 0, 0, 0, 0, 0, 7}
	if !bytes.Equal(data, want) {
		t.Fatalf("got % x, want % x", data, want)
	}
	// And a decoder must insist on that padding.
	if _, err := Unmarshal([]byte{0, 0, 0, 0, 7}, binary.LittleEndian, "aty", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty array without its padding decoded: %v", err)
	}
	// An empty array of structs or dict entries pads to 8 as well; of
	// int32 or bytes it needs none, so the byte after it is at 4.
	for sig, n := range map[Signature]int{"a(y)": 9, "ai": 5, "ay": 5, "a{sv}": 9} {
		data, _, err := Marshal(sig+"y", reflect.Zero(goTypeForTest(sig)).Interface(), byte(1))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != n || data[n-1] != 1 {
			t.Errorf("%sy with an empty array is % x, want %d bytes", sig, data, n)
		}
	}
}

func goTypeForTest(sig Signature) reflect.Type {
	switch sig {
	case "a(y)":
		return reflect.TypeFor[[]struct{ A byte }]()
	case "ai":
		return reflect.TypeFor[[]int32]()
	case "ay":
		return reflect.TypeFor[[]byte]()
	}
	return reflect.TypeFor[map[string]Variant]()
}

func TestBodiesMatchBytesWorkedOutFromTheSpecification(t *testing.T) {
	cases := []struct {
		sig  Signature
		vals []any
		want string
	}{
		// A dict entry is 8-aligned; the variant's uint32 is 4-aligned
		// after its signature.
		{"ya{sv}", []any{byte(1), map[string]Variant{"k": {"u", uint32(2)}}},
			"\x01\x00\x00\x00" + "\x10\x00\x00\x00" + "\x01\x00\x00\x00" + "k\x00\x01u" + "\x00\x00\x00\x00" + "\x02\x00\x00\x00"},
		// A struct is 8-aligned and its int64 again after the byte.
		{"(yx)b", []any{struct {
			A byte
			B int64
		}{3, -2}, true},
			"\x03\x00\x00\x00\x00\x00\x00\x00" + "\xfe\xff\xff\xff\xff\xff\xff\xff" + "\x01\x00\x00\x00"},
		// Strings count bytes, not characters, and end in NUL; a signature
		// has a one-byte length; a variant needs no alignment of its own.
		{"sogv", []any{"hé", ObjectPath("/a"), Signature("as"), MakeVariant(int16(-1))},
			"\x03\x00\x00\x00h\xc3\xa9\x00" + "\x02\x00\x00\x00/a\x00" + "\x02as\x00" + "\x01n\x00" + "\xff\xff"},
		// Descriptors are indices into the out-of-band list.
		{"hh", []any{UnixFD(10), UnixFD(11)}, "\x00\x00\x00\x00\x01\x00\x00\x00"},
	}
	for _, c := range cases {
		data, _, err := Marshal(c.sig, c.vals...)
		if err != nil {
			t.Fatalf("%q: %v", c.sig, err)
		}
		if string(data) != c.want {
			t.Errorf("%q:\n got % x\nwant % x", c.sig, data, []byte(c.want))
		}
	}
}

func TestTheSpecificationsBigEndianExamplesDecode(t *testing.T) {
	// "an array containing only the 64-bit integer 5"
	got, err := Unmarshal([]byte{0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, binary.BigEndian, "at", nil)
	if err != nil || !reflect.DeepEqual(got, []any{[]uint64{5}}) {
		t.Fatalf("array example = %#v, %v", got, err)
	}
	// "a variant containing a 64-bit integer 5"
	got, err = Unmarshal([]byte{1, 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, binary.BigEndian, "v", nil)
	if err != nil || !reflect.DeepEqual(got, []any{Variant{"t", uint64(5)}}) {
		t.Fatalf("variant example = %#v, %v", got, err)
	}
}

// helloBytes is the Hello call every client sends first, worked out by hand
// from the specification (and the same bytes libdbus sends).
const helloBytes = "l\x01\x00\x01" + "\x00\x00\x00\x00" + "\x01\x00\x00\x00" + "\x6d\x00\x00\x00" +
	"\x01\x01o\x00" + "\x15\x00\x00\x00" + "/org/freedesktop/DBus\x00" + "\x00\x00" +
	"\x02\x01s\x00" + "\x14\x00\x00\x00" + "org.freedesktop.DBus\x00" + "\x00\x00\x00" +
	"\x03\x01s\x00" + "\x05\x00\x00\x00" + "Hello\x00" + "\x00\x00" +
	"\x06\x01s\x00" + "\x14\x00\x00\x00" + "org.freedesktop.DBus\x00" + "\x00\x00\x00"

// signalBytes is a big-endian signal /a a.b.C(u 0x01020304), serial 7.
const signalBytes = "B\x04\x00\x01" + "\x00\x00\x00\x04" + "\x00\x00\x00\x07" + "\x00\x00\x00\x37" +
	"\x01\x01o\x00" + "\x00\x00\x00\x02" + "/a\x00" + "\x00\x00\x00\x00\x00" +
	"\x02\x01s\x00" + "\x00\x00\x00\x03" + "a.b\x00" + "\x00\x00\x00\x00" +
	"\x03\x01s\x00" + "\x00\x00\x00\x01" + "C\x00" + "\x00\x00\x00\x00\x00\x00" +
	"\x08\x01g\x00" + "\x01u\x00" + "\x00" +
	"\x01\x02\x03\x04"

func TestTheHelloCallHasTheBytesTheSpecificationGives(t *testing.T) {
	m := NewMethodCall(BusName, BusPath, BusInterface, "Hello")
	m.Serial = 1
	data, fds, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != helloBytes || len(fds) != 0 {
		t.Fatalf("Hello:\n got % x\nwant % x", data, []byte(helloBytes))
	}
	back, err := UnmarshalMessage(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if back.Type != TypeMethodCall || back.Serial != 1 || back.Path != BusPath || back.Interface != BusInterface ||
		back.Member != "Hello" || back.Destination != BusName || len(back.Body) != 0 {
		t.Fatalf("Hello decoded as %v", back)
	}
}

func TestABigEndianMessageDecodes(t *testing.T) {
	m, err := UnmarshalMessage([]byte(signalBytes), nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != TypeSignal || m.Serial != 7 || m.Path != "/a" || m.Interface != "a.b" || m.Member != "C" ||
		m.Signature != "u" || !reflect.DeepEqual(m.Body, []any{uint32(0x01020304)}) {
		t.Fatalf("decoded %v %#v", m, m.Body)
	}
	// The encoder, told to, writes the same bytes.
	m.Serial = 7
	data, _, err := m.marshal(binary.BigEndian)
	if err != nil || string(data) != signalBytes {
		t.Fatalf("re-encoded big-endian:\n got % x\nwant % x (%v)", data, []byte(signalBytes), err)
	}
}

func TestMessagesOfEveryKindRoundTrip(t *testing.T) {
	call := &Message{Type: TypeMethodCall, Serial: 42, Flags: FlagNoAutoStart | FlagAllowInteractiveAuthorization,
		Destination: "org.freedesktop.secrets", Path: "/org/freedesktop/secrets", Interface: "org.freedesktop.Secret.Service",
		Member: "OpenSession", Body: []any{"plain", MakeVariant("")}}
	call.Sender = ":1.7"
	msgs := []*Message{
		call,
		{Type: TypeMethodReturn, Serial: 43, ReplySerial: 42, Destination: ":1.7",
			Body: []any{Variant{"s", ""}, ObjectPath("/org/freedesktop/secrets/session/1")}, Signature: "vo"},
		{Type: TypeError, Serial: 44, ReplySerial: 42, ErrorName: "org.freedesktop.Secret.Error.IsLocked", Body: []any{"locked"}},
		{Type: TypeSignal, Serial: 45, Path: "/org/freedesktop/secrets", Interface: "org.freedesktop.Secret.Service",
			Member: "CollectionCreated", Body: []any{ObjectPath("/org/freedesktop/secrets/collection/x")}},
		{Type: TypeMethodCall, Serial: 46, Path: "/p", Member: "TakeFD", Body: []any{UnixFD(5), UnixFD(6)}},
	}
	for _, m := range msgs {
		data, fds, err := m.Marshal()
		if err != nil {
			t.Fatalf("%v: %v", m, err)
		}
		back, err := UnmarshalMessage(data, fds)
		if err != nil {
			t.Fatalf("%v: %v", m, err)
		}
		wantSig, _ := SignatureOf(m.Body...)
		if m.Signature != "" {
			wantSig = m.Signature
		}
		if back.Type != m.Type || back.Serial != m.Serial || back.Flags != m.Flags || back.Path != m.Path ||
			back.Interface != m.Interface || back.Member != m.Member || back.ErrorName != m.ErrorName ||
			back.ReplySerial != m.ReplySerial || back.Destination != m.Destination || back.Sender != m.Sender ||
			back.Signature != wantSig || !reflect.DeepEqual(back.Body, m.Body) {
			t.Errorf("round trip changed the message:\n%v %#v\n%v %#v", m, m.Body, back, back.Body)
		}
		if len(fds) > 0 {
			if _, err := UnmarshalMessage(data, nil); !errors.Is(err, ErrInvalid) {
				t.Errorf("a message decoded without the descriptors it declares: %v", err)
			}
		}
	}
	if err := (&Message{Type: TypeError, Serial: 1, ReplySerial: 1, ErrorName: "x"}).validate(); !errors.Is(err, ErrInvalid) {
		t.Error("an error name with one element was accepted")
	}
}

func TestMalformedMessagesAreRefused(t *testing.T) {
	hello := []byte(helloBytes)
	patch := func(at int, b ...byte) []byte {
		out := bytes.Clone(hello)
		copy(out[at:], b)
		return out
	}
	cases := map[string][]byte{
		"empty":                        {},
		"truncated header":             hello[:15],
		"truncated body":               hello[:100],
		"unknown byte order":           patch(0, 'x'),
		"protocol version 2":           patch(3, 2),
		"serial zero":                  patch(8, 0, 0, 0, 0),
		"body longer than sent":        patch(4, 1),
		"fields longer than sent":      patch(12, 0xff),
		"message over 128 MiB":         patch(4, 0, 0, 0, 0x08),
		"non-zero padding":             patch(46, 1),
		"path not NUL-terminated":      patch(45, 'x'),
		"invalid object path":          patch(24, 'x'),
		"path field of type s":         patch(18, 's'),
		"interface given twice":        patch(80, fieldInterface),
		"header field code 0":          patch(96, 0),
		"method call without a member": patch(80, 0x20),
		"invalid member name":          patch(88, '1'),
		"invalid destination":          patch(104, '.'),
		"trailing byte":                append(bytes.Clone(hello), 0),
	}
	for name, data := range cases {
		if m, err := UnmarshalMessage(data, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted as %v (%v)", name, m, err)
		}
	}
	// An unknown header field is skipped, as the specification requires.
	if m, err := UnmarshalMessage(patch(96, 0x20), nil); err != nil || m.Destination != "" {
		t.Errorf("an unknown header field was not skipped: %v %v", m, err)
	}
}

func TestMalformedBodiesAreRefused(t *testing.T) {
	le := binary.LittleEndian
	deep := func(levels int) []byte {
		b := bytes.Repeat([]byte{1, 'v', 0}, levels-1)
		return append(b, 1, 'y', 0, 5)
	}
	type body struct {
		sig  Signature
		data []byte
		fds  []UnixFD
	}
	cases := map[string]body{
		"boolean 2":                   {"b", []byte{2, 0, 0, 0}, nil},
		"invalid UTF-8":               {"s", []byte{1, 0, 0, 0, 0xff, 0}, nil},
		"NUL inside a string":         {"s", []byte{2, 0, 0, 0, 'a', 0, 0}, nil},
		"string without its NUL":      {"s", []byte{1, 0, 0, 0, 'a', 'b'}, nil},
		"string longer than the data": {"s", []byte{0xff, 0xff, 0xff, 0xff, 'a', 0}, nil},
		"invalid object path":         {"o", []byte{2, 0, 0, 0, 'a', '/', 0}, nil},
		"invalid signature":           {"g", []byte{1, 'z', 0}, nil},
		"variant of two types":        {"v", []byte{2, 'i', 'i', 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0}, nil},
		"variant of nothing":          {"v", []byte{0, 0}, nil},
		"array over 64 MiB":           {"ay", []byte{1, 0, 0, 4, 0}, nil},
		"array past the data":         {"ay", []byte{9, 0, 0, 0, 1}, nil},
		"element past its array":      {"ai", []byte{2, 0, 0, 0, 1, 0, 0, 0}, nil},
		"trailing bytes":              {"y", []byte{1, 2}, nil},
		"padding not zero":            {"yu", []byte{1, 9, 0, 0, 1, 0, 0, 0}, nil},
		"descriptor out of range":     {"h", []byte{0, 0, 0, 0}, nil},
		"descriptor used twice":       {"hh", []byte{0, 0, 0, 0, 0, 0, 0, 0}, []UnixFD{5}},
		"dict key twice":              {"a{ss}", dictTwice(), nil},
		"dict key NaN":                {"a{dy}", nanKeyDict(), nil},
		"65 nested variants":          {"v", deep(65), nil},
		"truncated int64":             {"x", []byte{1, 2, 3}, nil},
	}
	for name, c := range cases {
		if got, err := Unmarshal(c.data, le, c.sig, c.fds); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: decoded as %#v (%v)", name, got, err)
		}
	}
	if _, err := Unmarshal(deep(64), le, "v", nil); err != nil {
		t.Errorf("64 nested variants, the most allowed, were refused: %v", err)
	}
}

func nanKeyDict() []byte {
	// The encoder copes with a NaN key a Go map holds; the decoder refuses
	// one, since no lookup could find it.
	data, _, err := Marshal("a{dy}", map[float64]byte{math.NaN(): 1})
	if err != nil {
		panic(err)
	}
	return data
}

func dictTwice() []byte {
	data, _, err := Marshal("a(ss)", []any{[]any{"a", "1"}, []any{"a", "2"}})
	if err != nil {
		panic(err)
	}
	return data // a(ss) and a{ss} are laid out alike
}

func TestSignaturesAreValidated(t *testing.T) {
	good := []string{"", "y", "a{sv}", "(ii)", "a(sa{sv})", "v", "aaai", "a{oa{sa{sv}}}", "(oayays)",
		strings.Repeat("a", 32) + "y", strings.Repeat("(", 32) + "y" + strings.Repeat(")", 32), "ybnqiuxtdsogh"}
	for _, s := range good {
		if err := Signature(s).Validate(); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	bad := []string{"a", "(", "(i", ")", "()", "{ss}", "a{s}", "a{sss}", "a{vs}", "a{(i)s}", "a{ss", "z", "i)",
		strings.Repeat("a", 33) + "y", strings.Repeat("(", 33) + "y" + strings.Repeat(")", 33),
		strings.Repeat("i", 256), "a{s}v", "\x00"}
	for _, s := range bad {
		if err := Signature(s).Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", s)
		}
	}
	if _, err := parseSingle("ii"); err == nil {
		t.Error("two types accepted as one")
	}
}

func TestEncodingFollowsAGivenSignature(t *testing.T) {
	// With a signature, looser Go values are accepted and converted.
	ok := []struct {
		sig  Signature
		val  any
		want any
	}{
		{"u", 5, uint32(5)},
		{"y", int64(255), byte(255)},
		{"x", uint8(3), int64(3)},
		{"d", float32(0.5), 0.5},
		{"s", ObjectPath("/x"), "/x"},
		{"o", "/x", ObjectPath("/x")},
		{"g", "a{sv}", Signature("a{sv}")},
		{"(is)", []any{1, "x"}, []any{int32(1), "x"}},
		{"(is)", [2]any{int32(1), "x"}, []any{int32(1), "x"}},
		{"v", "x", Variant{"s", "x"}},
		{"a{sv}", map[string]any{"n": int32(1)}, map[string]Variant{"n": {"i", int32(1)}}},
		{"s", Variant{"s", "unwrapped"}, "unwrapped"},
		{"s", new(string), ""},
		{"ay", [2]byte{1, 2}, []byte{1, 2}},
	}
	for _, c := range ok {
		data, fds, err := Marshal(c.sig, c.val)
		if err != nil {
			t.Errorf("%q from %T: %v", c.sig, c.val, err)
			continue
		}
		got, err := Unmarshal(data, binary.LittleEndian, c.sig, fds)
		if err != nil || !reflect.DeepEqual(got, []any{c.want}) {
			t.Errorf("%q from %T: got %#v, %v", c.sig, c.val, got, err)
		}
	}
	bad := []struct {
		sig Signature
		val any
	}{
		{"i", "x"}, {"y", 256}, {"n", 40000}, {"u", -1}, {"t", -1}, {"x", uint64(math.MaxUint64)},
		{"s", "a\x00b"}, {"s", "\xff"}, {"o", "relative"}, {"g", "("}, {"h", 3}, {"i", UnixFD(3)},
		{"h", UnixFD(-1)}, {"b", 1}, {"d", 1}, {"(ii)", []any{int32(1)}}, {"(ii)", struct{ A int32 }{1}},
		{"v", Variant{}}, {"v", 1}, {"a{sv}", map[string]any{"n": 1}}, {"as", "x"}, {"a{ss}", []string{}},
		{"s", Variant{"i", int32(1)}}, {"s", (*string)(nil)}, {"s", nil},
	}
	for _, c := range bad {
		if _, _, err := Marshal(c.sig, c.val); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q from %#v was accepted", c.sig, c.val)
		}
	}
	if _, _, err := Marshal("ii", int32(1)); !errors.Is(err, ErrInvalid) {
		t.Error("two types for one value were accepted")
	}
	if _, _, err := Marshal("", 1); !errors.Is(err, ErrInvalid) {
		t.Error("an int's type was inferred")
	}
	if _, _, err := Marshal("ay", make([]byte, MaxArraySize+1)); !errors.Is(err, ErrInvalid) {
		t.Error("an array over 64 MiB was encoded")
	}
	v := MakeVariant(byte(1))
	for range 64 {
		v = MakeVariant(v)
	}
	if _, _, err := Marshal("v", v); !errors.Is(err, ErrInvalid) {
		t.Error("65 nested variants were encoded")
	}
	fds := make([]UnixFD, MaxUnixFDs+1)
	if _, _, err := Marshal("ah", fds); !errors.Is(err, ErrInvalid) {
		t.Error("more descriptors than a message may carry were encoded")
	}
}

func TestMapsEncodeInKeyOrder(t *testing.T) {
	m := map[string]uint32{"c": 3, "a": 1, "b": 2}
	first, _, _ := Marshal("a{su}", m)
	for range 20 {
		again, _, _ := Marshal("a{su}", m)
		if !bytes.Equal(first, again) {
			t.Fatal("the same map encoded two ways")
		}
	}
	if !bytes.Contains(first, []byte("a\x00\x00\x00\x01\x00\x00\x00")) || bytes.Index(first, []byte("a\x00")) > bytes.Index(first, []byte("b\x00")) {
		t.Fatalf("keys are not sorted: % x", first)
	}
}

func TestStoreFillsTypedValues(t *testing.T) {
	type secret struct {
		Session     ObjectPath
		Parameters  []byte
		Value       []byte
		ContentType string
	}
	data, _, err := Marshal("sa{sv}(oayays)a{o(oayays)}aai",
		"label",
		map[string]Variant{"a": {"s", "x"}, "b": {"s", "y"}},
		secret{"/s", nil, []byte("pw"), "text/plain"},
		map[ObjectPath]secret{"/i/1": {"/s", []byte{}, []byte("x"), "t"}},
		[][]int32{{1, 2}, {}})
	if err != nil {
		t.Fatal(err)
	}
	vals, err := Unmarshal(data, binary.LittleEndian, "sa{sv}(oayays)a{o(oayays)}aai", nil)
	if err != nil {
		t.Fatal(err)
	}
	var (
		label   []byte // a string into a byte slice is not allowed...
		attrs   map[string]string
		sec     *secret
		secrets map[ObjectPath]secret
		nested  [][]int64
	)
	if err := Store(vals, &label, &attrs, &sec, &secrets, &nested); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a string was stored in a []byte: %v", err)
	}
	var name string
	if err := Store(vals, &name, &attrs, &sec, &secrets, &nested); err != nil {
		t.Fatal(err)
	}
	if name != "label" || attrs["a"] != "x" || attrs["b"] != "y" || sec == nil || sec.Session != "/s" ||
		string(sec.Value) != "pw" || sec.ContentType != "text/plain" || string(secrets["/i/1"].Value) != "x" ||
		!reflect.DeepEqual(nested, [][]int64{{1, 2}, {}}) {
		t.Fatalf("stored %q %v %+v %+v %v", name, attrs, sec, secrets, nested)
	}

	var (
		i    int
		u8   uint8
		anyv any
		v    Variant
		fd   UnixFD
		arr  [2]string
	)
	for _, c := range []struct {
		src, dst any
		ok       bool
	}{
		{uint32(7), &i, true},
		{int64(300), &u8, false},
		{int32(-1), &u8, false},
		{Variant{"s", "x"}, &anyv, true},
		{"x", &v, true},
		{Variant{"u", uint32(3)}, &i, true},
		{UnixFD(4), &fd, true},
		{UnixFD(4), &i, false},
		{int32(4), &fd, false},
		{[]string{"a", "b"}, &arr, true},
		{[]string{"a"}, &arr, false},
		{[]any{"x"}, &sec, false},
		{true, &i, false},
		{2.5, &i, false},
	} {
		err := Store([]any{c.src}, c.dst)
		if (err == nil) != c.ok {
			t.Errorf("Store(%#v into %T) = %v", c.src, c.dst, err)
		}
	}
	if v != (Variant{"s", "x"}) || fd != 4 || i != 3 && i != 7 {
		t.Errorf("stored v=%v fd=%d i=%d", v, fd, i)
	}
	if err := Store([]any{1}, i); err == nil {
		t.Error("stored into a non-pointer")
	}
	if err := Store([]any{1, 2}, &i); err == nil {
		t.Error("stored two values into one destination")
	}
	var p *int32
	if err := Store([]any{int32(5)}, &p); err != nil || p == nil || *p != 5 {
		t.Errorf("pointer target: %v %v", p, err)
	}
}

func TestNamesAreValidated(t *testing.T) {
	check := func(kind string, f func(string) error, good, bad []string) {
		for _, s := range good {
			if err := f(s); err != nil {
				t.Errorf("%s %q refused: %v", kind, s, err)
			}
		}
		for _, s := range bad {
			if err := f(s); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s %q accepted", kind, s)
			}
		}
	}
	long := strings.Repeat("a", 250) + ".bcdef"
	check("interface", ValidateInterfaceName,
		[]string{"org.freedesktop.DBus", "a.b", "_a._b", "a1.b2"},
		[]string{"", "a", ".a.b", "a.b.", "a..b", "a.1b", "a-b.c", "a.b/c", long})
	check("error", ValidateErrorName,
		[]string{"org.freedesktop.Secret.Error.IsLocked"}, []string{"Failed", "org.x-y.Error"})
	check("member", ValidateMemberName,
		[]string{"Hello", "_x", "GetAll2"},
		[]string{"", "1x", "a.b", "a-b", strings.Repeat("a", 256)})
	check("bus", ValidateBusName,
		[]string{"org.freedesktop.secrets", ":1.42", ":1.2.3", "a-b.c-d", "org.freedesktop.DBus"},
		[]string{"", "org", ":1", ":", ":.1", "1a.b", "a.b.", "a b.c", ":1..2", long})
	check("object path", validateObjectPath,
		[]string{"/", "/a", "/org/freedesktop/secrets/collection/a_1"},
		[]string{"", "a", "//", "/a/", "/a//b", "/a-b", "/a.b", "/é"})
}

func TestPathElementsEscapeReversibly(t *testing.T) {
	for _, s := range []string{"", "login", "My Passwords", "a_b", "é/..", "_", "\x00\xff"} {
		e := EscapePathElement(s)
		if err := validateObjectPath("/" + e); err != nil {
			t.Errorf("%q escaped to %q, not a path element", s, e)
		}
		back, err := UnescapePathElement(e)
		if err != nil || back != s {
			t.Errorf("%q -> %q -> %q, %v", s, e, back, err)
		}
	}
	for _, e := range []string{"", "a_", "a_4", "_41", "_zz", "a-b"} {
		if _, err := UnescapePathElement(e); err == nil {
			t.Errorf("%q unescaped", e)
		}
	}
}
