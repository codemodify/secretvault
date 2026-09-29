package svage

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestBech32AcceptsBIP173ValidChecksums(t *testing.T) {
	for _, s := range []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		"?1ezyfcl",
	} {
		if _, _, err := bech32Values([]byte(s)); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestBech32RefusesBIP173InvalidStrings(t *testing.T) {
	for _, s := range []string{
		"\x201nwldj5", // HRP character out of range
		"\x7f1axkwrx", // HRP character out of range
		"\x801eym55h", // HRP character out of range
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
		"pzry9x0s0muk",  // no separator
		"1pzry9x0s0muk", // empty HRP
		"x1b4n0q5v",     // invalid data character
		"li1dgmt3",      // checksum too short
		"de1lg7wt\xff",  // invalid character in checksum
		"A1G7SGD8",      // checksum computed with an uppercase HRP
		"10a06t8",       // empty HRP
		"1qzzfhee",      // empty HRP
		"a12UEL5L",      // mixed case
	} {
		if _, _, err := bech32Values([]byte(s)); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
}

func TestBech32RoundTripsWithoutALengthLimit(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 33, 1216, 5000} {
		data := bytes.Repeat([]byte{0xa5, 0x5a, 0xff, 0x00}, n/4+1)[:n]
		for _, hrp := range []string{"age1pq", "AGE-SECRET-KEY-PQ-"} {
			s, err := bech32Encode(hrp, data)
			if err != nil {
				t.Fatal(err)
			}
			if hrp == strings.ToUpper(hrp) && s != strings.ToUpper(s) {
				t.Errorf("an uppercase HRP gave %q", s[:20])
			}
			gotHRP, got, err := bech32Decode(s)
			if err != nil || gotHRP != hrp || !bytes.Equal(got, data) {
				t.Errorf("%d bytes under %s: got %q %x, %v", n, hrp, gotHRP, got, err)
			}
		}
	}
	if _, err := bech32Encode("Age", nil); err == nil {
		t.Error("a mixed-case HRP was encoded")
	}
}

func TestBech32RefusesBadPadding(t *testing.T) {
	// A lone 5-bit group cannot hold a byte; two hold one byte and two
	// bits of padding, which must be zero.
	for _, values := range [][]byte{{0}, {1}, {0, 1}} {
		if _, err := convertBits(values, 5, 8, false); err == nil {
			t.Errorf("%v converted", values)
		}
	}
	if b, err := convertBits([]byte{0, 0}, 5, 8, false); err != nil || !bytes.Equal(b, []byte{0}) {
		t.Errorf("{0, 0} = %v, %v", b, err)
	}
}

// The keys quoted in the spec are what this package makes of them.
func TestSpecExampleKeysPairUp(t *testing.T) {
	b, err := os.ReadFile("testdata/spec-keys.txt")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	x, err := ParseX25519Identity(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	if x.String() != lines[0] || x.Recipient().String() != lines[1] {
		t.Errorf("X25519: %s gives %s", lines[0], x.Recipient())
	}
	pq, err := ParseHybridIdentity(lines[2])
	if err != nil {
		t.Fatal(err)
	}
	if pq.String() != lines[2] || pq.Recipient().String() != lines[3] {
		t.Errorf("hybrid: %s gives a different recipient", lines[2])
	}
	for _, s := range lines[4:6] {
		r, err := ParseRecipient(s)
		if err != nil {
			t.Fatalf("%.20s...: %v", s, err)
		}
		if tr, ok := r.(*TagRecipient); !ok || tr.String() != s {
			t.Errorf("%.20s... parses as %T", s, r)
		}
	}
}
