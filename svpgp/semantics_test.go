package svpgp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Finer points of the rules: MPI encodings, which format a message gets,
// user IDs retired after a signature, anonymous recipients.

func TestMPIsAreExactInVersion6AndOnlyPaddedToWholeBytesBefore(t *testing.T) {
	cases := []struct {
		wire       []byte
		v6, v4, ok bool
	}{
		{[]byte{0, 1, 1}, true, true, true},       // 1, exactly
		{[]byte{0, 9, 1, 0xFF}, true, true, true}, // 511, exactly
		{[]byte{0, 0}, true, true, true},          // zero
		{[]byte{0, 2, 1}, false, false, true},     // overstated by a bit
		{[]byte{0, 8, 1}, false, true, true},      // every bit of the octet counted (GnuPG's opaque MPIs)
		{[]byte{0, 16, 0, 1}, false, true, true},  // two octets, a leading zero one
		{[]byte{0, 8, 0xFF}, true, true, true},    // exactly, and all octets
		{[]byte{0, 7, 0xFF}, false, false, true},  // understated
		{[]byte{0, 9, 1}, false, false, false},    // runs past the end
	}
	for _, c := range cases {
		for _, strict := range []bool{true, false} {
			p := newParser(c.wire)
			p.mpi(strict)
			p.done()
			want := c.v4
			if strict {
				want = c.v6
			}
			if (p.err == nil) != want {
				t.Errorf("% x strict=%v: %v", c.wire, strict, p.err)
			}
		}
	}
}

func TestMessagesGetAFormatEveryRecipientReads(t *testing.T) {
	v6 := generate(t, KeyOptions{Version: 6})
	v4 := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Four"}})
	// A version 6 key that says it reads only v2 SEIPD.
	onlyV2 := generate(t, KeyOptions{Version: 6})
	dks, err := selfSignature(onlyV2.primary, SigDirectKey, onlyV2.CreatedAt(), func(b *subpacketBuilder) {
		b.add(spKeyFlags, true, flagCertify|flagSign)
		b.add(spFeatures, false, featureSEIPDv2)
	}, onlyV2.primary.pub, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	onlyV2.sigs = []*signature{dks}
	armored, _ := onlyV2.Armor(false)
	onlyV2Pub, err := ReadKey(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		recipients []*Key
		format     EncryptFormat
		want       int // SEIPD version, or 0 for refused
	}{
		{"v6 alone", []*Key{v6.Public()}, FormatAuto, 2},
		{"v4 alone", []*Key{v4.Public()}, FormatAuto, 1},
		{"v6 and v4", []*Key{v6.Public(), v4.Public()}, FormatAuto, 1},
		{"v6 forced to v1", []*Key{v6.Public()}, FormatV1, 1},
		{"v4 forced to v2", []*Key{v4.Public()}, FormatV2, 0},
		{"v2-only alone", []*Key{onlyV2Pub}, FormatAuto, 2},
		{"v2-only forced to v1", []*Key{onlyV2Pub}, FormatV1, 0},
		{"v2-only and v4", []*Key{onlyV2Pub, v4.Public()}, FormatAuto, 0},
	} {
		var out bytes.Buffer
		w, err := Encrypt(&out, c.recipients, EncryptOptions{Format: c.format})
		if c.want == 0 {
			if err == nil {
				t.Errorf("%s: encrypted anyway", c.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		io.WriteString(w, "x")
		w.Close()
		m, err := Decrypt(bytes.NewReader(out.Bytes()), []*Key{v6, v4}, nil)
		if c.name == "v2-only alone" {
			m, err = Decrypt(bytes.NewReader(out.Bytes()), []*Key{onlyV2}, nil)
		}
		if err != nil || m.SEIPDVersion != c.want {
			t.Fatalf("%s: %v %+v", c.name, err, m)
		}
	}
}

func TestAUserIDRetiredLaterStillCoversEarlierSignatures(t *testing.T) {
	start := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Old Name <old@example.org>"}, Created: start})
	msg := "signed under the old name"
	before := signed(t, k, msg, SignOptions{Time: start.Add(time.Hour)})
	id := k.identities[0]
	rev, err := selfSignature(k.primary, SigCertRevocation, start.Add(2*time.Hour), func(b *subpacketBuilder) {
		b.add(spRevocationReason, false, append([]byte{32}, "moved on"...)...)
	}, k.primary.pub, nil, id.raw)
	if err != nil {
		t.Fatal(err)
	}
	id.sigs = append(id.sigs, rev)
	armored, _ := k.Armor(false)
	pub, err := ReadKey(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.UserIDs()) != 0 {
		t.Fatalf("a revoked user ID is still listed: %q", pub.UserIDs())
	}
	results, err := Verify(strings.NewReader(msg), bytes.NewReader(before), []*Key{pub}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Valid {
		t.Fatalf("a signature made before the user ID was retired: %+v", results[0])
	}
	// After the retirement the (version 4) key has no self-signature left
	// to describe it, so it cannot sign.
	after := forceSign(t, k, msg, start.Add(150*time.Minute))
	results, _ = Verify(strings.NewReader(msg), bytes.NewReader(after), []*Key{pub}, time.Time{})
	if results[0].Valid || !errors.Is(results[0].Err, ErrKeyInvalid) {
		t.Fatalf("a signature after the only user ID was retired: %+v", results[0])
	}
}

func TestAnonymousRecipientsAreFound(t *testing.T) {
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Hidden"}})
		other := generate(t, KeyOptions{Version: v, UserIDs: []string{"Other"}})
		ct := encrypted(t, []*Key{k.Public()}, "for whoever can read it", EncryptOptions{})
		pr := newPacketReader(bytes.NewReader(ct))
		_, body, err := pr.next()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := body.readAll(maxPacketSize)
		rest := ct[len(packetBytes(ptPKESK, data)):]
		var anon []byte
		if v == 4 {
			// Version 3 PKESK: a key ID of zeros.
			anon = append([]byte{3}, make([]byte, 8)...)
			anon = append(anon, data[9:]...)
		} else {
			// Version 6 PKESK: no fingerprint at all.
			n := int(data[1])
			anon = append([]byte{6, 0}, data[2+n:]...)
		}
		hidden := append(packetBytes(ptPKESK, anon), rest...)
		m, err := Decrypt(bytes.NewReader(hidden), []*Key{other, k}, nil)
		if err != nil || string(m.Body) != "for whoever can read it" || m.DecryptedWith != k {
			t.Fatalf("v%d: %v", v, err)
		}
		if _, err := Decrypt(bytes.NewReader(hidden), []*Key{other}, nil); !errors.Is(err, ErrNoKey) {
			t.Fatalf("v%d: another key: %v", v, err)
		}
	}
}
