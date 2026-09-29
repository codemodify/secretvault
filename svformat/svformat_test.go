package svformat

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func TestTLVIsCanonical(t *testing.T) {
	fields := []Field{{1, []byte("a")}, {2, nil}, {0x90, []byte("zz")}}
	b, err := EncodeTLV(fields)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTLV(b)
	if err != nil || len(got) != 3 || string(got[2].Value) != "zz" || got[2].Tag != 0x90 {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err := EncodeTLV([]Field{{2, nil}, {1, nil}}); !errors.Is(err, ErrTLV) {
		t.Errorf("out-of-order fields encoded: %v", err)
	}
	if _, err := EncodeTLV([]Field{{1, nil}, {1, nil}}); !errors.Is(err, ErrTLV) {
		t.Errorf("a repeated tag encoded: %v", err)
	}
	for name, bad := range map[string][]byte{
		"truncated header": {1, 0},
		"value past end":   {1, 0, 5, 'a'},
		"out of order":     {2, 0, 0, 1, 0, 0},
		"repeated":         {1, 0, 0, 1, 0, 0},
	} {
		if _, err := DecodeTLV(bad); !errors.Is(err, ErrTLV) {
			t.Errorf("%s decoded: %v", name, err)
		}
	}
}

func testHeader(s svcrypto.Suite) RevisionHeader {
	return RevisionHeader{
		Suite:   s,
		Vault:   ID{1},
		Object:  ID{2},
		Epoch:   1,
		Time:    time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC).UnixNano(),
		Parents: []RevID{{9}, {3}, {9}}, // unsorted, repeated: sealing normalises
		Device:  ID{4},
	}
}

func TestRevisionsRoundTrip(t *testing.T) {
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		wrap, dek := svcrypto.RandomKey(), svcrypto.RandomKey()
		file, err := SealRevision(testHeader(s), wrap, dek, []byte(`{"name":"github"}`))
		if err != nil {
			t.Fatal(err)
		}
		h, err := ParseRevision(file)
		if err != nil {
			t.Fatal(err)
		}
		if h.Vault != (ID{1}) || h.Object != (ID{2}) || h.Device != (ID{4}) || h.Epoch != 1 || len(h.Parents) != 2 || h.Parents[0] != (RevID{3}) {
			t.Fatalf("header did not round-trip: %+v", h)
		}
		_, payload, gotDEK, err := OpenRevision(file, wrap)
		if err != nil || string(payload) != `{"name":"github"}` || !bytes.Equal(gotDEK, dek) {
			t.Fatalf("OpenRevision = %q, %v", payload, err)
		}
		if _, _, _, err := OpenRevision(file, svcrypto.RandomKey()); !errors.Is(err, svcrypto.ErrOpen) {
			t.Errorf("opened with another wrap key: %v", err)
		}
	}
}

func TestEveryByteOfARevisionIsAuthenticated(t *testing.T) {
	wrap := svcrypto.RandomKey()
	file, _ := SealRevision(testHeader(svcrypto.Modern), wrap, svcrypto.RandomKey(), []byte("x"))
	for i := range file {
		bad := bytes.Clone(file)
		bad[i] ^= 0x80
		if _, _, _, err := OpenRevision(bad, wrap); err == nil {
			t.Fatalf("changing byte %d of %d still opened", i, len(file))
		}
	}
}

func TestAWrappedKeyCannotMoveToAnotherObject(t *testing.T) {
	wrap, dek := svcrypto.RandomKey(), svcrypto.RandomKey()
	a, _ := SealRevision(testHeader(svcrypto.Modern), wrap, dek, []byte("a"))
	ha, _ := ParseRevision(a)
	// Build a revision for another object that reuses a's wrapped key.
	h := testHeader(svcrypto.Modern)
	h.Object = ID{7}
	b, _ := SealRevision(h, wrap, dek, []byte("b"))
	hb, _ := ParseRevision(b)
	moved := bytes.Replace(b, hb.wrapped, ha.wrapped, 1)
	if _, _, _, err := OpenRevision(moved, wrap); !errors.Is(err, svcrypto.ErrOpen) {
		t.Fatalf("a wrapped key moved to another object opened: %v", err)
	}
}

func TestUnknownCriticalTagsAreRefusedAndOptionalOnesSkipped(t *testing.T) {
	file, _ := SealRevision(testHeader(svcrypto.Modern), svcrypto.RandomKey(), svcrypto.RandomKey(), nil)
	h, _ := ParseRevision(file)
	withTag := func(tag uint8) []byte {
		fields, _ := DecodeTLV(file[8 : 8+(int(file[6])<<8|int(file[7]))])
		fields = append(fields, Field{tag, []byte{1}})
		for i := len(fields) - 1; i > 0 && fields[i].Tag < fields[i-1].Tag; i-- {
			fields[i], fields[i-1] = fields[i-1], fields[i]
		}
		hdr, _ := EncodeTLV(fields)
		out := append([]byte(revisionMagic), byte(h.Suite), 0, byte(len(hdr)>>8), byte(len(hdr)))
		return append(out, hdr...)
	}
	if _, err := ParseRevision(withTag(0x20)); !errors.Is(err, ErrRevision) {
		t.Errorf("an unknown critical tag was accepted: %v", err)
	}
	if _, err := ParseRevision(withTag(0x90)); err != nil {
		t.Errorf("an unknown optional tag was refused: %v", err)
	}
}

func TestMalformedRevisionsAreRefused(t *testing.T) {
	file, _ := SealRevision(testHeader(svcrypto.Modern), svcrypto.RandomKey(), svcrypto.RandomKey(), nil)
	for name, bad := range map[string][]byte{
		"empty":       nil,
		"wrong magic": append([]byte("SVR2"), file[4:]...),
		"bad suite":   append(append([]byte{}, file[:4]...), append([]byte{99}, file[5:]...)...),
		"reserved":    append(append([]byte{}, file[:5]...), append([]byte{1}, file[6:]...)...),
		"short":       file[:10],
	} {
		if _, err := ParseRevision(bad); !errors.Is(err, ErrRevision) && !errors.Is(err, ErrTLV) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPaddingHidesExactSizes(t *testing.T) {
	last := 0
	for n := 0; n < 70000; n += 37 {
		p := pad(make([]byte, n))
		if len(p) < n+4 || len(p) < last {
			t.Fatalf("pad(%d) = %d bytes", n, len(p))
		}
		last = len(p)
		got, err := unpad(p)
		if err != nil || len(got) != n {
			t.Fatalf("unpad(pad(%d)) = %d, %v", n, len(got), err)
		}
	}
	// Small payloads are indistinguishable by size.
	if len(pad(nil)) != len(pad(make([]byte, 200))) {
		t.Error("small payloads differ in padded size")
	}
	// Overhead stays within Padmé's ~12%.
	if n := 1 << 20; len(pad(make([]byte, n))) > n+n/8 {
		t.Errorf("padding of 1 MiB is %d bytes", len(pad(make([]byte, n))))
	}
	bad := pad([]byte("x"))
	bad[len(bad)-1] = 1
	if _, err := unpad(bad); err == nil {
		t.Error("non-zero padding accepted")
	}
}

// The golden revision pins the v1 byte layout. With crypto/rand made
// deterministic, sealing must reproduce it exactly, and opening it must keep
// working in every future version.
func TestTheGoldenRevisionStillOpens(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	wrap := bytes.Repeat([]byte{0x11}, 32)
	dek := bytes.Repeat([]byte{0x22}, 32)
	payload := []byte(`{"kind":"login","name":"example.com","fields":[{"name":"password","type":"concealed","value":"aHVudGVyMg=="}]}`)
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		path := "testdata/revision-" + s.String() + ".hex"
		file, err := SealRevision(testHeader(s), wrap, dek, payload)
		if err != nil {
			t.Fatal(err)
		}
		if *update {
			os.MkdirAll("testdata", 0o755)
			if err := os.WriteFile(path, []byte(hex.EncodeToString(file)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		golden, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test ./svformat -update once to create it)", err)
		}
		want, err := hex.DecodeString(strings.TrimSpace(string(golden)))
		if err != nil {
			t.Fatal(err)
		}
		_, got, _, err := OpenRevision(want, wrap)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%v: the golden revision no longer opens: %v", s, err)
		}
		if !bytes.Equal(file, want) {
			t.Errorf("%v: sealing no longer reproduces the golden revision byte for byte", s)
		}
	}
}

func TestRecoveryKeysSurviveBeingTypedBack(t *testing.T) {
	key := svcrypto.RandomKey()
	text := EncodeRecoveryKey(key)
	if !strings.HasPrefix(text, "SVRK1-") {
		t.Fatalf("recovery key %q", text)
	}
	got, err := ParseRecoveryKey(text)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("round trip: %v", err)
	}
	sloppy := strings.ToLower(strings.ReplaceAll(text, "-", " "))
	sloppy = strings.ReplaceAll(sloppy, "o", "0")
	if got, err := ParseRecoveryKey(sloppy); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("sloppy typing refused: %q: %v", sloppy, err)
	}
	// Change one character of the key part.
	body := []byte(text)
	i := len(recoveryPrefix) + 3
	if body[i] == 'A' {
		body[i] = 'B'
	} else {
		body[i] = 'A'
	}
	if _, err := ParseRecoveryKey(string(body)); !errors.Is(err, ErrRecoveryKey) {
		t.Errorf("a typo was accepted: %v", err)
	}
}

func TestUnsealKeysAndSharesAreTheirOwnForms(t *testing.T) {
	key := svcrypto.RandomKey()
	text := EncodeUnsealKey(key)
	if !strings.HasPrefix(text, "SVUK1-") {
		t.Fatalf("unseal key %q", text)
	}
	if got, err := ParseUnsealKey(strings.ToLower(text) + "\n"); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("round trip: %v", err)
	}
	// The same bytes as a recovery key, or with no prefix, are not an
	// unseal key; nor is an unseal key a recovery key.
	if _, err := ParseUnsealKey(EncodeRecoveryKey(key)); !errors.Is(err, ErrUnsealKey) {
		t.Errorf("a recovery key parsed as an unseal key: %v", err)
	}
	if _, err := ParseUnsealKey(strings.TrimPrefix(text, "SVUK1-")); !errors.Is(err, ErrUnsealKey) {
		t.Errorf("an unseal key without its prefix parsed: %v", err)
	}
	if _, err := ParseRecoveryKey(text); err == nil {
		t.Error("an unseal key parsed as a recovery key")
	}

	shares, err := svcrypto.SplitSecret(key, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	st := EncodeUnsealShare(shares[1], 2)
	if !strings.HasPrefix(st, "SVUS1-") {
		t.Fatalf("unseal share %q", st)
	}
	got, k, err := ParseUnsealShare(strings.ReplaceAll(st, "-", " "))
	if err != nil || k != 2 || !bytes.Equal(got, shares[1]) {
		t.Fatalf("share round trip: %v (k %d)", err, k)
	}
	if _, _, err := ParseUnsealShare(EncodeRecoveryShare(shares[1], 2)); !errors.Is(err, ErrUnsealShare) {
		t.Errorf("a recovery share parsed as an unseal share: %v", err)
	}
	if _, _, err := ParseRecoveryShare(st); !errors.Is(err, ErrRecoveryShare) {
		t.Errorf("an unseal share parsed as a recovery share: %v", err)
	}
	typo := []byte(st)
	i := len(unsealSharePrefix) + 4
	if typo[i] == 'A' {
		typo[i] = 'C'
	} else {
		typo[i] = 'A'
	}
	if _, _, err := ParseUnsealShare(string(typo)); !errors.Is(err, ErrUnsealShare) {
		t.Errorf("a typo was accepted: %v", err)
	}
}

func TestIdentitiesAndRecipientsHaveTextForms(t *testing.T) {
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		id, _ := s.NewIdentity()
		priv, _ := id.Bytes()
		gs, gpriv, err := ParseIdentity(EncodeIdentity(s, priv))
		if err != nil || gs != s || !bytes.Equal(gpriv, priv) {
			t.Fatalf("%v identity: %v", s, err)
		}
		rs, pub, err := ParseRecipient(EncodeRecipient(s, id.Recipient()))
		if err != nil || rs != s || !bytes.Equal(pub, id.Recipient()) {
			t.Fatalf("%v recipient: %v", s, err)
		}
	}
	if _, _, err := ParseRecipient("sv-recipient-1-modern-AAAA"); err == nil {
		t.Error("a garbage recipient parsed")
	}
}

func TestNamesRoundTrip(t *testing.T) {
	obj, rev := NewID(), RevID{0xab}
	o, r, ok := ParseRevisionName(RevisionName(obj, rev))
	if !ok || o != obj || r != rev {
		t.Fatal("revision name did not round-trip")
	}
	for _, bad := range []string{"objects/xx/" + obj.String() + "/" + rev.String() + ".svr", "slots/x.json", "objects/a/b"} {
		if _, _, ok := ParseRevisionName(bad); ok {
			t.Errorf("%q parsed as a revision name", bad)
		}
	}
	slot := NewID()
	if got, ok := ParseSlotName(SlotName(slot)); !ok || got != slot {
		t.Fatal("slot name did not round-trip")
	}
}

func TestSlotsAndDescriptorsAreChecked(t *testing.T) {
	if _, err := ParseSlot([]byte(`{"format":"secretvault/v1/slot","type":"passphrase"}`)); !errors.Is(err, ErrSlot) {
		t.Errorf("an incomplete slot parsed: %v", err)
	}
	if _, _, err := ParseDescriptor([]byte(`{"format":"secretvault/v2"}`)); !errors.Is(err, ErrDescriptor) {
		t.Errorf("a v2 descriptor parsed: %v", err)
	}
	s := &Slot{Vault: ID{1}, ID: ID{2}, Epoch: 1, Type: SlotPassphrase, Label: "main", Grants: []string{GrantContent}}
	a := s.AAD()
	s.Label = "other"
	if bytes.Equal(a, s.AAD()) {
		t.Error("a slot's label is not in its AAD")
	}
}
