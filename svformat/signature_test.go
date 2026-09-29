package svformat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/codemodify/secretvault/svcrypto"
)

func testKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// checkSignature opens a revision and checks its signature by pub, as a
// reader holding the vault key does.
func checkSignature(file, wrap []byte, pub ed25519.PublicKey) error {
	h, payload, dek, err := OpenRevision(file, wrap)
	if err != nil {
		return err
	}
	defer clear(dek)
	data, err := SignedData(file, dek, payload)
	if err != nil {
		return err
	}
	if !h.Signature.Verify(pub, data) {
		return errors.New("bad signature")
	}
	return nil
}

func TestSignedRevisionsVerify(t *testing.T) {
	key := testKey(0x33)
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		wrap, dek := svcrypto.RandomKey(), svcrypto.RandomKey()
		file, err := SealSignedRevision(testHeader(s), wrap, dek, []byte(`{"name":"github"}`), key)
		if err != nil {
			t.Fatal(err)
		}
		h, err := ParseRevision(file)
		if err != nil {
			t.Fatal(err)
		}
		if h.Signature == nil || h.Signature.Alg != SigEd25519 || h.Signature.Key != DeviceKeyID(pub(key)) || h.Device != (ID{4}) {
			t.Fatalf("%v: signature field %+v", s, h.Signature)
		}
		if err := checkSignature(file, wrap, pub(key)); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		if err := checkSignature(file, wrap, pub(testKey(0x44))); err == nil {
			t.Fatalf("%v: verified with another device's key", s)
		}
		// The payload and content key come back as for any revision.
		if _, payload, got, err := OpenRevision(file, wrap); err != nil || string(payload) != `{"name":"github"}` || !bytes.Equal(got, dek) {
			t.Fatalf("%v: OpenRevision = %q, %v", s, payload, err)
		}
	}
}

func TestUnsignedRevisionsHaveNoSignedData(t *testing.T) {
	wrap, dek := svcrypto.RandomKey(), svcrypto.RandomKey()
	file, _ := SealRevision(testHeader(svcrypto.Modern), wrap, dek, []byte("x"))
	h, _ := ParseRevision(file)
	if h.Signature != nil {
		t.Fatal("an unsigned revision has a signature")
	}
	if _, err := SignedData(file, dek, []byte("x")); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("SignedData of an unsigned revision: %v", err)
	}
	var none *RevisionSignature
	if none.Verify(pub(testKey(1)), nil) {
		t.Fatal("no signature verified")
	}
}

func TestASignedRevisionMustNameItsDevice(t *testing.T) {
	h := testHeader(svcrypto.Modern)
	h.Device = ID{}
	if _, err := SealSignedRevision(h, svcrypto.RandomKey(), svcrypto.RandomKey(), nil, testKey(1)); !errors.Is(err, ErrRevision) {
		t.Fatalf("signed without a device: %v", err)
	}
	wrap := svcrypto.RandomKey()
	file, _ := SealSignedRevision(testHeader(svcrypto.Modern), wrap, svcrypto.RandomKey(), nil, testKey(1))
	noDevice := reseal(t, file, wrap, nil, func(fs []Field) []Field {
		var out []Field
		for _, f := range fs {
			if f.Tag != tagDevice {
				out = append(out, f)
			}
		}
		return out
	})
	if _, err := ParseRevision(noDevice); !errors.Is(err, ErrRevision) {
		t.Fatalf("a signed revision without its device parsed: %v", err)
	}
	for name, v := range map[string][]byte{
		"short":            {SigEd25519, 1, 2},
		"short signature":  append([]byte{SigEd25519}, make([]byte, 16+63)...),
		"long signature":   append([]byte{SigEd25519}, make([]byte, 16+65)...),
		"empty":            {},
		"key id cut short": append([]byte{SigEd25519}, make([]byte, 15)...),
	} {
		bad := reseal(t, file, wrap, nil, func(fs []Field) []Field { return setField(fs, tagSignature, v) })
		if _, err := ParseRevision(bad); !errors.Is(err, ErrRevision) {
			t.Errorf("%s signature field parsed: %v", name, err)
		}
	}
	// An algorithm from a later version parses; it verifies with nothing
	// this version knows.
	later := reseal(t, file, wrap, nil, func(fs []Field) []Field {
		return setField(fs, tagSignature, append([]byte{2}, make([]byte, 16+100)...))
	})
	h2, err := ParseRevision(later)
	if err != nil || h2.Signature == nil || h2.Signature.Alg != 2 {
		t.Fatalf("a later algorithm: %+v, %v", h2.Signature, err)
	}
	if err := checkSignature(later, wrap, pub(testKey(1))); err == nil {
		t.Fatal("a signature of an unknown algorithm verified")
	}
}

// reseal rewrites a revision as someone holding the vault key can: the
// header's fields changed by edit, and the body sealed again under the same
// content key, with payload (or the revision's own, when nil). Such a
// revision opens; only its signature can tell it was changed.
func reseal(t *testing.T, file, wrap, payload []byte, edit func([]Field) []Field) []byte {
	t.Helper()
	h, own, dek, err := OpenRevision(file, wrap)
	if err != nil {
		t.Fatal(err)
	}
	if payload == nil {
		payload = own
	}
	n := int(binary.BigEndian.Uint16(file[6:8]))
	fields, err := DecodeTLV(file[8 : 8+n])
	if err != nil {
		t.Fatal(err)
	}
	fields = edit(fields)
	hdr, err := EncodeTLV(fields)
	if err != nil {
		t.Fatal(err)
	}
	prefix := append([]byte(revisionMagic), byte(h.Suite), 0)
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(hdr)))
	prefix = append(prefix, hdr...)
	body, err := h.Suite.Seal(dek, pad(payload), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return append(prefix, body...)
}

// setField replaces (or adds, in order) one field.
func setField(fields []Field, tag uint8, v []byte) []Field {
	var out []Field
	placed := false
	for _, f := range fields {
		switch {
		case f.Tag == tag:
			out = append(out, Field{tag, v})
			placed = true
			continue
		case f.Tag > tag && !placed:
			out = append(out, Field{tag, v})
			placed = true
		}
		out = append(out, f)
	}
	if !placed {
		out = append(out, Field{tag, v})
	}
	return out
}

func fieldOf(t *testing.T, file []byte, tag uint8) []byte {
	t.Helper()
	n := int(binary.BigEndian.Uint16(file[6:8]))
	fields, _ := DecodeTLV(file[8 : 8+n])
	for _, f := range fields {
		if f.Tag == tag {
			return bytes.Clone(f.Value)
		}
	}
	t.Fatalf("no tag 0x%02x", tag)
	return nil
}

// Whoever holds the vault key can write any revision; what they cannot
// do is make one that verifies as another device's, other than a copy of
// one that device wrote.
func TestASignatureCoversTheHeaderAndThePayload(t *testing.T) {
	key := testKey(0x33)
	wrap := svcrypto.RandomKey()
	file, _ := SealSignedRevision(testHeader(svcrypto.Modern), wrap, svcrypto.RandomKey(), []byte(`{"secret":"a"}`), key)
	if err := checkSignature(file, wrap, pub(key)); err != nil {
		t.Fatal(err)
	}
	// The same content sealed again, as anyone with the key can: it says
	// what the device said, and verifies.
	if err := checkSignature(reseal(t, file, wrap, nil, func(fs []Field) []Field { return fs }), wrap, pub(key)); err != nil {
		t.Fatalf("an honest copy: %v", err)
	}
	other, _ := SealSignedRevision(testHeader(svcrypto.Modern), wrap, svcrypto.RandomKey(), []byte(`{"secret":"b"}`), key)
	tampered := map[string][]byte{
		"other contents": reseal(t, file, wrap, []byte(`{"secret":"forged"}`), func(fs []Field) []Field { return fs }),
		"another time":   reseal(t, file, wrap, nil, func(fs []Field) []Field { return setField(fs, tagTime, make([]byte, 8)) }),
		"other parents":  reseal(t, file, wrap, nil, func(fs []Field) []Field { return setField(fs, tagParents, make([]byte, 32)) }),
		"another device": reseal(t, file, wrap, nil, func(fs []Field) []Field { return setField(fs, tagDevice, bytes.Repeat([]byte{5}, 16)) }),
		"an added field": reseal(t, file, wrap, nil, func(fs []Field) []Field { return setField(fs, 0x90, []byte("x")) }),
		"another revision's signature": reseal(t, file, wrap, nil, func(fs []Field) []Field {
			return setField(fs, tagSignature, fieldOf(t, other, tagSignature))
		}),
		"a flipped bit": reseal(t, file, wrap, nil, func(fs []Field) []Field {
			v := fieldOf(t, file, tagSignature)
			v[40] ^= 1
			return setField(fs, tagSignature, v)
		}),
		"another key's id": reseal(t, file, wrap, nil, func(fs []Field) []Field {
			v := fieldOf(t, file, tagSignature)
			k := DeviceKeyID(pub(testKey(0x44)))
			copy(v[1:], k[:])
			return setField(fs, tagSignature, v)
		}),
	}
	for name, bad := range tampered {
		if err := checkSignature(bad, wrap, pub(key)); err == nil {
			t.Errorf("%s: still verifies", name)
		}
	}
	// And the file itself is authenticated as before: the signature
	// cannot be changed or stripped by someone without the vault key.
	for i := range file {
		bad := bytes.Clone(file)
		bad[i] ^= 0x80
		if _, _, _, err := OpenRevision(bad, wrap); err == nil {
			t.Fatalf("changing byte %d of %d still opened", i, len(file))
		}
	}
}

// A reader written before signatures existed (format M0) knows tags 0x01
// to 0x06 and 0x81, skips optional tags it does not know, and uses the
// whole prefix as the body's associated data. It must open a signed
// revision exactly as it opens any other.
func m0Open(file, wrap []byte) ([]byte, error) {
	if len(file) < 8 || string(file[:4]) != "SVR1" || file[5] != 0 {
		return nil, errors.New("not a revision")
	}
	suite := svcrypto.Suite(file[4])
	n := int(binary.BigEndian.Uint16(file[6:8]))
	fields, err := DecodeTLV(file[8 : 8+n])
	if err != nil {
		return nil, err
	}
	var vault, object ID
	var epoch uint32
	var wrapped []byte
	for _, f := range fields {
		switch f.Tag {
		case 0x01:
			copy(vault[:], f.Value)
		case 0x02:
			copy(object[:], f.Value)
		case 0x03:
			epoch = binary.BigEndian.Uint32(f.Value)
		case 0x04, 0x05, 0x81:
		case 0x06:
			wrapped = f.Value
		default:
			if f.Tag < 0x80 {
				return nil, errors.New("unknown critical tag")
			}
		}
	}
	dek, err := suite.Open(wrap, wrapped, dekAAD(vault, object, epoch))
	if err != nil {
		return nil, err
	}
	padded, err := suite.Open(dek, file[8+n:], file[:8+n])
	if err != nil {
		return nil, err
	}
	return unpad(padded)
}

func TestReadersFromBeforeSignaturesOpenSignedRevisions(t *testing.T) {
	if Critical(tagSignature) {
		t.Fatal("the signature tag is critical: older readers would refuse signed revisions")
	}
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		wrap := svcrypto.RandomKey()
		file, _ := SealSignedRevision(testHeader(s), wrap, svcrypto.RandomKey(), []byte(`{"a":1}`), testKey(7))
		got, err := m0Open(file, wrap)
		if err != nil || string(got) != `{"a":1}` {
			t.Fatalf("%v: an M0 reader got %q, %v", s, got, err)
		}
	}
}

// The golden signed revisions pin the signature's layout: sealing with
// crypto/rand made deterministic and the device key below must reproduce
// them, and every later version must still verify them.
func TestTheGoldenSignedRevisionStillVerifies(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 1)
	wrap := bytes.Repeat([]byte{0x11}, 32)
	dek := bytes.Repeat([]byte{0x22}, 32)
	key := testKey(0x33)
	payload := []byte(`{"kind":"login","name":"example.com","fields":[{"name":"password","type":"concealed","value":"aHVudGVyMg=="}]}`)
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		path := "testdata/revision-signed-" + s.String() + ".hex"
		file, err := SealSignedRevision(testHeader(s), wrap, dek, payload, key)
		if err != nil {
			t.Fatal(err)
		}
		if *update {
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
		if err := checkSignature(want, wrap, pub(key)); err != nil {
			t.Fatalf("%v: the golden signed revision no longer verifies: %v", s, err)
		}
		if got, err := m0Open(want, wrap); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%v: an M0 reader cannot open the golden signed revision: %v", s, err)
		}
		if !bytes.Equal(file, want) {
			t.Errorf("%v: sealing no longer reproduces the golden signed revision byte for byte", s)
		}
	}
	// The key ID is pinned too.
	if got := DeviceKeyID(pub(key)).String(); got != goldenKeyID {
		t.Errorf("DeviceKeyID = %s, want %s", got, goldenKeyID)
	}
}

// goldenKeyID is DeviceKeyID of the golden device key (seed 32 × 0x33,
// public key 17cb79fb…80ce), as Python's hashlib and cryptography compute
// it.
const goldenKeyID = "bb01ccccfed954348b5f424b1a95677e"
