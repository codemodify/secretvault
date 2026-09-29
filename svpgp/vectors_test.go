package svpgp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test vectors of RFC 9580, appendix A. The armored blocks are in
// testdata/rfc9580, copied from the RFC text.

func vector(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "rfc9580", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorKey(t testing.TB, name string) *Key {
	t.Helper()
	k, err := ReadKey(bytes.NewReader(vector(t, name)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return k
}

// dearmored returns the binary contents of an armored vector.
func dearmored(t testing.TB, name string) []byte {
	t.Helper()
	block, err := Dearmor(bytes.NewReader(vector(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(block.Body); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func password() ([]byte, error) { return []byte("password"), nil }

// A.1 and A.2: the version 4 Ed25519Legacy key and its signature over
// "OpenPGP", checked down to the hashed data and the deterministic EdDSA
// signature value.
func TestRFC9580SampleV4Ed25519LegacyKeyAndSignature(t *testing.T) {
	k := vectorKey(t, "a1-v4-ed25519legacy-key.asc")
	if got, want := k.Fingerprint(), unhex(t, "C959BDBAFA32A2F89A153B678CFDE12197965A9A"); !bytes.Equal(got, want) {
		t.Fatalf("fingerprint %X, want %X", got, want)
	}
	pk := k.primary.pub
	if pk.version != 4 || pk.alg != EdDSALegacy || pk.curve != curveEd25519Legacy {
		t.Fatalf("parsed as v%d %v on %v", pk.version, pk.alg, pk.curve)
	}
	if want := unhex(t, "3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406"); !bytes.Equal(pk.ed, want) {
		t.Fatalf("public key %x", pk.ed)
	}
	if got := unhex(t, "98 33 04 53 f3 5f 0b 16 09 2b 06 01 04 01 da 47 0f 01 01 07 40 3f 09 89 94 bd d9 16 ed 40 53 19 79 34 e4 a8 7c 80 73 3a 12 80 d6 2f 80 10 99 2e 43 ee 3b 24 06"); !bytes.Equal(got, packetBytesLegacy(t, pk.body)) {
		t.Fatal("public key packet differs")
	}
	// The secret key D derives the public key.
	seed := unhex(t, "1a8b1ff05ded48e18bf50166c664ab023ea70003d78d9e41f5758a91d850f8d2")
	if priv := ed25519.NewKeyFromSeed(seed); !bytes.Equal(priv[32:], pk.ed) {
		t.Fatal("D does not derive q")
	}

	sigBin := dearmored(t, "a2-v4-ed25519legacy-sig.asc")
	wantPacket := unhex(t, `88 5e 04 00 16 08 00 06 05 02 55 f9 5f 95 00 0a 09 10 8c fd e1 21 97 96 5a 9a f6 22 00 ff 56 f9
		0c ca 98 e2 10 26 37 bd 98 3f db 16 c1 31 df d2 7e d8 2b f4 dd e5 60 6e 0d 75 6a ed 33 66 01 00
		d0 9c 4f a1 15 27 f0 38 e0 f5 7f 22 01 d8 2f 2e a2 c9 03 32 65 fa 6c eb 48 9e 85 4b ae 61 b4 04`)
	if !bytes.Equal(sigBin, wantPacket) {
		t.Fatalf("signature packet differs:\n% x", sigBin)
	}
	s, err := parseSignature(sigBin[2:], 0)
	if err != nil {
		t.Fatal(err)
	}
	c := newSigChecker(s)
	c.Write([]byte("OpenPGP"))
	s.writeTrailer(c.h)
	digest := c.h.Sum(nil)
	if want := unhex(t, "f6220a3f757814f4c2176ffbb68b00249cd4ccdc059c4b34ad871f30b1740280"); !bytes.Equal(digest, want) {
		t.Fatalf("digest %x", digest)
	}
	if want := sha256.Sum256(unhex(t, "4f70656e504750040016080006050255f95f9504ff0000000c")); !bytes.Equal(digest, want[:]) {
		t.Fatal("digest is not over the RFC's hash input m")
	}
	if err := s.verifyDigest(pk, digest); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	// EdDSA is deterministic: signing the same digest gives the RFC's r
	// and s.
	body := append(append([]byte{}, pk.body...), 0)
	material := appendMPI(nil, seed)
	body = append(body, material...)
	body = append(body, byte(checksum16(material)>>8), byte(checksum16(material)))
	sk, err := parseSecretKey(body, ptSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sk.sign(SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, s.material) {
		t.Fatalf("signing gave\n% x\nwant\n% x", got, s.material)
	}
	// Through the public API: the signature is by the key, but the key has
	// no self-signature, so nothing binds it and the signature is not
	// valid.
	results, err := Verify(strings.NewReader("OpenPGP"), bytes.NewReader(vector(t, "a2-v4-ed25519legacy-sig.asc")), []*Key{k}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	r := results[0]
	if r.Valid || !errors.Is(r.Err, ErrKeyInvalid) || !bytes.Equal(r.SigningKey, k.Fingerprint()) {
		t.Fatalf("result %+v", r)
	}
	if !r.CreatedAt.Equal(time.Date(2015, 9, 16, 12, 24, 53, 0, time.UTC)) || r.Hash != SHA256 {
		t.Fatalf("result %+v", r)
	}
}

// packetBytesLegacy frames a public key body the way A.1 shows it: a legacy
// header with a one-octet length.
func packetBytesLegacy(t testing.TB, body []byte) []byte {
	return append([]byte{0x98, byte(len(body))}, body...)
}

// A.3: the version 6 certificate, down to the data its two self-signatures
// hash (A.3.1).
func TestRFC9580SampleV6Certificate(t *testing.T) {
	k := vectorKey(t, "a3-v6-cert.asc")
	if got, want := k.Fingerprint(), unhex(t, "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"); !bytes.Equal(got, want) {
		t.Fatalf("fingerprint %X", got)
	}
	if k.Version() != 6 || k.Algorithm() != Ed25519 || k.KeyID() != 0xCB186C4F0609A697 {
		t.Fatalf("v%d %v %X", k.Version(), k.Algorithm(), k.KeyID())
	}
	subs := k.Subkeys()
	if len(subs) != 1 {
		t.Fatalf("%d subkeys", len(subs))
	}
	if want := unhex(t, "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"); !bytes.Equal(subs[0].Fingerprint, want) {
		t.Fatalf("subkey fingerprint %X", subs[0].Fingerprint)
	}
	if subs[0].Err != nil || !subs[0].CanEncrypt || subs[0].CanSign || subs[0].Algorithm != X25519 {
		t.Fatalf("subkey %+v", subs[0])
	}
	if err := k.Valid(time.Now()); err != nil {
		t.Fatalf("the certificate is not valid: %v", err)
	}
	if err := k.Valid(time.Date(2022, 11, 30, 16, 8, 2, 0, time.UTC)); err == nil {
		t.Fatal("the certificate is valid before it was made")
	}
	if len(k.UserIDs()) != 0 || k.Revoked() || !k.ExpiresAt().IsZero() || k.HasSecret() {
		t.Fatal("unexpected user IDs, revocation, expiry or secret")
	}
	// The direct key signature's preferences.
	dks := k.sigs[0]
	if !bytes.Equal(dks.prefSymmetric, []byte{9, 7}) || !bytes.Equal(dks.prefAEAD, []byte{9, 2, 7, 2}) || dks.flags() != 3 || dks.features[0] != 9 {
		t.Fatalf("direct key signature preferences %+v", dks)
	}

	dksData := unhex(t, `10 3e 2d 7d 22 7e c0 e6 d7 ce 44 71 db 36 bf c9 70 83 25 36 90 27 14 98 a7 ef 05 76 c0 7f aa e1
		9b 00 00 00 2a 06 63 87 7f e3 1b 00 00 00 20 f9 4d a7 bb 48 d6 0a 61 e5 67 70 6a 65 87 d0 33 19
		99 bb 9d 89 1a 08 24 2e ad 84 54 3d f8 95 a3 06 1f 1b 0a 00 00 00 42 05 82 63 87 7f e3 03 0b 09
		07 05 15 0a 0e 08 0c 02 16 00 02 9b 03 02 1e 09 22 21 06 cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c
		72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 05 27 09 02 07 02 06 ff 00 00 00 4a`)
	want := sha512.Sum512(dksData)
	got, err := keySignatureDigest(dks, k.primary.pub, nil, nil, false)
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("direct key signature digest %x, %v", got, err)
	}
	bindingData := unhex(t, `a6 e9 18 6d 9d 59 35 fc 8f e5 63 14 cd b5 27 48 6a 5a 51 20 f9 b7 62 a2 35 a7 29 f0 39 01 0a 56
		9b 00 00 00 2a 06 63 87 7f e3 1b 00 00 00 20 f9 4d a7 bb 48 d6 0a 61 e5 67 70 6a 65 87 d0 33 19
		99 bb 9d 89 1a 08 24 2e ad 84 54 3d f8 95 a3 9b 00 00 00 2a 06 63 87 7f e3 19 00 00 00 20 86 93
		24 83 67 f9 e5 01 5d b9 22 f8 f4 80 95 dd a7 84 98 7f 2d 59 85 b1 2f ba d1 6c af 5e 44 35 06 18
		1b 0a 00 00 00 2c 05 82 63 87 7f e3 02 9b 0c 22 21 06 cb 18 6c 4f 06 09 a6 97 e4 d5 2d fa 6c 72
		2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 06 ff 00 00 00 34`)
	want = sha512.Sum512(bindingData)
	sub := k.subkeys[0]
	got, err = keySignatureDigest(sub.sigs[0], k.primary.pub, sub.pub, nil, false)
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("subkey binding digest %x, %v", got, err)
	}
	// Written out again, the certificate is byte for byte the same.
	var out bytes.Buffer
	if err := k.Serialize(&out, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), dearmored(t, "a3-v6-cert.asc")) {
		t.Fatal("the certificate does not round-trip")
	}
	armored, err := k.Armor(false)
	if err != nil || bytes.Contains(armored, []byte("\n=")) {
		t.Fatalf("armored v6 key carries a CRC24 line or failed: %v\n%s", err, armored)
	}
	again, err := ReadKey(bytes.NewReader(armored))
	if err != nil || !bytes.Equal(again.Fingerprint(), k.Fingerprint()) {
		t.Fatalf("armored key does not read back: %v", err)
	}
}

// A.4: the unprotected version 6 secret key.
func TestRFC9580SampleV6SecretKey(t *testing.T) {
	k := vectorKey(t, "a4-v6-secret-key.asc")
	if !k.HasSecret() || k.Locked() {
		t.Fatal("the secret key is not usable as read")
	}
	if want := unhex(t, "4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8"); !bytes.Equal(k.subkeys[0].sec.secret.Bytes(), want) {
		t.Fatalf("subkey secret %x", k.subkeys[0].sec.secret.Bytes())
	}
	var out bytes.Buffer
	if err := k.Serialize(&out, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), dearmored(t, "a4-v6-secret-key.asc")) {
		t.Fatal("the secret key does not round-trip")
	}
	out.Reset()
	if err := k.Public().Serialize(&out, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), dearmored(t, "a3-v6-cert.asc")) {
		t.Fatal("the public half is not the certificate of A.3")
	}
	if err := k.Public().Serialize(&out, true); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("serializing a public key as secret: %v", err)
	}
}

// A.5: the same key locked with AEAD (OCB) and Argon2, with the
// intermediate values. Argon2 here uses 2 GiB, as the RFC's parameters say.
func TestRFC9580SampleLockedV6SecretKey(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 2 GiB of memory per Argon2 run")
	}
	k := vectorKey(t, "a5-v6-locked-secret-key.asc")
	if !k.Locked() {
		t.Fatal("the key is not locked")
	}
	primary, sub := k.primary.sec, k.subkeys[0].sec
	if primary.prot.usage != usageAEAD || primary.prot.aead != OCB || primary.prot.cipher != AES256 || primary.prot.s2k.typ != s2kArgon2 {
		t.Fatalf("protection %+v", primary.prot)
	}
	pass := []byte("correct horse battery staple")
	// Intermediate data for the primary key (A.5.1).
	derived, err := primary.prot.s2k.derive(pass, 32, true, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "832bd2662a5c2b251ee3fc82aec349a766ca539015880133002e5a21960b3bcf"); !bytes.Equal(derived, want) {
		t.Fatalf("primary S2K output %x", derived)
	}
	if want := unhex(t, "c50663877fe31b00000020f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3"); !bytes.Equal(append([]byte{0xC5}, primary.pub.body...), want) {
		t.Fatal("primary key additional data differs")
	}
	if want := unhex(t, "c70663877fe319000000208693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435"); !bytes.Equal(append([]byte{0xC7}, sub.pub.body...), want) {
		t.Fatal("subkey additional data differs")
	}
	if err := k.Unlock([]byte("incorrect horse")); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	if !k.Locked() {
		t.Fatal("a failed unlock left the key unlocked")
	}
	if err := k.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	plain := vectorKey(t, "a4-v6-secret-key.asc")
	if !bytes.Equal(primary.secret.Bytes(), plain.primary.sec.secret.Bytes()) || !bytes.Equal(sub.secret.Bytes(), plain.subkeys[0].sec.secret.Bytes()) {
		t.Fatal("unlocked material differs from A.4")
	}
	// Still locked on the wire, and lockable again without a passphrase.
	var out bytes.Buffer
	if err := k.Serialize(&out, true); err != nil || !bytes.Equal(out.Bytes(), dearmored(t, "a5-v6-locked-secret-key.asc")) {
		t.Fatalf("the locked key does not round-trip: %v", err)
	}
	if err := k.Lock(nil, nil); err != nil || !k.Locked() {
		t.Fatalf("relocking: %v", err)
	}
}

// A.5.2's subkey intermediate values, checked separately since each costs
// a 2 GiB Argon2 run.
func TestRFC9580SampleLockedSubkeyIntermediates(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 2 GiB of memory")
	}
	k := vectorKey(t, "a5-v6-locked-secret-key.asc")
	sub := k.subkeys[0].sec
	derived, err := sub.prot.s2k.derive([]byte("correct horse battery staple"), 32, true, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "f74a6ce873a089ef13a3da9ac059777bb22340d15eaa6c9dc0f8ef09035c67cd"); !bytes.Equal(derived, want) {
		t.Fatalf("subkey S2K output %x", derived)
	}
}

// A.6: the cleartext signed message, with its dash-escaped lines.
func TestRFC9580SampleCleartextSignedMessage(t *testing.T) {
	cert := vectorKey(t, "a3-v6-cert.asc")
	msg, err := VerifyInline(bytes.NewReader(vector(t, "a6-cleartext.asc")), []*Key{cert}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n"; string(msg.Body) != want {
		t.Fatalf("body %q", msg.Body)
	}
	if !msg.Cleartext || len(msg.Signatures) != 1 {
		t.Fatalf("%+v", msg)
	}
	r := msg.Signatures[0]
	if !r.Valid || r.Err != nil || r.Key != cert || !bytes.Equal(r.SigningKey, cert.Fingerprint()) || r.Hash != SHA512 || r.Version != 6 || r.Type != SigText {
		t.Fatalf("result %+v", r)
	}
	if !r.CreatedAt.Equal(time.Date(2022, 12, 13, 16, 8, 3, 0, time.UTC)) {
		t.Fatalf("created %v", r.CreatedAt)
	}
	// The hashed data of the example, byte for byte.
	data := unhex(t, `76 49 5f 50 21 88 90 f7 f5 e2 ee 3c 18 22 51 4f 70 50 0f 55 1d 86 e5 c9 21 e4 04 e3 4a 53 fb ac
		57 68 61 74 20 77 65 20 6e 65 65 64 20 66 72 6f 6d 20 74 68 65 20 67 72 6f 63 65 72 79 20 73 74
		6f 72 65 3a 0d 0a 0d 0a 2d 20 74 6f 66 75 0d 0a 2d 20 76 65 67 65 74 61 62 6c 65 73 0d 0a 2d 20
		6e 6f 6f 64 6c 65 73 0d 0a 06 01 1b 0a 00 00 00 29 05 82 63 98 a3 63 22 21 06 cb 18 6c 4f 06 09
		a6 97 e4 d5 2d fa 6c 72 2b 0c 1f 1e 27 c1 8a 56 70 8f 65 25 ec 27 ba d9 ac c9 06 ff 00 00 00 31`)
	sum := sha512.Sum512(data)
	if want := unhex(t, "69365bf44a97af1f0844f1f6ab83fdf6b36f26692efaa621a8aac91c4e29ea07e894cabc6e2f20eedfce6c03b89141a2cc7cbe245e6e7a5654addbec5000b89b"); !bytes.Equal(sum[:], want) {
		t.Fatal("the RFC's hashed data does not give its digest")
	}
	// Without the certificate the signer is unknown.
	msg, err = VerifyInline(bytes.NewReader(vector(t, "a6-cleartext.asc")), nil, time.Time{})
	if err != nil || msg.Signatures[0].Valid || !errors.Is(msg.Signatures[0].Err, ErrUnknownSigner) {
		t.Fatalf("with no keyring: %v %+v", err, msg)
	}
	// A changed line fails.
	changed := bytes.Replace(vector(t, "a6-cleartext.asc"), []byte("- - tofu"), []byte("- - tempeh"), 1)
	msg, err = VerifyInline(bytes.NewReader(changed), []*Key{cert}, time.Time{})
	if err != nil || msg.Signatures[0].Valid || !errors.Is(msg.Signatures[0].Err, ErrBadSignature) {
		t.Fatalf("changed text: %v %+v", err, msg.Signatures)
	}
}

// A.7: the same signature, inline.
func TestRFC9580SampleInlineSignedMessage(t *testing.T) {
	cert := vectorKey(t, "a3-v6-cert.asc")
	msg, err := VerifyInline(bytes.NewReader(vector(t, "a7-inline-signed.asc")), []*Key{cert}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n"; string(msg.Body) != want {
		t.Fatalf("body %q", msg.Body)
	}
	if msg.Format != 'u' || msg.Encrypted || len(msg.Signatures) != 1 || !msg.Signatures[0].Valid {
		t.Fatalf("%+v", msg)
	}
}

// A.8: X25519 with a v6 PKESK and a v2 SEIPD packet in OCB mode, with the
// intermediate session key.
func TestRFC9580SampleX25519AEADOCBMessage(t *testing.T) {
	k := vectorKey(t, "a4-v6-secret-key.asc")
	msg, err := Decrypt(bytes.NewReader(vector(t, "a8-x25519-aead-ocb.asc")), []*Key{k}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Body) != "Hello, world!" || msg.Format != 'b' {
		t.Fatalf("body %q", msg.Body)
	}
	if !msg.Encrypted || !msg.IntegrityProtected || msg.SEIPDVersion != 2 || msg.Cipher != AES128 || msg.AEAD != OCB {
		t.Fatalf("%+v", msg)
	}
	if msg.DecryptedWith != k || !bytes.Equal(msg.DecryptionKey, k.subkeys[0].pub.fp) {
		t.Fatal("wrong decryption key reported")
	}
	// The session key itself (A.8.2).
	bin := dearmored(t, "a8-x25519-aead-ocb.asc")
	p, err := parsePKESK(bin[2 : 2+0x5d])
	if err != nil {
		t.Fatal(err)
	}
	_, sessionKey, err := p.decrypt(k.subkeys[0].sec, AES128)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex(t, "dd708f6fa1ed65114d68d2343e7c2f1d"); !bytes.Equal(sessionKey, want) {
		t.Fatalf("session key %x", sessionKey)
	}
	// The primary key cannot decrypt it; a public key cannot either.
	if _, err := Decrypt(bytes.NewReader(vector(t, "a8-x25519-aead-ocb.asc")), []*Key{k.Public()}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("with only the public key: %v", err)
	}
}

// A.9 to A.11: passphrase-encrypted v2 SEIPD messages in EAX, OCB and GCM.
func TestRFC9580SampleAEADPassphraseMessages(t *testing.T) {
	for _, c := range []struct {
		file string
		mode AEADAlgorithm
	}{
		{"a9-aead-eax.asc", EAX},
		{"a10-aead-ocb.asc", OCB},
		{"a11-aead-gcm.asc", GCM},
	} {
		msg, err := Decrypt(bytes.NewReader(vector(t, c.file)), nil, password)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if string(msg.Body) != "Hello, world!" || msg.AEAD != c.mode || msg.Cipher != AES128 || msg.SEIPDVersion != 2 || msg.DecryptedWith != nil {
			t.Fatalf("%s: %+v", c.file, msg)
		}
		if _, err := Decrypt(bytes.NewReader(vector(t, c.file)), nil, func() ([]byte, error) { return []byte("pa55word"), nil }); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("%s: a wrong passphrase gave %v", c.file, err)
		}
		if _, err := Decrypt(bytes.NewReader(vector(t, c.file)), nil, nil); !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: no passphrase gave %v", c.file, err)
		}
	}
	// The session keys of A.9.2, A.10.2 and A.11.2.
	for _, c := range []struct{ file, key string }{
		{"a9-aead-eax.asc", "3881bafe985412459b86c36f98cb9a5e"},
		{"a10-aead-ocb.asc", "28e79ab82397d3c63de24ac217d7b791"},
		{"a11-aead-gcm.asc", "1936fc8568980274bb900d8319360c77"},
	} {
		bin := dearmored(t, c.file)
		s, err := parseSKESK(bin[2 : 2+int(bin[1])])
		if err != nil {
			t.Fatal(err)
		}
		_, key, err := s.decrypt([]byte("password"), AES128, DefaultLimits)
		if err != nil || !bytes.Equal(key, unhex(t, c.key)) {
			t.Fatalf("%s: session key %x, %v", c.file, key, err)
		}
	}
}

// A.12: v4 SKESK packets with Argon2 before v1 SEIPD packets, for each AES
// key size. Each Argon2 run uses 2 GiB.
func TestRFC9580SampleArgon2Messages(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 2 GiB of memory per message")
	}
	for _, c := range []struct {
		file       string
		cipher     CipherAlgorithm
		sessionKey string
	}{
		{"a12-1-argon2-aes128.asc", AES128, "01FE16BBACFD1E7B78EF3B865187374F"},
		{"a12-2-argon2-aes192.asc", AES192, "27006DAE68E509022CE45A14E569E91001C2955AF8DFE194"},
		{"a12-3-argon2-aes256.asc", AES256, "BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEFC13BAB2F1F8E18FB74580D8B0"},
	} {
		block, err := Dearmor(bytes.NewReader(vector(t, c.file)))
		if err != nil {
			t.Fatal(err)
		}
		if got := block.Headers["Comment"]; len(got) < 2 {
			t.Fatalf("%s: armor headers %v", c.file, block.Headers)
		}
		bin := dearmored(t, c.file)
		s, err := parseSKESK(bin[2 : 2+int(bin[1])])
		if err != nil {
			t.Fatal(err)
		}
		alg, key, err := s.decrypt([]byte("password"), 0, DefaultLimits)
		if err != nil || alg != c.cipher || !bytes.Equal(key, unhex(t, c.sessionKey)) {
			t.Fatalf("%s: session key %v %X, %v", c.file, alg, key, err)
		}
		msg, err := ReadMessage(bytes.NewReader(bin), ReadOptions{Passphrase: password})
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if string(msg.Body) != "Hello, world!" || msg.Cipher != c.cipher || msg.SEIPDVersion != 1 {
			t.Fatalf("%s: %+v", c.file, msg)
		}
	}
}
