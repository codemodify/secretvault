package svpgp

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What must fail, fails: changed signatures and ciphertexts, wrong keys,
// weak or unknown algorithms, malformed and oversized input, bombs. And
// nothing panics.

func TestEveryChangeToASignatureIsCaught(t *testing.T) {
	msg := "the terms are agreed"
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Signer"}})
		pub := k.Public()
		sig := signed(t, k, msg, SignOptions{})
		// The unhashed subpacket area is, by design, not covered: changing
		// it may leave the signature valid, and nothing in it is trusted.
		s, err := parseSignature(sig[2:], 0)
		if err != nil {
			t.Fatal(err)
		}
		unhashedStart := 2 + len(s.hashedPrefix()) + 2
		if v == 6 {
			unhashedStart += 2
		}
		unhashedEnd := unhashedStart + len(s.unhashed)
		for i := range sig {
			for _, bit := range []byte{0x01, 0x80} {
				bad := bytes.Clone(sig)
				bad[i] ^= bit
				results, err := Verify(strings.NewReader(msg), bytes.NewReader(bad), []*Key{pub}, time.Time{})
				if err != nil {
					continue // no longer parses as a signature at all
				}
				for _, r := range results {
					if r.Valid && (i < unhashedStart || i >= unhashedEnd) {
						t.Fatalf("v%d: flipping bit %02x of byte %d left the signature valid", v, bit, i)
					}
				}
			}
		}
		// Every truncation fails too.
		for n := 0; n < len(sig); n++ {
			results, err := Verify(strings.NewReader(msg), bytes.NewReader(sig[:n]), []*Key{pub}, time.Time{})
			if err == nil {
				for _, r := range results {
					if r.Valid {
						t.Fatalf("v%d: a signature cut to %d bytes is valid", v, n)
					}
				}
			}
		}
	}
}

func TestEveryChangeToACiphertextIsCaught(t *testing.T) {
	msg := "meet at the old mill at midnight"
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Recipient"}})
		for _, signer := range []*Key{nil, k} {
			ct := encrypted(t, []*Key{k.Public()}, msg, EncryptOptions{Signer: signer})
			for i := range ct {
				for _, bit := range []byte{0x01, 0x80} {
					bad := bytes.Clone(ct)
					bad[i] ^= bit
					m, err := Decrypt(bytes.NewReader(bad), []*Key{k}, nil)
					if err == nil {
						t.Fatalf("v%d: flipping bit %02x of byte %d of %d still decrypts, to %q", v, bit, i, len(ct), m.Body)
					}
				}
			}
			for n := 0; n < len(ct); n++ {
				if _, err := Decrypt(bytes.NewReader(ct[:n]), []*Key{k}, nil); err == nil {
					t.Fatalf("v%d: a ciphertext cut to %d bytes decrypts", v, n)
				}
			}
		}
	}
}

// The failures a decryption reports do not say where it failed: a bad MDC,
// a bad AEAD tag and a bad session key all look the same.
func TestDecryptionFailuresAreIndistinguishable(t *testing.T) {
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Recipient"}})
		ct := encrypted(t, []*Key{k.Public()}, strings.Repeat("x", 5000), EncryptOptions{})
		// Change the last byte (MDC or final tag) and a byte in the
		// middle of the data.
		for _, i := range []int{len(ct) - 1, len(ct) - 2000} {
			bad := bytes.Clone(ct)
			bad[i] ^= 0x40
			if _, err := Decrypt(bytes.NewReader(bad), []*Key{k}, nil); !errors.Is(err, ErrDecryption) || err.Error() != ErrDecryption.Error() {
				t.Fatalf("v%d: byte %d: %v", v, i, err)
			}
		}
	}
}

func TestWrongKeysDoNotDecryptOrVerify(t *testing.T) {
	alice := generate(t, KeyOptions{Version: 6})
	bob := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Bob"}})
	ct := encrypted(t, []*Key{alice.Public()}, "for alice", EncryptOptions{})
	if _, err := Decrypt(bytes.NewReader(ct), []*Key{bob}, nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("bob decrypting alice's message: %v", err)
	}
	// A PKESK that names Bob's subkey but holds a session key for someone
	// else gives no session key, not garbage.
	bin := encrypted(t, []*Key{bob.Public()}, "for bob", EncryptOptions{})
	pr := newPacketReader(bytes.NewReader(bin))
	_, body, _ := pr.next()
	data, _ := body.readAll(maxPacketSize)
	p, err := parsePKESK(data)
	if err != nil {
		t.Fatal(err)
	}
	p.keyID = alice.subkeys[0].pub.keyID
	p.alg = alice.subkeys[0].pub.alg
	if _, _, err := p.decrypt(alice.subkeys[0].sec, 0); err == nil {
		t.Fatal("a session key for another key decrypted")
	}
	// Verification by the wrong key: unknown signer, not bad or good.
	sig := signed(t, alice, "hello", SignOptions{})
	results, err := Verify(strings.NewReader("hello"), bytes.NewReader(sig), []*Key{bob.Public()}, time.Time{})
	if err != nil || results[0].Valid || !errors.Is(results[0].Err, ErrUnknownSigner) {
		t.Fatalf("%+v %v", results, err)
	}
	// Locked keys say so.
	locked := generate(t, KeyOptions{Version: 6, Passphrase: []byte("pw")})
	armored, _ := locked.Armor(true)
	locked, _ = ReadKey(bytes.NewReader(armored))
	ct = encrypted(t, []*Key{locked.Public()}, "x", EncryptOptions{})
	if _, err := Decrypt(bytes.NewReader(ct), []*Key{locked}, nil); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("decrypting with a locked key: %v", err)
	}
}

// Signatures that verify but must not count: weak hashes, a critical
// subpacket nobody understands, a one-pass packet that does not match,
// intended recipients outside encryption.
func TestPolicyRefusesSignaturesThatVerify(t *testing.T) {
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Signer"}})
	pub := k.Public()
	msg := "policy"
	sign := func(h HashAlgorithm, created time.Time, extra func(*subpacketBuilder)) []byte {
		t.Helper()
		tmpl := &signature{version: 4, typ: SigBinary, alg: k.primary.pub.alg, hash: h, created: created}
		var hashed subpacketBuilder
		hashed.addTime(spCreationTime, true, timeField(created))
		hashed.add(spIssuerFingerprint, false, append([]byte{4}, k.primary.pub.fp...)...)
		if extra != nil {
			extra(&hashed)
		}
		tmpl.hashed = hashed
		hh, err := tmpl.newHash()
		if err != nil {
			t.Fatal(err)
		}
		hh.Write([]byte(msg))
		tmpl.writeTrailer(hh)
		digest := hh.Sum(nil)
		sp, err := k.primary.sec.parts()
		if err != nil {
			t.Fatal(err)
		}
		defer sp.wipe()
		raw := ed25519.Sign(sp.ed, digest)
		material := appendMPI(appendMPI(nil, raw[:32]), raw[32:])
		s, err := assembleSignature(4, SigBinary, tmpl.alg, h, tmpl.hashed, nil, nil, digest[:2], material)
		if err != nil {
			t.Fatal(err)
		}
		return packetBytes(ptSignature, s.body)
	}
	verify := func(sig []byte) SignatureResult {
		t.Helper()
		results, err := Verify(strings.NewReader(msg), bytes.NewReader(sig), []*Key{pub}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return results[0]
	}
	now := time.Now()
	if r := verify(sign(SHA512, now, nil)); !r.Valid {
		t.Fatalf("the control signature is not valid: %+v", r)
	}
	unknownCritical := func(b *subpacketBuilder) { b.add(99, true, 1, 2, 3) }
	if r := verify(sign(SHA512, now, unknownCritical)); r.Valid || !errors.Is(r.Err, ErrSignatureMalformed) {
		t.Fatalf("unknown critical subpacket: %+v", r)
	}
	unknownPlain := func(b *subpacketBuilder) { b.add(99, false, 1, 2, 3) }
	if r := verify(sign(SHA512, now, unknownPlain)); !r.Valid {
		t.Fatalf("an unknown non-critical subpacket should be ignored: %+v", r)
	}
	criticalNotation := func(b *subpacketBuilder) {
		b.add(spNotation, true, append([]byte{0x80, 0, 0, 0, 0, 3, 0, 1}, "a@bx"...)...)
	}
	if r := verify(sign(SHA512, now, criticalNotation)); r.Valid {
		t.Fatalf("a critical notation was accepted: %+v", r)
	}
	expiring := func(b *subpacketBuilder) { b.addTime(spSigExpiration, true, 60) }
	if r := verify(sign(SHA512, now.Add(-2*time.Minute), expiring)); r.Valid || !errors.Is(r.Err, ErrSignatureExpired) {
		t.Fatalf("expired signature: %+v", r)
	}
	recipient := func(b *subpacketBuilder) {
		b.add(spIntendedRecipient, false, append([]byte{4}, pub.Fingerprint()...)...)
	}
	if r := verify(sign(SHA512, now, recipient)); r.Valid || !errors.Is(r.Err, ErrNotIntendedRecipient) {
		t.Fatalf("intended recipients outside encryption: %+v", r)
	}
	// MD5 is refused even though the signature is otherwise fine: the hash
	// byte is changed, which also breaks the signature, but the reason
	// given is the hash.
	sig := sign(SHA512, now, nil)
	s, _ := parseSignature(sig[2:], 0)
	s.hash = MD5
	if r := newSigChecker(s).result(&verifyContext{keyring: []*Key{pub}, now: now}); r.Valid || !errors.Is(r.Err, ErrWeakAlgorithm) {
		t.Fatalf("MD5: %+v", r)
	}
	// SHA-1: not after the cutoff (and Ed25519 needs 256 bits anyway).
	s.hash = SHA1
	if err := s.hashPolicy(); err == nil {
		t.Fatal("SHA-1 after the cutoff passed the policy")
	}
	s.created = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.hashPolicy(); err != nil {
		t.Fatal("SHA-1 before the cutoff failed the policy")
	}
	s.version = 6
	if err := s.hashPolicy(); err == nil {
		t.Fatal("SHA-1 in a version 6 signature passed the policy")
	}

	// A signature that verifies but does not match its one-pass packet.
	inline := signed(t, k, msg, SignOptions{Mode: SignInline})
	i := bytes.IndexByte(inline, 0xC4) // the one-pass packet
	bad := bytes.Clone(inline)
	bad[i+2+2] = byte(SHA256) // its hash algorithm
	m, err := VerifyInline(bytes.NewReader(bad), []*Key{pub}, time.Time{})
	if err != nil || m.Signatures[0].Valid || !errors.Is(m.Signatures[0].Err, ErrSignatureMalformed) {
		t.Fatalf("mismatched one-pass signature: %v %+v", err, m)
	}
	// A one-pass signature whose signature packet was cut off.
	j := -1
	for p := range inline {
		if inline[p] == 0xC2 && p+1 < len(inline) && p+2+int(inline[p+1]) == len(inline) {
			j = p
		}
	}
	if j < 0 {
		t.Fatal("no signature packet at the end of the inline message")
	}
	if _, err := VerifyInline(bytes.NewReader(inline[:j]), []*Key{pub}, time.Time{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a signed message without its signature: %v", err)
	}
}

func TestUnsupportedAlgorithmsAreRefusedClearly(t *testing.T) {
	// Keys: Ed448 and X448 in version 6, a brainpool curve, an RSA key that
	// is too small.
	ed448 := append([]byte{6}, 0x63, 0x87, 0x7f, 0xe3, byte(Ed448), 0, 0, 0, 57)
	ed448 = append(ed448, make([]byte, 57)...)
	// A key that parses but uses an algorithm this package does not
	// implement is read, so it can be listed, and refused for any use.
	edKey, err := ReadKey(bytes.NewReader(packetBytes(ptPublicKey, ed448)))
	if err != nil || !errors.Is(edKey.Valid(time.Now()), ErrUnsupported) {
		t.Fatalf("Ed448 key: %v", err)
	}
	if _, err := Encrypt(io.Discard, []*Key{edKey}, EncryptOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("encrypting to an Ed448 key: %v", err)
	}
	x448 := append([]byte{6}, 0x63, 0x87, 0x7f, 0xe3, byte(X448), 0, 0, 0, 56)
	x448 = append(x448, make([]byte, 56)...)
	if pk, _, err := parsePublicKey(x448, false); err != nil || !errors.Is(pk.unusable, ErrUnsupported) {
		t.Fatalf("X448 key: %v", err)
	}
	// A key that cannot even be delimited is skipped.
	if _, err := ReadKeys(bytes.NewReader(packetBytes(ptPublicKey, []byte{3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1}))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("version 3 key: %v", err)
	}
	bp := []byte{4, 0x63, 0x87, 0x7f, 0xe3, byte(ECDSA), 9, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}
	bp = appendMPI(bp, append([]byte{4}, make([]byte, 64)...))
	pk, _, err := parsePublicKey(bp, false)
	if err != nil || !errors.Is(pk.unusable, ErrUnsupported) || !strings.Contains(pk.unusable.Error(), "brainpoolP256r1") {
		t.Fatalf("brainpool key: %v %v", err, pk.unusable)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaBody := appendBigMPI(appendBigMPI([]byte{4, 0x63, 0x87, 0x7f, 0xe3, byte(RSA)}, small.N), big.NewInt(int64(small.E)))
	pk, _, err = parsePublicKey(rsaBody, false)
	if err != nil || !errors.Is(pk.unusable, ErrUnsupported) {
		t.Fatalf("1024-bit RSA key: %v %v", err, pk.unusable)
	}
	// Ciphers: Camellia and IDEA are refused; CAST5 and TripleDES decrypt.
	for _, c := range []CipherAlgorithm{Camellia128, IDEA, 42} {
		if _, err := c.newBlock(make([]byte, 16)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%v: %v", c, err)
		}
	}
	for _, c := range []CipherAlgorithm{TripleDES, CAST5, Blowfish, Twofish} {
		if _, err := c.newBlock(make([]byte, c.KeySize())); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if _, err := OCB.newAEAD(c, make([]byte, c.KeySize())); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%v accepted in AEAD mode: %v", c, err)
		}
	}
	// Hashes: MD5 and RIPEMD-160 never.
	for _, h := range []HashAlgorithm{MD5, RIPEMD160, 99} {
		if _, err := h.newHash(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%v: %v", h, err)
		}
	}
}

// oldMessage builds a passphrase message with a v4 SKESK and the given
// cipher, in a v1 SEIPD packet, or an SED packet when sed is set.
func oldMessage(t *testing.T, cipher CipherAlgorithm, sed bool, pass, plain string) []byte {
	t.Helper()
	spec := &s2k{typ: s2kIterated, hash: SHA256, salt: []byte("saltsalt"), count: 96}
	key, err := spec.derive([]byte(pass), cipher.KeySize(), false, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	out := packetBytes(ptSKESK, append([]byte{4, byte(cipher)}, spec.bytes()...))
	var inner bytes.Buffer
	if err := writeLiteral(&inner, false, "", strings.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if !sed {
		var seipd bytes.Buffer
		w, err := newSEIPDv1Writer(&seipd, cipher, key)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(inner.Bytes())
		w.Close()
		return append(out, seipd.Bytes()...)
	}
	block, _ := cipher.newBlock(key)
	bs := block.BlockSize()
	prefix := make([]byte, bs+2)
	rand.Read(prefix[:bs])
	prefix[bs], prefix[bs+1] = prefix[bs-2], prefix[bs-1]
	ct := make([]byte, bs+2+inner.Len())
	newCFB(block, make([]byte, bs), false).XORKeyStream(ct[:bs+2], prefix)
	newCFB(block, ct[2:bs+2], false).XORKeyStream(ct[bs+2:], inner.Bytes())
	return append(out, packetBytes(ptSED, ct)...)
}

func TestOldCiphersDecryptWithAWarningAndUnprotectedDataIsRefused(t *testing.T) {
	pass := func() ([]byte, error) { return []byte("old"), nil }
	for _, c := range []CipherAlgorithm{CAST5, TripleDES, Blowfish, Twofish, AES128} {
		m, err := Decrypt(bytes.NewReader(oldMessage(t, c, false, "old", "from 2005")), nil, pass)
		if err != nil || string(m.Body) != "from 2005" || m.Cipher != c || !m.IntegrityProtected {
			t.Fatalf("%v: %v %+v", c, err, m)
		}
		if c.legacy() != (len(m.Warnings) > 0) {
			t.Fatalf("%v: warnings %q", c, m.Warnings)
		}
	}
	sed := oldMessage(t, CAST5, true, "old", "from 1999")
	if _, err := Decrypt(bytes.NewReader(sed), nil, pass); !errors.Is(err, ErrUnprotected) {
		t.Fatalf("SED: %v", err)
	}
	m, err := ReadMessage(bytes.NewReader(sed), ReadOptions{Passphrase: pass, AllowUnprotected: true})
	if err != nil || string(m.Body) != "from 1999" || m.IntegrityProtected || len(m.Warnings) < 2 {
		t.Fatalf("SED allowed: %v %+v", err, m)
	}
	// Camellia is refused.
	camellia := packetBytes(ptSKESK, append([]byte{4, byte(Camellia128)}, (&s2k{typ: s2kIterated, hash: SHA256, salt: make([]byte, 8), count: 96}).bytes()...))
	camellia = append(camellia, packetBytes(ptSEIPD, append([]byte{1}, make([]byte, 64)...))...)
	if _, err := Decrypt(bytes.NewReader(camellia), nil, pass); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Camellia: %v", err)
	}
}

func TestMalformedAndOversizedPacketsAreRefused(t *testing.T) {
	cases := map[string][]byte{
		"not a packet":                    []byte("\x00\x01\x02"),
		"reserved tag 0":                  {0xC0, 0x01, 0x00},
		"length past the end":             {0xCB, 0x20, 'b', 0, 0, 0, 0, 0},
		"partial length on a signature":   {0xC2, 0xE9, 1, 2},
		"truncated 5-octet length":        {0xCB, 0xFF, 0, 0},
		"unknown critical packet":         packetBytes(30, []byte("x")),
		"two literals":                    append(packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00a")), packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00b"))...),
		"trust packet in a message":       append(packetBytes(ptTrust, []byte("x")), packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00a"))...),
		"literal with a bad format":       packetBytes(ptLiteral, []byte("z\x00\x00\x00\x00\x00a")),
		"session keys and no data":        packetBytes(ptSKESK, append([]byte{4, 9}, (&s2k{typ: s2kIterated, hash: SHA256, salt: make([]byte, 8)}).bytes()...)),
		"compressed as uncompressed":      packetBytes(ptCompressed, []byte{0, 1, 2, 3}),
		"signature only (detached)":       signed(t, generate(t, KeyOptions{}), "x", SignOptions{}),
		"literal after encrypted message": append(encrypted(t, nil, "x", EncryptOptions{Passphrase: []byte("p"), Format: FormatV1}), packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00a"))...),
	}
	for name, data := range cases {
		if _, err := ReadMessage(bytes.NewReader(data), ReadOptions{Passphrase: func() ([]byte, error) { return []byte("p"), nil }}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unknown non-critical packets, markers and padding are ignored.
	ok := append(packetBytes(ptMarker, []byte("PGP")), packetBytes(60, []byte("private"))...)
	ok = append(ok, packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00hi"))...)
	ok = append(ok, packetBytes(ptPadding, []byte("pad"))...)
	if m, err := ReadMessage(bytes.NewReader(ok), ReadOptions{}); err != nil || string(m.Body) != "hi" {
		t.Fatalf("ignorable packets: %v", err)
	}
	// A huge packet is refused from its header, before it is read.
	huge := io.MultiReader(bytes.NewReader([]byte{0xC2, 0xFF, 0x40, 0, 0, 0}), zeroReader{})
	if _, err := Verify(strings.NewReader(""), huge, nil, time.Time{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("a 1 GiB signature packet: %v", err)
	}
	huge = io.MultiReader(bytes.NewReader([]byte{0xC6, 0xFF, 0x40, 0, 0, 0}), zeroReader{})
	if _, err := ReadKeys(huge); !errors.Is(err, ErrLimit) {
		t.Fatalf("a 1 GiB key packet: %v", err)
	}
	// A literal packet bigger than the message limit.
	small := &Limits{MaxMessageSize: 1 << 20}
	big := io.MultiReader(bytes.NewReader([]byte{0xCB, 0xFF, 0x7F, 0, 0, 0, 'b', 0, 0, 0, 0, 0}), zeroReader{})
	if _, err := ReadMessage(big, ReadOptions{Limits: small}); !errors.Is(err, ErrLimit) {
		t.Fatalf("a 2 GiB literal: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestDecompressionBombsAndDeepNestingAreStopped(t *testing.T) {
	// BZip2: 93 bytes that expand to a 64 MiB literal packet. The ratio
	// check stops it long before the size check would.
	bz, err := os.ReadFile(filepath.Join("testdata", "literal-64MiB-zeros.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	bomb := packetBytes(ptCompressed, append([]byte{byte(BZip2)}, bz...))
	_, err = ReadMessage(bytes.NewReader(bomb), ReadOptions{})
	if !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "ratio") {
		t.Fatalf("bzip2 bomb: %v", err)
	}
	// ZLIB: a 64 MiB literal in about 64 KiB, stopped by the size limit.
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte{0xCB, 0xFF, 0x04, 0, 0, 0, 'b', 0, 0, 0, 0, 0})
	zw.Write(make([]byte, 64<<20-6))
	zw.Close()
	bomb = packetBytes(ptCompressed, append([]byte{byte(ZLIB)}, z.Bytes()...))
	if _, err = ReadMessage(bytes.NewReader(bomb), ReadOptions{Limits: &Limits{MaxMessageSize: 16 << 20}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("zlib bomb: %v", err)
	}
	// With room for it, the same message reads.
	m, err := ReadMessage(bytes.NewReader(bomb), ReadOptions{})
	if err != nil || len(m.Body) != 64<<20-6 {
		t.Fatalf("zlib message within the limits: %v", err)
	}
	// Compression inside compression inside ... is cut off.
	inner := packetBytes(ptLiteral, []byte("b\x00\x00\x00\x00\x00deep"))
	for range 12 {
		var c bytes.Buffer
		w, _ := compressor(&c, ZIP)
		w.Write(inner)
		w.Close()
		inner = c.Bytes()
	}
	if _, err := ReadMessage(bytes.NewReader(inner), ReadOptions{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("12 levels of compression: %v", err)
	}
	if m, err := ReadMessage(bytes.NewReader(inner), ReadOptions{Limits: &Limits{MaxNesting: 16}}); err != nil || string(m.Body) != "deep" {
		t.Fatalf("12 levels with a higher limit: %v", err)
	}
	// Encrypted data is only accepted as the outermost layer: inside
	// compressed data, or inside other encrypted data, it is refused.
	k := generate(t, KeyOptions{})
	once := encrypted(t, []*Key{k.Public()}, "x", EncryptOptions{Format: FormatV1})
	var outer bytes.Buffer
	c, _ := compressor(&outer, ZIP)
	c.Write(once)
	c.Close()
	if _, err := Decrypt(bytes.NewReader(outer.Bytes()), []*Key{k}, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("encrypted data inside compressed data: %v", err)
	}
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	esk, err := encryptSessionKey(3, k.subkeys[0].pub, AES256, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	var twice bytes.Buffer
	twice.Write(packetBytes(ptPKESK, esk))
	w, _ := newSEIPDv1Writer(&twice, AES256, sessionKey)
	w.Write(once)
	w.Close()
	if _, err := Decrypt(bytes.NewReader(twice.Bytes()), []*Key{k}, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("encrypted data inside encrypted data: %v", err)
	}
}

func TestArmorIsCheckedStrictly(t *testing.T) {
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Armor"}})
	good, _ := k.Armor(false)
	if _, err := ReadKey(bytes.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(good), "\n")
	crcLine := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "=") {
			crcLine = i
		}
	}
	if crcLine < 0 {
		t.Fatal("no CRC line in a v4 key's armor")
	}
	// A wrong CRC is refused; no CRC is fine.
	bad := slicesClone(lines)
	sum := []byte(bad[crcLine])
	if sum[1] == 'A' {
		sum[1] = 'B'
	} else {
		sum[1] = 'A'
	}
	bad[crcLine] = string(sum)
	if _, err := ReadKey(strings.NewReader(strings.Join(bad, "\n"))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("wrong CRC: %v", err)
	}
	noCRC := append(slicesClone(lines[:crcLine]), lines[crcLine+1:]...)
	if _, err := ReadKey(strings.NewReader(strings.Join(noCRC, "\n"))); err != nil {
		t.Fatalf("no CRC: %v", err)
	}
	// A changed data character is caught by the CRC.
	data := slicesClone(lines)
	b := []byte(data[3])
	b[10] ^= 1
	data[3] = string(b)
	if _, err := ReadKey(strings.NewReader(strings.Join(data, "\n"))); err == nil {
		t.Fatal("changed armor data accepted")
	}
	// Leading text, CR LF line endings and trailing whitespace are fine.
	crlf := "Here is my key:\r\n\r\n" + strings.ReplaceAll(string(good), "\n", "  \r\n")
	if _, err := ReadKey(strings.NewReader(crlf)); err != nil {
		t.Fatalf("CR LF armor: %v", err)
	}
	for name, s := range map[string]string{
		"no END":           strings.Join(lines[:len(lines)-2], "\n"),
		"wrong END":        strings.Replace(string(good), "END PGP PUBLIC KEY BLOCK", "END PGP MESSAGE", 1),
		"bad header":       strings.Replace(string(good), "-----\n\n", "-----\nnot a header\n\n", 1),
		"bad character":    strings.Replace(string(good), "\n\n", "\n\n*", 1),
		"no armor at all":  "just some text\n",
		"multi-part armor": "-----BEGIN PGP MESSAGE, PART 1/2-----\n\nAAAA\n-----END PGP MESSAGE, PART 1/2-----\n",
	} {
		if _, err := ReadKeys(strings.NewReader(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Cleartext signed messages: only Hash headers, and dashes escaped.
	clear := string(signed(t, k, "text\n", SignOptions{Mode: SignCleartext}))
	if _, err := VerifyInline(strings.NewReader(clear), []*Key{k}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"extra header":    strings.Replace(clear, "Hash: SHA512\n", "Hash: SHA512\nComment: signed text below\n", 1),
		"bad Hash header": strings.Replace(clear, "Hash: SHA512", "Hash: SHA512 and more", 1),
		"unescaped dash":  strings.Replace(clear, "\ntext\n", "\n-text\n", 1),
		"no signature":    clear[:strings.Index(clear, "-----BEGIN PGP SIGNATURE")],
	} {
		if _, err := VerifyInline(strings.NewReader(s), []*Key{k}, time.Time{}); err == nil {
			t.Errorf("cleartext with %s: accepted", name)
		}
	}
}

func TestLimitsBoundS2KWork(t *testing.T) {
	spec := &s2k{typ: s2kArgon2, salt: make([]byte, 16), t: 1, p: 4, m: 22}
	if _, err := spec.derive([]byte("x"), 32, true, DefaultLimits); !errors.Is(err, ErrLimit) {
		t.Fatalf("4 GiB Argon2: %v", err)
	}
	spec = &s2k{typ: s2kArgon2, salt: make([]byte, 16), t: 200, p: 1, m: 10}
	if _, err := spec.derive([]byte("x"), 32, true, DefaultLimits); !errors.Is(err, ErrLimit) {
		t.Fatalf("200 Argon2 passes: %v", err)
	}
	spec = &s2k{typ: s2kArgon2, salt: make([]byte, 16), t: 1, p: 8, m: 5}
	if _, err := spec.derive([]byte("x"), 32, true, DefaultLimits); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Argon2 memory below 8p: %v", err)
	}
	spec = &s2k{typ: s2kIterated, hash: SHA1, salt: make([]byte, 8), count: 0}
	if _, err := spec.derive([]byte("x"), 16, true, DefaultLimits); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("SHA-1 S2K in a v6 packet: %v", err)
	}
	if _, err := spec.derive([]byte("x"), 16, false, DefaultLimits); err != nil {
		t.Fatalf("SHA-1 S2K in a v4 packet: %v", err)
	}
}

// Keys whose binding signatures do not hold up give no usable subkeys.
func TestBrokenBindingsAreNotTrusted(t *testing.T) {
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Binder"}})
	// A signing subkey without a back-signature is not a signing key.
	sub, err := generateSigningKey(4, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sub.sec.tag = ptSecretSubkey
	binding, err := selfSignature(k.primary, SigSubkeyBinding, time.Now(), func(b *subpacketBuilder) {
		b.add(spKeyFlags, true, flagSign)
	}, k.primary.pub, sub.pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	k.subkeys = append(k.subkeys, &subkey{keyComponent: *sub, sigs: []*signature{binding}})
	armored, _ := k.Armor(true)
	back, err := ReadKey(bytes.NewReader(armored))
	if err != nil {
		t.Fatal(err)
	}
	if subs := back.Subkeys(); len(subs) != 2 || subs[1].CanSign || subs[1].Err != nil {
		t.Fatalf("a signing subkey without a back-signature: %+v", subs)
	}
	// Signing picks the primary key, not the unbacked subkey.
	c, err := back.signingKey(time.Now())
	if err != nil || c != back.primary {
		t.Fatalf("signing key: %v", err)
	}
	// A signature made with the unbacked subkey anyway is not valid.
	b, _ := newSigBuilder(&back.subkeys[1].keyComponent, SigBinary, SHA512, time.Now(), nil)
	b.Write([]byte("x"))
	s, _ := b.finish()
	results, _ := Verify(strings.NewReader("x"), bytes.NewReader(packetBytes(ptSignature, s.body)), []*Key{back.Public()}, time.Time{})
	if results[0].Valid || !errors.Is(results[0].Err, ErrKeyInvalid) {
		t.Fatalf("signature by an unbacked subkey: %+v", results[0])
	}
	// A user ID added without a self-signature, and one whose signature
	// was changed, are not the key's.
	k.identities = append(k.identities, &identity{raw: []byte("Mallory <m@example.org>")})
	cert := k.identities[0].sigs[0]
	forged := &identity{raw: []byte("Forged <f@example.org>"), sigs: []*signature{cert}}
	k.identities = append(k.identities, forged)
	armored, _ = k.Armor(false)
	back, _ = ReadKey(bytes.NewReader(armored))
	if uids := back.UserIDs(); len(uids) != 1 || uids[0] != "Binder" {
		t.Fatalf("user IDs %q", uids)
	}
	// A subkey binding moved onto another subkey does not bind it.
	other, _ := generateEncryptionKey(4, time.Now())
	moved := &subkey{keyComponent: *other, sigs: k.subkeys[0].sigs}
	k.subkeys = []*subkey{moved}
	armored, _ = k.Armor(false)
	back, _ = ReadKey(bytes.NewReader(armored))
	if subs := back.Subkeys(); len(subs) != 1 || subs[0].CanEncrypt || !errors.Is(subs[0].Err, ErrKeyInvalid) {
		t.Fatalf("moved binding: %+v", subs)
	}
	if _, err := Encrypt(io.Discard, []*Key{back}, EncryptOptions{}); err == nil {
		t.Fatal("encrypted to a key without a bound encryption subkey")
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }
