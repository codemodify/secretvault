package svpgp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func generate(t testing.TB, opts KeyOptions) *Key {
	t.Helper()
	k, err := GenerateKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signed(t testing.TB, k *Key, msg string, opts SignOptions) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Sign(&out, strings.NewReader(msg), k, opts); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func encrypted(t testing.TB, recipients []*Key, msg string, opts EncryptOptions) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := Encrypt(&out, recipients, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, msg); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func onlyValid(t testing.TB, results []SignatureResult, k *Key) {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("%d results", len(results))
	}
	r := results[0]
	if !r.Valid || r.Err != nil || r.Key != k {
		t.Fatalf("signature not valid: %+v", r)
	}
}

func TestGeneratedKeysHaveTheExpectedShape(t *testing.T) {
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Alice <alice@example.org>", "Alice <alice@example.net>"}})
		if k.Version() != v || !k.HasSecret() || k.Locked() || k.Revoked() || !k.ExpiresAt().IsZero() {
			t.Fatalf("v%d: %v", v, k)
		}
		if err := k.Valid(time.Now()); err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		if got := k.UserIDs(); len(got) != 2 || k.PrimaryUserID() != "Alice <alice@example.org>" {
			t.Fatalf("v%d: user IDs %q, primary %q", v, got, k.PrimaryUserID())
		}
		subs := k.Subkeys()
		if len(subs) != 1 || !subs[0].CanEncrypt || subs[0].CanSign || subs[0].Err != nil || !subs[0].HasSecret {
			t.Fatalf("v%d: subkeys %+v", v, subs)
		}
		wantPrimary, wantSub := Ed25519, X25519
		if v == 4 {
			wantPrimary, wantSub = EdDSALegacy, ECDH
		}
		if k.Algorithm() != wantPrimary || subs[0].Algorithm != wantSub {
			t.Fatalf("v%d: algorithms %v and %v", v, k.Algorithm(), subs[0].Algorithm)
		}
		if n := len(k.Fingerprint()); v == 4 && n != 20 || v == 6 && n != 32 {
			t.Fatalf("v%d: %d-byte fingerprint", v, n)
		}
		// Serialized and read back, it is the same key, public and secret.
		for _, secret := range []bool{false, true} {
			armored, err := k.Armor(secret)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ReadKey(bytes.NewReader(armored))
			if err != nil {
				t.Fatalf("v%d secret=%v: %v", v, secret, err)
			}
			if !bytes.Equal(back.Fingerprint(), k.Fingerprint()) || back.HasSecret() != secret || back.Valid(time.Now()) != nil {
				t.Fatalf("v%d secret=%v: read back as %v", v, secret, back)
			}
			if hasCRC := bytes.Contains(armored, []byte("\n=")); hasCRC != (v == 4) {
				t.Fatalf("v%d: CRC24 line present: %v", v, hasCRC)
			}
		}
	}
	if _, err := GenerateKey(KeyOptions{Version: 4}); err == nil {
		t.Fatal("a version 4 key without a user ID was made")
	}
	if _, err := GenerateKey(KeyOptions{Version: 5}); err == nil {
		t.Fatal("a version 5 key was made")
	}
}

func TestSignaturesInEveryModeVerifyAndCatchChanges(t *testing.T) {
	msg := "Dear Bob,\n- the plan is on\nFrom now on, trailing spaces   \n"
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Alice <alice@example.org>"}})
		pub := k.Public()
		keyring := []*Key{pub}
		for _, text := range []bool{false, true} {
			for _, armor := range []bool{false, true} {
				sig := signed(t, k, msg, SignOptions{Mode: SignDetached, Text: text, Armor: armor})
				results, err := Verify(strings.NewReader(msg), bytes.NewReader(sig), keyring, time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				onlyValid(t, results, pub)
				wantType := SigBinary
				if text {
					wantType = SigText
				}
				if results[0].Type != wantType || results[0].Version != v || results[0].Hash != SHA512 {
					t.Fatalf("v%d: %+v", v, results[0])
				}
				results, err = Verify(strings.NewReader(msg+"!"), bytes.NewReader(sig), keyring, time.Time{})
				if err != nil || results[0].Valid || !errors.Is(results[0].Err, ErrBadSignature) {
					t.Fatalf("v%d: a changed message verified: %+v %v", v, results, err)
				}
				if text {
					// A text signature survives a change of line endings.
					crlf := strings.ReplaceAll(msg, "\n", "\r\n")
					results, err = Verify(strings.NewReader(crlf), bytes.NewReader(sig), keyring, time.Time{})
					if err != nil {
						t.Fatal(err)
					}
					onlyValid(t, results, pub)
				}

				inline := signed(t, k, msg, SignOptions{Mode: SignInline, Text: text, Armor: armor})
				m, err := VerifyInline(bytes.NewReader(inline), keyring, time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				onlyValid(t, m.Signatures, pub)
				want, format := msg, byte('b')
				if text {
					want, format = strings.ReplaceAll(msg, "\n", "\r\n"), 'u'
				}
				if string(m.Body) != want || m.Format != format || m.Encrypted {
					t.Fatalf("inline body %q, format %c", m.Body, m.Format)
				}
			}
		}
		clear := signed(t, k, msg, SignOptions{Mode: SignCleartext})
		if !bytes.Contains(clear, []byte("\n- - the plan is on\n")) || !bytes.Contains(clear, []byte("\n- From now on")) {
			t.Fatalf("cleartext not dash-escaped:\n%s", clear)
		}
		if hasHash := bytes.Contains(clear, []byte("\nHash: SHA512\n")); hasHash != (v == 4) {
			t.Fatalf("v%d: Hash header present: %v", v, hasHash)
		}
		m, err := VerifyInline(bytes.NewReader(clear), keyring, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		onlyValid(t, m.Signatures, pub)
		if want := "Dear Bob,\n- the plan is on\nFrom now on, trailing spaces\n"; string(m.Body) != want || !m.Cleartext {
			t.Fatalf("cleartext body %q", m.Body)
		}
		tampered := bytes.Replace(clear, []byte("plan is on"), []byte("plan is off"), 1)
		m, err = VerifyInline(bytes.NewReader(tampered), keyring, time.Time{})
		if err != nil || m.Signatures[0].Valid {
			t.Fatalf("tampered cleartext verified: %v", err)
		}
		// Another key's keyring does not know the signer.
		other := generate(t, KeyOptions{Version: v, UserIDs: []string{"Mallory"}})
		sig := signed(t, k, msg, SignOptions{})
		results, err := Verify(strings.NewReader(msg), bytes.NewReader(sig), []*Key{other.Public()}, time.Time{})
		if err != nil || results[0].Valid || !errors.Is(results[0].Err, ErrUnknownSigner) {
			t.Fatalf("unknown signer: %+v %v", results, err)
		}
	}
}

func TestEncryptionRoundTripsInBothFormats(t *testing.T) {
	msg := "the eagle has landed\n"
	v4 := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Bob <bob@example.org>"}})
	v6 := generate(t, KeyOptions{Version: 6, UserIDs: []string{"Carol <carol@example.org>"}})
	alice := generate(t, KeyOptions{Version: 6, UserIDs: []string{"Alice <alice@example.org>"}})
	cases := []struct {
		name       string
		recipients []*Key
		opts       EncryptOptions
		seipd      int
	}{
		{"v6 recipient", []*Key{v6.Public()}, EncryptOptions{}, 2},
		{"v4 recipient", []*Key{v4.Public()}, EncryptOptions{}, 1},
		{"both", []*Key{v4.Public(), v6.Public()}, EncryptOptions{}, 1},
		{"v6 recipient, v1 forced", []*Key{v6.Public()}, EncryptOptions{Format: FormatV1}, 1},
		{"signed and armored", []*Key{v6.Public()}, EncryptOptions{Signer: alice, Armor: true}, 2},
		{"signed v1", []*Key{v4.Public()}, EncryptOptions{Signer: alice, Text: true}, 1},
		{"compressed", []*Key{v6.Public()}, EncryptOptions{Compression: ZLIB, Signer: alice}, 2},
		{"compressed ZIP v1", []*Key{v4.Public()}, EncryptOptions{Compression: ZIP}, 1},
		{"passphrase too", []*Key{v4.Public()}, EncryptOptions{Passphrase: []byte("sesame")}, 1},
	}
	keyring := []*Key{v4, v6, alice.Public()}
	for _, c := range cases {
		ct := encrypted(t, c.recipients, msg, c.opts)
		m, err := Decrypt(bytes.NewReader(ct), keyring, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		want := msg
		if c.opts.Text {
			want = strings.ReplaceAll(msg, "\n", "\r\n")
		}
		if string(m.Body) != want || m.SEIPDVersion != c.seipd || !m.IntegrityProtected || !m.Encrypted {
			t.Fatalf("%s: %+v", c.name, m)
		}
		if c.opts.Compression != 0 && !m.Compressed {
			t.Fatalf("%s: not compressed", c.name)
		}
		if c.opts.Signer != nil {
			onlyValid(t, m.Signatures, keyring[2])
		} else if len(m.Signatures) != 0 {
			t.Fatalf("%s: unexpected signatures", c.name)
		}
		if c.seipd == 2 && (m.AEAD != OCB || m.Cipher != AES256) {
			t.Fatalf("%s: %v %v", c.name, m.Cipher, m.AEAD)
		}
		if c.seipd == 1 && m.Cipher != AES256 {
			t.Fatalf("%s: %v", c.name, m.Cipher)
		}
		// Each recipient can decrypt it alone.
		for _, r := range c.recipients {
			var secret *Key
			for _, k := range []*Key{v4, v6} {
				if bytes.Equal(k.Fingerprint(), r.Fingerprint()) {
					secret = k
				}
			}
			m, err := Decrypt(bytes.NewReader(ct), []*Key{secret}, nil)
			if err != nil || string(m.Body) != want || m.DecryptedWith != secret {
				t.Fatalf("%s: %v alone: %v", c.name, secret, err)
			}
		}
		if c.opts.Passphrase != nil {
			m, err := Decrypt(bytes.NewReader(ct), nil, func() ([]byte, error) { return []byte("sesame"), nil })
			if err != nil || string(m.Body) != want || m.DecryptedWith != nil {
				t.Fatalf("%s: with the passphrase: %v", c.name, err)
			}
		}
	}
	// Passphrase only: v2 by default, v1 on request.
	for _, f := range []EncryptFormat{FormatAuto, FormatV1} {
		ct := encrypted(t, nil, msg, EncryptOptions{Passphrase: []byte("sesame"), Format: f})
		m, err := Decrypt(bytes.NewReader(ct), nil, func() ([]byte, error) { return []byte("sesame"), nil })
		if err != nil || string(m.Body) != msg {
			t.Fatalf("format %d: %v", f, err)
		}
		if want := map[EncryptFormat]int{FormatAuto: 2, FormatV1: 1}[f]; m.SEIPDVersion != want {
			t.Fatalf("format %d gave v%d", f, m.SEIPDVersion)
		}
		if _, err := Decrypt(bytes.NewReader(ct), nil, func() ([]byte, error) { return []byte("open"), nil }); err == nil {
			t.Fatalf("format %d: a wrong passphrase decrypted", f)
		}
	}
	// v2 cannot be forced on a key that does not support it.
	if _, err := Encrypt(io.Discard, []*Key{v4.Public()}, EncryptOptions{Format: FormatV2}); err == nil {
		t.Fatal("v2 forced on a v4 key without the feature")
	}
	// Large messages cross chunk and partial-length boundaries.
	big := strings.Repeat("0123456789abcdef", 300000)
	for _, r := range []*Key{v4, v6} {
		ct := encrypted(t, []*Key{r.Public()}, big, EncryptOptions{Signer: alice})
		m, err := Decrypt(bytes.NewReader(ct), []*Key{r, keyring[2]}, nil)
		if err != nil || string(m.Body) != big {
			t.Fatalf("large message to v%d: %v", r.Version(), err)
		}
		onlyValid(t, m.Signatures, keyring[2])
	}
}

func TestProtectedKeysRoundTripAndRefuseWrongPassphrases(t *testing.T) {
	for _, v := range []int{4, 6} {
		k := generate(t, KeyOptions{Version: v, UserIDs: []string{"Dave"}, Passphrase: []byte("hunter2")})
		if k.Locked() {
			t.Fatalf("v%d: a new key came back locked", v)
		}
		armored, err := k.Armor(true)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ReadKey(bytes.NewReader(armored))
		if err != nil {
			t.Fatal(err)
		}
		if !back.Locked() {
			t.Fatalf("v%d: the serialized key is not protected", v)
		}
		usage := back.primary.sec.prot.usage
		if v == 6 && usage != usageAEAD || v == 4 && usage != usageCFB {
			t.Fatalf("v%d: protected with usage %d", v, usage)
		}
		if err := Sign(io.Discard, strings.NewReader("x"), back, SignOptions{}); !errors.Is(err, ErrKeyLocked) {
			t.Fatalf("v%d: signing with a locked key: %v", v, err)
		}
		if err := back.Unlock([]byte("hunter3")); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("v%d: wrong passphrase: %v", v, err)
		}
		if err := back.Unlock([]byte("hunter2")); err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		sig := signed(t, back, "x", SignOptions{})
		results, err := Verify(strings.NewReader("x"), bytes.NewReader(sig), []*Key{k.Public()}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		onlyValid(t, results, results[0].Key)
		// A new passphrase, and AEAD protection for v4 on request.
		if err := back.Lock([]byte("correct horse"), &LockOptions{AEAD: true}); err != nil {
			t.Fatal(err)
		}
		if !back.Locked() || back.primary.sec.prot.usage != usageAEAD {
			t.Fatalf("v%d: relocked with usage %d", v, back.primary.sec.prot.usage)
		}
		again, _ := back.Armor(true)
		reread, err := ReadKey(bytes.NewReader(again))
		if err != nil {
			t.Fatal(err)
		}
		if err := reread.Unlock([]byte("hunter2")); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("v%d: the old passphrase still works: %v", v, err)
		}
		if err := reread.Unlock([]byte("correct horse")); err != nil {
			t.Fatal(err)
		}
		reread.Close()
		if !reread.Locked() {
			t.Fatal("Close left the key unlocked")
		}
	}
	// An unprotected key cannot be locked without a passphrase, and Close
	// wipes it for good.
	k := generate(t, KeyOptions{Version: 6})
	if err := k.Lock(nil, nil); err == nil {
		t.Fatal("an unprotected key locked without a passphrase")
	}
	k.Close()
	if err := Sign(io.Discard, strings.NewReader("x"), k, SignOptions{}); err == nil {
		t.Fatal("a closed key still signs")
	}
}

func TestRevokedAndExpiredKeysAreReported(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	msg := "payment approved"

	// Revocation: a signature made after a "retired" revocation is bad, one
	// made before it still good; a compromise makes both bad.
	for _, c := range []struct {
		reason     RevocationReason
		beforeGood bool
	}{
		{RevocationRetired, true},
		{RevocationCompromised, false},
		{RevocationNoReason, false},
	} {
		k := generate(t, KeyOptions{Version: 6, Created: now.Add(-2 * time.Hour)})
		before := signed(t, k, msg, SignOptions{Time: now.Add(-90 * time.Minute)})
		if err := k.Revoke(c.reason, "done with it", now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if !k.Revoked() || !errors.Is(k.Valid(now), ErrKeyRevoked) {
			t.Fatalf("reason %d: not revoked", c.reason)
		}
		// The revocation travels with the key.
		armored, _ := k.Armor(false)
		pub, err := ReadKey(bytes.NewReader(armored))
		if err != nil || !pub.Revoked() {
			t.Fatalf("reason %d: revocation lost: %v", c.reason, err)
		}
		results, err := Verify(strings.NewReader(msg), bytes.NewReader(before), []*Key{pub}, now)
		if err != nil {
			t.Fatal(err)
		}
		if results[0].Valid != c.beforeGood || !c.beforeGood && !errors.Is(results[0].Err, ErrKeyRevoked) {
			t.Fatalf("reason %d: signature from before the revocation: %+v", c.reason, results[0])
		}
		// Signing now is refused, and a signature made anyway is bad.
		if err := Sign(io.Discard, strings.NewReader(msg), k, SignOptions{}); !errors.Is(err, ErrKeyRevoked) {
			t.Fatalf("reason %d: signing with a revoked key: %v", c.reason, err)
		}
		after := forceSign(t, k, msg, now.Add(-30*time.Minute))
		results, _ = Verify(strings.NewReader(msg), bytes.NewReader(after), []*Key{pub}, now)
		if results[0].Valid || !errors.Is(results[0].Err, ErrKeyRevoked) {
			t.Fatalf("reason %d: signature after revocation: %+v", c.reason, results[0])
		}
		// And nobody encrypts to it.
		if _, err := Encrypt(io.Discard, []*Key{pub}, EncryptOptions{}); !errors.Is(err, ErrKeyRevoked) {
			t.Fatalf("reason %d: encrypting to a revoked key: %v", c.reason, err)
		}
	}

	// Expiry: a key valid for an hour, made two hours ago.
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Eve"}, Created: now.Add(-2 * time.Hour), Lifetime: time.Hour})
	if got := k.ExpiresAt(); !got.Equal(now.Add(-time.Hour)) {
		t.Fatalf("expires %v", got)
	}
	if !errors.Is(k.Valid(now), ErrKeyExpired) || k.Valid(now.Add(-90*time.Minute)) != nil {
		t.Fatal("validity around the expiry is wrong")
	}
	inTime := signed(t, k, msg, SignOptions{Time: now.Add(-90 * time.Minute)})
	results, _ := Verify(strings.NewReader(msg), bytes.NewReader(inTime), []*Key{k.Public()}, now)
	onlyValid(t, results, results[0].Key)
	late := forceSign(t, k, msg, now.Add(-30*time.Minute))
	results, _ = Verify(strings.NewReader(msg), bytes.NewReader(late), []*Key{k.Public()}, now)
	if results[0].Valid || !errors.Is(results[0].Err, ErrKeyExpired) {
		t.Fatalf("signature by an expired key: %+v", results[0])
	}
	if err := Sign(io.Discard, strings.NewReader(msg), k, SignOptions{}); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("signing with an expired key: %v", err)
	}
	if _, err := Encrypt(io.Discard, []*Key{k.Public()}, EncryptOptions{}); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("encrypting to an expired key: %v", err)
	}
	// A signature from before the key existed is not valid either.
	early := forceSign(t, k, msg, now.Add(-3*time.Hour))
	results, _ = Verify(strings.NewReader(msg), bytes.NewReader(early), []*Key{k.Public()}, now)
	if results[0].Valid || !errors.Is(results[0].Err, ErrKeyInvalid) {
		t.Fatalf("signature from before the key: %+v", results[0])
	}
	// A signature from the future is refused.
	future := forceSign(t, generate(t, KeyOptions{}), msg, now.Add(time.Hour))
	signer, _ := ReadKey(bytes.NewReader(mustArmor(t, generate(t, KeyOptions{}))))
	_ = signer
	results, _ = Verify(strings.NewReader(msg), bytes.NewReader(future), nil, now)
	if results[0].Valid {
		t.Fatal("a future signature is valid")
	}
}

// forceSign makes a binary signature at time at with the primary key,
// bypassing the checks Sign makes, to test what verifiers do with
// signatures that should not have been made.
func forceSign(t testing.TB, k *Key, msg string, at time.Time) []byte {
	t.Helper()
	b, err := newSigBuilder(k.primary, SigBinary, SHA512, at, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(b, msg)
	sig, err := b.finish()
	if err != nil {
		t.Fatal(err)
	}
	return packetBytes(ptSignature, sig.body)
}

func mustArmor(t testing.TB, k *Key) []byte {
	t.Helper()
	b, err := k.Armor(false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
