package svpgp

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"testing"
)

// The operations GnuPG's agent protocol asks of a secret key: a digest
// signed, checked with the standard library; an ECDH shared point, checked
// against crypto/ecdh; an RSA session key, encrypted by crypto/rsa.

// partsOf splits a key's parts into its primary key and its subkey.
func partsOf(t *testing.T, k *Key) (primary, sub KeyPart) {
	t.Helper()
	parts := k.Parts()
	if len(parts) != 2 || !parts[0].Primary || parts[1].Primary {
		t.Fatalf("parts %+v", parts)
	}
	return parts[0], parts[1]
}

// checkDigestSignature verifies SignDigest's values with the standard library.
func checkDigestSignature(t *testing.T, p KeyPart, h crypto.Hash, digest []byte, values [][]byte) {
	t.Helper()
	switch p.Algorithm {
	case RSA, RSASignOnly:
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(p.Public.N), E: int(new(big.Int).SetBytes(p.Public.E).Int64())}
		sig := make([]byte, pub.Size())
		new(big.Int).SetBytes(values[0]).FillBytes(sig)
		if len(values) != 1 || rsa.VerifyPKCS1v15(pub, h, digest, sig) != nil {
			t.Fatalf("the RSA signature does not verify")
		}
	case ECDSA:
		var c *ecdsa.PublicKey
		for _, cv := range []*curve{curveP256, curveP384, curveP521} {
			if bytes.Equal(cv.oid, p.Public.CurveOID) {
				var err error
				if c, err = ecdsa.ParseUncompressedPublicKey(cv.ecdsa, p.Public.Point); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(values) != 2 || c == nil || !ecdsa.Verify(c, digest, new(big.Int).SetBytes(values[0]), new(big.Int).SetBytes(values[1])) {
			t.Fatalf("the ECDSA signature does not verify")
		}
	case EdDSALegacy, Ed25519:
		pub := p.Public.Point
		if len(pub) == 33 {
			pub = pub[1:]
		}
		if len(values) != 2 || len(values[0]) != 32 || len(values[1]) != 32 ||
			!ed25519.Verify(pub, digest, append(append([]byte{}, values[0]...), values[1]...)) {
			t.Fatalf("the EdDSA signature does not verify")
		}
	default:
		t.Fatalf("a %v signature", p.Algorithm)
	}
}

// checkSharedPoint does ECDH as a sender would, and compares.
func checkSharedPoint(t *testing.T, k *Key, p KeyPart) {
	t.Helper()
	var c ecdh.Curve
	var eph []byte
	pub := p.Public.Point
	switch {
	case p.Algorithm == X25519 || len(pub) == 33 && pub[0] == 0x40:
		c = ecdh.X25519()
		if len(pub) == 33 {
			pub = pub[1:]
		}
	default:
		for _, cv := range []*curve{curveP256, curveP384, curveP521} {
			if bytes.Equal(cv.oid, p.Public.CurveOID) {
				c = cv.ecdh
			}
		}
	}
	rcpt, err := c.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := c.GenerateKey(rand.Reader)
	want, _ := e.ECDH(rcpt)
	eph = e.PublicKey().Bytes()
	if p.Algorithm == ECDH && c == ecdh.X25519() {
		eph = append([]byte{0x40}, eph...)
	}
	got, err := k.SharedPoint(p.Fingerprint, eph)
	if err != nil {
		t.Fatal(err)
	}
	if c == ecdh.X25519() {
		if !bytes.Equal(got, want) {
			t.Fatalf("shared point %x, want %x", got, want)
		}
		return
	}
	// The whole point: its x is the shared secret, and it is on the curve.
	if n := len(want); len(got) != 1+2*n || got[0] != 4 || !bytes.Equal(got[1:1+n], want) {
		t.Fatalf("shared point %x, want x %x", got, want)
	}
	if _, err := c.NewPublicKey(got); err != nil {
		t.Fatalf("the shared point is not on the curve: %v", err)
	}
	// Anything else for the ephemeral key is refused.
	for _, bad := range [][]byte{eph[:len(eph)-1], append([]byte{2}, eph[1:1+len(want)]...), make([]byte, len(eph))} {
		if _, err := k.SharedPoint(p.Fingerprint, bad); !errors.Is(err, ErrDecryption) {
			t.Fatalf("a bad ephemeral key: %v", err)
		}
	}
}

func TestAgentOperationsWithKeysOfOurOwn(t *testing.T) {
	for _, version := range []int{4, 6} {
		k, err := GenerateKey(KeyOptions{Version: version, UserIDs: []string{"Agent <agent@example.org>"}})
		if err != nil {
			t.Fatal(err)
		}
		defer k.Close()
		primary, sub := partsOf(t, k)
		if !primary.HasSecret || !primary.CanSign || primary.CanEncrypt || !sub.HasSecret || sub.CanSign || !sub.CanEncrypt {
			t.Fatalf("v%d parts %+v %+v", version, primary, sub)
		}
		digest := sha512.Sum512([]byte("to be signed"))
		sig, err := k.SignDigest(primary.Fingerprint, SHA512, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		checkDigestSignature(t, primary, crypto.SHA512, digest[:], sig)
		checkSharedPoint(t, k, sub)

		// What each part may not do, and digests that are not accepted.
		if _, err := k.SignDigest(sub.Fingerprint, SHA512, digest[:]); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("v%d: signed with the encryption subkey: %v", version, err)
		}
		if _, err := k.SharedPoint(primary.Fingerprint, make([]byte, 33)); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("v%d: ECDH with the signing key: %v", version, err)
		}
		sha1Digest := make([]byte, 20)
		if _, err := k.SignDigest(primary.Fingerprint, SHA1, sha1Digest); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("v%d: a SHA-1 signature: %v", version, err)
		}
		if _, err := k.SignDigest(primary.Fingerprint, SHA512, digest[:32]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("v%d: a short digest: %v", version, err)
		}
		if _, err := k.SignDigest([]byte("no such key"), SHA512, digest[:]); !errors.Is(err, ErrNoUsableKey) {
			t.Fatalf("v%d: another key: %v", version, err)
		}
	}
}

func TestAgentOperationsNeedTheSecret(t *testing.T) {
	k, err := GenerateKey(KeyOptions{Version: 4, UserIDs: []string{"Locked <locked@example.org>"}, Passphrase: []byte("a passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := k.Serialize(&buf, true); err != nil {
		t.Fatal(err)
	}
	k.Close()
	locked, err := ReadKey(&buf)
	if err != nil {
		t.Fatal(err)
	}
	primary, _ := partsOf(t, locked)
	digest := sha256.Sum256(nil)
	if _, err := locked.SignDigest(primary.Fingerprint, SHA256, digest[:]); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("signed with a locked key: %v", err)
	}
	if _, err := locked.Public().SignDigest(primary.Fingerprint, SHA256, digest[:]); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("signed with a public key: %v", err)
	}
	if !primary.HasSecret {
		t.Fatal("a locked key's part has no secret")
	}
	for _, p := range locked.Public().Parts() {
		if p.HasSecret {
			t.Fatal("a public key's part has a secret")
		}
	}
}

// Keys GnuPG made, of every kind it makes: RSA, ECDSA and ECDH on the NIST
// curves, EdDSA and ECDH on Curve25519; and a key exported without its
// primary secret (a GnuPG stub).
func TestAgentOperationsWithGnuPGKeys(t *testing.T) {
	for _, a := range gpgAlgorithms {
		t.Run(a.name, func(t *testing.T) {
			g := newGPG(t)
			fpr := g.generate("Agent <agent@example.org>", a.primary, a.sub, "never")
			_, sec := g.keys(fpr)
			primary, sub := partsOf(t, sec)
			if !primary.CanSign || primary.CanEncrypt || sub.CanSign || !sub.CanEncrypt {
				t.Fatalf("parts %+v %+v", primary, sub)
			}
			h := a.hash
			ch, _ := h.cryptoHash()
			digest := ch.New()
			digest.Write([]byte("to be signed"))
			sum := digest.Sum(nil)
			sig, err := sec.SignDigest(primary.Fingerprint, h, sum)
			if err != nil {
				t.Fatal(err)
			}
			checkDigestSignature(t, primary, ch, sum, sig)

			if sub.Algorithm == RSA {
				checkRSA(t, sec, sub)
				if _, err := sec.DecryptPKCS1(primary.Fingerprint, make([]byte, 16)); !errors.Is(err, ErrUnsupported) {
					t.Fatalf("decrypted with the signing key: %v", err)
				}
			} else {
				checkSharedPoint(t, sec, sub)
			}

			// Without the primary key's secret, only the subkey is there.
			out, _ := g.must(nil, "--armor", "--passphrase", gpgPass, "--export-secret-subkeys", fpr)
			stub, err := ReadKey(bytes.NewReader(out))
			if err != nil {
				t.Fatal(err)
			}
			if err := stub.Unlock([]byte(gpgPass)); err != nil {
				t.Fatal(err)
			}
			sp, ss := partsOf(t, stub)
			if sp.HasSecret || !ss.HasSecret {
				t.Fatalf("stub parts %+v %+v", sp, ss)
			}
			if _, err := stub.SignDigest(sp.Fingerprint, h, sum); !errors.Is(err, ErrKeyLocked) {
				t.Fatalf("signed with a stub: %v", err)
			}
		})
	}
}

// checkRSA encrypts session keys with crypto/rsa, and decrypts them.
func checkRSA(t *testing.T, k *Key, p KeyPart) {
	t.Helper()
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(p.Public.N), E: int(new(big.Int).SetBytes(p.Public.E).Int64())}
	msg := []byte{9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 136}
	c, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	for c[0] == 0 { // an MPI has no leading zeros; the key's size is known
		c, _ = rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	}
	got, err := k.DecryptPKCS1(p.Fingerprint, c)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("DecryptPKCS1 = %x, %v", got, err)
	}
	// Raw RSA is not on offer: whatever is not padded as encryption pads
	// is refused, so nothing can be signed by decrypting it.
	em := make([]byte, pub.Size())
	em[1] = 1 // signature padding
	for i := 2; i < len(em)-20; i++ {
		em[i] = 0xff
	}
	raw := new(big.Int).Exp(new(big.Int).SetBytes(em), big.NewInt(int64(pub.E)), pub.N).Bytes()
	for _, bad := range [][]byte{raw, append([]byte{1}, c...), {}, c[:len(c)/2]} {
		if _, err := k.DecryptPKCS1(p.Fingerprint, bad); !errors.Is(err, ErrDecryption) {
			t.Fatalf("a bad ciphertext: %v", err)
		}
	}
}
