package svcms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// What this package makes, it reads: signatures by every key type, both
// ways of carrying the content, and encryption to every recipient type.

func TestSignVerify(t *testing.T) {
	p := getPKI(t)
	content := []byte("Content-Type: text/plain\r\n\r\nHello, world.\r\n")
	for _, tc := range []struct {
		key  string
		opts SignOptions
	}{
		{"rsa", SignOptions{}},
		{"rsa", SignOptions{PSS: true}},
		{"rsa", SignOptions{Hash: crypto.SHA512}},
		{"p256", SignOptions{}},
		{"p384", SignOptions{}},
		{"p521", SignOptions{}},
		{"ed25519", SignOptions{}},
		{"rsa", SignOptions{Attached: true}},
		{"p256", SignOptions{Attached: true}},
	} {
		u := p.user(t, userOpts{keyType: tc.key})
		name := tc.key
		if tc.opts.PSS {
			name += "-pss"
		}
		if tc.opts.Attached {
			name += "-attached"
		}
		t.Run(name, func(t *testing.T) {
			der, err := Sign(content, u.key, []*x509.Certificate{u.cert, p.inter}, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			sd, err := ParseSignedData(der, nil)
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifyOptions{Roots: []*x509.Certificate{p.root}, Email: "ALICE@example.org"}
			if tc.opts.Attached {
				if !bytes.Equal(sd.Content, content) {
					t.Fatal("attached content differs")
				}
			} else {
				if sd.Content != nil {
					t.Fatal("detached signature carries content")
				}
				opts.Content = content
			}
			res, err := sd.Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 1 || !res[0].Valid {
				t.Fatalf("not valid: %+v", res)
			}
			if res[0].Certificate == nil || !res[0].Certificate.Equal(u.cert) || len(res[0].Chains) == 0 {
				t.Fatal("signer certificate or chain missing")
			}
			if time.Since(res[0].SigningTime) > time.Minute {
				t.Fatalf("signing time %v", res[0].SigningTime)
			}

			// Changing the content breaks it.
			bad := bytes.Clone(content)
			bad[len(bad)-3] ^= 1
			if tc.opts.Attached {
				i := bytes.Index(der, content)
				tampered := bytes.Clone(der)
				tampered[i+len(content)-3] ^= 1
				sd2, err := ParseSignedData(tampered, nil)
				if err != nil {
					t.Fatal(err)
				}
				res, _ = sd2.Verify(VerifyOptions{Roots: []*x509.Certificate{p.root}})
			} else {
				opts.Content = bad
				res, _ = sd.Verify(opts)
			}
			if res[0].Valid || !errors.Is(res[0].Err, ErrBadSignature) {
				t.Fatalf("tampered content: %v", res[0].Err)
			}
		})
	}
}

func TestSignatureTamperEveryByte(t *testing.T) {
	p := getPKI(t)
	u := p.user(t, userOpts{keyType: "p256"})
	content := []byte("tamper with me")
	der, err := Sign(content, u.key, []*x509.Certificate{u.cert, p.inter}, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Every byte of the SignerInfo (the last element) matters: flipping
	// one must never leave a valid signature.
	sd, _ := ParseSignedData(der, nil)
	start := len(der) - 300
	if start < 0 {
		start = 0
	}
	_ = sd
	for i := start; i < len(der); i++ {
		bad := bytes.Clone(der)
		bad[i] ^= 0x01
		sd, err := ParseSignedData(bad, nil)
		if err != nil {
			continue
		}
		res, err := sd.Verify(VerifyOptions{Content: content, Roots: []*x509.Certificate{p.root}})
		if err != nil {
			continue
		}
		for _, r := range res {
			if r.Valid {
				t.Fatalf("flipping byte %d left a valid signature", i)
			}
		}
	}
}

func TestCertificateProblems(t *testing.T) {
	p := getPKI(t)
	content := []byte("content")
	sign := func(u *testUser, chain ...*x509.Certificate) *SignedData {
		t.Helper()
		der, err := Sign(content, u.key, append([]*x509.Certificate{u.cert}, chain...), SignOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sd, err := ParseSignedData(der, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	check := func(name string, sd *SignedData, opts VerifyOptions, want ...error) {
		t.Helper()
		opts.Content = content
		res, err := sd.Verify(opts)
		if err != nil {
			t.Fatal(err)
		}
		r := res[0]
		if r.SignatureErr != nil {
			t.Fatalf("%s: signature error %v", name, r.SignatureErr)
		}
		if len(want) == 0 {
			if !r.Valid {
				t.Fatalf("%s: not valid: %v", name, r.Err)
			}
			return
		}
		if r.Valid {
			t.Fatalf("%s: valid", name)
		}
		for _, w := range want {
			if !errors.Is(r.CertificateErr, w) {
				t.Fatalf("%s: %v, want %v", name, r.CertificateErr, w)
			}
		}
	}
	roots := []*x509.Certificate{p.root}
	good := p.user(t, userOpts{})
	check("good", sign(good, p.inter), VerifyOptions{Roots: roots, Email: "alice@example.org"})
	check("no roots", sign(good, p.inter), VerifyOptions{}, ErrUntrustedRoot)
	check("no intermediate", sign(good), VerifyOptions{Roots: roots}, ErrUntrustedRoot)
	check("intermediate given", sign(good), VerifyOptions{Roots: roots, Intermediates: []*x509.Certificate{p.inter}})
	check("address", sign(good, p.inter), VerifyOptions{Roots: roots, Email: "mallory@example.org"}, ErrAddressMismatch)
	check("later", sign(good, p.inter), VerifyOptions{Roots: roots, Time: time.Now().Add(2 * 365 * 24 * time.Hour)}, ErrCertExpired)
	old := p.user(t, userOpts{notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)})
	check("expired", sign(old, p.inter), VerifyOptions{Roots: roots}, ErrCertExpired)
	check("expired and untrusted", sign(old, p.inter), VerifyOptions{}, ErrCertExpired, ErrUntrustedRoot)
	tls := p.user(t, userOpts{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	check("server auth", sign(tls, p.inter), VerifyOptions{Roots: roots}, ErrWrongUsage)
	enc := p.user(t, userOpts{keyUsage: x509.KeyUsageKeyEncipherment})
	check("encipherment only", sign(enc, p.inter), VerifyOptions{Roots: roots}, ErrWrongUsage)
	legacy := p.user(t, userOpts{email: "bob@example.org", subjectEmail: true})
	check("legacy emailAddress", sign(legacy, p.inter), VerifyOptions{Roots: roots, Email: "Bob@Example.org"})
	check("legacy mismatch", sign(legacy, p.inter), VerifyOptions{Roots: roots, Email: "alice@example.org"}, ErrAddressMismatch)
	any := p.user(t, userOpts{eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	check("any usage", sign(any, p.inter), VerifyOptions{Roots: roots})

	// A key too small is refused as weak, not reported as fine.
	small := p.user(t, userOpts{keyType: "rsa1024"})
	if _, err := Sign(content, small.key, []*x509.Certificate{small.cert}, SignOptions{}); !errors.Is(err, ErrWeakAlgorithm) {
		t.Fatalf("signing with RSA-1024: %v", err)
	}
}

func TestUnknownSigner(t *testing.T) {
	p := getPKI(t)
	u := p.user(t, userOpts{})
	der, err := Sign([]byte("x"), u.key, []*x509.Certificate{u.cert}, SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Strip the certificates by signing, then verifying a copy whose
	// certificate list does not contain the signer.
	sd, _ := ParseSignedData(der, nil)
	sd.Certificates = nil
	res, err := sd.Verify(VerifyOptions{Content: []byte("x"), Roots: []*x509.Certificate{p.root}})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(res[0].Err, ErrUnknownSigner) {
		t.Fatalf("got %v", res[0].Err)
	}
	// Given as a known certificate, it verifies.
	res, _ = sd.Verify(VerifyOptions{Content: []byte("x"), Roots: []*x509.Certificate{p.root}, Intermediates: []*x509.Certificate{u.cert, p.inter}})
	if !res[0].Valid {
		t.Fatalf("got %v", res[0].Err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	p := getPKI(t)
	content := []byte("Content-Type: text/plain\r\n\r\nsecret\r\n")
	for _, key := range []string{"rsa", "p256", "p384", "p521"} {
		for _, legacy := range []bool{false, true} {
			name := key
			if legacy {
				name += "-cbc"
			}
			t.Run(name, func(t *testing.T) {
				u := p.user(t, userOpts{keyType: key})
				other := p.user(t, userOpts{keyType: "p256", email: "bob@example.org"})
				der, err := Encrypt(content, []*x509.Certificate{other.cert, u.cert}, EncryptOptions{Legacy: legacy})
				if err != nil {
					t.Fatal(err)
				}
				ed, err := ParseEnvelopedData(der, nil)
				if err != nil {
					t.Fatal(err)
				}
				if ed.Authenticated == legacy || len(ed.Recipients) != 2 {
					t.Fatalf("authenticated %v, %d recipients", ed.Authenticated, len(ed.Recipients))
				}
				d, err := KeyDecrypter(u.cert, u.key)
				if err != nil {
					t.Fatal(err)
				}
				pt, err := ed.Decrypt(d)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(pt.Content, content) || !pt.Recipient.Matches(u.cert) {
					t.Fatal("wrong content or recipient")
				}

				// A key it was not encrypted to.
				strangerKey := key
				if key == "rsa" {
					strangerKey = "rsa2"
				}
				stranger := p.user(t, userOpts{keyType: strangerKey, email: "eve@example.org"})
				d2, _ := KeyDecrypter(stranger.cert, stranger.key)
				if _, err := ed.Decrypt(d2); !errors.Is(err, ErrNotRecipient) {
					t.Fatalf("stranger: %v", err)
				}
				// The right certificate with the wrong key.
				d3, _ := KeyDecrypter(u.cert, stranger.key)
				if _, err := ed.Decrypt(d3); !errors.Is(err, ErrDecryption) {
					t.Fatalf("wrong key: %v", err)
				}

				// Tampering with the ciphertext: GCM refuses it; CBC
				// fails only when the padding breaks, which is the point
				// of not using it.
				i := bytes.Index(der, ed.encrypted)
				bad := bytes.Clone(der)
				bad[i+len(ed.encrypted)-1] ^= 0x80
				ed2, err := ParseEnvelopedData(bad, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ed2.Decrypt(d); !errors.Is(err, ErrDecryption) {
					t.Fatalf("tampered: %v", err)
				}
			})
		}
	}
}

func TestEncryptRefuses(t *testing.T) {
	p := getPKI(t)
	signOnly := p.user(t, userOpts{keyUsage: x509.KeyUsageDigitalSignature})
	if _, err := Encrypt([]byte("x"), []*x509.Certificate{signOnly.cert}, EncryptOptions{}); !errors.Is(err, ErrWrongUsage) {
		t.Fatalf("sign-only certificate: %v", err)
	}
	ed := p.user(t, userOpts{keyType: "ed25519"})
	if _, err := Encrypt([]byte("x"), []*x509.Certificate{ed.cert}, EncryptOptions{}); err == nil {
		t.Fatal("encrypted to an Ed25519 key")
	}
}

// RFC 3394, section 4.
func TestKeyWrapVectors(t *testing.T) {
	for _, v := range []struct{ kek, key, wrapped string }{
		{"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
	} {
		kek, _ := hex.DecodeString(v.kek)
		key, _ := hex.DecodeString(v.key)
		want, _ := hex.DecodeString(v.wrapped)
		got, err := keyWrap(kek, key)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wrap: %x, %v", got, err)
		}
		back, err := keyUnwrap(kek, want)
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("unwrap: %x, %v", back, err)
		}
		want[3] ^= 1
		if _, err := keyUnwrap(kek, want); !errors.Is(err, ErrDecryption) {
			t.Fatalf("tampered unwrap: %v", err)
		}
	}
}

// SEC 1 / X9.63 KDF, checked against the vector in the NIST CAVS
// ansx963_2001 set (SHA-256, no shared info).
func TestX963KDF(t *testing.T) {
	z, _ := hex.DecodeString("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08")
	want, _ := hex.DecodeString("443024c3dae66b95e6f5670601558f71")
	if got := x963KDF(crypto.SHA256, z, nil, 16); !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
}

func TestBERToDER(t *testing.T) {
	// SEQUENCE (indefinite) { OCTET STRING constructed (indefinite)
	// { "ab", "cd" }, INTEGER 5 with a long-form length }
	ber, _ := hex.DecodeString("3080" + "2480" + "04026162" + "04026364" + "0000" + "02810105" + "0000")
	want, _ := hex.DecodeString("3009" + "040461626364" + "020105")
	got, err := toDER(ber, DefaultLimits)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x, %v", got, err)
	}
	// DER comes back as is.
	same, err := toDER(want, DefaultLimits)
	if err != nil || &same[0] != &want[0] {
		t.Fatal("DER input was copied or refused")
	}
	for _, bad := range []string{"3080", "30800000ff", "2403040261", "0480", "3084ffffffff00", "3002040100", "30030401"} {
		b, _ := hex.DecodeString(bad)
		if _, err := toDER(b, DefaultLimits); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	// Depth is bounded.
	deep := bytes.Repeat([]byte{0x30, 0x80}, 100)
	deep = append(deep, bytes.Repeat([]byte{0, 0}, 100)...)
	if _, err := toDER(deep, DefaultLimits); !errors.Is(err, ErrLimit) {
		t.Fatalf("deep nesting: %v", err)
	}
}
