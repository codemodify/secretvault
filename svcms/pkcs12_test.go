package svcms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

func TestPKCS12RoundTrip(t *testing.T) {
	p := getPKI(t)
	for _, key := range []string{"rsa", "p256", "p521", "ed25519"} {
		t.Run(key, func(t *testing.T) {
			u := p.user(t, userOpts{keyType: key})
			for _, pw := range []string{"hunter2", "", "ünïcødé 🔑"} {
				der, err := EncodePKCS12(u.key, u.cert, []*x509.Certificate{p.inter, p.root}, []byte(pw), &PKCS12Options{Iterations: 1000, FriendlyName: "Alice's key"})
				if err != nil {
					t.Fatal(err)
				}
				got, err := DecodePKCS12(der, []byte(pw), nil)
				if err != nil {
					t.Fatalf("password %q: %v", pw, err)
				}
				if !keysEqual(got.PrivateKey, u.key) || !got.Certificate.Equal(u.cert) || len(got.CACertificates) != 2 {
					t.Fatal("round trip lost something")
				}
				if got.FriendlyName != "Alice's key" || len(got.Warnings) != 0 {
					t.Fatalf("name %q, warnings %q", got.FriendlyName, got.Warnings)
				}
				parsed, err := x509.ParsePKCS8PrivateKey(got.PrivateKeyPKCS8)
				if err != nil || !keysEqual(parsed, u.key) {
					t.Fatal("PKCS #8 bytes do not hold the key")
				}
				if _, err := DecodePKCS12(der, []byte(pw+"!"), nil); !errors.Is(err, ErrPassword) {
					t.Fatalf("wrong password: %v", err)
				}
			}
		})
	}
	// The key must match the certificate.
	a, b := p.user(t, userOpts{keyType: "p256"}), p.user(t, userOpts{keyType: "p256"})
	if _, err := EncodePKCS12(a.key, b.cert, nil, []byte("x"), nil); err == nil {
		t.Fatal("encoded a key with another's certificate")
	}
}

func TestPKCS12Tampered(t *testing.T) {
	p := getPKI(t)
	u := p.user(t, userOpts{keyType: "p256"})
	der, err := EncodePKCS12(u.key, u.cert, nil, []byte("pw"), &PKCS12Options{Iterations: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(der); i += 7 {
		bad := bytes.Clone(der)
		bad[i] ^= 0x04
		got, err := DecodePKCS12(bad, []byte("pw"), nil)
		if err == nil && (!keysEqual(got.PrivateKey, u.key) || !got.Certificate.Equal(u.cert)) {
			t.Fatalf("byte %d changed: a different key or certificate came back", i)
		}
	}
}

func TestPKCS12Limits(t *testing.T) {
	p := getPKI(t)
	u := p.user(t, userOpts{keyType: "p256"})
	der, err := EncodePKCS12(u.key, u.cert, nil, []byte("pw"), &PKCS12Options{Iterations: 5000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePKCS12(der, []byte("pw"), &Limits{MaxIterations: 4999}); !errors.Is(err, ErrLimit) {
		t.Fatalf("iteration limit: %v", err)
	}
}

// RFC 2268, section 5. The vectors are encryptions; decryption must invert
// each.
func TestRC2Vectors(t *testing.T) {
	for _, v := range []struct {
		key       string
		effective int
		plain     string
		cipher    string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"},
	} {
		key, _ := hex.DecodeString(v.key)
		plain, _ := hex.DecodeString(v.plain)
		want, _ := hex.DecodeString(v.cipher)
		c := newRC2(key, v.effective)
		got := make([]byte, 8)
		c.Encrypt(got, plain)
		if !bytes.Equal(got, want) {
			t.Fatalf("key %s: encrypt %x, want %x", v.key, got, want)
		}
		c.Decrypt(got, want)
		if !bytes.Equal(got, plain) {
			t.Fatalf("key %s: decrypt %x, want %x", v.key, got, plain)
		}
	}
}

// PKCS #12's KDF, against OpenSSL's (`openssl kdf ... PKCS12KDF`, given
// the password already in BMP form). The first two are also the example
// published with OpenSSL's original implementation.
func TestPKCS12KDF(t *testing.T) {
	for _, v := range []struct {
		hash     crypto.Hash
		id       byte
		password []byte
		salt     string
		iter, n  int
		want     string
	}{
		{crypto.SHA1, 1, bmpPassword([]byte("smeg")), "0A58CF64530D823F", 1, 24, "8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3"},
		{crypto.SHA1, 2, bmpPassword([]byte("smeg")), "0A58CF64530D823F", 1, 8, "79993DFE048D3B76"},
		{crypto.SHA256, 3, bmpPassword([]byte("pässwörd")), "0102030405060708090a", 1000, 32, "E4A17A5958BDFDE5005234B365A2112FB01E1B5E0A71E7A14E11DF92FB27D84F"},
		{crypto.SHA512, 1, bmpPassword([]byte("x")), "0102030405060708090a0b0c0d0e0f10", 3, 100, "41389CA0BAF87EEE4F894A0E6B2E9439E9331497E6CDBED673EF5FCB94202B62A2858B5C10DCCC4C0E182DA329789FFB5A191BD5624C35D1A250D58952EED1D16E9EF96E4D8AF67131D291B0DA61FC7F7192E079EB45C568CD465C8EF82ECC48F3D1054F"},
		{crypto.SHA256, 2, bmpPassword(nil), "aabbccdd", 2, 70, "816FBFB95AC2C159A7EEEA7D4B15E6F6D388295856C4DCDE553017D6BB85486B4D4D07FD25210AD4712EC19A3DC1756827202789A5827A1786E6F8860E27C2F725CD073EDE70"},
	} {
		salt, _ := hex.DecodeString(v.salt)
		want, _ := hex.DecodeString(v.want)
		if got := pkcs12KDF(v.hash, v.id, v.password, salt, v.iter, v.n); !bytes.Equal(got, want) {
			t.Fatalf("%v id %d: got %X", v.hash, v.id, got)
		}
	}
}
