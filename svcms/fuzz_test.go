package svcms

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Whatever the parsers accept must be usable, and nothing, accepted or
// not, may panic or run away with memory or time. The seeds are messages
// and files made here.

var fuzzLimits = &Limits{MaxIterations: 2000, MaxSize: 1 << 20}

func fuzzSeeds(f *testing.F) (*testPKI, *testUser, *testUser) {
	p := getPKI(f)
	rsaUser := p.user(f, userOpts{keyType: "rsa"})
	ecUser := p.user(f, userOpts{keyType: "p256"})
	for _, u := range []*testUser{rsaUser, ecUser} {
		for _, attached := range []bool{false, true} {
			der, err := Sign([]byte("seed"), u.key, []*x509.Certificate{u.cert, p.inter}, SignOptions{Attached: attached})
			if err != nil {
				f.Fatal(err)
			}
			f.Add(der)
		}
	}
	for _, legacy := range []bool{false, true} {
		der, err := Encrypt([]byte("seed"), []*x509.Certificate{rsaUser.cert, ecUser.cert}, EncryptOptions{Legacy: legacy})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(der)
	}
	der, err := EncodePKCS12(ecUser.key, ecUser.cert, []*x509.Certificate{p.inter}, []byte("pw"), &PKCS12Options{Iterations: 10})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)
	ber, _ := hex.DecodeString("3080" + "2480" + "04026162" + "04026364" + "0000" + "02810105" + "0000")
	f.Add(ber)
	return p, rsaUser, ecUser
}

func FuzzBER(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		der, err := toDER(data, fuzzLimits.withDefaults())
		if err != nil {
			return
		}
		// The result is one well-formed element, and rewriting it again
		// changes nothing.
		s := cryptobyte.String(der)
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !s.ReadAnyASN1Element(&el, &tag) && len(der) > 0 && der[0]&0x1f != 0x1f {
			t.Fatalf("toDER made something cryptobyte cannot read: %x", der)
		}
		again, err := toDER(der, fuzzLimits.withDefaults())
		if err != nil || !bytes.Equal(again, der) {
			t.Fatalf("not idempotent: %x -> %x (%v)", der, again, err)
		}
	})
}

func FuzzSignedData(f *testing.F) {
	p, _, _ := fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		sd, err := ParseSignedData(data, fuzzLimits)
		if err != nil {
			return
		}
		res, err := sd.Verify(VerifyOptions{Content: []byte("seed"), Roots: []*x509.Certificate{p.root}})
		if err != nil {
			return
		}
		for _, r := range res {
			if r.Valid && r.Certificate == nil {
				t.Fatal("valid without a certificate")
			}
		}
	})
}

func FuzzEnvelopedData(f *testing.F) {
	_, rsaUser, ecUser := fuzzSeeds(f)
	d1, _ := KeyDecrypter(rsaUser.cert, rsaUser.key)
	d2, _ := KeyDecrypter(ecUser.cert, ecUser.key)
	f.Fuzz(func(t *testing.T, data []byte) {
		ed, err := ParseEnvelopedData(data, fuzzLimits)
		if err != nil {
			return
		}
		ed.Decrypt(Decrypters{d1, d2})
	})
}

func FuzzPKCS12(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		DecodePKCS12(data, []byte("pw"), fuzzLimits)
	})
}
