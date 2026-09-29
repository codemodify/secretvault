package svcms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"
)

// A small PKI made with crypto/x509, for tests that need no other
// implementation: a root, an intermediate, and people under it.

type testPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
}

type testUser struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var (
	pkiOnce   sync.Once
	sharedPKI *testPKI
	rsaKeys   = map[string]*rsa.PrivateKey{}
	rsaMu     sync.Mutex
)

// rsaKey returns the RSA key of that name, made once: RSA key generation
// is slow.
func rsaKey(t testing.TB, name string, bits int) *rsa.PrivateKey {
	rsaMu.Lock()
	defer rsaMu.Unlock()
	if k, ok := rsaKeys[name]; ok {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	rsaKeys[name] = k
	return k
}

var serial int64 = 1000

func nextSerial() *big.Int {
	rsaMu.Lock()
	defer rsaMu.Unlock()
	serial++
	return big.NewInt(serial)
}

func getPKI(t testing.TB) *testPKI {
	pkiOnce.Do(func() {
		p := &testPKI{}
		rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		now := time.Now()
		rootTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "svcms test root"},
			NotBefore:             now.Add(-48 * time.Hour),
			NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		p.root, _ = x509.ParseCertificate(der)
		p.rootKey = rootKey
		interTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "svcms test intermediate"},
			NotBefore:             now.Add(-48 * time.Hour),
			NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err = x509.CreateCertificate(rand.Reader, interTmpl, p.root, interKey.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		p.inter, _ = x509.ParseCertificate(der)
		p.interKey = interKey
		sharedPKI = p
	})
	if sharedPKI == nil {
		t.Fatal("no test PKI")
	}
	return sharedPKI
}

type userOpts struct {
	keyType      string // "rsa" and "rsa2" (2048), "rsa1024", "p256", "p384", "p521", "ed25519"
	email        string
	eku          []x509.ExtKeyUsage
	keyUsage     x509.KeyUsage
	notBefore    time.Time
	notAfter     time.Time
	subjectEmail bool // put the address in the subject as emailAddress, not in a SAN
}

func (p *testPKI) user(t testing.TB, o userOpts) *testUser {
	var key crypto.Signer
	switch o.keyType {
	case "", "rsa":
		key = rsaKey(t, "rsa", 2048)
	case "rsa2":
		key = rsaKey(t, "rsa2", 2048)
	case "rsa1024":
		key = rsaKey(t, "rsa1024", 1024)
	case "p256":
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, key, _ = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unknown key type %q", o.keyType)
	}
	if o.email == "" {
		o.email = "alice@example.org"
	}
	if o.eku == nil {
		o.eku = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	}
	if o.keyUsage == 0 {
		o.keyUsage = x509.KeyUsageDigitalSignature
		switch key.Public().(type) {
		case *rsa.PublicKey:
			o.keyUsage |= x509.KeyUsageKeyEncipherment
		case *ecdsa.PublicKey:
			o.keyUsage |= x509.KeyUsageKeyAgreement
		}
	}
	now := time.Now()
	if o.notBefore.IsZero() {
		o.notBefore = now.Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = now.Add(365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: "Test " + o.email},
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		ExtKeyUsage:  o.eku,
		KeyUsage:     o.keyUsage,
	}
	if o.subjectEmail {
		tmpl.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: oidEmailAddress, Value: o.email}}
	} else {
		tmpl.EmailAddresses = []string{o.email}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter, key.Public(), p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testUser{cert: cert, key: key}
}
