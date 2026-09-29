package svmail

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Keys made in the test process: OpenPGP keys with svpgp, and a small
// S/MIME PKI with crypto/x509.

var (
	pgpKeysMu sync.Mutex
	pgpKeys   = map[string]*svpgp.Key{}
)

// pgpKey returns the (unlocked, secret) version 4 key for a user ID, made
// once.
func pgpKey(t testing.TB, uid string) *svpgp.Key {
	pgpKeysMu.Lock()
	defer pgpKeysMu.Unlock()
	if k, ok := pgpKeys[uid]; ok {
		return k
	}
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{uid}})
	if err != nil {
		t.Fatal(err)
	}
	pgpKeys[uid] = k
	return k
}

type smimeUser struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type smimePKI struct {
	root, inter *x509.Certificate
	interKey    crypto.Signer
	users       map[string]*smimeUser
	mu          sync.Mutex
}

var (
	pkiOnce sync.Once
	pki     *smimePKI
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func getPKI(t testing.TB) *smimePKI {
	pkiOnce.Do(func() {
		rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		now := time.Now()
		rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "svmail test root"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour * 3650), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ := x509.CreateCertificate(rand.Reader, rootT, rootT, rootKey.Public(), rootKey)
		root, _ := x509.ParseCertificate(der)
		interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "svmail test intermediate"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour * 3650), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ = x509.CreateCertificate(rand.Reader, interT, root, interKey.Public(), rootKey)
		inter, _ := x509.ParseCertificate(der)
		pki = &smimePKI{root: root, inter: inter, interKey: interKey, users: map[string]*smimeUser{}}
	})
	return pki
}

// user returns the certificate and key for an address, made once: RSA for
// addresses starting "rsa", P-256 otherwise.
func (p *smimePKI) user(t testing.TB, email string) *smimeUser {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.users[email]; ok {
		return u
	}
	var key crypto.Signer
	ku := x509.KeyUsageDigitalSignature
	if strings.HasPrefix(email, "rsa") {
		rsaOnce.Do(func() { rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048) })
		key = rsaKey
		ku |= x509.KeyUsageKeyEncipherment
	} else {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ku |= x509.KeyUsageKeyAgreement
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(int64(100 + len(p.users))),
		Subject:        pkix.Name{CommonName: email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour * 365),
		EmailAddresses: []string{email},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		KeyUsage:       ku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter, key.Public(), p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	u := &smimeUser{cert: cert, key: key}
	p.users[email] = u
	return u
}

func (u *smimeUser) decrypter(t testing.TB) svcms.Decrypter {
	d, err := svcms.KeyDecrypter(u.cert, u.key)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// testMessage is a message as a mail client composes it.
const testMessage = `From: Alice <alice@example.org>
To: Bob <bob@example.org>
Subject: Lunch?
Date: Mon, 28 Sep 2026 12:00:00 +0000
Message-ID: <1@example.org>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Grüße, see attached.
--b1
Content-Type: application/octet-stream; name="data.bin"
Content-Disposition: attachment; filename="data.bin"
Content-Transfer-Encoding: base64

AAECAw==
--b1--
`

func inspect(t testing.TB, raw []byte, keys Keys) *Report {
	t.Helper()
	r, err := Inspect(raw, keys)
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, raw)
	}
	// Every report must go over RPC.
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func dump(r *Report) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

func hasWarning(r *Report, code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// textOf returns the text of the first text/plain part that is not a
// legacy display part.
func textOf(r *Report) string {
	for _, p := range r.Parts {
		if p.ContentType == "text/plain" && !p.LegacyDisplay {
			return p.Text
		}
	}
	return ""
}
