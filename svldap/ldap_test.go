package svldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/ldaptest"
)

func aliceCert(t *testing.T) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Alice Example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		EmailAddresses: []string{"alice@example.org"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestADirectoryGivesAlicesCertificate(t *testing.T) {
	for _, ldaps := range []bool{false, true} {
		s := ldaptest.New(t, ldaptest.Options{LDAPS: ldaps, BindDN: "cn=reader,dc=example,dc=org", Password: "s3cret",
			People: map[string]map[string][][]byte{"alice@example.org": {"userCertificate;binary": {aliceCert(t)}}}})
		if !ldaps {
			// Pretend the directory is not on this machine: StartTLS.
			saved := plainOK
			plainOK = func(string) bool { return false }
			t.Cleanup(func() { plainOK = saved })
		}
		d := &Directory{Label: "Example", URL: s.URL, BaseDN: ldaptest.Base, BindDN: "cn=reader,dc=example,dc=org",
			TLS:      &tls.Config{RootCAs: s.Roots, ServerName: "localhost"},
			Password: func(context.Context) ([]byte, error) { return []byte("s3cret"), nil }}
		keys, err := d.Lookup(context.Background(), "alice@example.org")
		if err != nil {
			t.Fatalf("ldaps=%v: %v", ldaps, err)
		}
		if len(keys) != 1 || keys[0].Addresses[0] != "alice@example.org" {
			t.Fatalf("ldaps=%v: keys %+v", ldaps, keys)
		}
		if !ldaps && !s.DidStartTLS() {
			t.Fatal("ldap:// to another machine did not StartTLS")
		}
		if keys, _ := d.Lookup(context.Background(), "bob@example.org"); len(keys) != 0 {
			t.Fatalf("bob: %+v", keys)
		}
		// An address cannot change the search: it is only ever a value.
		d.Lookup(context.Background(), "*)(mail=*")
		if seen := s.Seen(); seen[len(seen)-2] != "*)(mail=*" {
			t.Fatalf("the value sent: %q", seen)
		}
		d.Password = func(context.Context) ([]byte, error) { return []byte("wrong"), nil }
		var re *ResultError
		if _, err := d.Lookup(context.Background(), "alice@example.org"); !errors.As(err, &re) || re.Code != 49 {
			t.Fatalf("a wrong password: %v", err)
		}
	}
}

func TestOnlyLDAPURLsAreDialled(t *testing.T) {
	for _, u := range []string{"http://x", "ldap://", "x", "ldapi:///run/slapd"} {
		if _, err := Dial(context.Background(), u, nil); !errors.Is(err, ErrURL) {
			t.Errorf("%s: %v", u, err)
		}
	}
}
