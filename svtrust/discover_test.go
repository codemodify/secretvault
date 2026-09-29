package svtrust

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeInternet serves handler over TLS for the hosts that exist, with a
// certificate for all of them from a CA only the returned client trusts.
// Other hosts do not resolve. Nothing leaves the machine.
func fakeInternet(t *testing.T, handler http.Handler, hosts ...string) *http.Client {
	t.Helper()
	root := newCAValidNow(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, key.Public(), root.key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	c := DefaultClient()
	c.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if !slices.Contains(hosts, host) {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	return c
}

// newCAValidNow is a CA valid around the real time, for TLS.
func newCAValidNow(t *testing.T) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Internet"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert, key}
}

func TestWKDHashAndURLs(t *testing.T) {
	// The example of draft-koch-openpgp-webkey-service.
	if got := WKDHash("Joe.Doe"); got != "iy9q119eutrkn8s1mk4r39qejnbu3n5q" {
		t.Fatalf("WKDHash = %q", got)
	}
	adv, dir, err := WKDURLs("Joe.Doe@Example.ORG")
	if err != nil {
		t.Fatal(err)
	}
	if adv != "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" ||
		dir != "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe" {
		t.Fatalf("URLs:\n%s\n%s", adv, dir)
	}
	if _, _, err := WKDURLs("nobody"); err == nil {
		t.Fatal("an address without a domain")
	}
}

func TestWKDLookup(t *testing.T) {
	alice := pgpKey(t, 6, "Alice <alice@example.org>", "Alice <alice@elsewhere.example>")
	aliceNet := pgpKey(t, 4, "Alice <alice@example.net>")
	bob := pgpKey(t, 6, "Bob <bob@example.org>")
	var aliceBin, aliceNetBin, bobBin bytes.Buffer
	alice.Serialize(&aliceBin, false)
	aliceNet.Serialize(&aliceNetBin, false)
	bob.Serialize(&bobBin, false)
	hash := WKDHash("alice")
	var asked []string
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Host+r.URL.Path)
		switch r.Host + r.URL.Path {
		case "openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/" + hash:
			if r.URL.Query().Get("l") != "alice" {
				http.Error(w, "no l", 400)
				return
			}
			w.Write(append(bobBin.Bytes(), aliceBin.Bytes()...)) // another key too
		case "openpgpkey.example.org/.well-known/openpgpkey/example.org/policy":
			w.Write([]byte("# policy\nmailbox-only\nprotocol-version: 13\n"))
		case "example.net/.well-known/openpgpkey/hu/" + hash:
			w.Write(aliceNetBin.Bytes())
		case "example.com/.well-known/openpgpkey/hu/" + hash:
			w.Write(bobBin.Bytes()) // a key that is not alice's
		case "example.com/.well-known/openpgpkey/hu/" + WKDHash("big"):
			w.Write(make([]byte, 2<<20))
		default:
			http.NotFound(w, r)
		}
	})
	client := fakeInternet(t, mux, "openpgpkey.example.org", "example.org", "example.net", "example.com")
	w := &WKD{Client: client, Now: func() time.Time { return day0 }}
	ctx := context.Background()

	f, err := w.Lookup(ctx, "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Keys) != 1 || f.Keys[0].Fingerprint != fpOf(alice) || !strings.HasPrefix(f.URL, "https://openpgpkey.example.org/") {
		t.Fatalf("advanced: %+v", f)
	}
	k := f.Keys[0]
	if !slices.Equal(k.Addresses, []string{"alice@example.org"}) || len(k.Events) != 1 || k.Events[0].Method != MethodWKD ||
		k.Events[0].Level != Published || !slices.Equal(k.Events[0].Addresses, []string{"alice@example.org"}) || k.Source != f.URL {
		t.Fatalf("the key from WKD: %+v", k)
	}
	if !slices.Equal(f.Policy, []string{"mailbox-only", "protocol-version: 13"}) {
		t.Fatalf("policy = %q", f.Policy)
	}

	// No openpgpkey subdomain: the direct method.
	f, err = w.Lookup(ctx, "alice@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.URL, "https://example.net/.well-known/openpgpkey/hu/") || f.Policy != nil || f.Keys[0].Fingerprint != fpOf(aliceNet) {
		t.Fatalf("direct: %+v", f)
	}

	// A key that does not name the address is refused; none is not found;
	// too much is too much.
	if _, err := w.Lookup(ctx, "alice@example.com"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("someone else's key: %v", err)
	}
	if _, err := w.Lookup(ctx, "carol@example.org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := w.Lookup(ctx, "big@example.com"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("a huge answer: %v", err)
	}
	// A domain that does not exist at all.
	if _, err := w.Lookup(ctx, "alice@nowhere.example"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("no such domain: %v", err)
	}
}

func TestKeyserverVKSThenHKP(t *testing.T) {
	alice := pgpKey(t, 4, "Alice <alice@example.org>")
	bob := pgpKey(t, 4, "Bob <bob@example.org>")
	mallory := pgpKey(t, 4, "Mallory <mallory@example.org>")
	mux := http.NewServeMux()
	mux.HandleFunc("/vks/v1/by-email/{email}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("email") != "alice@example.org" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		w.Write(armored(t, alice, false))
	})
	mux.HandleFunc("/vks/v1/by-fingerprint/{fp}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("fp") == fpOf(bob) {
			w.Write(armored(t, mallory, false)) // not the key asked for
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/pks/lookup", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("op") == "get" && q.Get("search") == "bob@example.org" {
			w.Write(armored(t, bob, false))
			return
		}
		http.NotFound(w, r)
	})
	client := fakeInternet(t, mux, "keys.example")
	ks := &Keyserver{URL: "hkps://keys.example", Client: client, Now: func() time.Time { return day0 }}
	ctx := context.Background()

	f, err := ks.ByEmail(ctx, "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if f.URL != "https://keys.example/vks/v1/by-email/alice@example.org" || len(f.Keys) != 1 {
		t.Fatalf("VKS: %+v", f)
	}
	if e := f.Keys[0].Events; len(e) != 1 || e[0].Method != MethodKeyserver || !slices.Equal(e[0].Addresses, []string{"alice@example.org"}) {
		t.Fatalf("VKS events: %+v", e)
	}

	// Not on VKS: HKP, whose keys come unverified.
	f, err = ks.ByEmail(ctx, "bob@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.URL, "/pks/lookup?op=get") || len(f.Keys[0].Events) != 0 || !f.Keys[0].Bound("bob@example.org") {
		t.Fatalf("HKP: %+v", f.Keys[0])
	}

	// A keyserver answering with another key than the one asked for.
	if _, err := ks.ByFingerprint(ctx, fpOf(bob)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the wrong key: %v", err)
	}
	if _, err := ks.ByFingerprint(ctx, "not hex"); err == nil {
		t.Fatal("a fingerprint that is not one")
	}

	for in, want := range map[string]string{
		"":                      "https://keys.openpgp.org",
		"hkp://pool.example":    "http://pool.example:11371",
		"hkps://pool.example/":  "https://pool.example",
		"https://h.example:444": "https://h.example:444",
	} {
		if got, err := (&Keyserver{URL: in}).base(); err != nil || got != want {
			t.Errorf("base(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := (&Keyserver{URL: "ftp://x"}).base(); err == nil {
		t.Error("an ftp keyserver")
	}
}

// directory is an organisation's directory, in memory.
type directory map[string][]byte

func (d directory) Name() string { return "Example Corp (LDAP)" }

func (d directory) Lookup(_ context.Context, addr string) ([]*Key, error) {
	if data, ok := d[addr]; ok {
		return ParseKeys(data)
	}
	return nil, nil
}

func TestADirectoryVouches(t *testing.T) {
	s, _ := newStore(t)
	pk := pgpKey(t, 6, "Dana <dana@example.org>")
	f, err := LookupDirectory(context.Background(), directory{"dana@example.org": armored(t, pk, false)}, "Dana <dana@example.org>", day0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import(f.Keys, ImportOptions{By: "you", Origin: OriginLookup}); err != nil {
		t.Fatal(err)
	}
	wantReasons(t, check(t, s, fpOf(pk), "dana@example.org"),
		"Signed by a key, which the directory Example Corp (LDAP) lists (checked on 2026-09-01).")
	if _, err := LookupDirectory(context.Background(), directory{}, "x@example.org", day0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nobody: %v", err)
	}
}

func TestContactURIs(t *testing.T) {
	line, _ := sshLine(t, "a@b")
	sshKey := keyOf(t, []byte(line))
	pgp := keyOf(t, armored(t, pgpKey(t, 6, "Alice <alice@example.org>"), false))
	card := CardOf("Alice Example", []string{"alice@example.org"}, []*Key{pgp, sshKey})
	uri := card.URI()
	if !strings.HasPrefix(uri, "secretvault-contact:v1?n=Alice+Example&e=alice%40example.org&pgp="+pgp.Fingerprint+"&ssh=SHA256%3A") {
		t.Fatalf("URI = %s", uri)
	}
	back, err := ParseCard(uri + "&future=1")
	if err != nil {
		t.Fatal(err)
	}
	if back.Name != card.Name || !slices.Equal(back.Emails, card.Emails) || !slices.Equal(back.Keys, card.Keys) {
		t.Fatalf("round trip: %+v", back)
	}

	fp := strings.ToLower(pgp.Fingerprint)
	c, err := ParseCard("OPENPGP4FPR:" + fp + "#a=alice%40example.org&n=Alice")
	if err != nil || c.Keys[0] != (CardKey{OpenPGP, pgp.Fingerprint}) || c.Name != "Alice" || c.Emails[0] != "alice@example.org" {
		t.Fatalf("openpgp4fpr: %+v, %v", c, err)
	}
	for _, bad := range []string{
		"https://example.org",
		"openpgp4fpr:1234",
		"secretvault-contact:v2?pgp=" + pgp.Fingerprint,
		"secretvault-contact:v1?n=nobody",
		"secretvault-contact:v1?ssh=MD5:00",
		"secretvault-contact:v1?e=not-an-address&pgp=" + pgp.Fingerprint,
	} {
		if _, err := ParseCard(bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

func TestScanningACardVerifiesAndFetches(t *testing.T) {
	s, _ := newStore(t)
	have := pgpKey(t, 6, "Alice <alice@example.org>")
	res, err := s.Seen(keyOf(t, armored(t, have, false)), "alice@example.org", day0, "", "mail", "")
	if err != nil || res.Contact.Name != "alice@example.org" {
		t.Fatalf("Seen: %+v, %v", res, err)
	}
	fetchMe := pgpKey(t, 4, "Alice <alice@example.org>")
	line, _ := sshLine(t, "alice@laptop")
	sshKey := keyOf(t, []byte(line))
	card := &Card{Name: "Alice Example", Emails: []string{"alice@example.org", "alice@work.example"}, Keys: []CardKey{
		{OpenPGP, fpOf(have)}, {OpenPGP, fpOf(fetchMe)}, {SSH, sshKey.Fingerprint},
	}}
	var fetched []string
	fetch := func(fp string) ([]*Key, error) {
		fetched = append(fetched, fp)
		return []*Key{keyOf(t, armored(t, fetchMe, false))}, nil
	}
	sr, err := s.Scan(card, "you", fetch)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fetched, []string{fpOf(fetchMe)}) || len(sr.Verified) != 2 || len(sr.Missing) != 1 || sr.Missing[0].Type != SSH {
		t.Fatalf("scan: fetched %v, %+v", fetched, sr)
	}
	c := sr.Contact
	if c.Name != "Alice Example" || c.Origin != OriginQR || len(c.Keys) != 2 || !slices.Equal(c.Emails, card.Emails) {
		t.Fatalf("contact = %+v", c)
	}
	for _, fp := range []string{fpOf(have), fpOf(fetchMe)} {
		v := check(t, s, fp, "alice@work.example")
		if v.Level != InPerson || !v.Bound || v.Verification.Method != MethodQR {
			t.Fatalf("%s after the scan: %+v", fp, v)
		}
	}
	u, _ := url.Parse(card.URI())
	if u.Scheme != ContactScheme {
		t.Fatal(u)
	}
}
