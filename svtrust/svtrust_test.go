package svtrust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svstore"
)

// day0 is when the tests' stores think it is.
var day0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func cheapKDF(t testing.TB) {
	t.Helper()
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })
}

func newVault(t testing.TB, store svstore.Backend, device byte, now func() time.Time) *svcore.Vault {
	t.Helper()
	cheapKDF(t)
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: []byte("correct horse")},
		svcore.Options{Device: svformat.ID{device}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// newStore is a store in a fresh vault, whose clock the test moves.
func newStore(t testing.TB) (*Store, *time.Time) {
	t.Helper()
	clock := day0
	s := NewStore(newVault(t, svstore.NewMem(), 1, nil))
	s.Now = func() time.Time { return clock }
	return s, &clock
}

func pgpKey(t testing.TB, version int, uids ...string) *svpgp.Key {
	t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: version, UserIDs: uids})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func armored(t testing.TB, k *svpgp.Key, secret bool) []byte {
	t.Helper()
	b, err := k.Armor(secret)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keyOf reads one public key the way a caller of the store would.
func keyOf(t testing.TB, data []byte) *Key {
	t.Helper()
	k, err := ParseKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fpOf(k *svpgp.Key) string { return hexFP(k.Fingerprint()) }

// certificates: an organisation's CA and the S/MIME certificates it
// issues.
type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var certStart, certEnd = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)

func newCA(t testing.TB, name string) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: certStart, NotAfter: certEnd, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert, key}
}

func (c *ca) issue(t testing.TB, name, email string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: certStart, NotAfter: certEnd, EmailAddresses: []string{email},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func pemOf(certs ...*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

func sshLine(t testing.TB, comment string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment, sp
}

func TestParseKeysReadsEveryType(t *testing.T) {
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>", "Alice <alice@work.example>")
	bob := pgpKey(t, 4, "Bob <bob@example.org>")

	// OpenPGP: two armored keys, and one binary.
	keys, err := ParseKeys(append(armored(t, alice, false), armored(t, bob, false)...))
	if err != nil || len(keys) != 2 {
		t.Fatalf("two armored keys: %v, %v", keys, err)
	}
	a := keys[0]
	if a.Type != OpenPGP || a.Fingerprint != fpOf(alice) || len(a.Fingerprint) != 64 || a.Label != "Alice Example <alice@example.org>" ||
		len(a.Addresses) != 2 || !a.Bound("ALICE@example.org") || len(a.Subkeys) != 1 {
		t.Fatalf("alice = %+v", a)
	}
	if keys[1].Fingerprint != fpOf(bob) || len(keys[1].Fingerprint) != 40 {
		t.Fatalf("bob = %+v", keys[1])
	}
	var bin bytes.Buffer
	bob.Serialize(&bin, false)
	if k := keyOf(t, bin.Bytes()); k.Fingerprint != fpOf(bob) {
		t.Fatalf("binary: %+v", k)
	}
	// A secret key gives its public part only.
	k := keyOf(t, armored(t, alice, true))
	if back, err := svpgp.ReadKey(bytes.NewReader(k.Material)); err != nil || back.HasSecret() {
		t.Fatalf("a secret key's material: %v, secret %v", err, back.HasSecret())
	}

	// X.509: a certificate with its CA is one key with a chain.
	org := newCA(t, "Example Root")
	leaf := org.issue(t, "Carol Example", "carol@example.org")
	keys, err = ParseKeys(pemOf(leaf, org.cert))
	if err != nil || len(keys) != 1 {
		t.Fatalf("chain: %v, %v", keys, err)
	}
	c := keys[0]
	if c.Type != X509 || c.Label != "Carol Example" || len(c.Chain) != 1 || !c.Bound("carol@example.org") || len(c.Fingerprint) != 64 {
		t.Fatalf("carol = %+v", c)
	}
	if k := keyOf(t, leaf.Raw); k.Fingerprint != c.Fingerprint {
		t.Fatal("DER and PEM disagree")
	}
	if k := keyOf(t, pemOf(org.cert)); k.Label != "Example Root" || len(k.Chain) != 0 {
		t.Fatalf("a CA alone: %+v", k)
	}

	// SSH: authorized_keys lines, with options and comments.
	l1, p1 := sshLine(t, "dave@laptop")
	l2, _ := sshLine(t, "dave@desktop")
	keys, err = ParseKeys([]byte("# dave's keys\n" + l1 + "\nno-pty,from=\"10.0.0.0/8\" " + l2 + "\n"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("ssh: %v, %v", keys, err)
	}
	if keys[0].Type != SSH || keys[0].Fingerprint != ssh.FingerprintSHA256(p1) || keys[0].Label != "dave@laptop" || len(keys[0].Addresses) != 0 {
		t.Fatalf("ssh key = %+v", keys[0])
	}

	// secretvault recipients, as 'identity pub' prints them.
	id, _ := svcrypto.Modern.NewIdentity()
	rcpt := svformat.EncodeRecipient(svcrypto.Modern, id.Recipient())
	if k := keyOf(t, []byte(rcpt+"\n")); k.Type != Secretvault || string(k.Material) != rcpt || len(k.Fingerprint) != 64 {
		t.Fatalf("recipient = %+v", k)
	}

	// Private material is refused; nothing is not a key.
	priv, _ := id.Bytes()
	identityFile := "# recipient: " + rcpt + "\n" + svformat.EncodeIdentity(svcrypto.Modern, priv) + "\n"
	for _, bad := range []struct {
		data string
		err  error
	}{
		{identityFile, ErrPrivate},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", ErrPrivate},
		{"hello", ErrNoKey},
		{"", ErrNoKey},
	} {
		if _, err := ParseKeys([]byte(bad.data)); !errors.Is(err, bad.err) {
			t.Errorf("%.20q: %v, want %v", bad.data, err, bad.err)
		}
	}
}

func TestFingerprintsAndAddressesAsPeopleWriteThem(t *testing.T) {
	for in, want := range map[string]string{
		"0xabcd ef01":         "ABCDEF01",
		"AB:CD:EF":            "ABCDEF",
		"SHA256:AbC+/d":       "SHA256:AbC+/d",
		" 7a3b4c5d6e7f8a9b\t": "7A3B4C5D6E7F8A9B",
		"not a fingerprint!!": "not a fingerprint!!",
	} {
		if got := NormalizeFingerprint(in); got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"Alice <alice@example.org>":        "alice@example.org",
		"\"Example, Alice\" <a@b.example>": "a@b.example",
		"bob@example.org":                  "bob@example.org",
		"no address":                       "",
		"two@at@signs":                     "",
	} {
		if got := ParseAddress(in); got != want {
			t.Errorf("ParseAddress(%q) = %q, want %q", in, got, want)
		}
	}
	name, addr := SplitUserID("Alice Example (work) <alice@example.org>")
	if name != "Alice Example" || addr != "alice@example.org" {
		t.Errorf("SplitUserID = %q, %q", name, addr)
	}
}

// Members a newer version adds survive this one reading and rewriting a
// contact, at every level.
func TestContactJSONKeepsWhatItDoesNotKnow(t *testing.T) {
	in := `{"v":1,"name":"Alice","future":{"x":1},"created":"2026-09-01T12:00:00Z",
		"keys":[{"type":"openpgp","fingerprint":"AB","material":"AQI=","added":"2026-09-01T12:00:00Z","pinned":true,
			"events":[{"level":"in-person","method":"fingerprint","at":"2026-09-01T12:00:00Z","witness":"Bob"}],
			"seen":[{"address":"a@b.example","first":"2026-09-01T12:00:00Z","last":"2026-09-01T12:00:00Z","count":2,"via":"imap"}]}]}`
	c, err := decodeContact([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "Alice Example"
	c.Keys[0].Events[0].By = "you"
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"future":{"x":1}`, `"pinned":true`, `"witness":"Bob"`, `"via":"imap"`, `"name":"Alice Example"`, `"by":"you"`, `"count":2`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%s lost %s", out, want)
		}
	}
	back, err := decodeContact(out)
	if err != nil || back.Keys[0].Seen[0].Count != 2 || string(back.Keys[0].Material) != "\x01\x02" {
		t.Fatalf("round trip: %+v, %v", back, err)
	}
	// Known members are not kept twice, whatever their case.
	if c, _ := decodeContact([]byte(`{"Name":"x","v":1}`)); c.unknown != nil || c.Name != "x" {
		t.Fatalf("a known member kept as unknown: %v", c.unknown)
	}
}
