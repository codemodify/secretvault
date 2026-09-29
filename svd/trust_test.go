package svd

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

func pgpKey(t *testing.T, version int, uid string) *svpgp.Key {
	t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: version, UserIDs: []string{uid}})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func armoredPublic(t *testing.T, k *svpgp.Key) []byte {
	t.Helper()
	b, err := k.Public().Armor(false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fpOf(k *svpgp.Key) string { return hexFP(k.Fingerprint()) }

// Reading contacts is a question of its own: a program allowed to read
// them may not read items, and the other way round; changing them is
// another question.
func TestContactsAreAskedAboutApartFromItems(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, alice)}, Source: "alice.asc"}); err != nil {
		t.Fatal(err)
	}
	if h.desk.count() != 0 {
		t.Fatal("the CLI that made the vault was asked")
	}

	mail := h.connect("/usr/bin/mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	v, err := mail.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(alice), From: "alice@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if q := h.desk.asked[0]; !strings.Contains(q.Description, `mail (/usr/bin/mail) wants to read your contacts in vault "personal".`) {
		t.Fatalf("the prompt said %q", q.Description)
	}
	if !v.Known || v.Contact != "Alice Example" || v.Trusted || v.Status != "unverified" {
		t.Fatalf("verdict = %+v", v)
	}
	// Remembered: no second question.
	if _, err := mail.Contacts(ctx(t), "", ""); err != nil {
		t.Fatal(err)
	}
	// The contacts decision covers no item...
	h.desk.script("cancel")
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("an item with a contacts grant: %v", err)
	}
	// ... nor changing contacts.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.KeySeen(ctx(t), svrpc.TrustSeenParams{Key: armoredPublic(t, alice), Address: "alice@example.org"}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a write with a read grant: %v", err)
	}
	if q := h.desk.asked[2]; !strings.Contains(q.Description, "wants to change your contacts") {
		t.Fatalf("the write prompt said %q", q.Description)
	}
	h.desk.done(t)

	grants, _ := cli.Grants(ctx(t), "")
	found := false
	for _, g := range grants {
		found = found || g.Program == "mail (/usr/bin/mail)" && g.Item == "contacts" && g.Decision == "allow-always"
	}
	if !found {
		t.Fatalf("grants = %+v", grants)
	}

	// Decided ahead of time, for a program nobody is there to ask about.
	if _, err := cli.Grant(ctx(t), svrpc.GrantAddParams{Program: "/usr/bin/true", Contacts: true, Ops: []string{"read", "write"}, Decision: "allow-always"}); err != nil {
		t.Fatal(err)
	}
	daemon := h.connect("/usr/bin/true", nil)
	if _, err := daemon.KeySeen(ctx(t), svrpc.TrustSeenParams{Key: armoredPublic(t, alice), Address: "alice@example.org"}); err != nil {
		t.Fatal(err)
	}
	if h.desk.count() != 3 {
		t.Fatal("a program decided about ahead of time was asked")
	}
}

// The verdict API end to end: verified in person, trust on first use, and
// a different key for a verified address.
func TestSignersVerdicts(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	ch, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, alice)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.VerifyContact(ctx(t), svrpc.ContactVerifyParams{Ref: "Alice Example", Fingerprint: fpOf(alice), Method: svrpc.VerifyFingerprint}); err != nil {
		t.Fatal(err)
	}
	v, err := cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(alice), From: "Alice <alice@example.org>"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Trusted || v.Level != "in-person" || len(v.Reasons) != 1 || !strings.HasPrefix(v.Reasons[0], "Signed by Alice Example's key, which you verified in person on ") {
		t.Fatalf("verified: %+v", v)
	}
	if v.Verification == nil || !strings.Contains(v.Verification.By, "secretvault") || v.Verification.Derived {
		t.Fatalf("recorded by %+v", v.Verification)
	}

	// A key seen three times from bob@: trust on first use.
	bob := pgpKey(t, 4, "Bob <bob@example.org>")
	for range 3 {
		if _, err := cli.KeySeen(ctx(t), svrpc.TrustSeenParams{Key: armoredPublic(t, bob), Address: "bob@example.org", Name: "Bob"}); err != nil {
			t.Fatal(err)
		}
	}
	v, _ = cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(bob), From: "bob@example.org"})
	if v.Trusted || v.Level != "tofu" || !strings.Contains(v.Reasons[0], "seen 3 times from bob@example.org") {
		t.Fatalf("TOFU: %+v", v)
	}
	if v, _ := cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(bob), From: "bob@example.org", MinLevel: "tofu"}); !v.Trusted {
		t.Fatal("a policy that accepts TOFU did not")
	}

	// Someone else's key for alice@: kept apart, and called an impostor.
	mallory := pgpKey(t, 6, "Alice Example <alice@example.org>")
	seen, err := cli.KeySeen(ctx(t), svrpc.TrustSeenParams{Key: armoredPublic(t, mallory), Address: "alice@example.org", Name: "Alice Example"})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Bound || len(seen.Conflicts) != 1 || seen.Conflicts[0].ContactID != ch.Contact.ID || seen.Contact.ID == ch.Contact.ID {
		t.Fatalf("a second key for alice: %+v", seen)
	}
	v, _ = cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(mallory), From: "alice@example.org"})
	if v.Trusted || v.Status != "suspicious" || !strings.Contains(v.Reasons[1], "This may be an impostor.") {
		t.Fatalf("impostor: %+v", v)
	}
	c, err := cli.Contact(ctx(t), "", seen.Contact.ID)
	if err != nil || len(c.Warnings) != 1 || len(c.Keys[0].Seen) != 1 || c.Keys[0].Seen[0].Conflicts[0] != fpOf(alice) {
		t.Fatalf("the kept-apart contact: %+v, %v", c, err)
	}
	if _, err := cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{From: "alice@example.org"}); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeInvalidParams}) {
		t.Fatalf("no signer: %v", err)
	}
}

// Your OpenPGP key signs and decrypts in the daemon; a program allowed to
// sign or decrypt still cannot read the key.
func TestPGPKeysStayInTheDaemon(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	key, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if key.Item != "pgp/me@example.org" || key.Version != 6 || key.UserIDs[0] != "Me <me@example.org>" {
		t.Fatalf("generated %+v", key)
	}
	if _, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Emails: []string{"me@example.org"}}); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a second key under the same name: %v", err)
	}
	pub, err := svpgp.ReadKey(strings.NewReader(key.PublicKey))
	if err != nil || pub.HasSecret() || fpOf(pub) != key.Fingerprint {
		t.Fatalf("public key: %v", err)
	}
	if got, err := cli.PGPPublicKey(ctx(t), "", "me@example.org"); err != nil || got.Fingerprint != key.Fingerprint {
		t.Fatalf("PGPPublicKey: %+v, %v", got, err)
	}

	mail := h.connect("/usr/bin/mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	sig, err := mail.SignPGP(ctx(t), svrpc.PGPSignParams{Data: []byte("hello"), Armor: true})
	if err != nil {
		t.Fatal(err)
	}
	if q := h.desk.asked[0]; !strings.Contains(q.Description, `wants to sign with "pgp/me@example.org"`) {
		t.Fatalf("the prompt said %q", q.Description)
	}
	res, err := svpgp.Verify(strings.NewReader("hello"), bytes.NewReader(sig.Signature), []*svpgp.Key{pub}, time.Time{})
	if err != nil || len(res) != 1 || !res[0].Valid {
		t.Fatalf("the signature: %+v, %v", res, err)
	}
	if _, err := mail.SignPGP(ctx(t), svrpc.PGPSignParams{Data: []byte("again")}); err != nil {
		t.Fatal(err)
	}
	// Signing is not reading the key.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.Get(ctx(t), "", key.Item); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("reading the key with a sign grant: %v", err)
	}

	// A message to the key, signed by a contact.
	bob := pgpKey(t, 6, "Bob <bob@example.org>")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, bob)}}); err != nil {
		t.Fatal(err)
	}
	cli.VerifyContact(ctx(t), svrpc.ContactVerifyParams{Fingerprint: fpOf(bob), Method: svrpc.VerifyQR})
	var ct bytes.Buffer
	w, err := svpgp.Encrypt(&ct, []*svpgp.Key{pub}, svpgp.EncryptOptions{Signer: bob, Armor: true})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "meet at noon")
	w.Close()
	h.desk.script("choose:"+svrpc.ChoiceOnce, "choose:"+svrpc.ChoiceOnce)
	dec, err := mail.DecryptPGP(ctx(t), svrpc.PGPDecryptParams{Data: ct.Bytes(), Verify: true, From: "bob@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if string(dec.Body) != "meet at noon" || dec.Item != key.Item || len(dec.Signatures) != 1 {
		t.Fatalf("decrypted %+v", dec)
	}
	if s := dec.Signatures[0]; !s.Valid || s.Signer != fpOf(bob) || s.Verdict == nil || !s.Verdict.Trusted || s.Verdict.Contact != "Bob" {
		t.Fatalf("the signature inside: %+v", s)
	}
	if !strings.Contains(h.desk.asked[3].Description, `wants to decrypt with "pgp/me@example.org"`) {
		t.Fatalf("the decrypt prompt said %q", h.desk.asked[3].Description)
	}
	h.desk.done(t)

	// Not encrypted to any key here.
	var other bytes.Buffer
	w, _ = svpgp.Encrypt(&other, []*svpgp.Key{bob.Public()}, svpgp.EncryptOptions{})
	w.Write([]byte("x"))
	w.Close()
	if _, err := cli.DecryptPGP(ctx(t), svrpc.PGPDecryptParams{Data: other.Bytes()}); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("someone else's message: %v", err)
	}

	// A detached signature by a contact, checked against the claimed sender.
	var bobSig bytes.Buffer
	svpgp.Sign(&bobSig, strings.NewReader("minutes"), bob, svpgp.SignOptions{})
	ver, err := cli.VerifyPGP(ctx(t), svrpc.PGPVerifyParams{Data: []byte("minutes"), Signature: bobSig.Bytes(), From: "alice@example.org"})
	if err != nil || len(ver.Signatures) != 1 || !ver.Signatures[0].Valid || ver.Signatures[0].Verdict.Trusted || ver.Signatures[0].Verdict.Bound {
		t.Fatalf("Bob's signature, from alice's address: %+v, %v", ver, err)
	}
	ver, _ = cli.VerifyPGP(ctx(t), svrpc.PGPVerifyParams{Data: []byte("tampered"), Signature: bobSig.Bytes(), From: "bob@example.org"})
	if s := ver.Signatures[0]; s.Valid || s.Verdict.Trusted || s.Verdict.Status != "invalid" {
		t.Fatalf("a bad signature: %+v", s)
	}
}

func TestLookupAndTheContactsVault(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	carol := pgpKey(t, 6, "Carol <carol@example.org>")
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vks/v1/by-email/carol@example.org" {
			w.Write(armoredPublic(t, carol))
			return
		}
		http.NotFound(w, r)
	}))
	defer ks.Close()

	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "people", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	if name, err := cli.ContactsVault(ctx(t), "people"); err != nil || name != "people" {
		t.Fatalf("ContactsVault = %q, %v", name, err)
	}
	res, err := cli.LookupContact(ctx(t), svrpc.ContactLookupParams{Query: "carol@example.org", Keyserver: ks.URL, Add: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Found) != 1 || len(res.Added) != 1 || !res.Added[0].New || res.Found[0].Keys[0].Fingerprint != fpOf(carol) {
		t.Fatalf("lookup: %+v", res)
	}
	c, err := cli.Contact(ctx(t), "people", "carol@example.org")
	if err != nil || c.Origin != "lookup" || c.Level != "published" || c.Keys[0].Verifications[0].Method != "keyserver-email" {
		t.Fatalf("carol = %+v, %v", c, err)
	}
	if cs, _ := cli.Contacts(ctx(t), "personal", ""); len(cs) != 0 {
		t.Fatal("contacts went to the default vault")
	}
	if _, err := cli.LookupContact(ctx(t), svrpc.ContactLookupParams{Query: "dave@example.org", Keyserver: ks.URL}); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("nobody: %v", err)
	}
	// Only secretvault's own CLI moves the contacts.
	mail := h.connect("/usr/bin/mail", nil)
	if _, err := mail.ContactsVault(ctx(t), "personal"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a program moved the contacts: %v", err)
	}
	if name, _ := cli.ContactsVault(ctx(t), "-"); name != "personal" {
		t.Fatalf("back to the default: %q", name)
	}

	// A scanned QR code verifies the key it names in person.
	card := "openpgp4fpr:" + fpOf(carol) + "#a=carol%40example.org&n=Carol"
	if _, err := cli.ContactsVault(ctx(t), "people"); err != nil {
		t.Fatal(err)
	}
	imp, err := cli.ImportContacts(ctx(t), svrpc.ContactImportParams{URI: card})
	if err != nil || len(imp.Keys) != 1 || !imp.Keys[0].Verified {
		t.Fatalf("scan: %+v, %v", imp, err)
	}
	if v, _ := cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Fingerprint: fpOf(carol), From: "carol@example.org"}); v.Level != "in-person" {
		t.Fatalf("after the scan: %+v", v)
	}
}
