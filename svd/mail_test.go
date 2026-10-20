package svd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

const plainMail = "From: Alice Example <alice@example.org>\r\nTo: Me <me@example.org>\r\nSubject: the plan\r\nMessage-ID: <1@example.org>\r\nDate: Tue, 29 Sep 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMeet at noon.\r\n"

func inspectMail(t *testing.T, c *secretvault.Client, msg []byte, decrypt bool) (*svmail.Report, []svrpc.MailVerdict, error) {
	t.Helper()
	res, err := c.InspectMail(ctx(t), svrpc.MailInspectParams{Message: msg, Decrypt: decrypt})
	if err != nil {
		return nil, nil, err
	}
	var rep svmail.Report
	if err := json.Unmarshal(res.Report, &rep); err != nil {
		t.Fatal(err)
	}
	return &rep, res.Verdicts, nil
}

func TestAMailClientLearnsWhoSignedAndReadsWhatIsForYou(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, alice)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.VerifyContact(ctx(t), svrpc.ContactVerifyParams{Ref: "Alice Example", Fingerprint: fpOf(alice), Method: svrpc.VerifyFingerprint}); err != nil {
		t.Fatal(err)
	}
	me, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := svpgp.ReadKey(strings.NewReader(me.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	mail := h.connect("/usr/bin/mail-client", nil)
	// Signed by Alice: valid, and she is someone you verified in person.
	signed, err := svmail.SignPGPMIME([]byte(plainMail), alice, &svmail.ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	h.desk.script("choose:" + svrpc.ChoiceLock) // reading the contacts
	rep, verdicts, err := inspectMail(t, mail, signed, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Signed != svmail.CoverFull || len(verdicts) != 1 {
		t.Fatalf("signed: %s, verdicts %+v", rep.Signed, verdicts)
	}
	if v := verdicts[0].Verdict; !v.Trusted || v.Level != "in-person" || !strings.Contains(v.Reasons[0], "Alice Example") {
		t.Fatalf("the verdict on Alice: %+v", v)
	}

	// Changed on the way: not valid, whoever signed it.
	tampered := bytes.Replace(signed, []byte("Meet at noon."), []byte("Meet at one. "), 1)
	if _, verdicts, err = inspectMail(t, mail, tampered, false); err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 1 || verdicts[0].Verdict.Trusted || verdicts[0].Verdict.Status != "invalid" {
		t.Fatalf("a changed message: %+v", verdicts)
	}

	// Encrypted to you and signed by Alice. Without decrypt the key is
	// never touched; with it, decrypting is asked about on its own.
	sealed, err := svmail.EncryptPGPMIME([]byte(plainMail), []*svpgp.Key{mine}, alice, &svmail.ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	asked := h.desk.count()
	rep, _, err = inspectMail(t, mail, sealed, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Encrypted != svmail.CoverFull || h.desk.count() != asked || strings.Contains(string(mustJSON(t, rep)), "Meet at noon") {
		t.Fatalf("not asked to decrypt: encrypted %s, prompts %d, report %s", rep.Encrypted, h.desk.count()-asked, mustJSON(t, rep))
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce) // decrypting with the key
	rep, verdicts, err = inspectMail(t, mail, sealed, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustJSON(t, rep)), "Meet at noon") {
		t.Fatalf("decrypted: %s", mustJSON(t, rep))
	}
	if len(verdicts) != 1 || !verdicts[0].Verdict.Trusted {
		t.Fatalf("the signature inside: %+v", verdicts)
	}
	if q := h.desk.asked[len(h.desk.asked)-1]; !strings.Contains(q.Description, "decrypt") {
		t.Fatalf("decrypting was asked as %q", q.Description)
	}
	h.desk.done(t)
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// smimeUser makes a self-signed S/MIME certificate for addr, and its key.
func smimeUser(t *testing.T, addr string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: addr},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{addr}, SubjectKeyId: []byte(addr),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

const outgoing = "From: Me <me@example.org>\r\nTo: Alice Example <alice@example.org>\r\nSubject: the plan\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNoon it is.\r\n"

func TestOutgoingMailIsSignedWithYourKeyAndEncryptedToTheirs(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, alice)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}}); err != nil {
		t.Fatal(err)
	}
	app := h.connect("/usr/bin/mail-client", nil)
	h.desk.script("choose:"+svrpc.ChoiceLock, "choose:"+svrpc.ChoiceOnce) // the contacts, then signing
	res, err := app.ComposeMail(ctx(t), svrpc.MailComposeParams{Message: []byte(outgoing), Sign: true, Encrypt: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "openpgp" || res.SignedWith != "me@example.org" || len(res.EncryptedTo) != 1 {
		t.Fatalf("composed: %+v", res)
	}
	if q := h.desk.asked[len(h.desk.asked)-1]; !strings.Contains(q.Description, "sign") {
		t.Fatalf("signing was asked as %q", q.Description)
	}
	// Alice reads it with her own key, outside secretvault.
	rep, err := svmail.Inspect(res.Message, &svmail.LocalKeys{PGP: []*svpgp.Key{alice}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Encrypted != svmail.CoverFull || !strings.Contains(string(mustJSON(t, rep)), "Noon it is.") || strings.Contains(string(res.Message), "Noon it is.") {
		t.Fatalf("Alice's view: encrypted %s\n%s", rep.Encrypted, mustJSON(t, rep))
	}
	// Someone without a key cannot be encrypted to.
	bob := strings.Replace(outgoing, "Alice Example <alice@example.org>", "bob@example.org", 1)
	if _, err := app.ComposeMail(ctx(t), svrpc.MailComposeParams{Message: []byte(bob), Encrypt: true}); err == nil || !strings.Contains(err.Error(), "bob@example.org") {
		t.Fatalf("encrypting to someone with no key: %v", err)
	}
	h.desk.done(t)
}

func TestYourSMIMEKeyDecryptsAndSigns(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	mine, myKey := smimeUser(t, "me@example.org")
	p12, err := svcms.EncodePKCS12(myKey, mine, nil, []byte("p12 password"), &svcms.PKCS12Options{Iterations: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.ImportSMIME(ctx(t), svrpc.SMIMEImportParams{PKCS12: p12, Password: []byte("wrong")}); !errors.Is(err, svrpc.ErrWrongKey) {
		t.Fatalf("a wrong password: %v", err)
	}
	k, err := cli.ImportSMIME(ctx(t), svrpc.SMIMEImportParams{PKCS12: p12, Password: []byte("p12 password")})
	if err != nil || k.Item != "me@example.org" {
		t.Fatalf("import: %+v, %v", k, err)
	}
	if ks, err := cli.SMIMEKeys(ctx(t), ""); err != nil || len(ks) != 1 || ks[0].SHA256 != k.SHA256 {
		t.Fatalf("list: %+v, %v", ks, err)
	}

	// Alice's certificate, as a contact; she encrypts to you.
	aliceCert, aliceKey := smimeUser(t, "alice@example.org")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{aliceCert.Raw}}); err != nil {
		t.Fatal(err)
	}
	toMe := strings.Replace(strings.Replace(outgoing, "From: Me <me@example.org>", "From: alice@example.org", 1), "To: Alice Example <alice@example.org>", "To: me@example.org", 1)
	sealed, err := svmail.EncryptSMIME([]byte(toMe), []*x509.Certificate{mine}, aliceKey, []*x509.Certificate{aliceCert}, nil)
	if err != nil {
		t.Fatal(err)
	}
	app := h.connect("/usr/bin/mail-client", nil)
	h.desk.script("choose:"+svrpc.ChoiceLock, "choose:"+svrpc.ChoiceOnce) // the contacts, then decrypting
	rep, _, err := inspectMail(t, app, sealed, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustJSON(t, rep)), "Noon it is.") {
		t.Fatalf("decrypted with your S/MIME key: %s", mustJSON(t, rep))
	}

	// And you answer, signed and encrypted: S/MIME, as Alice has only a
	// certificate.
	h.desk.script("choose:" + svrpc.ChoiceOnce) // signing
	res, err := app.ComposeMail(ctx(t), svrpc.MailComposeParams{Message: []byte(outgoing), Sign: true, Encrypt: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "smime" || res.SignedWith != "me@example.org" {
		t.Fatalf("composed: %+v", res)
	}
	dec, _ := svcms.KeyDecrypter(aliceCert, aliceKey)
	rep, err = svmail.Inspect(res.Message, &svmail.LocalKeys{SMIME: []svcms.Decrypter{dec}, Roots: []*x509.Certificate{mine}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustJSON(t, rep)), "Noon it is.") || rep.Signed != svmail.CoverFull {
		t.Fatalf("Alice's view: signed %s\n%s", rep.Signed, mustJSON(t, rep))
	}
	h.desk.done(t)
}
