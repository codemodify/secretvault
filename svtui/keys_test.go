package svtui

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// file writes a file in the test's directory.
func (h *harness) file(name, content string) string {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// waitSaid waits for the status line's message to hold want, however
// long the message is.
func (h *harness) waitSaid(want string) {
	h.t.Helper()
	h.eventually("the message "+want, func() bool { return strings.Contains(h.u.message, tview.Escape(want)) })
}

// lastCopy is what was copied last.
func (h *harness) lastCopy() string {
	h.t.Helper()
	var got []string
	h.eventually("a copy", func() bool {
		got = h.copies()
		return len(got) > 0
	})
	return got[len(got)-1]
}

func TestOpenPGPKeysAreMadeExportedImportedAndUsed(t *testing.T) {
	h := newHarness(t)
	const filePass = "a passphrase for the file"
	h.start(Options{}, filePass)
	h.unlock()
	h.typeText("P")
	h.waitFor("Keys · personal")
	h.waitFor("None (n makes one)")

	// A new key.
	h.typeText("n")
	h.waitFor("New OpenPGP key in personal")
	h.typeText("Me")
	h.tabs(1)
	h.typeText("me@example.org")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("Made a version 6 OpenPGP key, stored as pgp/me@example.org")
	h.waitFor("Me <me@exampl")

	// Its public key, copied and exported.
	selectRef[pgpRef](h)
	h.typeText("c")
	if pub := h.lastCopy(); !strings.Contains(pub, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("copied %q", pub)
	}
	pubFile := filepath.Join(h.dir, "me.asc")
	h.typeText("e")
	h.waitFor("Export pgp/me@example.org")
	h.tabs(1)
	h.typeText(pubFile)
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitSaid("Wrote " + pubFile)
	b, _ := os.ReadFile(pubFile)
	pub, err := svpgp.ReadKey(bytes.NewReader(b))
	if err != nil || pub.HasSecret() {
		t.Fatalf("the exported public key: %v", err)
	}

	// The secret key, under a new passphrase.
	secFile := filepath.Join(h.dir, "me-secret.asc")
	h.typeText("e")
	h.waitFor("Export pgp/me@example.org")
	h.key(tcell.KeyEnter) // open the drop-down
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.tabs(1)
	h.typeText(secFile)
	h.tabs(2)
	h.typeText(filePass)
	h.tabs(1)
	h.typeText(filePass)
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitSaid("Wrote " + secFile)
	b, _ = os.ReadFile(secFile)
	sec, err := svpgp.ReadKey(bytes.NewReader(b))
	if err != nil || !sec.HasSecret() || !sec.Locked() || sec.Unlock([]byte(filePass)) != nil {
		t.Fatalf("the exported secret key: %v", err)
	}
	if h.leaked.Load() {
		t.Fatal("the new passphrase was drawn")
	}

	// A protected key from elsewhere: its passphrase is asked for.
	other, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 6, UserIDs: []string{"Other <other@example.org>"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Lock([]byte("its own"), nil); err != nil {
		t.Fatal(err)
	}
	armored, err := other.Armor(true)
	if err != nil {
		t.Fatal(err)
	}
	h.typeText("i")
	h.waitFor("Import an OpenPGP key into personal")
	h.typeText(h.file("other.asc", string(armored)))
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Passphrase of the key")
	h.typeText("its own")
	h.key(tcell.KeyEnter)
	h.waitFor("Imported")
	h.waitFor("pgp/other@example.org")
	h.key(tcell.KeyEscape)

	// Sign a file, and check the signature.
	doc := h.file("minutes.txt", "the minutes\n")
	h.menu("sign a file")
	h.waitFor("Sign a file")
	h.typeText(doc)
	h.tabs(1)
	h.typeText("pgp/me@example.org")
	h.tabs(6)
	h.key(tcell.KeyEnter)
	h.waitSaid("Signed minutes.txt with pgp/me@example.org: the signature is in " + doc + ".asc")
	h.menu("check a signature")
	h.waitFor("Check a signature")
	h.typeText(doc)
	h.tabs(1)
	h.typeText(doc + ".asc")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("Signature: ")
	h.waitFor("valid")
	h.key(tcell.KeyEscape)

	// Decrypt a file encrypted to the key.
	var enc bytes.Buffer
	w, err := svpgp.Encrypt(&enc, []*svpgp.Key{pub}, svpgp.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("for my eyes only\n"))
	w.Close()
	gpgFile := h.file("secret.txt.gpg", enc.String())
	h.menu("decrypt a file (openpgp)")
	h.waitFor("Decrypt a file (OpenPGP)")
	h.typeText(gpgFile)
	h.tabs(6)
	h.key(tcell.KeyEnter)
	h.waitSaid("Decrypted secret.txt.gpg into " + filepath.Join(h.dir, "secret.txt"))
	if got, _ := os.ReadFile(filepath.Join(h.dir, "secret.txt")); string(got) != "for my eyes only\n" {
		t.Fatalf("decrypted %q", got)
	}
	h.key(tcell.KeyEscape)

	// Compose a signed message, and inspect it.
	msg := "From: Me <me@example.org>\r\nTo: you@example.org\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello.\r\n"
	signed := filepath.Join(h.dir, "signed.eml")
	h.menu("sign and encrypt a message")
	h.waitFor("Sign and encrypt a message")
	h.typeText(h.file("out.eml", msg))
	h.tabs(2)
	h.key(tcell.KeyEnter) // not encrypted: you@example.org has no key
	h.tabs(3)
	h.typeText(signed)
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitSaid("Wrote " + signed)
	pubText, _ := os.ReadFile(pubFile)
	h.unlockAdmin("")
	if _, err := h.admin.AddContact(h.ctx(), svrpc.ContactAddParams{Keys: [][]byte{pubText}}); err != nil {
		t.Fatal(err)
	}
	h.menu("inspect a message")
	h.waitFor("Inspect a message")
	h.typeText(signed)
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("signature: valid")
	h.waitFor("Hello.")
}

func TestAgeIdentitiesEncryptAndDecrypt(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.typeText("P")
	h.waitFor("Keys · personal")
	h.typeText("k")
	h.waitFor("New age identity in personal")
	h.typeText("age/test")
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitFor("age identity age/test")
	lines := h.onceSecrets()
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "age1") || !strings.HasPrefix(lines[1], "AGE-PLUGIN-SECRETVAULT-1") {
		t.Fatalf("shown: %q", lines)
	}
	h.key(tcell.KeyEscape)
	selectRef[ageRef](h)
	h.typeText("r")
	if got := h.lastCopy(); got != lines[0] {
		t.Fatalf("copied the recipient %q, want %q", got, lines[0])
	}
	h.key(tcell.KeyEscape)

	// To the vault's identity, and back.
	plain := h.file("notes.txt", "age notes\n")
	h.menu("encrypt a file (age)")
	h.waitFor("Encrypt a file (age)")
	h.typeText(plain)
	h.tabs(1)
	h.typeText("sv://personal/age/test")
	h.tabs(8)
	h.key(tcell.KeyEnter)
	h.waitSaid("Encrypted notes.txt into " + plain + ".age")
	os.Remove(plain)
	h.menu("decrypt a file (age)")
	h.waitFor("Decrypt a file (age)")
	h.typeText(plain + ".age")
	h.tabs(1)
	h.typeText("sv://personal/age/test")
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitSaid("Decrypted notes.txt.age into " + plain)
	if got, _ := os.ReadFile(plain); string(got) != "age notes\n" {
		t.Fatalf("decrypted %q", got)
	}

	// To a passphrase, asked for again when decrypting.
	other := h.file("other.txt", "by passphrase\n")
	h.menu("encrypt a file (age)")
	h.waitFor("Encrypt a file (age)")
	h.typeText(other)
	h.tabs(3)
	h.typeText("age pass")
	h.tabs(1)
	h.typeText("age pass")
	h.tabs(5)
	h.key(tcell.KeyEnter)
	h.waitSaid("Encrypted other.txt into " + other + ".age")
	os.Remove(other)
	h.menu("decrypt a file (age)")
	h.waitFor("Decrypt a file (age)")
	h.typeText(other + ".age")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("encrypted to a passphrase")
	h.typeText("age pass")
	h.key(tcell.KeyEnter)
	h.waitSaid("Decrypted other.txt.age into " + other)
	if got, _ := os.ReadFile(other); string(got) != "by passphrase\n" {
		t.Fatalf("decrypted %q", got)
	}
}

func TestSMIMEKeysAndIdentityFiles(t *testing.T) {
	h := newHarness(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "me@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{"me@example.org"}, SubjectKeyId: []byte("me"),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	p12, err := svcms.EncodePKCS12(key, cert, nil, []byte("p12 password"), &svcms.PKCS12Options{Iterations: 2048})
	if err != nil {
		t.Fatal(err)
	}
	h.start(Options{}, "p12 password")
	h.unlock()
	h.typeText("P")
	h.waitFor("Keys · personal")
	h.typeText("m")
	h.waitFor("Import an S/MIME key into personal")
	h.typeText(h.file("me.p12", string(p12)))
	h.tabs(1)
	h.typeText("p12 password")
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Imported smime/me@example.org")
	h.waitFor("me@example.org, until")
	if h.leaked.Load() {
		t.Fatal("the file's password was drawn")
	}

	// An identity file, and its recipient.
	idFile := filepath.Join(h.dir, "me.id")
	h.typeText("f")
	h.waitFor("New identity file")
	h.typeText(idFile)
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Only you can read the new file")
	rcpt := h.onceSecrets()
	h.key(tcell.KeyEscape)
	h.typeText("p")
	h.waitFor("Public key of an identity file")
	h.typeText(idFile)
	h.key(tcell.KeyEnter)
	h.waitFor("Public key (recipient)")
	if got := h.onceSecrets(); len(rcpt) != 1 || len(got) != 1 || got[0] != rcpt[0] {
		t.Fatalf("the recipient %q, then %q", rcpt, got)
	}
}
