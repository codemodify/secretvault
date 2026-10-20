package svmanager

import (
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

	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// openKeysPage opens the keys page at tab, the vault unlocked.
func (h *harness) openKeysPage(tab int) *keysPage {
	h.t.Helper()
	h.m.showKeysPage(tab)
	h.waitFor("the keys page", h.m.showingVaultPage)
	h.idle()
	return h.m.kpage
}

// answer types into the question a worker asked (askSecret), and goes
// on.
func (h *harness) answer(fields map[string]string) {
	h.t.Helper()
	for name, v := range fields {
		h.fill(name, v)
	}
	h.press("Continue")
}

func TestOpenPGPKeysAreMadeExportedAndImported(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openKeysPage(tabPGP)
	if !strings.Contains(h.text(), "No OpenPGP keys yet") {
		t.Fatalf("the empty tab:\n%s", h.text())
	}
	h.pressOn("New…")
	h.fill("Your name", "Ada Lovelace")
	h.fill("Addresses", "ada@example.org")
	h.tick("Version 4", true)
	h.press("Make the key")
	h.waitText("Made a version 4 OpenPGP key, kept as ada@example.org")
	h.press("Close")
	h.idle()
	if len(p.pgp) != 1 {
		t.Fatalf("the tab lists %d keys", len(p.pgp))
	}

	h.pressOn("Copy the public key")
	h.waitFor("the copy", func() bool {
		c := h.clip.last()
		return c != nil && strings.Contains(c.text, "BEGIN PGP PUBLIC KEY BLOCK")
	})

	// The secret key, out under a new passphrase.
	out := filepath.Join(h.dir, "ada.asc")
	h.pressOn("Export…")
	h.choose("Export", 1)
	h.fill("File", out)
	h.press("Export the key")
	h.waitText("The exported key's passphrase")
	h.answer(map[string]string{"Passphrase": "exported key pass", "Repeat": "exported key pass"})
	h.said("Wrote it to " + out)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	k, err := svpgp.ReadKey(strings.NewReader(string(data)))
	if err != nil || !k.HasSecret() || !k.Locked() {
		t.Fatalf("the export: %v", err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("written with mode %v", st.Mode().Perm())
	}

	// And in again, as another item: its passphrase is asked for.
	h.pressOn("Import…")
	h.fill("Key file", out)
	h.fill("Item name", "pgp/ada-again")
	h.press("Import the key")
	h.waitText("The key's passphrase")
	h.answer(map[string]string{"Passphrase": "exported key pass"})
	h.said("as pgp/ada-again")
	h.idle()
	if len(p.pgp) != 2 {
		t.Fatalf("the tab lists %d keys", len(p.pgp))
	}
	// A name taken is said in this program's words.
	h.pressOn("Import…")
	h.fill("Key file", out)
	h.fill("Item name", "pgp/ada-again")
	h.press("Import the key")
	h.waitText("The key's passphrase")
	h.answer(map[string]string{"Passphrase": "exported key pass"})
	if got := h.failed(); !strings.Contains(got, "give the key another name") || strings.Contains(got, "--item") {
		t.Fatalf("a name taken: %q", got)
	}
}

func TestSMIMEKeysAreImported(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "me@example.org"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		EmailAddresses: []string{"me@example.org"}, SubjectKeyId: []byte("me")}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	cert, _ := x509.ParseCertificate(der)
	p12, err := svcms.EncodePKCS12(key, cert, nil, []byte("p12 password"), &svcms.PKCS12Options{Iterations: 2048})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h.dir, "me.p12")
	os.WriteFile(file, p12, 0o600)
	p := h.openKeysPage(tabSMIME)
	h.pressOn("Import…")
	h.fill("File", file)
	h.fill("The file's password", "wrong")
	h.press("Import the key")
	if got := h.failed(); got == "" {
		t.Fatal("a wrong password was taken")
	}
	h.fill("The file's password", "p12 password")
	h.press("Import the key")
	h.waitText("S/MIME key imported")
	h.press("Close")
	h.idle()
	if len(p.smime) != 1 || p.smime[0].Emails[0] != "me@example.org" {
		t.Fatalf("the tab lists %+v", p.smime)
	}
}

func TestAgeIdentitiesAndIdentityFiles(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openKeysPage(tabAge)
	idLine := filepath.Join(h.dir, "backups.txt")
	h.pressOn("New…")
	h.fill("Item name", "age/backups")
	h.fill("Identity line file", idLine)
	h.press("Make the identity")
	h.waitText("Made a new X25519 age identity, kept as age/backups")
	h.press("Close")
	h.idle()
	if len(p.age) != 1 {
		t.Fatalf("the tab lists %d", len(p.age))
	}
	if b, err := os.ReadFile(idLine); err != nil || !strings.Contains(string(b), "AGE-PLUGIN-SECRETVAULT-1") {
		t.Fatalf("the identity file: %q %v", b, err)
	}
	h.pressOn("Copy the public key")
	h.waitFor("the recipient", func() bool { c := h.clip.last(); return c != nil && strings.HasPrefix(c.text, "age1") })
	h.pressOn("Copy the identity line")
	h.waitFor("the identity line", func() bool { c := h.clip.last(); return strings.HasPrefix(c.text, "AGE-PLUGIN-SECRETVAULT-1") })

	h.m.showTools(tabIdentities)
	h.idle()
	file := filepath.Join(h.dir, "me.id")
	h.pressOn("New identity file…")
	h.fill("File", file)
	h.press("Make the file")
	h.waitText("Identity file made")
	want, err := svops.IdentityRecipient(file)
	if err != nil || !strings.Contains(h.text(), want) {
		t.Fatalf("the recipient shown is not the file's (%v):\n%s", err, h.text())
	}
	h.press("Close")
	h.picks = []string{file}
	h.pressOn("Show a file's public key…")
	h.waitText("The public key (recipient) of the identity in " + filepath.Base(file))
}

func TestSecurityKeysPluggedIn(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.m.showTools(tabSecurityKeys)
	h.waitText("No security key is plugged in")
	h.plug(fidotest.Options{Name: "YubiKey 5", PIN: "1234"})
	h.pressOn("Refresh")
	h.waitText("set, 8 tries left")
	if !strings.Contains(h.text(), "can open a vault") || strings.Contains(h.text(), "cannot open a vault") {
		t.Fatalf("the key:\n%s", h.text())
	}
	_ = svrpc.FIDO2Device{}
}
