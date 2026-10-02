package svmanager

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

func TestFilesAreSignedCheckedAndDecryptedWithOpenPGP(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	k, err := h.admin.GeneratePGP(h.ctx(), svrpc.PGPGenerateParams{Name: "Ada", Emails: []string{"ada@example.org"}, Version: 4})
	if err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(h.dir, "doc.txt")
	os.WriteFile(doc, []byte("the plan\n"), 0o600)

	h.m.signFile()
	h.waitText("Sign a file")
	h.fill("File", doc)
	h.press("Sign")
	h.said("Signed with pgp/ada@example.org; wrote " + doc + ".asc")
	sig, err := os.ReadFile(doc + ".asc")
	if err != nil || !bytes.Contains(sig, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("the signature: %q %v", sig, err)
	}

	h.m.verifyFile()
	h.pump()
	h.fill("File", doc)
	h.fill("Signature", doc+".asc")
	h.fill("From", "ada@example.org")
	h.press("Check")
	h.waitText("The signature")
	if !strings.Contains(h.text(), "Signature:") {
		t.Fatalf("the verdict:\n%s", h.text())
	}
	h.press("Close")

	// Decrypt what is encrypted to the key.
	pub, err := svpgp.ReadKey(strings.NewReader(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := svpgp.Encrypt(&ct, []*svpgp.Key{pub}, svpgp.EncryptOptions{Armor: true})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "for your eyes")
	w.Close()
	enc := filepath.Join(h.dir, "enc.asc")
	os.WriteFile(enc, ct.Bytes(), 0o600)
	plain := filepath.Join(h.dir, "plain.txt")
	h.m.decryptPGPFile()
	h.waitText("Decrypt a file (OpenPGP)")
	h.fill("File", enc)
	h.fill("Write to", plain)
	h.press("Decrypt")
	h.said("Decrypted with pgp/ada@example.org; wrote " + plain)
	if b, _ := os.ReadFile(plain); string(b) != "for your eyes" {
		t.Fatalf("decrypted %q", b)
	}
	if st, _ := os.Stat(plain); st.Mode().Perm() != 0o600 {
		t.Fatalf("the plaintext's mode is %v", st.Mode().Perm())
	}
}

func TestFilesAreEncryptedAndDecryptedWithAge(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	if _, err := svops.AgeKeygen(h.ctx(), h.admin, svrpc.Ref{Item: "age/me"}, false); err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(h.dir, "doc.txt")
	os.WriteFile(doc, []byte("age secret\n"), 0o600)
	enc := filepath.Join(h.dir, "doc.age")
	h.m.encryptAgeFile()
	h.waitText("Encrypt a file (age)")
	h.fill("File", doc)
	h.fill("Write to", enc)
	h.choose("Add", 1)
	h.press("Encrypt")
	h.said("Encrypted doc.txt into " + enc)

	out := filepath.Join(h.dir, "out.txt")
	h.m.decryptAgeFile()
	h.waitText("Decrypt a file (age)")
	h.fill("File", enc)
	h.fill("Write to", out)
	h.press("Decrypt")
	h.said("Decrypted doc.age into " + out)
	if b, _ := os.ReadFile(out); string(b) != "age secret\n" {
		t.Fatalf("decrypted %q", b)
	}

	// To a passphrase, asked for twice; and back with it.
	enc2 := filepath.Join(h.dir, "doc2.age")
	h.m.encryptAgeFile()
	h.waitText("Encrypt a file (age)")
	h.fill("File", doc)
	h.fill("Write to", enc2)
	h.tick("To a passphrase instead", true)
	h.press("Encrypt")
	h.waitText("The file's passphrase")
	h.answer(map[string]string{"Passphrase": "a file passphrase", "Repeat": "a file passphrase"})
	h.said("Encrypted doc.txt into " + enc2)
	if b, _ := os.ReadFile(enc2); !bytes.HasPrefix(b, []byte("age-encryption.org/v1")) {
		t.Fatalf("not an age file: %q", b[:min(40, len(b))])
	}
	out2 := filepath.Join(h.dir, "out2.txt")
	h.m.decryptAgeFile()
	h.waitText("Decrypt a file (age)")
	h.fill("File", enc2)
	h.fill("Write to", out2)
	h.tick("age/me", false)
	h.press("Decrypt")
	h.waitText("The file's passphrase")
	h.answer(map[string]string{"Passphrase": "a file passphrase"})
	h.said("Decrypted doc2.age")
	if b, _ := os.ReadFile(out2); string(b) != "age secret\n" {
		t.Fatalf("decrypted %q", b)
	}
	_ = svage.ErrIncorrectIdentity
}

func TestMailIsInspectedAndComposed(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}, Version: 4}); err != nil {
		t.Fatal(err)
	}
	msg := filepath.Join(h.dir, "out.eml")
	os.WriteFile(msg, []byte("From: Me <me@example.org>\r\nTo: Me <me@example.org>\r\nSubject: the plan\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNoon it is.\r\n"), 0o600)
	sent := filepath.Join(h.dir, "sent.eml")
	h.m.composeMessage()
	h.pump()
	h.fill("Message", msg)
	h.tick("Encrypt it", false)
	h.fill("Write to", sent)
	h.press("Write")
	h.said("Wrote " + sent + " (openpgp, signed with pgp/me@example.org)")

	h.m.inspectMessage()
	h.pump()
	h.fill("Message", sent)
	h.press("Inspect")
	h.waitText("The message's layers")
	if !strings.Contains(h.text(), "Subject (protected)") || strings.Contains(h.text(), "the plan") || !strings.Contains(h.text(), "signature:") {
		t.Fatalf("the report:\n%s", h.text())
	}
	if strings.Contains(h.text(), "Noon it is.") {
		t.Fatal("the text was shown before it was asked for")
	}
	h.press("Close")
}

func TestReferencesAreResolvedAndChecked(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.resolveReference()
	h.pump()
	h.fill("Reference", "sv://personal/web/github.com#username")
	h.press("Resolve")
	h.waitText("sv://personal/web/github.com#username names:")
	shown := h.secrets()
	if len(shown) != 1 || string(shown[0].value) != "ada" || strings.Contains(h.text(), "ada\n") {
		t.Fatalf("the value: %+v", shown)
	}
	held := shown[0].value
	h.press("Close")
	if !allZero(held) {
		t.Fatal("the value outlived its dialog")
	}

	env := filepath.Join(h.dir, "app.env")
	os.WriteFile(env, []byte("PLAIN=1\nTOKEN=sv://-/web/github.com\nMISSING=sv://-/web/nothing\n"), 0o600)
	h.picks = []string{env}
	h.m.checkEnvFile()
	h.waitText("References in app.env")
	if !strings.Contains(h.text(), "1 of 2 references resolve") || !strings.Contains(h.text(), "TOKEN = sv://-/web/github.com: resolves") {
		t.Fatalf("the check:\n%s", h.text())
	}
	if strings.Contains(h.text(), "hunter2") {
		t.Fatal("a value was shown")
	}
	h.press("Close")

	tmpl := filepath.Join(h.dir, "config.tmpl")
	os.WriteFile(tmpl, []byte("user = {{ sv://-/web/github.com#username }}\npass = {{ sv://-/web/github.com }}\n"), 0o600)
	filled := filepath.Join(h.dir, "config")
	h.m.checkTemplate()
	h.pump()
	h.fill("Template", tmpl)
	h.fill("Fill it into", filled)
	h.press("Check")
	h.waitText("Filled into " + filled)
	if b, _ := os.ReadFile(filled); string(b) != "user = ada\npass = hunter2-github\n" {
		t.Fatalf("filled %q", b)
	}
	if st, _ := os.Stat(filled); st.Mode().Perm() != 0o600 {
		t.Fatalf("filled with mode %v", st.Mode().Perm())
	}
}
