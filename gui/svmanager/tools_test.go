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
	h.fill("File to sign", doc)
	h.press("Sign the file")
	h.said("Signed doc.txt with ada@example.org: the signature is in " + doc + ".asc")
	sig, err := os.ReadFile(doc + ".asc")
	if err != nil || !bytes.Contains(sig, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("the signature: %q %v", sig, err)
	}

	h.m.verifyFile()
	h.pump()
	h.fill("Signed file", doc)
	h.fill("Signature file", doc+".asc")
	h.fill("Sent from", "ada@example.org")
	h.press("Check the signature")
	h.waitText("Signature checked")
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
	h.fill("Encrypted file", enc)
	h.fill("Save it decrypted to", plain)
	h.press("Decrypt the file")
	h.said("Decrypted enc.asc with ada@example.org into " + plain + ", which only you can read.")
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
	h.fill("File to encrypt", doc)
	h.fill("Save it encrypted to", enc)
	h.choose("Add a key", 1)
	h.press("Encrypt the file")
	h.said("Encrypted doc.txt into " + enc)

	out := filepath.Join(h.dir, "out.txt")
	h.m.decryptAgeFile()
	h.waitText("Decrypt a file (age)")
	h.fill("Encrypted file", enc)
	h.fill("Save it decrypted to", out)
	h.press("Decrypt the file")
	h.said("Decrypted doc.age into " + out)
	if b, _ := os.ReadFile(out); string(b) != "age secret\n" {
		t.Fatalf("decrypted %q", b)
	}

	// To a passphrase, asked for twice; and back with it.
	enc2 := filepath.Join(h.dir, "doc2.age")
	h.m.encryptAgeFile()
	h.waitText("Encrypt a file (age)")
	h.fill("File to encrypt", doc)
	h.fill("Save it encrypted to", enc2)
	h.tick("Use a passphrase instead", true)
	h.press("Encrypt the file")
	h.waitText("The file's passphrase")
	h.answer(map[string]string{"Passphrase": "a file passphrase", "Repeat": "a file passphrase"})
	h.said("Encrypted doc.txt into " + enc2)
	if b, _ := os.ReadFile(enc2); !bytes.HasPrefix(b, []byte("age-encryption.org/v1")) {
		t.Fatalf("not an age file: %q", b[:min(40, len(b))])
	}
	out2 := filepath.Join(h.dir, "out2.txt")
	h.m.decryptAgeFile()
	h.waitText("Decrypt a file (age)")
	h.fill("Encrypted file", enc2)
	h.fill("Save it decrypted to", out2)
	h.tick("age/me", false)
	h.press("Decrypt the file")
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
	h.fill("Save the result to", sent)
	h.press("Sign and encrypt")
	h.said("Wrote " + sent + " (openpgp, signed with me@example.org)")

	h.m.inspectMessage()
	h.pump()
	h.fill("Message", sent)
	h.press("Inspect the message")
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
	h.press("Show what it names")
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
	if !strings.Contains(h.text(), "1 of 2 references in it cannot be read") || !strings.Contains(h.text(), "TOKEN = sv://-/web/github.com: can be read") {
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
	h.press("Check the template")
	h.waitText("Filled into " + filled)
	if b, _ := os.ReadFile(filled); string(b) != "user = ada\npass = hunter2-github\n" {
		t.Fatalf("filled %q", b)
	}
	if st, _ := os.Stat(filled); st.Mode().Perm() != 0o600 {
		t.Fatalf("filled with mode %v", st.Mode().Perm())
	}
}
