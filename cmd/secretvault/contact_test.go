package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svtrust"
)

func newPGP(t *testing.T, version int, uid string) *svpgp.Key {
	t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: version, UserIDs: []string{uid}})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (h *harness) publicKeyFile(name string, k *svpgp.Key) string {
	h.t.Helper()
	b, err := k.Public().Armor(false)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.write(name, string(b))
}

// fails runs the CLI and fails the test unless it exits with code.
func (h *harness) fails(code int, args ...string) (string, string) {
	h.t.Helper()
	out, errs, got := h.run("", args...)
	if got != code {
		h.t.Fatalf("secretvault %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), got, code, out, errs)
	}
	return out, errs
}

func fpHex(k *svpgp.Key) string { return fmt.Sprintf("%X", k.Fingerprint()) }

func TestContactsAndVerdictsFromTheCommandLine(t *testing.T) {
	h := newHarness(t)
	h.init()
	alice := newPGP(t, 6, "Alice Example <alice@example.org>")
	file := h.publicKeyFile("alice.asc", alice)
	if out := h.ok("", h.with("contact", "add", file, "--notes", "met at FOSDEM")...); !strings.Contains(out, "Added Alice Example with 1 key(s).") {
		t.Fatalf("add said %q", out)
	}
	if out := h.ok("", h.with("contact", "ls")...); !strings.Contains(out, "Alice Example") || !strings.Contains(out, "not verified") {
		t.Fatalf("ls said %q", out)
	}

	fp := fpHex(alice)
	out, _ := h.fails(3, h.with("trust", "check", "--fingerprint", fp, "--from", "Alice <alice@example.org>")...)
	if out != "unverified\n  Signed by Alice Example's key, which you have not verified.\n" {
		t.Fatalf("check said %q", out)
	}
	// Fingerprints as people read them out: in groups, any case.
	spaced := strings.ToLower(svops.GroupFingerprint(fp))
	if out := h.ok("", h.with("contact", "verify", "Alice Example", "--fingerprint", spaced, "--in-person")...); !strings.Contains(out, "verified in person") {
		t.Fatalf("verify said %q", out)
	}
	out = h.ok("", h.with("trust", "check", "--fingerprint", fp, "--from", "alice@example.org")...)
	today := time.Now().UTC().Format("2006-01-02")
	if out != "verified\n  Signed by Alice Example's key, which you verified in person on "+today+".\n" {
		t.Fatalf("check said %q", out)
	}
	show := h.ok("", h.with("contact", "show", "alice@example.org")...)
	for _, want := range []string{"Alice Example", "met at FOSDEM", svops.GroupFingerprint(fp), "fingerprint compared in person on", "verified in person"} {
		if !strings.Contains(show, want) {
			t.Fatalf("show lacks %q:\n%s", want, show)
		}
	}

	// Someone else's key for Alice's address, seen in mail.
	mallory := newPGP(t, 6, "Alice Example <alice@example.org>")
	_, errs := h.fails(0, h.with("trust", "seen", "--key", h.publicKeyFile("m.asc", mallory), "--from", "alice@example.org", "--name", "Alice Example")...)
	if !strings.Contains(errs, "alice@example.org belongs to Alice Example's key") {
		t.Fatalf("seen warned %q", errs)
	}
	out, _ = h.fails(3, h.with("trust", "check", "--fingerprint", fpHex(mallory), "--from", "alice@example.org")...)
	if !strings.HasPrefix(out, "suspicious\n") || !strings.Contains(out, "This may be an impostor.") {
		t.Fatalf("an impostor: %q", out)
	}
	if out := h.ok("", h.with("contact", "ls")...); !strings.Contains(out, "alice@example.org (from mail)") {
		t.Fatalf("ls said %q", out)
	}

	h.ok("", h.with("contact", "rm", "Alice Example")...)
	h.fails(3, h.with("trust", "check", "--fingerprint", fp, "--from", "alice@example.org")...)

	if out := h.ok("", h.with("grant", "allow", "/usr/bin/true", "--contacts", "--ops", "read,write")...); !strings.Contains(out, `may read,write "contacts"`) {
		t.Fatalf("grant said %q", out)
	}
}

func TestYourOpenPGPKeyFromTheCommandLine(t *testing.T) {
	h := newHarness(t)
	h.init()
	out := h.ok("", h.with("pgp", "new", "--name", "Me", "--email", "me@example.org")...)
	if !strings.Contains(out, "Made a version 6 OpenPGP key, stored as me@example.org") {
		t.Fatalf("new said %q", out)
	}
	if out := h.ok("", h.with("pgp", "ls")...); !strings.Contains(out, "me@example.org") || !strings.Contains(out, "Me <me@example.org>") {
		t.Fatalf("ls said %q", out)
	}
	pub, err := svpgp.ReadKey(strings.NewReader(h.ok("", h.with("pgp", "pub")...)))
	if err != nil || pub.HasSecret() || pub.PrimaryUserID() != "Me <me@example.org>" {
		t.Fatalf("pub: %v", err)
	}

	// Sign, detached and cleartext.
	msg := h.write("msg.txt", "the minutes\n")
	sig := h.ok("", h.with("pgp", "sign", "-a", msg)...)
	res, err := svpgp.Verify(strings.NewReader("the minutes\n"), strings.NewReader(sig), []*svpgp.Key{pub}, time.Time{})
	if err != nil || len(res) != 1 || !res[0].Valid {
		t.Fatalf("detached: %+v, %v", res, err)
	}
	h.write("signed.asc", h.ok("", h.with("pgp", "sign", "--clear", msg)...))
	// Not a terminal here, so a binary signature is written as asked.
	bin := h.ok("", h.with("pgp", "sign", "--inline", msg)...)
	if m, err := svpgp.VerifyInline(strings.NewReader(bin), []*svpgp.Key{pub}, time.Time{}); err != nil || !m.Signatures[0].Valid || string(m.Body) != "the minutes\n" {
		t.Fatalf("inline: %v", err)
	}

	// Verifying against contacts: known and verified once added and
	// compared.
	h.ok("", h.with("contact", "add", h.publicKeyFile("me.asc", pub))...)
	_, errs := h.fails(3, h.with("pgp", "verify", filepath.Join(h.dir, "signed.asc"), "--from", "me@example.org")...)
	if !strings.Contains(errs, "Signature: unverified") {
		t.Fatalf("verify said %q", errs)
	}
	h.ok("", h.with("contact", "verify", "--fingerprint", fpHex(pub), "--qr")...)
	_, errs = h.fails(0, h.with("pgp", "verify", filepath.Join(h.dir, "signed.asc"), "--from", "me@example.org")...)
	if !strings.Contains(errs, "Signature: verified") || !strings.Contains(errs, "by scanning their QR code") {
		t.Fatalf("verify said %q", errs)
	}

	// Decrypt what is encrypted to the key.
	var ct bytes.Buffer
	w, err := svpgp.Encrypt(&ct, []*svpgp.Key{pub}, svpgp.EncryptOptions{Armor: true})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "for your eyes")
	w.Close()
	enc := h.write("enc.asc", ct.String())
	plain := filepath.Join(h.dir, "plain.txt")
	h.ok("", h.with("pgp", "decrypt", "-o", plain, enc)...)
	if b, _ := os.ReadFile(plain); string(b) != "for your eyes" {
		t.Fatalf("decrypted %q", b)
	}

	// The secret key leaves only when asked, protected.
	h.write("newpass", "a new passphrase\n")
	secFile := filepath.Join(h.dir, "sec.asc")
	h.ok("", h.with("pgp", "export", "me@example.org", "--secret", "--new-passphrase-file", filepath.Join(h.dir, "newpass"), "-o", secFile)...)
	b, _ := os.ReadFile(secFile)
	sec, err := svpgp.ReadKey(bytes.NewReader(b))
	if err != nil || !sec.Locked() || sec.Unlock([]byte("a new passphrase")) != nil || fpHex(sec) != fpHex(pub) {
		t.Fatalf("exported secret key: %v", err)
	}
	if st, _ := os.Stat(secFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("the secret key file is %v", st.Mode())
	}

	// Import a protected v4 key: its passphrase is kept with it, and it signs.
	old, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{"Old <old@example.org>"}, Passphrase: []byte("old pass")})
	if err != nil {
		t.Fatal(err)
	}
	oldArmor, _ := old.Armor(true)
	h.write("oldpass", "old pass\n")
	out = h.ok("", h.with("pgp", "import", h.write("old.asc", string(oldArmor)), "--key-passphrase-file", filepath.Join(h.dir, "oldpass"))...)
	if !strings.Contains(out, "as old@example.org") {
		t.Fatalf("import said %q", out)
	}
	sig = h.ok("", h.with("pgp", "sign", "-a", "--key", "old@example.org", msg)...)
	if res, _ := svpgp.Verify(strings.NewReader("the minutes\n"), strings.NewReader(sig), []*svpgp.Key{old.Public()}, time.Time{}); len(res) != 1 || !res[0].Valid {
		t.Fatalf("the imported key's signature: %+v", res)
	}
	if _, errs, code := h.run("", h.with("pgp", "sign", "-a", msg)...); code != 1 || !strings.Contains(errs, "say which") {
		t.Fatalf("two keys and none named: %d %q", code, errs)
	}
	if _, errs, code := h.run("", h.with("pgp", "import", h.publicKeyFile("pub.asc", pub))...); code != 1 || !strings.Contains(errs, "exactly one secret key") {
		t.Fatalf("importing a public key: %d %q", code, errs)
	}
}

func TestQRCodesFromTheCommandLine(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("", h.with("pgp", "new", "--name", "Me", "--email", "me@example.org")...)
	uri := strings.TrimSpace(h.ok("", h.with("contact", "qr", "--uri")...))
	card, err := svtrust.ParseCard(uri)
	if err != nil || card.Name != "Me" || card.Emails[0] != "me@example.org" || len(card.Keys) != 1 || card.Keys[0].Type != svtrust.OpenPGP {
		t.Fatalf("qr --uri = %q: %+v, %v", uri, card, err)
	}
	drawn := h.ok("", h.with("contact", "qr")...)
	if !strings.Contains(drawn, "█") || !strings.HasSuffix(drawn, uri+"\n") {
		t.Fatalf("qr drew:\n%s", drawn)
	}

	// Scanning someone's code verifies the key you have for them.
	bob := newPGP(t, 4, "Bob <bob@example.org>")
	h.ok("", h.with("contact", "add", h.publicKeyFile("bob.asc", bob))...)
	out := h.ok("", h.with("contact", "import", "OPENPGP4FPR:"+fpHex(bob))...)
	if !strings.Contains(out, "Verified in person: openpgp "+svops.GroupFingerprint(fpHex(bob))+" (Bob)") {
		t.Fatalf("import said %q", out)
	}
	out, _ = h.fails(0, h.with("trust", "check", "--fingerprint", fpHex(bob), "--from", "bob@example.org")...)
	if !strings.Contains(out, "by scanning their QR code") {
		t.Fatalf("check said %q", out)
	}
	if out, errs, code := h.run("", h.with("contact", "import", "openpgp4fpr:"+fpHex(newPGP(t, 4, "x <x@example.org>")))...); code != 1 || !strings.Contains(out, "Not found") {
		t.Fatalf("a key you do not have: %d %q %q", code, out, errs)
	}
}
