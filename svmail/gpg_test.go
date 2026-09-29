package svmail

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svpgp"
)

// Interoperability with GnuPG, both ways, on whole messages: gpg signs and
// encrypts the canonical bytes of MIME entities composed here, and this
// package inspects the messages built around them; this package builds
// messages, and gpg checks the parts taken out of them. Every gpg run uses
// its own throwaway home (and so its own agent), never the user's
// ~/.gnupg; the agent is killed when the test ends.

const gpgPass = "interop passphrase"

var gpgBinary = func() string {
	if _, err := os.Stat("/usr/bin/gpg"); err == nil {
		return "/usr/bin/gpg"
	}
	p, _ := exec.LookPath("gpg")
	return p
}()

type gpgHome struct {
	t    *testing.T
	home string
}

func newGPG(t *testing.T) *gpgHome {
	t.Helper()
	if gpgBinary == "" {
		t.Skip("GnuPG is not installed")
	}
	if testing.Short() {
		t.Skip("GnuPG interop is slow")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	g := &gpgHome{t: t, home: home}
	t.Cleanup(func() {
		conf := filepath.Join(filepath.Dir(gpgBinary), "gpgconf")
		for _, args := range [][]string{{"--kill", "all"}, {"--remove-socketdir"}} {
			cmd := exec.Command(conf, append([]string{"--homedir", home}, args...)...)
			cmd.Env = g.env()
			cmd.Run()
		}
	})
	return g
}

// env is the caller's environment without anything that could point at
// the real agent or home.
func (g *gpgHome) env() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GNUPGHOME=") || strings.HasPrefix(e, "GPG_AGENT_INFO=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, "GNUPGHOME="+g.home)
}

func (g *gpgHome) run(stdin []byte, args ...string) (stdout, status []byte, err error) {
	base := []string{"--homedir", g.home, "--batch", "--no-tty", "--yes", "--trust-model", "always",
		"--pinentry-mode", "loopback", "--passphrase", gpgPass, "--no-auto-key-retrieve", "--status-fd", "2"}
	cmd := exec.Command(gpgBinary, append(base, args...)...)
	cmd.Env = g.env()
	cmd.Dir = g.home
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func (g *gpgHome) must(stdin []byte, args ...string) ([]byte, []byte) {
	g.t.Helper()
	out, status, err := g.run(stdin, args...)
	if err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, status)
	}
	return out, status
}

func (g *gpgHome) file(name string, data []byte) string {
	g.t.Helper()
	p := filepath.Join(g.home, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		g.t.Fatal(err)
	}
	return p
}

var fprLine = regexp.MustCompile(`(?m)^fpr:::::::::([0-9A-F]+):`)

// key makes a key in gpg (Ed25519, with a Curve25519 encryption subkey)
// and returns its fingerprint, its public key, and its secret key,
// unlocked.
func (g *gpgHome) key(uid string) (string, *svpgp.Key, *svpgp.Key) {
	g.t.Helper()
	g.must(nil, "--quick-generate-key", uid, "future-default", "default", "never")
	out, _ := g.must(nil, "--with-colons", "--list-keys", uid)
	m := fprLine.FindSubmatch(out)
	if m == nil {
		g.t.Fatalf("no fingerprint in\n%s", out)
	}
	fpr := string(m[1])
	out, _ = g.must(nil, "--armor", "--export", fpr)
	pub, err := svpgp.ReadKey(bytes.NewReader(out))
	if err != nil {
		g.t.Fatal(err)
	}
	out, _ = g.must(nil, "--armor", "--export-secret-keys", fpr)
	sec, err := svpgp.ReadKey(bytes.NewReader(out))
	if err != nil {
		g.t.Fatal(err)
	}
	if err := sec.Unlock([]byte(gpgPass)); err != nil {
		g.t.Fatal(err)
	}
	return fpr, pub, sec
}

// gpgInner is a MIME entity to sign or encrypt: 8-bit safe already, with
// CR LF line endings, as RFC 3156 requires of what is signed.
var gpgInner = crlf(`Content-Type: multipart/alternative; boundary="alt"

--alt
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Hello from GnuPG =E2=9C=93
--alt
Content-Type: text/html; charset=utf-8

<p>Hello from GnuPG</p>
--alt--
`)

const gpgOuter = "From: Alice <alice@example.org>\r\nTo: Bob <bob@example.org>\r\nSubject: from gpg\r\nMIME-Version: 1.0\r\n"

func TestGPGToInspect(t *testing.T) {
	g := newGPG(t)
	afpr, apub, _ := g.key("Alice <alice@example.org>")
	bfpr, bpub, bsec := g.key("Bob <bob@example.org>")
	keys := &LocalKeys{PGP: []*svpgp.Key{apub, bsec}}

	sig, _ := g.must(gpgInner, "--armor", "--detach-sign", "--local-user", afpr)
	signed := gpgOuter + "Content-Type: multipart/signed; micalg=pgp-sha512; protocol=\"application/pgp-signature\"; boundary=\"s\"\r\n\r\n" +
		"--s\r\n" + string(gpgInner) + "\r\n--s\r\nContent-Type: application/pgp-signature\r\n\r\n" + string(sig) + "\r\n--s--\r\n"

	t.Run("pgp-mime-signed", func(t *testing.T) {
		for _, eol := range []string{"\r\n", "\n"} {
			// Stored with LF line endings, the signed bytes are
			// recovered by canonicalising.
			raw := strings.ReplaceAll(signed, "\r\n", eol)
			r := inspect(t, []byte(raw), keys)
			if len(r.Layers) != 1 || r.Layers[0].Signatures[0].Status != StatusValid || !r.Layers[0].Signatures[0].SenderMatch ||
				r.Layers[0].Signatures[0].Fingerprint != afpr || r.Signed != CoverFull {
				t.Fatalf("\n%s", dump(r))
			}
			if got := textOf(r); got != "Hello from GnuPG ✓" {
				t.Fatalf("text %q", got)
			}
		}
		bad := strings.Replace(signed, "Hello from GnuPG =E2", "Hello from GnuPG =E3", 1)
		if r := inspect(t, []byte(bad), keys); r.Layers[0].Signatures[0].Status != StatusBad {
			t.Fatalf("tampered: %s", r.Layers[0].Signatures[0].Status)
		}
	})

	encrypted := func(ct []byte) string {
		return gpgOuter + "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\r\n\r\n" +
			"--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--e\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n" +
			string(ct) + "\r\n--e--\r\n"
	}
	t.Run("pgp-mime-encrypted-and-signed", func(t *testing.T) {
		ct, _ := g.must(gpgInner, "--armor", "--encrypt", "--sign", "--recipient", bfpr, "--local-user", afpr)
		r := inspect(t, []byte(encrypted(ct)), keys)
		if len(r.Layers) != 2 || !r.Layers[0].Encryption.Decrypted || r.Layers[0].Encryption.Integrity == "none" ||
			r.Layers[1].Signatures[0].Status != StatusValid || textOf(r) != "Hello from GnuPG ✓" {
			t.Fatalf("\n%s", dump(r))
		}
		if r.Layers[0].Encryption.Recipients[0].KeyID == "" {
			t.Fatal("no recipient key ID")
		}
		// Without Bob's secret key.
		r = inspect(t, []byte(encrypted(ct)), &LocalKeys{PGP: []*svpgp.Key{apub, bpub}})
		if r.Layers[0].Encryption.Decrypted || !hasWarning(r, WarnDecryption) {
			t.Fatalf("\n%s", dump(r))
		}
	})
	t.Run("pgp-mime-signed-then-encrypted", func(t *testing.T) {
		entity := "Content-Type: multipart/signed; micalg=pgp-sha512; protocol=\"application/pgp-signature\"; boundary=\"s\"\r\n\r\n" +
			"--s\r\n" + string(gpgInner) + "\r\n--s\r\nContent-Type: application/pgp-signature\r\n\r\n" + string(sig) + "\r\n--s--\r\n"
		ct, _ := g.must([]byte(entity), "--armor", "--encrypt", "--recipient", bfpr)
		r := inspect(t, []byte(encrypted(ct)), keys)
		if len(r.Layers) != 2 || !r.Layers[0].Encryption.Decrypted || r.Layers[1].Parent != 1 || r.Layers[1].Signatures[0].Status != StatusValid {
			t.Fatalf("\n%s", dump(r))
		}
	})
	t.Run("inline", func(t *testing.T) {
		clear, _ := g.must([]byte("Meet at noon.\n"), "--clearsign", "--local-user", afpr)
		msg := gpgOuter + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + string(clear)
		r := inspect(t, []byte(msg), keys)
		if len(r.Layers) != 1 || r.Layers[0].Format != FormatPGPInline || r.Layers[0].Signatures[0].Status != StatusValid {
			t.Fatalf("\n%s", dump(r))
		}
		ct, _ := g.must([]byte("Secret plans.\n"), "--armor", "--encrypt", "--sign", "--recipient", bfpr, "--local-user", afpr)
		msg = gpgOuter + "Content-Type: text/plain; charset=utf-8\r\n\r\n" + string(ct)
		r = inspect(t, []byte(msg), keys)
		if len(r.Layers) != 2 || !r.Layers[0].Encryption.Decrypted || r.Layers[1].Signatures[0].Status != StatusValid ||
			r.Content == nil || string(r.Content.Raw) != "Secret plans.\n" {
			t.Fatalf("\n%s", dump(r))
		}
	})
}

func TestInspectToGPG(t *testing.T) {
	g := newGPG(t)
	afpr, _, asec := g.key("Alice <alice@example.org>")
	_, bpub, _ := g.key("Bob <bob@example.org>")
	msg := []byte(testMessage)

	for _, protect := range []bool{false, true} {
		out, err := SignPGPMIME(msg, asec, &ComposeOptions{ProtectHeaders: protect})
		if err != nil {
			t.Fatal(err)
		}
		// gpg checks the signed part exactly as the message carries it.
		root, err := ParseMessage(out, nil)
		if err != nil || len(root.Parts) != 2 {
			t.Fatalf("%v, %d parts", err, len(root.Parts))
		}
		if !strings.Contains(root.Params["micalg"], "pgp-sha") {
			t.Fatalf("micalg %q", root.Params["micalg"])
		}
		part := g.file("part1", root.Parts[0].Raw)
		sig := g.file("part1.asc", root.Parts[1].Body)
		_, status := g.must(nil, "--verify", sig, part)
		if !bytes.Contains(status, []byte("[GNUPG:] GOODSIG")) || !bytes.Contains(status, []byte("VALIDSIG "+afpr)) {
			t.Fatalf("gpg status:\n%s", status)
		}
		bad := bytes.Replace(root.Parts[0].Raw, []byte("AAECAw=="), []byte("AAECBA=="), 1)
		g.file("part1", bad)
		if _, status, err := g.run(nil, "--verify", sig, part); err == nil || !bytes.Contains(status, []byte("BADSIG")) {
			t.Fatalf("gpg accepted a changed part:\n%s", status)
		}

		// Encrypted to Bob, signed by Alice: gpg decrypts the second part
		// and finds the protected entity, signed.
		out, err = EncryptPGPMIME(msg, []*svpgp.Key{bpub}, asec, &ComposeOptions{ProtectHeaders: protect})
		if err != nil {
			t.Fatal(err)
		}
		root, err = ParseMessage(out, nil)
		if err != nil || root.MediaType != "multipart/encrypted" || len(root.Parts) != 2 {
			t.Fatalf("%v %s", err, root.MediaType)
		}
		plain, status := g.must(root.Parts[1].Body, "--decrypt")
		if !bytes.Contains(status, []byte("[GNUPG:] GOODSIG")) || !bytes.Contains(status, []byte("DECRYPTION_OKAY")) {
			t.Fatalf("gpg status:\n%s", status)
		}
		if protect != bytes.Contains(plain, []byte("hp=cipher")) || !bytes.Contains(plain, []byte("Gr=C3=BC=C3=9Fe")) {
			t.Fatalf("decrypted:\n%s", plain)
		}
		if protect && (!bytes.Contains(plain, []byte("Subject: Lunch?")) || !bytes.Contains(plain, []byte("HP-Outer: Subject: [...]"))) {
			t.Fatalf("protected headers missing:\n%s", plain)
		}
	}
}
