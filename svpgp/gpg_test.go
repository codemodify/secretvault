package svpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Interoperability with GnuPG, both ways: what gpg makes, this package
// reads, and what this package makes, gpg reads. Every gpg run uses its own
// throwaway home (and so its own agent), never the user's ~/.gnupg or
// running gpg-agent; the agent is killed when the test ends.

const gpgPass = "interop passphrase"

var gpgBinary = func() string {
	if _, err := os.Stat("/usr/bin/gpg"); err == nil {
		return "/usr/bin/gpg"
	}
	p, _ := exec.LookPath("gpg")
	return p
}()

type gpg struct {
	t    *testing.T
	home string
}

func newGPG(t *testing.T) *gpg {
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
	g := &gpg{t: t, home: home}
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

// env is the environment for gpg: the caller's, without anything that could
// point at the real agent or home.
func (g *gpg) env() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GNUPGHOME=") || strings.HasPrefix(e, "GPG_AGENT_INFO=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, "GNUPGHOME="+g.home)
}

// run runs gpg and returns its output and its stderr, which carries the
// status lines.
func (g *gpg) run(stdin []byte, args ...string) (stdout, status []byte, err error) {
	base := []string{"--homedir", g.home, "--batch", "--no-tty", "--yes", "--trust-model", "always",
		"--pinentry-mode", "loopback", "--no-auto-key-retrieve", "--status-fd", "2"}
	cmd := exec.Command(gpgBinary, append(base, args...)...)
	cmd.Env = g.env()
	cmd.Dir = g.home
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func (g *gpg) must(stdin []byte, args ...string) ([]byte, []byte) {
	g.t.Helper()
	out, status, err := g.run(stdin, args...)
	if err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, status)
	}
	return out, status
}

// file writes data into the gpg home and returns its path.
func (g *gpg) file(name string, data []byte) string {
	g.t.Helper()
	p := filepath.Join(g.home, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		g.t.Fatal(err)
	}
	return p
}

var fprLine = regexp.MustCompile(`(?m)^fpr:::::::::([0-9A-F]+):`)

// generate makes a key in gpg: a primary key that certifies and signs, and
// an encryption subkey. extra goes before the command (a faked time, say).
func (g *gpg) generate(uid, algo, subAlgo, expire string, extra ...string) string {
	g.t.Helper()
	g.must(nil, append(extra, "--passphrase", gpgPass, "--quick-generate-key", uid, algo, "cert,sign", expire)...)
	out, _ := g.must(nil, "--with-colons", "--list-keys", uid)
	m := fprLine.FindSubmatch(out)
	if m == nil {
		g.t.Fatalf("no fingerprint in\n%s", out)
	}
	fpr := string(m[1])
	g.must(nil, append(extra, "--passphrase", gpgPass, "--quick-add-key", fpr, subAlgo, "encr", expire)...)
	return fpr
}

// keys exports a gpg key and reads it: the public key, and the secret key
// unlocked.
func (g *gpg) keys(fpr string) (pub, sec *Key) {
	g.t.Helper()
	out, _ := g.must(nil, "--armor", "--export", fpr)
	pub, err := ReadKey(bytes.NewReader(out))
	if err != nil {
		g.t.Fatalf("reading gpg's public key: %v\n%s", err, out)
	}
	out, _ = g.must(nil, "--armor", "--passphrase", gpgPass, "--export-secret-keys", fpr)
	sec, err = ReadKey(bytes.NewReader(out))
	if err != nil {
		g.t.Fatalf("reading gpg's secret key: %v", err)
	}
	if !sec.Locked() {
		g.t.Fatal("gpg's exported secret key is not protected")
	}
	if err := sec.Unlock([]byte("wrong")); !errors.Is(err, ErrPassphrase) {
		g.t.Fatalf("a wrong passphrase: %v", err)
	}
	if err := sec.Unlock([]byte(gpgPass)); err != nil {
		g.t.Fatalf("unlocking gpg's secret key: %v", err)
	}
	return pub, sec
}

// goodSignature checks gpg's status lines for a good, valid signature by
// the given (sub)key fingerprint.
func goodSignature(t *testing.T, status []byte, fpr []byte) {
	t.Helper()
	s := string(status)
	if !strings.Contains(s, "[GNUPG:] GOODSIG ") || !strings.Contains(s, fmt.Sprintf("[GNUPG:] VALIDSIG %X ", fpr)) {
		t.Fatalf("gpg did not report a good signature by %X:\n%s", fpr, s)
	}
	if strings.Contains(s, "[GNUPG:] BADSIG") || strings.Contains(s, "[GNUPG:] ERRSIG") {
		t.Fatalf("gpg reported a bad signature:\n%s", s)
	}
}

func singleValid(t *testing.T, results []SignatureResult, k *Key, fpr []byte) {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("%d signatures", len(results))
	}
	r := results[0]
	if !r.Valid || r.Err != nil || r.Key == nil || !bytes.Equal(r.Key.Fingerprint(), k.Fingerprint()) || !bytes.Equal(r.SigningKey, fpr) {
		t.Fatalf("signature: %+v", r)
	}
}

// gpgAlgorithms are the key types checked both ways, with the hashes each
// can sign with (the curve's security level sets a minimum).
var gpgAlgorithms = []struct {
	name, primary, sub string
	hashes             []string
	hash               HashAlgorithm
}{
	{"ed25519-cv25519", "ed25519", "cv25519", []string{"SHA256", "SHA384"}, SHA256},
	{"nistp256", "nistp256", "nistp256", []string{"SHA256", "SHA384"}, SHA256},
	{"nistp384", "nistp384", "nistp384", []string{"SHA384", "SHA512"}, SHA384},
	{"nistp521", "nistp521", "nistp521", []string{"SHA512"}, SHA512},
	{"rsa3072", "rsa3072", "rsa3072", []string{"SHA256", "SHA384"}, SHA256},
}

// gpg-made keys, signatures and messages, read by this package; and this
// package's signatures and messages made with those keys, read by gpg.
func TestGnuPGKeysSignaturesAndMessagesInteroperate(t *testing.T) {
	for _, a := range gpgAlgorithms {
		t.Run(a.name, func(t *testing.T) {
			g := newGPG(t)
			fpr := g.generate("Gnu Pee <gnupee@example.org>", a.primary, a.sub, "never")
			pub, sec := g.keys(fpr)
			keyring := []*Key{pub}
			if fmt.Sprintf("%X", pub.Fingerprint()) != fpr || pub.Version() != 4 || pub.Valid(time.Now()) != nil {
				t.Fatalf("gpg key read as %v: %v", pub, pub.Valid(time.Now()))
			}
			if uids := pub.UserIDs(); len(uids) != 1 || uids[0] != "Gnu Pee <gnupee@example.org>" {
				t.Fatalf("user IDs %q", uids)
			}
			subs := pub.Subkeys()
			if len(subs) != 1 || !subs[0].CanEncrypt || subs[0].Err != nil {
				t.Fatalf("subkeys %+v", subs)
			}
			msg := []byte("Pay Mallory $100.\nNo, really.\n")
			text := []byte("line one  \r\nline two\t\r\n- dash line\r\nFrom the start\r\n")
			data := g.file("msg.txt", msg)
			textFile := g.file("text.txt", text)

			// gpg's signatures, verified here.
			signArgs := [][]string{{"--detach-sign"}, {"--detach-sign", "--armor"}}
			for _, h := range a.hashes {
				signArgs = append(signArgs, []string{"--detach-sign", "--digest-algo", h})
			}
			for _, args := range signArgs {
				sig, _ := g.must(nil, append([]string{"--passphrase", gpgPass, "-o", "-"}, append(args, data)...)...)
				results, err := Verify(bytes.NewReader(msg), bytes.NewReader(sig), keyring, time.Time{})
				if err != nil {
					t.Fatalf("%v: %v", args, err)
				}
				singleValid(t, results, pub, pub.Fingerprint())
				results, _ = Verify(bytes.NewReader(append(msg, 'x')), bytes.NewReader(sig), keyring, time.Time{})
				if results[0].Valid {
					t.Fatalf("%v: verified over changed data", args)
				}
			}
			sig, _ := g.must(nil, "--passphrase", gpgPass, "--textmode", "--detach-sign", "-o", "-", textFile)
			results, err := Verify(bytes.NewReader(text), bytes.NewReader(sig), keyring, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			singleValid(t, results, pub, pub.Fingerprint())
			if results[0].Type != SigText {
				t.Fatalf("gpg's text signature has type %v", results[0].Type)
			}
			inline, _ := g.must(nil, "--passphrase", gpgPass, "--sign", "-o", "-", data)
			m, err := VerifyInline(bytes.NewReader(inline), keyring, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			singleValid(t, m.Signatures, pub, pub.Fingerprint())
			if !bytes.Equal(m.Body, msg) || !m.Compressed || m.FileName != "msg.txt" {
				t.Fatalf("inline message %q compressed=%v name=%q", m.Body, m.Compressed, m.FileName)
			}
			clearSigned, _ := g.must(nil, "--passphrase", gpgPass, "--clearsign", "-o", "-", textFile)
			m, err = VerifyInline(bytes.NewReader(clearSigned), keyring, time.Time{})
			if err != nil {
				t.Fatalf("%v\n%s", err, clearSigned)
			}
			singleValid(t, m.Signatures, pub, pub.Fingerprint())
			if want := "line one\nline two\n- dash line\nFrom the start\n"; string(m.Body) != want {
				t.Fatalf("cleartext body %q", m.Body)
			}

			// gpg's encrypted messages, decrypted here.
			ct, _ := g.must(nil, "--encrypt", "-r", fpr, "-o", "-", data)
			m, err = Decrypt(bytes.NewReader(ct), []*Key{sec}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m.Body, msg) || m.SEIPDVersion != 1 || !m.IntegrityProtected || len(m.Signatures) != 0 {
				t.Fatalf("decrypted %+v", m)
			}
			if !bytes.Equal(m.DecryptionKey, subs[0].Fingerprint) {
				t.Fatal("not decrypted with the encryption subkey")
			}
			ct, _ = g.must(nil, "--passphrase", gpgPass, "--encrypt", "--sign", "--armor", "-r", fpr, "-o", "-", data)
			m, err = Decrypt(bytes.NewReader(ct), []*Key{sec, pub}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m.Body, msg) {
				t.Fatalf("decrypted %q", m.Body)
			}
			singleValid(t, m.Signatures, pub, pub.Fingerprint())
			ct, _ = g.must(nil, "--passphrase", "sym pass", "--symmetric", "-o", "-", data)
			m, err = Decrypt(bytes.NewReader(ct), nil, func() ([]byte, error) { return []byte("sym pass"), nil })
			if err != nil || !bytes.Equal(m.Body, msg) {
				t.Fatalf("symmetric: %v", err)
			}
			if _, err := Decrypt(bytes.NewReader(ct), nil, func() ([]byte, error) { return []byte("sym pas"), nil }); err == nil {
				t.Fatal("a wrong passphrase decrypted gpg's symmetric message")
			}
			// A tampered gpg message is refused.
			ct, _ = g.must(nil, "--encrypt", "-r", fpr, "-o", "-", data)
			bad := bytes.Clone(ct)
			bad[len(bad)-5] ^= 0x01
			if _, err := Decrypt(bytes.NewReader(bad), []*Key{sec}, nil); !errors.Is(err, ErrDecryption) {
				t.Fatalf("tampered gpg message: %v", err)
			}

			// This package's signatures with gpg's key, verified by gpg.
			for _, opts := range []SignOptions{
				{Mode: SignDetached},
				{Mode: SignDetached, Armor: true, Hash: a.hash},
				{Mode: SignDetached, Text: true},
			} {
				var out bytes.Buffer
				if err := Sign(&out, bytes.NewReader(text), sec, opts); err != nil {
					t.Fatal(err)
				}
				_, status := g.must(nil, "--verify", g.file("sig", out.Bytes()), textFile)
				goodSignature(t, status, pub.Fingerprint())
			}
			var out bytes.Buffer
			if err := Sign(&out, bytes.NewReader(text), sec, SignOptions{Mode: SignCleartext}); err != nil {
				t.Fatal(err)
			}
			_, status := g.must(nil, "--verify", g.file("clear.asc", out.Bytes()))
			goodSignature(t, status, pub.Fingerprint())

			// This package's messages to gpg's key, decrypted by gpg.
			for _, opts := range []EncryptOptions{
				{},
				{Armor: true, Signer: sec, Compression: ZLIB},
				{Format: FormatV1, Signer: sec, Text: true},
			} {
				ct := encrypted(t, []*Key{pub}, string(msg), opts)
				plain, status := g.must(nil, "--passphrase", gpgPass, "--decrypt", g.file("ct", ct))
				if !bytes.Equal(plain, msg) {
					t.Fatalf("gpg decrypted %q", plain)
				}
				if opts.Signer != nil {
					goodSignature(t, status, pub.Fingerprint())
				}
				if !strings.Contains(string(status), "[GNUPG:] DECRYPTION_OKAY") {
					t.Fatalf("gpg status:\n%s", status)
				}
			}
		})
	}
}

// Keys, signatures and messages made here, read by gpg.
func TestGnuPGReadsWhatThisPackageMakes(t *testing.T) {
	g := newGPG(t)
	k := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Sv Pgp <svpgp@example.org>", "Sv Pgp <other@example.org>"}, Passphrase: []byte(gpgPass)})
	secret, err := k.Armor(true)
	if err != nil {
		t.Fatal(err)
	}
	_, status := g.must(nil, "--passphrase", gpgPass, "--import", g.file("key.asc", secret))
	if !strings.Contains(string(status), "[GNUPG:] IMPORT_OK") || !strings.Contains(string(status), "secret keys imported: 1") && !strings.Contains(string(status), "IMPORT_RES") {
		t.Fatalf("gpg import:\n%s", status)
	}
	fpr := fmt.Sprintf("%X", k.Fingerprint())
	out, _ := g.must(nil, "--with-colons", "--list-secret-keys", fpr)
	if !bytes.Contains(out, []byte("Sv Pgp <svpgp@example.org>")) || !regexp.MustCompile(`(?m)^sec:[^:]*:255:22:`).Match(out) || !regexp.MustCompile(`(?m)^ssb:[^:]*:255:18:`).Match(out) {
		t.Fatalf("gpg lists the key as\n%s", out)
	}
	msg := []byte("Signed by svpgp.\n- with a dash\n")
	data := g.file("msg.txt", msg)

	for _, opts := range []SignOptions{
		{Mode: SignDetached},
		{Mode: SignDetached, Armor: true},
		{Mode: SignDetached, Text: true, Hash: SHA256},
		{Mode: SignDetached, Hash: SHA3_512},
	} {
		sig := signed(t, k, string(msg), opts)
		_, status, err := g.run(nil, "--verify", g.file("sig", sig), data)
		if opts.Hash == SHA3_512 {
			// GnuPG 2.4 has no SHA-3; it must not call the signature good.
			if err == nil || strings.Contains(string(status), "GOODSIG") {
				t.Fatalf("gpg accepted a SHA3-512 signature it cannot check:\n%s", status)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%+v: %v\n%s", opts, err, status)
		}
		goodSignature(t, status, k.Fingerprint())
	}
	for _, opts := range []SignOptions{{Mode: SignInline}, {Mode: SignInline, Armor: true, Text: true}} {
		inline := signed(t, k, string(msg), opts)
		plain, status := g.must(nil, "--decrypt", g.file("inline", inline))
		if !bytes.Equal(plain, msg) {
			t.Fatalf("gpg read %q", plain)
		}
		goodSignature(t, status, k.Fingerprint())
	}
	clearSigned := signed(t, k, string(msg), SignOptions{Mode: SignCleartext})
	plain, status := g.must(nil, "--decrypt", g.file("clear.asc", clearSigned))
	if !bytes.Equal(plain, msg) {
		t.Fatalf("gpg read the cleartext as %q", plain)
	}
	goodSignature(t, status, k.Fingerprint())
	// A changed cleartext is caught by gpg too.
	_, status, err = g.run(nil, "--verify", g.file("bad.asc", bytes.Replace(clearSigned, []byte("svpgp"), []byte("svPGP"), 1)))
	if err == nil || !strings.Contains(string(status), "BADSIG") {
		t.Fatalf("gpg accepted a changed cleartext:\n%s", status)
	}

	alice := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Alice <alice@example.org>"}})
	alicePub, _ := alice.Armor(false)
	g.must(nil, "--import", g.file("alice.asc", alicePub))
	for _, opts := range []EncryptOptions{
		{},
		{Armor: true},
		{Signer: alice},
		{Signer: k, Compression: ZIP, Text: true},
		{Passphrase: []byte("also this")},
	} {
		ct := encrypted(t, []*Key{k.Public()}, string(msg), opts)
		plain, status := g.must(nil, "--passphrase", gpgPass, "--decrypt", g.file("ct", ct))
		if !bytes.Equal(plain, msg) {
			t.Fatalf("gpg decrypted %q", plain)
		}
		if opts.Signer != nil {
			goodSignature(t, status, opts.Signer.Fingerprint())
		}
	}
	// Passphrase only, in the format GnuPG reads.
	ct := encrypted(t, nil, string(msg), EncryptOptions{Passphrase: []byte("just a passphrase"), Format: FormatV1, Armor: true})
	plain, _ = g.must(nil, "--passphrase", "just a passphrase", "--decrypt", g.file("sym", ct))
	if !bytes.Equal(plain, msg) {
		t.Fatalf("gpg decrypted %q", plain)
	}
	// gpg also exports the key as this package made it, and it reads back.
	out, _ = g.must(nil, "--armor", "--export", fpr)
	back, err := ReadKey(bytes.NewReader(out))
	if err != nil || !bytes.Equal(back.Fingerprint(), k.Fingerprint()) || len(back.UserIDs()) != 2 || back.Valid(time.Now()) != nil {
		t.Fatalf("gpg's export of our key: %v", err)
	}
}

// Expiry and revocation made by gpg are honoured here.
func TestGnuPGExpiryAndRevocationAreHonoured(t *testing.T) {
	g := newGPG(t)
	// A key made ten days ago that expired after one day, and a signature
	// made while it was valid.
	made := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	faked := fmt.Sprintf("--faked-system-time=%d!", made.Unix())
	fpr := g.generate("Old Key <old@example.org>", "ed25519", "cv25519", "1d", faked)
	msg := []byte("signed while valid")
	data := g.file("msg.txt", msg)
	sigInTime, _ := g.must(nil, faked, "--passphrase", gpgPass, "--detach-sign", "-o", "-", data)
	pub, _ := g.keys(fpr)
	if !errors.Is(pub.Valid(time.Now()), ErrKeyExpired) {
		t.Fatalf("the expired key: %v", pub.Valid(time.Now()))
	}
	if got, want := pub.ExpiresAt(), made.Add(24*time.Hour); !got.Equal(want) {
		t.Fatalf("expires %v, want %v", got, want)
	}
	results, err := Verify(bytes.NewReader(msg), bytes.NewReader(sigInTime), []*Key{pub}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	singleValid(t, results, pub, pub.Fingerprint())
	if _, err := Encrypt(io.Discard, []*Key{pub}, EncryptOptions{}); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("encrypting to an expired key: %v", err)
	}

	// A current key, a signature, then the key revoked with the revocation
	// certificate gpg made when it made the key (no reason given, so the
	// earlier signature does not survive it).
	fpr = g.generate("Revoked Key <rev@example.org>", "ed25519", "cv25519", "never")
	sig, _ := g.must(nil, "--passphrase", gpgPass, "--detach-sign", "-o", "-", data)
	pub, _ = g.keys(fpr)
	results, _ = Verify(bytes.NewReader(msg), bytes.NewReader(sig), []*Key{pub}, time.Time{})
	singleValid(t, results, pub, pub.Fingerprint())
	rev, err := os.ReadFile(filepath.Join(g.home, "openpgp-revocs.d", fpr+".rev"))
	if err != nil {
		t.Fatal(err)
	}
	rev = bytes.ReplaceAll(rev, []byte(":-----"), []byte("-----"))
	g.must(nil, "--import", g.file("rev.asc", rev))
	pub, _ = g.keys(fpr)
	if !pub.Revoked() || !errors.Is(pub.Valid(time.Now()), ErrKeyRevoked) {
		t.Fatal("gpg's revocation was not seen")
	}
	results, _ = Verify(bytes.NewReader(msg), bytes.NewReader(sig), []*Key{pub}, time.Time{})
	if results[0].Valid || !errors.Is(results[0].Err, ErrKeyRevoked) {
		t.Fatalf("signature by a revoked key: %+v", results[0])
	}
}

// Old and unusual gpg keys: DSA signatures verify and ElGamal messages
// decrypt (with a warning), but neither is used to sign or encrypt; the
// brainpool curves are refused clearly; SHA-1 counts only before 2023.
func TestGnuPGOldAlgorithmsAndPolicy(t *testing.T) {
	g := newGPG(t)
	msg := []byte("an old message")
	data := g.file("msg.txt", msg)

	fpr := g.generate("Dee Ess Ay <dsa@example.org>", "dsa2048", "elg2048", "never")
	pub, sec := g.keys(fpr)
	sig, _ := g.must(nil, "--passphrase", gpgPass, "-u", fpr, "--detach-sign", "-o", "-", data)
	results, err := Verify(bytes.NewReader(msg), bytes.NewReader(sig), []*Key{pub}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	singleValid(t, results, pub, pub.Fingerprint())
	if results[0].Algorithm != DSA {
		t.Fatalf("algorithm %v", results[0].Algorithm)
	}
	ct, _ := g.must(nil, "--encrypt", "-r", fpr, "-o", "-", data)
	m, err := Decrypt(bytes.NewReader(ct), []*Key{sec}, nil)
	if err != nil || !bytes.Equal(m.Body, msg) {
		t.Fatalf("ElGamal: %v", err)
	}
	if len(m.Warnings) == 0 || !strings.Contains(strings.Join(m.Warnings, " "), "ElGamal") {
		t.Fatalf("no ElGamal warning: %q", m.Warnings)
	}
	if err := Sign(io.Discard, bytes.NewReader(msg), sec, SignOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("signing with DSA: %v", err)
	}
	if _, err := Encrypt(io.Discard, []*Key{pub}, EncryptOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("encrypting to ElGamal: %v", err)
	}

	fpr = g.generate("Brain Pool <bp@example.org>", "brainpoolP256r1", "brainpoolP256r1", "never")
	out, _ := g.must(nil, "--armor", "--export", fpr)
	bp, err := ReadKey(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := bp.Valid(time.Now()); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "brainpoolP256r1") {
		t.Fatalf("brainpool key: %v", err)
	}
	sig, _ = g.must(nil, "--passphrase", gpgPass, "-u", fpr, "--detach-sign", "-o", "-", data)
	results, _ = Verify(bytes.NewReader(msg), bytes.NewReader(sig), []*Key{bp}, time.Time{})
	if results[0].Valid || !errors.Is(results[0].Err, ErrUnsupported) {
		t.Fatalf("brainpool signature: %+v", results[0])
	}
	if _, err := Encrypt(io.Discard, []*Key{bp}, EncryptOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("encrypting to brainpool: %v", err)
	}

	// An RSA-2048 key from 2020, with SHA-1 signatures then and now.
	then := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	faked := fmt.Sprintf("--faked-system-time=%d!", then.Unix())
	fpr = g.generate("Old Rsa <rsa@example.org>", "rsa2048", "rsa2048", "never", faked)
	pub, sec = g.keys(fpr)
	sig2020, _ := g.must(nil, faked, "--passphrase", gpgPass, "-u", fpr, "--digest-algo", "SHA1", "--detach-sign", "-o", "-", data)
	results, _ = Verify(bytes.NewReader(msg), bytes.NewReader(sig2020), []*Key{pub}, time.Time{})
	singleValid(t, results, pub, pub.Fingerprint())
	if results[0].Hash != SHA1 {
		t.Fatalf("hash %v", results[0].Hash)
	}
	sigNow, _ := g.must(nil, "--passphrase", gpgPass, "-u", fpr, "--digest-algo", "SHA1", "--detach-sign", "-o", "-", data)
	results, _ = Verify(bytes.NewReader(msg), bytes.NewReader(sigNow), []*Key{pub}, time.Time{})
	if results[0].Valid || !errors.Is(results[0].Err, ErrWeakAlgorithm) || results[0].Key == nil {
		t.Fatalf("a SHA-1 signature made now: %+v", results[0])
	}
	ct, _ = g.must(nil, "--encrypt", "-r", fpr, "-o", "-", data)
	m, err = Decrypt(bytes.NewReader(ct), []*Key{sec}, nil)
	if err != nil || !bytes.Equal(m.Body, msg) || !strings.Contains(strings.Join(m.Warnings, " "), "2048-bit RSA") {
		t.Fatalf("RSA-2048: %v %q", err, m.Warnings)
	}
}

// A key with a signing subkey, as people set up for tokens: gpg's
// signatures by the subkey verify here (the subkey's back-signature is
// checked), this package signs with the subkey too, and a copy exported
// with the primary secret key left out (a GnuPG stub) still signs and
// decrypts, while the primary key stays unusable.
func TestGnuPGSigningSubkeysAndStubbedPrimaryKeys(t *testing.T) {
	g := newGPG(t)
	fpr := g.generate("Sub Signer <sub@example.org>", "ed25519", "cv25519", "never")
	g.must(nil, "--passphrase", gpgPass, "--quick-add-key", fpr, "ed25519", "sign", "never")
	pub, sec := g.keys(fpr)
	var signingSub []byte
	for _, s := range pub.Subkeys() {
		if s.CanSign {
			signingSub = s.Fingerprint
		}
	}
	if signingSub == nil {
		t.Fatalf("no signing subkey in %+v", pub.Subkeys())
	}
	msg := []byte("signed by a subkey")
	data := g.file("msg.txt", msg)
	sig, _ := g.must(nil, "--passphrase", gpgPass, "--detach-sign", "-o", "-", data)
	results, err := Verify(bytes.NewReader(msg), bytes.NewReader(sig), []*Key{pub}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	singleValid(t, results, pub, signingSub)

	var out bytes.Buffer
	if err := Sign(&out, bytes.NewReader(msg), sec, SignOptions{}); err != nil {
		t.Fatal(err)
	}
	_, status := g.must(nil, "--verify", g.file("sig", out.Bytes()), data)
	goodSignature(t, status, signingSub)

	stubbed, _ := g.must(nil, "--armor", "--passphrase", gpgPass, "--export-secret-subkeys", fpr)
	laptop, err := ReadKey(bytes.NewReader(stubbed))
	if err != nil {
		t.Fatal(err)
	}
	if err := laptop.Unlock([]byte(gpgPass)); err != nil {
		t.Fatalf("unlocking the subkeys: %v", err)
	}
	if err := laptop.primary.sec.usable(); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("the stubbed primary key: %v", err)
	}
	out.Reset()
	if err := Sign(&out, bytes.NewReader(msg), laptop, SignOptions{Mode: SignCleartext}); err != nil {
		t.Fatal(err)
	}
	_, status = g.must(nil, "--verify", g.file("clear.asc", out.Bytes()))
	goodSignature(t, status, signingSub)
	ct, _ := g.must(nil, "--encrypt", "-r", fpr, "-o", "-", data)
	m, err := Decrypt(bytes.NewReader(ct), []*Key{laptop}, nil)
	if err != nil || !bytes.Equal(m.Body, msg) {
		t.Fatalf("decrypting with the subkeys only: %v", err)
	}
	if err := laptop.Revoke(RevocationRetired, "", time.Time{}); !errors.Is(err, ErrKeyLocked) {
		t.Fatalf("revoking without the primary secret: %v", err)
	}
	// The stub survives a round trip, still a stub.
	again, err := laptop.Armor(true)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ReadKey(bytes.NewReader(again))
	if err != nil || back.primary.sec == nil || back.primary.sec.prot.s2k == nil || back.primary.sec.prot.s2k.typ != s2kGNU {
		t.Fatalf("the stub did not round-trip: %v", err)
	}
}
