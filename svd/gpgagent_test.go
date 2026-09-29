//go:build linux

package svd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svgpgagent"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// The gpg-agent face, driven by GnuPG's own gpg. Every gpg runs in a
// throwaway home whose agent socket is linked to the face's (gnupg.link),
// with --no-autostart, so that it can reach no other agent and start
// none; the link goes with gpgconf --remove-socketdir when the test ends.
// The keys gpg makes for the vault are made once, in a home of their own
// that is removed as soon as they are exported.

var (
	gpgBin     = lookGPG("gpg")
	gpgconfBin = lookGPG("gpgconf")
)

func lookGPG(name string) string {
	if p := "/usr/bin/" + name; fileExists(p) {
		return p
	}
	p, _ := exec.LookPath(name)
	return p
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// gpgEnv is the environment without anything that points at the real
// agent or home.
func gpgEnv(home string) []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GNUPGHOME=") || strings.HasPrefix(e, "GPG_AGENT_INFO=") {
			continue
		}
		env = append(env, e)
	}
	return append(env, "GNUPGHOME="+home)
}

// gpgHomeCleanup kills whatever agent a home has and removes its socket
// directory (and so any link in it).
func gpgHomeCleanup(home string) {
	for _, args := range [][]string{{"--kill", "all"}, {"--remove-socketdir"}} {
		cmd := exec.Command(gpgconfBin, append([]string{"--homedir", home}, args...)...)
		cmd.Env = gpgEnv(home)
		cmd.Run()
	}
}

// gpgMadeKeys are secret keys gpg made: P-256 and RSA, each with an
// encryption subkey, armored, without a passphrase.
var gpgMadeKeys = sync.OnceValues(func() (map[string][]byte, error) {
	home, err := os.MkdirTemp("", "svgpgkeys")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	defer gpgHomeCleanup(home)
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(gpgBin, append([]string{"--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
		cmd.Env = gpgEnv(home)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("gpg %s: %v\n%s", strings.Join(args, " "), err, errb.Bytes())
		}
		return out.Bytes(), nil
	}
	keys := map[string][]byte{}
	for _, k := range []struct{ name, uid, algo string }{
		{"p256", "Nist Tester <p256@example.org>", "nistp256"},
		{"rsa", "Rsa Tester <rsa@example.org>", "rsa3072"},
	} {
		if _, err := run("--quick-generate-key", k.uid, k.algo, "cert,sign", "never"); err != nil {
			return nil, err
		}
		out, err := run("--with-colons", "--list-keys", k.uid)
		if err != nil {
			return nil, err
		}
		m := regexp.MustCompile(`(?m)^fpr:::::::::([0-9A-F]+):`).FindSubmatch(out)
		if m == nil {
			return nil, fmt.Errorf("no fingerprint for %s", k.uid)
		}
		if _, err := run("--quick-add-key", string(m[1]), k.algo, "encr", "never"); err != nil {
			return nil, err
		}
		if keys[k.name], err = run("--armor", "--export-secret-keys", string(m[1])); err != nil {
			return nil, err
		}
	}
	return keys, nil
})

// gnupg is a throwaway GnuPG home pointed at the face.
type gnupg struct {
	t    *testing.T
	home string
}

// gpgHarness is a daemon with the default vault ("personal"), its
// gpg-agent face, and a GnuPG home pointed at it.
func gpgHarness(t *testing.T) (*harness, *secretvault.Client, *gnupg) {
	t.Helper()
	if gpgBin == "" || gpgconfBin == "" {
		t.Skip("GnuPG is not installed")
	}
	if testing.Short() {
		t.Skip("GnuPG interop is slow")
	}
	h := newHarness(t)
	cli := h.setup()
	sock := filepath.Join(filepath.Dir(h.sock), "gpg-agent.sock")
	ln, cleanup, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.d.ServeGPGAgent(ctx, ln)

	g := &gnupg{t: t, home: t.TempDir()}
	os.Chmod(g.home, 0o700)
	t.Cleanup(func() { gpgHomeCleanup(g.home) })
	agentSock := g.gpgconf("agent-socket")
	for range 50 { // ServeGPGAgent records its socket as it starts
		if a, _ := h.d.gnupgSockets(); a != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := cli.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: g.home, Socket: agentSock}); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(agentSock); err != nil || target != sock {
		t.Fatalf("%s leads to %q (%v), not %s", agentSock, target, err, sock)
	}
	return h, cli, g
}

func ctxT(t *testing.T) context.Context { return ctx(t) }

// gpgconf is gpgconf --list-dirs's answer for the home.
func (g *gnupg) gpgconf(dir string) string {
	g.t.Helper()
	cmd := exec.Command(gpgconfBin, "--homedir", g.home, "--list-dirs", dir)
	cmd.Env = gpgEnv(g.home)
	out, err := cmd.Output()
	if err != nil {
		g.t.Fatalf("gpgconf --list-dirs %s: %v", dir, err)
	}
	return strings.TrimSpace(string(out))
}

// run runs gpg on the home; stderr carries the status lines.
func (g *gnupg) run(stdin []byte, args ...string) (stdout, stderr []byte, err error) {
	base := []string{"--homedir", g.home, "--batch", "--no-tty", "--no-autostart", "--status-fd", "2", "--trust-model", "always"}
	cmd := exec.Command(gpgBin, append(base, args...)...)
	cmd.Env = gpgEnv(g.home)
	cmd.Dir = g.home
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func (g *gnupg) must(stdin []byte, args ...string) []byte {
	g.t.Helper()
	out, status, err := g.run(stdin, args...)
	if err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, status)
	}
	return out
}

// vaultKey is a key put in the vault, and its public half.
type vaultKey struct {
	name string
	fpr  string
	pub  *svpgp.Key
}

// addGPGKey puts a key gpg made into the vault, as 'secretvault pgp
// import' does, and its public key into the GnuPG home.
func addGPGKey(t *testing.T, cli *secretvault.Client, g *gnupg, which string, attrs map[string]string) vaultKey {
	t.Helper()
	keys, err := gpgMadeKeys()
	if err != nil {
		t.Fatal(err)
	}
	k, err := svpgp.ReadKey(bytes.NewReader(keys[which]))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pub, err := k.Public().Armor(false)
	if err != nil {
		t.Fatal(err)
	}
	fpr := fmt.Sprintf("%X", k.Fingerprint())
	a := map[string]string{svrpc.PGPFingerprint: fpr, svrpc.PGPUserID: k.PrimaryUserID()}
	for n, v := range attrs {
		a[n] = v
	}
	name := "pgp/" + which
	it := svrpc.Item{Kind: svrpc.PGPItemKind, Name: name, Attrs: a, Fields: []svrpc.Field{
		{Name: svrpc.PGPSecretField, Type: svcore.FieldKey, Value: keys[which]},
		{Name: svrpc.PGPPublicField, Type: svcore.FieldText, Value: pub},
	}}
	if _, err := cli.Put(ctxT(t), "", it); err != nil {
		t.Fatal(err)
	}
	g.must(pub, "--import")
	return vaultKey{name: name, fpr: fpr, pub: k.Public()}
}

// addNewKey makes a version 4 key in the daemon (Ed25519, with a
// Curve25519 subkey), and puts its public key into the GnuPG home.
func addNewKey(t *testing.T, cli *secretvault.Client, g *gnupg) vaultKey {
	t.Helper()
	k, err := cli.GeneratePGP(ctxT(t), svrpc.PGPGenerateParams{Name: "Ada Lovelace", Emails: []string{"ada@example.org"}, Version: 4})
	if err != nil {
		t.Fatal(err)
	}
	g.must([]byte(k.PublicKey), "--import")
	pub, err := svpgp.ReadKey(strings.NewReader(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return vaultKey{name: k.Item, fpr: k.Fingerprint, pub: pub}
}

var goodSig = regexp.MustCompile(`\[GNUPG:\] VALIDSIG ([0-9A-F]+) `)

// verifies checks a signature both in gpg and in svpgp.
func (g *gnupg) verifies(k vaultKey, data, sig []byte, detached bool) {
	g.t.Helper()
	var status []byte
	var err error
	if detached {
		sigFile := filepath.Join(g.home, "sig")
		os.WriteFile(sigFile, sig, 0o600)
		_, status, err = g.run(data, "--verify", sigFile, "-")
	} else {
		_, status, err = g.run(sig, "--verify")
	}
	if err != nil || !goodSig.Match(status) {
		g.t.Fatalf("gpg does not verify the signature: %v\n%s", err, status)
	}
	var results []svpgp.SignatureResult
	if detached {
		results, err = svpgp.Verify(bytes.NewReader(data), bytes.NewReader(sig), []*svpgp.Key{k.pub}, time.Time{})
	} else {
		var msg *svpgp.Message
		msg, err = svpgp.VerifyInline(bytes.NewReader(sig), []*svpgp.Key{k.pub}, time.Time{})
		if msg != nil {
			results = msg.Signatures
		}
	}
	if err != nil || len(results) != 1 || !results[0].Valid {
		g.t.Fatalf("svpgp does not verify the signature: %v %+v", err, results)
	}
}

func TestGPGSignsWithKeysInTheVault(t *testing.T) {
	h, cli, g := gpgHarness(t)
	keys := []vaultKey{addNewKey(t, cli, g), addGPGKey(t, cli, g, "p256", nil), addGPGKey(t, cli, g, "rsa", nil)}

	// gpg lists them as secret keys it can use.
	out := g.must(nil, "--with-colons", "--list-secret-keys")
	for _, k := range keys {
		if !strings.Contains(string(out), "fpr:::::::::"+k.fpr+":") {
			t.Fatalf("gpg -K does not list %s:\n%s", k.fpr, out)
		}
	}
	if strings.Contains(string(out), "sec:u:") && strings.Count(string(out), "\nssb:") != 3 {
		t.Fatalf("gpg -K:\n%s", out)
	}

	data := []byte("signed by a key that never leaves the vault\n")
	for i, k := range keys {
		// The first signature is asked about; "always" covers the rest.
		h.desk.script("choose:" + svrpc.ChoiceAlways)
		sig := g.must(data, "--local-user", k.fpr+"!", "--detach-sign", "--armor")
		q := h.desk.asked[len(h.desk.asked)-1]
		if !strings.Contains(q.Description, "gpg (") || !strings.Contains(q.Description, "sign with \""+k.name+"\"") {
			t.Fatalf("key %d: the consent prompt said %q", i, q.Description)
		}
		g.verifies(k, data, sig, true)
		g.verifies(k, nil, g.must(data, "--local-user", k.fpr+"!", "--sign"), false)
		clear := g.must(data, "--local-user", k.fpr+"!", "--clearsign")
		if !bytes.Contains(clear, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			t.Fatalf("not a cleartext signed message:\n%s", clear)
		}
		g.verifies(k, nil, clear, false)
		h.desk.done(t)
	}
	if n := h.desk.count(); n != 3 {
		t.Fatalf("asked %d times for three keys, each allowed always", n)
	}
}

func TestGPGDecryptsWithKeysInTheVault(t *testing.T) {
	h, cli, g := gpgHarness(t)
	keys := []vaultKey{addNewKey(t, cli, g), addGPGKey(t, cli, g, "p256", nil), addGPGKey(t, cli, g, "rsa", nil)}
	for i, k := range keys {
		secret := []byte(fmt.Sprintf("for key %d only\n", i))
		// Encrypted by gpg, to the key's encryption subkey...
		ct := g.must(secret, "--encrypt", "--recipient", k.fpr)
		h.desk.script("choose:" + svrpc.ChoiceLock)
		out, status, err := g.run(ct, "--decrypt")
		if err != nil || !bytes.Equal(out, secret) || !bytes.Contains(status, []byte("DECRYPTION_OKAY")) {
			t.Fatalf("key %d: gpg --decrypt = %q, %v\n%s", i, out, err, status)
		}
		q := h.desk.asked[len(h.desk.asked)-1]
		if !strings.Contains(q.Description, "decrypt with \""+k.name+"\"") {
			t.Fatalf("key %d: the consent prompt said %q", i, q.Description)
		}
		// ... and by svpgp, which the decision "until locked" covers.
		var buf bytes.Buffer
		w, err := svpgp.Encrypt(&buf, []*svpgp.Key{k.pub}, svpgp.EncryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(secret)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if out := g.must(buf.Bytes(), "--decrypt"); !bytes.Equal(out, secret) {
			t.Fatalf("key %d: svpgp's message decrypts to %q", i, out)
		}
		h.desk.done(t)
	}
	if n := h.desk.count(); n != 3 {
		t.Fatalf("asked %d times", n)
	}
}

func TestGPGIsAskedAboutAsAnyProgramIs(t *testing.T) {
	h, cli, g := gpgHarness(t)
	k := addNewKey(t, cli, g)
	data := []byte("x")
	sign := func() error {
		_, status, err := g.run(data, "--local-user", k.fpr+"!", "--detach-sign")
		if err != nil {
			return fmt.Errorf("%v: %s", err, status)
		}
		return nil
	}

	// Allowed once: asked again the next time.
	for range 2 {
		h.desk.script("choose:" + svrpc.ChoiceOnce)
		if err := sign(); err != nil {
			t.Fatal(err)
		}
	}
	// Denied: gpg is told the operation was cancelled.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if err := sign(); err == nil || !strings.Contains(err.Error(), "Operation cancelled") {
		t.Fatalf("a denied signature: %v", err)
	}
	// Dismissed: likewise.
	h.desk.script("cancel")
	if err := sign(); err == nil {
		t.Fatal("a dismissed prompt signed")
	}
	// Remembered: asked once, then never.
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	for range 3 {
		if err := sign(); err != nil {
			t.Fatal(err)
		}
	}
	h.desk.done(t)
	if n := h.desk.count(); n != 5 {
		t.Fatalf("asked %d times, want 5", n)
	}
	// Decrypting is its own decision.
	ct := g.must([]byte("y"), "--encrypt", "--recipient", k.fpr)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, status, err := g.run(ct, "--decrypt"); err == nil || !bytes.Contains(status, []byte("cancel")) {
		t.Fatalf("a denied decryption: %v\n%s", err, status)
	}
	h.desk.done(t)

	// The audit log names gpg, the item and what it did.
	log, err := cli.Audit(ctxT(t), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var trail []string
	for _, e := range log {
		if strings.HasPrefix(e.Program, "gpg ") {
			trail = append(trail, e.Op+":"+e.Outcome)
		}
	}
	if got := strings.Join(trail, ","); !strings.HasPrefix(got, "sign:allowed,sign:allowed,sign:denied,sign:") || !strings.HasSuffix(got, "decrypt:denied") {
		t.Fatalf("gpg's audit trail: %s", got)
	}
}

func TestAKeyThatConfirmsIsAskedAboutEveryTime(t *testing.T) {
	h, cli, g := gpgHarness(t)
	k := addGPGKey(t, cli, g, "p256", map[string]string{"confirm": "always"})
	// KEYINFO says so ('c'), as gpg-agent does for such keys.
	out := g.must(nil, "--with-colons", "--list-secret-keys", k.fpr)
	if !strings.Contains(string(out), k.fpr) {
		t.Fatalf("gpg -K:\n%s", out)
	}
	for i := range 3 {
		h.desk.script("choose:" + svrpc.ChoiceOnce)
		g.must([]byte("z"), "--local-user", k.fpr+"!", "--detach-sign")
		q := h.desk.asked[len(h.desk.asked)-1]
		if len(q.Choices) != 2 || !strings.Contains(q.Description, "confirmed on every use") {
			t.Fatalf("use %d: asked %+v", i, q)
		}
	}
	h.desk.done(t)
}

func TestAKeyNotInTheVaultIsNotThere(t *testing.T) {
	h, cli, g := gpgHarness(t)
	addNewKey(t, cli, g)
	// gpg knows this key's public half; the vault does not hold it.
	keys, err := gpgMadeKeys()
	if err != nil {
		t.Fatal(err)
	}
	k, err := svpgp.ReadKey(bytes.NewReader(keys["rsa"]))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.Public().Armor(false)
	k.Close()
	g.must(pub, "--import")
	fpr := fmt.Sprintf("%X", k.Fingerprint())
	_, status, err := g.run([]byte("x"), "--local-user", fpr+"!", "--detach-sign")
	if err == nil || !bytes.Contains(status, []byte("No secret key")) && !strings.Contains(string(status), "secret key not available") {
		t.Fatalf("signing with a key the vault lacks: %v\n%s", err, status)
	}
	out := g.must(nil, "--with-colons", "--list-secret-keys")
	if strings.Contains(string(out), fpr) {
		t.Fatalf("gpg -K lists a key the vault lacks:\n%s", out)
	}
	if h.desk.count() != 0 {
		t.Fatal("somebody was asked about a key that is not there")
	}
}

func TestALockedVaultIsUnlockedWhenGPGLooksForAKey(t *testing.T) {
	h, cli, g := gpgHarness(t)
	k := addNewKey(t, cli, g)
	h.d.LockAll("test")
	// Once for the passphrase, once for the signature.
	h.desk.script("pass:"+string(pass), "choose:"+svrpc.ChoiceOnce)
	sig := g.must([]byte("m"), "--local-user", k.fpr+"!", "--detach-sign")
	g.verifies(k, []byte("m"), sig, true)
	if q := h.desk.asked[0]; q.Kind != svrpc.PromptPassphrase || !strings.Contains(q.Description, "wants to use your OpenPGP keys") {
		t.Fatalf("asked %+v", q)
	}
	h.desk.done(t)

	// Dismissing the unlock asks no more on that connection, however many
	// keys gpg asks about.
	h.d.LockAll("test")
	h.desk.script("cancel")
	before := h.desk.count()
	if _, _, err := g.run([]byte("m"), "--local-user", k.fpr+"!", "--detach-sign"); err == nil {
		t.Fatal("signed with a locked vault")
	}
	if n := h.desk.count() - before; n != 1 {
		t.Fatalf("asked %d times", n)
	}
	h.desk.done(t)
}

func TestKeysDoNotComeInOrGoOutThroughGPG(t *testing.T) {
	h, cli, g := gpgHarness(t)
	k := addNewKey(t, cli, g)
	if out, status, err := g.run(nil, "--armor", "--export-secret-keys", k.fpr); err == nil && bytes.Contains(out, []byte("PRIVATE KEY")) {
		t.Fatalf("gpg exported the secret key:\n%s\n%s", out, status)
	}
	if _, status, err := g.run(nil, "--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key", "New <new@example.org>", "ed25519"); err == nil {
		t.Fatalf("gpg made a key through the face:\n%s", status)
	}
	if _, status, err := g.run(nil, "--yes", "--delete-secret-keys", k.fpr+"!"); err == nil {
		t.Fatalf("gpg deleted a key through the face:\n%s", status)
	}
	// The key is still there, and still works.
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	g.must([]byte("still here"), "--local-user", k.fpr+"!", "--detach-sign")
	h.desk.done(t)
	if _, err := cli.Get(ctxT(t), "", k.name); err != nil {
		t.Fatal(err)
	}
}

// Whatever talks to the socket is asked about as itself: here the test,
// speaking the protocol by hand, junk and all.
func TestTheSocketTakesJunkAndNamesWhoeverAsks(t *testing.T) {
	h, cli, g := gpgHarness(t)
	k := addNewKey(t, cli, g)
	conn, err := net.Dial("unix", g.gpgconf("agent-socket")) // through the link
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)
	line := func() string {
		t.Helper()
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		return strings.TrimSuffix(l, "\n")
	}
	// do sends a command and returns its last line, skipping D and S lines.
	do := func(cmd string) string {
		t.Helper()
		fmt.Fprintf(conn, "%s\n", cmd)
		for {
			if l := line(); !strings.HasPrefix(l, "D ") && !strings.HasPrefix(l, "S ") {
				return l
			}
		}
	}
	if l := line(); !strings.HasPrefix(l, "OK Pleased to meet you") {
		t.Fatalf("greeting %q", l)
	}
	for cmd, want := range map[string]string{
		"GETINFO version":                       "OK",
		"\x7fELF\x02\x01\x01":                   "ERR 67109139",
		"HAVEKEY " + strings.Repeat("0", 39):    "ERR 67109144",
		"PKSIGN":                                "ERR 67108881",
		"EXPORT_KEY " + strings.Repeat("0", 40): "ERR 67108924",
		"SCD SERIALNO":                          "ERR 67108924",
	} {
		if l := do(cmd); !strings.HasPrefix(l, want) {
			t.Fatalf("%q: %q, want %q", cmd, l, want)
		}
	}
	var grip []byte
	for _, p := range k.pub.Parts() {
		if p.Primary {
			grip, _ = svgpgagent.Keygrip(p.Algorithm, p.Public)
		}
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	do(fmt.Sprintf("SIGKEY %X", grip))
	do("SETHASH 8 " + strings.Repeat("ab", 32))
	if l := do("PKSIGN"); !strings.HasPrefix(l, "ERR 67108963 ") {
		t.Fatalf("a denied PKSIGN: %q", l)
	}
	if q := h.desk.asked[0]; !strings.Contains(q.Description, filepath.Base(os.Args[0])) || strings.Contains(q.Description, "gpg (") {
		t.Fatalf("the prompt named %q", q.Description)
	}
	h.desk.done(t)
	// A line past Assuan's limit ends the connection.
	fmt.Fprintf(conn, "NOP %s\n", strings.Repeat("x", 4000))
	if l := line(); !strings.HasPrefix(l, "ERR 67109127 ") {
		t.Fatalf("a long line: %q", l)
	}
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("the connection went on")
	}
}

func TestOnlySecretvaultsOwnProgramsLinkGnuPG(t *testing.T) {
	h, cli, g := gpgHarness(t)
	other := h.connect("/usr/bin/gpg-sneaky", nil)
	evil := filepath.Join(t.TempDir(), svrpc.GnuPGAgentSocketName)
	if _, err := other.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: g.home, Socket: evil}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("another program linked a home: %v", err)
	}
	if _, err := os.Lstat(evil); err == nil {
		t.Fatal("the link was made anyway")
	}
	// Nor anything but a GnuPG socket, and never over a file.
	if _, err := cli.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: g.home, Socket: filepath.Join(t.TempDir(), "passwd")}); err == nil {
		t.Fatal("a link was made at a path that is no GnuPG socket")
	}
	file := filepath.Join(t.TempDir(), svrpc.GnuPGAgentSocketName)
	os.WriteFile(file, []byte("mine"), 0o600)
	if _, err := cli.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: t.TempDir(), Socket: file}); err == nil {
		t.Fatal("a file was replaced by a link")
	}
	if b, _ := os.ReadFile(file); string(b) != "mine" {
		t.Fatal("the file changed")
	}

	// The daemon links the home again when it starts; removing it takes
	// the link away.
	sock := g.gpgconf("agent-socket")
	os.Remove(sock)
	h.d.relinkGnuPG(false)
	if _, err := os.Readlink(sock); err != nil {
		t.Fatalf("not linked again: %v", err)
	}
	st, _ := cli.Status(ctxT(t))
	if len(st.GnuPGHomes) != 1 || st.GnuPGHomes[0] != g.home || st.GPGAgent == "" {
		t.Fatalf("status: %+v", st)
	}
	if _, err := cli.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: g.home, Remove: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sock); err == nil {
		t.Fatal("the link is still there")
	}
	if _, err := cli.LinkGnuPG(ctxT(t), svrpc.GnuPGLinkParams{Home: g.home, Relink: true}); err == nil {
		t.Fatal("a forgotten home was linked again")
	}
}
