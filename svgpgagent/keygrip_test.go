package svgpgagent

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svpgp"
)

// Keygrips against GnuPG's own: keys of every kind made by gpg, in a
// throwaway home of the test's own (with its own agent, killed when the
// test ends), and the keygrips gpg --with-keygrip lists for them.

var gpgBinary = func() string {
	if _, err := os.Stat("/usr/bin/gpg"); err == nil {
		return "/usr/bin/gpg"
	}
	p, _ := exec.LookPath("gpg")
	return p
}()

// gpgHome is a throwaway GnuPG home.
type gpgHome struct {
	t    *testing.T
	home string
}

func newGPGHome(t *testing.T) *gpgHome {
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

// env is the caller's environment without anything that points at the
// real agent or home.
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

func (g *gpgHome) must(args ...string) []byte {
	g.t.Helper()
	base := []string{"--homedir", g.home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}
	cmd := exec.Command(gpgBinary, append(base, args...)...)
	cmd.Env = g.env()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		g.t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, errb.Bytes())
	}
	return out.Bytes()
}

var colonLine = regexp.MustCompile(`(?m)^(fpr|grp):::::::::([0-9A-F]+):`)

// keygrips maps each (sub)key's fingerprint to gpg's keygrip for it.
func (g *gpgHome) keygrips() map[string]string {
	out := g.must("--with-colons", "--with-keygrip", "--list-keys")
	grips := map[string]string{}
	var fpr string
	for _, m := range colonLine.FindAllStringSubmatch(string(out), -1) {
		if m[1] == "fpr" {
			fpr = m[2]
		} else if fpr != "" {
			grips[fpr] = m[2]
			fpr = ""
		}
	}
	return grips
}

func TestKeygripsMatchGnuPGs(t *testing.T) {
	g := newGPGHome(t)
	for _, k := range []struct{ uid, primary, sub string }{
		{"RSA <rsa@example.org>", "rsa2048", "rsa2048"},
		{"P-256 <p256@example.org>", "nistp256", "nistp256"},
		{"P-384 <p384@example.org>", "nistp384", "nistp384"},
		{"P-521 <p521@example.org>", "nistp521", "nistp521"},
		{"Ed25519 <ed25519@example.org>", "ed25519", "cv25519"},
	} {
		g.must("--quick-generate-key", k.uid, k.primary, "cert,sign", "never")
		out := g.must("--with-colons", "--list-keys", k.uid)
		m := regexp.MustCompile(`(?m)^fpr:::::::::([0-9A-F]+):`).FindSubmatch(out)
		if m == nil {
			t.Fatalf("no fingerprint for %s", k.uid)
		}
		g.must("--quick-add-key", string(m[1]), k.sub, "encr", "never")
	}
	want := g.keygrips()
	keys, err := svpgp.ReadKeys(bytes.NewReader(g.must("--export")))
	if err != nil {
		t.Fatal(err)
	}
	algs := map[svpgp.PublicKeyAlgorithm]int{}
	checked := 0
	for _, k := range keys {
		for _, p := range k.Parts() {
			fpr := strings.ToUpper(hex.EncodeToString(p.Fingerprint))
			grip, err := Keygrip(p.Algorithm, p.Public)
			if err != nil {
				t.Errorf("%s (%v): %v", fpr, p.Algorithm, err)
				continue
			}
			if got := strings.ToUpper(hex.EncodeToString(grip)); got != want[fpr] {
				t.Errorf("%v key %s: keygrip %s, gpg says %s", p.Algorithm, fpr, got, want[fpr])
			}
			algs[p.Algorithm]++
			checked++
		}
	}
	if checked != 10 || algs[svpgp.RSA] != 2 || algs[svpgp.ECDSA] != 3 || algs[svpgp.ECDH] != 4 || algs[svpgp.EdDSALegacy] != 1 {
		t.Fatalf("checked %d keys: %v", checked, algs)
	}
}
