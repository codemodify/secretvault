package svtrust

import (
	"bytes"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Checks against GnuPG, where it is installed. Every run uses its own
// throwaway home (so its own agent), never ~/.gnupg or a running agent,
// and the agent is killed when the test ends.

type gnupg struct {
	t    *testing.T
	home string
}

func newGnuPG(t *testing.T) *gnupg {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("GnuPG is not installed")
	}
	if testing.Short() {
		t.Skip("GnuPG is slow")
	}
	home := t.TempDir()
	os.Chmod(home, 0o700)
	g := &gnupg{t, home}
	t.Cleanup(func() {
		for _, args := range [][]string{{"--kill", "all"}, {"--remove-socketdir"}} {
			cmd := exec.Command("gpgconf", append([]string{"--homedir", home}, args...)...)
			cmd.Env = g.env()
			cmd.Run()
		}
	})
	return g
}

func (g *gnupg) env() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GNUPGHOME=") && !strings.HasPrefix(e, "GPG_AGENT_INFO=") {
			env = append(env, e)
		}
	}
	return append(env, "GNUPGHOME="+g.home)
}

func (g *gnupg) run(bin string, args ...string) string {
	g.t.Helper()
	if bin == "gpg" {
		args = append([]string{"--homedir", g.home, "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = g.env()
	cmd.Dir = g.home
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		g.t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, errb.Bytes())
	}
	return out.String()
}

// GnuPG's own WKD client names the same file for every address.
func TestWKDHashMatchesGnuPG(t *testing.T) {
	g := newGnuPG(t)
	wks := ""
	for _, p := range []string{"/usr/bin/gpg-wks-client", "/usr/lib/gnupg/gpg-wks-client", "/usr/libexec/gpg-wks-client"} {
		if _, err := os.Stat(p); err == nil {
			wks = p
		}
	}
	if wks == "" {
		t.Skip("gpg-wks-client is not installed")
	}
	for _, addr := range []string{"Joe.Doe@Example.ORG", "alice@example.org", "ALICE+tag@example.org", "x_1-2.3@sub.example.co.uk", "Zz@example.org"} {
		fields := strings.Fields(g.run(wks, "--print-wkd-hash", addr))
		local := addr[:strings.LastIndexByte(addr, '@')]
		if len(fields) == 0 || fields[0] != WKDHash(local) {
			t.Errorf("%s: gpg-wks-client says %v, we say %s", addr, fields, WKDHash(local))
		}
		// GnuPG writes the l= parameter lowercased; the draft keeps the
		// local part as written. The file, which is what counts, agrees.
		want := strings.Fields(g.run(wks, "--print-wkd-url", addr))[0]
		adv, _, _ := WKDURLs(addr)
		if a, _, _ := strings.Cut(adv, "?"); !strings.HasPrefix(want, a+"?") {
			t.Errorf("%s: gpg-wks-client says %s, we say %s", addr, want, adv)
		}
	}
}

// A key GnuPG made reads with GnuPG's fingerprints for the key and its
// subkeys, and the addresses of its user IDs.
func TestKeysGnuPGMadeReadAsGnuPGSeesThem(t *testing.T) {
	g := newGnuPG(t)
	g.run("gpg", "--quick-gen-key", "Gina Example <gina@example.org>", "ed25519", "sign", "never")
	var fprs []string
	colons := func() {
		fprs = nil
		for _, line := range strings.Split(g.run("gpg", "--with-colons", "--list-keys"), "\n") {
			if f := strings.Split(line, ":"); f[0] == "fpr" {
				fprs = append(fprs, f[9])
			}
		}
	}
	colons()
	g.run("gpg", "--quick-add-key", fprs[0], "cv25519", "encr", "never")
	g.run("gpg", "--quick-add-key", fprs[0], "ed25519", "sign", "never")
	g.run("gpg", "--quick-add-uid", fprs[0], "Gina <gina@work.example>")
	colons()
	exported := g.run("gpg", "--armor", "--export", fprs[0])
	k := keyOf(t, []byte(exported))
	if k.Fingerprint != fprs[0] || !slices.Equal(k.Subkeys, fprs[1:]) {
		t.Fatalf("fingerprints: ours %s %v, GnuPG's %v", k.Fingerprint, k.Subkeys, fprs)
	}
	// Neither user ID is marked primary: which one labels the key depends
	// on their certifications' times, which may share a second.
	if !slices.Equal(k.Addresses, []string{"gina@example.org", "gina@work.example"}) ||
		k.Label != "Gina Example <gina@example.org>" && k.Label != "Gina <gina@work.example>" {
		t.Fatalf("addresses %v, label %q", k.Addresses, k.Label)
	}

	// Found by its signing subkey's fingerprint and key ID, as a signature
	// names it.
	s, _ := newStore(t)
	if _, _, err := s.Add(&Contact{Keys: []*Key{k}}); err != nil {
		t.Fatal(err)
	}
	signing := fprs[len(fprs)-1]
	for _, ref := range []string{signing, signing[24:]} {
		if c, _, err := s.ByFingerprint(ref); err != nil || !strings.HasPrefix(c.Name, "Gina") {
			t.Fatalf("by %s: %v, %v", ref, c, err)
		}
	}
}
