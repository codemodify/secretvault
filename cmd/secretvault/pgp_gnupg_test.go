//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svrpc"
)

// 'secretvault pgp gpg-setup', and gpg then signing through the daemon.
// The GnuPG home is the test's own: gpg-setup is always given it, never
// left to its default, and the socket directory gpgconf makes for it is
// removed when the test ends. gpg runs with --no-autostart, so it can
// start no agent of its own.

func gnupgTools(t *testing.T) (gpg, gpgconf string) {
	t.Helper()
	if testing.Short() {
		t.Skip("GnuPG interop is slow")
	}
	gpg, gpgconf, err := gnupgPrograms("")
	if err != nil {
		t.Skip(err)
	}
	return gpg, gpgconf
}

// serveGPGAgent starts the daemon's gpg-agent face.
func (h *harness) serveGPGAgent() string {
	h.t.Helper()
	sock := filepath.Join(filepath.Dir(h.sock), "gpg-agent.sock")
	ln, cleanup, err := svd.Listen(sock)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	go h.d.ServeGPGAgent(ctx, ln)
	for range 100 {
		if out := h.ok("", "status"); strings.Contains(out, "gpg:") {
			break
		}
	}
	return sock
}

func TestGPGSetupPointsAGnuPGHomeAtTheDaemon(t *testing.T) {
	gpg, gpgconf := gnupgTools(t)
	h := newHarness(t)
	h.init()
	sock := h.serveGPGAgent()
	h.ok("", h.with("pgp", "new", "--name", "Ada Lovelace", "--email", "ada@example.org", "--v4")...)
	h.ok("", h.with("pgp", "new", "--name", "Ada Six", "--email", "six@example.org", "--item", "pgp/six")...)
	home := filepath.Join(t.TempDir(), "gnupg")
	env := func() []string {
		var env []string
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "GNUPGHOME=") && !strings.HasPrefix(e, "GPG_AGENT_INFO=") {
				env = append(env, e)
			}
		}
		return append(env, "GNUPGHOME="+home)
	}
	t.Cleanup(func() {
		cmd := exec.Command(gpgconf, "--homedir", home, "--remove-socketdir")
		cmd.Env = env()
		cmd.Run()
	})
	agentSock, err := gnupgDir(gpgconf, home, "agent-socket")
	if err != nil {
		t.Fatal(err)
	}

	// --dry-run says what would happen, and nothing does.
	out := h.ok("", h.with("pgp", "gpg-setup", "--gnupghome", home, "--gpg", gpg, "--dry-run")...)
	for _, want := range []string{"make the directory " + home, "link " + agentSock + " (where gpg looks for its agent) to " + sock,
		"Ada Lovelace <ada@example.org>", "agent-program ", "Left out: pgp/six, a version 6 key", "Nothing was changed."} {
		if !strings.Contains(out, want) {
			t.Fatalf("the dry run does not say %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(home); err == nil {
		t.Fatal("the dry run made the home")
	}
	if _, err := os.Lstat(agentSock); err == nil {
		t.Fatal("the dry run linked the socket")
	}

	out = h.ok("", h.with("pgp", "gpg-setup", "--gnupghome", home, "--gpg", gpg)...)
	if !strings.Contains(out, "export GNUPGHOME="+home) {
		t.Fatalf("gpg-setup said:\n%s", out)
	}
	if fi, err := os.Stat(home); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the home: %v %v", fi, err)
	}
	if target, err := os.Readlink(agentSock); err != nil || target != sock {
		t.Fatalf("%s leads to %q (%v)", agentSock, target, err)
	}
	conf, _ := os.ReadFile(filepath.Join(home, "gpg.conf"))
	if !strings.Contains(string(conf), "|"+gpgAgentProgramFlag) || strings.Count(string(conf), "agent-program") != 1 {
		t.Fatalf("gpg.conf:\n%s", conf)
	}
	// Again changes nothing more.
	h.ok("", h.with("pgp", "gpg-setup", "--gnupghome", home, "--gpg", gpg)...)
	if conf2, _ := os.ReadFile(filepath.Join(home, "gpg.conf")); !bytes.Equal(conf, conf2) {
		t.Fatalf("gpg.conf changed:\n%s", conf2)
	}

	// gpg now signs with the vault's key, and trusts it as the person's own.
	runGPG := func(stdin []byte, args ...string) (string, string, error) {
		cmd := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--no-tty", "--no-autostart", "--status-fd", "2"}, args...)...)
		cmd.Env = env()
		cmd.Stdin = bytes.NewReader(stdin)
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		return o.String(), e.String(), err
	}
	if o, e, err := runGPG(nil, "--with-colons", "--list-secret-keys"); err != nil || !strings.Contains(o, "ada@example.org") {
		t.Fatalf("gpg -K: %v\n%s\n%s", err, o, e)
	}
	h.desk.choice = svrpc.ChoiceAlways
	sig, e, err := runGPG([]byte("hello"), "--detach-sign", "--armor")
	if err != nil {
		t.Fatalf("gpg --detach-sign: %v\n%s", err, e)
	}
	os.WriteFile(filepath.Join(h.dir, "sig"), []byte(sig), 0o600)
	if _, e, err := runGPG([]byte("hello"), "--verify", filepath.Join(h.dir, "sig"), "-"); err != nil || !strings.Contains(e, "TRUST_ULTIMATE") {
		t.Fatalf("gpg --verify: %v\n%s", err, e)
	}
	if q := h.desk.questions(); len(q) != 1 || !strings.Contains(q[0], "gpg (") {
		t.Fatalf("asked %q", q)
	}
	if out := h.ok("", "status"); !strings.Contains(out, "for "+home) {
		t.Fatalf("status:\n%s", out)
	}

	// With the link gone (a reboot empties /run/user), gpg starts
	// secretvault as its agent-program, which links it again.
	os.Remove(agentSock)
	if _, _, code := h.run("", "--homedir", home, "--use-standard-socket", gpgAgentProgramFlag, "--daemon"); code != 0 {
		t.Fatalf("started as gpg's agent: exit %d", code)
	}
	if target, _ := os.Readlink(agentSock); target != sock {
		t.Fatalf("not linked again: %q", target)
	}
	// A home that was never set up is not linked that way.
	other := t.TempDir()
	if _, _, code := h.run("", "--homedir", other, "--use-standard-socket", gpgAgentProgramFlag, "--daemon"); code == 0 {
		t.Fatal("linked a home nobody set up")
	}

	// --remove undoes the link and gpg.conf, and keeps the public keys.
	h.ok("", h.with("pgp", "gpg-setup", "--gnupghome", home, "--remove")...)
	if _, err := os.Lstat(agentSock); err == nil {
		t.Fatal("the link is still there")
	}
	if conf, _ := os.ReadFile(filepath.Join(home, "gpg.conf")); strings.Contains(string(conf), "agent-program") {
		t.Fatalf("gpg.conf:\n%s", conf)
	}
	if o, _, _ := runGPG(nil, "--with-colons", "--list-keys"); !strings.Contains(o, "ada@example.org") {
		t.Fatalf("the public key went too:\n%s", o)
	}
	if out := h.ok("", "status"); strings.Contains(out, "for "+home) {
		t.Fatalf("status:\n%s", out)
	}
}

func TestGPGSetupNeedsAKeyGnuPGCanUse(t *testing.T) {
	gpg, _ := gnupgTools(t)
	h := newHarness(t)
	h.init()
	h.serveGPGAgent()
	home := filepath.Join(t.TempDir(), "gnupg")
	_, errs, code := h.run("", h.with("pgp", "gpg-setup", "--gnupghome", home, "--gpg", gpg)...)
	if code == 0 || !strings.Contains(errs, "--v4") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if _, err := os.Stat(home); err == nil {
		t.Fatal("the home was made anyway")
	}
}
