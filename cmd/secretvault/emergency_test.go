package main

import (
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svserver"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// waitFor runs the CLI until its output holds want, for a few seconds.
func (h *harness) waitFor(want string, args ...string) string {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, errs, _ := h.run("", args...)
		if strings.Contains(out, want) {
			return out
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("secretvault %s never said %q:\n%s%s", strings.Join(args, " "), want, out, errs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The whole of emergency access from the command line: the owner grants
// it, the trustee accepts and asks, the owner is told and denies, the
// trustee asks again and opens the vault after the wait, and the owner
// revokes it and rotates the key.
func TestEmergencyAccessFromTheCommandLine(t *testing.T) {
	clock := &testClock{t: time.Now().UTC()}
	root := t.TempDir()
	srv, err := svserver.New(svserver.Config{Root: root, AdminToken: "an admin token of some length", Rate: -1, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewTLSServer(srv)
	t.Cleanup(func() {
		srv.Close()
		hs.Close()
	})
	withClock := func(o *svd.Options) { o.Now = clock.now }
	owner, trustee := newHarness(t, withClock), newHarness(t, withClock)

	owner.init()
	owner.ok("hunter2\n", owner.with("set", "mail/imap")...)
	token := owner.write("token", "an admin token of some length\n")
	owner.ok("", owner.with("sync", "setup", hs.URL, "--fingerprint", svserver.Fingerprint(hs.Certificate().Raw), "--admin-token-file", token)...)

	idFile := filepath.Join(trustee.dir, "alice.id")
	recipient := strings.TrimSpace(trustee.ok("", "identity", "new", "--out", idFile))

	// A recipient that is no contact: granted, with a warning.
	out, errs, code := owner.run("", owner.with("emergency", "grant", recipient, "--wait", "2d", "--name", "ada")...)
	if code != 0 || !strings.Contains(errs, "not one of your contacts") || !strings.Contains(out, "within 2 days") {
		t.Fatalf("grant: %d\n%s%s", code, out, errs)
	}
	invite := regexp.MustCompile(`accept '([^']+)'`).FindStringSubmatch(out)
	grant := regexp.MustCompile(`Grant ([0-9a-f]{32})\.`).FindStringSubmatch(out)
	if invite == nil || grant == nil {
		t.Fatalf("no invite or grant in:\n%s", out)
	}

	if out := trustee.ok("", "emergency", "accept", invite[1], "--identity", idFile); !strings.Contains(out, `Accepted, as "ada"`) {
		t.Fatalf("accept:\n%s", out)
	}
	if out := trustee.ok("", "emergency", "request", "ada"); !strings.Contains(out, "Asked.") {
		t.Fatalf("request:\n%s", out)
	}
	owner.waitFor("asked for emergency access to vault", "status")
	if out := owner.ok("", owner.with("emergency", "ls")...); !strings.Contains(out, "REQUESTED") {
		t.Fatalf("the owner's list:\n%s", out)
	}
	if out := owner.ok("", owner.with("emergency", "deny", grant[1][:8])...); !strings.Contains(out, "Denied") {
		t.Fatalf("deny:\n%s", out)
	}
	if _, errs, code := trustee.run("", "emergency", "open", "ada", "--identity", idFile); code == 0 || !strings.Contains(errs, "denied") {
		t.Fatalf("opened after a denial: %d %s", code, errs)
	}

	// Asked again, and the wait passes.
	trustee.ok("", "emergency", "request", "ada")
	clock.add(49 * time.Hour)
	if out := trustee.ok("", "emergency", "open", "ada", "--identity", idFile); !strings.Contains(out, `Opened vault "ada"`) {
		t.Fatalf("open:\n%s", out)
	}
	if out := trustee.ok("", "--vault", "ada", "get", "mail/imap", "--identity", idFile); strings.TrimSpace(out) != "hunter2" {
		t.Fatalf("get: %q", out)
	}
	if _, errs, code := trustee.run("x\n", "--vault", "ada", "set", "mine", "--identity", idFile); code == 0 || !strings.Contains(errs, "read-only") {
		t.Fatalf("a write: %d %s", code, errs)
	}
	if _, errs, code := trustee.run("", "--vault", "ada", "get", "mail/imap"); code == 0 || !strings.Contains(errs, "--identity") {
		t.Fatalf("without the identity: %d %s", code, errs)
	}
	if out := trustee.ok("", "emergency", "ls"); !strings.Contains(out, "opened, as vault ada") {
		t.Fatalf("the trustee's list:\n%s", out)
	}
	owner.waitFor("was given the key", "status")

	// Revoked, and the key rotated: she can no longer ask or follow.
	out = owner.ok("", owner.with("emergency", "revoke", grant[1][:8], "--rotate", "--new-passphrase-file", owner.passFile)...)
	if !strings.Contains(out, "Revoked") || !strings.Contains(out, "The vault key was rotated") {
		t.Fatalf("revoke:\n%s", out)
	}
	if _, errs, code := trustee.run("", "emergency", "request", "ada"); code == 0 || !strings.Contains(errs, "revoked") {
		t.Fatalf("a request after revoking: %d %s", code, errs)
	}
}
