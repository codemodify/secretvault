package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svserver"
)

func TestSyncFromTheCommandLineWithAnInviteToScan(t *testing.T) {
	root := t.TempDir()
	s, err := svserver.New(svserver.Config{Root: root, OpenRegistration: true, Rate: -1})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(func() { s.Close(); srv.Close() })
	fp := svserver.Fingerprint(srv.Certificate().Raw)

	h := newHarness(t)
	h.init()
	h.ok("hunter2", h.with("set", "x")...)
	if out := h.ok("", h.with("sync", "setup", srv.URL, "--fingerprint", fp, "--label", "laptop")...); !strings.Contains(out, "now syncs with "+srv.URL) {
		t.Fatalf("setup: %s", out)
	}
	out := h.ok("", h.with("sync", "invite", "--qr")...)
	if !strings.Contains(out, "secretvault sync join 'secretvault-sync:?") || !strings.ContainsAny(out, "▀▄█") {
		t.Fatalf("invite --qr:\n%s", out)
	}
	if out := h.ok("", "sync", "status"); !strings.Contains(out, srv.URL) {
		t.Fatalf("status: %s", out)
	}

	other := newHarness(t)
	invite := strings.Split(strings.Split(out2(h), "sync join '")[1], "'")[0]
	if out := other.ok(invite+"\n", "sync", "join", "-", "--name", "shared"); !strings.Contains(out, "Fetched vault \"shared\"") {
		t.Fatalf("join: %s", out)
	}
	if got := other.ok("", other.with("--vault", "shared", "get", "x")...); got != "hunter2\n" {
		t.Fatalf("the joined vault: %q", got)
	}
}

// out2 makes a fresh invite (each works once).
func out2(h *harness) string { return h.ok("", h.with("sync", "invite")...) }
