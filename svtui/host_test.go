//go:build linux

package svtui

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The host panel against a host daemon on the test's own directories
// (SECRETVAULT_HOST_DATA and SECRETVAULT_HOST_RUNTIME, which the harness
// sets), whose admin socket takes the test for root; systemd-creds is a
// stand-in.
func TestTheHostDaemonIsSetUpFromThePanel(t *testing.T) {
	h := newHarness(t)
	data, run := os.Getenv(svrpc.EnvHostData), os.Getenv(svrpc.EnvHostRuntime)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	var sealed []string
	creds := func(stdin []byte, args ...string) ([]byte, error) {
		sealed = append([]string(nil), args...)
		return nil, nil
	}
	d, err := svd.New(svd.Options{
		Mode: svd.ModeHost, Home: data,
		Host: svd.HostOptions{Runtime: run, FromServiceManager: func(net.Conn) error { return nil }},
		Peer: func(c net.Conn) (*svpeer.Process, error) {
			return &svpeer.Process{PID: 1, UID: os.Getuid(), Exe: "/usr/bin/secretvault", SystemOwned: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lns, err := d.ListenHost()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { d.ServeCredentials(ctx, lns.Credentials); wg.Done() }()
	go func() { d.ServeServices(ctx, lns.Services); wg.Done() }()
	go func() { d.Serve(ctx, lns.Admin); wg.Done() }()
	t.Cleanup(func() { cancel(); wg.Wait(); lns.Close() })

	h.start(Options{HostSocket: filepath.Join(run, svrpc.HostAdminSocketName), SystemdCreds: creds}, "")
	h.unlock()
	h.typeText("H")
	h.waitFor("Host daemon")
	h.waitFor("identity: none")

	// The identity, in a root-only file.
	h.typeText("i")
	h.waitFor("Make the host identity")
	h.tabs(5)
	h.key(tcell.KeyEnter)
	h.waitFor("Its recipient, which vaults are shared to")
	rcpt := h.onceSecrets()
	b, err := os.ReadFile(filepath.Join(data, "host.identity"))
	if len(rcpt) != 1 || err != nil || !strings.Contains(string(b), rcpt[0]) {
		t.Fatalf("the recipient %q; the identity file: %v", rcpt, err)
	}
	if st, err := os.Stat(filepath.Join(data, "host.identity")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the identity file: %v %v", st, err)
	}
	if sealed != nil {
		t.Fatal("systemd-creds ran without sealing")
	}
	h.key(tcell.KeyEscape)

	// A unit's credential, and a local service.
	h.typeText("a")
	h.waitFor("Allow a unit's credential")
	h.typeText("app.service")
	h.tabs(1)
	h.typeText("db")
	h.tabs(1)
	h.typeText("sv://prod/db/postgres#password")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("LoadCredential=db:" + filepath.Join(run, "credentials.sock"))
	h.key(tcell.KeyEscape)
	h.waitFor("credential db")
	h.typeText("l")
	h.waitFor("Allow a local service")
	h.typeText("4242")
	h.tabs(2)
	h.typeText("sv://prod/backup/*")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("may now read sv://prod/backup/*")
	h.key(tcell.KeyEscape)
	h.waitFor("user 4242")

	// The unit denied again.
	selectRef[svrpc.HostCredential](h)
	h.typeText("x")
	h.waitFor("Stop the service app.service reading secrets")
	h.waitForWords("will no longer get its credential db")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab) // Cancel, then Deny
	h.key(tcell.KeyEnter)
	h.waitSaid("Removed from the host policy")
	h.waitFor("None (a allows one)")

	// The log says what changed.
	h.typeText("v")
	h.waitFor("Host log")
	h.waitFor("changed")
	h.waitFor("the policy")
}
