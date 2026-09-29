//go:build linux

package svsecret_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svsecret"
)

// The client is tested against a real keyring: gnome-keyring-daemon run on
// a private bus, when it is installed (it is what most desktops migrate
// from).
func TestAllSecretsAreReadFromGnomeKeyring(t *testing.T) {
	gkd, err := exec.LookPath("gnome-keyring-daemon")
	if err != nil {
		t.Skip("gnome-keyring-daemon is not installed")
	}
	st, err := exec.LookPath("secret-tool")
	if err != nil {
		t.Skip("secret-tool is not installed")
	}
	dbustest.PrivateBus(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", home+"/data")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	// A login keyring made and unlocked with a fixture password.
	cmd := exec.Command(gkd, "--unlock", "--foreground", "--components=secrets")
	cmd.Stdin = strings.NewReader("fixture-password")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	bus, err := svdbus.ConnectSession()
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		if _, err := svsecret.CurrentOwner(ctx, bus); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("gnome-keyring never took the name")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The login keyring appears shortly after the name does.
	var out []byte
	for range 50 {
		store := exec.Command(st, "store", "--label=Imported one", "service", "legacy", "user", "bob")
		store.Stdin = strings.NewReader("from-gnome-keyring")
		if out, err = store.CombinedOutput(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("secret-tool could not store into the test keyring (%v): %s", err, out)
	}

	owner, _ := svsecret.CurrentOwner(ctx, bus)
	if owner.PID == 0 {
		t.Fatalf("owner %+v", owner)
	}
	c, err := svsecret.Open(ctx, bus)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	secrets, warnings, err := c.ReadAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range secrets {
		if s.Label == "Imported one" && string(s.Value) == "from-gnome-keyring" && s.Attributes["service"] == "legacy" {
			found = true
		}
		s.Wipe()
	}
	if !found {
		t.Fatalf("read %d secrets, warnings %v; the stored one is missing", len(secrets), warnings)
	}
}
