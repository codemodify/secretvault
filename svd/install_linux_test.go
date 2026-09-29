//go:build linux

package svd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesAUnitAndUninstallRemovesIt(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var calls []string
	systemctl = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}
	hasUserSystemd = func() bool { return true }
	t.Cleanup(func() {
		systemctl = func(args ...string) ([]byte, error) { panic("systemctl after test") }
	})

	msg, err := Install("/opt/secret vault/secretvaultd")
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), `ExecStart="/opt/secret vault/secretvaultd"`) || !strings.Contains(string(unit), "LimitCORE=0") {
		t.Fatalf("unit:\n%s", unit)
	}
	if !strings.Contains(strings.Join(calls, ";"), "--user enable --now secretvaultd.service") || !strings.Contains(msg, "every login") {
		t.Fatalf("calls %v, message %q", calls, msg)
	}
	if _, err := Uninstall(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(unitPath()); !os.IsNotExist(err) {
		t.Fatal("the unit is still there")
	}
	if _, err := Install("relative/path"); err == nil {
		t.Fatal("a relative path was installed")
	}
}

func TestWithoutSystemdAnAutostartEntryIsUsed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	hasUserSystemd = func() bool { return false }
	if _, err := Install("/usr/bin/secretvaultd"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "autostart", "secretvaultd.desktop"))
	if err != nil || !strings.Contains(string(b), "Exec=/usr/bin/secretvaultd") {
		t.Fatalf("autostart: %s, %v", b, err)
	}
}
