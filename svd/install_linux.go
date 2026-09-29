//go:build linux || freebsd || netbsd || openbsd

package svd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// systemctl runs systemctl; tests stand in for it, so they never touch
// the real user manager.
var systemctl = func(args ...string) ([]byte, error) {
	return exec.Command("systemctl", args...).CombinedOutput()
}

var hasUserSystemd = func() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := systemctl("--user", "show-environment")
	return err == nil
}

func unitPath() string      { return filepath.Join(configDir(), "systemd", "user", ServiceName) }
func autostartPath() string { return filepath.Join(configDir(), "autostart", "secretvaultd.desktop") }

func install(exe string) (string, error) {
	if hasUserSystemd() {
		p := unitPath()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, []byte(serviceUnit(exe)), 0o644); err != nil {
			return "", err
		}
		if out, err := systemctl("--user", "daemon-reload"); err != nil {
			return "", fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
		if out, err := systemctl("--user", "enable", "--now", ServiceName); err != nil {
			return "", fmt.Errorf("systemctl enable: %v: %s", err, out)
		}
		return "Installed " + p + "; secretvaultd starts at every login, and is running now.", nil
	}
	p := autostartPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(autostartEntry(exe)), 0o644); err != nil {
		return "", err
	}
	return "Installed " + p + "; secretvaultd starts at every login (no systemd user session here).", nil
}

func uninstall() (string, error) {
	var done []string
	if _, err := os.Stat(unitPath()); err == nil {
		systemctl("--user", "disable", ServiceName)
		if err := os.Remove(unitPath()); err != nil {
			return "", err
		}
		systemctl("--user", "daemon-reload")
		done = append(done, "removed "+unitPath())
	}
	if _, err := os.Stat(autostartPath()); err == nil {
		if err := os.Remove(autostartPath()); err != nil {
			return "", err
		}
		done = append(done, "removed "+autostartPath())
	}
	if len(done) == 0 {
		return "secretvaultd was not set to start at login.", nil
	}
	return strings.Join(done, "; ") + ". secretvaultd no longer starts at login.", nil
}
