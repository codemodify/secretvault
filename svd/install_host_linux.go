//go:build linux

package svd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func installHost(exe string, o HostInstall) (string, error) {
	if !o.PlainIdentity {
		if _, err := os.Stat(o.Credstore); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", fmt.Errorf("there is no sealed host identity at %s: make one with 'secretvault host init --seal' first, or install with --plain-identity to have the daemon read %s/host.identity", o.Credstore, hostDataDir)
			}
			return "", err
		}
	}
	if err := os.MkdirAll(o.UnitDir, 0o755); err != nil {
		return "", err
	}
	service := filepath.Join(o.UnitDir, HostServiceName)
	socket := filepath.Join(o.UnitDir, HostSocketName)
	if err := os.WriteFile(service, []byte(hostServiceUnit(exe, o)), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(socket, []byte(hostSocketUnit()), 0o644); err != nil {
		return "", err
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		return "", fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
	}
	args := []string{"enable", HostSocketName, HostServiceName}
	if !o.NoStart {
		args = []string{"enable", "--now", HostSocketName, HostServiceName}
	}
	if out, err := systemctl(args...); err != nil {
		return "", fmt.Errorf("systemctl enable: %v: %s", err, out)
	}
	msg := "Installed " + service + " and " + socket + "; the host daemon starts at boot"
	if !o.NoStart {
		msg += ", and is running now"
	}
	return msg + ". Units load credentials with LoadCredential=NAME:" + hostRuntimeDir + "/" + "credentials.sock.", nil
}

func uninstallHost(o HostInstall) (string, error) {
	var done []string
	for i, name := range []string{HostServiceName, HostSocketName} {
		p := filepath.Join(o.UnitDir, name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if i == 0 {
			systemctl("disable", "--now", HostServiceName, HostSocketName)
		}
		if err := os.Remove(p); err != nil {
			return "", err
		}
		done = append(done, "removed "+p)
	}
	if len(done) == 0 {
		return "The host daemon was not installed.", nil
	}
	systemctl("daemon-reload")
	return strings.Join(done, "; ") + ". The vaults in " + hostDataDir + " and the host identity are left alone.", nil
}
