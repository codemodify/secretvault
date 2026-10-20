package svd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svops"
)

// Starting at login. `secretvaultd install` makes the daemon start with
// every session, the way the platform expects:
//
//	Linux    a systemd user unit (else an XDG autostart entry)
//	macOS    a LaunchAgent
//	Windows  a Run entry under HKCU
//
// `secretvaultd uninstall` undoes it; a running daemon keeps running.

// ServiceName is the systemd user unit's name.
const ServiceName = svops.DaemonUnitName

// Install makes the daemon at exe start at every login, and says what it
// did.
func Install(exe string) (string, error) {
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("svd: %q is not an absolute path", exe)
	}
	return install(exe)
}

// Uninstall undoes Install.
func Uninstall() (string, error) { return uninstall() }

func systemdQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func desktopQuote(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\`$") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\"`, "`", "\\`", "$", `\$`).Replace(s) + `"`
}

// serviceUnit is the systemd user unit that runs exe. The hardening
// settings are the ones a per-user daemon can keep without losing
// anything it needs.
func serviceUnit(exe string) string {
	return `[Unit]
Description=secretvault daemon: holds vault keys, asks before any program uses them
Documentation=https://github.com/codemodify/secretvault

[Service]
ExecStart=` + systemdQuote(exe) + `
Restart=on-failure
RestartSec=2
# A second daemon on the same socket exits 3; restarting would only clash.
RestartPreventExitStatus=3
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
LimitCORE=0

[Install]
WantedBy=default.target
`
}

func autostartEntry(exe string) string {
	return `[Desktop Entry]
Type=Application
Name=secretvault daemon
Comment=Holds vault keys and asks before any program uses them
Exec=` + desktopQuote(exe) + `
NoDisplay=true
X-GNOME-Autostart-enabled=true
`
}
