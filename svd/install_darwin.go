//go:build darwin

package svd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/codemodify/secretvault/svops"
)

const launchLabel = svops.DaemonLaunchLabel

func plistPath() string { return svops.DaemonLaunchAgentFile() }

func install(exe string) (string, error) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + launchLabel + `</string>
	<key>ProgramArguments</key><array><string>` + exe + `</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
`
	p := plistPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
		return "", err
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	exec.Command("launchctl", "bootout", domain, p).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, p).CombinedOutput(); err != nil {
		return "", fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
	}
	return "Installed " + p + "; secretvaultd starts at every login, and is running now.", nil
}

func uninstall() (string, error) {
	p := plistPath()
	if _, err := os.Stat(p); err != nil {
		return "secretvaultd was not set to start at login.", nil
	}
	exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), p).Run()
	if err := os.Remove(p); err != nil {
		return "", err
	}
	return "Removed " + p + ". secretvaultd no longer starts at login.", nil
}
