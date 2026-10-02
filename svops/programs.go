package svops

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// secretvault's programs, which live in one directory, and the system
// commands the operations here run.

// CommandRunner runs a system command (systemctl) and returns what it
// said; tests replace it, so that none runs.
var CommandRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Executable is this program's own path, links resolved.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// SiblingProgram is the program called name (secretvaultd, secretvault)
// in this program's directory, or "" when there is none.
func SiblingProgram(name string) string {
	exe, err := Executable()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// CLIProgram is the secretvault command-line program beside this one
// (the managers are installed beside it), or "" when there is none. The
// operations that name the CLI to other programs (the browsers' host,
// gpg's agent-program) take it from the managers; the CLI passes "",
// meaning itself.
func CLIProgram() string { return SiblingProgram("secretvault") }
