//go:build !windows

package secretvault

import (
	"os/exec"
	"syscall"
)

// detach runs cmd in a session of its own, so the daemon outlives the
// program that started it and its terminal.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
