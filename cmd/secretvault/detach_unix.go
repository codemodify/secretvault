//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach runs cmd in a session of its own, so it outlives this command and
// its terminal.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
