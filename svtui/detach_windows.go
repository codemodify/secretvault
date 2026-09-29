//go:build windows

package svtui

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// detach runs cmd without a console, outliving this program.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}
