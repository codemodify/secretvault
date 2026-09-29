//go:build windows

package secretvault

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// detach runs cmd without a console of its own, outliving its starter.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}
