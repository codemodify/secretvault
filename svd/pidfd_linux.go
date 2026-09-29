//go:build linux

package svd

import (
	"errors"

	"golang.org/x/sys/unix"
)

// pidfdAlive reports whether the process a pidfd names is still running:
// signal 0 checks without sending anything.
func pidfdAlive(fd int) bool {
	err := unix.PidfdSendSignal(fd, 0, nil, 0)
	return err == nil || !errors.Is(err, unix.ESRCH)
}

func closeFD(fd int) { unix.Close(fd) }
