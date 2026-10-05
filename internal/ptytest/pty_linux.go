package ptytest

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// open opens /dev/ptmx and unlocks its terminal, as openpty does.
func open() (*os.File, string, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	return os.NewFile(uintptr(fd), "/dev/ptmx"), fmt.Sprintf("/dev/pts/%d", n), nil
}
