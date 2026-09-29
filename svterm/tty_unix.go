//go:build !windows

package svterm

import "os"

func openTerminal() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	return f, f, err
}
