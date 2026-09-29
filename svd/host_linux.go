//go:build linux

package svd

import (
	"errors"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerAddress is the address the other end of c is bound to
// (getpeername), with "@" for the NUL of an abstract name.
func peerAddress(c net.Conn) (string, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return "", errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return "", err
	}
	var sa unix.Sockaddr
	var nameErr error
	if err := raw.Control(func(fd uintptr) { sa, nameErr = unix.Getpeername(int(fd)) }); err != nil {
		return "", err
	}
	if nameErr != nil {
		return "", nameErr
	}
	su, ok := sa.(*unix.SockaddrUnix)
	if !ok {
		return "", errors.New("not a Unix socket")
	}
	return su.Name, nil
}

// fileOwner is the uid a file belongs to.
func fileOwner(st os.FileInfo) (int, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(sys.Uid), true
}
