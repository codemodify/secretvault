//go:build windows

package svpeer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID: the process ID of an
// AF_UNIX socket's peer (Windows 10 1803 and later).
const sioAFUnixGetPeerPID = 0x58000100

func peerCred(c net.Conn) (pid, uid int, err error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, 0, errors.New("svpeer: not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var peer uint32
	var ioErr error
	if err := raw.Control(func(fd uintptr) {
		var n uint32
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
			(*byte)(unsafe.Pointer(&peer)), 4, &n, nil, 0)
	}); err != nil {
		return 0, 0, err
	}
	if ioErr != nil {
		return 0, 0, ioErr
	}
	same, err := sameUser(peer)
	if err != nil {
		return 0, 0, err
	}
	// Windows has no numeric uids (os.Getuid is -1): report ours for the
	// same user and anything else for another.
	if !same {
		return int(peer), os.Getuid() - 1, nil
	}
	return int(peer), os.Getuid(), nil
}

// sameUser compares the peer process's token user with ours.
func sameUser(pid uint32) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return false, err
	}
	defer tok.Close()
	theirs, err := tok.GetTokenUser()
	if err != nil {
		return false, err
	}
	mine, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	return windows.EqualSid(theirs.User.Sid, mine.User.Sid), nil
}

// describe reads the image path. The Authenticode publisher arrives with
// the Windows work; until then identity is path and hash.
func describe(p *Process) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		return fmt.Errorf("svpeer: process %d: %w", p.PID, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return fmt.Errorf("svpeer: process %d: %w", p.PID, err)
	}
	p.Exe = windows.UTF16ToString(buf[:n])
	return nil
}
