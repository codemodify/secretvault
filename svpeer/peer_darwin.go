//go:build darwin

package svpeer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerCred(c net.Conn) (pid, uid int, err error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, 0, errors.New("svpeer: not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Xucred
	var credErr, pidErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	if pidErr != nil {
		return 0, 0, pidErr
	}
	return pid, int(cred.Uid), nil
}

// describe reads the executable path from kern.procargs2, whose layout is
// argc (4 bytes) followed by the NUL-terminated exec path. Code-signing
// identity needs the Security framework (cgo) and arrives with M1's
// macOS work; until then identity is path and hash.
func describe(p *Process) error {
	b, err := unix.SysctlRaw("kern.procargs2", p.PID)
	if err != nil || len(b) < 5 {
		return fmt.Errorf("svpeer: process %d: %v", p.PID, err)
	}
	argc := binary.LittleEndian.Uint32(b)
	rest := b[4:]
	i := bytes.IndexByte(rest, 0)
	if i <= 0 {
		return fmt.Errorf("svpeer: process %d: no exec path", p.PID)
	}
	p.Exe = string(rest[:i])
	if st, err := os.Stat(p.Exe); err == nil {
		p.SystemOwned = systemOwned(st)
	}
	if isInterpreter(p.Exe) && argc > 1 {
		args := bytes.Split(bytes.TrimLeft(rest[i:], "\x00"), []byte{0})
		var s []string
		for _, a := range args[:min(len(args), int(argc))] {
			s = append(s, string(a))
		}
		p.Script = scriptArg(s)
	}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", p.PID); err == nil && kp.Eproc.Tdev != -1 {
		p.TTY = fmt.Sprintf("ttys%03d", kp.Eproc.Tdev&0xffffff)
		p.Terminal = fmt.Sprintf("tty=%d;pgid=%d;start=%d", kp.Eproc.Tdev, kp.Eproc.Pgid, kp.Proc.P_starttime.Sec)
	}
	return nil
}
