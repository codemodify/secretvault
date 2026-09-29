//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package svdbus

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// unixTransport is a connected unix stream socket.
type unixTransport struct {
	c   *net.UnixConn
	oob []byte
}

func dialTransport(ctx context.Context, a Address) (transport, error) {
	path, err := a.unixSocket()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return &unixTransport{
		c:   c.(*net.UnixConn),
		oob: make([]byte, unix.CmsgSpace(4*MaxUnixFDs)),
	}, nil
}

// authIdentity is who we claim to be with EXTERNAL: the decimal uid the
// server also reads from the socket.
func authIdentity() string { return strconv.Itoa(os.Getuid()) }

func (t *unixTransport) canPassFDs() bool { return true }

func (t *unixTransport) read(b []byte) (int, []UnixFD, error) {
	// Go asks for MSG_CMSG_CLOEXEC (or sets FD_CLOEXEC) on descriptors
	// received this way, so none leaks into a child process.
	n, oobn, flags, _, err := t.c.ReadMsgUnix(b, t.oob)
	var fds []UnixFD
	if oobn > 0 {
		msgs, perr := unix.ParseSocketControlMessage(t.oob[:oobn])
		if perr == nil {
			for i := range msgs {
				if msgs[i].Header.Level != unix.SOL_SOCKET || msgs[i].Header.Type != unix.SCM_RIGHTS {
					continue
				}
				rights, rerr := unix.ParseUnixRights(&msgs[i])
				if rerr != nil {
					perr = rerr
					continue
				}
				for _, fd := range rights {
					fds = append(fds, UnixFD(fd))
				}
			}
		}
		if perr != nil && err == nil {
			err = perr
		}
	}
	if flags&unix.MSG_CTRUNC != 0 && err == nil {
		err = errors.New("svdbus: descriptors were lost in transit (control data truncated)")
	}
	if err != nil {
		for _, fd := range fds {
			closeFD(fd)
		}
		return n, nil, err
	}
	if n == 0 && oobn == 0 {
		return 0, nil, io.EOF
	}
	return n, fds, nil
}

func (t *unixTransport) write(b []byte, fds []UnixFD) error {
	var oob []byte
	if len(fds) > 0 {
		raw := make([]int, len(fds))
		for i, fd := range fds {
			raw[i] = int(fd)
		}
		oob = unix.UnixRights(raw...)
	}
	for len(b) > 0 {
		n, _, err := t.c.WriteMsgUnix(b, oob, nil)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b, oob = b[n:], nil
	}
	return nil
}

func (t *unixTransport) setDeadline(d time.Time) error { return t.c.SetDeadline(d) }

func (t *unixTransport) close() error { return t.c.Close() }

func closeFD(fd UnixFD) {
	if fd >= 0 {
		_ = unix.Close(int(fd))
	}
}

// dupFD duplicates a descriptor, close-on-exec.
func dupFD(fd UnixFD) (UnixFD, error) {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	return UnixFD(n), err
}
