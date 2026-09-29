//go:build !windows

package svd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/codemodify/secretvault/svrpc"
)

// The socket is the daemon's only door, so it is guarded like one:
//
//   - its directory is created 0700 and must be owned by us;
//   - a lock file beside it keeps a second daemon from taking over the
//     path of a running one;
//   - it is bound under umask 0177 and chmodded 0600, so there is no
//     moment at which another user could connect;
//   - every connection's peer is checked by the kernel to be us (svpeer).

type socketLock struct{ f *os.File }

func (l *socketLock) release() {
	if l == nil || l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
	l.f = nil
}

func lockSocket(socket string) (*socketLock, error) {
	f, err := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w on %s", ErrRunning, socket)
	}
	if err := f.Truncate(0); err == nil {
		fmt.Fprintf(f, "%d\n", os.Getpid())
	}
	return &socketLock{f: f}, nil
}

func prepareDir(socket string, mode os.FileMode) error {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("svd: %s is not a directory", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("svd: socket directory %s belongs to uid %d, not us", dir, sys.Uid)
	}
	if st.Mode().Perm() != mode {
		return os.Chmod(dir, mode)
	}
	return nil
}

// maxSocketPath is the longest socket path the kernel accepts (sun_path is
// 108 bytes on Linux, 104 on the BSDs and macOS, including the final NUL).
const maxSocketPath = 103

// Listen opens secretvaultd's socket at path.
func Listen(path string) (net.Listener, func(), error) {
	return listen(path, 0o600, 0o700, svrpc.EnvSocket)
}

// listen opens a socket of the given mode, in a directory of dirMode
// (both exactly); env names what moves it, for when the path is too
// long.
func listen(path string, mode, dirMode os.FileMode, env string) (net.Listener, func(), error) {
	if len(path) > maxSocketPath {
		return nil, nil, fmt.Errorf("svd: the socket path %s is %d bytes long; sockets allow at most %d (set %s to a shorter path)",
			path, len(path), maxSocketPath, env)
	}
	if err := prepareDir(path, dirMode); err != nil {
		return nil, nil, err
	}
	lock, err := lockSocket(path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.RemoveAll(path); err != nil { // the lock is ours: whatever is there is stale
		lock.release()
		return nil, nil, err
	}
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		lock.release()
		return nil, nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		lock.release()
		return nil, nil, err
	}
	cleanup := func() {
		ln.Close()
		os.Remove(path)
		lock.release()
	}
	return ln, cleanup, nil
}

// ListenHost opens the host daemon's sockets in its runtime directory,
// which is 0755 so local services can reach theirs: admin.sock and
// credentials.sock 0600 (root, and systemd), secretvaultd.sock 0666 (any
// local service; the policy decides what it gets). A socket systemd
// passed (socket activation, sd_listen_fds(3)) is taken in place of
// making it: secretvaultd-host.socket holds credentials.sock from early
// boot, so units that start before the daemon wait for it instead of
// failing.
func (d *Daemon) ListenHost() (*HostListeners, error) {
	if d.host == nil {
		return nil, errors.New("svd: ListenHost is for host mode")
	}
	dir := d.host.opts.Runtime
	passed := systemdListeners(d.opts.Log)
	l := &HostListeners{}
	open := func(name string, mode os.FileMode) (net.Listener, error) {
		p := filepath.Join(dir, name)
		if ln, ok := passed[p]; ok {
			delete(passed, p)
			l.closers = append(l.closers, func() { ln.Close() })
			return ln, nil
		}
		ln, cleanup, err := listen(p, mode, 0o755, svrpc.EnvHostRuntime)
		if err != nil {
			return nil, err
		}
		l.closers = append(l.closers, cleanup)
		return ln, nil
	}
	var err error
	// The admin socket first: its lock keeps a second host daemon away.
	if l.Admin, err = open(svrpc.HostAdminSocketName, 0o600); err == nil {
		if l.Credentials, err = open(svrpc.HostCredentialSocketName, 0o600); err == nil {
			l.Services, err = open(svrpc.HostServiceSocketName, 0o666)
		}
	}
	for p, ln := range passed {
		d.opts.Log("systemd passed a socket that is not one of ours: " + p)
		ln.Close()
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// systemdListeners takes the sockets systemd passed (LISTEN_PID is us,
// and LISTEN_FDS of them start at fd 3), by the path each is bound to.
func systemdListeners(logf func(string)) map[string]net.Listener {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil
	}
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	var fds []int
	for fd := 3; fd < 3+n; fd++ {
		fds = append(fds, fd)
	}
	return listenersFromFDs(fds, logf)
}

// listenersFromFDs makes listeners of Unix sockets' file descriptors, by
// the path each is bound to. Closing one never removes its path: the
// socket belongs to whoever made it.
func listenersFromFDs(fds []int, logf func(string)) map[string]net.Listener {
	out := map[string]net.Listener{}
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
		f := os.NewFile(uintptr(fd), "socket from systemd")
		ln, err := net.FileListener(f) // a copy of the descriptor
		f.Close()
		if err != nil {
			logf(fmt.Sprintf("a socket systemd passed (fd %d): %v", fd, err))
			continue
		}
		ua, ok := ln.Addr().(*net.UnixAddr)
		if !ok || ua.Name == "" {
			logf(fmt.Sprintf("a socket systemd passed (fd %d) is not a Unix socket with a path", fd))
			ln.Close()
			continue
		}
		out[ua.Name] = ln
	}
	return out
}
