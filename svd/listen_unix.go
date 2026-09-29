//go:build !windows

package svd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
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

func prepareDir(socket string) error {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	if st.Mode().Perm()&0o077 != 0 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// maxSocketPath is the longest socket path the kernel accepts (sun_path is
// 108 bytes on Linux, 104 on the BSDs and macOS, including the final NUL).
const maxSocketPath = 103

// Listen opens secretvaultd's socket at path.
func Listen(path string) (net.Listener, func(), error) {
	if len(path) > maxSocketPath {
		return nil, nil, fmt.Errorf("svd: the socket path %s is %d bytes long; sockets allow at most %d (set %s to a shorter path)",
			path, len(path), maxSocketPath, "SECRETVAULT_SOCK")
	}
	if err := prepareDir(path); err != nil {
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
	if err := os.Chmod(path, 0o600); err != nil {
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
