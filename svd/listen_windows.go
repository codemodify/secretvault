//go:build windows

package svd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ListenHost is for host mode, which runs on Linux only.
func (d *Daemon) ListenHost() (*HostListeners, error) {
	return nil, errors.New("svd: host mode runs on Linux only")
}

// On Windows secretvaultd listens on an AF_UNIX socket (Windows 10 1803
// and later) inside %LOCALAPPDATA%, which only the user can reach. A
// lock file held with LockFileEx keeps a second daemon away, and every
// peer's token is compared with ours (svpeer).

// Listen opens secretvaultd's socket at path.
func Listen(path string) (net.Listener, func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%w on %s", ErrRunning, path)
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	cleanup := func() {
		ln.Close()
		os.Remove(path)
		windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		f.Close()
	}
	return ln, cleanup, nil
}
