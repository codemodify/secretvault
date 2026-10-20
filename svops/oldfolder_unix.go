//go:build !windows

package svops

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes the lock file at path, as secretvaultd takes it beside its
// socket, without waiting: ok is false when another process holds it.
func tryLock(path string) (unlock func(), ok bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, true, nil
}

// crossDevice reports whether a rename failed only because its two paths
// are on different filesystems.
func crossDevice(err error) bool { return errors.Is(err, syscall.EXDEV) }
