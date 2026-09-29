//go:build !windows

package svpeer

import (
	"os"
	"syscall"
)

// systemOwned reports whether a file belongs to the administrator: owned
// by root and writable by nobody else.
func systemOwned(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0 && st.Mode().Perm()&0o022 == 0
}
