//go:build windows

package svpeer

import "os"

// systemOwned is false on Windows until Authenticode publishers are read:
// every program is known by path and hash.
func systemOwned(os.FileInfo) bool { return false }
