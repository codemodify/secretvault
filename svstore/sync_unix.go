//go:build !windows

package svstore

import "os"

// syncDir makes a new directory entry durable. Best effort: some
// filesystems refuse to sync a directory, and the data is already synced.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}
