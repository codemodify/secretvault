//go:build windows

package svstore

// syncDir is a no-op: NTFS journals directory entries itself, and Windows
// cannot open a directory for flushing through os.Open.
func syncDir(string) {}
