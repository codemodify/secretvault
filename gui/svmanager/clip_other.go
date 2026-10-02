//go:build !(linux || freebsd || netbsd || openbsd)

package svmanager

// systemClipboard is where the manager's copies go: uitoolkit's secret
// clipboard. On Windows a helper ended would leave its copy behind, so a
// copy could not be taken back at a lock; macOS has no svclip yet.
func systemClipboard() Clipboard { return desktopClipboard{} }
