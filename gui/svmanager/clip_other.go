//go:build !(freebsd || netbsd || openbsd)

package svmanager

// systemClipboard is where the manager's copies go: uitoolkit's secret
// clipboard (clip.go says why not the CLI's here).
func systemClipboard() Clipboard { return desktopClipboard{} }
