//go:build !(linux || freebsd || netbsd || openbsd || windows)

package svclip

import "time"

// macOS needs AppKit's pasteboard, reachable only through cgo; it arrives
// with the macOS build.
func copyText([]byte, time.Duration, func(string)) (bool, error) { return false, ErrUnavailable }

func pasteText() ([]byte, error) { return nil, ErrUnavailable }
