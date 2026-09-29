//go:build windows

package svclip

import (
	"errors"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                   = windows.NewLazySystemDLL("user32.dll")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard        = user32.NewProc("OpenClipboard")
	procCloseClipboard       = user32.NewProc("CloseClipboard")
	procEmptyClipboard       = user32.NewProc("EmptyClipboard")
	procSetClipboardData     = user32.NewProc("SetClipboardData")
	procGetClipboardData     = user32.NewProc("GetClipboardData")
	procRegisterFormat       = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequence = user32.NewProc("GetClipboardSequenceNumber")
	procGlobalAlloc          = kernel32.NewProc("GlobalAlloc")
	procGlobalLock           = kernel32.NewProc("GlobalLock")
	procGlobalUnlock         = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func open() error {
	for range 20 {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return nil
		}
		time.Sleep(25 * time.Millisecond) // another program has it open
	}
	return errors.New("svclip: the clipboard is busy")
}

// put copies b into a movable global block and hands it to the clipboard.
func put(format uintptr, b []byte) error {
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(b)))
	if h == 0 {
		return err
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return err
	}
	copy(unsafe.Slice((*byte)(unsafe.Add(nil, p)), len(b)), b) // OS memory, not Go heap
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(format, h); r == 0 {
		return err
	}
	return nil
}

func register(name string) uintptr {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := procRegisterFormat.Call(uintptr(unsafe.Pointer(p)))
	return r
}

// copyText sets CF_UNICODETEXT, plus the formats that keep clipboard
// history, cloud clipboard and monitoring tools from keeping it.
func copyText(secret []byte, ttl time.Duration, ready func(string)) (bool, error) {
	u := utf16.Encode([]rune(string(secret)))
	u = append(u, 0)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
	defer clear(buf)
	if err := open(); err != nil {
		return false, err
	}
	procEmptyClipboard.Call()
	err := put(cfUnicodeText, buf)
	zero := []byte{0, 0, 0, 0}
	if f := register("ExcludeClipboardContentFromMonitorProcessing"); f != 0 {
		put(f, zero)
	}
	if f := register("CanIncludeInClipboardHistory"); f != 0 {
		put(f, zero)
	}
	if f := register("CanUploadToCloudClipboard"); f != 0 {
		put(f, zero)
	}
	procCloseClipboard.Call()
	if err != nil {
		return false, err
	}
	seq, _, _ := procGetClipboardSequence.Call()
	ready("windows")
	time.Sleep(ttl)
	if now, _, _ := procGetClipboardSequence.Call(); now != seq {
		return false, nil // something else was copied since
	}
	if err := open(); err != nil {
		return false, err
	}
	procEmptyClipboard.Call()
	procCloseClipboard.Call()
	return true, nil
}

func pasteText() ([]byte, error) {
	if err := open(); err != nil {
		return nil, err
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return nil, nil
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return nil, err
	}
	defer procGlobalUnlock.Call(h)
	base := unsafe.Add(nil, p) // OS memory, not Go heap
	var n int
	for *(*uint16)(unsafe.Add(base, n*2)) != 0 {
		n++
	}
	return []byte(string(utf16.Decode(unsafe.Slice((*uint16)(base), n)))), nil
}
