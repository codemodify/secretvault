//go:build windows

package svcrypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func allocProtected(n int) (region []byte, locked, ok bool) {
	if n <= 0 {
		return nil, false, false
	}
	addr, err := windows.VirtualAlloc(0, uintptr(n), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, false, false
	}
	// The memory is outside the Go heap, so a pointer made from its address
	// is valid for as long as the mapping is.
	region = unsafe.Slice((*byte)(unsafe.Add(nil, addr)), n)
	return region, windows.VirtualLock(addr, uintptr(n)) == nil, true
}

func freeProtected(region []byte, locked bool) {
	addr := uintptr(unsafe.Pointer(unsafe.SliceData(region)))
	if locked {
		_ = windows.VirtualUnlock(addr, uintptr(len(region)))
	}
	_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// Windows writes no core dumps by default; Windows Error Reporting's local
// dumps are opt-in machine policy, outside a process's control.
func hardenProcess() error { return nil }

func noCoreDumps() error { return nil }
