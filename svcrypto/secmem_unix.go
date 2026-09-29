//go:build linux || darwin || freebsd || netbsd || openbsd

package svcrypto

import (
	"os"

	"golang.org/x/sys/unix"
)

func allocProtected(n int) (region []byte, locked, ok bool) {
	if n <= 0 {
		return nil, false, false
	}
	page := os.Getpagesize()
	size := (n + page - 1) / page * page
	region, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, false, false
	}
	excludeFromDumps(region)
	return region, unix.Mlock(region) == nil, true
}

func freeProtected(region []byte, locked bool) {
	if locked {
		_ = unix.Munlock(region)
	}
	_ = unix.Munmap(region)
}
