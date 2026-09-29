//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package svcrypto

func allocProtected(int) ([]byte, bool, bool) { return nil, false, false }

func freeProtected([]byte, bool) {}

func hardenProcess() error { return nil }
