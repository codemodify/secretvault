//go:build darwin || freebsd || netbsd || openbsd

package svcrypto

import "golang.org/x/sys/unix"

func excludeFromDumps([]byte) {}

func hardenProcess() error { return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) }
