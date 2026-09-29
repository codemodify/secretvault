//go:build linux

package svcrypto

import "golang.org/x/sys/unix"

func excludeFromDumps(region []byte) { _ = unix.Madvise(region, unix.MADV_DONTDUMP) }

func hardenProcess() error {
	if err := noCoreDumps(); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func noCoreDumps() error { return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) }
