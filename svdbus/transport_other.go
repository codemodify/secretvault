//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package svdbus

import (
	"context"
	"fmt"
	"runtime"
)

// Without unix sockets there is no transport: the wire format, the Go
// mapping and message encoding still work, and connecting fails.

func dialTransport(ctx context.Context, a Address) (transport, error) {
	return nil, fmt.Errorf("%w: D-Bus transports on %s", ErrUnsupported, runtime.GOOS)
}

func authIdentity() string { return "" }

func closeFD(fd UnixFD) {}

func dupFD(fd UnixFD) (UnixFD, error) {
	return -1, fmt.Errorf("%w: file descriptors on %s", ErrUnsupported, runtime.GOOS)
}
