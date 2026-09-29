//go:build !linux

package svd

import (
	"errors"
	"net"
	"os"
)

// Host mode runs on Linux only (New refuses it elsewhere); these keep
// the rest of it compiling.

func peerAddress(net.Conn) (string, error) {
	return "", errors.New("host mode runs on Linux only")
}

func fileOwner(os.FileInfo) (int, bool) { return 0, false }
