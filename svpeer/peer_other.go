//go:build !(linux || darwin || windows)

package svpeer

import "net"

func peerCred(net.Conn) (int, int, error) { return 0, 0, ErrUnsupported }

func describe(*Process) error { return ErrUnsupported }

func parentPID(int) (int, error) { return 0, ErrUnsupported }
