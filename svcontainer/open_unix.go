//go:build unix

package svcontainer

import "syscall"

// nonBlocking keeps opening a FIFO from blocking (see openImage).
const nonBlocking = syscall.O_NONBLOCK
