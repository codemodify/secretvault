// Package svwayland is a minimal Wayland client: the wire protocol, a
// registry, and just enough of the data-control protocols
// (ext_data_control_v1, and its wlroots predecessor
// zwlr_data_control_unstable_v1) for secretvault to own the clipboard
// without a window. That is how a command in a terminal copies a password
// and takes it back after a timeout.
//
// It is written from the Wayland protocol specification, uses no C
// library, and handles only what it needs. Anything unexpected from the
// compositor ends the connection rather than being guessed at.
package svwayland

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The wire format (https://wayland.freedesktop.org/docs/html/ch04.html):
// every message is an 8-byte header, object ID then (size << 16 | opcode),
// followed by arguments, each padded to 32 bits. Strings and arrays carry
// a 32-bit length first; strings include their terminating NUL. File
// descriptors travel out of band (SCM_RIGHTS).

const headerSize = 8

// maxMessage is the largest message the protocol allows (the size field is
// 16 bits).
const maxMessage = 4096

// ErrProtocol is a message that does not follow the protocol.
var ErrProtocol = errors.New("svwayland: protocol error")

// encoder builds one message's arguments.
type encoder struct {
	b   []byte
	fds []int
}

func (e *encoder) uint(v uint32)    { e.b = binary.LittleEndian.AppendUint32(e.b, v) }
func (e *encoder) int(v int32)      { e.uint(uint32(v)) }
func (e *encoder) object(id uint32) { e.uint(id) }

func (e *encoder) string(s string) {
	e.uint(uint32(len(s) + 1))
	e.b = append(e.b, s...)
	e.b = append(e.b, 0)
	e.pad()
}

func (e *encoder) array(a []byte) {
	e.uint(uint32(len(a)))
	e.b = append(e.b, a...)
	e.pad()
}

func (e *encoder) fd(fd int) { e.fds = append(e.fds, fd) }

func (e *encoder) pad() {
	for len(e.b)%4 != 0 {
		e.b = append(e.b, 0)
	}
}

// message frames the arguments for object and opcode.
func (e *encoder) message(object uint32, opcode uint16) ([]byte, error) {
	size := headerSize + len(e.b)
	if size > maxMessage {
		return nil, fmt.Errorf("svwayland: message of %d bytes", size)
	}
	out := binary.LittleEndian.AppendUint32(make([]byte, 0, size), object)
	out = binary.LittleEndian.AppendUint32(out, uint32(size)<<16|uint32(opcode))
	return append(out, e.b...), nil
}

// decoder reads one message's arguments.
type decoder struct {
	b   []byte
	fds *[]int // the connection's queue of received descriptors
	err error
}

func (d *decoder) fail() {
	if d.err == nil {
		d.err = ErrProtocol
	}
}

func (d *decoder) uint() uint32 {
	if len(d.b) < 4 {
		d.fail()
		return 0
	}
	v := binary.LittleEndian.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *decoder) int() int32 { return int32(d.uint()) }

func (d *decoder) string() string {
	n := d.uint()
	if d.err != nil || n == 0 {
		return ""
	}
	padded := (int(n) + 3) &^ 3
	if n > math.MaxInt32 || padded > len(d.b) || d.b[n-1] != 0 {
		d.fail()
		return ""
	}
	s := string(d.b[:n-1])
	d.b = d.b[padded:]
	return s
}

func (d *decoder) array() []byte {
	n := d.uint()
	padded := (int(n) + 3) &^ 3
	if d.err != nil || n > math.MaxInt32 || padded > len(d.b) {
		d.fail()
		return nil
	}
	a := append([]byte(nil), d.b[:n]...)
	d.b = d.b[padded:]
	return a
}

// fd takes the next received descriptor. The caller owns (and closes) it.
func (d *decoder) fd() int {
	if len(*d.fds) == 0 {
		d.fail()
		return -1
	}
	fd := (*d.fds)[0]
	*d.fds = (*d.fds)[1:]
	return fd
}
