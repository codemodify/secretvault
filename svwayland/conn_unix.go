//go:build linux || freebsd || netbsd || openbsd

package svwayland

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// handler receives the events of one object.
type handler func(opcode uint16, d *decoder) error

// Conn is a connection to a Wayland compositor. It is used from one
// goroutine at a time.
type Conn struct {
	uc       *net.UnixConn
	registry uint32
	nextID   uint32
	handlers map[uint32]handler
	in       []byte
	fds      []int
	globals  []Global
	err      error
}

// Global is an interface the compositor offers.
type Global struct {
	Name      uint32
	Interface string
	Version   uint32
}

// ErrNoDisplay is a session without Wayland.
var ErrNoDisplay = errors.New("svwayland: no Wayland display (WAYLAND_DISPLAY is not set)")

// Connect connects to the compositor named by the environment
// (WAYLAND_SOCKET, else WAYLAND_DISPLAY under XDG_RUNTIME_DIR) and reads
// its globals.
func Connect() (*Conn, error) {
	if s := os.Getenv("WAYLAND_SOCKET"); s != "" {
		fd, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("svwayland: WAYLAND_SOCKET=%q", s)
		}
		os.Unsetenv("WAYLAND_SOCKET")
		fc, err := net.FileConn(os.NewFile(uintptr(fd), "wayland"))
		if err != nil {
			return nil, err
		}
		return newConn(fc.(*net.UnixConn))
	}
	name := os.Getenv("WAYLAND_DISPLAY")
	if name == "" {
		return nil, ErrNoDisplay
	}
	path := name
	if !filepath.IsAbs(name) {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			return nil, errors.New("svwayland: XDG_RUNTIME_DIR is not set")
		}
		path = filepath.Join(dir, name)
	}
	return Dial(path)
}

// Dial connects to the compositor socket at path.
func Dial(path string) (*Conn, error) {
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	return newConn(uc)
}

func newConn(uc *net.UnixConn) (*Conn, error) {
	c := &Conn{uc: uc, nextID: 2, handlers: map[uint32]handler{}}
	c.handlers[1] = c.displayEvent
	// wl_display.get_registry(new_id)
	reg := c.newID(func(op uint16, d *decoder) error {
		switch op {
		case 0: // global(name, interface, version)
			g := Global{Name: d.uint(), Interface: d.string(), Version: d.uint()}
			if d.err == nil {
				c.globals = append(c.globals, g)
			}
		case 1: // global_remove(name)
			name := d.uint()
			for i, g := range c.globals {
				if g.Name == name {
					c.globals = append(c.globals[:i], c.globals[i+1:]...)
					break
				}
			}
		}
		return d.err
	})
	var e encoder
	e.object(reg)
	if err := c.send(1, 1, &e); err != nil {
		uc.Close()
		return nil, err
	}
	c.registry = reg
	if err := c.Roundtrip(); err != nil {
		uc.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	for _, fd := range c.fds {
		syscall.Close(fd)
	}
	c.fds = nil
	return c.uc.Close()
}

// Globals is what the compositor offers.
func (c *Conn) Globals() []Global { return c.globals }

// Find returns the global with the given interface.
func (c *Conn) Find(iface string) (Global, bool) {
	for _, g := range c.globals {
		if g.Interface == iface {
			return g, true
		}
	}
	return Global{}, false
}

// displayEvent handles wl_display's events: error and delete_id.
func (c *Conn) displayEvent(op uint16, d *decoder) error {
	switch op {
	case 0: // error(object_id, code, message)
		obj, code, msg := d.uint(), d.uint(), d.string()
		return fmt.Errorf("svwayland: compositor error on object %d (code %d): %s", obj, code, msg)
	case 1: // delete_id(id)
		delete(c.handlers, d.uint())
	}
	return d.err
}

func (c *Conn) newID(h handler) uint32 {
	id := c.nextID
	c.nextID++
	c.handlers[id] = h
	return id
}

func (c *Conn) send(object uint32, opcode uint16, e *encoder) error {
	msg, err := e.message(object, opcode)
	if err != nil {
		return err
	}
	var oob []byte
	if len(e.fds) > 0 {
		oob = syscall.UnixRights(e.fds...)
	}
	_, _, err = c.uc.WriteMsgUnix(msg, oob, nil)
	return err
}

// Bind binds a global and returns the new object's ID. h receives its
// events.
func (c *Conn) Bind(g Global, version uint32, h handler) (uint32, error) {
	if version > g.Version {
		version = g.Version
	}
	id := c.newID(h)
	var e encoder
	e.uint(g.Name)
	e.string(g.Interface)
	e.uint(version)
	e.object(id)
	return id, c.send(c.registry, 0, &e)
}

// Roundtrip waits until the compositor has handled everything sent so far.
func (c *Conn) Roundtrip() error {
	done := false
	cb := c.newID(func(op uint16, d *decoder) error {
		d.uint()
		done = true
		return d.err
	})
	var e encoder
	e.object(cb)
	if err := c.send(1, 0, &e); err != nil { // wl_display.sync
		return err
	}
	for !done {
		if err := c.Dispatch(time.Time{}); err != nil {
			return err
		}
	}
	return nil
}

// errTimeout is Dispatch reaching its deadline.
var errTimeout = errors.New("svwayland: deadline reached")

// Dispatch reads at least one message (or until deadline, if not zero)
// and delivers every complete message to its object.
func (c *Conn) Dispatch(deadline time.Time) error {
	if c.err != nil {
		return c.err
	}
	c.uc.SetReadDeadline(deadline)
	buf := make([]byte, maxMessage)
	oob := make([]byte, syscall.CmsgSpace(28*4))
	n, oobn, _, _, err := c.uc.ReadMsgUnix(buf, oob)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errTimeout
		}
		c.err = err
		return err
	}
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err == nil {
			for _, m := range msgs {
				if fds, err := syscall.ParseUnixRights(&m); err == nil {
					c.fds = append(c.fds, fds...)
				}
			}
		}
	}
	c.in = append(c.in, buf[:n]...)
	for len(c.in) >= headerSize {
		obj := binary.LittleEndian.Uint32(c.in)
		word := binary.LittleEndian.Uint32(c.in[4:])
		size, op := int(word>>16), uint16(word)
		if size < headerSize || size%4 != 0 {
			c.err = ErrProtocol
			return c.err
		}
		if len(c.in) < size {
			break
		}
		d := &decoder{b: c.in[headerSize:size], fds: &c.fds}
		if h := c.handlers[obj]; h != nil {
			if err := h(op, d); err != nil {
				c.err = err
				return err
			}
		}
		c.in = c.in[size:]
	}
	return nil
}
