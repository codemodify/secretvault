// Package svx11 is a minimal X11 client: connection setup with
// MIT-MAGIC-COOKIE-1 authorisation, a handful of core requests, and the
// selection protocol (ICCCM section 2) for owning and reading the
// CLIPBOARD. secretvault uses it to copy a secret where the Wayland
// data-control protocol is not offered (GNOME, and plain X11 sessions);
// under XWayland the desktop bridges it to Wayland applications.
//
// It is written from the X Window System Protocol specification and uses
// no C library. Replies and events are read strictly: anything malformed
// ends the connection.
package svx11

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Request opcodes (X11 core protocol).
const (
	opCreateWindow      = 1
	opDestroyWindow     = 4
	opInternAtom        = 16
	opChangeProperty    = 18
	opGetProperty       = 20
	opSetSelectionOwner = 22
	opGetSelectionOwner = 23
	opConvertSelection  = 24
	opSendEvent         = 25
	opGetInputFocus     = 43
)

// Event codes.
const (
	evPropertyNotify   = 28
	evSelectionClear   = 29
	evSelectionRequest = 30
	evSelectionNotify  = 31
)

// ErrProtocol is a reply or event that does not follow the protocol.
var ErrProtocol = errors.New("svx11: protocol error")

// Conn is a connection to an X server, used from one goroutine at a time.
type Conn struct {
	nc      net.Conn
	r       *bufio.Reader
	seq     uint16
	idBase  uint32
	idMask  uint32
	nextID  uint32
	Root    uint32
	events  [][]byte // events read while waiting for a reply
	maxReq  int      // largest request, in bytes
	atomsOf map[string]uint32
}

// Connect connects to the display named by $DISPLAY.
func Connect() (*Conn, error) {
	d, err := ParseDisplay("")
	if err != nil {
		return nil, err
	}
	nc, err := d.dial()
	if err != nil {
		return nil, err
	}
	name, data := findCookie(d)
	c, err := setup(nc, name, data)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

// setup performs the connection handshake on nc.
func setup(nc net.Conn, authName string, authData []byte) (*Conn, error) {
	pad := func(n int) int { return (4 - n%4) % 4 }
	req := []byte{'l', 0}
	req = binary.LittleEndian.AppendUint16(req, 11) // protocol major
	req = binary.LittleEndian.AppendUint16(req, 0)  // minor
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authName)))
	req = binary.LittleEndian.AppendUint16(req, uint16(len(authData)))
	req = append(req, 0, 0)
	req = append(req, authName...)
	req = append(req, make([]byte, pad(len(authName)))...)
	req = append(req, authData...)
	req = append(req, make([]byte, pad(len(authData)))...)
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	defer nc.SetDeadline(time.Time{})
	if _, err := nc.Write(req); err != nil {
		return nil, err
	}
	r := bufio.NewReader(nc)
	head := make([]byte, 8)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	extra := int(binary.LittleEndian.Uint16(head[6:])) * 4
	if extra > 1<<20 {
		return nil, ErrProtocol
	}
	body := make([]byte, extra)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	switch head[0] {
	case 0:
		n := int(head[1])
		if n > len(body) {
			n = len(body)
		}
		return nil, fmt.Errorf("svx11: the X server refused the connection: %s", body[:n])
	case 2:
		return nil, errors.New("svx11: the X server wants further authentication")
	case 1:
	default:
		return nil, ErrProtocol
	}
	// body starts at byte 8 of the reply.
	if len(body) < 32 {
		return nil, ErrProtocol
	}
	c := &Conn{nc: nc, r: r, atomsOf: map[string]uint32{}}
	c.idBase = binary.LittleEndian.Uint32(body[4:])
	c.idMask = binary.LittleEndian.Uint32(body[8:])
	vendorLen := int(binary.LittleEndian.Uint16(body[16:]))
	c.maxReq = int(binary.LittleEndian.Uint16(body[18:])) * 4
	screens := int(body[20])
	formats := int(body[21])
	off := 32 + vendorLen + pad(vendorLen) + 8*formats
	if screens < 1 || off+4 > len(body) || c.idMask == 0 {
		return nil, ErrProtocol
	}
	c.Root = binary.LittleEndian.Uint32(body[off:])
	return c, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.nc.Close() }

// NewID allocates a resource ID.
func (c *Conn) NewID() (uint32, error) {
	c.nextID++
	if c.nextID > c.idMask {
		return 0, errors.New("svx11: out of resource IDs")
	}
	return c.idBase | (c.nextID & c.idMask), nil
}

// send writes one request: opcode, data byte, and the body (padded to 4).
func (c *Conn) send(op, data byte, body []byte) error {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	size := 4 + len(body)
	if c.maxReq > 0 && size > c.maxReq {
		return fmt.Errorf("svx11: request of %d bytes exceeds the server's limit", size)
	}
	req := []byte{op, data}
	req = binary.LittleEndian.AppendUint16(req, uint16(size/4))
	req = append(req, body...)
	c.seq++
	_, err := c.nc.Write(req)
	return err
}

// readUnit reads one reply, event or error: 32 bytes, plus the reply's
// extra data.
func (c *Conn) readUnit(deadline time.Time) ([]byte, error) {
	c.nc.SetReadDeadline(deadline)
	b := make([]byte, 32)
	if _, err := io.ReadFull(c.r, b); err != nil {
		return nil, err
	}
	if b[0] == 1 { // a reply: more data may follow
		extra := int(binary.LittleEndian.Uint32(b[4:])) * 4
		if extra > 16<<20 {
			return nil, ErrProtocol
		}
		if extra > 0 {
			more := make([]byte, extra)
			if _, err := io.ReadFull(c.r, more); err != nil {
				return nil, err
			}
			b = append(b, more...)
		}
	}
	return b, nil
}

// XError is an error the server reported.
type XError struct {
	Code  byte
	Major byte
}

func (e *XError) Error() string {
	return fmt.Sprintf("svx11: X error %d on request %d", e.Code, e.Major)
}

// reply waits for the reply to the last request, keeping events that
// arrive meanwhile for later.
func (c *Conn) reply() ([]byte, error) {
	for {
		b, err := c.readUnit(time.Now().Add(10 * time.Second))
		if err != nil {
			return nil, err
		}
		seq := binary.LittleEndian.Uint16(b[2:])
		switch b[0] {
		case 0:
			if seq == c.seq {
				return nil, &XError{Code: b[1], Major: b[10]}
			}
		case 1:
			if seq == c.seq {
				return b, nil
			}
		default:
			c.events = append(c.events, b)
		}
	}
}

// Sync waits until the server has handled every request sent so far, and
// reports an error any of them caused.
func (c *Conn) Sync() error {
	if err := c.send(opGetInputFocus, 0, nil); err != nil {
		return err
	}
	_, err := c.reply()
	return err
}

// NextEvent returns the next event (codes without the send-event bit), or
// an error when deadline passes (os.ErrDeadlineExceeded).
func (c *Conn) NextEvent(deadline time.Time) ([]byte, error) {
	for {
		if len(c.events) > 0 {
			ev := c.events[0]
			c.events = c.events[1:]
			return ev, nil
		}
		b, err := c.readUnit(deadline)
		if err != nil {
			return nil, err
		}
		if b[0] == 0 {
			return nil, &XError{Code: b[1], Major: b[10]}
		}
		if b[0] != 1 {
			return b, nil
		}
	}
}

// Atom interns a name.
func (c *Conn) Atom(name string) (uint32, error) {
	if a, ok := c.atomsOf[name]; ok {
		return a, nil
	}
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(name)))
	body = append(body, 0, 0)
	body = append(body, name...)
	if err := c.send(opInternAtom, 0, body); err != nil {
		return 0, err
	}
	b, err := c.reply()
	if err != nil {
		return 0, err
	}
	a := binary.LittleEndian.Uint32(b[8:])
	if a == 0 {
		return 0, fmt.Errorf("svx11: no atom for %q", name)
	}
	c.atomsOf[name] = a
	return a, nil
}

// CreateInputWindow makes an unmapped InputOnly window with the given
// event mask: the owner of a selection needs a window, not a visible one.
func (c *Conn) CreateInputWindow(eventMask uint32) (uint32, error) {
	id, err := c.NewID()
	if err != nil {
		return 0, err
	}
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, id)
	body = binary.LittleEndian.AppendUint32(body, c.Root)
	body = append(body, 0, 0, 0, 0)                  // x, y
	body = binary.LittleEndian.AppendUint16(body, 1) // width
	body = binary.LittleEndian.AppendUint16(body, 1) // height
	body = binary.LittleEndian.AppendUint16(body, 0) // border width
	body = binary.LittleEndian.AppendUint16(body, 2) // class InputOnly
	body = binary.LittleEndian.AppendUint32(body, 0) // visual: CopyFromParent
	body = binary.LittleEndian.AppendUint32(body, 0x800)
	body = binary.LittleEndian.AppendUint32(body, eventMask)
	return id, c.send(opCreateWindow, 0, body)
}

// DestroyWindow destroys a window.
func (c *Conn) DestroyWindow(w uint32) error {
	return c.send(opDestroyWindow, 0, binary.LittleEndian.AppendUint32(nil, w))
}

// ChangeProperty sets (or, with appendMode, extends) a property.
func (c *Conn) ChangeProperty(w, prop, typ uint32, format byte, data []byte, appendMode bool) error {
	mode := byte(0)
	if appendMode {
		mode = 2
	}
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, w)
	body = binary.LittleEndian.AppendUint32(body, prop)
	body = binary.LittleEndian.AppendUint32(body, typ)
	body = append(body, format, 0, 0, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)/(int(format)/8)))
	body = append(body, data...)
	return c.send(opChangeProperty, mode, body)
}

// GetProperty reads (and with remove, deletes) a property.
func (c *Conn) GetProperty(w, prop uint32, remove bool) (typ uint32, data []byte, err error) {
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, w)
	body = binary.LittleEndian.AppendUint32(body, prop)
	body = binary.LittleEndian.AppendUint32(body, 0)     // AnyPropertyType
	body = binary.LittleEndian.AppendUint32(body, 0)     // offset
	body = binary.LittleEndian.AppendUint32(body, 1<<22) // length, in 4-byte units (16 MiB)
	del := byte(0)
	if remove {
		del = 1
	}
	if err := c.send(opGetProperty, del, body); err != nil {
		return 0, nil, err
	}
	b, err := c.reply()
	if err != nil {
		return 0, nil, err
	}
	format := int(b[1])
	typ = binary.LittleEndian.Uint32(b[8:])
	n := int(binary.LittleEndian.Uint32(b[16:])) * max(format/8, 1)
	if 32+n > len(b) {
		return 0, nil, ErrProtocol
	}
	return typ, append([]byte(nil), b[32:32+n]...), nil
}

// SetSelectionOwner makes w (0 for none) the selection's owner.
func (c *Conn) SetSelectionOwner(w, selection, time uint32) error {
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, w)
	body = binary.LittleEndian.AppendUint32(body, selection)
	body = binary.LittleEndian.AppendUint32(body, time)
	return c.send(opSetSelectionOwner, 0, body)
}

// SelectionOwner returns the selection's owner window (0 for none).
func (c *Conn) SelectionOwner(selection uint32) (uint32, error) {
	if err := c.send(opGetSelectionOwner, 0, binary.LittleEndian.AppendUint32(nil, selection)); err != nil {
		return 0, err
	}
	b, err := c.reply()
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[8:]), nil
}

// ConvertSelection asks the selection's owner to put it in a property of
// w as target.
func (c *Conn) ConvertSelection(w, selection, target, prop, time uint32) error {
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, w)
	body = binary.LittleEndian.AppendUint32(body, selection)
	body = binary.LittleEndian.AppendUint32(body, target)
	body = binary.LittleEndian.AppendUint32(body, prop)
	body = binary.LittleEndian.AppendUint32(body, time)
	return c.send(opConvertSelection, 0, body)
}

// SendEvent sends a 32-byte event to a window.
func (c *Conn) SendEvent(w uint32, event []byte) error {
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, w)
	body = binary.LittleEndian.AppendUint32(body, 0) // event mask: the window's owner
	body = append(body, event...)
	return c.send(opSendEvent, 0, body)
}
