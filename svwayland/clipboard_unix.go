//go:build linux || freebsd || netbsd || openbsd

package svwayland

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

// The data-control protocols let a client without a window read and set
// the clipboard. ext_data_control_v1 is the standard (KDE Plasma 6.3+,
// wlroots compositors); zwlr_data_control_manager_v1 is its predecessor
// with the same requests and events. GNOME offers neither, and the caller
// then falls back to X11 through XWayland.
//
//	manager:  create_data_source(new_id) 0, get_data_device(new_id, seat) 1, destroy 2
//	device:   set_selection(source?) 0, destroy 1, set_primary_selection(source?) 2
//	          events: data_offer(new_id) 0, selection(offer?) 1, finished 2, primary_selection(offer?) 3
//	source:   offer(mime) 0, destroy 1;  events: send(mime, fd) 0, cancelled 1
//	offer:    receive(mime, fd) 0, destroy 1;  events: offer(mime) 0

// ErrNoDataControl is a compositor without a data-control protocol.
var ErrNoDataControl = errors.New("svwayland: the compositor offers no data-control protocol")

var managers = []string{"ext_data_control_manager_v1", "zwlr_data_control_manager_v1"}

// Clipboard owns or reads the clipboard through data control.
type Clipboard struct {
	c      *Conn
	device uint32
	mgr    uint32

	offers    map[uint32][]string // offer object -> MIME types
	selection uint32              // the current selection's offer, 0 when empty
	finished  bool
}

// OpenClipboard connects and binds the data-control manager of the first
// seat.
func OpenClipboard() (*Clipboard, error) {
	c, err := Connect()
	if err != nil {
		return nil, err
	}
	cb, err := newClipboard(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return cb, nil
}

func newClipboard(c *Conn) (*Clipboard, error) {
	var mg Global
	found := false
	for _, name := range managers {
		if g, ok := c.Find(name); ok {
			mg, found = g, true
			break
		}
	}
	if !found {
		return nil, ErrNoDataControl
	}
	sg, ok := c.Find("wl_seat")
	if !ok {
		return nil, errors.New("svwayland: the compositor offers no seat")
	}
	cb := &Clipboard{c: c, offers: map[uint32][]string{}}
	seat, err := c.Bind(sg, 1, func(uint16, *decoder) error { return nil })
	if err != nil {
		return nil, err
	}
	if cb.mgr, err = c.Bind(mg, 1, func(uint16, *decoder) error { return nil }); err != nil {
		return nil, err
	}
	cb.device = c.newID(cb.deviceEvent)
	var e encoder
	e.object(cb.device)
	e.object(seat)
	if err := c.send(cb.mgr, 1, &e); err != nil {
		return nil, err
	}
	// The device announces the current selection straight away.
	if err := c.Roundtrip(); err != nil {
		return nil, err
	}
	return cb, nil
}

func (cb *Clipboard) deviceEvent(op uint16, d *decoder) error {
	switch op {
	case 0: // data_offer(new_id): the compositor made an offer object
		id := d.uint()
		cb.offers[id] = nil
		cb.c.handlers[id] = func(op uint16, d *decoder) error {
			if op == 0 {
				cb.offers[id] = append(cb.offers[id], d.string())
			}
			return d.err
		}
	case 1: // selection(offer or 0)
		old := cb.selection
		cb.selection = d.uint()
		if old != 0 && old != cb.selection {
			cb.destroyOffer(old)
		}
	case 2: // finished: the device is gone (seat removed)
		cb.finished = true
	case 3: // primary_selection: not used; drop the offer
		if id := d.uint(); id != 0 && id != cb.selection {
			cb.destroyOffer(id)
		}
	}
	return d.err
}

func (cb *Clipboard) destroyOffer(id uint32) {
	delete(cb.offers, id)
	var e encoder
	cb.c.send(id, 1, &e)
}

// Close closes the connection (a selection it owns goes with it).
func (cb *Clipboard) Close() error { return cb.c.Close() }

// Offer is one representation of the clipboard's contents.
type Offer struct {
	MIME string
	Data []byte
}

// Serve makes offers the clipboard's contents and answers paste requests
// until someone else takes the clipboard or ttl passes. At the deadline,
// if the contents are still ours, it clears the clipboard. It returns
// whether it cleared. ready, if not nil, is called once the compositor has
// made the offers the clipboard. The caller wipes the offers' data
// afterwards.
func (cb *Clipboard) Serve(offers []Offer, ttl time.Duration, ready func()) (cleared bool, err error) {
	c := cb.c
	cancelled := false
	source := c.newID(func(op uint16, d *decoder) error {
		switch op {
		case 0: // send(mime, fd)
			mime, fd := d.string(), d.fd()
			if d.err != nil {
				return d.err
			}
			f := os.NewFile(uintptr(fd), "paste")
			for _, o := range offers {
				if o.MIME == mime {
					f.Write(o.Data)
					break
				}
			}
			f.Close()
		case 1: // cancelled: another client owns the clipboard now
			cancelled = true
		}
		return d.err
	})
	var e encoder
	e.object(source)
	if err := c.send(cb.mgr, 0, &e); err != nil { // create_data_source
		return false, err
	}
	for _, o := range offers {
		var e encoder
		e.string(o.MIME)
		if err := c.send(source, 0, &e); err != nil {
			return false, err
		}
	}
	e = encoder{}
	e.object(source)
	if err := c.send(cb.device, 0, &e); err != nil { // set_selection(source)
		return false, err
	}
	if err := c.Roundtrip(); err != nil {
		return false, err
	}
	if ready != nil && !cancelled {
		ready()
	}
	deadline := time.Now().Add(ttl)
	for !cancelled && !cb.finished {
		err := c.Dispatch(deadline)
		if errors.Is(err, errTimeout) {
			break
		}
		if err != nil {
			return false, err
		}
	}
	if !cancelled && !cb.finished {
		e = encoder{}
		e.object(0)
		if err := c.send(cb.device, 0, &e); err != nil { // set_selection(null)
			return false, err
		}
		cleared = true
	}
	e = encoder{}
	c.send(source, 1, &e) // destroy
	return cleared, c.Roundtrip()
}

// Read returns the clipboard's contents as mime, or nil when the
// clipboard is empty or does not offer that type.
func (cb *Clipboard) Read(mime string) ([]byte, error) {
	if err := cb.c.Roundtrip(); err != nil {
		return nil, err
	}
	if cb.selection == 0 {
		return nil, nil
	}
	has := false
	for _, m := range cb.offers[cb.selection] {
		has = has || m == mime
	}
	if !has {
		return nil, nil
	}
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
		return nil, err
	}
	// The read end is non-blocking so a deadline applies: an owner that
	// never writes must not hang us.
	syscall.SetNonblock(p[0], true)
	r := os.NewFile(uintptr(p[0]), "clipboard")
	defer r.Close()
	var e encoder
	e.string(mime)
	e.fd(p[1])
	err := cb.c.send(cb.selection, 0, &e) // receive(mime, fd)
	syscall.Close(p[1])
	if err != nil {
		return nil, err
	}
	r.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("svwayland: reading the clipboard: %w", err)
	}
	return b, nil
}
