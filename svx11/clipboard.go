package svx11

import (
	"encoding/binary"
	"errors"
	"os"
	"time"
)

// Offer is one representation of the clipboard's contents, by target
// name (a MIME type, or UTF8_STRING and the like).
type Offer struct {
	Target string
	Data   []byte
}

const propertyChangeMask = 1 << 22

// maxOffer is the largest offer served in one piece; larger ones would
// need the INCR protocol, which secrets never do.
const maxOffer = 256 << 10

// Serve owns the CLIPBOARD selection with offers and answers paste
// requests until another client takes the selection or ttl passes. At the
// deadline, if the selection is still ours, it gives it up, emptying the
// clipboard. It returns whether it did. ready, if not nil, is called once
// the selection is ours. The caller wipes the offers' data.
func Serve(c *Conn, offers []Offer, ttl time.Duration, ready func()) (cleared bool, err error) {
	atom := func(name string) uint32 {
		if err != nil {
			return 0
		}
		var a uint32
		a, err = c.Atom(name)
		return a
	}
	clipboard, targets, timestamp := atom("CLIPBOARD"), atom("TARGETS"), atom("TIMESTAMP")
	atomType, integer, stamp := atom("ATOM"), atom("INTEGER"), atom("SECRETVAULT_TIME")
	offerAtoms := make([]uint32, len(offers))
	for i, o := range offers {
		if len(o.Data) > maxOffer {
			return false, errors.New("svx11: too large for the clipboard")
		}
		offerAtoms[i] = atom(o.Target)
	}
	if err != nil {
		return false, err
	}
	w, err := c.CreateInputWindow(propertyChangeMask)
	if err != nil {
		return false, err
	}
	defer c.DestroyWindow(w)

	// ICCCM: own a selection with a real server time, not CurrentTime.
	// Appending nothing to a property of our window makes the server tell
	// us the time in a PropertyNotify.
	if err := c.ChangeProperty(w, stamp, atomType, 8, nil, true); err != nil {
		return false, err
	}
	var now uint32
	for now == 0 {
		ev, err := c.NextEvent(time.Now().Add(5 * time.Second))
		if err != nil {
			return false, err
		}
		if ev[0]&0x7f == evPropertyNotify && binary.LittleEndian.Uint32(ev[4:]) == w {
			now = binary.LittleEndian.Uint32(ev[12:])
		}
	}
	if err := c.SetSelectionOwner(w, clipboard, now); err != nil {
		return false, err
	}
	if owner, err := c.SelectionOwner(clipboard); err != nil {
		return false, err
	} else if owner != w {
		return false, errors.New("svx11: could not take the clipboard")
	}
	if ready != nil {
		ready()
	}

	deadline := time.Now().Add(ttl)
	for {
		ev, err := c.NextEvent(deadline)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			return false, err
		}
		switch ev[0] & 0x7f {
		case evSelectionClear:
			if binary.LittleEndian.Uint32(ev[8:]) == w {
				return false, nil // someone else copied: nothing of ours to clear
			}
		case evSelectionRequest:
			if err := answer(c, ev, now, targets, timestamp, atomType, integer, offerAtoms, offers); err != nil {
				return false, err
			}
		}
	}
	if owner, err := c.SelectionOwner(clipboard); err != nil {
		return false, err
	} else if owner != w {
		return false, nil
	}
	if err := c.SetSelectionOwner(0, clipboard, now); err != nil {
		return false, err
	}
	return true, c.Sync()
}

// answer serves one SelectionRequest.
func answer(c *Conn, ev []byte, now, targets, timestamp, atomType, integer uint32, offerAtoms []uint32, offers []Offer) error {
	t := binary.LittleEndian.Uint32(ev[4:])
	requestor := binary.LittleEndian.Uint32(ev[12:])
	selection := binary.LittleEndian.Uint32(ev[16:])
	target := binary.LittleEndian.Uint32(ev[20:])
	prop := binary.LittleEndian.Uint32(ev[24:])
	if prop == 0 {
		prop = target // obsolete clients (ICCCM 2.2)
	}
	var err error
	switch {
	case t != 0 && t < now:
		prop = 0 // a request from before we owned it
	case target == targets:
		list := binary.LittleEndian.AppendUint32(nil, targets)
		list = binary.LittleEndian.AppendUint32(list, timestamp)
		for _, a := range offerAtoms {
			list = binary.LittleEndian.AppendUint32(list, a)
		}
		err = c.ChangeProperty(requestor, prop, atomType, 32, list, false)
	case target == timestamp:
		err = c.ChangeProperty(requestor, prop, integer, 32, binary.LittleEndian.AppendUint32(nil, now), false)
	default:
		found := false
		for i, a := range offerAtoms {
			if a == target {
				err = c.ChangeProperty(requestor, prop, target, 8, offers[i].Data, false)
				found = true
				break
			}
		}
		if !found {
			prop = 0 // refuse: SAVE_TARGETS, MULTIPLE and anything not offered
		}
	}
	if err != nil {
		return err
	}
	notify := make([]byte, 32)
	notify[0] = evSelectionNotify
	binary.LittleEndian.PutUint32(notify[4:], t)
	binary.LittleEndian.PutUint32(notify[8:], requestor)
	binary.LittleEndian.PutUint32(notify[12:], selection)
	binary.LittleEndian.PutUint32(notify[16:], target)
	binary.LittleEndian.PutUint32(notify[20:], prop)
	return c.SendEvent(requestor, notify)
}

// Read returns the CLIPBOARD's contents as target, or nil when it is
// empty or the owner does not offer that target.
func Read(c *Conn, target string) ([]byte, error) {
	clipboard, err := c.Atom("CLIPBOARD")
	if err != nil {
		return nil, err
	}
	tgt, err := c.Atom(target)
	if err != nil {
		return nil, err
	}
	prop, err := c.Atom("SECRETVAULT_SELECTION")
	if err != nil {
		return nil, err
	}
	w, err := c.CreateInputWindow(propertyChangeMask)
	if err != nil {
		return nil, err
	}
	defer c.DestroyWindow(w)
	if err := c.ConvertSelection(w, clipboard, tgt, prop, 0); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ev, err := c.NextEvent(deadline)
		if err != nil {
			return nil, err
		}
		if ev[0]&0x7f != evSelectionNotify || binary.LittleEndian.Uint32(ev[8:]) != w {
			continue
		}
		if binary.LittleEndian.Uint32(ev[20:]) == 0 {
			return nil, nil // refused, or nothing on the clipboard
		}
		_, data, err := c.GetProperty(w, prop, true)
		return data, err
	}
}
