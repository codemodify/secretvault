package svfido

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"
)

// CTAPHID (CTAP 2.1 §11.2): messages cut into 64-byte HID reports.
//
//	initialisation packet   CID (4) | CMD | 0x80 (1) | BCNT (2) | DATA (57)
//	continuation packet     CID (4) | SEQ 0..127 (1) | DATA (59)
//
// A program first asks for a channel (INIT on the broadcast channel, with
// a nonce) and then talks on it; other programs' channels share the wire,
// so reports for other channels are skipped. While the device works, and
// while it waits for a touch, it sends KEEPALIVE every 100 ms; the host
// may abandon a request with CANCEL.

// ReportSize is the size of every HID report CTAPHID uses.
const ReportSize = 64

const (
	initData   = ReportSize - 7
	contData   = ReportSize - 5
	maxMessage = initData + 128*contData // 7609 bytes

	broadcastCID = 0xffffffff

	cmdPing      = 0x81
	cmdMsg       = 0x83
	cmdInit      = 0x86
	cmdWink      = 0x88
	cmdCBOR      = 0x90
	cmdCancel    = 0x91
	cmdKeepalive = 0xbb
	cmdError     = 0xbf

	statusProcessing = 1
	statusUPNeeded   = 2

	capCBOR = 0x04
	capNMSG = 0x08
)

// Transport carries HID reports to one device and back. On Linux it is
// a /dev/hidraw node; tests use an in-memory pipe to a software
// authenticator.
type Transport interface {
	// WriteReport sends one output report of ReportSize bytes.
	WriteReport(report []byte) error
	// ReadReport waits until deadline for one input report and returns
	// its length. It returns os.ErrDeadlineExceeded when none came.
	ReadReport(report []byte, deadline time.Time) (int, error)
	// Close releases the device.
	Close() error
}

// Timing. The spec has keepalives every 100 ms, so a device that says
// nothing for seconds has hung; a touch can take as long as the person
// likes, but the device keeps sending keepalives meanwhile.
var (
	// defaultSilence is how long a device may say nothing mid-request.
	defaultSilence = 10 * time.Second
	// touchDelay is when a request that needs a touch is taken to be
	// waiting for one, for devices that do not say so in their keepalives.
	touchDelay = 500 * time.Millisecond
	// pollInterval bounds how long a read waits before looking at the
	// context again.
	pollInterval = 50 * time.Millisecond
	// cancelDrain is how long the answer to a cancelled request is
	// waited for, to keep the channel in step.
	cancelDrain = 2 * time.Second
	// busyRetry is how long a busy device is waited for before giving up.
	busyRetry = 3 * time.Second
)

// hidConn is one CTAPHID channel on a transport.
type hidConn struct {
	t       Transport
	cid     uint32
	silence time.Duration
	caps    byte
	buf     [ReportSize]byte
}

// write sends a message as an initialisation packet and continuations.
func (h *hidConn) write(cid uint32, cmd byte, data []byte) error {
	if len(data) > maxMessage {
		return errors.New("svfido: message too large for CTAPHID")
	}
	var p [ReportSize]byte
	binary.BigEndian.PutUint32(p[0:4], cid)
	p[4] = cmd
	binary.BigEndian.PutUint16(p[5:7], uint16(len(data)))
	n := copy(p[7:], data)
	if err := h.t.WriteReport(p[:]); err != nil {
		return err
	}
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		p = [ReportSize]byte{}
		binary.BigEndian.PutUint32(p[0:4], cid)
		p[4] = seq
		n = copy(p[5:], data)
		if err := h.t.WriteReport(p[:]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// read waits for a whole message of command want on channel cid, and
// returns its payload. Keepalives go to onKeepalive. It returns ctx's
// error, unwrapped, when ctx ends first.
func (h *hidConn) read(ctx context.Context, cid uint32, want byte, onKeepalive func(byte)) ([]byte, error) {
	silence := h.silence
	if silence <= 0 {
		silence = defaultSilence
	}
	quiet := time.Now().Add(silence) // when the device has said nothing for too long
	var msg []byte
	var total int
	var seq byte
	assembling := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(pollInterval)
		if quiet.Before(deadline) {
			deadline = quiet
		}
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		n, err := h.t.ReadReport(h.buf[:], deadline)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if !time.Now().Before(quiet) {
				return nil, ErrTimeout
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		p := h.buf[:n]
		if n < 5 || binary.BigEndian.Uint32(p[0:4]) != cid {
			continue // another program's channel, or noise
		}
		b := p[4]
		if b&0x80 == 0 { // a continuation
			if !assembling {
				continue // stray: a message we stopped reading
			}
			if b != seq {
				return nil, malformed("continuation %d where %d was due", b, seq)
			}
			seq++
			msg = append(msg, p[5:min(n, 5+total-len(msg))]...)
			quiet = time.Now().Add(silence)
			if len(msg) == total {
				return msg, nil
			}
			continue
		}
		if n < 7 {
			return nil, malformed("a %d-byte packet", n)
		}
		if assembling {
			return nil, malformed("a new message began before the last ended")
		}
		bcnt := int(binary.BigEndian.Uint16(p[5:7]))
		quiet = time.Now().Add(silence)
		switch b {
		case cmdKeepalive:
			if bcnt >= 1 && onKeepalive != nil {
				onKeepalive(p[7])
			}
			continue
		case cmdError:
			if bcnt < 1 {
				return nil, malformed("an error without a code")
			}
			return nil, HIDError(p[7])
		case want:
		default:
			return nil, malformed("an answer of type 0x%02x to a request of type 0x%02x", b, want)
		}
		if bcnt > maxMessage {
			return nil, malformed("a %d-byte message", bcnt)
		}
		total = bcnt
		msg = make([]byte, 0, total)
		msg = append(msg, p[7:min(n, 7+total)]...)
		if len(msg) == total {
			return msg, nil
		}
		assembling, seq = true, 0
	}
}

// open allocates a channel (CTAPHID_INIT on the broadcast channel).
func (h *hidConn) open(ctx context.Context) error {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	if err := h.write(broadcastCID, cmdInit, nonce); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		resp, err := h.read(ctx, broadcastCID, cmdInit, nil)
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrTimeout
		}
		if err != nil {
			return err
		}
		if len(resp) < 17 || string(resp[:8]) != string(nonce) {
			continue // another program's INIT
		}
		cid := binary.BigEndian.Uint32(resp[8:12])
		if cid == 0 || cid == broadcastCID {
			return malformed("channel %08x", cid)
		}
		h.cid, h.caps = cid, resp[16]
		if h.caps&capCBOR == 0 {
			return ErrNotCTAP2
		}
		return nil
	}
}

// transact sends one request on the channel and waits for its answer.
// onUP is called once, perhaps from another goroutine, when the device
// waits for a touch: when it says so, or when it has not answered within
// touchDelay. If ctx ends
// first, the request is cancelled on the device (CTAPHID_CANCEL) and
// ctx's error is returned.
func (h *hidConn) transact(ctx context.Context, cmd byte, data []byte, onUP func()) ([]byte, error) {
	busyUntil := time.Now().Add(busyRetry)
	for {
		resp, err := h.transactOnce(ctx, cmd, data, onUP)
		if errors.Is(err, hidErrChannelBusy) && time.Now().Before(busyUntil) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		return resp, err
	}
}

func (h *hidConn) transactOnce(ctx context.Context, cmd byte, data []byte, onUP func()) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := h.write(h.cid, cmd, data); err != nil {
		return nil, err
	}
	var keepalive func(byte)
	if onUP != nil {
		var once sync.Once
		ask := func() { once.Do(onUP) }
		t := time.AfterFunc(touchDelay, ask)
		defer t.Stop()
		keepalive = func(status byte) {
			if status == statusUPNeeded {
				ask()
			}
		}
	}
	resp, err := h.read(ctx, h.cid, cmd, keepalive)
	if err == nil || ctx.Err() == nil {
		return resp, err
	}
	// Abandoned: tell the device, and read its answer (normally
	// CTAP2_ERR_KEEPALIVE_CANCEL) so the next request does not see it.
	h.write(h.cid, cmdCancel, nil)
	drain, cancel := context.WithTimeout(context.Background(), cancelDrain)
	defer cancel()
	h.read(drain, h.cid, cmd, nil)
	return nil, ctx.Err()
}
