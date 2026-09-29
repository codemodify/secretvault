package svfido

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/cbor"
)

// wire is a Transport whose device end the test plays.
type wire struct {
	toDevice chan []byte
	toHost   chan []byte
}

func newWire() *wire { return &wire{toDevice: make(chan []byte, 256), toHost: make(chan []byte, 256)} }

func (w *wire) WriteReport(r []byte) error {
	if len(r) != ReportSize {
		return errors.New("test: a short report")
	}
	w.toDevice <- bytes.Clone(r)
	return nil
}

func (w *wire) ReadReport(r []byte, deadline time.Time) (int, error) {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case rep := <-w.toHost:
		return copy(r, rep), nil
	case <-t.C:
		return 0, os.ErrDeadlineExceeded
	}
}

func (w *wire) Close() error { return nil }

// packets cuts a message as a device sends it.
func packets(cid uint32, cmd byte, data []byte) [][]byte {
	var out [][]byte
	p := make([]byte, ReportSize)
	binary.BigEndian.PutUint32(p, cid)
	p[4] = cmd
	binary.BigEndian.PutUint16(p[5:], uint16(len(data)))
	n := copy(p[7:], data)
	out = append(out, p)
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		p = make([]byte, ReportSize)
		binary.BigEndian.PutUint32(p, cid)
		p[4] = seq
		n = copy(p[5:], data)
		out = append(out, p)
		data = data[n:]
	}
	return out
}

func (w *wire) say(cid uint32, cmd byte, data []byte) {
	for _, p := range packets(cid, cmd, data) {
		w.toHost <- p
	}
}

const testCID = 0x11223344

func TestMessagesAreCutAndJoinedAndOtherChannelsIgnored(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w, cid: testCID}
	req := bytes.Repeat([]byte{0xab}, 300)
	resp := make([]byte, 200)
	for i := range resp {
		resp[i] = byte(i)
	}
	go func() {
		cid, cmd, data := h2(w)
		if cid != testCID || cmd != cmdCBOR || !bytes.Equal(data, req) {
			w.say(testCID, cmdError, []byte{0x7f})
			return
		}
		// Another program's conversation, interleaved.
		ps := packets(testCID, cmdCBOR, resp)
		w.say(0x99999999, cmdCBOR, bytes.Repeat([]byte{1}, 100))
		for _, p := range ps {
			w.toHost <- p
			w.say(0x99999999, cmdKeepalive, []byte{1})
		}
	}()
	got, err := h.transact(context.Background(), cmdCBOR, req, nil)
	if err != nil || !bytes.Equal(got, resp) {
		t.Fatalf("transact = %x, %v", got, err)
	}
}

// h2 reads one whole message the host sent, as the device.
func h2(w *wire) (uint32, byte, []byte) {
	p := <-w.toDevice
	cid, cmd := binary.BigEndian.Uint32(p), p[4]
	total := int(binary.BigEndian.Uint16(p[5:7]))
	data := append([]byte(nil), p[7:min(ReportSize, 7+total)]...)
	for len(data) < total {
		p = <-w.toDevice
		data = append(data, p[5:min(ReportSize, 5+total-len(data))]...)
	}
	return cid, cmd, data
}

func TestWritesArePaddedAndNumbered(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w}
	if err := h.write(testCID, cmdCBOR, bytes.Repeat([]byte{7}, 57+59+1)); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{
		append([]byte{0x11, 0x22, 0x33, 0x44, cmdCBOR, 0, 117}, bytes.Repeat([]byte{7}, 57)...),
		append([]byte{0x11, 0x22, 0x33, 0x44, 0}, bytes.Repeat([]byte{7}, 59)...),
		append([]byte{0x11, 0x22, 0x33, 0x44, 1, 7}, make([]byte, 58)...),
	}
	for i, wp := range want {
		if p := <-w.toDevice; !bytes.Equal(p, wp) {
			t.Fatalf("packet %d = % x\nwant % x", i, p, wp)
		}
	}
	if err := h.write(testCID, cmdCBOR, make([]byte, maxMessage+1)); err == nil {
		t.Fatal("a message beyond CTAPHID's limit was sent")
	}
}

func TestKeepalivesAskForTheTouchOnce(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w, cid: testCID}
	go func() {
		h2(w)
		w.say(testCID, cmdKeepalive, []byte{statusProcessing})
		for range 5 {
			w.say(testCID, cmdKeepalive, []byte{statusUPNeeded})
		}
		w.say(testCID, cmdCBOR, []byte{0})
	}()
	asked := 0
	if _, err := h.transact(context.Background(), cmdCBOR, []byte{4}, func() { asked++ }); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Fatalf("asked for the touch %d times", asked)
	}
}

func TestTransportErrorsAreReported(t *testing.T) {
	for name, tc := range map[string]struct {
		device func(w *wire)
		want   error
	}{
		"an error packet":         {func(w *wire) { w.say(testCID, cmdError, []byte{0x0b}) }, HIDError(0x0b)},
		"an error without a code": {func(w *wire) { w.say(testCID, cmdError, nil) }, ErrMalformed},
		"the wrong answer":        {func(w *wire) { w.say(testCID, cmdWink, nil) }, ErrMalformed},
		"a continuation out of order": {func(w *wire) {
			ps := packets(testCID, cmdCBOR, make([]byte, 100))
			ps[1][4] = 5
			for _, p := range ps {
				w.toHost <- p
			}
		}, ErrMalformed},
		"a message too long": {func(w *wire) {
			p := packets(testCID, cmdCBOR, []byte{0})[0]
			binary.BigEndian.PutUint16(p[5:], maxMessage+1)
			w.toHost <- p
		}, ErrMalformed},
		"a new message mid-message": {func(w *wire) {
			w.toHost <- packets(testCID, cmdCBOR, make([]byte, 100))[0]
			w.toHost <- packets(testCID, cmdCBOR, make([]byte, 100))[0]
		}, ErrMalformed},
		"silence": {func(w *wire) {}, ErrTimeout},
		"keepalives, then silence": {func(w *wire) {
			for range 3 {
				w.say(testCID, cmdKeepalive, []byte{1})
				time.Sleep(20 * time.Millisecond)
			}
		}, ErrTimeout},
	} {
		w := newWire()
		h := &hidConn{t: w, cid: testCID, silence: 100 * time.Millisecond}
		go func() { h2(w); tc.device(w) }()
		if _, err := h.transact(context.Background(), cmdCBOR, []byte{4}, nil); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestABusyDeviceIsAskedAgain(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w, cid: testCID}
	go func() {
		h2(w)
		w.say(testCID, cmdError, []byte{0x06})
		h2(w)
		w.say(testCID, cmdCBOR, []byte{0, 0xa0})
	}()
	got, err := h.transact(context.Background(), cmdCBOR, []byte{4}, nil)
	if err != nil || !bytes.Equal(got, []byte{0, 0xa0}) {
		t.Fatalf("after busy: %x, %v", got, err)
	}
}

func TestCancellingTellsTheDeviceAndKeepsTheChannelInStep(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w, cid: testCID}
	heard := make(chan []byte, 1)
	go func() {
		h2(w)
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
					w.say(testCID, cmdKeepalive, []byte{statusUPNeeded})
				}
			}
		}()
		_, cmd, data := h2(w)
		close(stop)
		heard <- append([]byte{cmd}, data...)
		w.say(testCID, cmdCBOR, []byte{byte(StatusKeepaliveCancel)})
		// The next request gets its own answer, not the cancelled one's.
		h2(w)
		w.say(testCID, cmdCBOR, []byte{0, 0xa0})
	}()
	c, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := h.transact(c, cmdCBOR, []byte{2}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled request: %v", err)
	}
	if got := <-heard; !bytes.Equal(got, []byte{cmdCancel}) {
		t.Fatalf("the device heard % x, want a CANCEL", got)
	}
	got, err := h.transact(context.Background(), cmdCBOR, []byte{4}, nil)
	if err != nil || !bytes.Equal(got, []byte{0, 0xa0}) {
		t.Fatalf("the next request: %x, %v", got, err)
	}
}

func TestAChannelIsOpenedWithOurNonce(t *testing.T) {
	w := newWire()
	h := &hidConn{t: w}
	go func() {
		cid, cmd, nonce := h2(w)
		if cid != broadcastCID || cmd != cmdInit || len(nonce) != 8 {
			return
		}
		// Another program's INIT answer first.
		w.say(broadcastCID, cmdInit, append(make([]byte, 8), 0, 0, 0, 9, 2, 1, 0, 0, capCBOR))
		w.say(broadcastCID, cmdInit, append(bytes.Clone(nonce), 0x11, 0x22, 0x33, 0x44, 2, 5, 4, 1, capCBOR|capNMSG))
	}()
	if err := h.open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.cid != testCID {
		t.Fatalf("channel %08x", h.cid)
	}

	// A U2F-only device is refused.
	w = newWire()
	h = &hidConn{t: w}
	go func() {
		_, _, nonce := h2(w)
		w.say(broadcastCID, cmdInit, append(bytes.Clone(nonce), 0x11, 0x22, 0x33, 0x44, 2, 5, 4, 1, 0))
	}()
	if err := h.open(context.Background()); !errors.Is(err, ErrNotCTAP2) {
		t.Fatalf("a U2F device: %v", err)
	}
}

// FuzzHIDResponse: whatever a device sends, reading returns, with a
// message or an error, and never panics.
func FuzzHIDResponse(f *testing.F) {
	var seed []byte
	for _, p := range packets(testCID, cmdCBOR, bytes.Repeat([]byte{1}, 130)) {
		seed = append(seed, p...)
	}
	f.Add(seed)
	f.Add(packets(testCID, cmdKeepalive, []byte{2})[0])
	f.Add(packets(testCID, cmdError, []byte{6})[0])
	f.Fuzz(func(t *testing.T, stream []byte) {
		w := newWire()
		for len(stream) > 0 {
			n := min(len(stream), ReportSize)
			p := make([]byte, ReportSize)
			copy(p, stream[:n])
			// Most reports on our channel, so the fuzzer reaches the parser.
			if len(stream) > 4 && stream[0]&1 == 0 {
				binary.BigEndian.PutUint32(p, testCID)
			}
			w.toHost <- p
			stream = stream[n:]
			if len(w.toHost) == cap(w.toHost) {
				break
			}
		}
		h := &hidConn{t: w, cid: testCID, silence: time.Millisecond}
		msg, err := h.read(context.Background(), testCID, cmdCBOR, func(byte) {})
		if err == nil && len(msg) > maxMessage {
			t.Fatalf("a %d-byte message", len(msg))
		}
	})
}

// FuzzResponses: the parsers of what devices answer refuse, rather than
// trip over, anything malformed.
func FuzzResponses(f *testing.F) {
	info, _ := cbor.Marshal(cbor.Map{1: []any{"FIDO_2_1"}, 2: []any{"hmac-secret"}, 3: make([]byte, 16),
		4: cbor.Map{"clientPin": true}, 5: int64(1200), 6: []any{int64(2), int64(1)}})
	f.Add(info)
	ad := append(make([]byte, 32), FlagUP|FlagED, 0, 0, 0, 1)
	ext, _ := cbor.Marshal(cbor.Map{"hmac-secret": make([]byte, 48)})
	f.Add(append(ad, ext...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := cbor.Unmarshal(b); err == nil {
			if m, ok := v.(cbor.Map); ok {
				parseInfo(m)
				parseCOSEKey(m)
			}
		}
		parseAuthData(b)
		parseDescriptor(b)
	})
}
