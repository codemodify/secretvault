//go:build linux

package svwayland

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeCompositor speaks just enough Wayland to host the data-control
// protocol, so the client is tested without touching the real desktop's
// clipboard.
type fakeCompositor struct {
	t    *testing.T
	ln   *net.UnixListener
	path string

	mu        sync.Mutex
	conn      *net.UnixConn
	iface     map[uint32]string // client object -> interface
	mimes     map[uint32][]string
	selection uint32 // current source, 0 = none
	sets      []uint32
	offerMime []string
	offerData []byte
	nextSrvID uint32
	readyCh   chan struct{}
}

func newFake(t *testing.T, withDataControl bool, offer ...string) *fakeCompositor {
	dir := t.TempDir()
	path := filepath.Join(dir, "wl")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCompositor{t: t, ln: ln, path: path, iface: map[uint32]string{1: "wl_display"}, mimes: map[uint32][]string{},
		nextSrvID: 0xff000000, readyCh: make(chan struct{})}
	if len(offer) == 2 { // a MIME type and data already on the clipboard
		f.offerMime, f.offerData = []string{offer[0]}, []byte(offer[1])
	}
	go f.serve(withDataControl)
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeCompositor) event(obj uint32, op uint16, e *encoder) {
	msg, _ := e.message(obj, op)
	var oob []byte
	if len(e.fds) > 0 {
		oob = syscall.UnixRights(e.fds...)
	}
	f.conn.WriteMsgUnix(msg, oob, nil)
}

func (f *fakeCompositor) serve(withDataControl bool) {
	c, err := f.ln.AcceptUnix()
	if err != nil {
		return
	}
	f.mu.Lock()
	f.conn = c
	f.mu.Unlock()
	close(f.readyCh)
	var in []byte
	var fds []int
	buf := make([]byte, 4096)
	oob := make([]byte, 256)
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if err != nil {
			return
		}
		if oobn > 0 {
			msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
			for _, m := range msgs {
				if got, err := syscall.ParseUnixRights(&m); err == nil {
					fds = append(fds, got...)
				}
			}
		}
		in = append(in, buf[:n]...)
		for len(in) >= 8 {
			obj := binary.LittleEndian.Uint32(in)
			word := binary.LittleEndian.Uint32(in[4:])
			size, op := int(word>>16), uint16(word)
			if len(in) < size {
				break
			}
			d := &decoder{b: in[8:size], fds: &fds}
			f.mu.Lock()
			f.request(obj, op, d, withDataControl)
			f.mu.Unlock()
			in = in[size:]
		}
	}
}

func (f *fakeCompositor) request(obj uint32, op uint16, d *decoder, withDataControl bool) {
	switch f.iface[obj] {
	case "wl_display":
		switch op {
		case 0: // sync(callback)
			cb := d.uint()
			var e encoder
			e.uint(1)
			f.event(cb, 0, &e) // done
			e = encoder{}
			e.uint(cb)
			f.event(1, 1, &e) // delete_id
		case 1: // get_registry(registry)
			reg := d.uint()
			f.iface[reg] = "wl_registry"
			globals := []Global{{1, "wl_compositor", 6}, {2, "wl_seat", 9}}
			if withDataControl {
				globals = append(globals, Global{3, "ext_data_control_manager_v1", 1})
			}
			for _, g := range globals {
				var e encoder
				e.uint(g.Name)
				e.string(g.Interface)
				e.uint(g.Version)
				f.event(reg, 0, &e)
			}
		}
	case "wl_registry": // bind(name, interface, version, id)
		d.uint()
		iface := d.string()
		d.uint()
		f.iface[d.uint()] = iface
	case "ext_data_control_manager_v1":
		switch op {
		case 0: // create_data_source
			f.iface[d.uint()] = "source"
		case 1: // get_data_device(id, seat)
			dev := d.uint()
			f.iface[dev] = "device"
			f.announce(dev)
		}
	case "source":
		if op == 0 {
			f.mimes[obj] = append(f.mimes[obj], d.string())
		}
	case "device":
		if op == 0 { // set_selection(source?)
			src := d.uint()
			if f.selection != 0 && f.selection != src {
				var e encoder
				f.event(f.selection, 1, &e) // cancelled
			}
			f.selection = src
			f.sets = append(f.sets, src)
		}
	case "offer":
		if op == 0 { // receive(mime, fd)
			mime, fd := d.string(), d.fd()
			file := os.NewFile(uintptr(fd), "pipe")
			if mime == f.offerMime[0] {
				file.Write(f.offerData)
			}
			file.Close()
		}
	}
}

// announce tells a new device the current selection: an offer when the
// fake has contents of its own to offer.
func (f *fakeCompositor) announce(dev uint32) {
	if f.offerData == nil {
		var e encoder
		e.uint(0)
		f.event(dev, 1, &e)
		return
	}
	id := f.nextSrvID
	f.nextSrvID++
	f.iface[id] = "offer"
	var e encoder
	e.uint(id)
	f.event(dev, 0, &e) // data_offer
	for _, m := range f.offerMime {
		e = encoder{}
		e.string(m)
		f.event(id, 0, &e) // offer(mime)
	}
	e = encoder{}
	e.uint(id)
	f.event(dev, 1, &e) // selection
}

// paste asks the current source for mime, as a pasting client would.
func (f *fakeCompositor) paste(mime string) string {
	f.mu.Lock()
	src := f.selection
	var p [2]int
	syscall.Pipe(p[:])
	var e encoder
	e.string(mime)
	e.fd(p[1])
	f.event(src, 0, &e) // send(mime, fd)
	f.mu.Unlock()
	syscall.Close(p[1])
	r := os.NewFile(uintptr(p[0]), "r")
	defer r.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func (f *fakeCompositor) otherClientCopies() {
	f.mu.Lock()
	defer f.mu.Unlock()
	var e encoder
	f.event(f.selection, 1, &e) // cancelled
	f.selection = 0xdead
}

func (f *fakeCompositor) setsSeen() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.sets...)
}

func open(t *testing.T, f *fakeCompositor) *Clipboard {
	t.Helper()
	c, err := Dial(f.path)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := newClipboard(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cb.Close() })
	return cb
}

var secretOffers = []Offer{
	{MIME: "text/plain;charset=utf-8", Data: []byte("hunter2")},
	{MIME: "x-kde-passwordManagerHint", Data: []byte("secret")},
}

func TestACopyIsPastedThenClearedAtTheDeadline(t *testing.T) {
	f := newFake(t, true)
	cb := open(t, f)
	done := make(chan bool, 1)
	go func() {
		cleared, err := cb.Serve(secretOffers, 400*time.Millisecond, nil)
		if err != nil {
			t.Error(err)
		}
		done <- cleared
	}()
	time.Sleep(100 * time.Millisecond)
	if got := f.paste("text/plain;charset=utf-8"); got != "hunter2" {
		t.Fatalf("pasted %q", got)
	}
	if got := f.paste("x-kde-passwordManagerHint"); got != "secret" {
		t.Fatalf("the clipboard-manager hint is %q", got)
	}
	f.mu.Lock()
	mimes := f.mimes[f.selection]
	f.mu.Unlock()
	if len(mimes) != 2 {
		t.Fatalf("offered %v", mimes)
	}
	if !<-done {
		t.Fatal("the clipboard was not cleared at the deadline")
	}
	if sets := f.setsSeen(); len(sets) != 2 || sets[1] != 0 {
		t.Fatalf("set_selection calls %v, want the source then null", sets)
	}
}

func TestSomeoneElseCopyingEndsOurOwnershipWithoutClearing(t *testing.T) {
	f := newFake(t, true)
	cb := open(t, f)
	done := make(chan bool, 1)
	go func() {
		cleared, _ := cb.Serve(secretOffers, 10*time.Second, nil)
		done <- cleared
	}()
	time.Sleep(100 * time.Millisecond)
	f.otherClientCopies()
	select {
	case cleared := <-done:
		if cleared {
			t.Fatal("cleared a clipboard that was no longer ours")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve kept running after losing the clipboard")
	}
	if sets := f.setsSeen(); len(sets) != 1 {
		t.Fatalf("set_selection calls %v: it must not clear someone else's copy", sets)
	}
}

func TestTheClipboardCanBeRead(t *testing.T) {
	f := newFake(t, true, "text/plain;charset=utf-8", "from elsewhere")
	cb := open(t, f)
	got, err := cb.Read("text/plain;charset=utf-8")
	if err != nil || string(got) != "from elsewhere" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if got, _ := cb.Read("image/png"); got != nil {
		t.Fatal("read a type that was not offered")
	}
}

func TestACompositorWithoutDataControlIsReported(t *testing.T) {
	f := newFake(t, false)
	c, err := Dial(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := newClipboard(c); err != ErrNoDataControl {
		t.Fatalf("err = %v", err)
	}
}
