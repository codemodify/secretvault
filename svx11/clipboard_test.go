//go:build !windows

package svx11

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeX is an X server that knows just the requests svx11 makes, so the
// selection protocol is tested without touching the real clipboard. It
// also plays the other clients: a requestor window (0x999) that pastes,
// and an external owner.
type fakeX struct {
	t      *testing.T
	ln     net.Listener
	mu     sync.Mutex
	conn   net.Conn
	seq    uint16
	atoms  map[string]uint32
	names  map[uint32]string
	props  map[[2]uint32][]byte // (window, atom) -> data
	ptype  map[[2]uint32]uint32
	owners map[uint32]uint32 // selection -> owner window
	masks  map[uint32]uint32 // client windows -> event mask
	sent   chan []byte       // events the client sent to other clients
	clears []uint32          // SetSelectionOwner(None) calls, by selection
	auth   string            // cookie the client presented
	now    uint32

	externalData []byte // what an external owner serves (for Read)
}

const (
	root      = 0x100
	requestor = 0x999
	external  = 0x777
)

func newFakeX(t *testing.T) (*fakeX, string) {
	path := filepath.Join(t.TempDir(), "X0")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeX{t: t, ln: ln, atoms: map[string]uint32{}, names: map[uint32]string{}, props: map[[2]uint32][]byte{},
		ptype: map[[2]uint32]uint32{}, owners: map[uint32]uint32{}, masks: map[uint32]uint32{}, sent: make(chan []byte, 16), now: 1000}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f, path
}

func (f *fakeX) atom(name string) uint32 {
	if a, ok := f.atoms[name]; ok {
		return a
	}
	a := uint32(100 + len(f.atoms))
	f.atoms[name], f.names[a] = a, name
	return a
}

func (f *fakeX) write(b []byte) { f.conn.Write(b) }

func (f *fakeX) reply(extra []byte, data byte, words ...uint32) {
	b := make([]byte, 32)
	b[0], b[1] = 1, data
	binary.LittleEndian.PutUint16(b[2:], f.seq)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(extra)/4))
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[8+4*i:], w)
	}
	f.write(append(b, extra...))
}

func (f *fakeX) event(code byte, words ...uint32) {
	b := make([]byte, 32)
	b[0] = code
	binary.LittleEndian.PutUint16(b[2:], f.seq)
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[4+4*i:], w)
	}
	f.write(b)
}

func (f *fakeX) serve() {
	c, err := f.ln.Accept()
	if err != nil {
		return
	}
	f.mu.Lock()
	f.conn = c
	f.mu.Unlock()
	head := make([]byte, 12)
	io.ReadFull(c, head)
	nlen, dlen := int(binary.LittleEndian.Uint16(head[6:])), int(binary.LittleEndian.Uint16(head[8:]))
	pad := func(n int) int { return (n + 3) &^ 3 }
	auth := make([]byte, pad(nlen)+pad(dlen))
	io.ReadFull(c, auth)
	f.mu.Lock()
	f.auth = string(auth[:nlen]) + ":" + string(auth[pad(nlen):pad(nlen)+dlen])
	f.mu.Unlock()

	body := make([]byte, 76)
	binary.LittleEndian.PutUint32(body[4:], 0x00400000) // id base
	binary.LittleEndian.PutUint32(body[8:], 0x001fffff) // id mask
	binary.LittleEndian.PutUint16(body[16:], 4)         // vendor length
	binary.LittleEndian.PutUint16(body[18:], 0xffff)    // max request length
	body[20], body[21] = 1, 0                           // screens, formats
	copy(body[32:], "fake")
	binary.LittleEndian.PutUint32(body[36:], root)
	setup := []byte{1, 0, 11, 0, 0, 0}
	setup = binary.LittleEndian.AppendUint16(setup, uint16(len(body)/4))
	c.Write(append(setup, body...))

	for {
		h := make([]byte, 4)
		if _, err := io.ReadFull(c, h); err != nil {
			return
		}
		b := make([]byte, int(binary.LittleEndian.Uint16(h[2:]))*4-4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		f.mu.Lock()
		f.seq++
		f.request(h[0], h[1], b)
		f.mu.Unlock()
	}
}

func u32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }

func (f *fakeX) request(op, data byte, b []byte) {
	switch op {
	case opInternAtom:
		n := int(binary.LittleEndian.Uint16(b))
		f.reply(nil, 0, f.atom(string(b[4:4+n])))
	case opCreateWindow:
		f.masks[u32(b, 0)] = u32(b, 28)
	case opDestroyWindow:
		delete(f.masks, u32(b, 0))
	case opChangeProperty:
		w, prop, typ, format, n := u32(b, 0), u32(b, 4), u32(b, 8), int(b[12]), int(u32(b, 16))
		val := b[20 : 20+n*format/8]
		key := [2]uint32{w, prop}
		if data == 2 {
			f.props[key] = append(f.props[key], val...)
		} else {
			f.props[key] = append([]byte(nil), val...)
		}
		f.ptype[key] = typ
		if f.masks[w]&propertyChangeMask != 0 {
			f.now++
			f.event(evPropertyNotify, w, prop, f.now, 0)
		}
	case opGetProperty:
		w, prop, remove := u32(b, 0), u32(b, 4), data == 1
		key := [2]uint32{w, prop}
		val := f.props[key]
		if remove {
			delete(f.props, key)
		}
		padded := append(append([]byte(nil), val...), make([]byte, (4-len(val)%4)%4)...)
		f.reply(padded, 8, f.ptype[key], 0, uint32(len(val)))
	case opSetSelectionOwner:
		owner, sel := u32(b, 0), u32(b, 4)
		if prev := f.owners[sel]; prev != 0 && prev != owner && f.masks[prev] != 0 {
			f.event(evSelectionClear, f.now, prev, sel)
		}
		if owner == 0 {
			f.clears = append(f.clears, sel)
		}
		f.owners[sel] = owner
	case opGetSelectionOwner:
		f.reply(nil, 0, f.owners[u32(b, 0)])
	case opConvertSelection:
		w, sel, target, prop := u32(b, 0), u32(b, 4), u32(b, 8), u32(b, 12)
		if f.owners[sel] == external && f.externalData != nil && f.names[target] == "UTF8_STRING" {
			f.props[[2]uint32{w, prop}] = f.externalData
			f.ptype[[2]uint32{w, prop}] = target
		} else {
			prop = 0
		}
		f.event(evSelectionNotify, 0, w, sel, target, prop)
	case opSendEvent:
		ev := append([]byte(nil), b[8:40]...)
		f.sent <- ev
	case opGetInputFocus:
		f.reply(nil, 0, root)
	}
}

// paste plays a client asking the owner for target, and returns what it
// got (nil when refused).
func (f *fakeX) paste(target string) []byte {
	f.mu.Lock()
	clip, tgt, prop := f.atom("CLIPBOARD"), f.atom(target), f.atom("PASTE")
	owner := f.owners[clip]
	f.event(evSelectionRequest, 0, owner, requestor, clip, tgt, prop)
	f.mu.Unlock()
	select {
	case ev := <-f.sent:
		if ev[0] != evSelectionNotify || u32(ev, 20) == 0 {
			return nil
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.props[[2]uint32{requestor, u32(ev, 20)}]
	case <-time.After(3 * time.Second):
		f.t.Fatal("the owner never answered")
		return nil
	}
}

func (f *fakeX) owner() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.owners[f.atoms["CLIPBOARD"]]
}

func dialFake(t *testing.T, path string) *Conn {
	nc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := setup(nc, "MIT-MAGIC-COOKIE-1", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

var secret = []Offer{
	{Target: "UTF8_STRING", Data: []byte("hunter2")},
	{Target: "text/plain;charset=utf-8", Data: []byte("hunter2")},
	{Target: "x-kde-passwordManagerHint", Data: []byte("secret")},
}

func waitOwned(t *testing.T, f *fakeX) {
	deadline := time.Now().Add(3 * time.Second)
	for f.owner() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the client never took the clipboard")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTheOwnerServesPastesAndLetsGoAtTheDeadline(t *testing.T) {
	f, path := newFakeX(t)
	c := dialFake(t, path)
	if f.auth != "MIT-MAGIC-COOKIE-1:0123456789abcdef" {
		t.Fatalf("the server saw auth %q", f.auth)
	}
	done := make(chan bool, 1)
	go func() {
		cleared, err := Serve(c, secret, 500*time.Millisecond, nil)
		if err != nil {
			t.Error(err)
		}
		done <- cleared
	}()
	waitOwned(t, f)
	if got := f.paste("UTF8_STRING"); string(got) != "hunter2" {
		t.Fatalf("pasted %q", got)
	}
	targets := f.paste("TARGETS")
	var names []string
	for i := 0; i+4 <= len(targets); i += 4 {
		f.mu.Lock()
		names = append(names, f.names[binary.LittleEndian.Uint32(targets[i:])])
		f.mu.Unlock()
	}
	if !strings.Contains(strings.Join(names, ","), "x-kde-passwordManagerHint") {
		t.Fatalf("TARGETS = %v", names)
	}
	// Clipboard managers ask to save the contents; that is refused.
	if got := f.paste("SAVE_TARGETS"); got != nil {
		t.Fatalf("SAVE_TARGETS was served: %q", got)
	}
	if !<-done {
		t.Fatal("the clipboard was not given up at the deadline")
	}
	f.mu.Lock()
	clears := len(f.clears)
	f.mu.Unlock()
	if clears != 1 || f.owner() != 0 {
		t.Fatalf("clears %d, owner %#x", clears, f.owner())
	}
}

func TestLosingTheSelectionEndsServingWithoutClearing(t *testing.T) {
	f, path := newFakeX(t)
	c := dialFake(t, path)
	done := make(chan bool, 1)
	go func() {
		cleared, _ := Serve(c, secret, 10*time.Second, nil)
		done <- cleared
	}()
	waitOwned(t, f)
	f.mu.Lock()
	clip := f.atoms["CLIPBOARD"]
	prev := f.owners[clip]
	f.owners[clip] = external
	f.event(evSelectionClear, f.now, prev, clip)
	f.mu.Unlock()
	select {
	case cleared := <-done:
		if cleared {
			t.Fatal("cleared another client's clipboard")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("still serving after losing the selection")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.clears) != 0 || f.owners[clip] != external {
		t.Fatal("the new owner's clipboard was touched")
	}
}

func TestTheClipboardCanBeReadFromAnotherOwner(t *testing.T) {
	f, path := newFakeX(t)
	f.mu.Lock()
	f.owners[f.atom("CLIPBOARD")] = external
	f.externalData = []byte("from elsewhere")
	f.mu.Unlock()
	c := dialFake(t, path)
	got, err := Read(c, "UTF8_STRING")
	if err != nil || string(got) != "from elsewhere" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if got, err := Read(c, "image/png"); err != nil || got != nil {
		t.Fatalf("an unoffered target: %q, %v", got, err)
	}
}

func TestDisplayNamesParse(t *testing.T) {
	for in, want := range map[string]Display{
		":0":             {Number: "0"},
		":1.0":           {Number: "1"},
		"unix:2":         {Host: "unix", Number: "2"},
		"example.org:10": {Host: "example.org", Number: "10"},
	} {
		if got, err := ParseDisplay(in); err != nil || got != want {
			t.Errorf("ParseDisplay(%q) = %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"nocolon", ":x"} {
		if _, err := ParseDisplay(bad); err == nil {
			t.Errorf("ParseDisplay(%q) accepted", bad)
		}
	}
}

func TestTheRightCookieIsPicked(t *testing.T) {
	host, _ := os.Hostname()
	var file bytes.Buffer
	entry := func(family uint16, addr, num, name, data string) {
		binary.Write(&file, binary.BigEndian, family)
		for _, s := range []string{addr, num, name, data} {
			binary.Write(&file, binary.BigEndian, uint16(len(s)))
			file.WriteString(s)
		}
	}
	entry(familyLocal, "otherhost", "0", "MIT-MAGIC-COOKIE-1", "wrong-host")
	entry(familyLocal, host, "1", "MIT-MAGIC-COOKIE-1", "wrong-number")
	entry(familyLocal, host, "0", "XDM-AUTHORIZATION-1", "wrong-kind")
	entry(familyLocal, host, "0", "MIT-MAGIC-COOKIE-1", "right")
	p := filepath.Join(t.TempDir(), "xauth")
	os.WriteFile(p, file.Bytes(), 0o600)
	t.Setenv("XAUTHORITY", p)
	name, data := findCookie(Display{Number: "0"})
	if name != "MIT-MAGIC-COOKIE-1" || string(data) != "right" {
		t.Fatalf("picked %q %q", name, data)
	}
	if _, data := findCookie(Display{Number: "7"}); data != nil {
		t.Fatalf("a cookie for display 7: %q", data)
	}
}
