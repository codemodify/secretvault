// Package udiskstest plays UDisks2 on a private bus, for tests of the code
// that mounts containers. Nothing it does reaches the real system: its
// "loop devices" are the files it is handed, its unlocking opens the LUKS2
// header with svluks (so a wrong key, or a key passed the wrong way, fails
// as it would), "formatting" writes a marker into the decrypted data, and
// "mounting" makes an empty directory.
package udiskstest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svudisks"
)

const blockDevices = svdbus.ObjectPath("/org/freedesktop/UDisks2/block_devices")

// Fake is the pretend UDisks2.
type Fake struct {
	// Addr is the private bus, which DBUS_SYSTEM_BUS_ADDRESS names for the
	// rest of the test.
	Addr string

	// MountDir is where mount points are made.
	MountDir string

	bus   *svdbus.Conn
	mu    sync.Mutex
	loops map[svdbus.ObjectPath]*loop
	next  int
	calls []string
	fail  map[string]*svdbus.Error
	auto  bool
}

type loop struct {
	n       int
	file    *os.File
	backing string
	uid     uint32
	clear   *cleartext
}

type cleartext struct {
	vol           *svluks.Volume
	fstype, label string
	owned         bool
	mountPoint    string
	mountOptions  string
}

// Start starts a private bus with the fake UDisks2 on it.
func Start(t *testing.T) *Fake {
	t.Helper()
	f := &Fake{Addr: dbustest.PrivateBus(t), MountDir: t.TempDir(), loops: map[svdbus.ObjectPath]*loop{}, fail: map[string]*svdbus.Error{}}
	bus, err := svdbus.Connect(f.Addr)
	if err != nil {
		t.Fatal(err)
	}
	f.bus = bus
	t.Cleanup(func() {
		bus.Close()
		f.mu.Lock()
		for _, l := range f.loops {
			l.file.Close()
		}
		f.mu.Unlock()
	})
	err = bus.Export(svudisks.RootPath, &svdbus.Interface{
		Name: "org.freedesktop.DBus.ObjectManager",
		Methods: []*svdbus.Method{{Name: "GetManagedObjects", Out: []svdbus.Arg{{Name: "objects", Type: "a{oa{sa{sv}}}"}},
			Handler: func(context.Context, *svdbus.Call) ([]any, error) { return []any{f.objects()}, nil }}},
	})
	if err == nil {
		err = bus.Export(svudisks.ManagerPath, &svdbus.Interface{
			Name: svudisks.IfaceManager,
			Methods: []*svdbus.Method{{Name: "LoopSetup", In: []svdbus.Arg{{Name: "fd", Type: "h"}, {Name: "options", Type: "a{sv}"}},
				Out: []svdbus.Arg{{Name: "resulting_device", Type: "o"}}, Handler: f.loopSetup}},
		})
	}
	if err == nil {
		err = bus.ExportSubtree(blockDevices, svdbus.Subtree{Lookup: f.lookup})
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := bus.RequestName(ctx, svudisks.Service, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

// Fail makes every later call of method (LoopSetup, Unlock, Format, Mount,
// Unmount, Lock, Delete) fail with the named error; name "" stops that.
func (f *Fake) Fail(method, name, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == "" {
		delete(f.fail, method)
		return
	}
	f.fail[method] = svdbus.NewError(name, message)
}

// Calls lists the calls made, as "Method" or "Method(detail)".
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// State is one attached image, as a test sees it.
type State struct {
	Backing      string
	Unlocked     bool
	FSType       string
	Label        string
	Owned        bool // formatted with take-ownership
	MountPoint   string
	MountOptions string
}

// Attached lists the images attached as loop devices.
func (f *Fake) Attached() []State {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []State
	for _, l := range f.loops {
		s := State{Backing: l.backing}
		if c := l.clear; c != nil {
			s.Unlocked, s.FSType, s.Label, s.Owned, s.MountPoint, s.MountOptions = true, c.fstype, c.label, c.owned, c.mountPoint, c.mountOptions
		}
		out = append(out, s)
	}
	return out
}

// begin records a call and returns the error the test asked for, if any.
// f.mu must be held.
func (f *Fake) begin(method, detail string) error {
	if detail != "" {
		method += "(" + detail + ")"
	}
	f.calls = append(f.calls, method)
	if e := f.fail[strings.SplitN(method, "(", 2)[0]]; e != nil {
		return e
	}
	return nil
}

func failed(format string, args ...any) error {
	return svdbus.NewError(svudisks.ErrorFailed, fmt.Sprintf(format, args...))
}

func loopPath(n int) svdbus.ObjectPath {
	return blockDevices + svdbus.ObjectPath(fmt.Sprintf("/loop%d", n))
}
func clearPath(n int) svdbus.ObjectPath {
	return blockDevices + svdbus.ObjectPath(fmt.Sprintf("/dm_2d%d", n))
}

func (f *Fake) loopSetup(_ context.Context, call *svdbus.Call) ([]any, error) {
	var fd svdbus.UnixFD
	var opts map[string]svdbus.Variant
	if err := call.Decode(&fd, &opts); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "image")
	backing, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		file.Close()
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("LoopSetup", filepath.Base(backing)); err != nil {
		file.Close()
		return nil, err
	}
	l := &loop{n: f.next, file: file, backing: backing, uid: uint32(os.Getuid())}
	f.next++
	f.loops[loopPath(l.n)] = l
	return []any{loopPath(l.n)}, nil
}

// find is the loop device at path, or the one whose cleartext device is
// at path. f.mu must be held.
func (f *Fake) find(path svdbus.ObjectPath) (*loop, bool) {
	if l, ok := f.loops[path]; ok {
		return l, false
	}
	for _, l := range f.loops {
		if l.clear != nil && clearPath(l.n) == path {
			return l, true
		}
	}
	return nil, false
}

// marker is what "formatting" writes at the start of the decrypted data.
const marker = "udiskstest-fs\x00"

func (f *Fake) lookup(path svdbus.ObjectPath) []*svdbus.Interface {
	f.mu.Lock()
	l, isClear := f.find(path)
	f.mu.Unlock()
	if l == nil {
		return nil
	}
	opts := svdbus.Arg{Name: "options", Type: "a{sv}"}
	method := func(name string, in []svdbus.Arg, out []svdbus.Arg, h svdbus.MethodHandler) *svdbus.Method {
		return &svdbus.Method{Name: name, In: in, Out: out, Handler: h}
	}
	if !isClear {
		return []*svdbus.Interface{
			{Name: svudisks.IfaceLoop, Methods: []*svdbus.Method{method("Delete", []svdbus.Arg{opts}, nil, f.handler(path, f.delete))}},
			{Name: svudisks.IfaceEncrypted, Methods: []*svdbus.Method{
				method("Unlock", []svdbus.Arg{{Name: "passphrase", Type: "s"}, opts}, []svdbus.Arg{{Name: "cleartext_device", Type: "o"}}, f.handler(path, f.unlock)),
				method("Lock", []svdbus.Arg{opts}, nil, f.handler(path, f.lock)),
			}},
			{Name: svudisks.IfaceBlock},
		}
	}
	ifaces := []*svdbus.Interface{{Name: svudisks.IfaceBlock, Methods: []*svdbus.Method{
		method("Format", []svdbus.Arg{{Name: "type", Type: "s"}, opts}, nil, f.handler(path, f.format)),
	}}}
	f.mu.Lock()
	formatted := l.clear != nil && l.clear.fstype != ""
	f.mu.Unlock()
	if formatted {
		ifaces = append(ifaces, &svdbus.Interface{Name: svudisks.IfaceFilesystem, Methods: []*svdbus.Method{
			method("Mount", []svdbus.Arg{opts}, []svdbus.Arg{{Name: "mount_path", Type: "s"}}, f.handler(path, f.mount)),
			method("Unmount", []svdbus.Arg{opts}, nil, f.handler(path, f.unmount)),
		}})
	}
	return ifaces
}

// handler serves a method of the device at path under f.mu.
func (f *Fake) handler(path svdbus.ObjectPath, h func(l *loop, call *svdbus.Call) ([]any, error)) svdbus.MethodHandler {
	return func(_ context.Context, call *svdbus.Call) ([]any, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		l, _ := f.find(path)
		if l == nil {
			return nil, svdbus.NewError(svdbus.ErrorUnknownObject, "no such device")
		}
		return h(l, call)
	}
}

func (f *Fake) unlock(l *loop, call *svdbus.Call) ([]any, error) {
	var pass string
	var opts map[string]svdbus.Variant
	if err := call.Decode(&pass, &opts); err != nil {
		return nil, err
	}
	if err := f.begin("Unlock", ""); err != nil {
		return nil, err
	}
	if l.clear != nil {
		return nil, failed("Device /dev/loop%d is already unlocked", l.n)
	}
	kf, ok := opts["keyfile_contents"]
	if pass != "" || !ok || kf.Signature != "ay" {
		return nil, failed("udiskstest: the key must come as keyfile_contents (ay) with an empty passphrase; got passphrase %q, options %v", pass, opts)
	}
	key := kf.Value.([]byte)
	h, err := svluks.Read(l.file)
	if err != nil {
		return nil, failed("Error unlocking /dev/loop%d: %v", l.n, err)
	}
	vk, _, err := h.Unlock(l.file, key)
	if err != nil {
		return nil, failed("Error unlocking /dev/loop%d: Failed to activate device: Operation not permitted", l.n)
	}
	defer vk.Destroy()
	vol, err := h.Volume(l.file, vk)
	if err != nil {
		return nil, failed("%v", err)
	}
	c := &cleartext{vol: vol}
	head := make([]byte, 128)
	vol.ReadAt(head, 0)
	if rest, ok := bytes.CutPrefix(head, []byte(marker)); ok {
		// fstype NUL label NUL, then whatever the sector held before.
		if fields := strings.SplitN(string(rest), "\x00", 3); len(fields) == 3 {
			c.fstype, c.label = fields[0], fields[1]
		}
	}
	l.clear = c
	if f.auto && c.fstype != "" {
		f.mountAt(l, "")
	}
	return []any{clearPath(l.n)}, nil
}

func (f *Fake) lock(l *loop, call *svdbus.Call) ([]any, error) {
	if err := f.begin("Lock", ""); err != nil {
		return nil, err
	}
	if l.clear == nil {
		return nil, failed("Device /dev/loop%d is not unlocked", l.n)
	}
	if l.clear.mountPoint != "" {
		return nil, svdbus.NewError(svudisks.ErrorDeviceBusy, fmt.Sprintf("Cannot lock /dev/loop%d: the cleartext device is mounted", l.n))
	}
	l.clear.vol.Close()
	l.clear = nil
	return nil, nil
}

func (f *Fake) delete(l *loop, call *svdbus.Call) ([]any, error) {
	if err := f.begin("Delete", ""); err != nil {
		return nil, err
	}
	if l.clear != nil {
		return nil, svdbus.NewError(svudisks.ErrorDeviceBusy, fmt.Sprintf("Error deleting /dev/loop%d: device is busy", l.n))
	}
	l.file.Close()
	delete(f.loops, loopPath(l.n))
	return nil, nil
}

func (f *Fake) format(l *loop, call *svdbus.Call) ([]any, error) {
	var fstype string
	var opts map[string]svdbus.Variant
	if err := call.Decode(&fstype, &opts); err != nil {
		return nil, err
	}
	if err := f.begin("Format", fstype); err != nil {
		return nil, err
	}
	switch fstype {
	case "ext4", "exfat", "vfat", "btrfs", "xfs":
	default:
		return nil, svdbus.NewError(svudisks.ErrorNotSupported, "Don't know how to make a "+fstype+" filesystem")
	}
	var label string
	var owned bool
	if v, ok := opts["label"]; ok && v.Store(&label) != nil {
		return nil, failed("label is not a string")
	}
	if v, ok := opts["take-ownership"]; ok && v.Store(&owned) != nil {
		return nil, failed("take-ownership is not a boolean")
	}
	if owned && (fstype == "vfat" || fstype == "exfat") {
		return nil, failed("udiskstest: %s has no owners to take", fstype)
	}
	if l.clear.mountPoint != "" {
		return nil, svdbus.NewError(svudisks.ErrorDeviceBusy, "the device is mounted")
	}
	if _, err := l.clear.vol.WriteAt([]byte(marker+fstype+"\x00"+label+"\x00"), 0); err != nil {
		return nil, failed("%v", err)
	}
	l.clear.fstype, l.clear.label, l.clear.owned = fstype, label, owned
	if f.auto {
		f.mountAt(l, "")
	}
	return nil, nil
}

func (f *Fake) mount(l *loop, call *svdbus.Call) ([]any, error) {
	var opts map[string]svdbus.Variant
	if err := call.Decode(&opts); err != nil {
		return nil, err
	}
	var options string
	if v, ok := opts["options"]; ok {
		v.Store(&options)
	}
	if err := f.begin("Mount", options); err != nil {
		return nil, err
	}
	if mp := l.clear.mountPoint; mp != "" {
		return nil, svdbus.NewError(svudisks.ErrorAlreadyMounted, "Device is already mounted at `"+mp+"'.")
	}
	if err := f.mountAt(l, options); err != nil {
		return nil, err
	}
	return []any{l.clear.mountPoint}, nil
}

// mountAt "mounts" l's filesystem. f.mu must be held.
func (f *Fake) mountAt(l *loop, options string) error {
	c := l.clear
	name := c.label
	if name == "" {
		name = fmt.Sprintf("dm-%d", l.n)
	}
	mp := filepath.Join(f.MountDir, name)
	if err := os.MkdirAll(mp, 0o700); err != nil {
		return failed("%v", err)
	}
	c.mountPoint, c.mountOptions = mp, options
	return nil
}

// Automount makes the fake mount a filesystem as soon as it is made or
// unlocked, as a desktop's automounter (gvfs, udiskie) would.
func (f *Fake) Automount(on bool) {
	f.mu.Lock()
	f.auto = on
	f.mu.Unlock()
}

func (f *Fake) unmount(l *loop, call *svdbus.Call) ([]any, error) {
	if err := f.begin("Unmount", ""); err != nil {
		return nil, err
	}
	c := l.clear
	if c.mountPoint == "" {
		return nil, svdbus.NewError(svudisks.ErrorNotMounted, "Device is not mounted")
	}
	os.Remove(c.mountPoint)
	c.mountPoint, c.mountOptions = "", ""
	return nil, nil
}

// objects answers GetManagedObjects.
func (f *Fake) objects() map[svdbus.ObjectPath]map[string]map[string]svdbus.Variant {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := svdbus.MakeVariant
	dev := func(s string) svdbus.Variant { return v(append([]byte(s), 0)) }
	out := map[svdbus.ObjectPath]map[string]map[string]svdbus.Variant{}
	for path, l := range f.loops {
		cleartext := svdbus.ObjectPath("/")
		if l.clear != nil {
			cleartext = clearPath(l.n)
		}
		out[path] = map[string]map[string]svdbus.Variant{
			svudisks.IfaceBlock: {"Device": dev(fmt.Sprintf("/dev/loop%d", l.n)), "CryptoBackingDevice": v(svdbus.ObjectPath("/")),
				"IdUsage": v("crypto"), "IdType": v("crypto_LUKS")},
			svudisks.IfaceLoop:      {"BackingFile": dev(l.backing), "SetupByUID": v(l.uid)},
			svudisks.IfaceEncrypted: {"CleartextDevice": v(cleartext)},
		}
		if c := l.clear; c != nil {
			usage := ""
			if c.fstype != "" {
				usage = "filesystem"
			}
			ifaces := map[string]map[string]svdbus.Variant{
				svudisks.IfaceBlock: {"Device": dev(fmt.Sprintf("/dev/dm-%d", l.n)), "CryptoBackingDevice": v(path),
					"IdUsage": v(usage), "IdType": v(c.fstype), "IdLabel": v(c.label)},
			}
			if c.fstype != "" {
				mps := [][]byte{}
				if c.mountPoint != "" {
					mps = append(mps, append([]byte(c.mountPoint), 0))
				}
				ifaces[svudisks.IfaceFilesystem] = map[string]svdbus.Variant{"MountPoints": v(mps)}
			}
			out[clearPath(l.n)] = ifaces
		}
	}
	return out
}

// ErrNoSuchImage is a State asked for an image that is not attached.
var ErrNoSuchImage = errors.New("udiskstest: that image is not attached")

// Image is the state of the image at path.
func (f *Fake) Image(path string) (State, error) {
	for _, s := range f.Attached() {
		if s.Backing == path {
			return s, nil
		}
	}
	return State{}, ErrNoSuchImage
}
