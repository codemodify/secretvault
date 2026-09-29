//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package svdbus

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests run against a private dbus-daemon each test starts for
// itself. They never touch the desktop's session or system bus: every
// connection goes to the address the private daemon prints, and the one
// test of ConnectSession points the environment at that daemon first.

// privateBus starts a dbus-daemon of our own, with no service directory
// (nothing can be activated) and a policy that allows everything, and
// returns its address.
func privateBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		if _, serr := os.Stat("/usr/bin/dbus-daemon"); serr != nil {
			t.Skip("dbus-daemon is not installed")
		}
		daemon = "/usr/bin/dbus-daemon"
	}
	// A short directory: socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "svdbus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	conf := filepath.Join(dir, "bus.conf")
	err = os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=`+dir+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--print-address")
	cmd.Env = isolatedEnv("")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		lines <- strings.TrimSpace(line)
		io.Copy(io.Discard, out)
	}()
	select {
	case addr := <-lines:
		if !strings.HasPrefix(addr, "unix:") {
			t.Fatalf("the private bus printed %q", addr)
		}
		return addr
	case <-time.After(10 * time.Second):
		t.Fatal("the private bus did not start")
	}
	return ""
}

// isolatedEnv is the environment for child processes: every bus address
// points at the private bus, never at the desktop's.
func isolatedEnv(addr string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DBUS_SESSION_BUS_ADDRESS=") || strings.HasPrefix(kv, "DBUS_SYSTEM_BUS_ADDRESS=") ||
			strings.HasPrefix(kv, "DBUS_STARTER_") {
			continue
		}
		env = append(env, kv)
	}
	if addr == "" {
		addr = "unix:path=/nonexistent/svdbus-test"
	}
	return append(env, "DBUS_SESSION_BUS_ADDRESS="+addr, "DBUS_SYSTEM_BUS_ADDRESS="+addr)
}

func dial(t *testing.T, addr string, opts ...Option) *Conn {
	t.Helper()
	c, err := Connect(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func receive(t *testing.T, ch <-chan *Message) *Message {
	t.Helper()
	select {
	case m, ok := <-ch:
		if !ok {
			t.Fatal("the subscription closed")
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no signal arrived")
	}
	return nil
}

func quiet(t *testing.T, ch <-chan *Message) {
	t.Helper()
	select {
	case m := <-ch:
		t.Fatalf("unexpected signal %v %v", m, m.Body)
	case <-time.After(150 * time.Millisecond):
	}
}

func dbusError(t *testing.T, err error, name string) *Error {
	t.Helper()
	var de *Error
	if !errors.As(err, &de) || de.Name != name {
		t.Fatalf("got %v, want the D-Bus error %s", err, name)
	}
	return de
}

const echoPath = ObjectPath("/com/example/Echo")

type item struct {
	Label string
	Attrs map[string]Variant
}

// echo is the interface most tests export.
func echo(extra ...*Method) *Interface {
	methods := []*Method{
		{
			Name: "Echo", In: []Arg{{"text", "s"}}, Out: []Arg{{"text", "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var s string
				if err := call.Decode(&s); err != nil {
					return nil, err
				}
				return []any{s}, nil
			},
		},
		{
			Name: "Add", In: []Arg{{"a", "i"}, {"b", "i"}}, Out: []Arg{{"sum", "i"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var a, b int32
				if err := call.Decode(&a, &b); err != nil {
					return nil, err
				}
				return []any{a + b}, nil
			},
		},
		{
			Name: "Describe", In: []Arg{{"item", "(sa{sv})"}}, Out: []Arg{{"label", "s"}, {"count", "u"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var it item
				if err := call.Decode(&it); err != nil {
					return nil, err
				}
				return []any{it.Label, len(it.Attrs)}, nil // an int, encoded as the declared u
			},
		},
		{
			Name: "Count", In: []Arg{{"dict", "a{ss}"}}, Out: []Arg{{"n", "u"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var m map[string]string
				if err := call.Decode(&m); err != nil {
					return nil, err
				}
				return []any{uint32(len(m))}, nil
			},
		},
		{
			Name: "Fail",
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				return nil, NewError("com.example.Error.Nope", "nope")
			},
		},
		{
			Name: "FailPlain",
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				return nil, errors.New("plain failure")
			},
		},
		{
			Name: "Panic",
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				panic("handler bug")
			},
		},
		{
			Name: "BadReply", Out: []Arg{{"n", "u"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				return []any{"not a number"}, nil
			},
		},
		{
			Name: "CallerPID", Out: []Arg{{"pid", "u"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				// A handler calling out on its own connection.
				pid, err := call.Conn.GetConnectionUnixProcessID(ctx, call.Sender())
				return []any{pid}, err
			},
		},
		{
			Name: "Relay", In: []Arg{{"text", "s"}}, Out: []Arg{{"text", "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				// A handler calling its own object back through the bus.
				var s string
				call.Decode(&s)
				r, err := call.Conn.Call(ctx, call.Conn.UniqueName(), echoPath, "com.example.Echo", "Echo", "relayed "+s)
				if err != nil {
					return nil, err
				}
				return r.Body, nil
			},
		},
	}
	return &Interface{
		Name:    "com.example.Echo",
		Methods: append(methods, extra...),
		Signals: []*Signal{{Name: "Poked", Args: []Arg{{"what", "s"}, {"n", "u"}}}},
	}
}

func TestTwoConnectionsCallEachOther(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	if err := a.Export(echoPath, echo()); err != nil {
		t.Fatal(err)
	}
	if err := b.Export("/com/example/Other", echo()); err != nil {
		t.Fatal(err)
	}
	if a.UniqueName() == "" || a.UniqueName() == b.UniqueName() || !strings.HasPrefix(a.UniqueName(), ":") {
		t.Fatalf("unique names %q and %q", a.UniqueName(), b.UniqueName())
	}

	r, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", "héllo")
	if err != nil || !reflect.DeepEqual(r.Body, []any{"héllo"}) {
		t.Fatalf("Echo = %v, %v", r, err)
	}
	var sum int32
	r, err = a.Call(ctx, b.UniqueName(), "/com/example/Other", "com.example.Echo", "Add", int32(40), int32(2))
	if err != nil || r.Decode(&sum) != nil || sum != 42 {
		t.Fatalf("Add = %v, %v", sum, err)
	}
	r, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Describe",
		item{"login", map[string]Variant{"user": MakeVariant("ada"), "port": MakeVariant(uint16(993))}})
	if err != nil || !reflect.DeepEqual(r.Body, []any{"login", uint32(2)}) {
		t.Fatalf("Describe = %v %v, %v", r, r.Body, err)
	}
	// With no interface named, the method is found by name.
	r, err = b.Call(ctx, a.UniqueName(), echoPath, "", "Echo", "any")
	if err != nil || r.Body[0] != "any" {
		t.Fatalf("Echo without an interface = %v, %v", r, err)
	}

	// Errors, from handlers and from dispatch.
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Fail")
	if de := dbusError(t, err, "com.example.Error.Nope"); de.Message() != "nope" {
		t.Fatalf("message %q", de.Message())
	}
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "FailPlain")
	if de := dbusError(t, err, ErrorFailed); de.Message() != "plain failure" {
		t.Fatalf("message %q", de.Message())
	}
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Panic")
	dbusError(t, err, ErrorFailed)
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "BadReply")
	dbusError(t, err, ErrorFailed)
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", int32(1))
	dbusError(t, err, ErrorInvalidArgs)
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Nope")
	dbusError(t, err, ErrorUnknownMethod)
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Nope", "Echo", "x")
	dbusError(t, err, ErrorUnknownInterface)
	_, err = b.Call(ctx, a.UniqueName(), "/com/example/Nope", "com.example.Echo", "Echo", "x")
	dbusError(t, err, ErrorUnknownObject)
	_, err = b.Call(ctx, "com.example.NobodyHere", echoPath, "com.example.Echo", "Echo", "x")
	dbusError(t, err, ErrorServiceUnknown)

	// Peer works on any path, even one with no object.
	if _, err := b.Call(ctx, a.UniqueName(), "/no/object/here", "org.freedesktop.DBus.Peer", "Ping"); err != nil {
		t.Fatalf("Ping = %v", err)
	}
	if id, err := MachineID(); err == nil {
		r, err := b.Call(ctx, a.UniqueName(), "/", "org.freedesktop.DBus.Peer", "GetMachineId")
		if err != nil || r.Body[0] != id {
			t.Fatalf("GetMachineId = %v, %v; want %s", r, err, id)
		}
	}

	// Unexporting takes the object away.
	a.Unexport(echoPath)
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", "x")
	dbusError(t, err, ErrorUnknownObject)
}

func TestExportRefusesBadDescriptions(t *testing.T) {
	addr := privateBus(t)
	a := dial(t, addr)
	h := func(ctx context.Context, call *Call) ([]any, error) { return nil, nil }
	bad := []*Interface{
		nil,
		{Name: "noDots"},
		{Name: "org.freedesktop.DBus.Properties"},
		{Name: "a.b", Methods: []*Method{{Name: "M"}}},
		{Name: "a.b", Methods: []*Method{{Name: "1M", Handler: h}}},
		{Name: "a.b", Methods: []*Method{{Name: "M", Handler: h}, {Name: "M", Handler: h}}},
		{Name: "a.b", Methods: []*Method{{Name: "M", In: []Arg{{"x", "ii"}}, Handler: h}}},
		{Name: "a.b", Properties: []*Property{{Name: "P", Type: "s"}}},
		{Name: "a.b", Properties: []*Property{{Name: "P", Type: "", Get: func(context.Context, *Call) (any, error) { return nil, nil }}}},
		{Name: "a.b", Signals: []*Signal{{Name: "S", Args: []Arg{{"x", "a"}}}}},
	}
	for _, i := range bad {
		if err := a.Export("/x", i); !errors.Is(err, ErrInvalid) {
			t.Errorf("exported %+v: %v", i, err)
		}
	}
	if err := a.Export("x", &Interface{Name: "a.b"}); !errors.Is(err, ErrInvalid) {
		t.Error("exported at a relative path")
	}
	if err := a.ExportSubtree("/x", Subtree{}); !errors.Is(err, ErrInvalid) {
		t.Error("exported a subtree without Lookup")
	}
}

func TestHandlersCanCallOutOnTheirOwnConnection(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	a.Export(echoPath, echo())
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var pid uint32
			r, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "CallerPID")
			if err != nil || r.Decode(&pid) != nil || int(pid) != os.Getpid() {
				t.Errorf("CallerPID = %d, %v", pid, err)
			}
			r, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Relay", fmt.Sprint(i))
			if err != nil || r.Body[0] != fmt.Sprintf("relayed %d", i) {
				t.Errorf("Relay = %v, %v", r, err)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentCallsEachGetTheirOwnReply(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	a.Export(echoPath, echo())
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 25 {
				want := fmt.Sprintf("%d/%d/%s", i, j, strings.Repeat("x", i*j))
				r, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", want)
				if err != nil || r.Body[0] != want {
					t.Errorf("Echo(%q) = %v, %v", want, r, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSignalsReachTheSubscriptionsTheyMatch(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	a.Export(echoPath, echo())

	yes, err := b.Subscribe(ctx, MatchRule{Interface: "com.example.Echo", Member: "Poked", Args: map[int]string{0: "yes"}})
	if err != nil {
		t.Fatal(err)
	}
	no, err := b.Subscribe(ctx, MatchRule{Interface: "com.example.Echo", Member: "Poked", Args: map[int]string{0: "no"}})
	if err != nil {
		t.Fatal(err)
	}
	all, err := b.Subscribe(ctx, MatchRule{PathNamespace: "/com/example"})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var viaFunc []string
	got := make(chan struct{}, 10)
	fn, err := b.SubscribeFunc(ctx, MatchRule{Interface: "com.example.Echo", Member: "Poked"}, func(m *Message) {
		// A callback may call out on the connection.
		if _, err := m.Body[0].(string); !err {
			return
		}
		if _, err := b.ListNames(ctx); err != nil {
			t.Error(err)
		}
		mu.Lock()
		viaFunc = append(viaFunc, m.Body[0].(string))
		mu.Unlock()
		got <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}

	for i, what := range []string{"no", "yes", "no", "yes"} {
		if err := a.Emit(echoPath, "com.example.Echo", "Poked", what, i); err != nil { // i encodes as the declared u
			t.Fatal(err)
		}
	}
	for _, want := range []uint32{1, 3} {
		m := receive(t, yes.C)
		if m.Sender != a.UniqueName() || m.Path != echoPath || !reflect.DeepEqual(m.Body, []any{"yes", want}) {
			t.Fatalf("yes got %v %v", m, m.Body)
		}
	}
	for _, want := range []uint32{0, 2} {
		if m := receive(t, no.C); !reflect.DeepEqual(m.Body, []any{"no", want}) {
			t.Fatalf("no got %v", m.Body)
		}
	}
	for i := range 4 {
		if m := receive(t, all.C); m.Body[1] != uint32(i) {
			t.Fatalf("all got %v", m.Body)
		}
	}
	for range 4 {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("the callback was not called")
		}
	}
	mu.Lock()
	if !slices.Equal(viaFunc, []string{"no", "yes", "no", "yes"}) {
		t.Fatalf("the callback saw %q", viaFunc)
	}
	mu.Unlock()
	quiet(t, yes.C)
	quiet(t, no.C)

	// A signal outside the namespace misses that subscription only.
	a.Emit("/elsewhere", "com.example.Echo", "Poked", "yes", uint32(9))
	if m := receive(t, yes.C); m.Path != "/elsewhere" {
		t.Fatalf("yes got %v", m)
	}
	quiet(t, all.C)

	// A closed subscription stops and closes its channel.
	if err := yes.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-yes.C; ok {
		t.Fatal("a closed subscription's channel is open")
	}
	a.Emit(echoPath, "com.example.Echo", "Poked", "yes", uint32(5))
	if m := receive(t, all.C); m.Body[0] != "yes" {
		t.Fatalf("all got %v", m.Body)
	}
	fn.Close()
	no.Close()
	all.Close()

	// Unicast signals go only to their destination.
	c := dial(t, addr)
	toC, _ := c.Subscribe(ctx, MatchRule{Member: "Direct"})
	toB, _ := b.Subscribe(ctx, MatchRule{Member: "Direct"})
	if err := a.EmitTo(c.UniqueName(), echoPath, "com.example.Echo", "Direct", "psst"); err != nil {
		t.Fatal(err)
	}
	if m := receive(t, toC.C); m.Body[0] != "psst" || m.Destination != c.UniqueName() {
		t.Fatalf("unicast got %v", m)
	}
	quiet(t, toB.C)
}

func TestASenderNamedByWellKnownNameIsFollowedToItsOwner(t *testing.T) {
	addr := privateBus(t)
	a, b, c := dial(t, addr), dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	const name = "com.example.Sender"
	if r, err := a.RequestName(ctx, name, 0); err != nil || r != RequestNamePrimaryOwner {
		t.Fatalf("RequestName = %v, %v", r, err)
	}
	// Everything from com.example.Echo, so the bus sends both a's and c's
	// signals here; the second subscription must still take only the
	// owner's.
	any, err := b.Subscribe(ctx, MatchRule{Interface: "com.example.Echo"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := b.Subscribe(ctx, MatchRule{Sender: name, Interface: "com.example.Echo"})
	if err != nil {
		t.Fatal(err)
	}
	c.Emit(echoPath, "com.example.Echo", "Poked", "from c", uint32(0))
	a.Emit(echoPath, "com.example.Echo", "Poked", "from a", uint32(0))
	if m := receive(t, any.C); m.Body[0] != "from c" {
		t.Fatalf("got %v", m.Body)
	}
	if m := receive(t, any.C); m.Body[0] != "from a" {
		t.Fatalf("got %v", m.Body)
	}
	if m := receive(t, owner.C); m.Body[0] != "from a" {
		t.Fatalf("the owner's subscription got %v", m.Body)
	}
	quiet(t, owner.C)

	// The name moves to c; so does the subscription.
	if r, err := a.ReleaseName(ctx, name); err != nil || r != ReleaseNameReleased {
		t.Fatalf("ReleaseName = %v, %v", r, err)
	}
	if r, err := c.RequestName(ctx, name, 0); err != nil || r != RequestNamePrimaryOwner {
		t.Fatalf("RequestName = %v, %v", r, err)
	}
	a.Emit(echoPath, "com.example.Echo", "Poked", "from a", uint32(1))
	c.Emit(echoPath, "com.example.Echo", "Poked", "from c", uint32(1))
	if m := receive(t, owner.C); m.Body[0] != "from c" {
		t.Fatalf("after the move the subscription got %v", m.Body)
	}
	quiet(t, owner.C)
}

func TestNamesCanBeOwnedQueuedAndTakenOver(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	const name = "com.example.Owned"
	lost, err := a.Subscribe(ctx, MatchRule{Sender: BusName, Interface: BusInterface, Member: "NameLost"})
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := a.Subscribe(ctx, MatchRule{Sender: BusName, Interface: BusInterface, Member: "NameAcquired", Args: map[int]string{0: name}})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := a.RequestName(ctx, name, NameAllowReplacement); err != nil || r != RequestNamePrimaryOwner {
		t.Fatalf("RequestName = %v, %v", r, err)
	}
	if !slices.Contains(a.Names(), name) || !slices.Contains(a.Names(), a.UniqueName()) {
		t.Fatalf("a owns %q", a.Names())
	}
	receive(t, acquired.C)
	// Asking again restates the flags, so replacement stays allowed.
	if r, err := a.RequestName(ctx, name, NameAllowReplacement); err != nil || r != RequestNameAlreadyOwner {
		t.Fatalf("RequestName again = %v, %v", r, err)
	}
	if r, err := b.RequestName(ctx, name, NameDoNotQueue); err != nil || r != RequestNameExists {
		t.Fatalf("RequestName without queueing = %v, %v", r, err)
	}
	if r, err := b.RequestName(ctx, name, NameReplaceExisting|NameDoNotQueue); err != nil || r != RequestNamePrimaryOwner {
		t.Fatalf("RequestName replacing = %v, %v", r, err)
	}
	if m := receive(t, lost.C); m.Body[0] != name {
		t.Fatalf("NameLost for %v", m.Body)
	}
	if slices.Contains(a.Names(), name) || !slices.Contains(b.Names(), name) {
		t.Fatalf("after the takeover a owns %q and b %q", a.Names(), b.Names())
	}
	if owner, err := a.GetNameOwner(ctx, name); err != nil || owner != b.UniqueName() {
		t.Fatalf("GetNameOwner = %q, %v", owner, err)
	}

	// b did not allow replacement, so a queues, and gets the name when b
	// lets go.
	if r, err := a.RequestName(ctx, name, NameReplaceExisting); err != nil || r != RequestNameInQueue {
		t.Fatalf("RequestName queueing = %v, %v", r, err)
	}
	if r, err := b.ReleaseName(ctx, name); err != nil || r != ReleaseNameReleased {
		t.Fatalf("ReleaseName = %v, %v", r, err)
	}
	receive(t, acquired.C)
	if !slices.Contains(a.Names(), name) || slices.Contains(b.Names(), name) {
		t.Fatalf("after the release a owns %q and b %q", a.Names(), b.Names())
	}
	if r, err := b.ReleaseName(ctx, name); err != nil || r != ReleaseNameNotOwner {
		t.Fatalf("ReleaseName of a's name = %v, %v", r, err)
	}
	if r, err := b.ReleaseName(ctx, "com.example.NeverOwned"); err != nil || r != ReleaseNameNonExistent {
		t.Fatalf("ReleaseName of nobody's name = %v, %v", r, err)
	}
	if _, err := a.RequestName(ctx, ":1.1", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("requested a unique name: %v", err)
	}
}

func TestPropertiesAreServedAndChangesAnnounced(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	var mu sync.Mutex
	label, token := "initial", ""
	get := func(v *string) func(context.Context, *Call) (any, error) {
		return func(context.Context, *Call) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			return *v, nil
		}
	}
	set := func(v *string) func(context.Context, *Call, Variant) error {
		return func(_ context.Context, _ *Call, val Variant) error {
			mu.Lock()
			defer mu.Unlock()
			return val.Store(v)
		}
	}
	props := &Interface{
		Name: "com.example.Props",
		Properties: []*Property{
			{Name: "Version", Type: "s", Get: func(context.Context, *Call) (any, error) { return "1.0", nil }, EmitsChanged: EmitsChangedConst},
			{Name: "Label", Type: "s", Get: get(&label), Set: set(&label)},
			{Name: "Count", Type: "u", Get: func(context.Context, *Call) (any, error) { return 7, nil }},
			{Name: "Token", Type: "s", Set: set(&token), EmitsChanged: EmitsChangedInvalidates},
			{Name: "Attrs", Type: "a{ss}", Get: func(context.Context, *Call) (any, error) {
				return map[string]string{"k": "v"}, nil
			}},
		},
	}
	if err := a.Export(echoPath, echo(), props); err != nil {
		t.Fatal(err)
	}
	dest := a.UniqueName()
	v, err := b.GetProperty(ctx, dest, echoPath, "com.example.Props", "Version")
	if err != nil || v != (Variant{"s", "1.0"}) {
		t.Fatalf("Get Version = %v, %v", v, err)
	}
	all, err := b.GetAllProperties(ctx, dest, echoPath, "com.example.Props")
	want := map[string]Variant{"Version": {"s", "1.0"}, "Label": {"s", "initial"}, "Count": {"u", uint32(7)},
		"Attrs": {"a{ss}", map[string]string{"k": "v"}}}
	if err != nil || !reflect.DeepEqual(all, want) {
		t.Fatalf("GetAll = %v, %v", all, err)
	}
	if all, err := b.GetAllProperties(ctx, dest, echoPath, "com.example.Echo"); err != nil || len(all) != 0 {
		t.Fatalf("GetAll of an interface without properties = %v, %v", all, err)
	}

	changes, err := b.Subscribe(ctx, MatchRule{Interface: "org.freedesktop.DBus.Properties", Member: "PropertiesChanged", Path: echoPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SetProperty(ctx, dest, echoPath, "com.example.Props", "Label", "renamed"); err != nil {
		t.Fatal(err)
	}
	m := receive(t, changes.C)
	if !reflect.DeepEqual(m.Body, []any{"com.example.Props", map[string]Variant{"Label": {"s", "renamed"}}, []string{}}) {
		t.Fatalf("PropertiesChanged %v", m.Body)
	}
	if v, _ := b.GetProperty(ctx, dest, echoPath, "com.example.Props", "Label"); v.Value != "renamed" {
		t.Fatalf("Label is %v", v)
	}
	if err := b.SetProperty(ctx, dest, echoPath, "com.example.Props", "Token", "t0k3n"); err != nil {
		t.Fatal(err)
	}
	m = receive(t, changes.C)
	if !reflect.DeepEqual(m.Body, []any{"com.example.Props", map[string]Variant{}, []string{"Token"}}) {
		t.Fatalf("PropertiesChanged %v", m.Body)
	}
	mu.Lock()
	if token != "t0k3n" {
		t.Fatalf("token = %q", token)
	}
	mu.Unlock()

	// Refusals.
	err = b.SetProperty(ctx, dest, echoPath, "com.example.Props", "Version", "2.0")
	dbusError(t, err, ErrorPropertyReadOnly)
	err = b.SetProperty(ctx, dest, echoPath, "com.example.Props", "Label", uint32(1))
	dbusError(t, err, ErrorInvalidArgs)
	_, err = b.GetProperty(ctx, dest, echoPath, "com.example.Props", "Token")
	dbusError(t, err, ErrorAccessDenied)
	_, err = b.GetProperty(ctx, dest, echoPath, "com.example.Props", "Nope")
	dbusError(t, err, ErrorUnknownProperty)
	_, err = b.GetAllProperties(ctx, dest, echoPath, "com.example.Nope")
	dbusError(t, err, ErrorUnknownInterface)
	// An empty interface name searches them all.
	if v, err := b.GetProperty(ctx, dest, echoPath, "", "Count"); err != nil || v.Value != uint32(7) {
		t.Fatalf("Get with no interface = %v, %v", v, err)
	}

	// Announcing a change by hand encodes by the declared type.
	if err := a.EmitPropertiesChanged(echoPath, "com.example.Props", map[string]any{"Count": 8}, "Attrs"); err != nil {
		t.Fatal(err)
	}
	m = receive(t, changes.C)
	if !reflect.DeepEqual(m.Body, []any{"com.example.Props", map[string]Variant{"Count": {"u", uint32(8)}}, []string{"Attrs"}}) {
		t.Fatalf("PropertiesChanged %v", m.Body)
	}
}

func TestIntrospectionDescribesObjectsAsValidXML(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	props := &Interface{
		Name:        "com.example.Props",
		Annotations: []Annotation{{"org.freedesktop.DBus.Deprecated", "true"}},
		Properties: []*Property{
			{Name: "Version", Type: "s", Get: func(context.Context, *Call) (any, error) { return "1", nil }, EmitsChanged: EmitsChangedConst},
			{Name: "Secret", Type: "ay", Set: func(context.Context, *Call, Variant) error { return nil }},
		},
	}
	a.Export(echoPath, echo(), props)
	a.Export("/com/example/Echo/child", echo())

	r, err := b.Call(ctx, a.UniqueName(), echoPath, "org.freedesktop.DBus.Introspectable", "Introspect")
	if err != nil {
		t.Fatal(err)
	}
	doc := r.Body[0].(string)
	if !strings.HasPrefix(doc, IntrospectDocType) {
		t.Fatalf("no doctype:\n%s", doc)
	}
	// Valid XML, read with nothing but encoding/xml.
	var generic struct {
		XMLName    xml.Name
		Interfaces []struct {
			Name string `xml:"name,attr"`
		} `xml:"interface"`
	}
	if err := xml.Unmarshal([]byte(doc), &generic); err != nil || generic.XMLName.Local != "node" {
		t.Fatalf("not valid introspection XML (%v):\n%s", err, doc)
	}
	node, err := ParseIntrospection([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, i := range node.Interfaces {
		names = append(names, i.Name)
	}
	wantNames := []string{"com.example.Echo", "com.example.Props", "org.freedesktop.DBus.Peer",
		"org.freedesktop.DBus.Introspectable", "org.freedesktop.DBus.Properties"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("interfaces %q", names)
	}
	echoInfo, propsInfo := node.Interfaces[0], node.Interfaces[1]
	describe := echoInfo.Methods[slices.IndexFunc(echoInfo.Methods, func(m MethodInfo) bool { return m.Name == "Describe" })]
	if !reflect.DeepEqual(describe.Args, []ArgInfo{{"item", "(sa{sv})", "in"}, {"label", "s", "out"}, {"count", "u", "out"}}) {
		t.Fatalf("Describe's args %+v", describe.Args)
	}
	if len(echoInfo.Signals) != 1 || echoInfo.Signals[0].Name != "Poked" || len(echoInfo.Signals[0].Args) != 2 {
		t.Fatalf("signals %+v", echoInfo.Signals)
	}
	wantProps := []PropertyInfo{
		{"Version", "s", "read", []AnnotationInfo{{"org.freedesktop.DBus.Property.EmitsChangedSignal", "const"}}},
		{"Secret", "ay", "write", nil},
	}
	if !reflect.DeepEqual(propsInfo.Properties, wantProps) || len(propsInfo.Annotations) != 1 {
		t.Fatalf("properties %+v, annotations %+v", propsInfo.Properties, propsInfo.Annotations)
	}
	if len(node.Children) != 1 || node.Children[0].Name != "child" {
		t.Fatalf("children %+v", node.Children)
	}

	// Paths above an object list their children, with only the standard
	// interfaces of their own.
	for path, child := range map[ObjectPath]string{"/": "com", "/com": "example", "/com/example": "Echo"} {
		node, err := b.Introspect(ctx, a.UniqueName(), path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(node.Children) != 1 || node.Children[0].Name != child || len(node.Interfaces) != 2 {
			t.Fatalf("%s: %+v", path, node)
		}
	}
	_, err = b.Introspect(ctx, a.UniqueName(), "/com/other")
	dbusError(t, err, ErrorUnknownObject)
}

func TestSubtreesServePathsThatComeAndGo(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	const base = ObjectPath("/org/example/items")
	var mu sync.Mutex
	items := map[string]bool{"a": true, "b": true}
	itemIface := func(name string) *Interface {
		return &Interface{Name: "com.example.Item", Methods: []*Method{{
			Name: "Name", Out: []Arg{{"name", "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				return []any{name + "@" + string(call.Path())}, nil
			},
		}}}
	}
	list := &Interface{Name: "com.example.List", Methods: []*Method{{
		Name: "Add", In: []Arg{{"name", "s"}}, Out: []Arg{{"path", "o"}},
		Handler: func(ctx context.Context, call *Call) ([]any, error) {
			var n string
			call.Decode(&n)
			mu.Lock()
			items[n] = true
			mu.Unlock()
			return []any{base + "/" + ObjectPath(EscapePathElement(n))}, nil
		},
	}}}
	err := a.ExportSubtree(base, Subtree{
		Lookup: func(p ObjectPath) []*Interface {
			if p == base {
				return []*Interface{list}
			}
			rest, ok := strings.CutPrefix(string(p), string(base)+"/")
			if !ok || strings.Contains(rest, "/") {
				return nil
			}
			name, err := UnescapePathElement(rest)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !items[name] {
				return nil
			}
			return []*Interface{itemIface(name)}
		},
		Children: func(p ObjectPath) []string {
			if p != base {
				return nil
			}
			mu.Lock()
			defer mu.Unlock()
			var out []string
			for n := range items {
				out = append(out, EscapePathElement(n))
			}
			return out
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Call(ctx, a.UniqueName(), base+"/a", "com.example.Item", "Name")
	if err != nil || r.Body[0] != "a@/org/example/items/a" {
		t.Fatalf("Name = %v, %v", r, err)
	}
	_, err = b.Call(ctx, a.UniqueName(), base+"/zz", "com.example.Item", "Name")
	dbusError(t, err, ErrorUnknownObject)

	r, err = b.Call(ctx, a.UniqueName(), base, "com.example.List", "Add", "My Item")
	if err != nil || r.Body[0] != base+"/My_20Item" {
		t.Fatalf("Add = %v, %v", r, err)
	}
	r, err = b.Call(ctx, a.UniqueName(), base+"/My_20Item", "com.example.Item", "Name")
	if err != nil || r.Body[0] != "My Item@/org/example/items/My_20Item" {
		t.Fatalf("the new item = %v, %v", r, err)
	}
	// A static export wins over the subtree at its own path.
	a.Export(base+"/b", echo())
	if _, err := b.Call(ctx, a.UniqueName(), base+"/b", "com.example.Item", "Name"); err == nil {
		t.Fatal("the subtree served a path exported statically")
	}
	node, err := b.Introspect(ctx, a.UniqueName(), base)
	if err != nil {
		t.Fatal(err)
	}
	var children []string
	for _, c := range node.Children {
		children = append(children, c.Name)
	}
	if !slices.Equal(children, []string{"My_20Item", "a", "b"}) || node.Interfaces[0].Name != "com.example.List" {
		t.Fatalf("introspection %+v", node)
	}
	if node, err := b.Introspect(ctx, a.UniqueName(), "/org/example"); err != nil || node.Children[0].Name != "items" {
		t.Fatalf("parent introspection %+v, %v", node, err)
	}
	a.UnexportSubtree(base)
	_, err = b.Call(ctx, a.UniqueName(), base+"/a", "com.example.Item", "Name")
	dbusError(t, err, ErrorUnknownObject)
}

func TestCredentialsNameTheProcessBehindAConnection(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	cr, err := b.GetConnectionCredentials(ctx, a.UniqueName())
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Close()
	if cr.ProcessID != uint32(os.Getpid()) || cr.UnixUserID != int64(os.Getuid()) {
		t.Fatalf("credentials %+v, want pid %d uid %d", cr, os.Getpid(), os.Getuid())
	}
	if cr.ProcessFD >= 0 {
		// A pidfd: on Linux its fdinfo names the process.
		info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", cr.ProcessFD))
		if err == nil && !strings.Contains(string(info), fmt.Sprintf("Pid:\t%d\n", os.Getpid())) {
			t.Fatalf("ProcessFD %d is not a pidfd for us:\n%s", cr.ProcessFD, info)
		}
		t.Logf("the bus passed a pidfd (%d)", cr.ProcessFD)
	}
	pid, err := b.GetConnectionUnixProcessID(ctx, a.UniqueName())
	if err != nil || pid != uint32(os.Getpid()) {
		t.Fatalf("GetConnectionUnixProcessID = %d, %v", pid, err)
	}
	uid, err := b.GetConnectionUnixUser(ctx, a.UniqueName())
	if err != nil || uid != uint32(os.Getuid()) {
		t.Fatalf("GetConnectionUnixUser = %d, %v", uid, err)
	}
	_, err = b.GetConnectionCredentials(ctx, ":1.99999")
	dbusError(t, err, ErrorNameHasNoOwner)
}

func TestFileDescriptorsPassBothWays(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	if !a.CanPassFDs() || !b.CanPassFDs() {
		t.Fatal("the bus did not agree to pass descriptors")
	}
	fdMethods := []*Method{
		{
			Name: "Read", In: []Arg{{"fd", "h"}}, Out: []Arg{{"data", "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var fd UnixFD
				call.Decode(&fd)
				f := os.NewFile(uintptr(fd), "in")
				defer f.Close()
				data, err := io.ReadAll(f)
				return []any{string(data)}, err
			},
		},
		{
			// As the Secret portal's RetrieveSecret: the caller hands over a
			// descriptor and the service writes the secret into it.
			Name: "Write", In: []Arg{{"fd", "h"}, {"data", "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				var fd UnixFD
				var data string
				call.Decode(&fd, &data)
				f := os.NewFile(uintptr(fd), "out")
				defer f.Close()
				_, err := f.WriteString(data)
				return nil, err
			},
		},
		{
			Name: "Open", Out: []Arg{{"fd", "h"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				r, w, err := os.Pipe()
				if err != nil {
					return nil, err
				}
				w.WriteString("from a")
				w.Close()
				// Handed over: the connection closes it once sent.
				fd, err := dupFD(UnixFD(r.Fd()))
				r.Close()
				return []any{fd}, err
			},
		},
	}
	a.Export(echoPath, echo(fdMethods...))

	r, w, _ := os.Pipe()
	w.WriteString("hello")
	w.Close()
	reply, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Read", UnixFD(r.Fd()))
	r.Close()
	if err != nil || reply.Body[0] != "hello" {
		t.Fatalf("Read = %v, %v", reply, err)
	}

	r, w, _ = os.Pipe()
	_, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Write", UnixFD(w.Fd()), "s3cret")
	w.Close() // ours; the service closed its own
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(r)
	r.Close()
	if string(data) != "s3cret" {
		t.Fatalf("read back %q", data)
	}

	reply, err = b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Open")
	if err != nil {
		t.Fatal(err)
	}
	var fd UnixFD
	if err := reply.Decode(&fd); err != nil || len(reply.FDs()) != 1 {
		t.Fatalf("Open = %v, %v", reply.Body, err)
	}
	f := os.NewFile(uintptr(fd), "from-a")
	data, _ = io.ReadAll(f)
	f.Close()
	if string(data) != "from a" {
		t.Fatalf("read %q", data)
	}

	// A signal carrying a descriptor gives each subscriber its own.
	s1, _ := b.Subscribe(ctx, MatchRule{Member: "Handing"})
	s2, _ := b.Subscribe(ctx, MatchRule{Member: "Handing"})
	r, w, _ = os.Pipe()
	defer w.Close()
	if err := a.Emit(echoPath, "com.example.Echo", "Handing", UnixFD(r.Fd())); err != nil {
		t.Fatal(err)
	}
	r.Close()
	m1, m2 := receive(t, s1.C), receive(t, s2.C)
	fd1, fd2 := m1.Body[0].(UnixFD), m2.Body[0].(UnixFD)
	if fd1 == fd2 {
		t.Fatalf("two subscribers share descriptor %d", fd1)
	}
	w.WriteString("x")
	f1 := os.NewFile(uintptr(fd1), "1")
	buf := make([]byte, 1)
	if n, err := f1.Read(buf); n != 1 || err != nil {
		t.Fatalf("the first subscriber's descriptor: %d, %v", n, err)
	}
	f1.Close()
	os.NewFile(uintptr(fd2), "2").Close()

	// Without agreement, descriptors are refused before anything is sent.
	c := dial(t, addr, WithoutUnixFDs())
	if c.CanPassFDs() {
		t.Fatal("descriptors agreed after WithoutUnixFDs")
	}
	if _, err := c.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Read", UnixFD(0)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("sent a descriptor without agreement: %v", err)
	}
}

func slowEcho(started chan<- struct{}, release <-chan struct{}) *Interface {
	return echo(&Method{
		Name: "Slow",
		Handler: func(ctx context.Context, call *Call) ([]any, error) {
			if started != nil {
				started <- struct{}{}
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, nil
		},
	})
}

func TestCallsGiveUpAtTheirDeadline(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	release := make(chan struct{})
	defer close(release)
	a.Export(echoPath, slowEcho(nil, release))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Slow")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("Slow = %v after %v", err, time.Since(start))
	}
	c := dial(t, addr, WithCallTimeout(100*time.Millisecond))
	if _, err := c.Call(context.Background(), a.UniqueName(), echoPath, "com.example.Echo", "Slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Slow with a default timeout = %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Slow"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Slow cancelled = %v", err)
	}
	// The connection still works afterwards.
	if _, err := b.Call(testContext(t), a.UniqueName(), echoPath, "com.example.Echo", "Echo", "ok"); err != nil {
		t.Fatal(err)
	}
}

func TestTooManyCallsAtOnceAreRefusedNotQueued(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr, WithHandlerLimit(1)), dial(t, addr)
	ctx := testContext(t)
	started, release := make(chan struct{}, 1), make(chan struct{})
	a.Export(echoPath, slowEcho(started, release))
	done := make(chan error, 1)
	go func() {
		_, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Slow")
		done <- err
	}()
	<-started
	_, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", "x")
	dbusError(t, err, ErrorLimitsExceeded)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", "x"); err != nil {
		t.Fatalf("after the slow call: %v", err)
	}
}

func TestCallsWithoutReplyRunTheirHandler(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ran := make(chan string, 1)
	a.Export(echoPath, echo(&Method{
		Name: "Note", In: []Arg{{"text", "s"}},
		Handler: func(ctx context.Context, call *Call) ([]any, error) {
			ran <- call.Args()[0].(string)
			return nil, nil
		},
	}))
	if err := b.CallNoReply(a.UniqueName(), echoPath, "com.example.Echo", "Note", "noted"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-ran:
		if s != "noted" {
			t.Fatalf("handler got %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not run")
	}
}

func TestClosingFailsWaitingCallsAndEndsSubscriptions(t *testing.T) {
	addr := privateBus(t)
	a := dial(t, addr)
	b, err := Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	a.Export(echoPath, slowEcho(started, release))
	sub, err := b.Subscribe(testContext(t), MatchRule{Member: "Poked"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := b.Call(context.Background(), a.UniqueName(), echoPath, "com.example.Echo", "Slow")
		done <- err
	}()
	<-started
	if b.Err() != nil {
		t.Fatalf("Err before Close = %v", b.Err())
	}
	b.Close()
	b.Close()
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("the waiting call got %v", err)
	}
	if _, ok := <-sub.C; ok {
		t.Fatal("the subscription's channel stayed open")
	}
	<-b.Done()
	if !errors.Is(b.Err(), ErrClosed) {
		t.Fatalf("Err = %v", b.Err())
	}
	if _, err := b.Call(context.Background(), a.UniqueName(), echoPath, "com.example.Echo", "Echo", "x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("a call after Close = %v", err)
	}
	if err := sub.Close(); err != nil {
		t.Fatalf("closing a subscription of a closed connection: %v", err)
	}
}

func TestLargeMessagesPassAndOversizedOnesCloseTheConnection(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	a.Export(echoPath, echo())
	big := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	r, err := b.Call(ctx, a.UniqueName(), echoPath, "com.example.Echo", "Echo", big)
	if err != nil || r.Body[0] != big {
		t.Fatalf("a 1 MiB echo failed: %v", err)
	}
	small := dial(t, addr, WithMaxMessageSize(64<<10))
	small.Export(echoPath, echo())
	// The bus may or may not answer for a peer that left mid-message.
	short, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err = b.Call(short, small.UniqueName(), echoPath, "com.example.Echo", "Echo", big); err == nil {
		t.Fatal("a message over the limit was served")
	}
	select {
	case <-small.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection that got an oversized message stayed open")
	}
	if !errors.Is(small.Err(), ErrInvalid) || !errors.Is(small.Err(), ErrClosed) {
		t.Fatalf("Err = %v", small.Err())
	}
}

func TestTheBusDaemonsOwnMethodsAnswer(t *testing.T) {
	addr := privateBus(t)
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	names, err := b.ListNames(ctx)
	if err != nil || !slices.Contains(names, BusName) || !slices.Contains(names, a.UniqueName()) || !slices.Contains(names, b.UniqueName()) {
		t.Fatalf("ListNames = %q, %v", names, err)
	}
	if has, err := b.NameHasOwner(ctx, a.UniqueName()); err != nil || !has {
		t.Fatalf("NameHasOwner = %v, %v", has, err)
	}
	if has, err := b.NameHasOwner(ctx, "com.example.Nobody"); err != nil || has {
		t.Fatalf("NameHasOwner of nobody = %v, %v", has, err)
	}
	_, err = b.GetNameOwner(ctx, "com.example.Nobody")
	dbusError(t, err, ErrorNameHasNoOwner)
	r, err := b.Call(ctx, BusName, BusPath, BusInterface, "GetId")
	if err != nil || len(r.Body[0].(string)) != 32 {
		t.Fatalf("GetId = %v, %v", r, err)
	}
	node, err := b.Introspect(ctx, BusName, BusPath)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(node.Interfaces, func(i InterfaceInfo) bool { return i.Name == BusInterface })
	if i < 0 || !slices.ContainsFunc(node.Interfaces[i].Methods, func(m MethodInfo) bool { return m.Name == "Hello" }) {
		t.Fatalf("the bus describes itself as %+v", node)
	}
	if err := b.AddMatch(ctx, MatchRule{Member: "X"}); err != nil {
		t.Fatal(err)
	}
	if err := b.RemoveMatch(ctx, MatchRule{Member: "X"}); err != nil {
		t.Fatal(err)
	}
	err = b.RemoveMatch(ctx, MatchRule{Member: "X"})
	dbusError(t, err, ErrorMatchRuleNotFound)
}

func TestConnectingFollowsTheEnvironmentAndTheAddress(t *testing.T) {
	addr := privateBus(t)
	// Only ever the private bus: the environment is pointed at it first.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", addr)
	for name, connect := range map[string]func(...Option) (*Conn, error){"session": ConnectSession, "system": ConnectSystem} {
		c, err := connect()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.ListNames(testContext(t)); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	// A dead alternative is skipped.
	c, err := Connect("unix:path=/nonexistent/svdbus;" + addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// The address's GUID must be the server's.
	parsed, _ := ParseAddresses(addr)
	a := parsed[0]
	if a.Params["guid"] == "" {
		t.Skip("the bus printed no GUID")
	}
	if !strings.EqualFold(a.Params["guid"], c.ServerGUID()) {
		t.Fatalf("GUID %s, server said %s", a.Params["guid"], c.ServerGUID())
	}
	a.Params["guid"] = strings.Repeat("0", 32)
	if _, err := Connect(a.String()); !errors.Is(err, ErrAuth) {
		t.Fatalf("connected despite a wrong GUID: %v", err)
	}
	if _, err := Connect("tcp:host=127.0.0.1,port=1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("tcp: %v", err)
	}
	if _, err := Connect("unix:tmpdir=/tmp"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tmpdir: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ConnectContext(ctx, addr); err == nil {
		t.Fatal("connected with a cancelled context")
	}
}

func TestDBusSendInteroperates(t *testing.T) {
	addr := privateBus(t)
	send, err := exec.LookPath("dbus-send")
	if err != nil {
		t.Skip("dbus-send is not installed")
	}
	a, b := dial(t, addr), dial(t, addr)
	ctx := testContext(t)
	props := &Interface{Name: "com.example.Props", Properties: []*Property{
		{Name: "Version", Type: "s", Get: func(context.Context, *Call) (any, error) { return "1.0", nil }},
	}}
	a.Export(echoPath, echo(), props)
	run := func(args ...string) (string, error) {
		cmd := exec.Command(send, append([]string{"--bus=" + addr}, args...)...)
		cmd.Env = isolatedEnv(addr)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	call := func(args ...string) string {
		t.Helper()
		out, err := run(append([]string{"--print-reply", "--dest=" + a.UniqueName(), string(echoPath)}, args...)...)
		if err != nil {
			t.Fatalf("dbus-send %q: %v\n%s", args, err, out)
		}
		return out
	}
	if out := call("com.example.Echo.Echo", "string:hello"); !strings.Contains(out, `string "hello"`) {
		t.Fatalf("Echo:\n%s", out)
	}
	if out := call("com.example.Echo.Add", "int32:40", "int32:2"); !strings.Contains(out, "int32 42") {
		t.Fatalf("Add:\n%s", out)
	}
	if out := call("com.example.Echo.Count", "dict:string:string:a,1,b,2,c,3"); !strings.Contains(out, "uint32 3") {
		t.Fatalf("Count:\n%s", out)
	}
	if out := call("org.freedesktop.DBus.Properties.Get", "string:com.example.Props", "string:Version"); !strings.Contains(out, `string "1.0"`) {
		t.Fatalf("Properties.Get:\n%s", out)
	}
	if out := call("org.freedesktop.DBus.Introspectable.Introspect"); !strings.Contains(out, `<interface name="com.example.Echo">`) {
		t.Fatalf("Introspect:\n%s", out)
	}
	out, err := run("--print-reply", "--dest="+a.UniqueName(), string(echoPath), "com.example.Echo.Fail")
	if err == nil || !strings.Contains(out, "com.example.Error.Nope") {
		t.Fatalf("Fail: %v\n%s", err, out)
	}

	// And a signal from dbus-send reaches a subscription.
	sub, err := b.Subscribe(ctx, MatchRule{Interface: "com.example.Echo", Member: "Poked"})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := run("--type=signal", string(echoPath), "com.example.Echo.Poked", "string:from dbus-send", "uint32:9"); err != nil {
		t.Fatalf("dbus-send signal: %v\n%s", err, out)
	}
	if m := receive(t, sub.C); !reflect.DeepEqual(m.Body, []any{"from dbus-send", uint32(9)}) {
		t.Fatalf("got %v", m.Body)
	}
}
