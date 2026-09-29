package svdbus

import (
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestAddressesParseWithEscapesAndAlternatives(t *testing.T) {
	addrs, err := ParseAddresses("unix:path=/run/user/1000/bus,guid=0123456789abcdef0123456789abcdef;;" +
		"unix:abstract=/tmp/dbus-%41b%2cc;launchd:env=DBUS_LAUNCHD_SESSION_BUS_SOCKET;tcp:host=127.0.0.1,port=4242")
	if err != nil {
		t.Fatal(err)
	}
	want := []Address{
		{"unix", map[string]string{"path": "/run/user/1000/bus", "guid": "0123456789abcdef0123456789abcdef"}},
		{"unix", map[string]string{"abstract": "/tmp/dbus-Ab,c"}},
		{"launchd", map[string]string{"env": "DBUS_LAUNCHD_SESSION_BUS_SOCKET"}},
		{"tcp", map[string]string{"host": "127.0.0.1", "port": "4242"}},
	}
	if !reflect.DeepEqual(addrs, want) {
		t.Fatalf("got %v", addrs)
	}
	// Formatting escapes what must be escaped and round-trips.
	a := Address{"unix", map[string]string{"path": "/tmp/my bus;x=1,é"}}
	if s := a.String(); s != "unix:path=/tmp/my%20bus%3bx%3d1%2c%c3%a9" {
		t.Fatalf("String = %q", s)
	}
	back, err := ParseAddresses(a.String())
	if err != nil || !reflect.DeepEqual(back[0], a) {
		t.Fatalf("round trip = %v, %v", back, err)
	}
	for _, bad := range []string{"", ";", "unix", ":path=/x", "unix:path", "unix:=x", "unix:path=/a b",
		"unix:path=/a%2", "unix:path=/a%zz", "unix:path=/a,path=/b", "unix:path=/x\x00"} {
		if got, err := ParseAddresses(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
}

func TestOnlyConnectableUnixAddressesNameASocket(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/4242")
	t.Setenv("SV_TEST_LAUNCHD", "/tmp/launchd.sock")
	cases := map[string]string{
		"unix:path=/run/bus":             "/run/bus",
		"unix:path=%40odd":               "./@odd",
		"unix:runtime=yes":               "/run/user/4242/bus",
		"launchd:env=SV_TEST_LAUNCHD":    "/tmp/launchd.sock",
		"unix:abstract=/tmp/dbus-abcdef": "@/tmp/dbus-abcdef",
	}
	for addr, want := range cases {
		a, _ := ParseAddresses(addr)
		got, err := a[0].unixSocket()
		if addr == "unix:abstract=/tmp/dbus-abcdef" && runtime.GOOS != "linux" {
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("abstract socket on %s: %v", runtime.GOOS, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", addr, got, err, want)
		}
	}
	for _, addr := range []string{"unix:tmpdir=/tmp", "unix:dir=/tmp", "unix:runtime=no", "unix:path=/a,abstract=b",
		"unix:guid=00", "launchd:env=SV_TEST_UNSET_VARIABLE", "unix:path="} {
		a, _ := ParseAddresses(addr)
		if got, err := a[0].unixSocket(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s names %q (%v)", addr, got, err)
		}
	}
	for _, addr := range []string{"tcp:host=localhost,port=1", "nonce-tcp:", "autolaunch:"} {
		a, _ := ParseAddresses(addr)
		if _, err := a[0].unixSocket(); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestTheSessionBusIsFoundWithoutTouchingTheRealOne(t *testing.T) {
	// Point everything at a directory of our own, so nothing here can reach
	// the desktop's bus.
	dir := t.TempDir()
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("XDG_RUNTIME_DIR", dir)
	if a, err := SessionBusAddress(); err == nil {
		t.Fatalf("found a session bus at %q in an empty runtime directory", a)
	}
	l, err := net.Listen("unix", filepath.Join(dir, "bus"))
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	a, err := SessionBusAddress()
	if err != nil || a != "unix:path="+escapeAddressValue(filepath.Join(dir, "bus")) {
		t.Fatalf("SessionBusAddress = %q, %v", a, err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/x")
	if a, _ := SessionBusAddress(); a != "unix:path=/x" {
		t.Fatalf("the environment did not win: %q", a)
	}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "")
	if SystemBusAddress() != "unix:path=/run/dbus/system_bus_socket" {
		t.Fatalf("SystemBusAddress = %q", SystemBusAddress())
	}
}

func TestMatchRulesFormatAsTheBusReadsThem(t *testing.T) {
	r := MatchRule{
		Type: TypeSignal, Sender: "org.freedesktop.login1", Interface: "org.freedesktop.login1.Manager",
		Member: "PrepareForSleep", PathNamespace: "/org/freedesktop/login1",
		Args: map[int]string{2: "it's", 0: `a\b`}, ArgPaths: map[int]string{1: "/x/"}, Arg0Namespace: "org.example",
	}
	want := `type='signal',sender='org.freedesktop.login1',interface='org.freedesktop.login1.Manager',` +
		`member='PrepareForSleep',path_namespace='/org/freedesktop/login1',arg0='a\b',arg2='it'\''s',` +
		`arg1path='/x/',arg0namespace='org.example'`
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := r.String(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for _, bad := range []MatchRule{
		{Type: 5}, {Sender: "no"}, {Interface: "x"}, {Member: "a.b"}, {Path: "/a/"}, {PathNamespace: "x"},
		{Path: "/a", PathNamespace: "/a"}, {Destination: "org.example.Name"}, {Args: map[int]string{64: "x"}},
		{Args: map[int]string{0: "a\x00"}}, {ArgPaths: map[int]string{-1: "/"}}, {Arg0Namespace: "a..b"},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestMatchRulesMatchLocally(t *testing.T) {
	sig := &Message{Type: TypeSignal, Sender: ":1.5", Path: "/org/example/a/b", Interface: "org.example.I",
		Member: "Changed", Body: []any{"org.example.app.x", ObjectPath("/aa/bb/cc"), "z"}}
	cases := []struct {
		rule MatchRule
		want bool
	}{
		{MatchRule{}, true},
		{MatchRule{Type: TypeSignal, Interface: "org.example.I", Member: "Changed"}, true},
		{MatchRule{Type: TypeMethodCall}, false},
		{MatchRule{Member: "Other"}, false},
		{MatchRule{Path: "/org/example/a/b"}, true},
		{MatchRule{Path: "/org/example/a"}, false},
		{MatchRule{PathNamespace: "/org/example"}, true},
		{MatchRule{PathNamespace: "/org/exam"}, false},
		{MatchRule{PathNamespace: "/"}, true},
		{MatchRule{Destination: ":1.9"}, false},
		{MatchRule{Args: map[int]string{0: "org.example.app.x", 2: "z"}}, true},
		{MatchRule{Args: map[int]string{1: "/aa/bb/cc"}}, false}, // argN matches strings only
		{MatchRule{Args: map[int]string{5: "z"}}, false},
		{MatchRule{ArgPaths: map[int]string{1: "/aa/bb/"}}, true},
		{MatchRule{ArgPaths: map[int]string{1: "/aa/b"}}, false},
		{MatchRule{ArgPaths: map[int]string{1: "/aa/bb/cc/dd"}}, false},
		{MatchRule{ArgPaths: map[int]string{0: "org.example.app.x"}}, true},
		{MatchRule{Arg0Namespace: "org.example"}, true},
		{MatchRule{Arg0Namespace: "org.example.app.x"}, true},
		{MatchRule{Arg0Namespace: "org.exam"}, false},
		{MatchRule{Sender: ":1.5"}, true},
		{MatchRule{Sender: ":1.6"}, false},
		{MatchRule{Sender: "org.example.Owner"}, true},  // owned by :1.5, below
		{MatchRule{Sender: "org.example.Other"}, false}, // owner unknown
	}
	c := &Conn{watches: map[string]*nameWatch{"org.example.Owner": {owner: ":1.5"}}}
	for _, tc := range cases {
		if got := c.matchLocked(&tc.rule, sig); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.rule, got, tc.want)
		}
	}
	// An argument path ending in '/' matches rules below it too.
	dir := &Message{Type: TypeSignal, Body: []any{"/aa/"}}
	if !(&MatchRule{ArgPaths: map[int]string{0: "/aa/bb/"}}).matches(dir) {
		t.Error("arg0path='/aa/bb/' did not match the argument '/aa/'")
	}
}
