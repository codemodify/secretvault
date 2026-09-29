//go:build linux

package svd

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svrpc"
)

// fakeLogind plays org.freedesktop.login1 on a private bus: one session of
// ours, whose signals the test sends.
type fakeLogind struct {
	bus  *svdbus.Conn
	path svdbus.ObjectPath
}

func newFakeLogind(t *testing.T, addr string) *fakeLogind {
	bus, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bus.Close() })
	f := &fakeLogind{bus: bus, path: "/org/freedesktop/login1/session/_31"}
	uid := uint32(os.Getuid())
	type session struct {
		ID   string
		UID  uint32
		Name string
		Seat string
		Path svdbus.ObjectPath
	}
	err = bus.Export("/org/freedesktop/login1", &svdbus.Interface{
		Name: login1Manager,
		Methods: []*svdbus.Method{{
			Name: "ListSessions",
			Out:  []svdbus.Arg{{Name: "sessions", Type: "a(susso)"}},
			Handler: func(context.Context, *svdbus.Call) ([]any, error) {
				return []any{[]session{{"1", uid, "me", "seat0", f.path}}}, nil
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = bus.Export(f.path, &svdbus.Interface{
		Name: login1Session,
		Properties: []*svdbus.Property{{
			Name: "User", Type: "(uo)",
			Get: func(context.Context, *svdbus.Call) (any, error) {
				return struct {
					UID  uint32
					Path svdbus.ObjectPath
				}{uid, "/org/freedesktop/login1/user/_1000"}, nil
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := bus.RequestName(ctx, login1, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

// daemonWithVaults starts a daemon with two unlocked vaults: one that
// locks on screen lock and sleep, one that does not.
func daemonWithVaults(t *testing.T) *harness {
	h := newHarness(t)
	cli := h.setup() // "personal", default auto-lock
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "server-keys", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	h.d.mu.Lock()
	h.d.vaults["server-keys"].cfg.AutoLock = svrpc.AutoLock{IdleMinutes: 0}
	h.d.mu.Unlock()
	return h
}

func locked(t *testing.T, h *harness, name string) bool {
	h.d.mu.Lock()
	mv := h.d.vaults[name]
	h.d.mu.Unlock()
	return mv.v.Locked()
}

func waitLocked(t *testing.T, h *harness, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !locked(t, h, name) {
		if time.Now().After(deadline) {
			t.Fatalf("vault %s did not lock", name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startWatching(t *testing.T, h *harness) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.d.WatchSession(ctx)
	time.Sleep(100 * time.Millisecond) // let the match rules reach the bus
}

func TestSleepLocksTheVaultsThatAskForIt(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	f := newFakeLogind(t, addr)
	h := daemonWithVaults(t)
	startWatching(t, h)
	f.bus.Emit("/org/freedesktop/login1", login1Manager, "PrepareForSleep", true)
	waitLocked(t, h, "personal")
	time.Sleep(100 * time.Millisecond)
	if locked(t, h, "server-keys") {
		t.Fatal("a vault set not to lock on sleep locked")
	}
}

func TestTheScreenLockingLocksVaults(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	f := newFakeLogind(t, addr)
	h := daemonWithVaults(t)
	startWatching(t, h)
	f.bus.EmitPropertiesChanged(f.path, login1Session, map[string]any{"LockedHint": true})
	waitLocked(t, h, "personal")
}

func TestAScreensaverSignalLocksVaults(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	newFakeLogind(t, addr)
	h := daemonWithVaults(t)
	startWatching(t, h)
	other, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.Emit("/ScreenSaver", "org.freedesktop.ScreenSaver", "ActiveChanged", true)
	waitLocked(t, h, "personal")
}

func TestLoggingOutOfTheLastSessionLocksEverything(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	f := newFakeLogind(t, addr)
	h := daemonWithVaults(t)
	startWatching(t, h)
	f.bus.Emit("/org/freedesktop/login1", login1Manager, "SessionRemoved", "1", f.path)
	waitLocked(t, h, "personal")
	waitLocked(t, h, "server-keys")
}

func TestOnlyTheRealLogindIsBelieved(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	newFakeLogind(t, addr)
	h := daemonWithVaults(t)
	startWatching(t, h)
	// Another client, not the owner of org.freedesktop.login1, claims the
	// user logged out.
	impostor, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Close()
	impostor.Emit("/org/freedesktop/login1", login1Manager, "SessionRemoved", "1", svdbus.ObjectPath("/org/freedesktop/login1/session/_31"))
	time.Sleep(300 * time.Millisecond)
	if locked(t, h, "server-keys") {
		t.Fatal("a signal from an impostor locked the vaults")
	}
}
