//go:build linux

package svd

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svdbus"
)

// WatchSession follows the desktop session and locks vaults when it locks,
// sleeps or ends, until ctx is done:
//
//   - logind (system bus): PrepareForSleep; our sessions' Lock signal and
//     LockedHint property (which screen lockers such as KDE's set); and the
//     removal of our last session.
//   - the screensaver (session bus): org.freedesktop.ScreenSaver and
//     org.gnome.ScreenSaver ActiveChanged.
//
// A bus that cannot be reached is logged and skipped; the daemon still
// locks on idle and on request. Anything on the session bus may send the
// screensaver signals, and the worst it can do is lock a vault.
func (d *Daemon) WatchSession(ctx context.Context) {
	opts := []svdbus.Option{svdbus.WithMaxMessageSize(1 << 20)}
	if sys, err := svdbus.ConnectSystem(opts...); err != nil {
		d.opts.Log("no system bus, so sleep and logout are not followed: " + err.Error())
	} else if err := d.watchLogind(ctx, sys); err != nil {
		d.opts.Log("following logind: " + err.Error())
		sys.Close()
	} else {
		go func() { <-ctx.Done(); sys.Close() }()
	}
	if ses, err := svdbus.ConnectSession(opts...); err != nil {
		d.opts.Log("no session bus, so the screensaver is not followed: " + err.Error())
	} else if err := d.watchScreenSaver(ctx, ses); err != nil {
		d.opts.Log("following the screensaver: " + err.Error())
		ses.Close()
	} else {
		go func() { <-ctx.Done(); ses.Close() }()
	}
}

const (
	login1        = "org.freedesktop.login1"
	login1Manager = "org.freedesktop.login1.Manager"
	login1Session = "org.freedesktop.login1.Session"
	sessionPaths  = svdbus.ObjectPath("/org/freedesktop/login1/session")
)

func (d *Daemon) watchLogind(ctx context.Context, bus *svdbus.Conn) error {
	uid := uint32(os.Getuid())
	// Our sessions, so logging out of the last one can lock everything.
	var mu sync.Mutex
	ours := map[svdbus.ObjectPath]bool{}
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if reply, err := bus.Call(callCtx, login1, "/org/freedesktop/login1", login1Manager, "ListSessions"); err == nil {
		var sessions []struct {
			ID   string
			UID  uint32
			Name string
			Seat string
			Path svdbus.ObjectPath
		}
		if reply.Decode(&sessions) == nil {
			for _, s := range sessions {
				if s.UID == uid {
					ours[s.Path] = true
				}
			}
		}
	}
	isOurs := func(path svdbus.ObjectPath) bool {
		mu.Lock()
		known := ours[path]
		mu.Unlock()
		if known {
			return true
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		v, err := bus.GetProperty(c, login1, path, login1Session, "User")
		if err != nil {
			return false
		}
		var user struct {
			UID  uint32
			Path svdbus.ObjectPath
		}
		if v.Store(&user) != nil || user.UID != uid {
			return false
		}
		mu.Lock()
		ours[path] = true
		mu.Unlock()
		return true
	}

	subs := []struct {
		rule svdbus.MatchRule
		fn   func(*svdbus.Message)
	}{
		{svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: login1, Interface: login1Manager, Member: "PrepareForSleep"},
			func(m *svdbus.Message) {
				var start bool
				if m.Decode(&start) == nil && start {
					d.Sleeping()
				}
			}},
		{svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: login1, Interface: login1Session, Member: "Lock", PathNamespace: sessionPaths},
			func(m *svdbus.Message) {
				if isOurs(m.Path) {
					d.ScreenLocked()
				}
			}},
		{svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: login1, Interface: "org.freedesktop.DBus.Properties", Member: "PropertiesChanged",
			PathNamespace: sessionPaths, Args: map[int]string{0: login1Session}},
			func(m *svdbus.Message) {
				var iface string
				var changed map[string]svdbus.Variant
				var invalidated []string
				if m.Decode(&iface, &changed, &invalidated) != nil {
					return
				}
				if v, ok := changed["LockedHint"]; ok {
					if locked, _ := v.Value.(bool); locked && isOurs(m.Path) {
						d.ScreenLocked()
					}
				}
			}},
		{svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: login1, Interface: login1Manager, Member: "SessionNew"},
			func(m *svdbus.Message) {
				var id string
				var path svdbus.ObjectPath
				if m.Decode(&id, &path) == nil {
					isOurs(path)
				}
			}},
		{svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: login1, Interface: login1Manager, Member: "SessionRemoved"},
			func(m *svdbus.Message) {
				var id string
				var path svdbus.ObjectPath
				if m.Decode(&id, &path) != nil {
					return
				}
				mu.Lock()
				was := ours[path]
				delete(ours, path)
				last := was && len(ours) == 0
				mu.Unlock()
				if last {
					d.LoggedOut()
				}
			}},
	}
	for _, s := range subs {
		if _, err := bus.SubscribeFunc(ctx, s.rule, s.fn); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) watchScreenSaver(ctx context.Context, bus *svdbus.Conn) error {
	for _, iface := range []string{"org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"} {
		rule := svdbus.MatchRule{Type: svdbus.TypeSignal, Interface: iface, Member: "ActiveChanged"}
		if _, err := bus.SubscribeFunc(ctx, rule, func(m *svdbus.Message) {
			var active bool
			if m.Decode(&active) == nil && active {
				d.ScreenLocked()
			}
		}); err != nil {
			return err
		}
	}
	return nil
}
