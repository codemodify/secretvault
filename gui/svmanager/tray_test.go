package svmanager

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/uitoolkit/platform"
)

// privateBus starts a dbus-daemon of the test's own, allowing everything
// and activating nothing, and points the session bus address at it: the
// desktop's bus is never involved.
func privateBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is not installed")
	}
	dir, err := os.MkdirTemp("", "svgui-bus") // short: socket paths are limited
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
	cmd.Env = os.Environ()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
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
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
		return addr
	case <-time.After(10 * time.Second):
		t.Fatal("the private bus did not start")
	}
	return ""
}

// On Linux the tray is only somewhere to hide the window in when a host
// shows status items: a session bus alone is not one. uitoolkit's Shown,
// which the manager relies on, on a bus of the test's own: no watcher, a
// watcher with no host, and a watcher whose host comes.
func TestHidingInTheTrayNeedsAHostThatShowsIt(t *testing.T) {
	addr := privateBus(t)
	t.Setenv("UITK_TRAY", "")
	item, err := platform.NewStatusItem(platform.StatusItemOptions{ID: "svgui-test", Title: "svgui-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	if item.Backend() != "sni" {
		t.Skipf("no status item on the private bus: %s", item.Backend())
	}
	var heard atomic.Int32
	item.SetOnShownChange(func(bool) { heard.Add(1) })
	if item.Shown() {
		t.Fatal("a bus with no StatusNotifierWatcher counts as a tray")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := svdbus.ConnectContext(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var hosted atomic.Bool
	err = conn.Export("/StatusNotifierWatcher", &svdbus.Interface{
		Name: "org.kde.StatusNotifierWatcher",
		Properties: []*svdbus.Property{{
			Name: "IsStatusNotifierHostRegistered", Type: "b",
			Get: func(context.Context, *svdbus.Call) (any, error) { return hosted.Load(), nil },
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName(ctx, "org.kde.StatusNotifierWatcher", 0); err != nil {
		t.Fatal(err)
	}
	wait := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if cond() {
				return
			}
		}
		t.Fatal(what)
	}
	time.Sleep(100 * time.Millisecond) // the watcher's arrival reaches the item
	if item.Shown() {
		t.Fatal("a watcher with no host counts as a tray")
	}
	hosted.Store(true)
	if err := conn.Emit("/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher", "StatusNotifierHostRegistered"); err != nil {
		t.Fatal(err)
	}
	wait("a watcher with a host does not count as a tray", item.Shown)
	wait("the host arriving was not told", func() bool { return heard.Load() > 0 })
}
