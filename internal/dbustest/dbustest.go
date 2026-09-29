// Package dbustest starts private D-Bus buses for tests, so no test ever
// touches the desktop's own session or system bus: those carry the real
// keyring and the real login manager.
package dbustest

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PrivateBus starts a dbus-daemon of the test's own, with no service
// directory (nothing can be activated) and a policy that allows
// everything, and returns its address. It points DBUS_SESSION_BUS_ADDRESS
// and DBUS_SYSTEM_BUS_ADDRESS at it for the rest of the test, so code that
// looks for "the" bus finds this one. It skips the test when dbus-daemon
// is not installed.
func PrivateBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		if _, serr := os.Stat("/usr/bin/dbus-daemon"); serr != nil {
			t.Skip("dbus-daemon is not installed")
		}
		daemon = "/usr/bin/dbus-daemon"
	}
	// A short directory: socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "svbus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
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
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+conf, "--nofork", "--print-address")
	cmd.Env = isolated("")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
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
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
		t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", addr)
		return addr
	case <-time.After(10 * time.Second):
		t.Fatal("the private bus did not start")
	}
	return ""
}

// isolated is the environment without the desktop's bus addresses.
func isolated(addr string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DBUS_SESSION_BUS_ADDRESS=") || strings.HasPrefix(kv, "DBUS_SYSTEM_BUS_ADDRESS=") ||
			strings.HasPrefix(kv, "DBUS_STARTER_") {
			continue
		}
		env = append(env, kv)
	}
	if addr == "" {
		addr = "unix:path=/nonexistent/secretvault-test"
	}
	return append(env, "DBUS_SESSION_BUS_ADDRESS="+addr, "DBUS_SYSTEM_BUS_ADDRESS="+addr)
}
