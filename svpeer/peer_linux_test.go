//go:build linux

package svpeer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalNames(t *testing.T) {
	for dev, want := range map[int]string{
		136<<8 | 3:                 "pts/3",
		137<<8 | 1:                 "pts/257",
		4<<8 | 2:                   "tty2",
		4<<8 | 64:                  "ttyS0",
		(136 << 8) | (1 << 20) | 5: "pts/261",
	} {
		if got := ttyName(dev); got != want {
			t.Errorf("ttyName(%#x) = %q, want %q", dev, got, want)
		}
	}
}

func TestAChildNamesTheProgramThatStartedIt(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	cmd := exec.Command(sleep, "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	p, err := Parent(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if p.PID != os.Getpid() || p.Exe != exe {
		t.Fatalf("the parent of sleep is %+v, want this test (%d, %s)", p, os.Getpid(), exe)
	}
	if _, err := Parent(1); err == nil {
		t.Fatal("init was given a parent")
	}
}

func TestANonDumpableProcessIsKnownOnlyByItsPID(t *testing.T) {
	// ssh-agent makes itself non-dumpable; the test uses it if present.
	agent, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("no ssh-agent")
	}
	sock := filepath.Join(t.TempDir(), "a")
	cmd := exec.Command(agent, "-D", "-a", sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(200 * time.Millisecond)
	p, err := Describe(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Exe != "" {
		t.Skipf("ssh-agent is readable here (%s): not hardened on this system", p.Exe)
	}
	if !strings.HasPrefix(p.Identity(), "unknown:pid-") || !strings.Contains(p.Display(), "ssh-agent") {
		t.Fatalf("identity %q, display %q", p.Identity(), p.Display())
	}
}
