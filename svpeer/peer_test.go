package svpeer

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestASocketPeerIsIdentifiedByTheKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercised on Linux")
	}
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := FromConn(c)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if p.PID != os.Getpid() || p.UID != os.Getuid() || p.Exe != exe {
		t.Fatalf("peer = %+v, want pid %d exe %s", p, os.Getpid(), exe)
	}
	// The test binary is the user's own file: its identity carries a hash.
	if p.SystemOwned || p.ExeHash == "" || !strings.Contains(p.Identity(), "#sha256:") {
		t.Fatalf("identity %q (system %v)", p.Identity(), p.SystemOwned)
	}
}

func TestSystemProgramsAreKnownByPathAndScriptsByScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("exercised on Linux")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep")
	}
	cmd := exec.Command(sleep, "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	p, err := Describe(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(sleep)
	if !p.SystemOwned || p.Identity() != "exe:"+real || p.Terminal != "" {
		t.Fatalf("sleep = %+v, identity %q", p, p.Identity())
	}

	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	script := filepath.Join(t.TempDir(), "tool.py")
	os.WriteFile(script, []byte("import time\ntime.sleep(5)\n"), 0o600)
	cmd = exec.Command(py, "-u", script)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	p, err = Describe(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Script != script || !strings.Contains(p.Identity(), script) || !strings.HasPrefix(p.Display(), "tool.py") {
		t.Fatalf("python script = %+v, identity %q, display %q", p, p.Identity(), p.Display())
	}
}

func TestSandboxIdentitiesWin(t *testing.T) {
	p := &Process{Exe: "/app/bin/evolution", Flatpak: "org.gnome.Evolution", ExeHash: "ab"}
	if p.Identity() != "flatpak:org.gnome.Evolution" || !strings.Contains(p.Display(), "Flatpak") {
		t.Fatalf("%q / %q", p.Identity(), p.Display())
	}
	q := &Process{Exe: "/snap/firefox/x/firefox", Snap: "firefox"}
	if q.Identity() != "snap:firefox" {
		t.Fatalf("%q", q.Identity())
	}
}

func TestInterpretersAndTheirScripts(t *testing.T) {
	for exe, want := range map[string]bool{
		"/usr/bin/python3": true, "/usr/bin/python3.12": true, "/usr/bin/perl5.38": true,
		"/usr/bin/bash": true, "/usr/bin/firefox": false, "/usr/bin/pythonista": false,
	} {
		if isInterpreter(exe) != want {
			t.Errorf("isInterpreter(%s) = %v", exe, !want)
		}
	}
	for args, want := range map[string]string{
		"python3 -u tool.py":     "tool.py",
		"python3 -c print(1)":    "",
		"python3 -m http.server": "",
		"bash -e ./deploy.sh x":  "./deploy.sh",
		"python3":                "",
	} {
		if got := scriptArg(strings.Fields(args)); got != want {
			t.Errorf("scriptArg(%q) = %q, want %q", args, got, want)
		}
	}
}

// A file's name can hold anything but a slash: shown to a person, what
// would not show as itself is spelled out.
func TestNamesAreShownAsTheyAre(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/bin/comms-mail":                      "/usr/bin/comms-mail",
		"/tmp/q/\n\nProgram: /usr/bin/thunderbird": `/tmp/q/\n\nProgram: /usr/bin/thunderbird`,
		"/tmp/\u202egnp.exe":                       `/tmp/\u202egnp.exe`,
		"/tmp/\x1b[2Kmail":                         `/tmp/\x1b[2Kmail`,
		"/tmp/caf\xe9":                             `/tmp/caf\xe9`,
		"/home/ada/bin/ünïcode":                    "/home/ada/bin/ünïcode",
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
	p := &Process{PID: 1, Exe: "/tmp/q/\n\nProgram: /usr/bin/thunderbird"}
	if d := p.Display(); strings.ContainsAny(d, "\n\r") {
		t.Fatalf("Display = %q", d)
	}
}
