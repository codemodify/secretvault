package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheGnomeKeyringUnitKeepsItsOtherComponents(t *testing.T) {
	for in, want := range map[string]string{
		`/usr/bin/gnome-keyring-daemon --foreground --components="pkcs11,secrets" --control-directory=%t/keyring`: `/usr/bin/gnome-keyring-daemon --foreground --components="pkcs11" --control-directory=%t/keyring`,
		`/usr/bin/gnome-keyring-daemon --foreground --components=pkcs11,secrets,ssh`:                              `/usr/bin/gnome-keyring-daemon --foreground --components=pkcs11,ssh`,
	} {
		if got, ok := execStartWithout(in, "secrets"); !ok || got != want {
			t.Errorf("execStartWithout(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := execStartWithout(`/usr/bin/gnome-keyring-daemon --components=secrets`, "secrets"); ok {
		t.Error("removing the only component was accepted")
	}
}

func TestATakeoverPlanForGnomeKeyringWritesOnlyUserFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	saved := commandRunner
	t.Cleanup(func() { commandRunner = saved })
	commandRunner = func(name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "--user cat gnome-keyring-daemon.service" {
			return []byte("[Service]\nExecStart=/usr/bin/gnome-keyring-daemon --foreground --components=\"pkcs11,secrets\" --control-directory=%t/keyring\n"), nil
		}
		t.Fatalf("unexpected command %s %v", name, args)
		return nil, nil
	}
	p, err := planTakeover("/usr/bin/gnome-keyring-daemon", "/opt/sv/secretvaultd")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.order {
		if !strings.HasPrefix(f, home) {
			t.Errorf("the plan writes %s, outside the user's own directories", f)
		}
	}
	svc := p.files[filepath.Join(home, "data", "dbus-1", "services", "org.freedesktop.secrets.service")]
	if !strings.Contains(svc, "Exec=/opt/sv/secretvaultd") {
		t.Fatalf("activation file:\n%s", svc)
	}
	dropIn := p.files[filepath.Join(home, "config", "systemd", "user", "gnome-keyring-daemon.service.d", "50-secretvault.conf")]
	if !strings.Contains(dropIn, "ExecStart=\n") || !strings.Contains(dropIn, `--components="pkcs11"`) {
		t.Fatalf("drop-in:\n%s", dropIn)
	}
	if len(p.restart) != 1 || p.restart[0] != "gnome-keyring-daemon.service" {
		t.Fatalf("restart %v", p.restart)
	}
	if _, err := os.Stat("/etc/xdg/autostart/gnome-keyring-secrets.desktop"); err == nil {
		auto := p.files[filepath.Join(home, "config", "autostart", "gnome-keyring-secrets.desktop")]
		if !strings.HasSuffix(auto, "Hidden=true\n") {
			t.Fatalf("autostart override:\n%s", auto)
		}
	}
}

func TestOtherKeyringsGetStepsToDoByHand(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for exe, want := range map[string]string{
		"/usr/bin/ksecretd":   "KWallet",
		"/usr/bin/keepassxc":  "KeePassXC",
		"/usr/bin/oo7-daemon": "oo7",
	} {
		p, _ := planTakeover(exe, "/x/secretvaultd")
		if len(p.notes) != 1 || !strings.Contains(p.notes[0], want) {
			t.Errorf("%s: notes %v", exe, p.notes)
		}
	}
}
