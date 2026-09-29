package main

import (
	"os"
	"path/filepath"
	"slices"
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

// portalSystem lays out a system's xdg-desktop-portal files in a temp dir
// and points the XDG variables at it: gnome-keyring.portal when
// withBackend, and a <desktop>-portals.conf picking secret for Secret.
func portalSystem(t *testing.T, desktop, secret string, withBackend bool) string {
	t.Helper()
	sys := t.TempDir()
	data := filepath.Join(sys, "share")
	os.MkdirAll(filepath.Join(data, "xdg-desktop-portal", "portals"), 0o755)
	if withBackend {
		os.WriteFile(filepath.Join(data, "xdg-desktop-portal", "portals", "gnome-keyring.portal"),
			[]byte("[portal]\nDBusName=org.freedesktop.secrets\nInterfaces=org.freedesktop.impl.portal.Secret\nUseIn=gnome\n"), 0o644)
	}
	os.WriteFile(filepath.Join(data, "xdg-desktop-portal", strings.ToLower(desktop)+"-portals.conf"),
		[]byte("[preferred]\ndefault="+strings.ToLower(desktop)+"\norg.freedesktop.impl.portal.Secret="+secret+"\n"), 0o644)
	t.Setenv("XDG_DATA_DIRS", data)
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(sys, "etc"))
	t.Setenv("XDG_CURRENT_DESKTOP", desktop)
	return sys
}

func TestATakeoverPlanForGnomeKeyringWritesOnlyUserFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	portalSystem(t, "GNOME", "gnome-keyring", true)
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
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	portalSystem(t, "GNOME", "gnome-keyring", true)
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

func TestFlatpakAppsSecretPortalIsPointedAtSecretvault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	userConf := filepath.Join(home, "config", "xdg-desktop-portal", "kde-portals.conf")

	// KDE picks kwallet: a copy of its file, with only Secret changed.
	portalSystem(t, "KDE", "kwallet", true)
	p, _ := planTakeover("/usr/bin/ksecretd", "/x/secretvaultd")
	conf, ok := p.files[userConf]
	if !ok {
		t.Fatalf("no user portals.conf in the plan: %v", p.order)
	}
	if !strings.Contains(conf, "default=kde\n") || !strings.Contains(conf, "org.freedesktop.impl.portal.Secret=gnome-keyring\n") || strings.Contains(conf, "kwallet") {
		t.Fatalf("the copy:\n%s", conf)
	}
	if !slices.Contains(p.restart, "xdg-desktop-portal.service") {
		t.Fatalf("restarts: %v", p.restart)
	}

	// GNOME already picks gnome-keyring: nothing to write.
	portalSystem(t, "GNOME", "gnome-keyring", true)
	p, _ = planTakeover("/usr/bin/ksecretd", "/x/secretvaultd")
	for _, f := range p.order {
		if strings.Contains(f, "xdg-desktop-portal") {
			t.Fatalf("GNOME got %s", f)
		}
	}

	// The user's own file is never overwritten: they are told what to set.
	portalSystem(t, "KDE", "kwallet", true)
	os.MkdirAll(filepath.Dir(userConf), 0o755)
	os.WriteFile(userConf, []byte("[preferred]\ndefault=kde\n"), 0o644)
	p, _ = planTakeover("/usr/bin/ksecretd", "/x/secretvaultd")
	if _, ok := p.files[userConf]; ok || !strings.Contains(strings.Join(p.notes, "\n"), userConf) {
		t.Fatalf("the user's file: planned %v, notes %v", ok, p.notes)
	}
	os.Remove(userConf)

	// With no backend that reaches org.freedesktop.secrets, it says so.
	portalSystem(t, "KDE", "kwallet", false)
	p, _ = planTakeover("/usr/bin/ksecretd", "/x/secretvaultd")
	if _, ok := p.files[userConf]; ok || !strings.Contains(strings.Join(p.notes, "\n"), "Flatpak apps keep theirs") {
		t.Fatalf("no backend: planned %v, notes %v", ok, p.notes)
	}
}

func TestWithPortalChangesOnlyTheSecretLine(t *testing.T) {
	for in, want := range map[string]string{
		"[preferred]\ndefault=kde\norg.freedesktop.impl.portal.Secret=kwallet\n": "[preferred]\ndefault=kde\norg.freedesktop.impl.portal.Secret=gnome-keyring\n",
		"[preferred]\ndefault=gtk\n": "[preferred]\norg.freedesktop.impl.portal.Secret=gnome-keyring\ndefault=gtk\n",
		"# only a comment\n":         "# only a comment\n[preferred]\norg.freedesktop.impl.portal.Secret=gnome-keyring\n",
	} {
		if got, changed := withPortal(in, portalSecret, gnomeKeyringPortal); !changed || got != want {
			t.Errorf("withPortal(%q) = %q, %v", in, got, changed)
		}
	}
	if _, changed := withPortal("[preferred]\norg.freedesktop.impl.portal.Secret=gnome-keyring\n", portalSecret, gnomeKeyringPortal); changed {
		t.Error("an unchanged file was changed")
	}
}
