package svd

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeInstall stands in for an installation: a directory the daemon runs
// from, and one of system programs. Programs are files that are never
// run; desktopPrompter only looks for them.
type fakeInstall struct {
	t      *testing.T
	daemon string // the daemon's directory
	system string // the system's program directory
}

func newFakeInstall(t *testing.T, platform string) *fakeInstall {
	f := &fakeInstall{t: t, daemon: t.TempDir(), system: t.TempDir()}
	oldExe, oldOS, oldDirs := executable, goos, systemBinDirs
	executable = func() (string, error) { return filepath.Join(f.daemon, "secretvaultd"), nil }
	goos = platform
	systemBinDirs = []string{f.system}
	t.Cleanup(func() { executable, goos, systemBinDirs = oldExe, oldOS, oldDirs })
	// No desktop until a test says there is one, whatever this machine has.
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("XDG_CURRENT_DESKTOP", "KDE")
	return f
}

func (f *fakeInstall) put(dir, name string, mode os.FileMode) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 1\n"), mode); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// program is the pinentry desktopPrompter chose, or "" for none.
func program(p Prompter) string {
	if p == nil {
		return ""
	}
	return p.(pinentryPrompter).p.Program
}

func TestTheDesktopPromptIsOurOwnWhereThereIsADisplay(t *testing.T) {
	f := newFakeInstall(t, "linux")
	ours := f.put(f.daemon, "secretvault-gui-prompt", 0o755)
	qt := f.put(f.system, "pinentry-qt", 0o755)

	// No display: nobody, not even the system's pinentry, which could
	// not show a window either.
	if got := program(desktopPrompter(PromptConfig{})); got != "" {
		t.Fatalf("with no display the prompter is %q", got)
	}
	// A Wayland or an X11 display: ours, ahead of the system's.
	for _, env := range []string{"WAYLAND_DISPLAY", "DISPLAY"} {
		t.Setenv(env, "test-display")
		if got := program(desktopPrompter(PromptConfig{})); got != ours {
			t.Fatalf("with %s the prompter is %q, want %q", env, got, ours)
		}
		t.Setenv(env, "")
	}
	// The config still wins, and "none" is none.
	t.Setenv("DISPLAY", ":0")
	if got := program(desktopPrompter(PromptConfig{Program: "/opt/pinentry-special"})); got != "/opt/pinentry-special" {
		t.Fatalf("the configured program lost to %q", got)
	}
	if p := desktopPrompter(PromptConfig{Program: "none"}); p != nil {
		t.Fatalf("\"none\" gave %q", program(p))
	}
	// A file that cannot be run is not our prompt: the system's stands in.
	if err := os.Chmod(ours, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := program(desktopPrompter(PromptConfig{})); got != qt {
		t.Fatalf("with no runnable prompt of ours the prompter is %q, want %q", got, qt)
	}
	os.Remove(ours)
	if got := program(desktopPrompter(PromptConfig{})); got != qt {
		t.Fatalf("without ours the prompter is %q, want %q", got, qt)
	}
}

// Windows and macOS always have a desktop to show a window on, and keep no
// DISPLAY to say so.
func TestWindowsAndMacOSAlwaysHaveADisplay(t *testing.T) {
	for _, platform := range []string{"windows", "darwin"} {
		f := newFakeInstall(t, platform)
		name := "secretvault-gui-prompt"
		if platform == "windows" {
			name += ".exe"
		}
		ours := f.put(f.daemon, name, 0o644)
		if platform == "darwin" {
			os.Chmod(ours, 0o755)
		}
		if got := program(desktopPrompter(PromptConfig{})); got != ours {
			t.Errorf("%s: the prompter is %q, want %q", platform, got, ours)
		}
		// Without it there is nothing: the system pinentries are for
		// X11 and Wayland desktops.
		f.put(f.system, "pinentry-qt", 0o755)
		os.Remove(ours)
		if got := program(desktopPrompter(PromptConfig{})); got != "" {
			t.Errorf("%s without ours: the prompter is %q", platform, got)
		}
	}
}

func TestADaemonStartedBeforeTheDesktopFindsItLater(t *testing.T) {
	f := newFakeInstall(t, "linux")
	ours := f.put(f.daemon, "secretvault-gui-prompt", 0o755)
	saved := sessionEnv
	t.Cleanup(func() { sessionEnv = saved })
	var session []string
	sessionEnv = func() []string { return session }

	d := &Daemon{cfg: &Config{}, findDesktop: true}
	// Started with the session, before the desktop said where it is.
	if p := d.desktopNow(); p != nil {
		t.Fatalf("a prompter with no display anywhere: %s", p.Describe())
	}
	// The desktop comes up and tells the service manager.
	session = []string{"WAYLAND_DISPLAY=wayland-1", "XDG_CURRENT_DESKTOP=KDE", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"}
	p := d.desktopNow()
	if program(p) != ours {
		t.Fatalf("after the desktop came up: %q", program(p))
	}
	if env := p.(pinentryPrompter).p.Env; lookupEnv(env, "WAYLAND_DISPLAY") != "wayland-1" || lookupEnv(env, "DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatalf("the prompt would not reach the display: %q", env)
	}
	// Its own display wins over the service manager's.
	t.Setenv("DISPLAY", ":7")
	if env := d.desktopNow().(pinentryPrompter).p.Env; lookupEnv(env, "WAYLAND_DISPLAY") != "" || lookupEnv(env, "DISPLAY") != ":7" {
		t.Fatalf("mixed its own display with the session's: %q", env)
	}
	// A given prompter, even none, and host mode, are never replaced.
	given := &Daemon{cfg: &Config{}, desktop: &scripted{}}
	if _, ok := given.desktopNow().(*scripted); !ok {
		t.Fatal("the given prompter was replaced")
	}
	given.desktop = nil
	if p := given.desktopNow(); p != nil {
		t.Fatal("a daemon given no one to ask found the desktop")
	}
	if p := (&Daemon{cfg: &Config{}}).desktopNow(); p != nil {
		t.Fatal("a daemon not for a person has a desktop prompt")
	}
}
