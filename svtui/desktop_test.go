//go:build linux

package svtui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The desktop's changes, made in the test's own HOME and XDG directories,
// on a private session bus, with svops' programs a fake's: nothing of the
// machine's is touched. A plan is shown before each change, and Escape on
// it changes nothing.

// fakeCLI is a stand-in for the secretvault CLI beside the manager, in
// the test's directory.
func (h *harness) fakeCLI() string {
	h.t.Helper()
	cli := filepath.Join(h.dir, "bin", "secretvault")
	if err := os.MkdirAll(filepath.Dir(cli), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	return cli
}

func TestTheKeyringIsTakenOverAndGivenBack(t *testing.T) {
	h := newHarness(t)
	dbustest.PrivateBus(t) // the session bus is the test's own
	daemon := filepath.Join(h.dir, "bin", "secretvaultd")
	h.start(Options{CLI: h.fakeCLI(), Daemon: daemon}, "")
	h.unlock()
	h.typeText("Y")
	h.waitFor("System keyring")
	h.waitFor("nothing: no app can keep passwords there now")

	// The plan, in plain words, its files behind Show details; declined:
	// nothing changes.
	service := filepath.Join(h.home, ".local", "share", "dbus-1", "services", "org.freedesktop.secrets.service")
	h.typeText("t")
	h.waitFor("Make secretvault your system keyring")
	h.waitForWords("secretvault becomes the system keyring")
	if strings.Contains(h.text(), "org.freedesktop.secrets.service") {
		t.Fatalf("the plan names its files before Show details:\n%s", h.text())
	}
	h.details()
	h.waitFor("org.freedesktop.secrets.service")
	h.waitFor("turn on secretvaultd's Secret Service")
	h.key(tcell.KeyEscape)
	h.waitGone("Make secretvault your system keyring")
	if _, err := os.Stat(service); err == nil {
		t.Fatal("declining the plan wrote the service file")
	}

	// Accepted.
	h.typeText("t")
	h.waitFor("Make secretvault your system keyring")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab) // Cancel, then Take over the keyring
	h.key(tcell.KeyEnter)
	h.waitFor("secretvault is your system keyring")
	b, err := os.ReadFile(service)
	if err != nil || !strings.Contains(string(b), "Exec="+daemon) {
		t.Fatalf("the service file: %q %v", b, err)
	}
	if st, err := h.admin.Status(h.ctx()); err != nil || !strings.Contains(st.SecretService, "serving") && !strings.Contains(st.SecretService, "on") {
		t.Logf("the daemon says: %+v %v", st.SecretService, err)
	}
	h.key(tcell.KeyEscape)
	h.waitFor("takeover")

	// Given back.
	h.typeText("r")
	h.waitFor("Stop being the system keyring")
	h.details()
	h.waitFor("- remove ")
	h.key(tcell.KeyBacktab)
	h.key(tcell.KeyEnter)
	h.waitFor("secretvault is no longer the system keyring")
	if _, err := os.Stat(service); err == nil {
		t.Fatal("the service file is still there")
	}
	if _, err := svops.LoadTakeover(); err == nil {
		t.Fatal("the takeover is still recorded")
	}
}

// The keyring to import from is another daemon's Secret Service, on the
// private bus, which lets this test's program read it.
func TestTheKeyringsSecretsAreImportedNamesFirst(t *testing.T) {
	h := newHarness(t)
	other := newHarness(t)
	dbustest.PrivateBus(t) // after both: the bus both use
	other.unlockAdmin("")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.admin.Grant(other.ctx(), svrpc.GrantAddParams{Program: exe, Ops: []string{"read", "list"}, Decision: "allow-always"}); err != nil {
		t.Fatal(err)
	}
	if err := other.admin.ServeKeyring(other.ctx(), true); err != nil {
		t.Skipf("the other daemon cannot serve the keyring here: %v", err)
	}
	h.start(Options{}, "")
	h.unlock()
	h.typeText("Y")
	h.waitFor("System keyring")
	h.typeText("i")
	h.waitFor("Copy the keyring's passwords into personal")
	h.waitForWords("copied into vault personal.")
	h.details()
	h.waitFor("GitHub") // named for its label
	h.key(tcell.KeyBacktab)
	h.key(tcell.KeyEnter)
	h.waitSaid("Copied")
	if _, err := h.get("GitHub"); err != nil {
		t.Fatalf("imported: %v", err)
	}
}

func TestBrowsersAreSetUpAndUndone(t *testing.T) {
	h := newHarness(t)
	cli := h.fakeCLI()
	if err := os.MkdirAll(filepath.Join(h.home, ".mozilla", "firefox"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.start(Options{CLI: cli}, "")
	h.unlock()
	h.typeText("B")
	h.waitFor("the secretvault extension")
	h.waitFor("Firefox")

	// secretvault's own extension's host: the plan in plain words, its
	// files behind Show details.
	dir := filepath.Join(h.home, ".mozilla", "native-messaging-hosts")
	manifest := filepath.Join(dir, svext.HostName+".json")
	h.typeText("i")
	h.waitFor("Which browser should the extension work in?")
	h.key(tcell.KeyDown) // Firefox
	h.key(tcell.KeyEnter)
	h.waitFor("Let Firefox use secretvault")
	h.waitForWords("Firefox needs your permission to start secretvault")
	h.details()
	h.waitFor("The browsers would start " + cli)
	h.waitFor("firefox: write")
	h.key(tcell.KeyBacktab) // Allow Firefox
	h.key(tcell.KeyEnter)
	h.waitFor("Restart the browser, then add")
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || m["path"] != cli || m["name"] != svext.HostName {
		t.Fatalf("the manifest: %s", b)
	}
	h.key(tcell.KeyEscape)
	h.waitFor("Yes")

	h.typeText("u")
	h.waitFor("Stop Firefox using secretvault")
	h.waitForWords("the secretvault extension cannot fill logins there")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("firefox: removed ")
	if _, err := os.Stat(filepath.Join(dir, svext.HostName+".json")); err == nil {
		t.Fatal("the manifest is still there")
	}
	h.key(tcell.KeyEscape)

	// The extension, written out to load.
	zip := filepath.Join(h.dir, "ext.zip")
	h.typeText("e")
	h.waitFor("A .zip file, for Firefox")
	h.key(tcell.KeyEnter)
	h.waitFor("Path:")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(zip)
	h.key(tcell.KeyEnter)
	h.waitFor("Load Temporary Add-on")
	if st, err := os.Stat(zip); err != nil || st.Size() < 1000 {
		t.Fatalf("the extension: %v", err)
	}
	h.key(tcell.KeyEscape)

	// And as a folder, for Chromium, with Chromium's manifest.
	folder := filepath.Join(h.dir, "ext-chromium")
	h.typeText("e")
	h.waitFor("A folder, for Chrome")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("Path:")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(folder)
	h.key(tcell.KeyEnter)
	h.waitFor("Load unpacked")
	written, err := os.ReadFile(filepath.Join(folder, "manifest.json"))
	if err != nil || !strings.Contains(string(written), `"service_worker"`) || strings.Contains(string(written), "browser_specific_settings") {
		t.Fatalf("the folder's manifest (%v):\n%s", err, written)
	}
}

func TestGPGIsPointedAtTheVaultAndBack(t *testing.T) {
	h := newHarness(t)
	cli := h.fakeCLI()
	// A gpg and a gpgconf of the test's own: they say where the agent's
	// socket is, and do nothing else.
	home := filepath.Join(h.dir, "ghome") // no other name starts so: Tab would complete it
	bin := filepath.Join(h.dir, "tools")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "gpg"), []byte("#!/bin/sh\ncat >/dev/null\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "gpgconf"), []byte("#!/bin/sh\ncase \"$*\" in\n*agent-ssh-socket*) echo "+home+"/S.gpg-agent.ssh ;;\n*agent-socket*) echo "+home+"/S.gpg-agent ;;\nesac\n"), 0o755)
	sock := filepath.Join(filepath.Dir(h.sock), "gpg-agent.sock")
	ln, cleanup, err := svd.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.d.ServeGPGAgent(ctx, ln)
	h.unlockAdmin("")
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}, Version: 4}); err != nil {
		t.Fatal(err)
	}
	h.lockAll()

	h.start(Options{CLI: cli}, "")
	h.unlock()
	h.menu("gnupg")
	h.waitFor("Let gpg use the vault's keys")
	h.typeText(home)
	h.tabs(1)
	h.typeText(filepath.Join(bin, "gpg"))
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Let gpg use the keys in vault personal")
	h.details()
	h.waitFor("Pointing the GnuPG home ")
	h.waitFor("import the public key")
	h.key(tcell.KeyBacktab) // Let gpg use the keys
	h.key(tcell.KeyEnter)
	h.waitFor("gpg now signs and decrypts with the keys in vault personal")
	conf, _ := os.ReadFile(filepath.Join(home, "gpg.conf"))
	if !strings.Contains(string(conf), "agent-program "+cli+"|"+svops.GPGAgentProgramFlag) {
		t.Fatalf("gpg.conf: %s", conf)
	}
	h.key(tcell.KeyEscape)

	h.menu("gnupg")
	h.waitFor("Let gpg use the vault's keys")
	h.typeText(home)
	h.tabs(2)
	h.key(tcell.KeyEnter) // stop
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitForWords("gpg goes back to its own agent")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitSaid("no longer uses the vault's keys")
	conf, _ = os.ReadFile(filepath.Join(home, "gpg.conf"))
	if strings.Contains(string(conf), svops.GPGAgentProgramFlag) {
		t.Fatalf("gpg.conf still names secretvault: %s", conf)
	}
}

func TestProgramHelpersAreLinkedAndConfigured(t *testing.T) {
	h := newHarness(t)
	cli := h.fakeCLI()
	t.Setenv("DOCKER_CONFIG", filepath.Join(h.home, ".docker"))
	var git []string
	h.commandAnswer = func(name string, args ...string) ([]byte, error) {
		if filepath.Base(name) != "git" {
			return nil, os.ErrNotExist
		}
		switch {
		case slices.Contains(args, "--get-all"):
			return []byte(strings.Join(git, "\n")), nil
		case slices.Contains(args, "--add"):
			git = append(git, args[len(args)-1])
		case slices.Contains(args, "--unset-all"):
			git = nil
		}
		return nil, nil
	}
	h.start(Options{CLI: cli}, "")
	h.unlock()
	h.menu("program helpers")
	h.waitFor("Program helpers")
	h.waitFor("git-credential-secretvault")
	h.waitFor("not there")
	h.typeText("s")
	h.waitFor("Set up git, docker and age")
	h.details()
	h.waitFor("git config --global --add credential.helper secretvault")
	h.key(tcell.KeyBacktab) // Set up git, docker and age
	h.key(tcell.KeyEnter)
	h.waitFor("git, docker and age can use secretvault")
	if target, err := os.Readlink(filepath.Join(h.dir, "bin", "docker-credential-secretvault")); err != nil || target != "secretvault" {
		t.Fatalf("the docker link: %q %v", target, err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.home, ".docker", "config.json")); !strings.Contains(string(b), `"credsStore": "secretvault"`) {
		t.Fatalf("docker's config: %s", b)
	}
	if !slices.Equal(git, []string{"secretvault"}) {
		t.Fatalf("git's helpers: %q", git)
	}
	h.key(tcell.KeyEscape)
	h.waitFor("keeps its logins in your vault")

	h.typeText("u")
	h.waitFor("Stop git, docker and age using secretvault")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("git, docker and age no longer use secretvault")
	if _, err := os.Lstat(filepath.Join(h.dir, "bin", "git-credential-secretvault")); err == nil {
		t.Fatal("the git link is still there")
	}
}
