//go:build linux

package svmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The desktop's setup, against the test's own home, data folders and
// fake programs: nothing reaches the real ~/.gnupg, browser profiles,
// keyring, systemd or /etc. Every change is shown as a plan first, and
// what other programs are told to start is the CLI, never this program.

// openDesktopPage opens the desktop page at tab.
func (h *harness) openDesktopPage(tab int) *desktopPage {
	h.t.Helper()
	h.m.showDesktopPage(tab)
	h.waitFor("the desktop page", h.m.showingVaultPage)
	h.idle()
	return h.m.dpage
}

// fakeCLI is a stand-in for the secretvault CLI installed beside the
// manager: a file in the test's directory, which nothing runs.
func (h *harness) fakeCLI() string {
	h.t.Helper()
	bin := filepath.Join(h.dir, "bin")
	os.MkdirAll(bin, 0o755)
	cli := filepath.Join(bin, "secretvault")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.m.cliProgram = func() string { return cli }
	return cli
}

// under reports whether path is inside dir.
func under(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && !strings.HasPrefix(rel, "..")
}

func TestTheKeyringIsTakenOverAndGivenBackOnAPlan(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	data := os.Getenv("XDG_DATA_HOME")
	if !strings.Contains(data, "svgui-env") {
		t.Fatalf("XDG_DATA_HOME is %q, not the test's", data)
	}
	h.openDesktopPage(tabKeyring)
	h.waitText("no session bus")

	// Importing needs the keyring on the session bus, which there is not.
	h.pressOn("Import its secrets…")
	h.press("Preview")
	if got := h.failed(); got == "" {
		t.Fatal("reading a keyring with no bus said nothing")
	}
	h.press("Cancel")

	h.m.daemonExe = func() string { return "/opt/test/secretvaultd" }
	h.pressOn("Become the keyring…")
	h.waitText("Become the keyring")
	h.press("Next")
	h.waitText("Becoming the keyring would:")
	service := filepath.Join(data, "dbus-1", "services", "org.freedesktop.secrets.service")
	if !strings.Contains(h.text(), "write "+service) || !strings.Contains(h.text(), "turn on secretvaultd's Secret Service") {
		t.Fatalf("the plan:\n%s", h.text())
	}
	for _, line := range strings.Split(h.text(), "\n") {
		if f, ok := strings.CutPrefix(line, "write "); ok && !under(f, filepath.Dir(data)) {
			t.Fatalf("the plan writes %s, outside the test's directories", f)
		}
	}
	if _, err := os.Stat(service); err == nil {
		t.Fatal("the plan wrote before it was said yes to")
	}
	h.press("Cancel")
	if _, err := os.Stat(service); err == nil {
		t.Fatal("a plan said no to was carried out")
	}

	// Carried out, in the test's directories: the Secret Service cannot
	// be served with no session bus, which is said.
	h.pressOn("Become the keyring…")
	h.waitText("Become the keyring")
	h.press("Next")
	h.waitText("Becoming the keyring would:")
	h.press("Become the keyring")
	h.waitText("Wrote " + service)
	if b, err := os.ReadFile(service); err != nil || !strings.Contains(string(b), "Exec=/opt/test/secretvaultd") {
		t.Fatalf("the activation file: %q %v", b, err)
	}
	h.press("Close")
	h.idle()
	if _, err := svops.LoadTakeover(); err != nil {
		t.Fatalf("no record of the takeover: %v", err)
	}

	h.pressOn("Give it back…")
	h.waitText("Giving the keyring back")
	if !strings.Contains(h.text(), "remove "+service) {
		t.Fatalf("the plan:\n%s", h.text())
	}
	h.press("Give it back")
	h.waitText("Removed " + service)
	if _, err := os.Stat(service); err == nil {
		t.Fatal("the activation file is still there")
	}
	if _, err := svops.LoadTakeover(); err == nil {
		t.Fatal("the takeover is still recorded")
	}
	h.press("Close")
}

func TestBrowsersAreSetUpForTheCLIAndUndone(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	home := os.Getenv("HOME")
	if !strings.Contains(home, "svgui-env") {
		t.Fatalf("HOME is %q, not the test's", home)
	}

	// With no CLI beside this program, nothing is offered.
	h.m.cliProgram = func() string { return "" }
	h.openDesktopPage(tabBrowsers)
	h.waitText("not installed beside this one")
	if b := button(h.m.ui.main, "Set up…"); b == nil || b.Enabled() {
		t.Fatal("Set up… was offered with no CLI to name")
	}

	cli := h.fakeCLI()
	h.m.dpage.panes[tabBrowsers].refresh()
	h.idle()
	h.pressOn("Set up…")
	h.tick("Firefox", true)
	h.press("Next")
	h.waitText("The browsers would start " + cli)
	manifest := filepath.Join(home, ".mozilla", "native-messaging-hosts", "org.keepassxc.keepassxc_browser.json")
	if !strings.Contains(h.text(), "firefox: write "+manifest) {
		t.Fatalf("the plan:\n%s", h.text())
	}
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("the plan wrote before it was said yes to")
	}
	h.press("Set them up")
	h.waitText("firefox: wrote " + manifest)
	h.press("Close")
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var mf svops.NativeManifest
	exe, _ := os.Executable()
	if json.Unmarshal(b, &mf) != nil || mf.Path != cli || mf.Path == exe {
		t.Fatalf("the manifest names %q (the CLI is %s, this program %s)", mf.Path, cli, exe)
	}
	h.idle()
	h.pressOn("Undo…")
	h.waitText("Undoing would:")
	h.press("Undo")
	h.waitText("Browsers' setup undone")
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("the manifest is still there")
	}
	h.press("Close")
}

// fakeGnuPG writes stand-ins for gpg and gpgconf that name sockets in the
// test's directory and do nothing else.
func (h *harness) fakeGnuPG() (gpg, sockDir string) {
	h.t.Helper()
	dir := filepath.Join(h.dir, "gnupg-bin")
	sockDir = filepath.Join(h.dir, "gs")
	os.MkdirAll(dir, 0o755)
	os.MkdirAll(sockDir, 0o700)
	gpgconf := "#!/bin/sh\ncase \"$*\" in\n*agent-ssh-socket*) echo " + filepath.Join(sockDir, "S.gpg-agent.ssh") +
		" ;;\n*agent-socket*) echo " + filepath.Join(sockDir, "S.gpg-agent") + " ;;\nesac\n"
	os.WriteFile(filepath.Join(dir, "gpgconf"), []byte(gpgconf), 0o755)
	os.WriteFile(filepath.Join(dir, "gpg"), []byte("#!/bin/sh\ncat >/dev/null\nexit 0\n"), 0o755)
	return filepath.Join(dir, "gpg"), sockDir
}

func TestGnuPGIsPointedAtTheDaemonForTheCLI(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	agent := filepath.Join(h.dir, "s", "gpg-agent.sock")
	ln, cleanup, err := svd.Listen(agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.d.ServeGPGAgent(ctx, ln)
	h.prove()
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpc.PGPGenerateParams{Name: "Ada", Emails: []string{"ada@example.org"}, Version: 4}); err != nil {
		t.Fatal(err)
	}
	cli := h.fakeCLI()
	gpg, sockDir := h.fakeGnuPG()
	home := filepath.Join(h.dir, "gnupg-home")

	h.openDesktopPage(tabGnuPG)
	h.pressOn("Let gpg use the vault's keys…")
	h.fill("GnuPG home", home)
	h.fill("gpg", gpg)
	h.press("Next")
	h.waitText("Pointing the GnuPG home " + home + " at secretvault would:")
	if !strings.Contains(h.text(), "make the directory "+home) || !strings.Contains(h.text(), "agent-program "+cli+"|--secretvault-gpg-agent") {
		t.Fatalf("the plan:\n%s", h.text())
	}
	if _, err := os.Stat(home); err == nil {
		t.Fatal("the plan made the home before it was said yes to")
	}
	h.press("Do it")
	h.waitText("signs and decrypts with secretvault's keys")
	h.press("Close")
	conf, err := os.ReadFile(filepath.Join(home, "gpg.conf"))
	if err != nil || !strings.Contains(string(conf), "agent-program "+cli+"|") {
		t.Fatalf("gpg.conf: %q %v", conf, err)
	}
	if target, err := os.Readlink(filepath.Join(sockDir, "S.gpg-agent")); err != nil || target != agent {
		t.Fatalf("the agent socket leads to %q (%v)", target, err)
	}

	h.idle()
	h.pressOn("Stop…")
	h.fill("GnuPG home", home)
	h.press("Next")
	h.waitText("Removing would take away:")
	h.press("Remove")
	h.said("is no longer pointed at secretvault")
	if conf, _ := os.ReadFile(filepath.Join(home, "gpg.conf")); strings.Contains(string(conf), "agent-program") {
		t.Fatalf("gpg.conf still names secretvault:\n%s", conf)
	}
}

func TestProgramHelpersSayWhereTheirLinksAre(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	cli := h.fakeCLI()
	link := filepath.Join(filepath.Dir(cli), "git-credential-secretvault")
	if err := os.Symlink("secretvault", link); err != nil {
		t.Fatal(err)
	}
	h.openDesktopPage(tabHelpers)
	h.waitText("Link: " + link)
	h.pressOn("Copy git's setting")
	if got := h.clip.last(); got == nil || got.text != "git config --global credential.helper secretvault" {
		t.Fatalf("copied %+v", got)
	}
	h.pressOn("Show git's logins")
	if h.m.showingVaultPage() {
		t.Fatal("still on the desktop page")
	}
}

// fakeGit stands in for git while the test runs, keeping
// credential.helper in the slice it returns; every other command is
// refused, as the harness's fake refuses it.
func (h *harness) fakeGit() *[]string {
	h.t.Helper()
	var git []string
	var mu sync.Mutex
	run := svops.CommandRunner
	h.t.Cleanup(func() { svops.CommandRunner = run })
	svops.CommandRunner = func(name string, args ...string) ([]byte, error) {
		if name != "git" {
			return run(name, args...)
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case slices.Contains(args, "--get-all"):
			if len(git) == 0 {
				return nil, errors.New("exit status 1")
			}
			return []byte(strings.Join(git, "\n") + "\n"), nil
		case slices.Contains(args, "--add"):
			git = append(git, args[len(args)-1])
		case slices.Contains(args, "--unset-all"):
			git = slices.DeleteFunc(git, func(s string) bool { return s == "secretvault" })
		}
		return nil, nil
	}
	return &git
}

func TestProgramHelpersAreSetUpOnAPlanAndUndone(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	docker := filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json")
	if !strings.Contains(docker, "svgui-env") {
		t.Fatalf("docker's config is %q, not the test's", docker)
	}
	os.MkdirAll(filepath.Dir(docker), 0o700)
	os.WriteFile(docker, []byte(`{"auths": {"r.example": {}}, "credsStore": "desktop"}`), 0o600)
	t.Cleanup(func() {
		os.RemoveAll(filepath.Dir(docker))
		os.Remove(filepath.Join(os.Getenv("SECRETVAULT_HOME"), "helpers.json"))
	})
	git := h.fakeGit()

	// With no CLI beside this program, nothing is offered.
	h.m.cliProgram = func() string { return "" }
	h.openDesktopPage(tabHelpers)
	h.waitText("not installed beside this one")
	if b := button(h.m.ui.main, "Set up…"); b == nil || b.Enabled() {
		t.Fatal("Set up… was offered with no CLI to name")
	}

	cli := h.fakeCLI()
	link := filepath.Join(filepath.Dir(cli), "git-credential-secretvault")
	h.m.dpage.panes[tabHelpers].refresh()
	h.waitText("credsStore is desktop")
	h.waitText("secretvault is not among git's credential helpers")
	if b := button(h.m.ui.main, "Undo…"); b == nil || b.Enabled() {
		t.Fatal("Undo… was offered with nothing to undo")
	}

	// The plan, said no to: nothing changes.
	h.pressOn("Set up…")
	h.waitText("Setting the helpers up, as links to " + cli + ", would:")
	for _, want := range []string{"- link " + link + " to secretvault", "- git config --global --add credential.helper secretvault",
		`- set "credsStore": "secretvault" in ` + docker + `, in place of "desktop"`} {
		if !strings.Contains(h.text(), want) {
			t.Fatalf("the plan lacks %q:\n%s", want, h.text())
		}
	}
	h.press("Cancel")
	h.idle()
	if _, err := os.Lstat(link); err == nil || len(*git) != 0 {
		t.Fatal("a plan said no to was carried out")
	}

	// Said yes to: carried out, and the pane filled again.
	h.pressOn("Set up…")
	h.waitText("Setting the helpers up")
	h.press("Set them up")
	h.waitText("linked " + link)
	h.press("Close")
	h.idle()
	if target, err := os.Readlink(link); err != nil || target != "secretvault" {
		t.Fatalf("the git link leads to %q (%v)", target, err)
	}
	if !slices.Equal(*git, []string{"secretvault"}) {
		t.Fatalf("git's helpers: %q", *git)
	}
	if b, _ := os.ReadFile(docker); !strings.Contains(string(b), `"credsStore": "secretvault"`) || !strings.Contains(string(b), "r.example") {
		t.Fatalf("docker's config: %s", b)
	}
	h.waitText("credential.helper includes secretvault")
	h.waitText("credsStore is secretvault (" + docker + ")")
	h.waitText("Link: " + link)

	// Undone, on a plan too: only what is secretvault's goes.
	h.pressOn("Undo…")
	h.waitText("Undoing the helpers would:")
	if !strings.Contains(h.text(), "- remove the link "+link) || !strings.Contains(h.text(), `- put "credsStore": "desktop" back in `+docker) {
		t.Fatalf("the undo plan:\n%s", h.text())
	}
	h.press("Undo")
	h.waitText("removed " + link)
	h.press("Close")
	h.idle()
	if _, err := os.Lstat(link); err == nil {
		t.Fatal("the git link is still there")
	}
	if _, err := os.Stat(cli); err != nil {
		t.Fatal("the CLI itself was removed")
	}
	if len(*git) != 0 {
		t.Fatalf("git's helpers: %q", *git)
	}
	if b, _ := os.ReadFile(docker); !strings.Contains(string(b), `"credsStore": "desktop"`) {
		t.Fatalf("docker's config: %s", b)
	}
	h.waitText("credsStore is desktop")
	if b := button(h.m.ui.main, "Undo…"); b == nil || b.Enabled() {
		t.Fatal("Undo… is offered with nothing left to undo")
	}
}

// hostDaemon starts a host daemon on the test's host directories
// (SECRETVAULT_HOST_DATA, SECRETVAULT_HOST_RUNTIME): its admin socket's
// peer is root.
func (h *harness) hostDaemon() {
	h.t.Helper()
	d, err := svd.New(svd.Options{
		Mode: svd.ModeHost, Home: svrpc.HostDataDir(),
		Host: svd.HostOptions{Runtime: svrpc.HostRuntimeDir(), FromServiceManager: func(net.Conn) error { return nil }},
		Peer: func(c net.Conn) (*svpeer.Process, error) {
			if strings.HasSuffix(c.LocalAddr().String(), svrpc.HostAdminSocketName) {
				return &svpeer.Process{PID: 1, UID: os.Getuid(), Exe: "/usr/bin/secretvault", SystemOwned: true}, nil
			}
			return &svpeer.Process{PID: 2, UID: 4242, Exe: "/usr/local/bin/backup", SystemOwned: true}, nil
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	lns, err := d.ListenHost()
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { d.ServeCredentials(ctx, lns.Credentials); wg.Done() }()
	go func() { d.ServeServices(ctx, lns.Services); wg.Done() }()
	go func() { d.Serve(ctx, lns.Admin); wg.Done() }()
	h.t.Cleanup(func() { cancel(); wg.Wait(); lns.Close() })
}

func TestTheHostDaemonIsSetUp(t *testing.T) {
	data := svrpc.HostDataDir()
	if !strings.Contains(data, "svgui-env") {
		t.Fatalf("the host's data is %q, not the test's", data)
	}
	os.RemoveAll(data)
	t.Cleanup(func() { os.RemoveAll(data); os.RemoveAll(svrpc.HostRuntimeDir()) })
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	var credsArgs []string
	h.m.systemdCreds = func(stdin []byte, args ...string) ([]byte, error) {
		credsArgs = args
		return nil, nil
	}

	// No host daemon: what it is, and the identity can still be made.
	h.openDesktopPage(tabHost)
	h.waitText("does not answer on " + svrpc.HostAdminSocket())
	h.pressOn("Make the host identity…")
	h.press("Make")
	h.waitText("Made the host identity, in " + svrpc.HostIdentityFile())
	h.press("Close")
	if st, err := os.Stat(svrpc.HostIdentityFile()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the identity file: %v %v", st, err)
	}
	credstore := filepath.Join(h.dir, "credstore", "secretvault-host.identity")
	h.idle()
	h.pressOn("Make the host identity…")
	h.tick("Seal it with systemd-creds", true)
	h.fill("TPM2 PCRs", "7")
	h.fill("Sealed, to", credstore)
	h.press("Make")
	h.waitText("sealed in " + credstore)
	h.press("Close")
	if got := strings.Join(credsArgs, " "); got != "encrypt --name=secretvault-host.identity --tpm2-pcrs=7 - "+credstore {
		t.Fatalf("systemd-creds %s", got)
	}

	// The host daemon running: its status, policy and log, and a rule.
	h.hostDaemon()
	h.m.dpage.panes[tabHost].refresh()
	h.waitText("secretvaultd --host")
	h.pressOn("Allow…")
	h.fill("Unit", "backup.service")
	h.fill("Credential", "db-password")
	h.fill("References", "sv://prod/db/postgres")
	h.press("Allow")
	h.waitText("backup.service now gets its credential db-password")
	h.press("Close")
	h.idle()
	if !strings.Contains(h.text(), "backup.service") || !strings.Contains(h.text(), "changed") {
		t.Fatalf("the policy and the log:\n%s", h.text())
	}
	h.pressOn("Deny…")
	h.fill("Unit", "backup.service")
	h.fill("Credential", "db-password")
	h.press("Deny")
	h.said("Removed from the host policy.")
}
