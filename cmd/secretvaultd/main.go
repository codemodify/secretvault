// Command secretvaultd is the secretvault daemon: it holds vault keys and
// brokers every access to them (see docs/architecture.md).
//
//   - Clients speak JSON-RPC 2.0, one object per line, over a Unix socket
//     ($XDG_RUNTIME_DIR/secretvault/secretvaultd.sock, 0600 in a 0700
//     directory; same-user peers only, checked by the kernel). On Windows
//     the socket is an AF_UNIX socket under %LOCALAPPDATA%.
//
//   - It is a consent broker: when a program asks for a secret, the daemon
//     works out which program it is and, unless a remembered decision
//     covers it, asks the person: allow once, until the vault locks,
//     always, or deny. secretvault's own CLI proves it is the person by
//     taking the vault's passphrase on its terminal.
//
//   - Prompts go to the CLI's terminal, a registered
//     `secretvault-tui-prompt --agent`, or the desktop's pinentry
//     (pinentry-gnome3/-qt/-gtk) until secretvault-gui-prompt exists.
//
//   - It is an SSH agent (ssh-agent.sock beside its socket; point
//     SSH_AUTH_SOCK at it): keys live in vaults, and each program's first
//     signature is asked about.
//
//   - Vaults lock after 15 idle minutes, when the screen locks and before
//     the machine sleeps (all adjustable per vault); every vault locks when
//     the user's last session ends and when the daemon stops.
//
// With --host it is instead the machine's system service (Linux, as
// root): it serves systemd's LoadCredential= on
// /run/secretvault/credentials.sock and local services on
// /run/secretvault/secretvaultd.sock, by the policy in
// /var/lib/secretvault/host.json, and asks nobody. Its vaults open with
// the host identity, which systemd passes as an encrypted credential (or
// which it reads from /var/lib/secretvault/host.identity). root manages it
// with 'secretvault host ...' over /run/secretvault/admin.sock.
//
// Usage:
//
//	secretvaultd              run (normally started by a client, or at login)
//	secretvaultd --host [--data DIR] [--runtime DIR] [--policy FILE] [--identity FILE]
//	                          run as the host's system service
//	secretvaultd install      start at every login (systemd user unit, LaunchAgent, Run key)
//	secretvaultd install --host [--plain-identity] [--no-start] [--unit-dir DIR]
//	                          install the host's system units (secretvaultd-host.service, .socket)
//	secretvaultd uninstall [--host]
//	secretvaultd -version
//
// Environment: SECRETVAULT_HOST_DATA and SECRETVAULT_HOST_RUNTIME move the
// host daemon's data and sockets, as --data and --runtime do.
//
// It links no user-interface code (see daemon_test.go). Exit status 3
// means another secretvaultd already serves the socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svrpc"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("secretvaultd: ")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-version", "--version", "version":
			fmt.Println("secretvaultd", secretvault.Version)
			return
		case "install", "uninstall":
			os.Exit(install(os.Args[1], os.Args[2:]))
		}
	}
	fs := flag.NewFlagSet("secretvaultd", flag.ContinueOnError)
	host := fs.Bool("host", false, "run as the host's system service (Linux, as root)")
	var hf hostFlags
	hf.register(fs)
	if err := fs.Parse(os.Args[1:]); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: secretvaultd [--host [--data DIR] [--runtime DIR] [--policy FILE] [--identity FILE]] | install [--host] | uninstall [--host] | -version")
		os.Exit(2)
	}
	if !*host && hf != (hostFlags{}) {
		fmt.Fprintln(os.Stderr, "secretvaultd: --data, --runtime, --policy and --identity are for --host")
		os.Exit(2)
	}
	if err := svcrypto.HardenProcess(); err != nil {
		log.Printf("could not disable core dumps: %v", err)
	}
	if *host {
		os.Exit(runHost(hf))
	}
	runUser()
}

func runUser() {
	sock := svrpc.DefaultSocket()
	d, err := svd.New(svd.Options{Socket: sock, Log: func(s string) { log.Print(s) }})
	if err != nil {
		log.Fatal(err)
	}
	ln, cleanup, err := svd.Listen(sock)
	if err != nil {
		if errors.Is(err, svd.ErrRunning) {
			log.Print(err)
			os.Exit(3)
		}
		log.Fatal(err)
	}
	defer cleanup()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d.WatchSession(ctx) // lock on screen lock, sleep and logout
	d.StartSync(ctx)    // keep synced vaults in step with their servers
	d.UnlockAtLogin()   // open the vaults set to open at login
	if d.SSHAgentEnabled() {
		agentSock := svrpc.SSHAgentSocket()
		if aln, acleanup, err := svd.Listen(agentSock); err != nil {
			log.Printf("the SSH agent: %v", err)
		} else {
			defer acleanup()
			go d.ServeSSHAgent(ctx, aln)
			log.Printf("SSH agent on %s (export SSH_AUTH_SOCK=%s)", agentSock, agentSock)
		}
	}
	if d.SecretServiceEnabled() {
		if err := d.StartSecretService(ctx); err != nil {
			log.Printf("the Secret Service: %v", err)
		}
	}
	log.Printf("%s serving %s", secretvault.Version, sock)
	if err := d.Serve(ctx, ln); err != nil {
		log.Print(err)
	}
	log.Print("stopped; every vault is locked")
}

// hostFlags move the host daemon's files, for tests and unusual systems.
type hostFlags struct {
	data, runtime, policy, identity string
}

func (h *hostFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&h.data, "data", "", "--host: the data directory (default $"+svrpc.EnvHostData+", else /var/lib/secretvault)")
	fs.StringVar(&h.runtime, "runtime", "", "--host: the directory for its sockets (default $"+svrpc.EnvHostRuntime+", else /run/secretvault)")
	fs.StringVar(&h.policy, "policy", "", "--host: the policy file (default DATA/host.json)")
	fs.StringVar(&h.identity, "identity", "", "--host: the identity file read when systemd passes none (default DATA/host.identity)")
}

// options are the daemon's options for these flags.
func (h hostFlags) options() svd.Options {
	data, runtime := h.data, h.runtime
	if data == "" {
		data = svrpc.HostDataDir()
	}
	if runtime == "" {
		runtime = svrpc.HostRuntimeDir()
	}
	return svd.Options{
		Mode:   svd.ModeHost,
		Home:   data,
		Socket: filepath.Join(runtime, svrpc.HostAdminSocketName),
		Host:   svd.HostOptions{Runtime: runtime, Policy: h.policy, Identity: h.identity},
	}
}

// runHost runs the host daemon, and returns the exit status.
func runHost(hf hostFlags) int {
	opts := hf.options()
	opts.Log = func(s string) { log.Print(s) }
	d, err := svd.New(opts)
	if err != nil {
		log.Print(err)
		return 1
	}
	lns, err := d.ListenHost()
	if err != nil {
		log.Print(err)
		if errors.Is(err, svd.ErrRunning) {
			return 3
		}
		return 1
	}
	defer lns.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d.StartSync(ctx) // keep synced vaults in step with their servers
	// A socket that stops answering stops the daemon, so systemd restarts it.
	var failed atomic.Bool
	serve := func(what string, f func(context.Context, net.Listener) error, ln net.Listener) {
		if err := f(ctx, ln); err != nil {
			log.Printf("%s: %v", what, err)
			failed.Store(true)
			stop()
		}
	}
	go serve("the credential socket", d.ServeCredentials, lns.Credentials)
	go serve("the services socket", d.ServeServices, lns.Services)
	log.Printf("%s serving the host: credentials on %s, services on %s, root on %s", secretvault.Version,
		lns.Credentials.Addr(), lns.Services.Addr(), lns.Admin.Addr())
	if err := d.Serve(ctx, lns.Admin); err != nil {
		log.Print(err)
		failed.Store(true)
	}
	log.Print("stopped; every vault is locked")
	if failed.Load() {
		return 1
	}
	return 0
}

// install runs install or uninstall.
func install(cmd string, args []string) int {
	fs := flag.NewFlagSet("secretvaultd "+cmd, flag.ContinueOnError)
	host := fs.Bool("host", false, "the host daemon's system units (secretvaultd-host.service and .socket), not your login's")
	unitDir := fs.String("unit-dir", "", "--host: where the units go (default /etc/systemd/system)")
	var plain, noStart *bool
	if cmd == "install" {
		plain = fs.Bool("plain-identity", false, "--host: have the daemon read "+svrpc.HostDataDir()+"/host.identity, not a credential sealed with systemd-creds")
		noStart = fs.Bool("no-start", false, "--host: enable the units, but do not start them now")
	}
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2
	}
	var msg string
	var err error
	switch {
	case *host && cmd == "install":
		var exe string
		if exe, err = executable(); err == nil {
			msg, err = svd.InstallHost(exe, svd.HostInstall{UnitDir: *unitDir, PlainIdentity: *plain, NoStart: *noStart})
		}
	case *host:
		msg, err = svd.UninstallHost(svd.HostInstall{UnitDir: *unitDir})
	case *unitDir != "" || plain != nil && (*plain || *noStart):
		fmt.Fprintln(os.Stderr, "secretvaultd: --unit-dir, --plain-identity and --no-start are for --host")
		return 2
	case cmd == "install":
		var exe string
		if exe, err = executable(); err == nil {
			msg, err = svd.Install(exe)
		}
	default:
		msg, err = svd.Uninstall()
	}
	if err != nil {
		log.Print(err)
		return 1
	}
	fmt.Println(msg)
	return 0
}

// executable is this program's real path.
func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
