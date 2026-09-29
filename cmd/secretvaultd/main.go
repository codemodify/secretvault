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
// Usage:
//
//	secretvaultd              run (normally started by a client, or at login)
//	secretvaultd install      start at every login (systemd user unit, LaunchAgent, Run key)
//	secretvaultd uninstall    stop starting at login
//	secretvaultd -version
//
// It links no user-interface code (see daemon_test.go). Exit status 3
// means another secretvaultd already serves the socket.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
		case "install":
			exe, err := os.Executable()
			if err == nil {
				exe, err = filepath.EvalSymlinks(exe)
			}
			if err != nil {
				log.Fatal(err)
			}
			msg, err := svd.Install(exe)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(msg)
			return
		case "uninstall":
			msg, err := svd.Uninstall()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(msg)
			return
		default:
			fmt.Fprintln(os.Stderr, "usage: secretvaultd [install | uninstall | -version]")
			os.Exit(2)
		}
	}
	if err := svcrypto.HardenProcess(); err != nil {
		log.Printf("could not disable core dumps: %v", err)
	}
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
