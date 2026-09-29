// Command secretvaultd is the secretvault daemon. It is a stub in
// milestone 0; docs/roadmap.md (M1) and docs/architecture.md describe what
// it becomes:
//
//   - One binary, three modes. "user" (the default) runs per login session:
//     it holds the user's vaults unlocked, locks them on idle, screen lock
//     and suspend, and serves every local face (CLI, TUI, GUI, Secret
//     Service on D-Bus, the SSH agent, git and docker credential helpers,
//     age plugin requests). "host" runs as a system service for machine
//     secrets (systemd credentials, volume unlock), unlocked by TPM or a
//     host key. "server" serves secretvault's own HTTPS API, for sync
//     between devices (it stores only ciphertext) and for delivering
//     secrets to services and CI, with Shamir unseal, auth methods,
//     policies and an audit log.
//
//   - Clients speak JSON-RPC 2.0, one object per line, over a Unix socket
//     ($XDG_RUNTIME_DIR/secretvaultd.sock, 0600, same-uid peers only by
//     SO_PEERCRED / LOCAL_PEERCRED) or, on Windows, the named pipe
//     \\.\pipe\secretvaultd-<user SID> with an owner-only DACL.
//
//   - It is a consent broker: when a program asks for a secret, the daemon
//     works out which program it is (path and publisher signature) and,
//     unless a remembered decision covers it, asks the person: allow once,
//     until the vault locks, always, or deny. Prompts run as
//     secretvault-gui-prompt or secretvault-tui-prompt over the pinentry
//     (Assuan) protocol, or on the terminal of the CLI that asked.
//
// The daemon links no user-interface code (see daemon_test.go).
package main

import (
	"fmt"
	"os"

	"github.com/codemodify/secretvault"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("secretvaultd", secretvault.Version)
		return
	}
	fmt.Fprintln(os.Stderr, "secretvaultd: not implemented yet (milestone M1, see docs/roadmap.md);")
	fmt.Fprintln(os.Stderr, "the secretvault CLI opens vaults directly in the meantime.")
	os.Exit(1)
}
