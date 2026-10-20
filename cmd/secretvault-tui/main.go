// Command secretvault-tui is the terminal password manager: browse and
// filter vaults, view, edit and generate items, copy with auto-clear, see
// an item's history, and review what programs may do and have done, in a
// full-screen terminal interface.
//
// It is a client of secretvaultd, which it starts if it is not running,
// and holds no keys itself. When the daemon needs to know it is you, it
// asks here for the vault's passphrase, as it asks the CLI on its
// terminal. Copies go through the secretvault CLI installed beside it
// (secretvault __clip), and clear themselves after 30 seconds.
//
// Usage:
//
//	secretvault-tui [--vault NAME]
//
// Keys (? shows them all):
//
//	Tab, ← →      move between the vaults, the items and the open item
//	Enter         open the vault or the item under the cursor
//	/             filter the items as you type
//	c  u  o       copy the secret (or the selected field), the username, the one-time code
//	r             reveal or hide concealed values
//	e  n  d  m    edit, new item, delete, rename
//	h             the item's history
//	g             the password generator
//	l  L  U       lock this vault, lock every vault, unlock
//	G  A          grants (and revoking them), the audit log
//	q             quit
//
// Environment: SECRETVAULT_VAULT names the vault to show first,
// SECRETVAULT_SOCK the daemon's socket.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtui"
)

// EnvVault names the vault to show first when --vault is not given.
const EnvVault = "SECRETVAULT_VAULT"

func main() {
	_ = svcrypto.NoCoreDumps()
	fs := flag.NewFlagSet("secretvault-tui", flag.ContinueOnError)
	vault := fs.String("vault", os.Getenv(EnvVault), "the vault to show first (default: the default vault)")
	version := fs.Bool("version", false, "print the version")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if *version {
		fmt.Printf("secretvault-tui %s\n", secretvault.Version)
		return
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: secretvault-tui [--vault NAME]")
		os.Exit(2)
	}
	// Before any daemon has, move what an earlier version kept in one
	// folder to the settings and data folders (a running daemon did).
	if mv, err := svops.MoveOldFolderUnlessRunning(svrpc.DefaultSocket(), nil); err == nil && mv.Summary() != "" {
		fmt.Fprintln(os.Stderr, mv.Summary())
	}
	ui, err := svtui.New(svtui.Options{Vault: *vault})
	if err != nil {
		if errors.Is(err, secretvault.ErrNoDaemon) {
			fmt.Fprintln(os.Stderr, "secretvault-tui:", err, "(is secretvaultd installed beside secretvault-tui?)")
		} else {
			fmt.Fprintln(os.Stderr, "secretvault-tui:", err)
		}
		os.Exit(1)
	}
	if err := ui.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-tui:", err)
		os.Exit(1)
	}
}
