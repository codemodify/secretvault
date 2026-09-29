// Command secretvault-gui is the desktop password manager, built on
// github.com/codemodify/uitoolkit: vaults with their lock state, the
// folders their item names make, instant search, items with masked values
// and live one-time codes, an editor with the password generator, files,
// history and conflicts, grants and the audit log, and a tray icon to open
// it, search, and lock every vault from anywhere.
//
// It is a client of secretvaultd, which it starts if it is not running,
// and holds no keys itself. When the daemon needs to know it is you, it
// asks here, in a window of its own, for the vault's passphrase, as it asks
// the CLI on its terminal. Copies go to the clipboard marked for clipboard
// managers not to keep, and clear themselves after 30 seconds.
//
// Usage:
//
//	secretvault-gui [--vault NAME] [--no-tray]
//
// Keys (F1 shows them all):
//
//	Ctrl+F           search; Down goes to the results
//	Enter            open the item (or unlock the vault) selected
//	Ctrl+C           copy the password; Ctrl+B the username, Ctrl+T the code
//	Ctrl+Shift+C     copy the password and minimise the window
//	Ctrl+R           show or hide the concealed values
//	Ctrl+N  Ctrl+E   new item, edit item
//	F2  Delete       rename, delete (asks first)
//	Ctrl+H  Ctrl+G   history, password generator
//	Ctrl+U  Ctrl+L   unlock, lock; Ctrl+Shift+L locks every vault
//	Ctrl+W  Ctrl+Q   close the window (to the tray, if there is one), quit
//
// Environment: SECRETVAULT_VAULT names the vault to show first,
// SECRETVAULT_SOCK the daemon's socket. The look follows the desktop's
// light or dark mode, and uitoolkit's settings (UITK_THEME and the rest).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/codemodify/uitoolkit"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/gui/svmanager"
	"github.com/codemodify/secretvault/svcrypto"
)

// EnvVault names the vault to show first when --vault is not given.
const EnvVault = "SECRETVAULT_VAULT"

func main() {
	_ = svcrypto.NoCoreDumps()
	fs := flag.NewFlagSet("secretvault-gui", flag.ContinueOnError)
	vault := fs.String("vault", os.Getenv(EnvVault), "the vault to show first (default: the default vault)")
	noTray := fs.Bool("no-tray", false, "no tray icon: closing the window quits")
	version := fs.Bool("version", false, "print the version")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if *version {
		fmt.Printf("secretvault-gui %s\n", secretvault.Version)
		return
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: secretvault-gui [--vault NAME] [--no-tray]")
		os.Exit(2)
	}
	// The look is the desktop's: its light or dark mode, and whatever
	// uitoolkit's settings say.
	a := uitoolkit.New(uitoolkit.Options{})
	m, err := svmanager.New(svmanager.Options{App: a, Vault: *vault, Tray: !*noTray})
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-gui:", err)
		os.Exit(1)
	}
	if err := m.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-gui:", err)
		os.Exit(1)
	}
}
