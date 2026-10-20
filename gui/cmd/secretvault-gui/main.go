// Command secretvault-gui is the desktop password manager, built on
// github.com/codemodify/uitoolkit: vaults with their lock state, the
// folders their item names make, instant search, items with masked values
// and live one-time codes, an editor with the password generator, files,
// history and conflicts, grants and the audit log, and a tray icon to open
// it, search, and lock every vault from anywhere.
//
// It does whatever the secretvault CLI does, through the same daemon
// methods and svops functions (docs/interfaces.md maps each command to
// its place here). Its window has no menu bar: a toolbar along the top
// (the password generator, the shortcuts, About, Quit) and three tabs.
// Vault is the vaults, a padlock on each row, and beside them a tab for
// each kind of item (logins, passwords, passkeys, one-time codes, cards,
// notes, SSH and API keys…), each its items by folder with the item
// picked beside them; then My keys, Contacts, and Vault, whose own tabs
// are the ways it unlocks, sharing, devices, sync, grants, the audit log
// and settings. Disk lists
// the encrypted disk files whose keys the vaults keep, and shows the one
// picked. Tools holds files and mail signed or encrypted, references, the
// password generator, identity files, security keys, the other programs
// secretvault works with (every change shown as a plan before it is
// made), and where everything is kept. Every button has an icon, and
// every dialog is a window of its own.
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
//	Ctrl+Shift+G     the vault's grants; Ctrl+Shift+K the contacts
//	Escape           from a page back to the items
//	Ctrl+PgDn  PgUp  the next, the previous of the Vaults, Disks and Tools tabs
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
	"os/signal"
	"syscall"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/platform"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/gui/svmanager"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// EnvVault names the vault to show first when --vault is not given.
const EnvVault = "SECRETVAULT_VAULT"

// AppID is what a Linux desktop files the manager's windows under (the
// Wayland app_id, the X11 WM_CLASS): its own task-bar entry and window
// rules, apart from the prompt's, whatever the binary is called.
const AppID = "secretvault-gui"

func main() {
	_ = svcrypto.NoCoreDumps()
	platform.SetAppID(AppID)
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
	// The look is uitoolkit's: whatever its Settings say, and with nothing
	// chosen there, the desktop's light or dark mode, followed as it
	// changes.
	// Before any daemon has, move what an earlier version kept in one
	// folder to the settings and data folders (a running daemon did).
	if mv, err := svops.MoveOldFolderUnlessRunning(svrpc.DefaultSocket(), nil); err == nil && mv.Summary() != "" {
		fmt.Fprintln(os.Stderr, mv.Summary())
	}
	a := uitoolkit.New(uitoolkit.Options{})
	secretui.UseLook(a) // secretvault's own look, as chosen in Tools › Appearance
	m, err := svmanager.New(svmanager.Options{App: a, Vault: *vault, Tray: !*noTray})
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-gui:", err)
		os.Exit(1)
	}
	// Told to stop, it quits as if asked: what it holds is wiped, and a
	// copy it put on the clipboard is taken back (on Windows and macOS the
	// clipboard would otherwise keep it after the program is gone).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		a.Post(m.Quit)
	}()
	if err := m.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-gui:", err)
		os.Exit(1)
	}
}
