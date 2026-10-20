package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svsecret"
)

// `secretvault keyring`: making secretvault the desktop's keyring (the
// Secret Service, org.freedesktop.secrets) on Linux.
//
//	status     who holds the keyring now
//	import     copy every secret out of the current keyring into a vault
//	takeover   import, then make secretvault the keyring from now on
//	restore    undo takeover exactly
//
// What the takeover changes, and how it is undone, is svops'
// (keyring.go): here are the flags, the dry runs and the daemon's part.

func (c *cli) cmdKeyring(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	if args[0] != "status" {
		if err := svops.KeyringHere(); err != nil {
			return err
		}
	}
	switch args[0] {
	case "status":
		return c.keyringStatus(args[1:])
	case "import":
		return c.keyringImport(args[1:])
	case "takeover":
		return c.keyringTakeover(args[1:])
	case "restore":
		return c.keyringRestore(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault keyring: unknown subcommand %q (status, import, takeover, restore)\n", args[0])
	return errUsage
}

func (c *cli) keyringStatus(args []string) error {
	if _, err := parse(c.flags("keyring status"), args, 0, 0, ""); err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	switch h := svops.KeyringHolderNow(ctx); {
	case h.BusErr != nil:
		fmt.Fprintf(c.stdout, "keyring:   no session bus (%v)\n", h.BusErr)
	case h.Held:
		fmt.Fprintf(c.stdout, "keyring:   %s (process %d)\n", svops.DescribeExe(h.Owner.Exe), h.Owner.PID)
	default:
		fmt.Fprintln(c.stdout, "keyring:   none (nothing holds org.freedesktop.secrets)")
	}
	if cl, err := c.daemon(); err == nil {
		if st, err := cl.Status(ctx); err == nil {
			fmt.Fprintf(c.stdout, "secretvault: %s\n", st.SecretService)
		}
	}
	if s, err := svops.LoadTakeover(); err == nil {
		fmt.Fprintf(c.stdout, "takeover:  done %s (undo with 'secretvault keyring restore')\n", s.When.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

// keyringImport copies every secret out of the current keyring.
func (c *cli) keyringImport(args []string) error {
	fs := c.flags("keyring import")
	dryRun := fs.Bool("dry-run", false, "list what would be imported, and import nothing")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	n, err := c.importFromKeyring(&u, *dryRun)
	if err == nil && !*dryRun {
		fmt.Fprintf(c.stdout, "Imported %d secrets.\n", n)
	}
	return err
}

func (c *cli) importFromKeyring(u *unlockFlags, dryRun bool) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	secrets, warnings, err := svops.ReadKeyring(ctx, func(o svsecret.Owner) {
		fmt.Fprintf(c.stderr, "Reading from %s; it may ask you to unlock it.\n", svops.DescribeExe(o.Exe))
	})
	if err != nil {
		return 0, err
	}
	defer func() {
		for i := range secrets {
			secrets[i].Wipe()
		}
	}()
	for _, w := range warnings {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
	if dryRun {
		names, _, _ := svops.ImportKeyring(ctx, nil, c.vault, secrets)
		for _, name := range names {
			fmt.Fprintln(c.stdout, name)
		}
		return 0, nil
	}
	cl, err := c.open(u)
	if err != nil {
		return 0, err
	}
	_, n, err := svops.ImportKeyring(ctx, cl, c.vault, secrets)
	return n, err
}

func (c *cli) keyringTakeover(args []string) error {
	fs := c.flags("keyring takeover")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	noImport := fs.Bool("no-import", false, "do not copy the current keyring's secrets first")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--dry-run] [--no-import]"); err != nil {
		return err
	}
	if s, err := svops.LoadTakeover(); err == nil {
		return fmt.Errorf("the takeover was already done on %s", s.When.Local().Format("2006-01-02"))
	}
	daemon := svops.SiblingProgram("secretvaultd")
	if daemon == "" {
		return errors.New("no secretvaultd beside this program")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	exe := ""
	if h := svops.KeyringHolderNow(ctx); h.Held {
		exe = h.Owner.Exe
	}
	p, err := svops.PlanTakeover(exe, daemon)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(c.stdout, "%s\n\n", svops.TakeoverPlain(p, exe, !*noImport, c.vault).Text())
		for _, l := range svops.TakeoverLines(p, exe, !*noImport) {
			fmt.Fprintln(c.stdout, l)
		}
		return nil
	}
	if !*noImport && exe != "" {
		n, err := c.importFromKeyring(&u, false)
		if err != nil {
			return fmt.Errorf("importing first (use --no-import to skip): %w", err)
		}
		fmt.Fprintf(c.stdout, "Imported %d secrets.\n", n)
	}
	written, err := svops.ApplyTakeover(p, exe)
	for _, f := range written {
		fmt.Fprintf(c.stdout, "Wrote %s\n", f)
	}
	if err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	if err := cl.ServeKeyring(ctx, true); err != nil {
		return err
	}
	for _, f := range svops.RestartUnits(p.Restart) {
		fmt.Fprintf(c.stderr, "warning: restarting %s: %v %s\n", f.Unit, f.Err, f.Output)
	}
	for _, n := range p.Notes {
		fmt.Fprintln(c.stdout, "Still to do by hand:", n)
	}
	fmt.Fprintln(c.stdout, "secretvault is now the keyring. Undo with 'secretvault keyring restore'.")
	return nil
}

func (c *cli) keyringRestore(args []string) error {
	fs := c.flags("keyring restore")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	s, err := svops.LoadTakeover()
	if errors.Is(err, fs2NotExist) {
		return errors.New("there is no takeover to undo")
	}
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(c.stdout, "%s\n\n", svops.RestorePlain(s).Text())
		for _, l := range svops.RestoreLines(s) {
			fmt.Fprintln(c.stdout, l)
		}
		return nil
	}
	if cl, err := c.daemon(); err == nil {
		ctx, cancel := c.ctx()
		defer cancel()
		if err := cl.ServeKeyring(ctx, false); err != nil {
			fmt.Fprintf(c.stderr, "warning: %v\n", err)
		}
	}
	removed, _, err := svops.UndoTakeover(s) // as before, units that do not restart go unsaid
	for _, f := range removed {
		fmt.Fprintf(c.stdout, "Removed %s\n", f)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Restored: %s is the keyring again.\n", svops.DescribeExe(s.Previous))
	return nil
}

var fs2NotExist = fs.ErrNotExist
