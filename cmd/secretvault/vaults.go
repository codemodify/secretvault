package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

func (c *cli) cmdInit(args []string) error {
	fs := c.flags("init")
	name := fs.String("name", "", "the vault's name (default: \"default\", or --vault)")
	path := fs.String("path", "", "keep the vault in `DIR` instead of the data directory (a synced folder, say)")
	suite := fs.String("suite", "modern", "cipher suite: modern or nist")
	recovery := fs.Bool("recovery", false, "also make a recovery key, and print it once")
	passFile := fs.String("passphrase-file", "", "read the new passphrase from `FILE` instead of asking")
	if _, err := parse(fs, args, 0, 0, "[--name NAME] [--path DIR] [--suite modern|nist] [--recovery]"); err != nil {
		return err
	}
	if *name == "" {
		*name = c.vault
	}
	if *name == "" {
		*name = "default"
	}
	if *path != "" {
		abs, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		*path = abs
	}
	pass, err := c.newPassphrase(*passFile)
	if err != nil {
		return err
	}
	defer clear(pass)
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.CreateVault(ctx, svrpc.VaultCreateParams{Name: *name, Path: *path, Suite: *suite, Passphrase: pass, Recovery: *recovery})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Created vault %q (%s, %s) at %s\n", res.Vault.Name, res.Vault.ID, res.Vault.Suite, res.Vault.Path)
	if res.RecoveryKey != "" {
		c.printRecoveryKey(res.RecoveryKey)
	}
	return nil
}

func (c *cli) printRecoveryKey(rk string) {
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "Recovery key (write it down and keep it somewhere safe; it is shown only now):")
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "    "+rk)
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "It opens the vault on its own, like the passphrase: 'secretvault unlock --recovery'.")
}

func (c *cli) cmdUnlock(args []string) error {
	fs := c.flags("unlock")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[VAULT] [--passphrase-file F | --keyfile F | --identity F | --recovery | --shares]")
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		c.vault = pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	if !u.given() {
		ctx, cancel := c.ctx()
		defer cancel()
		if _, err := cl.Unlock(ctx, c.vault, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *cli) cmdLock(args []string) error {
	fs := c.flags("lock")
	all := fs.Bool("all", false, "lock every vault")
	pos, err := parse(fs, args, 0, 1, "[VAULT] [--all]")
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		c.vault = pos[0]
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	return cl.Lock(ctx, c.vault, *all)
}

func (c *cli) printVaults(vaults []svrpc.VaultInfo) error {
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATE\tAUTO-LOCK\tPATH")
	for _, v := range vaults {
		state := "unlocked"
		switch {
		case v.ID == "":
			state = "missing"
		case v.Locked:
			state = "locked"
		}
		name := v.Name
		if v.Default {
			name += " *"
		}
		lock := "never"
		switch {
		case v.LoginUnlock:
			lock = "at logout"
		case v.AutoLock.IdleMinutes > 0:
			lock = fmt.Sprintf("%d min idle", v.AutoLock.IdleMinutes)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, state, lock, v.Path)
	}
	return tw.Flush()
}

func (c *cli) cmdStatus(args []string) error {
	if _, err := parse(c.flags("status"), args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	st, err := cl.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "secretvaultd %s, process %d\n", st.Version, st.PID)
	if st.Mode == "host" {
		fmt.Fprintln(c.stdout, "mode:    host (the machine's service: 'secretvault host status' says more)")
	}
	fmt.Fprintf(c.stdout, "data:    %s\n", st.Home)
	if st.Socket != "" {
		fmt.Fprintf(c.stdout, "socket:  %s\n", st.Socket)
	}
	fmt.Fprintf(c.stdout, "prompts: %s\n", st.Prompts)
	fmt.Fprintf(c.stdout, "keyring: %s\n", st.SecretService)
	if st.SSHAgent != "" {
		fmt.Fprintf(c.stdout, "ssh:     %s (export SSH_AUTH_SOCK=%s)\n", st.SSHAgent, st.SSHAgent)
	}
	if st.GPGAgent != "" {
		homes := "no GnuPG home pointed at it yet: 'secretvault pgp gpg-setup'"
		if len(st.GnuPGHomes) > 0 {
			homes = "for " + strings.Join(st.GnuPGHomes, ", ")
		}
		fmt.Fprintf(c.stdout, "gpg:     %s (%s)\n", st.GPGAgent, homes)
	}
	fmt.Fprintln(c.stdout)
	if len(st.Emergency) > 0 {
		fmt.Fprintln(c.stdout, "Emergency access:")
		for _, n := range st.Emergency {
			fmt.Fprintln(c.stdout, "  "+n.Text)
		}
		fmt.Fprintln(c.stdout)
	}
	if len(st.Vaults) == 0 {
		fmt.Fprintln(c.stdout, "No vaults yet: create one with 'secretvault init'.")
		return nil
	}
	return c.printVaults(st.Vaults)
}

func (c *cli) cmdVault(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	switch args[0] {
	case "list", "ls":
		if _, err := parse(c.flags("vault list"), args[1:], 0, 0, ""); err != nil {
			return err
		}
		vaults, err := cl.Vaults(ctx)
		if err != nil {
			return err
		}
		return c.printVaults(vaults)
	case "create", "init":
		return c.cmdInit(args[1:])
	case "add":
		pos, err := parse(c.flags("vault add"), args[1:], 2, 2, "NAME DIR")
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(pos[1])
		if err != nil {
			return err
		}
		v, err := cl.AddVault(ctx, pos[0], abs)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Added vault %q (%s) at %s\n", v.Name, v.ID, v.Path)
		return nil
	case "forget":
		pos, err := parse(c.flags("vault forget"), args[1:], 1, 1, "NAME   (the folder is left as it is)")
		if err != nil {
			return err
		}
		return cl.ForgetVault(ctx, pos[0])
	case "default":
		pos, err := parse(c.flags("vault default"), args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return cl.SetDefault(ctx, pos[0])
	case "rotate":
		return c.rotate(args[1:], nil)
	case "login":
		fs := c.flags("vault login")
		var u unlockFlags
		u.register(fs)
		pos, err := parse(fs, args[1:], 1, 1, "on|off   (open the vault when you log in, with a key the system keeps for you)")
		if err != nil {
			return err
		}
		if pos[0] != "on" && pos[0] != "off" {
			return fmt.Errorf("vault login: %q is neither on nor off", pos[0])
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		v, err := cl.SetLoginUnlock(ctx, c.vault, pos[0] == "on")
		if err != nil {
			return err
		}
		if v.LoginUnlock {
			fmt.Fprintf(c.stdout, "Vault %q opens when you log in, and locks when you log out. Programs still ask before they read it.\n", v.Name)
		} else {
			fmt.Fprintf(c.stdout, "Vault %q no longer opens at login; it locks after %d idle minutes, on screen lock and on sleep.\n", v.Name, v.AutoLock.IdleMinutes)
		}
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault vault: unknown subcommand %q (list, add, forget, default, rotate, login)\n", args[0])
	return errUsage
}

func (c *cli) cmdVersion(args []string) error {
	if _, err := parse(c.flags("version"), args, 0, 0, ""); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "secretvault %s\n", secretvault.Version)
	return nil
}
