package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

func (c *cli) cmdSync(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	fs := c.flags("sync " + args[0])
	var u unlockFlags
	u.register(fs)
	switch args[0] {
	case "setup":
		fp := fs.String("fingerprint", "", "the server certificate's SHA-256, as secretvault-server printed it (for a self-signed certificate)")
		tokenFile := fs.String("admin-token-file", "", "the server's admin token, in `FILE` (when it does not let anyone make vaults)")
		label := fs.String("label", "", "this device's name to the others (default: the host name)")
		pos, err := parse(fs, args[1:], 1, 1, "URL [--fingerprint FP] [--admin-token-file F] [--label L]")
		if err != nil {
			return err
		}
		token := ""
		if *tokenFile != "" {
			b, err := os.ReadFile(*tokenFile)
			if err != nil {
				return err
			}
			token = strings.TrimSpace(string(b))
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		st, err := cl.SyncSetup(ctx, svrpc.SyncSetupParams{Vault: c.vault, URL: pos[0], Fingerprint: *fp, AdminToken: token, Label: *label})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Vault %q now syncs with %s (sent %d files).\n", st.Vault, st.URL, st.Pushed)
		fmt.Fprintln(c.stdout, "To add another device: 'secretvault sync invite' here, then 'secretvault sync join INVITE' there.")
		return nil

	case "join":
		name := fs.String("name", "", "the vault's name on this device (default: \"default\", or --vault)")
		path := fs.String("path", "", "keep the vault in `DIR` instead of the data directory")
		label := fs.String("label", "", "this device's name to the others (default: the host name)")
		pos, err := parse(fs, args[1:], 1, 1, "INVITE|- [--name NAME] [--path DIR] [--label L]   (- reads the invite from standard input)")
		if err != nil {
			return err
		}
		invite := pos[0]
		if invite == "-" {
			line, err := bufio.NewReader(c.stdin).ReadString('\n')
			if err != nil && line == "" {
				return fmt.Errorf("no invite on standard input")
			}
			invite = strings.TrimSpace(line)
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
		cl, err := c.daemon()
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		v, err := cl.SyncJoin(ctx, svrpc.SyncJoinParams{Invite: invite, Name: *name, Path: *path, Label: *label})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Fetched vault %q (%s) into %s; it syncs from now on.\n", v.Name, v.ID, v.Path)
		fmt.Fprintf(c.stdout, "Unlock it with its passphrase: 'secretvault unlock %s'.\n", v.Name)
		return nil

	case "invite":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		inv, err := cl.SyncInvite(ctx, c.vault)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, "On the new device, run (before "+inv.Expires.Local().Format("15:04")+"; it works once):")
		fmt.Fprintln(c.stdout)
		fmt.Fprintln(c.stdout, "    secretvault sync join '"+inv.Invite+"'")
		fmt.Fprintln(c.stdout)
		fmt.Fprintln(c.stdout, "It gets the vault's ciphertext; opening it still takes the passphrase, or a keyslot you add for it.")
		return nil

	case "status", "st":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.daemon()
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		sts, err := cl.SyncStatus(ctx, c.vault)
		if err != nil {
			return err
		}
		if len(sts) == 0 {
			fmt.Fprintln(c.stdout, "No vault syncs with a server: set one up with 'secretvault sync setup URL'.")
			return nil
		}
		return c.printSyncStatus(sts)

	case "now":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		st, err := cl.SyncNow(ctx, c.vault)
		if err != nil {
			return err
		}
		return c.printSyncStatus([]svrpc.SyncStatus{st})

	case "devices":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		devs, err := cl.SyncDevices(ctx, c.vault)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KEY\tLABEL\tADDED\tLAST SEEN")
		for _, dv := range devs {
			label := dv.Label
			if dv.This {
				label += " (this device)"
			}
			seen := "never"
			if dv.LastSeen != nil {
				seen = dv.LastSeen.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", dv.Key, label, dv.Added.Local().Format("2006-01-02 15:04"), seen)
		}
		return tw.Flush()

	case "rm-device":
		pos, err := parse(fs, args[1:], 1, 1, "KEY   (from 'secretvault sync devices')")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		if err := cl.SyncRemove(ctx, c.vault, pos[0]); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, "Removed. That device keeps what it already has, and any key it opens the vault with:")
		fmt.Fprintln(c.stdout, "to cut it off for good, remove its keyslot and rotate ('secretvault unshare').")
		return nil

	case "off":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		return cl.SyncOff(ctx, c.vault)
	}
	fmt.Fprintf(c.stderr, "secretvault sync: unknown subcommand %q (setup, join, invite, status, now, devices, rm-device, off)\n", args[0])
	return errUsage
}

func (c *cli) printSyncStatus(sts []svrpc.SyncStatus) error {
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VAULT\tSERVER\tLAST SYNC\tSENT\tFETCHED\tSTATE")
	for _, st := range sts {
		last := "not yet"
		if !st.Last.IsZero() {
			last = st.Last.Local().Format(time.DateTime)
		}
		state := "ok"
		switch {
		case st.Error != "":
			state = st.Error
		case st.Last.IsZero():
			state = "starting"
		case st.Kept > 0:
			state = fmt.Sprintf("ok; refused %d keyslot removals that would have left no key", st.Kept)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n", st.Vault, st.URL, last, st.Pushed, st.Pulled+st.Removed, state)
	}
	return tw.Flush()
}
