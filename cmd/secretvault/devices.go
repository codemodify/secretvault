package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/codemodify/secretvault/svrpc"
)

// The devices registered in a vault, whose keys sign what they write.
//
//	secretvault device [ls]                  list them, with their key IDs
//	secretvault device label [DEVICE] NAME   name a device (this one by default)
//	secretvault device rm DEVICE             mark a device removed
//	secretvault device vouch DEVICE          vouch for a device (--withdraw to stop)
//
// DEVICE is a key ID, or its first digits, as 'device ls' shows it.

func (c *cli) cmdDevice(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		args = append([]string{"ls"}, args...)
	}
	fs := c.flags("device " + args[0])
	var u unlockFlags
	u.register(fs)
	switch args[0] {
	case "ls", "list":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		devs, err := cl.Devices(ctx, c.vault)
		if err != nil {
			return err
		}
		if len(devs) == 0 {
			fmt.Fprintln(c.stdout, "No device is registered in this vault yet: each registers itself when it unlocks it.")
			return nil
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "KEY\tLABEL\tDEVICE\tREGISTERED\tSTANDING")
		for _, d := range devs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.Key, d.Label, d.Device[:8], d.Registered.Local().Format("2006-01-02 15:04"), standing(d))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout)
		fmt.Fprintln(c.stdout, "Anyone who can open the vault can register a device, under any label. Before")
		fmt.Fprintln(c.stdout, "vouching for one ('secretvault device vouch KEY'), check that its KEY is the one")
		fmt.Fprintln(c.stdout, "'secretvault device ls' shows as \"this device\" on that device.")
		return nil

	case "label":
		pos, err := parse(fs, args[1:], 1, 2, "[DEVICE] NAME   (this device when DEVICE is left out)")
		if err != nil {
			return err
		}
		device, label := "", pos[0]
		if len(pos) == 2 {
			device, label = pos[0], pos[1]
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		d, err := cl.LabelDevice(ctx, c.vault, device, label)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Device %s is now %q.\n", d.Key, d.Label)
		return nil

	case "rm", "remove":
		pos, err := parse(fs, args[1:], 1, 1, "DEVICE   (a key ID, or its first digits, from 'secretvault device ls')")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		d, err := cl.RemoveDevice(ctx, c.vault, pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Removed device %s %q. What it signed still verifies, and shows as a removed device's.\n", d.Key, d.Label)
		fmt.Fprintln(c.stdout, "It can still open the vault and write to it: to cut it off, rotate the key without")
		fmt.Fprintln(c.stdout, "it ('secretvault unshare' for a person's keyslot, else 'secretvault vault rotate').")
		return nil

	case "vouch":
		withdraw := fs.Bool("withdraw", false, "no longer vouch for it")
		pos, err := parse(fs, args[1:], 1, 1, "DEVICE [--withdraw]   (a key ID, or its first digits, from 'secretvault device ls')")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		d, err := cl.VouchDevice(ctx, c.vault, pos[0], *withdraw)
		if err != nil {
			return err
		}
		if *withdraw {
			fmt.Fprintf(c.stdout, "This device no longer vouches for %s %q.\n", d.Key, d.Label)
		} else {
			fmt.Fprintf(c.stdout, "This device vouches for %s %q, and for the devices it vouches for.\n", d.Key, d.Label)
		}
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault device: unknown subcommand %q (ls, label, rm, vouch)\n", args[0])
	return errUsage
}

// standing is how far a device is to be believed, as this device sees it.
func standing(d svrpc.Device) string {
	switch {
	case d.This && d.Removed:
		return "this device, removed"
	case d.This:
		return "this device"
	case d.Removed:
		return "removed"
	case d.Vouched:
		return "vouched for"
	}
	return "not vouched for"
}

// signatures shows or sets a vault's policy on signatures.
func (c *cli) signatures(args []string) error {
	fs := c.flags("vault signatures")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[required|optional]")
	if err != nil {
		return err
	}
	var require *bool
	if len(pos) == 1 {
		switch pos[0] {
		case "required", "require", "on":
			require = new(bool)
			*require = true
		case "optional", "off":
			require = new(bool)
		default:
			return fmt.Errorf("vault signatures: %q is neither required nor optional", pos[0])
		}
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	p, err := cl.Signatures(ctx, c.vault, require)
	if err != nil {
		return err
	}
	if p.Require {
		fmt.Fprintf(c.stdout, "Vault %q counts only revisions signed by a device registered in it; the rest show in\n", p.Vault)
		fmt.Fprintln(c.stdout, "'secretvault history' as ignored. Versions of secretvault that cannot sign cannot write to it.")
	} else {
		fmt.Fprintf(c.stdout, "Vault %q counts every revision, signed or not; 'secretvault history' shows who signed each.\n", p.Vault)
	}
	return nil
}
