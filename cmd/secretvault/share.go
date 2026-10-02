package main

import (
	"context"
	"fmt"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Sharing a vault with people, and cutting them off.
//
//	secretvault share RECIPIENT|FILE [--label NAME]   give a person's identity a keyslot
//	secretvault unshare SLOT-ID                       remove it, and rotate the key
//	secretvault vault rotate [--new-recovery]         rotate the key, keeping everyone
//
// Unsharing rotates the vault key: removing the keyslot alone would leave
// the person able to use the key they already opened.

func (c *cli) cmdShare(args []string) error {
	fs := c.flags("share")
	label := fs.String("label", "", "a name for the person or device")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "RECIPIENT|FILE [--label NAME]")
	if err != nil {
		return err
	}
	r, err := svops.RecipientArg(pos[0])
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.AddSlot(ctx, svrpc.SlotAddParams{Vault: c.vault, Type: svformat.SlotRecipient, Label: *label, Secret: []byte(r)})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Shared: keyslot %s opens the vault with that identity. Undo with 'secretvault unshare %s'.\n", info.ID, info.ID)
	return nil
}

func (c *cli) cmdUnshare(args []string) error {
	return c.rotate(args, func(pos []string) []string { return pos })
}

// rotate rotates the vault key; drop picks, from the arguments, the
// recipient slots to cut off.
func (c *cli) rotate(args []string, drop func([]string) []string) error {
	fs := c.flags("vault rotate")
	recovery := fs.Bool("new-recovery", false, "also make a new recovery key (the old one stops working)")
	newPassFile := fs.String("new-passphrase-file", "", "the passphrase for the new key, from `FILE` (default: asked; may be the same as now)")
	var u unlockFlags
	u.register(fs)
	usage := "[--new-recovery]"
	min, maxArgs := 0, 0
	if drop != nil {
		usage, min, maxArgs = "SLOT-ID... [--new-recovery]", 1, -1
	}
	pos, err := parse(fs, args, min, maxArgs, usage)
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if !u.given() {
		if _, err := cl.Unlock(ctx, c.vault, nil); err != nil {
			return err
		}
	}
	var dropped []string
	if drop != nil {
		dropped = drop(pos)
	}
	return c.rotateWith(ctx, cl, *newPassFile, *recovery, dropped)
}

// rotateWith rotates the vault key through a connection that may use the
// vault, asking for the new key's passphrase, and says what opens it now.
func (c *cli) rotateWith(ctx context.Context, cl *secretvault.Client, newPassFile string, recovery bool, drop []string) error {
	p, err := c.newPassphrase(newPassFile)
	if err != nil {
		return err
	}
	defer clear(p)
	res, err := cl.Rotate(ctx, svrpc.RotateParams{Vault: c.vault, Passphrase: p, Recovery: recovery, Drop: drop})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "The vault key was rotated (epoch %d). It opens with:\n", res.Epoch)
	for _, s := range res.Slots {
		label := s.Label
		if label == "" {
			label = s.Type
		}
		fmt.Fprintf(c.stdout, "  %s  %s\n", s.ID, label)
	}
	if len(res.Dropped) > 0 {
		fmt.Fprintln(c.stdout, "No longer opening it (add them again with 'secretvault slot add', or 'secretvault emergency grant'):")
		for _, s := range res.Dropped {
			fmt.Fprintf(c.stdout, "  %s  %s (%s)\n", s.ID, s.Label, s.Type)
		}
	}
	if res.RecoveryKey != "" {
		c.printRecoveryKey(res.RecoveryKey)
	}
	return nil
}
