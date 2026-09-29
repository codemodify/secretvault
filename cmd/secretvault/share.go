package main

import (
	"fmt"

	"github.com/codemodify/secretvault/svformat"
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
	r, err := recipientArg(pos[0])
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
	p, err := c.newPassphrase(*newPassFile)
	if err != nil {
		return err
	}
	defer clear(p)
	params := svrpc.RotateParams{Vault: c.vault, Passphrase: p, Recovery: *recovery}
	if drop != nil {
		params.Drop = drop(pos)
	}
	res, err := cl.Rotate(ctx, params)
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
	if res.RecoveryKey != "" {
		c.printRecoveryKey(res.RecoveryKey)
	}
	return nil
}
