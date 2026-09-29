package main

import (
	"errors"
	"fmt"

	"github.com/codemodify/secretvault/svage"
)

// age-plugin-secretvault: this program under the name age, rage, SOPS and
// friends look for when an identity reads AGE-PLUGIN-SECRETVAULT-1...
// (https://c2sp.org/age-plugin). They run it as
//
//	age-plugin-secretvault --age-plugin=identity-v1    to unwrap file keys
//	age-plugin-secretvault --age-plugin=recipient-v1   to wrap to an identity's public half
//
// and talk to it over stdin and stdout. The identity names a vault item
// ("VAULT/ITEM"); the plugin asks the daemon for it, unwraps the file key
// itself, and hands the file key back. It never prompts: the daemon asks
// the person, on the desktop or the terminal agent, as it does for any
// program, and an answer the person already gave for this terminal holds.

func (c *cli) cmdAgePlugin(args []string) error {
	fs := c.flags("age-plugin-secretvault")
	sm := fs.String("age-plugin", "", "the state machine age asks for: identity-v1 or recipient-v1")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *sm == "" || fs.NArg() > 0 {
		fmt.Fprintln(c.stderr, "age-plugin-secretvault is run by age, rage or SOPS for AGE-PLUGIN-SECRETVAULT-1... identities.")
		fmt.Fprintln(c.stderr, "Make one with 'secretvault age keygen --name ITEM', or print an item's with 'secretvault age identity ITEM'.")
		return errUsage
	}
	// No prompter: the plugin's stdin and stdout belong to age, and the
	// person is asked by the daemon.
	c.canAsk = false
	c.clientName = "age-plugin-secretvault"
	p := &svage.Plugin{
		Name: agePluginName,
		Identity: func(data []byte) (svage.Identity, error) {
			r, err := itemOfPluginIdentity(data)
			if err != nil {
				return nil, err
			}
			return &vaultIdentity{c: c, r: r}, nil
		},
		IdentityAsRecipient: func(data []byte) (svage.Recipient, error) {
			r, err := itemOfPluginIdentity(data)
			if err != nil {
				return nil, err
			}
			cl, err := c.daemon()
			if err != nil {
				return nil, err
			}
			ctx, cancel := c.ctx()
			defer cancel()
			rcpt, err := c.itemRecipient(ctx, cl, r)
			if err != nil {
				return nil, fmt.Errorf("sv://%s/%s: %s", r.vault, r.item, describe(err))
			}
			return svage.ParseRecipient(rcpt)
		},
	}
	if err := p.Serve(*sm, c.stdin, c.stdout); err != nil {
		return errors.New("age plugin protocol: " + err.Error())
	}
	return nil
}
