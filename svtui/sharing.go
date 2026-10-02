package svtui

import (
	"context"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// shareWith is 'secretvault share RECIPIENT|FILE': a person's (or a
// device's, or a server's) identity gets a keyslot.
func (u *UI) shareWith(vault string, then func()) {
	f := u.newForm("Share "+vault, "Give a person's identity a keyslot: their recipient (svr1…), or a file holding it, or their identity file. They open the vault with their identity; Cut off undoes it.")
	who := f.path("Recipient or file", "", "svr1… or a path")
	label := f.text("Label", "", "a name for the person or device")
	f.show("Share", func() string {
		arg := trimmed(who)
		if arg == "" {
			return "Give a recipient, or a file."
		}
		r, err := svops.RecipientArg(expandHome(arg))
		if err != nil {
			return err.Error()
		}
		p := svrpc.SlotAddParams{Vault: vault, Type: svformat.SlotRecipient, Label: trimmed(label), Secret: []byte(r)}
		var info svrpc.SlotInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			info, err = c.AddSlot(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Shared: keyslot %s opens %s with that identity; Cut off undoes it", info.ID, vault)
			if then != nil {
				then()
			}
		})
		return ""
	})
}
