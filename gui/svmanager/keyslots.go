package svmanager

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Keyslots: the ways a vault opens (its passphrase, a recovery key or its
// shares, keyfiles, people's identities, security keys), adding and
// removing them, changing the passphrase, and rotating the vault's key.

func (m *Manager) fillSlots(p *vaultPage, pn *pane) {
	var slots []svrpc.SlotInfo
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		slots, err = c.Slots(ctx, p.vault)
		return err
	}, func() widget.Component {
		p.slots = slots
		p.stable = table("Keyslots", []widgets.TableColumn{
			{Title: "ID", Width: 110},
			{Title: "Type", Width: 90},
			{Title: "Label"},
			{Title: "Created", Width: 130},
			{Title: "Detail"},
		}, len(slots), func(r, c int) string {
			s := slots[r]
			switch c {
			case 0:
				return s.ID
			case 1:
				return s.Type
			case 2:
				return s.Label
			case 3:
				return s.Created.Local().Format("2006-01-02 15:04")
			}
			if s.Recipient != "" {
				return s.Recipient[:min(40, len(s.Recipient))] + "…"
			}
			return s.Detail
		})
		pn.focus = p.stable
		remove := widgets.NewButton("Remove…", func() { m.removeSlot(p) })
		remove.SetEnabled(len(slots) > 1)
		return m.paneColumn("Each keyslot opens the vault on its own. Removing one does not take away a key "+
			"already opened with it: rotating the key does that.", p.stable,
			widgets.NewButton("Add…", func() { m.addSlot(p) }),
			remove,
			widgets.NewButton("Change the passphrase…", func() { m.changePassphrase(p) }),
			widgets.NewButton("Rotate the key…", func() { m.rotateKey(p, nil, "") }))
	})
}

// slotKinds are the keyslots that can be added, as slot.add names them,
// and as people are offered them.
var slotKinds = []struct{ typ, text string }{
	{svformat.SlotPassphrase, "Another passphrase"},
	{svformat.SlotRecovery, "A recovery key, shown once (or as shares)"},
	{svformat.SlotKeyfile, "A keyfile"},
	{svformat.SlotRecipient, "A person's or device's identity (a recipient)"},
	{svformat.SlotFIDO2, "The security key plugged in"},
}

// addSlot adds a keyslot (the CLI's slot add): the kind at the head, and
// under it what that kind takes, and nothing else.
func (m *Manager) addSlot(p *vaultPage) {
	f := m.newForm("Add a keyslot to " + p.vault)
	kinds := make([]string, len(slotKinds))
	for i, k := range slotKinds {
		kinds[i] = k.text
	}
	kind := widgets.NewRadioGroup(kinds, 0, nil)
	kind.SetAccessibleName("Kind")
	f.row("Kind", kind)
	label := f.text("Label", "", "optional: whose, or what for")
	var newPass func() ([]byte, bool)
	var split, create *widgets.Checkbox
	var shares, threshold *widgets.NumberField
	var keyfile, recipient *pathField
	var uv *widgets.ComboBox
	parts := make([]*formPart, len(slotKinds))
	for i, k := range slotKinds {
		parts[i] = f.part(func() {
			switch k.typ {
			case svformat.SlotPassphrase:
				newPass = f.newPassphrase("Passphrase")
			case svformat.SlotRecovery:
				f.note("A recovery key opens the vault on its own, like the passphrase. It is shown once, and kept nowhere.")
				split = f.check("Split it into shares, for several people to hold", false)
				shares = widgets.NewNumberField(2, 255, 3, 1, nil)
				shares.SetAccessibleName("Shares")
				threshold = widgets.NewNumberField(2, 255, 2, 1, nil)
				threshold.SetAccessibleName("Shares it takes")
				f.row("Shares", widgets.NewRow(shares, widgets.NewLabel("of which it takes"), threshold).WithGap(gap).WithAlign(layout.AlignCenter))
			case svformat.SlotKeyfile:
				keyfile = f.path("Keyfile", PickSave, "vault.key")
				create = f.check("Make a new keyfile there (64 random bytes, only yours to read)", false)
			case svformat.SlotRecipient:
				recipient = f.path("Recipient", PickOpen, "")
				f.note("The text of a recipient, a file holding one, or an identity file. Sharing › Share with… offers your contacts.")
			case svformat.SlotFIDO2:
				f.note("The security key plugged in is enrolled: it is asked for its PIN, if it has one, and to be touched.")
				uv = f.choice("Opening asks", []string{"for its PIN with every touch, if it has one", "for its PIN, always", "for a touch alone"}, 0)
			}
		})
	}
	kind.OnChange = func(i int) {
		f.fail("") // what was wrong was with another kind
		f.showPart(parts, i)
	}
	f.showPart(parts, kind.Selected())
	f.show("Add", func() {
		typ := slotKinds[max(0, kind.Selected())].typ
		params := svrpc.SlotAddParams{Vault: p.vault, Type: typ, Label: strings.TrimSpace(label.Text)}
		n, k := 0, 0
		var keyPath, rcpt string
		var makeKey bool
		switch typ {
		case svformat.SlotPassphrase:
			pass, ok := newPass()
			if !ok {
				return
			}
			params.Secret = pass
		case svformat.SlotRecovery:
			if split.Checked {
				n = int(shares.Value)
				var err error
				if k, err = svops.SplitThreshold(n, int(threshold.Value)); err != nil {
					f.fail(sentence(err.Error()))
					return
				}
				if params.Label == "" {
					params.Label = svops.SplitLabel(n, k)
				}
			}
		case svformat.SlotKeyfile:
			if keyPath = keyfile.Path(); keyPath == "" {
				f.fail("Choose the keyfile.")
				return
			}
			makeKey = create.Checked
		case svformat.SlotRecipient:
			if rcpt = recipient.Path(); rcpt == "" {
				f.fail("Give the recipient, or the file that holds it.")
				return
			}
		case svformat.SlotFIDO2:
			switch uv.Selected {
			case 1:
				yes := true
				params.UV = &yes
			case 2:
				no := false
				params.UV = &no
			}
		}
		var info svrpc.SlotInfo
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			defer func() { clear(params.Secret) }()
			switch typ {
			case svformat.SlotKeyfile:
				if makeKey {
					if err := svops.CreateKeyfile(keyPath); err != nil {
						return err
					}
				}
				b, err := os.ReadFile(keyPath)
				if err != nil {
					return err
				}
				params.Secret = b
			case svformat.SlotRecipient:
				r, err := svops.RecipientArg(rcpt)
				if err != nil {
					return err
				}
				params.Secret = []byte(r)
			}
			var err error
			info, err = c.AddSlot(ctx, params)
			return err
		}, func() {
			m.say("Added a %s keyslot, %s.", info.Type, info.ID)
			m.refreshTab(p, tabKeyslots)
			if info.Type == svformat.SlotFIDO2 {
				m.showText("Security key added", fmt.Sprintf("%s opens vault %s with: %s. Try it: lock the vault, then Vault › Unlock with… › the security key.", info.Label, p.vault, info.Detail), "")
			}
			if info.RecoveryKey != "" {
				m.showNewRecovery(p.vault, info.RecoveryKey, n, k)
			}
		}, params.Secret)
	})
}

// showNewRecovery shows a new recovery key once, or the shares it is
// split into (svops.SplitRecoveryKey), in which case the whole key is
// never shown.
func (m *Manager) showNewRecovery(vault, text string, n, k int) {
	if n == 0 {
		m.showRecoveryKey(vault, []byte(text))
		return
	}
	shares, err := svops.SplitRecoveryKey(text, n, k)
	if err != nil {
		m.fail(err)
		return
	}
	list := make([]secretShown, len(shares))
	for i, s := range shares {
		list[i] = secretShown{label: fmt.Sprintf("Share %d of %d", i+1, n), value: []byte(s)}
	}
	m.showSecrets("Recovery shares for "+vault,
		fmt.Sprintf("The recovery key, as %d shares: any %d of them open vault %s, fewer reveal nothing. "+
			"Give each to a different person or place. They are shown only now; to open the vault with them, "+
			"Vault › Unlock with… › recovery shares.", n, k, vault), list, false, "I have handed them out")
}

// removeSlot removes the keyslot selected, after asking.
func (m *Manager) removeSlot(p *vaultPage) {
	i := selected(p.stable)
	if i < 0 || i >= len(p.slots) {
		return
	}
	s := p.slots[i]
	if s.Type == svformat.SlotEmergency {
		// Removing it would end the grant only half: the server would
		// still hold it. Revoking ends it whole.
		m.say("Keyslot %s is emergency access: end it with Sharing › Emergency access › Revoke…", s.ID)
		m.selectTab(p.tabbedPage, tabSharing)
		return
	}
	what := s.Type
	if s.Label != "" {
		what += " (" + s.Label + ")"
	}
	m.confirm("Remove the keyslot?", fmt.Sprintf("Remove keyslot %s, %s, from vault %s?\n\nIt stops opening the vault. "+
		"Whoever opened the vault with it may still hold its key: to cut them off, rotate the key, or use Sharing › Cut off.", s.ID, what, p.vault),
		"Remove", func() {
			m.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.RemoveSlot(ctx, p.vault, s.ID)
			}, func(err error) {
				if err != nil {
					m.fail(err)
					return
				}
				m.say("Removed keyslot %s.", s.ID)
				m.refreshTab(p, tabKeyslots)
			})
		})
}

// proveThen has the daemon know the person is there (it asks for the
// vault's passphrase, or its security key) before then asks for anything
// new, as the CLI's passwd and rotate do.
func (m *Manager) proveThen(vault string, then func()) {
	m.call(func(ctx context.Context, c *secretvault.Client) error {
		_, err := c.Unlock(ctx, vault, nil)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		then()
	})
}

// changePassphrase replaces the passphrase that opens the vault (the
// CLI's passwd).
func (m *Manager) changePassphrase(p *vaultPage) {
	m.proveThen(p.vault, func() {
		f := m.newForm("Change the passphrase of " + p.vault)
		f.note("The passphrase keyslot used to unlock is replaced; other keyslots are left as they are.")
		newPass := f.newPassphrase("New passphrase")
		f.show("Change", func() {
			pass, ok := newPass()
			if !ok {
				return
			}
			var info svrpc.SlotInfo
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				info, err = c.Passwd(ctx, p.vault, pass)
				return err
			}, func() {
				m.say("Changed the passphrase (keyslot %s).", info.ID)
				m.refreshTab(p, tabKeyslots)
			}, pass)
		})
	})
}

// rotateKey rotates the vault's key, dropping the recipient keyslots in
// drop (the CLI's vault rotate, and unshare): the new key opens with a
// passphrase (the current one, or a new one), every other recipient
// keyslot, and a new recovery key if asked for. why heads the dialog.
func (m *Manager) rotateKey(p *vaultPage, drop []string, why string) {
	m.proveThen(p.vault, func() {
		title := "Rotate the key of " + p.vault
		if len(drop) > 0 {
			title = "Cut off, and rotate the key of " + p.vault
		}
		f := m.newForm(title)
		if why != "" {
			f.note(why)
		}
		f.note("A new key is made and every item sealed under it. Keyfiles and security keys do not carry over: " +
			"add them again afterwards. The passphrase may be the one it has now.")
		newPass := f.newPassphrase("Passphrase")
		recovery := f.check("Make a new recovery key (the old one stops working)", false)
		f.show("Rotate", func() {
			pass, ok := newPass()
			if !ok {
				return
			}
			params := svrpc.RotateParams{Vault: p.vault, Passphrase: pass, Recovery: recovery.Checked, Drop: drop}
			var res svrpc.RotateResult
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.Rotate(ctx, params)
				return err
			}, func() {
				m.say("The key of %s was rotated (epoch %d).", p.vault, res.Epoch)
				m.refreshTab(p, tabKeyslots)
				m.refreshTab(p, tabSharing)
				m.showText("The key was rotated", fmt.Sprintf("Vault %s has a new key (epoch %d).", p.vault, res.Epoch), rotateReport(res))
				if res.RecoveryKey != "" {
					m.showRecoveryKey(p.vault, []byte(res.RecoveryKey))
				}
			}, pass)
		})
	})
}

// rotateReport says what opens a vault after its key was rotated.
func rotateReport(res svrpc.RotateResult) string {
	var b strings.Builder
	b.WriteString("It opens with:\n")
	for _, s := range res.Slots {
		label := s.Label
		if label == "" {
			label = s.Type
		}
		fmt.Fprintf(&b, "  %s  %s\n", s.ID, label)
	}
	if len(res.Dropped) > 0 {
		b.WriteString("\nNo longer opening it (add them again on the Keyslots tab, or grant emergency access again):\n")
		for _, s := range res.Dropped {
			fmt.Fprintf(&b, "  %s  %s (%s)\n", s.ID, s.Label, s.Type)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
