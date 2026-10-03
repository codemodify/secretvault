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
				return svops.SlotTypeName(s.Type)
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
		return m.paneColumn(svops.KeyslotsNote, p.stable,
			widgets.NewButton("Add a keyslot…", func() { m.addSlot(p) }),
			remove,
			widgets.NewButton("Change the passphrase…", func() { m.changePassphrase(p) }),
			widgets.NewButton("Give it a new key…", func() { m.rotateKey(p, nil, "") }))
	})
}

// addSlot adds a keyslot (the CLI's slot add): the kind at the head, and
// under it what that kind takes, and nothing else.
func (m *Manager) addSlot(p *vaultPage) {
	f := m.newForm(svops.AddSlotTitle(p.vault))
	kinds := make([]string, len(svops.SlotKinds))
	for i, k := range svops.SlotKinds {
		kinds[i] = k.Text
	}
	kind := widgets.NewRadioGroup(kinds, 0, nil)
	kind.SetAccessibleName("Opens with")
	f.row("Opens with", kind)
	label := f.text("Label", "", svops.SlotLabelPlaceholder)
	var newPass func() ([]byte, bool)
	var split, create *widgets.Checkbox
	var shares, threshold *widgets.NumberField
	var keyfile, recipient *pathField
	var uv *widgets.ComboBox
	parts := make([]*formPart, len(svops.SlotKinds))
	for i, k := range svops.SlotKinds {
		parts[i] = f.part(func() {
			switch k.Type {
			case svformat.SlotPassphrase:
				newPass = f.newPassphrase("Passphrase")
			case svformat.SlotRecovery:
				f.note(svops.RecoveryKeyIntro)
				split = f.check("Split it into shares, for several people to hold", false)
				shares = widgets.NewNumberField(2, 255, 3, 1, nil)
				shares.SetAccessibleName("Shares")
				threshold = widgets.NewNumberField(2, 255, 2, 1, nil)
				threshold.SetAccessibleName("Shares it takes")
				f.row("Shares", widgets.NewRow(shares, widgets.NewLabel("of which it takes"), threshold).WithGap(gap).WithAlign(layout.AlignCenter))
			case svformat.SlotKeyfile:
				f.note(svops.KeyfileIntro)
				keyfile = f.path("Keyfile", PickSave, "vault.key")
				create = f.check("Make a new keyfile there", false)
			case svformat.SlotRecipient:
				recipient = f.path("Their key", PickOpen, "")
				f.note("Their public key (a recipient): its text, a file that holds it, or an identity file. To choose from your contacts, use Sharing › Share with… instead.")
			case svformat.SlotFIDO2:
				f.note(svops.FIDO2SlotIntro)
				uv = f.choice(svops.FIDO2PINLabel, svops.FIDO2PINChoices, 0)
			}
		})
	}
	kind.OnChange = func(i int) {
		f.fail("") // what was wrong was with another kind
		f.showPart(parts, i)
		if f.accept != nil {
			f.accept.Text = svops.SlotAddAction(svops.SlotKinds[max(0, i)].Type)
			f.accept.Invalidate()
		}
	}
	f.showPart(parts, kind.Selected())
	f.show(svops.SlotAddAction(svops.SlotKinds[max(0, kind.Selected())].Type), func() {
		typ := svops.SlotKinds[max(0, kind.Selected())].Type
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
				f.fail("Give their public key, or the file that holds it.")
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
			m.say("%s", svops.SlotAdded(p.vault, info))
			m.refreshTab(p, tabKeyslots)
			if info.Type == svformat.SlotFIDO2 {
				m.showText("Security key added", fmt.Sprintf("%s now opens vault %s (%s). Try it: lock the vault, then Vault › Unlock with… › The security key plugged in.", info.Label, p.vault, info.Detail), "")
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
		m.say("That keyslot is emergency access: end it on the Sharing tab, under Emergency access, with Revoke….")
		m.selectTab(p.tabbedPage, tabSharing)
		return
	}
	m.confirm(svops.RemoveSlotTitle, svops.RemoveSlotText(p.vault, s)+" (Give it a new key… on this tab; Sharing › Cut off… does both.)",
		svops.RemoveSlotAction, func() {
			m.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.RemoveSlot(ctx, p.vault, s.ID)
			}, func(err error) {
				if err != nil {
					m.fail(err)
					return
				}
				m.say("%s", svops.SlotRemoved(p.vault, s))
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
		f := m.newForm(svops.ChangePassphraseTitle(p.vault))
		f.intro(svops.ChangePassphraseIntro)
		newPass := f.newPassphrase("New passphrase")
		f.show(svops.ChangePassphraseAction, func() {
			pass, ok := newPass()
			if !ok {
				return
			}
			f.call(func(ctx context.Context, c *secretvault.Client) error {
				_, err := c.Passwd(ctx, p.vault, pass)
				return err
			}, func() {
				m.say("%s", svops.PassphraseChanged(p.vault))
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
		f := m.newForm(svops.RotateTitle(p.vault, len(drop) > 0))
		intro := svops.RotateIntro(len(drop))
		if why != "" {
			intro = why + "\n\n" + intro
		}
		f.intro(intro)
		newPass := f.newPassphrase("Passphrase")
		recovery := f.check(svops.RotateRecoveryCheck, false)
		f.show(svops.RotateAction(len(drop) > 0), func() {
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
				m.say("%s", svops.RotateStatus(p.vault))
				m.refreshTab(p, tabKeyslots)
				m.refreshTab(p, tabSharing)
				m.showDone("The vault has a new key", svops.RotateDone(p.vault, res, len(drop)), svops.RotateDetails(res))
				if res.RecoveryKey != "" {
					m.showRecoveryKey(p.vault, []byte(res.RecoveryKey))
				}
			}, pass)
		})
	})
}
