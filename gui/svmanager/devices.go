package svmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The devices registered in a vault, whose keys sign the revisions they
// write: naming them, removing them, vouching for them, and whether the
// vault counts only signed revisions.

func (m *Manager) fillDevices(p *vaultPage, pn *pane) {
	var devs []svrpc.Device
	var policy svrpc.SignaturePolicy
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		if devs, err = c.Devices(ctx, p.vault); err != nil {
			return err
		}
		policy, err = c.Signatures(ctx, p.vault, nil)
		return err
	}, func() widget.Component {
		p.devices, p.policy = devs, policy
		p.dtable = table("Devices", []widgets.TableColumn{
			{Title: "Key", Width: 150},
			{Title: "Label"},
			{Title: "Device", Width: 80},
			{Title: "Registered", Width: 130},
			{Title: "Standing", Width: 130},
		}, len(devs), func(r, c int) string {
			d := devs[r]
			switch c {
			case 0:
				return d.Key
			case 1:
				return d.Label
			case 2:
				return d.Device[:min(8, len(d.Device))]
			case 3:
				return d.Registered.Local().Format("2006-01-02 15:04")
			}
			return svops.DeviceStanding(d)
		})
		pn.focus = p.dtable
		signed := widgets.NewCheckbox("Count only signed revisions", policy.Require, nil)
		signed.OnInput = func(on bool) { m.setSignatures(p, on, signed) }
		note := "Every device that opens the vault registers itself, under any label it likes. Before vouching for one, " +
			"check that its key is the one this tab shows as \"this device\" on that device."
		if len(devs) == 0 {
			note = "No device is registered in this vault yet: each registers itself when it unlocks it."
		}
		col := m.paneColumn(note, p.dtable,
			widgets.NewButton("Rename…", func() { m.labelDevice(p) }),
			widgets.NewButton("Vouch for it", func() { m.vouchDevice(p, false) }),
			widgets.NewButton("Withdraw", func() { m.vouchDevice(p, true) }),
			widgets.NewButton("Remove…", func() { m.removeDevice(p) }))
		col.Add(widgets.NewTip("Revisions not signed by a registered device are then ignored, and show so in the history. "+
			"Versions of secretvault that cannot sign cannot write to the vault.", signed))
		return col
	})
}

// device is the device selected, or an error saying none is.
func (p *vaultPage) device() (svrpc.Device, error) {
	i := selected(p.dtable)
	if i < 0 || i >= len(p.devices) {
		return svrpc.Device{}, errors.New("choose a device first")
	}
	return p.devices[i], nil
}

// labelDevice names the device selected (the CLI's device label).
func (m *Manager) labelDevice(p *vaultPage) {
	d, err := p.device()
	if err != nil {
		m.fail(err)
		return
	}
	widgets.PromptFor(m.root(), "Rename the device", "Label for "+d.Key+":", widgets.MessageBoxInput{
		Text: d.Label, Required: true, AcceptLabel: "Rename",
		ValidateAsync: func(label string, done func(error)) {
			label = strings.TrimSpace(label)
			var out svrpc.Device
			m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				out, err = c.LabelDevice(ctx, p.vault, d.Key, label)
				return err
			}, func(err error) {
				if err != nil {
					done(errors.New(m.describe(err)))
					return
				}
				done(nil)
				m.say("Device %s is now %q.", out.Key, out.Label)
				m.refreshTab(p, tabDevices)
			})
		},
	}, nil)
}

// vouchDevice vouches for the device selected, or withdraws (the CLI's
// device vouch).
func (m *Manager) vouchDevice(p *vaultPage, withdraw bool) {
	d, err := p.device()
	if err != nil {
		m.fail(err)
		return
	}
	do := func() {
		var out svrpc.Device
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			out, err = c.VouchDevice(ctx, p.vault, d.Key, withdraw)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			if withdraw {
				m.say("This device no longer vouches for %s %q.", out.Key, out.Label)
			} else {
				m.say("This device vouches for %s %q, and for the devices it vouches for.", out.Key, out.Label)
			}
			m.refreshTab(p, tabDevices)
		})
	}
	if withdraw {
		do()
		return
	}
	m.confirm("Vouch for "+d.Label+"?", fmt.Sprintf("Vouch for device %q, key\n\n%s\n\nCheck first that this is the key that device's Devices tab shows "+
		"as \"this device\": anyone who can open the vault can register a device under any label.", d.Label, d.Key), "Vouch", do)
}

// removeDevice marks the device selected removed (the CLI's device rm).
func (m *Manager) removeDevice(p *vaultPage) {
	d, err := p.device()
	if err != nil {
		m.fail(err)
		return
	}
	m.confirm("Remove the device?", fmt.Sprintf("Remove device %s %q?\n\nWhat it signed still verifies, and shows as a removed device's. "+
		"It can still open the vault and write to it: to cut it off, rotate the key without it (Sharing › Cut off for a person's keyslot, "+
		"else Keyslots › Rotate the key).", d.Key, d.Label), "Remove", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.RemoveDevice(ctx, p.vault, d.Key)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Removed device %s.", d.Key)
			m.refreshTab(p, tabDevices)
		})
	})
}

// setSignatures sets the vault's policy on signatures (the CLI's vault
// signatures).
func (m *Manager) setSignatures(p *vaultPage, require bool, box *widgets.Checkbox) {
	var out svrpc.SignaturePolicy
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		out, err = c.Signatures(ctx, p.vault, &require)
		return err
	}, func(err error) {
		if err != nil {
			box.Checked = !require
			box.Invalidate()
			m.fail(err)
			return
		}
		if out.Require {
			m.say("Vault %s counts only revisions signed by a device registered in it.", out.Vault)
		} else {
			m.say("Vault %s counts every revision, signed or not.", out.Vault)
		}
		m.refreshTab(p, tabDevices)
	})
}
