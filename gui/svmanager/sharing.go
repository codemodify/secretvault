package svmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Sharing a vault: the people and devices it is shared with (their
// identities' keyslots), sharing it with one more, cutting one off (which
// rotates the key), and emergency access, given to a person who can open
// the vault after a wait unless it is denied; and on the other side,
// accepting such access, asking for it, and opening the vault after the
// wait.

func (m *Manager) fillSharing(p *vaultPage, pn *pane) {
	var slots []svrpc.SlotInfo
	var list svrpc.EmergencyList
	var emErr error
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		if slots, err = c.Slots(ctx, p.vault); err != nil {
			return err
		}
		list, emErr = c.EmergencyList(ctx, p.vault)
		if errors.Is(emErr, svrpc.ErrCanceled) {
			return emErr
		}
		return nil
	}, func() widget.Component {
		p.shared = p.shared[:0]
		for _, s := range slots {
			if s.Type == svformat.SlotRecipient {
				p.shared = append(p.shared, s)
			}
		}
		p.emergency = list
		return m.drawSharing(p, pn, emErr)
	})
}

func (m *Manager) drawSharing(p *vaultPage, pn *pane, emErr error) widget.Component {
	col := widgets.NewColumn().WithGap(gap).WithPad(gap)
	shared := p.shared
	col.Add(m.paragraph("A person or device given a keyslot opens the vault with their own identity. Cutting one off " +
		"removes their keyslot and rotates the key, so the key they already opened stops opening what is written afterwards."))
	p.shtable = table("Shared with", []widgets.TableColumn{
		{Title: "Keyslot", Width: 110}, {Title: "Label"}, {Title: "Recipient"}, {Title: "Since", Width: 130},
	}, len(shared), func(r, c int) string {
		s := shared[r]
		switch c {
		case 0:
			return s.ID
		case 1:
			return s.Label
		case 2:
			return s.Recipient[:min(40, len(s.Recipient))] + "…"
		}
		return s.Created.Local().Format("2006-01-02 15:04")
	})
	pn.focus = p.shtable
	if len(shared) == 0 {
		col.Add(m.paragraph("It is shared with nobody."))
	} else {
		col.Add(widgets.NewHeightBox(min(40+28*float32(len(shared)), 180), p.shtable))
	}
	cut := widgets.NewButton("Cut off…", func() { m.unshare(p) })
	cut.SetEnabled(len(shared) > 0)
	col.Add(buttons(widgets.NewButton("Share with…", func() { m.share(p) }), cut))

	col.Add(section(m, "Emergency access"))
	col.Add(m.paragraph("A person you trust may ask for the vault, and has it after a wait, unless you deny it within the wait. " +
		"The vault must sync with a server, which keeps the wait."))
	if emErr != nil {
		col.Add(m.paragraph(m.describe(emErr)))
	}
	given := p.emergency.Given
	p.etable = table("Emergency access given", []widgets.TableColumn{
		{Title: "Grant", Width: 110}, {Title: "Trustee"}, {Title: "Wait", Width: 80}, {Title: "State"},
	}, len(given), func(r, c int) string {
		g := given[r]
		switch c {
		case 0:
			return g.ID[:min(12, len(g.ID))]
		case 1:
			return trusteeName(g)
		case 2:
			return svops.WaitText(g.Wait)
		}
		return grantState(g)
	})
	if len(given) > 0 {
		col.Add(widgets.NewHeightBox(min(40+28*float32(len(given)), 180), p.etable))
		for _, g := range given {
			for _, x := range g.Problems {
				l := toned(g.ID[:min(12, len(g.ID))]+": "+x, widgets.ToneWarning)
				l.Wrap = true
				col.Add(l)
			}
		}
	} else if emErr == nil {
		col.Add(m.paragraph("Nobody has emergency access to this vault."))
	}
	deny := widgets.NewButton("Deny…", func() { m.denyEmergency(p) })
	revoke := widgets.NewButton("Revoke…", func() { m.revokeEmergency(p) })
	deny.SetEnabled(len(given) > 0)
	revoke.SetEnabled(len(given) > 0)
	col.Add(buttons(widgets.NewButton("Grant…", func() { m.grantEmergency(p) }), deny, revoke))
	if held := p.emergency.Held; len(held) > 0 {
		col.Add(section(m, "Emergency access held here"))
		col.Add(m.heldTable(held))
		col.Add(m.paragraph("File › Emergency access asks for it, and opens a vault once it is yours."))
	}
	return scrolled(col)
}

// heldTable lists the emergency access this device holds.
func (m *Manager) heldTable(held []svrpc.EmergencyAccess) widget.Component {
	t := table("Emergency access held", []widgets.TableColumn{
		{Title: "Name", Width: 110}, {Title: "Owner's name", Width: 120}, {Title: "Server"}, {Title: "State"},
	}, len(held), func(r, c int) string {
		a := held[r]
		switch c {
		case 0:
			return a.Name
		case 1:
			return a.Owner
		case 2:
			return a.URL
		}
		if a.Error != "" {
			return a.Error
		}
		return accessState(a)
	})
	return widgets.NewHeightBox(min(40+28*float32(len(held)), 180), t)
}

func trusteeName(g svrpc.EmergencyGrant) string {
	if g.Trustee != "" {
		return g.Trustee
	}
	return "the trustee"
}

func when(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// grantState says where a grant given is, as the CLI's emergency ls does.
func grantState(g svrpc.EmergencyGrant) string {
	switch g.State {
	case svrpc.GrantInvited:
		return "not accepted yet"
	case svrpc.GrantAccepted:
		s := "accepted"
		if g.Device != "" {
			s += " on " + g.Device
		}
		if g.Denied != nil {
			s += "; last request denied " + when(g.Denied)
		}
		return s
	case svrpc.GrantRequested:
		return "REQUESTED " + when(g.Requested) + "; released " + when(g.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		return "RELEASED " + when(g.Released)
	}
	return "unknown to the server"
}

// accessState says where access held is, in this program's words.
func accessState(a svrpc.EmergencyAccess) string {
	switch a.State {
	case svrpc.GrantAccepted:
		if a.Denied != nil {
			return "last request denied " + when(a.Denied) + "; you may ask again"
		}
		return "accepted; ask for it when you need it"
	case svrpc.GrantRequested:
		return "requested; yours " + when(a.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		if a.Vault != "" {
			return "opened, as vault " + a.Vault
		}
		return "released: yours to open"
	}
	return a.State
}

// contactChoice is a choice of contact, or something typed or chosen
// instead: the first entry of the list.
type contactChoice struct {
	combo    *widgets.ComboBox
	contacts []svrpc.Contact
}

// withContacts lists the contacts, then calls then with them, or with none
// when they cannot be listed (a vault that holds none, say).
func (m *Manager) withContacts(then func([]svrpc.Contact)) {
	var list []svrpc.Contact
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		list, err = c.Contacts(ctx, "", "")
		return err
	}, func(err error) {
		if errors.Is(err, svrpc.ErrCanceled) {
			m.fail(err)
			return
		}
		then(list)
	})
}

// secretvaultKey is a contact's secretvault key (its recipient), if it has
// one.
func secretvaultKey(c svrpc.Contact) (svrpc.ContactKey, bool) {
	for _, k := range c.Keys {
		if k.Type == "secretvault" && k.State == "" {
			return k, true
		}
	}
	return svrpc.ContactKey{}, false
}

// share gives a person's or device's identity a keyslot (the CLI's
// share): one of the contacts' secretvault keys, a recipient, or an
// identity file.
func (m *Manager) share(p *vaultPage) {
	m.withContacts(func(all []svrpc.Contact) {
		var withKey []svrpc.Contact
		names := []string{"A recipient or identity file, below"}
		for _, c := range all {
			if _, ok := secretvaultKey(c); ok {
				withKey = append(withKey, c)
				names = append(names, c.Name+" (contact)")
			}
		}
		f := m.newForm("Share " + p.vault)
		who := f.choice("With", names, min(1, len(withKey)))
		rcpt := f.path("Recipient", PickOpen, "")
		f.note("Recipient: the text of one, a file holding one, or an identity file (its public half is used).")
		label := f.text("Label", "", "a name for the person or device")
		f.show("Share", func() {
			arg, name := rcpt.Path(), strings.TrimSpace(label.Text)
			if i := who.Selected - 1; i >= 0 && i < len(withKey) {
				k, _ := secretvaultKey(withKey[i])
				arg = string(k.Material)
				if name == "" {
					name = withKey[i].Name
				}
			}
			if arg == "" {
				f.fail("Choose a contact, or give a recipient.")
				return
			}
			var info svrpc.SlotInfo
			f.call(func(ctx context.Context, c *secretvault.Client) error {
				r, err := svops.RecipientArg(arg)
				if err != nil {
					return err
				}
				info, err = c.AddSlot(ctx, svrpc.SlotAddParams{Vault: p.vault, Type: svformat.SlotRecipient, Label: name, Secret: []byte(r)})
				return err
			}, func() {
				m.say("Shared: keyslot %s opens the vault with that identity.", info.ID)
				m.refreshTab(p, tabSharing)
				m.refreshTab(p, tabKeyslots)
			})
		})
	})
}

// unshare cuts off the person selected (the CLI's unshare): their keyslot
// goes, and the key is rotated without it.
func (m *Manager) unshare(p *vaultPage) {
	i := selected(p.shtable)
	if i < 0 || i >= len(p.shared) {
		m.say("Choose whom to cut off first.")
		return
	}
	s := p.shared[i]
	who := s.Label
	if who == "" {
		who = "keyslot " + s.ID
	}
	m.rotateKey(p, []string{s.ID}, fmt.Sprintf("%s stops opening vault %s: their keyslot goes, and the vault gets a new key, "+
		"so the key they may have kept does not open what is written from now on.", who, p.vault))
}

// grantEmergency lets a person ask for the vault, and have it after a wait
// unless it is denied (the CLI's emergency grant); the invite to send them
// is shown, to copy, or as a QR code.
func (m *Manager) grantEmergency(p *vaultPage) {
	m.withContacts(func(all []svrpc.Contact) {
		names := []string{"A recipient, below"}
		for _, c := range all {
			names = append(names, c.Name)
		}
		f := m.newForm("Emergency access to " + p.vault)
		who := f.choice("Trustee", names, min(1, len(all)))
		rcpt := f.text("Recipient", "", "a secretvault recipient, if not a contact")
		fp := f.text("Fingerprint", "", "which of the contact's secretvault keys, if they have several")
		wait := f.text("Wait", "7d", "like 48h, 7d or 2w (an hour to a year)")
		name := f.text("Its name to them", "", "default: "+p.vault)
		f.note("They may then ask for the vault. You are told when they do, and unless you deny it within the wait, they get it.")
		f.show("Grant", func() {
			contact := strings.TrimSpace(rcpt.Text)
			if i := who.Selected - 1; i >= 0 && i < len(all) {
				contact = all[i].ID
			}
			if contact == "" {
				f.fail("Choose a contact, or give a recipient.")
				return
			}
			d, err := svops.ParseWait(strings.TrimSpace(wait.Text))
			if err != nil {
				f.fail(sentence(err.Error()))
				return
			}
			params := svrpc.EmergencyGrantParams{Vault: p.vault, Contact: contact, Fingerprint: strings.TrimSpace(fp.Text),
				Wait: int64(d / time.Second), Name: strings.TrimSpace(name.Text)}
			var res svrpc.EmergencyGrantResult
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.EmergencyGrant(ctx, params)
				return err
			}, func() {
				g := res.Grant
				m.refreshTab(p, tabSharing)
				note := fmt.Sprintf("%s may now ask for vault %s. Unless you deny it within %s of their asking, they get it. "+
					"Send them this invite: it holds no secret, since accepting it takes their identity. "+
					"They accept it in File › Emergency access › Accept an invite…", trusteeName(g), g.Vault, svops.WaitText(g.Wait))
				if res.Warning != "" {
					note += "\n\nWarning: " + res.Warning
				}
				m.showSecrets("Emergency access invite", note, []secretShown{{label: "Invite", value: []byte(res.Invite)}}, true, "Done")
			})
		})
	})
}

// emergencyGrant is the grant selected, or nil.
func (p *vaultPage) emergencyGrant() *svrpc.EmergencyGrant {
	i := selected(p.etable)
	if i < 0 || i >= len(p.emergency.Given) {
		return nil
	}
	return &p.emergency.Given[i]
}

// denyEmergency refuses the request of the grant selected (the CLI's
// emergency deny).
func (m *Manager) denyEmergency(p *vaultPage) {
	g := p.emergencyGrant()
	if g == nil {
		m.say("Choose a grant first.")
		return
	}
	id, who := g.ID, trusteeName(*g)
	m.confirm("Deny the request?", fmt.Sprintf("Deny %s's request for vault %s?\n\nThey get nothing from it. They can ask again, which starts the wait over, and you are told again.", who, p.vault), "Deny", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.EmergencyDeny(ctx, p.vault, id)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Denied: %s gets nothing from that request.", who)
			m.refreshTab(p, tabSharing)
			m.loadEmergency()
		})
	})
}

// revokeEmergency ends the grant selected (the CLI's emergency revoke),
// and rotates the key if asked, which it should be once they were given
// it.
func (m *Manager) revokeEmergency(p *vaultPage) {
	g := p.emergencyGrant()
	if g == nil {
		m.say("Choose a grant first.")
		return
	}
	id, who := g.ID, trusteeName(*g)
	f := m.newForm("Revoke emergency access")
	f.note(fmt.Sprintf("%s's emergency access to vault %s goes, with its keyslot and the server's escrow.", who, p.vault))
	rotate := f.check("Rotate the key too, which cuts them off from all that is written afterwards", g.Released != nil)
	if g.Released != nil {
		f.warn("They were given the vault's key on " + when(g.Released) + ", and may have kept it: rotate the key.")
	}
	f.show("Revoke", func() {
		var out svrpc.EmergencyGrant
		again := rotate.Checked
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			out, err = c.EmergencyRevoke(ctx, p.vault, id)
			return err
		}, func() {
			msg := fmt.Sprintf("Revoked: %s's emergency access to vault %s is gone.", who, out.Vault)
			if len(out.Problems) > 0 {
				msg += " Note: " + strings.Join(out.Problems, "; ")
			}
			m.say("%s", msg)
			m.refreshTab(p, tabSharing)
			m.refreshTab(p, tabKeyslots)
			m.loadEmergency()
			if again {
				m.rotateKey(p, nil, msg)
			}
		})
	})
}

// acceptEmergency takes an emergency access invite, with the identity it
// names (the CLI's emergency accept).
func (m *Manager) acceptEmergency() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Accept emergency access")
	invite := f.text("Invite", "", "the invite its owner sent")
	identity := f.path("Identity file", PickOpen, "")
	as := f.text("Call it", "", "default: the invite's name")
	label := f.text("This device", "", "its name to the owner (default: the host name)")
	f.note("The identity file is the one the grant was made for; it is needed again to open the vault.")
	f.show("Accept", func() {
		inv, id := strings.TrimSpace(invite.Text), identity.Path()
		switch {
		case inv == "":
			f.fail("Paste the invite.")
			return
		case id == "":
			f.fail("Choose the identity file the grant was made for.")
			return
		}
		var a svrpc.EmergencyAccess
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			b, err := readFile(id)
			if err != nil {
				return err
			}
			defer clear(b)
			a, err = c.EmergencyAccept(ctx, svrpc.EmergencyAcceptParams{Invite: inv, Identity: b, Name: strings.TrimSpace(as.Text), Label: strings.TrimSpace(label.Text)})
			return err
		}, func() {
			m.showText("Emergency access accepted", fmt.Sprintf("Accepted, as %q. Should you need it, File › Emergency access › Ask for access…: its owner is told, "+
				"and unless they deny it within %s, File › Emergency access › Open the vault… opens it then.", a.Name, svops.WaitText(a.Wait)), "")
			m.loadEmergency()
		})
	})
}

// heldAccess lists the emergency access held here, then calls then; with
// none when they cannot be listed (then the name is typed, as the CLI
// takes it).
func (m *Manager) heldAccess(then func([]svrpc.EmergencyAccess)) {
	var l svrpc.EmergencyList
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		l, err = c.EmergencyList(ctx, "")
		return err
	}, func(err error) {
		if errors.Is(err, svrpc.ErrCanceled) {
			m.fail(err)
			return
		}
		then(l.Held)
	})
}

// requestEmergency asks for access held (the CLI's emergency request): the
// wait starts, and the owner is told.
func (m *Manager) requestEmergency() {
	m.chooseHeld("Ask for emergency access", "Ask", "Its owner is told at once; unless they deny it within the wait, it is yours then.", func(f *formDialog, name string) {
		var a svrpc.EmergencyAccess
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			a, err = c.EmergencyRequest(ctx, name)
			return err
		}, func() {
			if a.State == svrpc.GrantReleased {
				m.say("It is yours already: File › Emergency access › Open the vault…")
			} else {
				m.say("Asked. Its owner is told; unless they deny it, it is yours on %s.", when(a.ReleasesAt))
			}
			m.loadEmergency()
		})
	})
}

// openEmergency fetches and opens a vault whose emergency access was
// released (the CLI's emergency open), read-only.
func (m *Manager) openEmergency() {
	var identity, folder *pathField
	m.chooseHeld("Open a vault by emergency access", "Open", "Once the wait is over, the vault is fetched and opened here, read-only: it follows its owner's copy.", func(f *formDialog, name string) {
		id := identity.Path()
		if id == "" {
			f.fail("Choose the identity file the grant was made for.")
			return
		}
		dir := folder.Path()
		var v svrpc.VaultInfo
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			b, err := readFile(id)
			if err != nil {
				return err
			}
			defer clear(b)
			if dir, err = absPath(dir); err != nil {
				return err
			}
			v, err = c.EmergencyOpen(ctx, svrpc.EmergencyOpenParams{Name: name, Identity: b, Path: dir})
			return err
		}, func() {
			m.say("Opened vault %s in %s, read-only. Once it locks, Vault › Unlock with… › an identity file opens it again.", v.Name, v.Path)
			m.reloadVaults()
			m.showVault(v.Name, true)
			m.loadEmergency()
		})
	}, func(f *formDialog) {
		identity = f.path("Identity file", PickOpen, "")
		folder = f.path("Folder", PickFolder, "")
		f.note("Folder: leave it empty to keep the vault in secretvault's data folder.")
	})
}

// chooseHeld asks which emergency access held here an action is about:
// chosen from those held, or its name typed when they cannot be listed.
func (m *Manager) chooseHeld(title, action, note string, do func(f *formDialog, name string), more ...func(*formDialog)) {
	if m.gone {
		m.fail(errGone)
		return
	}
	m.heldAccess(func(held []svrpc.EmergencyAccess) {
		f := m.newForm(title)
		var which *widgets.ComboBox
		var typed *widgets.TextField
		if len(held) > 0 {
			names := make([]string, len(held))
			for i, a := range held {
				names[i] = a.Name + ": " + accessState(a)
			}
			which = f.choice("Access", names, 0)
		} else {
			typed = f.text("Name", "", "as accepted")
			f.note("No emergency access held here could be listed: type its name as it was accepted (File › Emergency access › Accept an invite…).")
		}
		for _, fn := range more {
			fn(f)
		}
		f.note(note)
		f.show(action, func() {
			name := ""
			if which != nil {
				name = held[max(0, which.Selected)].Name
			} else if name = strings.TrimSpace(typed.Text); name == "" {
				f.fail("Type the name it was accepted as.")
				return
			}
			do(f, name)
		})
	})
}

// loadEmergency asks the daemon which emergency requests are waiting, for
// the status bar.
func (m *Manager) loadEmergency() {
	var st svrpc.Status
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.Status(ctx)
		return err
	}, func(err error) {
		if err != nil {
			return
		}
		m.emergency = st.Emergency
		m.drawStatus()
	})
}

// emergencyLine is what the status bar says of an emergency request, in
// this program's words (the daemon's name the CLI's commands).
func (m *Manager) emergencyLine() string {
	for _, n := range m.emergency {
		who := n.Trustee
		if who == "" {
			who = "Your trustee"
		}
		switch {
		case n.Held && n.State == svrpc.GrantRequested:
			return "; emergency access to " + n.Vault + " is yours " + when(n.ReleasesAt) + " unless denied"
		case n.Held && n.State == svrpc.GrantReleased:
			return "; emergency access to " + n.Vault + " is yours: File › Emergency access › Open the vault…"
		case n.State == svrpc.GrantRequested:
			return "; " + who + " asked for emergency access to " + n.Vault + ": theirs " + when(n.ReleasesAt) + " unless you deny it (Vault › Sharing)"
		case n.State == svrpc.GrantReleased:
			return "; " + who + " was given vault " + n.Vault + " by emergency access: revoke and rotate if they were not meant to (Vault › Sharing)"
		}
	}
	return ""
}
