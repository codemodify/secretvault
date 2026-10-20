package svtui

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svqr"
	"github.com/codemodify/secretvault/svrpc"
)

// The sharing panel (E): the people the vault is shared with ('secretvault
// share', 'unshare'), the emergency access it gives ('emergency grant',
// 'ls', 'deny', 'revoke'), and the emergency access this device holds to
// others' vaults ('emergency accept', 'request', 'open').

func (u *UI) showSharing() {
	if !u.needVault() {
		return
	}
	vault := u.vault
	p := u.newPanel("Sharing and emergency access · "+vault, "WHO", "WHAT", "STATE", "")
	p.vault = vault
	p.reload = func() {
		var slots []svrpc.SlotInfo
		var list svrpc.EmergencyList
		var listErr error
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if slots, err = c.Slots(ctx, vault); err != nil {
				return err
			}
			list, listErr = c.EmergencyList(ctx, vault)
			return nil
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			p.setHead(svops.SharingAbout + "\n" + svops.EmergencyAbout)
			p.heading("Shared with")
			shared := 0
			for _, s := range slots {
				if s.Type != svformat.SlotRecipient {
					continue
				}
				shared++
				label := s.Label
				if label == "" {
					label = "(no label)"
				}
				p.row(s, label, "keyslot "+s.ID, s.Created.Local().Format("2006-01-02"), s.Recipient[:min(24, len(s.Recipient))]+"…")
			}
			if shared == 0 {
				p.none("Nobody (s shares).")
			}
			p.heading("Emergency access given")
			if listErr != nil {
				p.setHead("[red]" + tview.Escape(u.describe(listErr)) + "[-]")
			} else if len(list.Given) == 0 {
				p.none("Nobody (g grants it).")
			}
			for _, g := range list.Given {
				state := svops.GrantState(g)
				if g.State == svrpc.GrantRequested || g.State == svrpc.GrantReleased {
					state = tagged("[red]" + tview.Escape(state) + "[-]")
				}
				p.row(g, svops.TrusteeName(g), "waits "+svops.WaitText(g.Wait), state, strings.Join(g.Problems, "; "))
			}
			p.heading("Emergency access held")
			if listErr == nil && len(list.Held) == 0 {
				p.none("None (a accepts an invite).")
			}
			for _, a := range list.Held {
				state := accessState(a)
				if a.Error != "" {
					state = a.Error
				}
				p.row(a, a.Name, a.Owner+" at "+a.URL, state)
			}
			p.done()
		})
	}
	p.act('s', "Share with…", func() { u.shareWith(vault, p.refresh) })
	p.rowAct('c', "Cut off… (gives the vault a new key)", is[svrpc.SlotInfo], func(ref any) {
		s := ref.(svrpc.SlotInfo)
		u.rotateKey(vault, []string{s.ID}, p.refresh)
	})
	p.act('g', "Grant emergency access…", func() { u.grantEmergency(vault, p.refresh) })
	p.rowAct('d', "Deny the request…", func(ref any) bool {
		g, ok := ref.(svrpc.EmergencyGrant)
		return ok && g.State == svrpc.GrantRequested
	}, func(ref any) {
		g := ref.(svrpc.EmergencyGrant)
		deny := svops.DenyEmergencyPlain(svops.TrusteeName(g), vault)
		u.confirm(deny.Title, deny.Summary, deny.Action, func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				_, err := c.EmergencyDeny(ctx, vault, g.ID)
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Denied: %s gets nothing from that request", svops.TrusteeName(g))
				p.refresh()
				u.noteEmergency()
			})
		})
	})
	p.rowAct('v', "Revoke it…", is[svrpc.EmergencyGrant], func(ref any) { u.revokeEmergency(vault, ref.(svrpc.EmergencyGrant), p.refresh) })
	p.act('a', "Accept an invite…", func() { u.acceptEmergency(p.refresh) })
	p.rowAct('r', "Ask for it…", func(ref any) bool {
		a, ok := ref.(svrpc.EmergencyAccess)
		return ok && a.State != svrpc.GrantReleased
	}, func(ref any) { u.requestEmergency(ref.(svrpc.EmergencyAccess).Name, p.refresh) })
	p.rowAct('o', "Open the vault…", func(ref any) bool {
		a, ok := ref.(svrpc.EmergencyAccess)
		return ok && a.Vault == ""
	}, func(ref any) { u.openEmergency(ref.(svrpc.EmergencyAccess).Name, p.refresh) })
	p.show()
}

// accessState says where access held stands, in the TUI's words.
func accessState(a svrpc.EmergencyAccess) string {
	switch a.State {
	case svrpc.GrantAccepted:
		if a.Denied != nil {
			return "last request denied " + svops.When(a.Denied) + "; you may ask again (r)"
		}
		return "accepted; r asks for it"
	case svrpc.GrantRequested:
		return "requested; yours " + svops.When(a.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		if a.Vault != "" {
			return "opened, as vault " + a.Vault
		}
		return "released: o opens it"
	}
	return a.State
}

// grantEmergency is 'secretvault emergency grant CONTACT|RECIPIENT'.
func (u *UI) grantEmergency(vault string, then func()) {
	f := u.newForm("Grant emergency access to "+vault, svops.EmergencyGrantLead+" Name a contact who has a secretvault key, or paste their "+svops.RecipientMeans+".")
	who := f.text("Who", "", "a contact's name, address or fingerprint, or their recipient")
	wait := f.text("Wait", "7d", "how long you have to deny it: 48h, 7d, 2w (an hour to a year)")
	fp := f.text("Which key", "", "only if the contact has several: its fingerprint")
	name := f.text("Name they see", "", "what the invite calls the vault (default: its name)")
	f.show("Give access", func() string {
		if trimmed(who) == "" {
			return "Name the contact, or paste their public key."
		}
		d, err := svops.ParseWait(trimmed(wait))
		if err != nil {
			return err.Error()
		}
		params := svrpc.EmergencyGrantParams{Vault: vault, Contact: trimmed(who), Fingerprint: trimmed(fp), Wait: int64(d / time.Second), Name: trimmed(name)}
		var res svrpc.EmergencyGrantResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.EmergencyGrant(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			g := res.Grant
			if then != nil {
				then()
			}
			lines := []onceLine{
				{text: svops.EmergencyGrantedText(svops.TrusteeName(g), g.Vault, g.Wait)},
			}
			if res.Warning != "" {
				lines = append(lines, onceLine{text: "Warning: " + res.Warning})
			}
			lines = append(lines,
				onceLine{},
				onceLine{text: "Send them this invite. " + svops.InviteHoldsNoSecret},
				onceLine{secret: []byte(res.Invite)},
				onceLine{},
				onceLine{text: "They accept it in Sharing › Accept an invite (or 'secretvault emergency accept'). You are told when they ask; deny or revoke it here."},
				onceLine{text: "Or they scan it:"},
			)
			code, err := svqr.Encode([]byte(res.Invite), svqr.M)
			if err != nil {
				code = nil
			}
			u.showOnce("Emergency access granted", lines, code)
		})
		return ""
	})
}

// revokeEmergency is 'secretvault emergency revoke GRANT [--rotate]'.
func (u *UI) revokeEmergency(vault string, g svrpc.EmergencyGrant, then func()) {
	intro := svops.RevokeEmergencyText(svops.TrusteeName(g), vault)
	if g.Released != nil {
		intro += " " + svops.KeptACopyText(svops.When(g.Released))
	}
	f := u.newForm("Revoke emergency access", intro)
	rotate := f.check("Give the vault a new key too", g.Released != nil)
	f.show("Revoke access", func() string {
		alsoRotate := rotate.IsChecked()
		var res svrpc.EmergencyGrant
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.EmergencyRevoke(ctx, vault, g.ID)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			msg := svops.RevokedText(svops.TrusteeName(res), res.Vault)
			for _, p := range res.Problems {
				msg += " Note: " + p
			}
			if then != nil {
				then()
			}
			u.noteEmergency()
			switch {
			case alsoRotate:
				u.say("%s", msg)
				u.rotateKey(vault, nil, then)
			case res.Released != nil:
				u.showText("Revoked", tview.Escape(msg+"\n\n"+svops.KeptACopyText(svops.When(res.Released))+" (Ways to unlock, r)"))
			default:
				u.say("%s", msg)
			}
		})
		return ""
	})
}

// acceptEmergency is 'secretvault emergency accept INVITE --identity FILE'.
func (u *UI) acceptEmergency(then func()) {
	f := u.newForm("Accept an emergency access invite", svops.AcceptEmergencyLead+" It is used once here, and not kept: keep the file, to open the vault later.")
	invite := f.text("Invite", "", "secretvault-emergency:…")
	identity := f.path("Identity file", "", "")
	as := f.text("Name it here", "", "default: the name in the invite")
	label := f.text("This device's name", "", "its name to the owner (default: the host name)")
	f.show("Accept the invite", func() string {
		inv, idPath := trimmed(invite), filePath(identity)
		if inv == "" || idPath == "" {
			return "Paste the invite, and give the identity file."
		}
		k, err := svops.KeyFromFile("identity", idPath)
		if err != nil {
			return err.Error()
		}
		params := svrpc.EmergencyAcceptParams{Invite: inv, Identity: k.Secret, Name: trimmed(as), Label: trimmed(label)}
		var a svrpc.EmergencyAccess
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(params.Identity)
			a, err = c.EmergencyAccept(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Accepted, as %s. When you need the vault, ask for it (r): its owner is told, and unless they deny it within %s, it is yours", a.Name, svops.WaitText(a.Wait))
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// requestEmergency is 'secretvault emergency request NAME'.
func (u *UI) requestEmergency(name string, then func()) {
	u.confirm("Ask for "+name+"?", "Ask for emergency access to "+name+"? Its owner is told at once, and the wait starts: unless they deny it, the vault is yours when it ends.", "Ask for access", func() {
		var a svrpc.EmergencyAccess
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			a, err = c.EmergencyRequest(ctx, name)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if a.State == svrpc.GrantReleased {
				u.say("It is yours already: o opens it")
			} else {
				u.say("Asked. Its owner is told; unless they deny it, it is yours on %s", svops.When(a.ReleasesAt))
			}
			if then != nil {
				then()
			}
		})
	})
}

// openEmergency is 'secretvault emergency open NAME --identity FILE'.
func (u *UI) openEmergency(name string, then func()) {
	f := u.newForm("Open "+name, "After the wait, the vault is fetched and opened with your identity file, read-only: it follows its owner's copy.")
	identity := f.path("Identity file", "", "")
	dir := f.path("Folder", "", "empty: secretvault's own")
	f.show("Open the vault", func() string {
		idPath := filePath(identity)
		if idPath == "" {
			return "Give the identity file."
		}
		k, err := svops.KeyFromFile("identity", idPath)
		if err != nil {
			return err.Error()
		}
		params := svrpc.EmergencyOpenParams{Name: name, Identity: k.Secret}
		if d := filePath(dir); d != "" {
			if params.Path, err = filepath.Abs(d); err != nil {
				clear(params.Identity)
				return err.Error()
			}
		}
		var v svrpc.VaultInfo
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			defer clear(params.Identity)
			v, err = c.EmergencyOpen(ctx, params)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Opened vault %s, read-only; once it locks, Unlock with › An identity file opens it again", v.Name)
			if then != nil {
				then()
			}
			u.reloadVaults()
		})
		return ""
	})
}

// shareWith is 'secretvault share RECIPIENT|FILE': a person's (or a
// device's, or a server's) identity gets a keyslot.
func (u *UI) shareWith(vault string, then func()) {
	f := u.newForm("Share vault "+vault, svops.ShareLead+" Paste their "+svops.RecipientMeans+", or give the file that holds it (an identity file works too: only its public half is used).")
	who := f.path("Their public key", "", "their recipient, or a file holding it")
	label := f.text("Name", "", "who or what it is: Bob, Bob's laptop")
	f.show("Share the vault", func() string {
		arg := trimmed(who)
		if arg == "" {
			return "Paste their public key, or give the file that holds it."
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
			u.say("%s", svops.SharedText(vault, info.Label))
			if then != nil {
				then()
			}
		})
		return ""
	})
}
