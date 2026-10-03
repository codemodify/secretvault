package svmanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Keys: your own OpenPGP keys, S/MIME keys and age identities, which are
// kept in the vault shown (the daemon signs and decrypts with them, so
// the secret key never comes here unless it is exported); identity files,
// which open keyslots and emergency access; and the security keys plugged
// in.

// The keys page's tabs.
const (
	tabPGP = iota
	tabSMIME
	tabAge
	tabIdentities
	tabSecurityKeys
)

// keysPage is the keys page's state.
type keysPage struct {
	*tabbedPage
	pgp     []svrpc.Entry
	ptable  *widgets.TableView
	smime   []svrpc.SMIMEKey
	age     []svrpc.Entry
	atable  *widgets.TableView
	devices []svrpc.FIDO2Device
}

// showKeysPage shows the keys page, open at tab.
func (m *Manager) showKeysPage(tab int) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	if m.gone {
		m.fail(errGone)
		return
	}
	if m.kpage != nil && m.kpage.vault == m.vault && m.up(m.kpage.tabbedPage) {
		m.selectTab(m.kpage.tabbedPage, tab)
		return
	}
	m.closeVaultPage()
	title := "Keys"
	if m.vault != "" {
		title = "Keys in vault " + m.vault
	}
	p := &keysPage{tabbedPage: &tabbedPage{kind: pageKeys, vault: m.vault, title: title}}
	p.panes = []*pane{
		newPane("OpenPGP", func(pn *pane) { m.fillPGP(p, pn) }),
		newPane("S/MIME", func(pn *pane) { m.fillSMIME(p, pn) }),
		newPane("age", func(pn *pane) { m.fillAge(p, pn) }),
		newPane("Identity files", func(pn *pane) { m.fillIdentities(pn) }),
		newPane("Security keys", func(pn *pane) { m.fillSecurityKeys(p, pn) }),
	}
	m.kpage = p
	m.openPage(p.tabbedPage, tab)
}

// refreshKeys fills a tab of the keys page again, if it is up.
func (m *Manager) refreshKeys(p *keysPage, tab int) {
	if p != nil && m.up(p.tabbedPage) && p.panes[tab].filled {
		p.panes[tab].refresh()
	}
}

// needsVault is a tab's body when no vault is shown.
func (m *Manager) needsVault(pn *pane) bool {
	if pn.pg.vault != "" {
		return false
	}
	pn.box.Set(m.paragraph("These keys are kept in a vault: make one first (File › New vault…)."))
	return true
}

func (m *Manager) fillPGP(p *keysPage, pn *pane) {
	if m.needsVault(pn) {
		return
	}
	var entries []svrpc.Entry
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.List(ctx, p.vault, "")
		return err
	}, func() widget.Component {
		keys := svops.PGPKeyEntries(entries)
		p.pgp = keys
		p.ptable = table("OpenPGP keys", []widgets.TableColumn{
			{Title: "Item", Width: 170}, {Title: "Fingerprint", Width: 330}, {Title: "User ID"},
		}, len(keys), func(r, c int) string {
			e := keys[r]
			switch c {
			case 0:
				return e.Item.Name
			case 1:
				return svops.GroupFingerprint(e.Item.Attrs[svrpc.PGPFingerprint])
			}
			return e.Item.Attrs[svrpc.PGPUserID]
		})
		pn.focus = p.ptable
		note := "Your OpenPGP keys, for signing and decrypting mail and files. " + svops.KeysInVaultNote +
			" Desktop › GnuPG lets gpg use them too."
		if len(keys) == 0 {
			note = "No OpenPGP keys yet: New… makes one, Import… takes one in."
		}
		return m.paneColumn(note, p.ptable,
			widgets.NewButton("New…", func() { m.newPGPKey(p) }),
			widgets.NewButton("Import…", func() { m.importPGPKey(p) }),
			widgets.NewButton("Export…", func() { m.exportPGPKey(p) }),
			widgets.NewButton("Copy the public key", func() { m.copyPGPPublic(p) }))
	})
}

// pgpKey is the OpenPGP key selected (its item), or "" with one key or
// none, which the daemon then picks or refuses.
func (p *keysPage) pgpKey() string {
	if i := selected(p.ptable); i >= 0 && i < len(p.pgp) {
		return p.pgp[i].Item.Name
	}
	return ""
}

// newPGPKey makes an OpenPGP key in the daemon (the CLI's pgp new).
func (m *Manager) newPGPKey(p *keysPage) {
	f := m.newForm("New OpenPGP key")
	f.note(svops.PGPVersionNote)
	name := f.text("Your name", "", "as people will see it")
	emails := f.text("Addresses", "", "your address; several separated by commas")
	item := f.text("Item name", "", "Leave empty for pgp/ADDRESS")
	expires := f.text("Expires after", "", "days; empty for never")
	v4 := f.check("Version 4, for GnuPG 2.4 and older", false)
	f.show("Make the key", func() {
		params := svrpc.PGPGenerateParams{Vault: p.vault, Item: strings.TrimSpace(item.Text), Name: strings.TrimSpace(name.Text), Version: 6}
		for _, e := range strings.Split(emails.Text, ",") {
			if e = strings.TrimSpace(e); e != "" {
				params.Emails = append(params.Emails, e)
			}
		}
		if params.Name == "" && len(params.Emails) == 0 {
			f.fail("Give your name, or an address.")
			return
		}
		if d := strings.TrimSpace(expires.Text); d != "" {
			n, err := strconv.Atoi(d)
			if err != nil || n <= 0 {
				f.fail("Give the days it lasts as a number, or leave it empty.")
				return
			}
			params.LifetimeDays = n
		}
		if v4.Checked {
			params.Version = 4
		}
		var k svrpc.PGPKey
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			k, err = c.GeneratePGP(ctx, params)
			return err
		}, func() {
			m.refreshKeys(p, tabPGP)
			m.showText("OpenPGP key made", fmt.Sprintf("Made a version %d OpenPGP key, kept as %s. Give people its public key "+
				"(Copy the public key), or show it as a QR code (Contacts › Show my QR code…). %s", k.Version, k.Item, svops.FingerprintNote),
				svops.GroupFingerprint(k.Fingerprint)+"\n"+strings.Join(k.UserIDs, "\n"))
		})
	})
}

// importPGPKey takes a secret key in from a file (the CLI's pgp import);
// the key's own passphrase is asked for if it has one.
func (m *Manager) importPGPKey(p *keysPage) {
	f := m.newForm("Import an OpenPGP key")
	file := f.path("Key file", PickOpen, "")
	item := f.text("Item name", "", "Leave empty for pgp/ADDRESS")
	f.intro("One secret key of yours. Someone else's public key goes to Contacts › Add… instead.")
	f.show("Import the key", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the key's file.")
			return
		}
		name := strings.TrimSpace(item.Text)
		var it svrpc.Item
		var fp string
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			defer clear(data)
			it, fp, err = svops.PGPImportItem(data, path, name, func() ([]byte, error) {
				return m.askSecret("The key's passphrase", "Passphrase", "The key in "+filepath.Base(path)+
					" is protected by a passphrase. The vault keeps it beside the key.", false, 1)
			})
			if err != nil {
				return err
			}
			defer svops.Wipe(&it)
			return svops.StorePGPKey(ctx, c, p.vault, it)
		}, func() {
			m.say("Imported %s as %s.", svops.GroupFingerprint(fp), it.Name)
			m.refreshKeys(p, tabPGP)
		})
	})
}

// exportPGPKey writes a key's public key, or its secret key, to a file
// (the CLI's pgp export, and pub -o).
func (m *Manager) exportPGPKey(p *keysPage) {
	key := p.pgpKey()
	f := m.newForm("Export an OpenPGP key")
	what := f.choice("Export", []string{"its public key", "its secret key, under a new passphrase", "its secret key, as the vault keeps it"}, 0)
	file := f.path("File", PickSave, "key.asc")
	f.warn("A secret key taken out of the vault can be used by whoever gets the file, without asking you: keep it as safe as the vault.")
	f.show("Export the key", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose where it goes.")
			return
		}
		kind := what.Selected
		var note string
		m.replacing(path, func() {
			f.call(func(ctx context.Context, c *secretvault.Client) error {
				k, err := c.PGPPublicKey(ctx, p.vault, key)
				if err != nil {
					return err
				}
				data := []byte(k.PublicKey)
				if kind > 0 {
					e, err := c.Get(ctx, p.vault, k.Item)
					if err != nil {
						return err
					}
					defer svops.Wipe(&e.Item)
					sf, ok := svops.Field(&e.Item, svrpc.PGPSecretField)
					if !ok {
						return fmt.Errorf("%s has no secret key", k.Item)
					}
					data = sf.Value
					if kind == 1 {
						if data, err = svops.ProtectPGPKey(&e.Item, func() ([]byte, error) {
							return m.askSecret("The exported key's passphrase", "Passphrase", "The key is written protected by this passphrase.", true, minPassphrase)
						}); err != nil {
							return err
						}
						defer clear(data)
					} else if _, protected := svops.Field(&e.Item, svrpc.PGPPassField); protected {
						note = fmt.Sprintf(" The key is protected by the passphrase in its item's %q field.", svrpc.PGPPassField)
					}
				}
				return writeAtomic(path, 0o600, data)
			}, func() {
				m.say("Wrote it to %s.%s", path, note)
			})
		})
	})
}

// writeAtomic writes data to path, which appears only once it is whole
// (svops.CreateAtomic), with mode.
func writeAtomic(path string, mode os.FileMode, data []byte) error {
	a, err := svops.CreateAtomic(path, mode)
	if err != nil {
		return err
	}
	defer a.Abort()
	if _, err := a.Write(data); err != nil {
		return err
	}
	return a.Commit()
}

// copyPGPPublic copies the public key of the key selected (the CLI's pgp
// pub).
func (m *Manager) copyPGPPublic(p *keysPage) {
	key := p.pgpKey()
	var k svrpc.PGPKey
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		k, err = c.PGPPublicKey(ctx, p.vault, key)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		m.copyValue([]byte(k.PublicKey), "The public key of "+k.Item, "")
	})
}

func (m *Manager) fillSMIME(p *keysPage, pn *pane) {
	if m.needsVault(pn) {
		return
	}
	var keys []svrpc.SMIMEKey
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		keys, err = c.SMIMEKeys(ctx, p.vault)
		return err
	}, func() widget.Component {
		p.smime = keys
		t := table("S/MIME keys", []widgets.TableColumn{
			{Title: "Item", Width: 160}, {Title: "Addresses"}, {Title: "Certificate", Width: 150}, {Title: "Until", Width: 100},
		}, len(keys), func(r, c int) string {
			k := keys[r]
			switch c {
			case 0:
				return k.Item
			case 1:
				return strings.Join(k.Emails, ", ")
			case 2:
				return k.SHA256[:min(16, len(k.SHA256))]
			}
			return k.NotAfter.Local().Format("2006-01-02")
		})
		pn.focus = t
		note := "Your S/MIME keys and certificates, for signed and encrypted mail. Tools › Sign and encrypt a message… uses them."
		if len(keys) == 0 {
			note = "No S/MIME keys: Import… takes one in from a .p12 file."
		}
		return m.paneColumn(note, t, widgets.NewButton("Import…", func() { m.importSMIME(p) }))
	})
}

// importSMIME takes a key and its certificate in from a PKCS #12 file
// (the CLI's smime import).
func (m *Manager) importSMIME(p *keysPage) {
	f := m.newForm("Import an S/MIME key")
	f.intro("A PKCS #12 file (.p12 or .pfx): your certificate and its private key.")
	file := f.path("File", PickOpen, "")
	pass := f.secret("The file's password", "")
	item := f.text("Item name", "", "Leave empty for smime/ADDRESS")
	f.show("Import the key", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose the .p12 file.")
			return
		}
		params := svrpc.SMIMEImportParams{Vault: p.vault, Item: strings.TrimSpace(item.Text), Password: pass.Bytes()}
		var k svrpc.SMIMEKey
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			defer clear(data)
			params.PKCS12 = data
			k, err = c.ImportSMIME(ctx, params)
			return err
		}, func() {
			m.refreshKeys(p, tabSMIME)
			m.showText("S/MIME key imported", fmt.Sprintf("Imported %s: %s, for %s, until %s.", k.Item, k.Subject,
				strings.Join(k.Emails, ", "), k.NotAfter.Local().Format("2006-01-02")), strings.Join(k.Warnings, "\n"))
		}, params.Password)
	})
}

func (m *Manager) fillAge(p *keysPage, pn *pane) {
	if m.needsVault(pn) {
		return
	}
	var entries []svrpc.Entry
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		entries, err = c.List(ctx, p.vault, "")
		return err
	}, func() widget.Component {
		keys := svops.AgeKeyEntries(entries)
		p.age = keys
		p.atable = table("age identities", []widgets.TableColumn{
			{Title: "Item", Width: 170}, {Title: "Public key (recipient)"},
		}, len(keys), func(r, c int) string {
			if c == 0 {
				return keys[r].Item.Name
			}
			return keys[r].Item.Attrs[svops.AgeRecipientName]
		})
		pn.focus = p.atable
		note := svops.AgeNote + " Tools › Decrypt a file (age)… decrypts here; Desktop › Program helpers sets age up."
		if len(keys) == 0 {
			note = "No age identities yet: New… makes one."
		}
		return m.paneColumn(note, p.atable,
			widgets.NewButton("New…", func() { m.newAgeIdentity(p) }),
			widgets.NewButton("Copy the public key", func() { m.copyAge(p, false) }),
			widgets.NewButton("Copy the identity line", func() { m.copyAge(p, true) }))
	})
}

// newAgeIdentity makes an age identity and stores it (the CLI's age
// keygen), and offers its identity line as a file for age and SOPS.
func (m *Manager) newAgeIdentity(p *keysPage) {
	f := m.newForm("New age identity")
	name := f.text("Item name", "age/", "where to keep it, like age/backups")
	pq := f.check("Post-quantum (ML-KEM-768 with X25519; age 1.3 or later reads it)", false)
	file := f.path("Identity line file", PickSave, "identity.txt")
	f.note("Optional: a file for age and SOPS that names the identity. It holds no secret; the key stays in the vault.")
	f.show("Make the identity", func() {
		r, err := svops.AgeItemRef(p.vault, strings.TrimSpace(name.Text))
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		out := file.Path()
		var k *svops.AgeKey
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			n, err := svops.GenerateAgeIdentity(pq.Checked)
			if err != nil {
				return err
			}
			defer n.Wipe()
			if k, err = svops.StoreAgeIdentity(ctx, c, r, n); err != nil {
				return err
			}
			if out != "" {
				return svops.WriteNew(out, k.File)
			}
			return nil
		}, func() {
			m.refreshKeys(p, tabAge)
			intro := fmt.Sprintf("Made a new %s age identity, kept as %s.", k.Kind, r.Item)
			if out != "" {
				intro += " Its identity line is also in " + out + "."
			}
			intro += " Its public key (recipient), for encrypting to it, and its identity line, for age and SOPS:"
			m.showText("age identity made", intro, k.Recipient+"\n"+k.Plugin)
		})
	})
}

// copyAge copies the recipient of the identity selected (the CLI's age
// recipient), or its identity line (age identity).
func (m *Manager) copyAge(p *keysPage, line bool) {
	i := selected(p.atable)
	if i < 0 || i >= len(p.age) {
		m.say("Choose an identity first.")
		return
	}
	r := svrpc.Ref{Vault: p.vault, Item: p.age[i].Item.Name}
	var s string
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		if !line {
			s, err = svops.AgeItemRecipient(ctx, c, r)
			return err
		}
		if _, err = svops.AgeItemRecipient(ctx, c, r); err != nil {
			return err
		}
		vault, err := svops.VaultName(ctx, c, r.Vault)
		if err != nil {
			return err
		}
		s, err = svops.AgePluginIdentity(vault, r.Item)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		what := "The public key"
		if line {
			what = "The identity line"
		}
		m.copyValue([]byte(s), what, "")
	})
}

func (m *Manager) fillIdentities(pn *pane) {
	newID := widgets.NewButton("New identity file…", m.newIdentityFile)
	pn.focus = newID
	pn.box.Set(m.paneColumn(svops.IdentityFileNote, nil,
		newID, widgets.NewButton("Show a file's public key…", m.showIdentityRecipient)))
}

// newIdentityFile makes an identity and writes it to a new file (the
// CLI's identity new), and shows its recipient.
func (m *Manager) newIdentityFile() {
	f := m.newForm("New identity file")
	file := f.path("File", PickSave, "identity.txt")
	suites := make([]string, len(svops.IdentitySuites))
	for i, s := range svops.IdentitySuites {
		suites[i] = s.Text
	}
	suite := f.choice(svops.SuiteLabel, suites, 0)
	f.show("Make the file", func() {
		path := file.Path()
		if path == "" {
			f.fail("Choose where it goes.")
			return
		}
		var rcpt string
		s := svops.IdentitySuites[max(0, suite.Selected)].Name
		f.work(func() error {
			r, body, err := svops.NewIdentity(s, "identity")
			if err != nil {
				return err
			}
			defer clear(body)
			rcpt = r
			return svops.WriteNew(path, body)
		}, func() {
			m.showText("Identity file made", svops.IdentityMadeNote+" (The file: "+path+".)", rcpt)
		})
	})
}

// showIdentityRecipient shows the recipient of an identity file (the
// CLI's identity pub).
func (m *Manager) showIdentityRecipient() {
	m.pickFile(PickOpen, "", func(path string) {
		if path == "" {
			return
		}
		var rcpt string
		m.work(func() (err error) {
			rcpt, err = svops.IdentityRecipient(path)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.showText("Public key of an identity file", "The public key (recipient) of the identity in "+filepath.Base(path)+", to give to people who share vaults with you:", rcpt)
		})
	})
}

func (m *Manager) fillSecurityKeys(p *keysPage, pn *pane) {
	var keys []svrpc.FIDO2Device
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		keys, err = c.SecurityKeys(ctx)
		return err
	}, func() widget.Component {
		p.devices = keys
		col := widgets.NewColumn().WithGap(gap).WithPad(gap)
		refresh := widgets.NewButton("Refresh", pn.refresh)
		pn.focus = refresh
		if len(keys) == 0 {
			col.Add(m.paragraph("No security key is plugged in. Plug one in and press Refresh; Vault › Keyslots › Add a keyslot… adds it as a way to open a vault."))
		}
		for _, k := range keys {
			col.Add(section(m, k.Name))
			col.Add(m.facts(svops.SecurityKeyFacts(k)))
		}
		col.Add(buttons(refresh))
		return scrolled(col)
	})
}
