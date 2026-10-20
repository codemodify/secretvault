package svmanager

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Contacts: the people whose keys you hold, how each key was verified,
// finding keys (by WKD, keyservers and organisations' directories),
// verifying them, your own keys as a QR code for others to scan, and the
// trust store's verdict on a signer. They live in the contacts vault
// (Vault › Contacts › Keep contacts in…).

// The contacts page's tabs.
const (
	tabPeople = iota
	tabDirectories
)

// contactsPage is the contacts page's state.
type contactsPage struct {
	*tabbedPage
	query    string
	list     []svrpc.Contact
	ctable   *widgets.TableView
	detail   *slot
	shown    *svrpc.Contact // the contact shown below the list, whole
	dirs     []svrpc.DirectoryConfig
	dtable   *widgets.TableView
	showGen  int
	searchTF *widgets.TextField
}

// showContactsPage shows the contacts page, open at tab.
func (m *Manager) showContactsPage(tab int) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	if m.gone {
		m.fail(errGone)
		return
	}
	m.showVaultTab(vtContacts)
	if m.cpage != nil {
		m.selectTab(m.cpage.tabbedPage, tab)
	}
}

// makeContactsPage makes the contacts' page.
func (m *Manager) makeContactsPage() {
	p := &contactsPage{tabbedPage: &tabbedPage{kind: pageContacts, title: "Contacts"}, detail: newSlot()}
	p.panes = []*pane{
		newPane("People", func(pn *pane) { m.fillPeople(p, pn) }),
		newPane("Directories", func(pn *pane) { m.fillDirectories(p, pn) }),
	}
	m.cpage = p
}

// refreshContacts lists the contacts again, if their page is up.
func (m *Manager) refreshContacts() {
	if p := m.cpage; p != nil && m.up(p.tabbedPage) && p.panes[tabPeople].filled {
		p.panes[tabPeople].refresh()
	}
}

func (m *Manager) fillPeople(p *contactsPage, pn *pane) {
	var list []svrpc.Contact
	query := p.query
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		list, err = c.Contacts(ctx, "", query)
		return err
	}, func() widget.Component {
		p.list = list
		p.ctable = table("Contacts", []widgets.TableColumn{
			{Title: "Name", Width: 180}, {Title: "Addresses"}, {Title: "Keys", Width: 130}, {Title: "Verified", Width: 150},
		}, len(list), func(r, c int) string {
			ct := list[r]
			switch c {
			case 0:
				if ct.Origin == svtrust.OriginMail || ct.Origin == svtrust.OriginLookup {
					return ct.Name + " (from " + ct.Origin + ")"
				}
				return ct.Name
			case 1:
				return strings.Join(ct.Emails, ", ")
			case 2:
				var types []string
				for _, k := range ct.Keys {
					types = append(types, k.Type)
				}
				return strings.Join(types, ", ")
			}
			return svops.LevelText(ct.Level)
		})
		p.ctable.OnSelect = func(i int) { m.showContact(p, i) }
		p.ctable.OnActivate = func(i int) { m.showContact(p, i) }
		search := widgets.NewTextField(p.query, "Filter the contacts", nil)
		search.SetAccessibleName("Filter the contacts")
		search.OnSubmit = func(q string) {
			p.query = strings.TrimSpace(q)
			pn.refresh()
		}
		p.searchTF = search
		pn.focus = p.ctable
		if len(list) == 0 {
			p.detail.Set(m.paragraph("No contacts yet. " + svops.ContactsAbout + " Add… takes someone's public key from a file, " +
				"Import… takes a file of keys or a scanned QR code, and Look up… finds keys by email address."))
		} else {
			p.ctable.Selected = 0
			m.showContact(p, 0)
		}
		col := widgets.NewColumn(search,
			widgets.NewHeightBox(200, p.ctable),
			buttons(
				newButton("Add…", m.addContact),
				newButton("Import…", m.importContacts),
				newButton("Look up…", m.lookupContact),
				newButton("Verify…", func() { m.verifyContact(p) }),
				newButton("Remove…", func() { m.removeContact(p) }),
				newButton("Show my QR code…", m.showMyQR),
				newButton("Check a signer…", m.checkSigner),
				newButton("Record a key seen in mail…", m.recordSeen),
				newButton("Keep contacts in…", m.contactsVault),
			),
			p.detail).WithGap(gap).WithPad(gap)
		col.AddFlex(p.detail, 1)
		return col
	})
}

// showContact fetches the contact at row i, whole, and shows it below the
// list: its keys, how each was verified, where each was seen.
func (m *Manager) showContact(p *contactsPage, i int) {
	if i < 0 || i >= len(p.list) {
		return
	}
	id := p.list[i].ID
	p.showGen++
	gen := p.showGen
	var ct svrpc.Contact
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		ct, err = c.Contact(ctx, "", id)
		return err
	}, func(err error) {
		if gen != p.showGen || !m.up(p.tabbedPage) {
			return
		}
		if err != nil {
			p.detail.Set(m.paragraph(m.describe(err)))
			return
		}
		p.shown = &ct
		p.detail.Set(widgets.NewScrollView(m.contactView(ct)))
	})
}

// contactView lays a contact out, as the CLI's contact show prints it.
func (m *Manager) contactView(ct svrpc.Contact) widget.Component {
	day := func(t time.Time) string { return t.Local().Format("2006-01-02") }
	col := widgets.NewColumn(heading(ct.Name)).WithGap(gap)
	rows := [][2]string{{"ID", ct.ID}}
	if len(ct.Emails) > 0 {
		rows = append(rows, [2]string{"Addresses", strings.Join(ct.Emails, ", ")})
	}
	if ct.Organisation {
		rows = append(rows, [2]string{"Organisation", "yes: its CA certificates vouch for those they issue"})
	}
	if ct.Notes != "" {
		rows = append(rows, [2]string{"Notes", ct.Notes})
	}
	rows = append(rows, [2]string{"Origin", ct.Origin + ", " + day(ct.Created)})
	col.Add(m.facts(rows))
	for _, k := range ct.Keys {
		col.Add(section(m, k.Type+" key"))
		fp := widgets.NewLabel(svops.GroupFingerprint(k.Fingerprint))
		fp.Mono = true
		fp.Wrap = true
		fp.SetAccessibleName("Fingerprint: " + k.Fingerprint)
		col.Add(fp)
		var kr [][2]string
		if k.Label != "" {
			kr = append(kr, [2]string{"Label", k.Label})
		}
		if len(k.Addresses) > 0 {
			kr = append(kr, [2]string{"Addresses", strings.Join(k.Addresses, ", ")})
		}
		kr = append(kr, [2]string{"Verified", svops.LevelText(k.Level)})
		if k.State != "" {
			kr = append(kr, [2]string{"State", k.State})
		}
		added := day(k.Added)
		if k.Source != "" {
			added += ", from " + k.Source
		}
		kr = append(kr, [2]string{"Added", added})
		for _, v := range k.Verifications {
			kr = append(kr, [2]string{"How", v.Description})
		}
		for _, s := range k.Seen {
			kr = append(kr, [2]string{"Seen", fmt.Sprintf("%s from %s, %s to %s", timesText(s.Count), s.Address, day(s.First), day(s.Last))})
		}
		col.Add(m.facts(kr))
	}
	for _, w := range ct.Warnings {
		l := toned("Warning: "+w, widgets.ToneWarning)
		l.Wrap = true
		col.Add(l)
	}
	return col
}

func timesText(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// fingerprintsOf lists keys, for a report.
func fingerprintsOf(keys []svrpc.ImportedKey) string {
	var b strings.Builder
	for _, k := range keys {
		what := "Updated"
		switch {
		case k.Verified:
			what = "Verified in person"
		case k.New:
			what = "Added"
		}
		fmt.Fprintf(&b, "%s: %s %s (%s)\n", what, k.Type, svops.GroupFingerprint(k.Fingerprint), k.Contact)
		for _, w := range k.Warnings {
			b.WriteString("  warning: " + w + "\n")
		}
	}
	return b.String()
}

// addContact makes a contact with the keys in the files chosen (the CLI's
// contact add).
func (m *Manager) addContact() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Add a contact")
	f.intro(svops.AddContactLead)
	files := f.path("Key files", PickOpen, "")
	f.note("Key files: one, or several separated by commas.")
	name := f.text("Name", "", "leave empty to take it from the key")
	emails := f.text("Addresses", "", "email addresses, separated by commas")
	notes := f.text("Notes", "", "optional: how you know them")
	org := f.check("An organisation: certificates its CA issues count as vouched for by it", false)
	f.show("Add the contact", func() {
		var paths []string
		for _, s := range strings.Split(files.Path(), ",") {
			if s = strings.TrimSpace(s); s != "" {
				paths = append(paths, s)
			}
		}
		params := svrpc.ContactAddParams{Name: strings.TrimSpace(name.Text), Emails: splitList(emails.Text), Notes: strings.TrimSpace(notes.Text), Organisation: org.Checked}
		if len(paths) == 0 && params.Name == "" {
			f.fail("Choose a key file, or give a name.")
			return
		}
		if len(paths) > 0 {
			params.Source = "file " + strings.Join(paths, ", ")
		}
		var ch svrpc.ContactChange
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			for _, p := range paths {
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				params.Keys = append(params.Keys, data)
			}
			var err error
			ch, err = c.AddContact(ctx, params)
			return err
		}, func() {
			var b strings.Builder
			for _, k := range ch.Contact.Keys {
				fmt.Fprintf(&b, "%s %s\n", k.Type, svops.GroupFingerprint(k.Fingerprint))
			}
			for _, w := range ch.Warnings {
				b.WriteString("warning: " + w + "\n")
			}
			intro := fmt.Sprintf("Added %s with %s.", ch.Contact.Name, plural(len(ch.Contact.Keys), "key"))
			if len(ch.Contact.Keys) > 0 {
				intro += " It is not verified yet: compare the fingerprint below with them, then use the Verify… button."
			}
			m.refreshContacts()
			m.showText("Contact added", intro, strings.TrimRight(b.String(), "\n"))
		})
	})
}

// splitList reads a comma-separated list.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// importContacts takes in many keys from a file, or records a QR code
// scanned from someone's screen, pasted as its text (the CLI's contact
// import): a scanned code verifies the keys it names.
func (m *Manager) importContacts() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Import contacts")
	f.intro(svops.ImportContactsLead)
	from := f.path("File or code", PickOpen, "")
	f.note("A scanned code is pasted as its text, which starts secretvault-contact: or openpgp4fpr:.")
	to := f.text("Into contact", "", "optional: add the keys to this contact")
	name := f.text("Name", "", "optional: the name for new contacts")
	fetch := f.check("If the code names OpenPGP keys you do not have, download them from the keyserver", false)
	keyserver := f.text("Keyserver", "", "leave empty for keys.openpgp.org")
	f.show("Import", func() {
		arg := from.Path()
		if arg == "" {
			f.fail("Choose a file, or paste a code.")
			return
		}
		params := svrpc.ContactImportParams{Contact: strings.TrimSpace(to.Text), Name: strings.TrimSpace(name.Text), Fetch: fetch.Checked, Keyserver: strings.TrimSpace(keyserver.Text)}
		var res svrpc.ContactImportResult
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			if svops.IsContactURI(arg) {
				params.URI = arg
			} else {
				data, err := os.ReadFile(arg)
				if err != nil {
					return err
				}
				params.Data, params.Source = data, "file "+arg
			}
			var err error
			res, err = c.ImportContacts(ctx, params)
			return err
		}, func() {
			text := fingerprintsOf(res.Keys)
			for _, x := range res.Missing {
				typ, fp, _ := strings.Cut(x, ":")
				text += fmt.Sprintf("Not found: %s %s (add the key, or fetch it, then scan again)\n", typ, svops.GroupFingerprint(fp))
			}
			for _, w := range res.Warnings {
				text += "warning: " + w + "\n"
			}
			m.refreshContacts()
			intro := "Imported " + plural(len(res.Keys), "key") + "."
			if len(res.Keys) == 0 {
				// As the CLI, which fails: said, with what was not found,
				// which is what a scanned code naming keys you do not
				// have needs.
				intro = "Nothing was imported."
			}
			m.showText("Contacts imported", intro, strings.TrimRight(text, "\n"))
		})
	})
}

// removeContact removes the contact shown, or one of its keys (the CLI's
// contact rm).
func (m *Manager) removeContact(p *contactsPage) {
	ct := p.shown
	if ct == nil {
		m.say("Choose a contact first.")
		return
	}
	f := m.newForm("Remove " + ct.Name)
	choices := []string{"the whole contact"}
	for _, k := range ct.Keys {
		choices = append(choices, "only its "+k.Type+" key "+svops.GroupFingerprint(k.Fingerprint))
	}
	which := f.choice("Remove", choices, 0)
	f.note("How you verified it is forgotten with it. Nothing else changes: vaults you share with them stay shared.")
	f.show("Remove", func() {
		fp := ""
		if i := which.Selected - 1; i >= 0 && i < len(ct.Keys) {
			fp = ct.Keys[i].Fingerprint
		}
		var out svrpc.Contact
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			out, err = c.RemoveContact(ctx, "", ct.ID, fp)
			return err
		}, func() {
			if fp != "" {
				m.say("Removed key %s from %s.", svops.GroupFingerprint(fp), out.Name)
			} else {
				m.say("Removed %s.", out.Name)
			}
			p.shown = nil
			m.refreshContacts()
		})
	})
}

// verifyContact records how one of the contact's keys was verified (the
// CLI's contact verify): the fingerprint is typed as it was compared.
func (m *Manager) verifyContact(p *contactsPage) {
	ct := p.shown
	if ct == nil || len(ct.Keys) == 0 {
		m.say("Choose a contact with a key first.")
		return
	}
	f := m.newForm("Verify " + ct.Name + "'s key")
	f.intro(svops.VerifyLead)
	var keys []string
	for _, k := range ct.Keys {
		keys = append(keys, k.Type+" "+svops.GroupFingerprint(k.Fingerprint))
	}
	key := f.choice("Key", keys, 0)
	fp := f.text("Fingerprint", "", "as you compared it, or its last 16 characters")
	methods := make([]string, len(svops.VerifyWays))
	for i, v := range svops.VerifyWays {
		methods[i] = v.Text
	}
	how := widgets.NewRadioGroup(methods, 0, nil)
	how.SetAccessibleName("How")
	f.row("How", how)
	org := f.text("Organisation", "", "if an organisation vouches for it: which")
	emails := f.text("Addresses", "", "optional: only for these (else the key's own)")
	note := f.text("Note", "", "optional: where or how, in your words")
	f.show("Mark as verified", func() {
		typed := strings.TrimSpace(fp.Text)
		chosen := ct.Keys[max(0, key.Selected)]
		norm := svtrust.NormalizeFingerprint(typed)
		switch {
		case typed == "":
			f.fail("Type the fingerprint as you compared it.")
			return
		case norm != chosen.Fingerprint && !strings.HasSuffix(chosen.Fingerprint, norm):
			f.fail(svops.NotTheFingerprint)
			return
		}
		v := svops.VerifyWays[max(0, how.Selected())]
		params := svrpc.ContactVerifyParams{Ref: ct.ID, Fingerprint: typed, Method: v.Method, Source: strings.TrimSpace(note.Text), Addresses: splitList(emails.Text)}
		if v.Method == svrpc.VerifyOrgDirectory {
			if params.Source = strings.TrimSpace(org.Text); params.Source == "" {
				f.fail("Say which organisation vouches for it.")
				return
			}
		}
		var out svrpc.Contact
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			out, err = c.VerifyContact(ctx, params)
			return err
		}, func() {
			for _, k := range out.Keys {
				if k.Fingerprint == chosen.Fingerprint {
					m.say("%s's %s key %s: %s.", out.Name, k.Type, svops.GroupFingerprint(k.Fingerprint), svops.LevelText(k.Level))
				}
			}
			m.refreshContacts()
		})
	})
}

// lookupContact finds keys by address or fingerprint, through WKD,
// keyservers and the organisations' directories (the CLI's contact
// lookup), and keeps them if asked.
func (m *Manager) lookupContact() {
	if m.gone {
		m.fail(errGone)
		return
	}
	var dirs []svrpc.DirectoryConfig
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		dirs, err = c.Directories(ctx)
		return err
	}, func(error) {
		f := m.newForm("Look up keys")
		f.intro(svops.LookupLead)
		query := f.text("Address or fingerprint", "", "ada@example.org")
		where := []string{"everywhere", "only the email provider's key directory (WKD)", "only the keyserver below"}
		for _, d := range dirs {
			where = append(where, "only the directory "+d.Name)
		}
		at := f.choice("Ask", where, 0)
		keyserver := f.text("Keyserver", "", "only to ask one: hkps://keys.example.org")
		add := f.check("Add what is found to the contacts, not verified", false)
		name := f.text("Name", "", "for new contacts")
		f.show("Look up", func() {
			q := strings.TrimSpace(query.Text)
			if q == "" {
				f.fail("Give an address or a fingerprint.")
				return
			}
			params := svrpc.ContactLookupParams{Query: q, Add: add.Checked, Name: strings.TrimSpace(name.Text)}
			switch i := at.Selected; {
			case i == 1:
				params.WKD = true
			case i == 2:
				if params.Keyserver = strings.TrimSpace(keyserver.Text); params.Keyserver == "" {
					f.fail("Give the keyserver.")
					return
				}
			case i > 2:
				params.Directory = dirs[i-3].Name
			}
			var res svrpc.ContactLookupResult
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				res, err = c.LookupContact(ctx, params)
				return err
			}, func() {
				var b strings.Builder
				for _, found := range res.Found {
					fmt.Fprintf(&b, "From %s\n", found.URL)
					if len(found.Policy) > 0 {
						fmt.Fprintf(&b, "  policy: %s\n", strings.Join(found.Policy, "; "))
					}
					for i, k := range found.Keys {
						known := ""
						if i < len(found.Known) && found.Known[i] != "" {
							known = " (you have it: " + found.Known[i] + ")"
						}
						fmt.Fprintf(&b, "  %s %s  %s%s\n", k.Type, svops.GroupFingerprint(k.Fingerprint), k.Label, known)
						if len(k.Addresses) > 0 {
							fmt.Fprintf(&b, "    for %s: %s\n", strings.Join(k.Addresses, ", "), svops.LevelText(k.Level))
						}
					}
				}
				for _, e := range res.Errors {
					fmt.Fprintf(&b, "note: %s\n", e)
				}
				b.WriteString(fingerprintsOf(res.Added))
				intro := "Found nothing for " + q + "."
				if len(res.Found) > 0 {
					intro = "Found for " + q + ". None of it is verified until you compare its fingerprint with them."
				}
				if len(res.Added) > 0 {
					m.refreshContacts()
				}
				m.showText("Looked up "+q, intro, strings.TrimRight(b.String(), "\n"))
			})
		})
	})
}

// showMyQR shows your own keys as a QR code for someone to scan (the
// CLI's contact qr): the key items chosen (OpenPGP or SSH keys; none
// chosen, every OpenPGP key), and secretvault recipients if named.
func (m *Manager) showMyQR() {
	if m.gone {
		m.fail(errGone)
		return
	}
	vault := m.vault
	var entries []svrpc.Entry
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		if vault == "" {
			return nil
		}
		entries, err = c.List(ctx, vault, "")
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		f := m.newForm("My QR code")
		f.intro(svops.MyCodeLead)
		var keys []string
		for _, e := range entries {
			if e.Item.Attrs[svrpc.PGPFingerprint] != "" || e.Item.Kind == "ssh-key" {
				keys = append(keys, e.Item.Name)
			}
		}
		boxes := make([]*widgets.Checkbox, len(keys))
		if len(keys) > 0 {
			list := widgets.NewColumn().WithGap(4)
			for i, k := range keys {
				boxes[i] = widgets.NewCheckbox(k, false, nil)
				list.Add(boxes[i])
			}
			f.row("Keys", list)
			f.note("None ticked: every OpenPGP key in vault " + vault + ".")
		}
		rcpt := f.path("Recipient", PickOpen, "")
		f.note("Optional: your " + svops.RecipientMeans + ", or your identity file, so that they can share vaults with you.")
		name := f.text("Name", "", "default: from your first OpenPGP key")
		emails := f.text("Addresses", "", "default: your first OpenPGP key's")
		f.show("Show the code", func() {
			var items, recipients []string
			for i, b := range boxes {
				if b.Checked {
					items = append(items, keys[i])
				}
			}
			if r := rcpt.Path(); r != "" {
				recipients = []string{r}
			}
			var card *svtrust.Card
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				card, err = svops.OwnCard(ctx, c, vault, items, recipients)
				return err
			}, func() {
				if n := strings.TrimSpace(name.Text); n != "" {
					card.Name = n
				}
				if e := splitList(emails.Text); len(e) > 0 {
					card.Emails = e
				}
				uri := card.URI()
				qr, code := m.qrCode("contact code", []byte(uri), "Scan it with the other device's camera.")
				m.showTextWith("My contact code", "Let them scan this code from your screen: it holds no secret. "+
					"Or send them the text below, for Vault › Contacts › Import… on their side.", uri, qr, code.forget)
			})
		})
	})
}

// contactsVault chooses the vault contacts are kept in (the CLI's contact
// vault), saying which it is now.
func (m *Manager) contactsVault() {
	if m.gone {
		m.fail(errGone)
		return
	}
	var now string
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		now, err = c.ContactsVault(ctx, "")
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		// The vaults as they are now: the list may change under the dialog.
		names := []string{"the default vault, whichever it is"}
		var vaultNames []string
		sel := 0
		for i, v := range m.vaults {
			names = append(names, v.Name)
			vaultNames = append(vaultNames, v.Name)
			if v.Name == now {
				sel = i + 1
			}
		}
		f := m.newForm("Keep contacts in")
		f.note("Contacts are kept in vault " + now + " now. Choosing another vault does not move them: it shows that vault's own contacts instead.")
		which := f.choice("Vault", names, sel)
		f.show("Keep contacts there", func() {
			set := "-"
			if i := which.Selected - 1; i >= 0 && i < len(vaultNames) {
				set = vaultNames[i]
			}
			var name string
			f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				name, err = c.ContactsVault(ctx, set)
				return err
			}, func() {
				m.say("Contacts are kept in vault %s now.", name)
				m.refreshContacts()
			})
		})
	})
}

func (m *Manager) fillDirectories(p *contactsPage, pn *pane) {
	var dirs []svrpc.DirectoryConfig
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		dirs, err = c.Directories(ctx)
		return err
	}, func() widget.Component {
		p.dirs = dirs
		p.dtable = table("Directories", []widgets.TableColumn{
			{Title: "Name", Width: 120}, {Title: "Address"}, {Title: "People under"}, {Title: "Binds as", Width: 140},
		}, len(dirs), func(r, c int) string {
			d := dirs[r]
			switch c {
			case 0:
				return d.Name
			case 1:
				return d.URL
			case 2:
				return d.BaseDN
			}
			if d.BindDN == "" {
				return "anonymous"
			}
			return d.BindDN
		})
		pn.focus = p.dtable
		note := svops.DirectoriesAbout
		if len(dirs) == 0 {
			note = "No directories yet. " + svops.DirectoriesAbout + " Add… adds one."
		}
		remove := newButton("Remove…", func() { m.removeDirectory(p) })
		remove.SetEnabled(len(dirs) > 0)
		return m.paneColumn(note, p.dtable, newButton("Add…", func() { m.addDirectory(p) }), remove)
	})
}

// addDirectory adds an organisation's directory (the CLI's contact
// directory add).
func (m *Manager) addDirectory(p *contactsPage) {
	f := m.newForm("Add a directory")
	f.intro(svops.DirectoriesAbout)
	name := f.text("Name", "", "what to call it: example")
	url := f.text("Address", "", "ldaps://ldap.example.com, or ldap:// for StartTLS")
	base := f.text("People under", "", "dc=example,dc=com")
	bind := f.text("Bind as", "", "optional: the account's DN (else anonymously)")
	pw := f.text("Its password", "", "the vault item that holds it: sv://VAULT/ITEM#FIELD")
	ca := f.path("CA certificate", PickOpen, "")
	f.note(svops.DirectoryPasswordNote + " The CA certificate is needed only for a private CA.")
	f.show("Add the directory", func() {
		d := svrpc.DirectoryConfig{Name: strings.TrimSpace(name.Text), URL: strings.TrimSpace(url.Text), BaseDN: strings.TrimSpace(base.Text),
			BindDN: strings.TrimSpace(bind.Text), Password: strings.TrimSpace(pw.Text), CAFile: ca.Path()}
		if d.Name == "" || d.URL == "" {
			f.fail("Give the directory a name and its address.")
			return
		}
		f.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.AddDirectory(ctx, d)
		}, func() {
			m.say("Lookups of an address now ask %s first; what it says counts as %s vouching for the key.", d.Name, d.Name)
			if m.up(p.tabbedPage) {
				p.panes[tabDirectories].refresh()
			}
		})
	})
}

// removeDirectory removes the directory selected (the CLI's contact
// directory rm).
func (m *Manager) removeDirectory(p *contactsPage) {
	i := selected(p.dtable)
	if i < 0 || i >= len(p.dirs) {
		return
	}
	name := p.dirs[i].Name
	rm := svops.RemoveDirectoryPlain(name)
	m.confirm(rm.Title, rm.Summary, rm.Action, func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.RemoveDirectory(ctx, name)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Removed directory %s.", name)
			if m.up(p.tabbedPage) {
				p.panes[tabDirectories].refresh()
			}
		})
	})
}

// minLevels are the weakest verifications a signer check counts, as
// trust.check takes them, in svops's words (svops.TrustLevels).
var minLevels = func() []struct{ level, text string } {
	out := make([]struct{ level, text string }, len(svops.TrustLevels))
	for i, l := range svops.TrustLevels {
		out[i].level, out[i].text = l.Level, l.Text
	}
	return out
}()

// checkSigner asks the trust store for its verdict on a signer (the
// CLI's trust check): a fingerprint or a key file, and the address the
// message claims to be from.
func (m *Manager) checkSigner() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Check a signer")
	f.intro(svops.CheckSignerLead)
	fp := f.text("Fingerprint", "", "the signer's key fingerprint or key ID")
	key := f.path("Or its key", PickOpen, "")
	from := f.text("From", "", "the address the message claims to be from")
	levels := make([]string, len(minLevels))
	for i, l := range minLevels {
		levels[i] = l.text
	}
	least := f.choice("Counts if at least", levels, 0)
	f.show("Check", func() {
		params := svrpc.TrustCheckParams{Fingerprint: strings.TrimSpace(fp.Text), From: strings.TrimSpace(from.Text), MinLevel: minLevels[max(0, least.Selected)].level}
		path := key.Path()
		if (params.Fingerprint == "") == (path == "") {
			f.fail("Give a fingerprint, or choose the key's file: one of them.")
			return
		}
		var v svrpc.Verdict
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if path != "" {
				if params.Key, err = os.ReadFile(path); err != nil {
					return err
				}
			}
			v, err = c.CheckSigner(ctx, params)
			return err
		}, func() {
			m.showVerdicts("The signer", []svrpc.Verdict{v})
		})
	})
}

// showVerdicts shows the trust store's verdicts, with their reasons.
func (m *Manager) showVerdicts(title string, vs []svrpc.Verdict) {
	var b strings.Builder
	intro := ""
	for i, v := range vs {
		if i == 0 {
			intro = v.Status
		} else {
			b.WriteString("\n" + v.Status + "\n")
		}
		for _, r := range v.Reasons {
			b.WriteString("  " + r + "\n")
		}
	}
	m.showText(title, intro, strings.TrimRight(b.String(), "\n"))
}

// recordSeen records a key that came with a message from an address
// (the CLI's trust seen), so that a later one from that address is
// compared with it.
func (m *Manager) recordSeen() {
	if m.gone {
		m.fail(errGone)
		return
	}
	f := m.newForm("Record a key seen in mail")
	f.intro(svops.KeySeenLead)
	key := f.path("Key", PickOpen, "")
	from := f.text("From", "", "the address it came from")
	at := f.text("Received", "", "optional: YYYY-MM-DD (else now)")
	source := f.text("What it was", "", "optional (default: mail from the address, on the day)")
	name := f.text("Their name", "", "optional, for a new contact")
	f.show("Record", func() {
		path, addr := key.Path(), strings.TrimSpace(from.Text)
		if path == "" || addr == "" {
			f.fail("Choose the key that came with the message, and give the address it came from.")
			return
		}
		params := svrpc.TrustSeenParams{Address: addr, Source: strings.TrimSpace(source.Text), Name: strings.TrimSpace(name.Text)}
		if s := strings.TrimSpace(at.Text); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				if t, err = time.ParseInLocation("2006-01-02", s, time.Local); err != nil {
					f.fail("Give when it was received as YYYY-MM-DD, or leave it empty.")
					return
				}
			}
			params.Time = t
		}
		var res svrpc.SeenResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if params.Key, err = os.ReadFile(path); err != nil {
				return err
			}
			res, err = c.KeySeen(ctx, params)
			return err
		}, func() {
			what := "Seen again"
			if res.New {
				what = "A new key"
			}
			m.refreshContacts()
			m.showText("Key recorded", fmt.Sprintf("%s: %s from %s (%s).", what, svops.GroupFingerprint(res.Fingerprint), svtrust.ParseAddress(addr), res.Contact.Name),
				strings.Join(res.Warnings, "\n"))
		})
	})
}
