package svtui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svqr"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// The contacts panel (C): people and their keys, and how each was
// verified ('secretvault contact'), the verdict on a message's signer and
// keys seen in mail ('secretvault trust'), and the organisations'
// directories asked for keys ('contact directory'). Contacts live in the
// contacts vault (the configured one, else the default), as for the CLI.

func (u *UI) showContacts() {
	p := u.newPanel("Contacts", "NAME", "EMAILS", "KEYS", "VERIFIED")
	query := ""
	p.reload = func() {
		var cs []svrpc.Contact
		var where string
		q := query
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			if where, err = c.ContactsVault(ctx, ""); err != nil {
				return err
			}
			cs, err = c.Contacts(ctx, "", q)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.vault = where
			title := "Contacts · in " + where
			if query != "" {
				title += " · matching " + query
			}
			p.frame.SetTitle(" " + tview.Escape(title) + " ")
			p.clear()
			if len(cs) == 0 {
				p.none("No contacts yet (a adds one).")
			}
			for _, ct := range cs {
				var types []string
				for _, k := range ct.Keys {
					types = append(types, k.Type)
				}
				name := ct.Name
				if ct.Origin == svtrust.OriginMail || ct.Origin == svtrust.OriginLookup {
					name += " (from " + ct.Origin + ")"
				}
				p.row(ct, name, strings.Join(ct.Emails, ", "), strings.Join(types, ", "), svops.LevelText(ct.Level))
			}
			p.done()
		})
	}
	p.setHead(svops.ContactsAbout + " Enter shows a contact's keys and how each was verified; v there verifies one, once you have compared its fingerprint with them.")
	isContact := is[svrpc.Contact]
	p.rowAct('o', "Its keys", isContact, func(ref any) { u.showContact(ref.(svrpc.Contact).ID, p.refresh) })
	p.rowAct('x', "Remove the contact…", isContact, func(ref any) {
		ct := ref.(svrpc.Contact)
		u.removeContact(ct.ID, ct.Name, "", p.refresh)
	})
	p.act('/', "Find…", func() {
		u.askTo("Find contacts", "Name or address:", query, "Find", func(q string) {
			query = q
			p.refresh()
		})
	})
	p.act('*', "All", func() {
		query = ""
		p.refresh()
	})
	p.act('a', "Add…", func() { u.addContact(p.refresh) })
	p.act('m', "Import keys or a scanned code…", func() { u.importContacts(p.refresh) })
	p.act('l', "Look up keys…", func() { u.lookupContact(p.refresh) })
	p.act('c', "My QR code…", u.showMyCard)
	p.act('t', "Check a signer…", u.checkSigner)
	p.act('s', "Record a key seen in mail…", func() { u.keySeen(p.refresh) })
	p.act('v', "Keep contacts in…", func() { u.chooseContactsVault(p.refresh) })
	p.act('d', "Directories…", u.showDirectories)
	p.enter = func(ref any) {
		if ct, ok := ref.(svrpc.Contact); ok {
			u.showContact(ct.ID, p.refresh)
		}
	}
	p.show()
}

// keyRef is a row of a contact's keys.
type keyRef struct {
	contact string // its name
	key     svrpc.ContactKey
}

// showContact is 'secretvault contact show NAME', as a panel of the
// contact's keys: v verifies one, x removes one, Enter tells all of it.
func (u *UI) showContact(id string, then func()) {
	p := u.newPanel("Contact", "TYPE", "FINGERPRINT", "VERIFIED", "STATE")
	p.page = pageSub
	var ct svrpc.Contact
	p.reload = func() {
		var got svrpc.Contact
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			got, err = c.Contact(ctx, "", id)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			ct = got
			p.frame.SetTitle(" " + tview.Escape(ct.Name) + " ")
			var b strings.Builder
			fmt.Fprintf(&b, "[::b]%s[::-]  %s", tview.Escape(ct.Name), tview.Escape(svops.LevelText(ct.Level)))
			if len(ct.Emails) > 0 {
				fmt.Fprintf(&b, "\nemails: %s", tview.Escape(strings.Join(ct.Emails, ", ")))
			}
			if ct.Organisation {
				b.WriteString("\norganisation: its CA certificates vouch for those they issue")
			}
			if ct.Notes != "" {
				fmt.Fprintf(&b, "\nnotes: %s", tview.Escape(ct.Notes))
			}
			fmt.Fprintf(&b, "\norigin: %s, %s · id %s", tview.Escape(ct.Origin), ct.Created.Local().Format("2006-01-02"), tview.Escape(ct.ID))
			for _, w := range ct.Warnings {
				fmt.Fprintf(&b, "\n[yellow]warning:[-] %s", tview.Escape(w))
			}
			p.setHead(b.String())
			p.clear()
			if len(ct.Keys) == 0 {
				p.none("No keys.")
			}
			for _, k := range ct.Keys {
				p.row(keyRef{ct.Name, k}, k.Type, svops.GroupFingerprint(k.Fingerprint), svops.LevelText(k.Level), k.State)
			}
			p.done()
		})
	}
	isKey := is[keyRef]
	p.enter = func(ref any) { u.showContactKey(ref.(keyRef)) }
	p.rowAct('i', "All about it", isKey, p.enter)
	p.rowAct('v', "Verify it…", isKey, func(ref any) {
		k := ref.(keyRef)
		u.verifyContact(id, k.key.Fingerprint, func() {
			p.refresh()
			if then != nil {
				then()
			}
		})
	})
	p.rowAct('x', "Remove this key…", isKey, func(ref any) {
		k := ref.(keyRef)
		u.removeContact(id, ct.Name, k.key.Fingerprint, func() {
			p.refresh()
			if then != nil {
				then()
			}
		})
	})
	p.act('V', "Verify a key by its fingerprint…", func() {
		u.verifyContact(id, "", func() {
			p.refresh()
			if then != nil {
				then()
			}
		})
	})
	p.show()
}

// showContactKey is one key of 'secretvault contact show'.
func (u *UI) showContactKey(k keyRef) {
	var b strings.Builder
	fmt.Fprintf(&b, "[::b]%s's %s key[::-]\n%s\n\n", tview.Escape(k.contact), k.key.Type, svops.GroupFingerprint(k.key.Fingerprint))
	if k.key.Label != "" {
		fmt.Fprintf(&b, "label:     %s\n", tview.Escape(k.key.Label))
	}
	if len(k.key.Addresses) > 0 {
		fmt.Fprintf(&b, "addresses: %s\n", tview.Escape(strings.Join(k.key.Addresses, ", ")))
	}
	fmt.Fprintf(&b, "level:     %s\n", tview.Escape(svops.LevelText(k.key.Level)))
	if k.key.State != "" {
		fmt.Fprintf(&b, "state:     %s\n", tview.Escape(k.key.State))
	}
	added := k.key.Added.Local().Format("2006-01-02")
	if k.key.Source != "" {
		added += ", from " + k.key.Source
	}
	fmt.Fprintf(&b, "added:     %s\n", tview.Escape(added))
	for _, v := range k.key.Verifications {
		fmt.Fprintf(&b, "verified:  %s\n", tview.Escape(v.Description))
	}
	for _, s := range k.key.Seen {
		times := fmt.Sprintf("%d times", s.Count)
		switch s.Count {
		case 1:
			times = "once"
		case 2:
			times = "twice"
		}
		fmt.Fprintf(&b, "seen:      %s from %s, %s to %s\n", times, tview.Escape(s.Address), s.First.Local().Format("2006-01-02"), s.Last.Local().Format("2006-01-02"))
	}
	u.showText("Key", b.String())
}

// readFiles reads the files named one per line, as the CLI reads FILE...
func readFiles(text string) ([][]byte, []string, error) {
	var out [][]byte
	var names []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		b, err := os.ReadFile(expandHome(line))
		if err != nil {
			return nil, nil, err
		}
		out = append(out, b)
		names = append(names, line)
	}
	return out, names, nil
}

// splitList splits a comma-separated list.
func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// addContact is 'secretvault contact add FILE...'.
func (u *UI) addContact(then func()) {
	f := u.newForm("Add a contact", svops.AddContactLead+" Verify it afterwards, by comparing its fingerprint with them.")
	files := f.area("Key files", "", 3)
	files.SetPlaceholder("one path per line")
	name := f.text("Name", "", "empty: take it from the key")
	emails := f.text("Emails", "", "comma-separated (optional)")
	notes := f.text("Notes", "", "how you know them (optional)")
	org := f.check("An organisation: certificates its CA issues count as vouched for by it", false)
	f.show("Add the contact", func() string {
		keys, names, err := readFiles(files.GetText())
		if err != nil {
			return err.Error()
		}
		p := svrpc.ContactAddParams{Name: trimmed(name), Emails: splitList(trimmed(emails)), Notes: trimmed(notes), Organisation: org.IsChecked(), Keys: keys}
		if len(keys) == 0 && p.Name == "" {
			return "Give a key file, or at least a name."
		}
		if len(names) > 0 {
			p.Source = "file " + strings.Join(names, ", ")
		}
		var ch svrpc.ContactChange
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			ch, err = c.AddContact(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Added %s with %d key(s).\n", tview.Escape(ch.Contact.Name), len(ch.Contact.Keys))
			for _, k := range ch.Contact.Keys {
				fmt.Fprintf(&b, "  %s %s\n", k.Type, svops.GroupFingerprint(k.Fingerprint))
			}
			for _, w := range ch.Warnings {
				fmt.Fprintf(&b, "\n[yellow]warning:[-] %s", tview.Escape(w))
			}
			if len(ch.Contact.Keys) > 0 {
				b.WriteString("\n\nIt is not verified yet: compare the fingerprint with them, then verify the key (Enter on the contact, then v).")
			}
			u.say("Added %s", ch.Contact.Name)
			if then != nil {
				then()
			}
			u.showText("Contact added", b.String())
		})
		return ""
	})
}

// importContacts is 'secretvault contact import FILE|URI'.
func (u *UI) importContacts(then func()) {
	f := u.newForm("Import keys", svops.ImportContactsLead+" A scanned code is pasted as its text, which starts secretvault-contact: or openpgp4fpr:.")
	what := f.path("File or scanned code", "", "")
	to := f.text("Into the contact", "", "(optional: else new contacts)")
	name := f.text("Name new contacts", "", "(optional)")
	fetch := f.check("Download the OpenPGP keys a code names that you do not have", false)
	keyserver := f.text("Keyserver", "", "empty: keys.openpgp.org")
	f.show("Import", func() string {
		arg := trimmed(what)
		if arg == "" {
			return "Give a file, or the scanned code."
		}
		p := svrpc.ContactImportParams{Contact: trimmed(to), Name: trimmed(name), Fetch: fetch.IsChecked(), Keyserver: trimmed(keyserver)}
		if svops.IsContactURI(arg) {
			p.URI = arg
		} else {
			b, err := os.ReadFile(expandHome(arg))
			if err != nil {
				return err.Error()
			}
			p.Data, p.Source = b, "file "+arg
		}
		var res svrpc.ContactImportResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.ImportContacts(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			var b strings.Builder
			for _, k := range res.Keys {
				w := "Updated"
				switch {
				case k.Verified:
					w = "Verified in person"
				case k.New:
					w = "Added"
				}
				fmt.Fprintf(&b, "%s: %s %s (%s)\n", w, k.Type, svops.GroupFingerprint(k.Fingerprint), tview.Escape(k.Contact))
				for _, x := range k.Warnings {
					fmt.Fprintf(&b, "  [yellow]warning:[-] %s\n", tview.Escape(x))
				}
			}
			for _, m := range res.Missing {
				typ, fp, _ := strings.Cut(m, ":")
				fmt.Fprintf(&b, "Not found: %s %s (add the key, or tick Fetch, then import the code again)\n", typ, svops.GroupFingerprint(fp))
			}
			for _, x := range res.Warnings {
				fmt.Fprintf(&b, "[yellow]warning:[-] %s\n", tview.Escape(x))
			}
			if len(res.Keys) == 0 {
				b.WriteString("[red]Nothing was imported.[-]")
				u.say("Nothing was imported")
			} else {
				u.say("Imported %d key(s)", len(res.Keys))
			}
			if then != nil {
				then()
			}
			u.showText("Contacts imported", b.String())
		})
		return ""
	})
}

// removeContact is 'secretvault contact rm NAME [--fingerprint FPR]'.
func (u *UI) removeContact(id, name, fp string, then func()) {
	title, action := "Remove "+name+"?", "Remove the contact"
	text := fmt.Sprintf("%s and all their keys leave your contacts, and how you verified them is forgotten. Vaults you share with them stay shared.", name)
	if fp != "" {
		title, action = "Remove a key of "+name+"?", "Remove the key"
		text = fmt.Sprintf("The key %s leaves %s's contact, and how you verified it is forgotten.", svops.GroupFingerprint(fp), name)
	}
	u.confirm(title, text, action, func() {
		var ct svrpc.Contact
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			ct, err = c.RemoveContact(ctx, "", id, fp)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if fp != "" {
				u.say("Removed key %s from %s", svops.GroupFingerprint(svtrust.NormalizeFingerprint(fp)), ct.Name)
			} else {
				u.say("Removed %s", ct.Name)
				if sub := u.panels[pageSub]; sub != nil && sub.title == "Contact" {
					sub.close()
				}
			}
			if then != nil {
				then()
			}
		})
	})
}

// verifyContact is 'secretvault contact verify NAME --fingerprint FPR'.
func (u *UI) verifyContact(id, fp string, then func()) {
	f := u.newForm("Verify a key", svops.VerifyLead+" Give the fingerprint as you compared it, and how.")
	fpr := f.text("Fingerprint", svops.GroupFingerprint(fp), "")
	var labels []string
	for _, m := range svops.VerifyWays {
		labels = append(labels, m.Text)
	}
	how := f.choice("How", labels, 0)
	org := f.text("Organisation", "", "(if an organisation vouches for it: which)")
	emails := f.text("Only for", "", "addresses, comma-separated (default: the key's own)")
	note := f.text("Note", "", "where or how, in your words (optional)")
	f.show("Mark as verified", func() string {
		i, _ := how.GetCurrentOption()
		p := svrpc.ContactVerifyParams{Ref: id, Fingerprint: strings.ReplaceAll(trimmed(fpr), " ", ""), Method: svops.VerifyWays[i].Method, Source: trimmed(note), Addresses: splitList(trimmed(emails))}
		if p.Fingerprint == "" {
			return "Give the fingerprint you compared."
		}
		if p.Method == svrpc.VerifyOrgDirectory {
			if p.Source = trimmed(org); p.Source == "" {
				return "Name the organisation."
			}
		}
		var ct svrpc.Contact
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			ct, err = c.VerifyContact(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			want := svtrust.NormalizeFingerprint(p.Fingerprint)
			u.say("Recorded for %s", ct.Name)
			for _, k := range ct.Keys {
				if k.Fingerprint == want || strings.HasSuffix(k.Fingerprint, want) {
					u.say("%s's %s key %s: %s", ct.Name, k.Type, svops.GroupFingerprint(k.Fingerprint), svops.LevelText(k.Level))
				}
			}
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// lookupContact is 'secretvault contact lookup ADDRESS|FPR'.
func (u *UI) lookupContact(then func()) {
	f := u.newForm("Look up keys", svops.LookupLead)
	query := f.text("Address or fingerprint", "", "ada@example.org")
	where := f.choice("Ask", []string{"everywhere", "the email provider's key directory (WKD) only", "one keyserver only", "one directory only"}, 0)
	keyserver := f.text("Keyserver or directory", "", "hkps://keys.example.org, or a directory's name")
	add := f.check("Add what is found to the contacts, not verified", false)
	name := f.text("Name new contacts", "", "(optional)")
	f.show("Look up", func() string {
		p := svrpc.ContactLookupParams{Query: trimmed(query), Add: add.IsChecked(), Name: trimmed(name)}
		if p.Query == "" {
			return "Give an address or a fingerprint."
		}
		switch i, _ := where.GetCurrentOption(); i {
		case 1:
			p.WKD = true
		case 2:
			if p.Keyserver = trimmed(keyserver); p.Keyserver == "" {
				return "Give the keyserver."
			}
		case 3:
			if p.Directory = trimmed(keyserver); p.Directory == "" {
				return "Name the directory."
			}
		}
		var res svrpc.ContactLookupResult
		u.say("Looking %s up…", p.Query)
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.LookupContact(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			var b strings.Builder
			for _, fd := range res.Found {
				fmt.Fprintf(&b, "[::b]From %s[::-]\n", tview.Escape(fd.URL))
				if len(fd.Policy) > 0 {
					fmt.Fprintf(&b, "  policy: %s\n", tview.Escape(strings.Join(fd.Policy, "; ")))
				}
				for i, k := range fd.Keys {
					known := ""
					if i < len(fd.Known) && fd.Known[i] != "" {
						known = " (you have it: " + fd.Known[i] + ")"
					}
					fmt.Fprintf(&b, "  %s %s  %s%s\n", k.Type, svops.GroupFingerprint(k.Fingerprint), tview.Escape(k.Label), tview.Escape(known))
					if len(k.Addresses) > 0 {
						fmt.Fprintf(&b, "    for %s: %s\n", tview.Escape(strings.Join(k.Addresses, ", ")), tview.Escape(svops.LevelText(k.Level)))
					}
				}
			}
			for _, e := range res.Errors {
				fmt.Fprintf(&b, "[gray]note: %s[-]\n", tview.Escape(e))
			}
			for _, k := range res.Added {
				w := "Updated"
				if k.New {
					w = "Added"
				}
				fmt.Fprintf(&b, "%s: %s %s (%s)\n", w, k.Type, svops.GroupFingerprint(k.Fingerprint), tview.Escape(k.Contact))
				for _, x := range k.Warnings {
					fmt.Fprintf(&b, "  [yellow]warning:[-] %s\n", tview.Escape(x))
				}
			}
			if len(res.Found) == 0 {
				b.WriteString("Nothing was found.")
			} else {
				b.WriteString("\nNone of it is verified until you compare its fingerprint with them.")
			}
			u.say("Looked %s up", p.Query)
			if then != nil && len(res.Added) > 0 {
				then()
			}
			u.showText("Look up "+p.Query, b.String())
		})
		return ""
	})
}

// showMyCard is 'secretvault contact qr': your keys as a QR code, for
// someone to scan (svops.OwnCard, svtrust.Card.URI, svqr).
func (u *UI) showMyCard() {
	f := u.newForm("My QR code", svops.MyCodeLead+" Every OpenPGP key in the vault is shown, unless you name key items.")
	items := f.text("Key items", "", "comma-separated (default: every OpenPGP key)")
	recipients := f.text("Recipients", "", "your public keys for sharing vaults, or identity files (optional)")
	name := f.text("Your name", "", "default: from your first OpenPGP key")
	emails := f.text("Your addresses", "", "comma-separated (default: your first OpenPGP key's)")
	vault := u.vault
	f.show("Show the code", func() string {
		its, rs := splitList(trimmed(items)), splitList(trimmed(recipients))
		for i := range rs {
			rs[i] = expandHome(rs[i])
		}
		n, es := trimmed(name), splitList(trimmed(emails))
		var card *svtrust.Card
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			card, err = svops.OwnCard(ctx, c, vault, its, rs)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			if n != "" {
				card.Name = n
			}
			if len(es) > 0 {
				card.Emails = es
			}
			uri := card.URI()
			code, err := svqr.Encode([]byte(uri), svqr.M)
			if err != nil {
				u.fail(err)
				return
			}
			u.showCode("My QR code", []onceLine{
				{text: "For them to scan from your screen: it adds and verifies your keys for them, and holds no secret."},
				{secret: []byte(uri)},
			}, code)
		})
		return ""
	})
}

// chooseContactsVault is 'secretvault contact vault [VAULT|-]'.
func (u *UI) chooseContactsVault(then func()) {
	var names []string
	for _, v := range u.vaults {
		names = append(names, v.Name)
	}
	vaults := len(names)
	u.choose("Keep contacts in", append(names, "the default vault, whichever it is"), func(i int) {
		set := "-"
		if i < vaults {
			set = names[i]
		}
		var name string
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			name, err = c.ContactsVault(ctx, set)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			u.say("Contacts are kept in vault %s now", name)
			if then != nil {
				then()
			}
		})
	})
}

// checkSigner is 'secretvault trust check'.
func (u *UI) checkSigner() {
	f := u.newForm("Check a signer", svops.CheckSignerLead)
	fp := f.text("Fingerprint", "", "or a key file below")
	keyFile := f.path("Key file", "", "")
	from := f.text("From", "", "the message's sender (optional)")
	var levels []string
	for _, l := range svops.TrustLevels {
		levels = append(levels, l.Text)
	}
	minLevel := f.choice("Counts if at least", levels, 0)
	f.show("Check", func() string {
		p := svrpc.TrustCheckParams{Fingerprint: strings.ReplaceAll(trimmed(fp), " ", ""), From: trimmed(from)}
		if i, _ := minLevel.GetCurrentOption(); i > 0 {
			p.MinLevel = svops.TrustLevels[i].Level
		}
		kf := filePath(keyFile)
		if (p.Fingerprint == "") == (kf == "") {
			return "Give the fingerprint, or a key file: one of them."
		}
		if kf != "" {
			b, err := os.ReadFile(kf)
			if err != nil {
				return err.Error()
			}
			p.Key = b
		}
		var v svrpc.Verdict
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			v, err = c.CheckSigner(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			colour := "red"
			if v.Trusted {
				colour = "green"
			}
			var b strings.Builder
			fmt.Fprintf(&b, "[%s::b]%s[-::-]\n", colour, tview.Escape(v.Status))
			for _, r := range v.Reasons {
				fmt.Fprintf(&b, "  %s\n", tview.Escape(r))
			}
			u.showText("Signer", b.String())
		})
		return ""
	})
}

// keySeen is 'secretvault trust seen'.
func (u *UI) keySeen(then func()) {
	f := u.newForm("Record a key seen in mail", svops.KeySeenLead)
	keyFile := f.path("Key file", "", "")
	from := f.text("From", "", "the sender's address")
	at := f.text("Received", "", "YYYY-MM-DD (empty: now)")
	source := f.text("What it was", "", "default: mail from ADDRESS on DATE")
	name := f.text("Sender's name", "", "for a new contact (optional)")
	f.show("Record", func() string {
		kf, addr := filePath(keyFile), trimmed(from)
		if kf == "" || addr == "" {
			return "Give the key file and the address it came from."
		}
		b, err := os.ReadFile(kf)
		if err != nil {
			return err.Error()
		}
		p := svrpc.TrustSeenParams{Key: b, Address: addr, Source: trimmed(source), Name: trimmed(name)}
		if s := trimmed(at); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				if t, err = time.ParseInLocation("2006-01-02", s, time.Local); err != nil {
					return fmt.Sprintf("%q is not a date: give it as YYYY-MM-DD, or leave it empty.", s)
				}
			}
			p.Time = t
		}
		var res svrpc.SeenResult
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = c.KeySeen(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			w := "Seen again"
			if res.New {
				w = "New key"
			}
			u.say("%s: %s from %s (%s)", w, svops.GroupFingerprint(res.Fingerprint), svtrust.ParseAddress(addr), res.Contact.Name)
			if len(res.Warnings) > 0 {
				u.showText("Key seen", "[yellow]warning:[-] "+tview.Escape(strings.Join(res.Warnings, "\nwarning: ")))
			}
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// showDirectories is 'secretvault contact directory ls', with adding and
// removing one.
func (u *UI) showDirectories() {
	p := u.newPanel("Directories", "NAME", "URL", "BASE", "BIND")
	p.page = pageSub
	p.setHead(svops.DirectoriesAbout)
	p.reload = func() {
		var dirs []svrpc.DirectoryConfig
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			dirs, err = c.Directories(ctx)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			if len(dirs) == 0 {
				p.none("None (a adds one).")
			}
			for _, d := range dirs {
				bind := "anonymous"
				if d.BindDN != "" {
					bind = d.BindDN
				}
				p.row(d, d.Name, d.URL, d.BaseDN, bind)
			}
			p.done()
		})
	}
	p.act('a', "Add…", func() {
		f := u.newForm("Add a directory", svops.DirectoriesAbout+" "+svops.DirectoryPasswordNote)
		name := f.text("Name", "", "what to call it: example")
		url := f.text("URL", "", "ldaps://HOST or ldap://HOST (StartTLS)")
		base := f.text("Base DN", "", "where its people are: dc=example,dc=com")
		bind := f.text("Bind DN", "", "the account to sign in as (default: anonymously)")
		password := f.text("Password item", "", "the vault item that holds it: sv://VAULT/ITEM[#FIELD]")
		ca := f.path("CA file", "", "PEM, for a private CA (optional)")
		f.show("Add the directory", func() string {
			d := svrpc.DirectoryConfig{Name: trimmed(name), URL: trimmed(url), BaseDN: trimmed(base), BindDN: trimmed(bind), Password: trimmed(password), CAFile: filePath(ca)}
			if d.Name == "" || d.URL == "" {
				return "Give the directory a name, and its URL."
			}
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.AddDirectory(ctx, d)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Lookups of an address now ask %s first", d.Name)
				p.refresh()
			})
			return ""
		})
	})
	p.rowAct('x', "Remove it…", is[svrpc.DirectoryConfig], func(ref any) {
		d := ref.(svrpc.DirectoryConfig)
		rm := svops.RemoveDirectoryPlain(d.Name)
		u.confirm(rm.Title, rm.Summary, rm.Action, func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return c.RemoveDirectory(ctx, d.Name)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("Removed directory %s", d.Name)
				p.refresh()
			})
		})
	})
	p.show()
}
