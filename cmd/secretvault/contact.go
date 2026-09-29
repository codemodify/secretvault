package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svqr"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Contacts and the trust store:
//
//	secretvault contact ls [QUERY]
//	secretvault contact show NAME
//	secretvault contact add FILE... [--name N] [--email E]... [--notes TEXT] [--org]
//	secretvault contact import FILE|URI [--to NAME] [--name N] [--fetch] [--keyserver URL]
//	secretvault contact rm NAME [--fingerprint FPR]
//	secretvault contact verify [NAME] --fingerprint FPR --in-person|--qr|--org ORG|--tofu [--email E]... [--note TEXT]
//	secretvault contact lookup ADDRESS|FPR [--wkd] [--keyserver URL] [--add] [--name N]
//	secretvault contact qr [--key ITEM]... [--recipient R|FILE]... [--name N] [--email E]... [--uri] [--light]
//	secretvault contact vault [VAULT|-]
//	secretvault trust check --fingerprint FPR|--key FILE [--from ADDRESS] [--min-level LEVEL] [--json]
//	secretvault trust seen --key FILE --from ADDRESS [--at TIME] [--source TEXT] [--name N]
//
// NAME is a contact's name, one of its addresses, one of its keys'
// fingerprints, or its ID. Contacts live in the contacts vault (see
// 'contact vault'), or the vault --vault names. A URI given to import is
// taken as scanned from the person's screen, in person: it verifies the
// keys it names. 'trust check' exits 0 when the signer is verified, 3
// when it is not.

func (c *cli) cmdContact(args []string) error {
	usage := func() error {
		fmt.Fprintln(c.stderr, "usage: secretvault contact ls|show|add|import|rm|verify|lookup|qr|vault [flags] [args]")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "  ls [QUERY]                        list contacts")
		fmt.Fprintln(c.stderr, "  show NAME                         a contact, its keys, and how each was verified")
		fmt.Fprintln(c.stderr, "  add FILE...                       a new contact with the keys in FILE (OpenPGP, certificates, SSH, recipients)")
		fmt.Fprintln(c.stderr, "  import FILE|URI                   add many keys, or record a QR code you scanned (secretvault-contact:, openpgp4fpr:)")
		fmt.Fprintln(c.stderr, "  rm NAME [--fingerprint FPR]       remove a contact, or one of its keys")
		fmt.Fprintln(c.stderr, "  verify [NAME] --fingerprint FPR --in-person|--qr|--org ORG|--tofu")
		fmt.Fprintln(c.stderr, "  lookup ADDRESS|FPR                find keys by WKD or a keyserver (--add to keep them)")
		fmt.Fprintln(c.stderr, "  qr                                show your keys as a QR code for someone to scan")
		fmt.Fprintln(c.stderr, "  vault [VAULT|-]                   show, or choose, the vault contacts live in")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "NAME is a contact's name, address, key fingerprint or ID.")
		return errUsage
	}
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "ls", "list":
		return c.contactList(args[1:])
	case "show":
		return c.contactShow(args[1:])
	case "add":
		return c.contactAdd(args[1:])
	case "import":
		return c.contactImport(args[1:])
	case "rm", "remove":
		return c.contactRemove(args[1:])
	case "verify":
		return c.contactVerify(args[1:])
	case "lookup":
		return c.contactLookup(args[1:])
	case "qr":
		return c.contactQR(args[1:])
	case "vault":
		return c.contactVault(args[1:])
	case "directory":
		return c.contactDirectory(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault contact: unknown subcommand %q\n", args[0])
	return usage()
}

// levelText says a verification level in words.
func levelText(l string) string {
	if l == "" {
		return "not verified"
	}
	return svtrust.Level(l).String()
}

// groupFP writes a hex fingerprint in groups of four, as people compare
// them; other fingerprints as they are.
func groupFP(fp string) string {
	if strings.HasPrefix(fp, "SHA256:") || len(fp)%4 != 0 {
		return fp
	}
	var groups []string
	for i := 0; i < len(fp); i += 4 {
		groups = append(groups, fp[i:i+4])
	}
	return strings.Join(groups, " ")
}

func day(t time.Time) string { return t.Local().Format("2006-01-02") }

func (c *cli) contactList(args []string) error {
	fs := c.flags("contact ls")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[QUERY]")
	if err != nil {
		return err
	}
	query := ""
	if len(pos) == 1 {
		query = pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	cs, err := cl.Contacts(ctx, c.vault, query)
	if err != nil {
		return err
	}
	if len(cs) == 0 {
		fmt.Fprintln(c.stdout, "No contacts.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tEMAILS\tKEYS\tVERIFIED")
	for _, ct := range cs {
		var types []string
		for _, k := range ct.Keys {
			types = append(types, k.Type)
		}
		name := ct.Name
		if ct.Origin == svtrust.OriginMail || ct.Origin == svtrust.OriginLookup {
			name += " (from " + ct.Origin + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, strings.Join(ct.Emails, ", "), strings.Join(types, ", "), levelText(ct.Level))
	}
	return tw.Flush()
}

func (c *cli) contactShow(args []string) error {
	fs := c.flags("contact show")
	asJSON := fs.Bool("json", false, "print the contact as JSON")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--json]")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	ct, err := cl.Contact(ctx, c.vault, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ct)
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, ct.Name)
	fmt.Fprintf(tw, "  id\t%s\n", ct.ID)
	if len(ct.Emails) > 0 {
		fmt.Fprintf(tw, "  emails\t%s\n", strings.Join(ct.Emails, ", "))
	}
	if ct.Organisation {
		fmt.Fprintf(tw, "  organisation\tyes: its CA certificates vouch for those they issue\n")
	}
	if ct.Notes != "" {
		fmt.Fprintf(tw, "  notes\t%s\n", ct.Notes)
	}
	fmt.Fprintf(tw, "  origin\t%s, %s\n", ct.Origin, day(ct.Created))
	for _, k := range ct.Keys {
		fmt.Fprintf(tw, "\n%s key %s\n", k.Type, groupFP(k.Fingerprint))
		if k.Label != "" {
			fmt.Fprintf(tw, "  label\t%s\n", k.Label)
		}
		if len(k.Addresses) > 0 {
			fmt.Fprintf(tw, "  addresses\t%s\n", strings.Join(k.Addresses, ", "))
		}
		fmt.Fprintf(tw, "  level\t%s\n", levelText(k.Level))
		if k.State != "" {
			fmt.Fprintf(tw, "  state\t%s\n", k.State)
		}
		added := day(k.Added)
		if k.Source != "" {
			added += ", from " + k.Source
		}
		fmt.Fprintf(tw, "  added\t%s\n", added)
		for _, v := range k.Verifications {
			fmt.Fprintf(tw, "  verified\t%s\n", v.Description)
		}
		for _, s := range k.Seen {
			fmt.Fprintf(tw, "  seen\t%s from %s, %s to %s\n", timesText(s.Count), s.Address, day(s.First), day(s.Last))
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, w := range ct.Warnings {
		fmt.Fprintln(c.stdout, "\nwarning:", w)
	}
	return nil
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

// readArg reads a file, or stdin for "-".
func (c *cli) readArg(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(c.stdin)
	}
	return os.ReadFile(path)
}

func (c *cli) contactAdd(args []string) error {
	fs := c.flags("contact add")
	name := fs.String("name", "", "the contact's name (default: from the first key)")
	var emails multi
	fs.Var(&emails, "email", "an address of the contact (repeatable)")
	notes := fs.String("notes", "", "notes about the contact")
	org := fs.Bool("org", false, "an organisation: its CA certificates vouch for the certificates they issue")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, -1, "FILE... [--name N] [--email E]... [--notes TEXT] [--org]")
	if err != nil {
		return err
	}
	if len(pos) == 0 && *name == "" {
		fmt.Fprintln(c.stderr, "usage: secretvault contact add FILE... [--name N] [--email E]... [--notes TEXT] [--org]")
		return errUsage
	}
	p := svrpc.ContactAddParams{Vault: c.vault, Name: *name, Emails: emails, Notes: *notes, Organisation: *org}
	for _, f := range pos {
		data, err := c.readArg(f)
		if err != nil {
			return err
		}
		p.Keys = append(p.Keys, data)
	}
	if len(pos) > 0 {
		p.Source = "file " + strings.Join(pos, ", ")
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	ch, err := cl.AddContact(ctx, p)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Added %s with %d key(s).\n", ch.Contact.Name, len(ch.Contact.Keys))
	for _, k := range ch.Contact.Keys {
		fmt.Fprintf(c.stdout, "  %s %s\n", k.Type, groupFP(k.Fingerprint))
	}
	c.warn(ch.Warnings)
	if len(ch.Contact.Keys) > 0 {
		fmt.Fprintf(c.stdout, "Compare fingerprints with them, then: secretvault contact verify %q --fingerprint FPR --in-person\n", ch.Contact.Name)
	}
	return nil
}

func (c *cli) warn(ws []string) {
	for _, w := range ws {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
}

// isContactURI reports whether an argument is a URI a QR code shows.
func isContactURI(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, svtrust.ContactScheme+":") || strings.HasPrefix(l, "openpgp4fpr:")
}

func (c *cli) contactImport(args []string) error {
	fs := c.flags("contact import")
	to := fs.String("to", "", "put new keys in this contact")
	name := fs.String("name", "", "the name for new contacts")
	fetch := fs.Bool("fetch", false, "for a URI: fetch the OpenPGP keys it names that you do not have, from the keyserver")
	keyserver := fs.String("keyserver", "", "the keyserver --fetch uses (default: keys.openpgp.org)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE|URI [--to NAME] [--name N] [--fetch] [--keyserver URL]")
	if err != nil {
		return err
	}
	p := svrpc.ContactImportParams{Vault: c.vault, Contact: *to, Name: *name, Fetch: *fetch, Keyserver: *keyserver}
	if isContactURI(pos[0]) {
		p.URI = pos[0]
	} else {
		if p.Data, err = c.readArg(pos[0]); err != nil {
			return err
		}
		p.Source = "file " + pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.ImportContacts(ctx, p)
	if err != nil {
		return err
	}
	for _, k := range res.Keys {
		what := "Updated"
		switch {
		case k.Verified:
			what = "Verified in person"
		case k.New:
			what = "Added"
		}
		fmt.Fprintf(c.stdout, "%s: %s %s (%s)\n", what, k.Type, groupFP(k.Fingerprint), k.Contact)
		c.warn(k.Warnings)
	}
	for _, m := range res.Missing {
		typ, fp, _ := strings.Cut(m, ":")
		fmt.Fprintf(c.stdout, "Not found: %s %s (add the key, or use --fetch, then scan again)\n", typ, groupFP(fp))
	}
	c.warn(res.Warnings)
	if len(res.Keys) == 0 {
		return errors.New("nothing was imported")
	}
	return nil
}

func (c *cli) contactRemove(args []string) error {
	fs := c.flags("contact rm")
	fp := fs.String("fingerprint", "", "remove only this key")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--fingerprint FPR]")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	ct, err := cl.RemoveContact(ctx, c.vault, pos[0], *fp)
	if err != nil {
		return err
	}
	if *fp != "" {
		fmt.Fprintf(c.stdout, "Removed key %s from %s.\n", groupFP(svtrust.NormalizeFingerprint(*fp)), ct.Name)
	} else {
		fmt.Fprintf(c.stdout, "Removed %s.\n", ct.Name)
	}
	return nil
}

func (c *cli) contactVerify(args []string) error {
	fs := c.flags("contact verify")
	fp := fs.String("fingerprint", "", "the key's fingerprint, as you compared it (required)")
	inPerson := fs.Bool("in-person", false, "you compared the fingerprint with them, face to face")
	qr := fs.Bool("qr", false, "you scanned their QR code, and it showed this fingerprint")
	org := fs.String("org", "", "the organisation `ORG` vouches for the key (its directory, or its people)")
	tofu := fs.Bool("tofu", false, "accept the key as it is, without verifying it")
	var emails multi
	fs.Var(&emails, "email", "the verification covers only this address (repeatable; default: the key's own)")
	note := fs.String("note", "", "where or how, in your words")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[NAME] --fingerprint FPR --in-person|--qr|--org ORG|--tofu")
	if err != nil {
		return err
	}
	var methods []string
	source := *note
	if *inPerson {
		methods = append(methods, svrpc.VerifyFingerprint)
	}
	if *qr {
		methods = append(methods, svrpc.VerifyQR)
	}
	if *org != "" {
		methods = append(methods, svrpc.VerifyOrgDirectory)
		source = *org
	}
	if *tofu {
		methods = append(methods, svrpc.VerifyTOFU)
	}
	if *fp == "" || len(methods) != 1 {
		fmt.Fprintln(c.stderr, "usage: secretvault contact verify [NAME] --fingerprint FPR --in-person|--qr|--org ORG|--tofu")
		fmt.Fprintln(c.stderr, "Give the fingerprint you compared, and one way you verified it.")
		return errUsage
	}
	p := svrpc.ContactVerifyParams{Vault: c.vault, Fingerprint: *fp, Method: methods[0], Source: source, Addresses: emails}
	if len(pos) == 1 {
		p.Ref = pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	ct, err := cl.VerifyContact(ctx, p)
	if err != nil {
		return err
	}
	for _, k := range ct.Keys {
		if k.Fingerprint == svtrust.NormalizeFingerprint(*fp) || strings.HasSuffix(k.Fingerprint, svtrust.NormalizeFingerprint(*fp)) {
			fmt.Fprintf(c.stdout, "%s's %s key %s: %s.\n", ct.Name, k.Type, groupFP(k.Fingerprint), levelText(k.Level))
			return nil
		}
	}
	fmt.Fprintf(c.stdout, "Recorded for %s.\n", ct.Name)
	return nil
}

func (c *cli) contactLookup(args []string) error {
	fs := c.flags("contact lookup")
	wkd := fs.Bool("wkd", false, "ask only the address's Web Key Directory")
	keyserver := fs.String("keyserver", "", "ask only this keyserver (https://, hkps:// or hkp://)")
	directory := fs.String("directory", "", "ask only this organisation directory ('contact directory ls')")
	add := fs.Bool("add", false, "keep what is found, as contacts")
	name := fs.String("name", "", "the name for new contacts (with --add)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "ADDRESS|FPR [--wkd] [--keyserver URL] [--directory NAME] [--add] [--name N]")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.LookupContact(ctx, svrpc.ContactLookupParams{Vault: c.vault, Query: pos[0], WKD: *wkd, Keyserver: *keyserver, Directory: *directory, Add: *add, Name: *name})
	if err != nil {
		return err
	}
	for _, f := range res.Found {
		fmt.Fprintf(c.stdout, "From %s\n", f.URL)
		if len(f.Policy) > 0 {
			fmt.Fprintf(c.stdout, "  policy: %s\n", strings.Join(f.Policy, "; "))
		}
		for i, k := range f.Keys {
			known := ""
			if i < len(f.Known) && f.Known[i] != "" {
				known = " (you have it: " + f.Known[i] + ")"
			}
			fmt.Fprintf(c.stdout, "  %s %s  %s%s\n", k.Type, groupFP(k.Fingerprint), k.Label, known)
			if len(k.Addresses) > 0 {
				fmt.Fprintf(c.stdout, "    for %s: %s\n", strings.Join(k.Addresses, ", "), levelText(k.Level))
			}
		}
	}
	for _, e := range res.Errors {
		fmt.Fprintln(c.stderr, "note:", e)
	}
	for _, k := range res.Added {
		what := "Updated"
		if k.New {
			what = "Added"
		}
		fmt.Fprintf(c.stdout, "%s: %s %s (%s)\n", what, k.Type, groupFP(k.Fingerprint), k.Contact)
		c.warn(k.Warnings)
	}
	return nil
}

// contactQR shows your own keys as a secretvault-contact URI, in a QR
// code, for someone to scan.
func (c *cli) contactQR(args []string) error {
	fs := c.flags("contact qr")
	var items, recipients, emails multi
	fs.Var(&items, "key", "show this key item: an OpenPGP key or an SSH key (repeatable; default: every OpenPGP key)")
	fs.Var(&recipients, "recipient", "show this secretvault recipient, or an identity file's (repeatable)")
	name := fs.String("name", "", "your name (default: from your first OpenPGP key)")
	fs.Var(&emails, "email", "your address (repeatable; default: your first OpenPGP key's)")
	onlyURI := fs.Bool("uri", false, "print only the URI")
	light := fs.Bool("light", false, "draw without colours, for a terminal with dark text on a light background")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--key ITEM]... [--recipient R|FILE]... [--name N] [--email E]... [--uri]"); err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	card, err := c.ownCard(ctx, cl, items, recipients)
	if err != nil {
		return err
	}
	if *name != "" {
		card.Name = *name
	}
	if len(emails) > 0 {
		card.Emails = emails
	}
	uri := card.URI()
	if *onlyURI {
		fmt.Fprintln(c.stdout, uri)
		return nil
	}
	if err := c.printQR(uri, *light); err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, uri)
	return nil
}

// printQR draws text as a QR code on the terminal: black on white where
// the terminal takes colours; else light modules drawn, for the usual
// light text on a dark background (light: dark modules, for a light one).
func (c *cli) printQR(text string, light bool) error {
	code, err := svqr.Encode([]byte(text), svqr.M)
	if err != nil {
		return err
	}
	opts := svqr.TerminalOptions{Quiet: 2, Invert: !light}
	if f, ok := c.stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) && !light {
		opts.Colour = true
	}
	fmt.Fprint(c.stdout, code.Terminal(opts))
	return nil
}

// ownCard gathers the fingerprints of your keys for a QR code.
func (c *cli) ownCard(ctx context.Context, cl *secretvault.Client, items, recipients []string) (*svtrust.Card, error) {
	entries, err := cl.List(ctx, c.vault, "")
	if err != nil {
		return nil, err
	}
	card := &svtrust.Card{}
	firstUID := ""
	addPGP := func(it svrpc.Item) {
		card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.OpenPGP, Fingerprint: it.Attrs[svrpc.PGPFingerprint]})
		if firstUID == "" {
			firstUID = it.Attrs[svrpc.PGPUserID]
		}
	}
	for _, want := range items {
		var found *svrpc.Item
		for i := range entries {
			if entries[i].Item.Name == want {
				found = &entries[i].Item
			}
		}
		switch {
		case found == nil:
			return nil, fmt.Errorf("%s: %w", want, svrpc.ErrNotFound)
		case found.Attrs[svrpc.PGPFingerprint] != "":
			addPGP(*found)
		case found.Kind == "ssh-key":
			fp := found.Attrs["fingerprint"]
			if fp == "" {
				e, err := cl.Get(ctx, c.vault, want)
				if err != nil {
					return nil, err
				}
				if f, ok := field(&e.Item, "public_key"); ok {
					if k, err := svtrust.ParseKey(f.Value); err == nil {
						fp = k.Fingerprint
					}
				}
				wipe(&e.Item)
			}
			if fp == "" {
				return nil, fmt.Errorf("%s has no public key to show", want)
			}
			card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.SSH, Fingerprint: fp})
		default:
			return nil, fmt.Errorf("%s is neither an OpenPGP key nor an SSH key", want)
		}
	}
	if len(items) == 0 {
		for _, e := range entries {
			if e.Item.Kind == svrpc.PGPItemKind && e.Item.Attrs[svrpc.PGPFingerprint] != "" {
				addPGP(e.Item)
			}
		}
	}
	for _, r := range recipients {
		text, err := recipientArg(r)
		if err != nil {
			return nil, err
		}
		k, err := svtrust.ParseKey([]byte(text))
		if err != nil {
			return nil, err
		}
		card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.Secretvault, Fingerprint: k.Fingerprint})
	}
	if len(card.Keys) == 0 {
		return nil, errors.New("no keys to show: make one with 'secretvault pgp new', or name them with --key or --recipient")
	}
	name, addr := svtrust.SplitUserID(firstUID)
	card.Name = name
	if addr != "" {
		card.Emails = []string{addr}
	}
	return card, nil
}

func (c *cli) contactVault(args []string) error {
	pos, err := parse(c.flags("contact vault"), args, 0, 1, "[VAULT|-]")
	if err != nil {
		return err
	}
	cl, err := c.open(nil)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	set := ""
	if len(pos) == 1 {
		set = pos[0]
	}
	name, err := cl.ContactsVault(ctx, set)
	if err != nil {
		return err
	}
	if set != "" {
		fmt.Fprintf(c.stdout, "Contacts now live in vault %q.\n", name)
		return nil
	}
	fmt.Fprintln(c.stdout, name)
	return nil
}

func (c *cli) cmdTrust(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault trust check --fingerprint FPR|--key FILE [--from ADDRESS] | seen --key FILE --from ADDRESS")
		return errUsage
	}
	switch args[0] {
	case "check":
		return c.trustCheck(args[1:])
	case "seen":
		return c.trustSeen(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault trust: unknown subcommand %q (check, seen)\n", args[0])
	return errUsage
}

func (c *cli) trustCheck(args []string) error {
	fs := c.flags("trust check")
	fp := fs.String("fingerprint", "", "the signer's key fingerprint or key ID")
	keyFile := fs.String("key", "", "the signer's certificate or public key, from `FILE`")
	fs.StringVar(keyFile, "cert", "", "the same as --key")
	from := fs.String("from", "", "the address the message claims to be from")
	minLevel := fs.String("min-level", "", "the weakest verification that counts: tofu, published (the default), logged, organisation, in-person")
	asJSON := fs.Bool("json", false, "print the verdict as JSON")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "--fingerprint FPR|--key FILE [--from ADDRESS] [--min-level LEVEL] [--json]"); err != nil {
		return err
	}
	if (*fp == "") == (*keyFile == "") {
		fmt.Fprintln(c.stderr, "usage: secretvault trust check --fingerprint FPR|--key FILE [--from ADDRESS] [--min-level LEVEL] [--json]")
		return errUsage
	}
	p := svrpc.TrustCheckParams{Vault: c.vault, Fingerprint: *fp, From: *from, MinLevel: *minLevel}
	if *keyFile != "" {
		data, err := c.readArg(*keyFile)
		if err != nil {
			return err
		}
		p.Key = data
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	v, err := cl.CheckSigner(ctx, p)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(c.stdout, v.Status)
		for _, r := range v.Reasons {
			fmt.Fprintln(c.stdout, "  "+r)
		}
	}
	if !v.Trusted {
		return exitCode(3)
	}
	return nil
}

func (c *cli) trustSeen(args []string) error {
	fs := c.flags("trust seen")
	keyFile := fs.String("key", "", "the key or certificate that came with the message, from `FILE` (required)")
	from := fs.String("from", "", "the address it came from (required)")
	at := fs.String("at", "", "when the message was received: RFC 3339 or YYYY-MM-DD (default: now)")
	source := fs.String("source", "", "what the message was (default: mail from ADDRESS on DATE)")
	name := fs.String("name", "", "the sender's name, for a new contact")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "--key FILE --from ADDRESS [--at TIME] [--source TEXT] [--name N]"); err != nil {
		return err
	}
	if *keyFile == "" || *from == "" {
		fmt.Fprintln(c.stderr, "usage: secretvault trust seen --key FILE --from ADDRESS [--at TIME] [--source TEXT] [--name N]")
		return errUsage
	}
	data, err := c.readArg(*keyFile)
	if err != nil {
		return err
	}
	p := svrpc.TrustSeenParams{Vault: c.vault, Key: data, Address: *from, Source: *source, Name: *name}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			if t, err = time.ParseInLocation("2006-01-02", *at, time.Local); err != nil {
				return fmt.Errorf("--at %q is neither RFC 3339 nor YYYY-MM-DD", *at)
			}
		}
		p.Time = t
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.KeySeen(ctx, p)
	if err != nil {
		return err
	}
	what := "Seen again"
	if res.New {
		what = "New key"
	}
	fmt.Fprintf(c.stdout, "%s: %s from %s (%s)\n", what, groupFP(res.Fingerprint), svtrust.ParseAddress(*from), res.Contact.Name)
	c.warn(res.Warnings)
	return nil
}

// contactDirectory is `secretvault contact directory add|ls|rm`: the
// organisations' LDAP directories asked for people's keys.
func (c *cli) contactDirectory(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	fs := c.flags("contact directory " + args[0])
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	switch args[0] {
	case "add":
		base := fs.String("base", "", "where people are: `DN`, like dc=example,dc=com")
		bindDN := fs.String("bind-dn", "", "bind as this `DN` (default: anonymously)")
		password := fs.String("password", "", "the bind password, as a reference to a vault item: sv://VAULT/ITEM[#FIELD]")
		ca := fs.String("ca", "", "trust the directory's certificate from this PEM `FILE` (a private CA)")
		pos, err := parse(fs, args[1:], 2, 2, "NAME ldaps://HOST|ldap://HOST --base DN [--bind-dn DN --password sv://...] [--ca FILE]")
		if err != nil {
			return err
		}
		if err := cl.AddDirectory(ctx, svrpc.DirectoryConfig{Name: pos[0], URL: pos[1], BaseDN: *base, BindDN: *bindDN, Password: *password, CAFile: *ca}); err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Lookups of an address now ask %s first; what it says counts as %s vouching for the key.\n", pos[0], pos[0])
		return nil
	case "ls", "list":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		dirs, err := cl.Directories(ctx)
		if err != nil {
			return err
		}
		if len(dirs) == 0 {
			fmt.Fprintln(c.stdout, "No directories: add one with 'secretvault contact directory add NAME ldaps://HOST --base DN'.")
			return nil
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		for _, d := range dirs {
			bind := "anonymous"
			if d.BindDN != "" {
				bind = d.BindDN
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", d.Name, d.URL, d.BaseDN, bind)
		}
		return tw.Flush()
	case "rm", "remove":
		pos, err := parse(fs, args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return cl.RemoveDirectory(ctx, pos[0])
	}
	fmt.Fprintln(c.stderr, "secretvault contact directory: add NAME URL --base DN | ls | rm NAME")
	return errUsage
}
