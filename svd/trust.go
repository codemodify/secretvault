package svd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// The trust store's face: contacts, their keys, and verdicts on signers
// (svtrust), kept in the contacts vault (the configured one, else the
// default vault).
//
// Who you know is private, so reading contacts is asked about like
// reading an item: per program, remembered, with "contacts" as the item.
// Changing them (adding, importing, verifying, a key seen in mail) is a
// write. A decision about contacts covers no item and one about an item
// covers no contacts; a decision about the whole vault covers both.
// Lookups go to the network only when a program asks for one, and only
// after it may read the contacts.

// contactsScope is the "item" decisions about contacts are about: not an
// item ID (those are 32 hex digits), so no item grant covers it.
const (
	contactsScope = "@contacts"
	contactsName  = "contacts"
)

func init() {
	for m, h := range map[string]handler{
		svrpc.MContactList:   (*Daemon).contactList,
		svrpc.MContactGet:    (*Daemon).contactGet,
		svrpc.MContactAdd:    (*Daemon).contactAdd,
		svrpc.MContactImport: (*Daemon).contactImport,
		svrpc.MContactRemove: (*Daemon).contactRemove,
		svrpc.MContactVerify: (*Daemon).contactVerify,
		svrpc.MContactLookup: (*Daemon).contactLookup,
		svrpc.MContactVault:  (*Daemon).contactVault,
		svrpc.MTrustCheck:    (*Daemon).trustCheck,
		svrpc.MTrustSeen:     (*Daemon).trustSeen,
	} {
		registerMethod(m, trustErrors(h))
	}
}

// trustErrors gives the trust store's errors their protocol codes.
func trustErrors(h handler) handler {
	return func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		res, err := h(d, ctx, cl, decode)
		var e *svrpc.Error
		switch {
		case err == nil, errors.As(err, &e):
		case errors.Is(err, svtrust.ErrNotFound):
			err = svrpc.Errorf(svrpc.CodeNotFound, "%s", strings.TrimPrefix(err.Error(), "svtrust: "))
		case errors.Is(err, svtrust.ErrKeyHeld):
			err = svrpc.Errorf(svrpc.CodeExists, "%s", strings.TrimPrefix(err.Error(), "svtrust: "))
		case errors.Is(err, svtrust.ErrAmbiguous), errors.Is(err, svtrust.ErrNoKey), errors.Is(err, svtrust.ErrPrivate), errors.Is(err, svtrust.ErrNotCard):
			err = svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svtrust: "))
		}
		return res, err
	}
}

// contactsVault finds the vault contacts are kept in.
func (d *Daemon) contactsVault(name string) (*managedVault, error) {
	if name == "" {
		d.mu.Lock()
		name = d.cfg.ContactsVault
		d.mu.Unlock()
	}
	return d.vault(name)
}

// contacts authorizes op on the contacts of a vault (unlocking it first
// if need be) and returns their store.
func (d *Daemon) contacts(ctx context.Context, cl *client, vault string, op svbroker.Op) (*managedVault, *svtrust.Store, error) {
	mv, err := d.contactsVault(vault)
	if err != nil {
		return nil, nil, err
	}
	verb := "read"
	if op != svbroker.OpRead {
		verb = "change"
	}
	why := fmt.Sprintf("%s wants to %s your contacts in vault %q.", cl.display(), verb, mv.cfg.Name)
	record := d.recorder(cl, mv, contactsName, op)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		record(outcomeOf(err), err.Error())
		return nil, nil, err
	}
	if err := d.decide(ctx, cl, mv, contactsScope, contactsName, op, why, prompted, own, record); err != nil {
		return nil, nil, err
	}
	return mv, d.trustStore(mv), nil
}

// trustStore is the one store of a vault's contacts, which serialises
// changes to them.
func (d *Daemon) trustStore(mv *managedVault) *svtrust.Store {
	if s, ok := d.stores.Load(mv.v); ok {
		return s.(*svtrust.Store)
	}
	s := svtrust.NewStore(mv.v)
	s.Now = d.opts.Now
	got, _ := d.stores.LoadOrStore(mv.v, s)
	return got.(*svtrust.Store)
}

func (d *Daemon) httpClient() *http.Client {
	if d.opts.HTTP != nil {
		return d.opts.HTTP
	}
	return svtrust.DefaultClient()
}

func (d *Daemon) keyserver(url string) *svtrust.Keyserver {
	return &svtrust.Keyserver{URL: url, Client: d.httpClient(), Now: d.opts.Now}
}

func (d *Daemon) contactList(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactListParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	all, err := st.Contacts()
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(p.Query))
	var keys []*svtrust.Key
	var shown []*svtrust.Contact
	for _, c := range all {
		if q != "" && !strings.Contains(strings.ToLower(c.Name), q) &&
			!strings.Contains(strings.ToLower(strings.Join(c.Emails, " ")), q) {
			continue
		}
		shown = append(shown, c)
		keys = append(keys, c.Keys...)
	}
	derived, err := st.Derived(keys)
	if err != nil {
		return nil, err
	}
	out := []svrpc.Contact{}
	for _, c := range shown {
		out = append(out, d.contactView(c, false, derived[:len(c.Keys)]))
		derived = derived[len(c.Keys):]
	}
	return out, nil
}

func (d *Daemon) contactGet(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	c, err := st.Get(p.Ref)
	if err != nil {
		return nil, err
	}
	derived, err := st.Derived(c.Keys)
	if err != nil {
		return nil, err
	}
	out := d.contactView(c, true, derived)
	out.Warnings, err = st.Warnings(c)
	return out, err
}

// parseKeys reads keys from what a client sent, noting where they came
// from.
func parseKeys(data []byte, source string) ([]*svtrust.Key, error) {
	keys, err := svtrust.ParseKeys(data)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svtrust: "))
	}
	for _, k := range keys {
		k.Source = source
	}
	return keys, nil
}

func (d *Daemon) contactAdd(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactAddParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	var keys []*svtrust.Key
	for _, data := range p.Keys {
		ks, err := parseKeys(data, p.Source)
		if err != nil {
			return nil, err
		}
		keys = append(keys, ks...)
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	c, warnings, err := st.Add(&svtrust.Contact{Name: p.Name, Emails: p.Emails, Notes: p.Notes, Organisation: p.Organisation, Keys: keys})
	if err != nil {
		return nil, err
	}
	return svrpc.ContactChange{Contact: d.contactView(c, false, nil), Warnings: warnings}, nil
}

func (d *Daemon) contactImport(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactImportParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if (p.URI == "") == (len(p.Data) == 0) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "import either key data or a URI")
	}
	out := svrpc.ContactImportResult{Keys: []svrpc.ImportedKey{}}
	if p.URI != "" {
		card, err := svtrust.ParseCard(p.URI)
		if err != nil {
			return nil, err
		}
		_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
		if err != nil {
			return nil, err
		}
		var fetch svtrust.Fetcher
		if p.Fetch {
			ks := d.keyserver(p.Keyserver)
			fetch = func(fp string) ([]*svtrust.Key, error) {
				lctx, cancel := context.WithTimeout(ctx, time.Minute)
				defer cancel()
				f, err := ks.ByFingerprint(lctx, fp)
				if err != nil {
					return nil, err
				}
				return f.Keys, nil
			}
		}
		res, err := st.Scan(card, cl.display(), fetch)
		if err != nil {
			return nil, err
		}
		for _, k := range res.Verified {
			out.Keys = append(out.Keys, svrpc.ImportedKey{ContactID: res.Contact.ID, Contact: res.Contact.Name,
				Type: string(k.Type), Fingerprint: k.Fingerprint, Label: k.Label, Verified: true})
		}
		for _, m := range res.Missing {
			out.Missing = append(out.Missing, string(m.Type)+":"+m.Fingerprint)
		}
		out.Warnings = res.Warnings
		return out, nil
	}
	keys, err := parseKeys(p.Data, p.Source)
	if err != nil {
		return nil, err
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	imported, err := st.Import(keys, svtrust.ImportOptions{Contact: p.Contact, Name: p.Name, By: cl.display()})
	if err != nil {
		return nil, err
	}
	for _, im := range imported {
		out.Keys = append(out.Keys, importedView(im))
	}
	return out, nil
}

func importedView(im svtrust.Imported) svrpc.ImportedKey {
	return svrpc.ImportedKey{ContactID: im.Contact.ID, Contact: im.Contact.Name, Type: string(im.Key.Type),
		Fingerprint: im.Key.Fingerprint, Label: im.Key.Label, New: im.New, Warnings: im.Warnings}
}

func (d *Daemon) contactRemove(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactRemoveParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	var c *svtrust.Contact
	if p.Fingerprint != "" {
		c, err = st.RemoveKey(p.Ref, p.Fingerprint)
	} else {
		c, err = st.Remove(p.Ref)
	}
	if err != nil {
		return nil, err
	}
	return d.contactView(c, false, nil), nil
}

func (d *Daemon) contactVerify(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactVerifyParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	switch {
	case svtrust.MethodLevel(p.Method) == svtrust.None:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not a way of verifying a key", p.Method)
	case (p.Method == svtrust.MethodOrgCA || p.Method == svtrust.MethodOrgDirectory) && p.Source == "":
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "say which organisation vouches for the key")
	case p.Fingerprint == "":
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "say which key: its fingerprint")
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	c, err := st.Verify(p.Ref, p.Fingerprint, svtrust.Event{Method: p.Method, By: cl.display(), Source: p.Source, Addresses: p.Addresses})
	if err != nil {
		return nil, err
	}
	return d.contactView(c, false, nil), nil
}

func (d *Daemon) contactLookup(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.ContactLookupParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	q := strings.TrimSpace(p.Query)
	addr := svtrust.ParseAddress(q)
	if addr == "" && p.WKD {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "WKD looks up addresses; %q is not one", q)
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var found []*svtrust.Found
	var errs []string
	try := func(where string, f *svtrust.Found, err error) {
		if err != nil {
			errs = append(errs, where+": "+strings.TrimPrefix(err.Error(), "svtrust: "))
			return
		}
		found = append(found, f)
	}
	dirs, err := d.directories(ctx, cl, p.Directory)
	if err != nil {
		return nil, err
	}
	switch {
	case addr != "" && p.Directory != "":
		for _, dir := range dirs {
			f, err := svtrust.LookupDirectory(lctx, dir, addr, d.opts.Now())
			try(dir.Name(), f, err)
		}
	case addr != "":
		// An organisation's directory is asked first: for its own people
		// it is the authority.
		if !p.WKD && p.Keyserver == "" {
			for _, dir := range dirs {
				f, err := svtrust.LookupDirectory(lctx, dir, addr, d.opts.Now())
				try(dir.Name(), f, err)
			}
		}
		if p.WKD || p.Keyserver == "" {
			f, err := (&svtrust.WKD{Client: d.httpClient(), Now: d.opts.Now}).Lookup(lctx, addr)
			try("WKD", f, err)
		}
		if !p.WKD && (p.Keyserver != "" || len(found) == 0) {
			ks := d.keyserver(p.Keyserver)
			f, err := ks.ByEmail(lctx, addr)
			try("keyserver", f, err)
		}
	default:
		f, err := d.keyserver(p.Keyserver).ByFingerprint(lctx, q)
		try("keyserver", f, err)
	}
	if len(found) == 0 {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "no key found for %s (%s)", q, strings.Join(errs, "; "))
	}
	out := svrpc.ContactLookupResult{Errors: errs}
	var keys []*svtrust.Key
	now := d.opts.Now()
	for _, f := range found {
		lf := svrpc.LookupFound{URL: f.URL, Policy: f.Policy}
		for _, k := range f.Keys {
			lf.Keys = append(lf.Keys, keyView(k, now, true, nil))
			known := ""
			if c, _, err := st.ByFingerprint(k.Fingerprint); err == nil {
				known = c.Name
			}
			lf.Known = append(lf.Known, known)
			keys = append(keys, k)
		}
		out.Found = append(out.Found, lf)
	}
	if p.Add {
		if _, _, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite); err != nil {
			return nil, err
		}
		imported, err := st.Import(keys, svtrust.ImportOptions{Name: p.Name, Origin: svtrust.OriginLookup, By: cl.display()})
		if err != nil {
			return nil, err
		}
		for _, im := range imported {
			out.Added = append(out.Added, importedView(im))
		}
	}
	return out, nil
}

// contactVault says which vault contacts are kept in, and, when the CLI
// names one ("-" for the default vault), keeps them there from now on.
func (d *Daemon) contactVault(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.VaultRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	if p.Vault != "" {
		if !cl.cli {
			return nil, svrpc.Errorf(svrpc.CodeDenied, "%v", errNotCLI)
		}
		name := ""
		if p.Vault != "-" {
			mv, err := d.vault(p.Vault)
			if err != nil {
				return nil, err
			}
			name = mv.cfg.Name
		}
		d.mu.Lock()
		old := d.cfg.ContactsVault
		d.cfg.ContactsVault = name
		err := d.cfg.save(d.home)
		if err != nil {
			d.cfg.ContactsVault = old
		}
		d.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	mv, err := d.contactsVault("")
	if err != nil {
		return nil, err
	}
	return svrpc.VaultRef{Vault: mv.cfg.Name}, nil
}

func (d *Daemon) trustCheck(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.TrustCheckParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	min, ok := svtrust.ParseLevel(p.MinLevel)
	if !ok {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not a verification level (tofu, published, logged, organisation, in-person)", p.MinLevel)
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	v, err := st.Check(svtrust.Query{Fingerprint: p.Fingerprint, Key: p.Key, From: p.From})
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svtrust: "))
	}
	return d.verdictView(v, svtrust.Policy{MinLevel: min}), nil
}

func (d *Daemon) trustSeen(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.TrustSeenParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	keys, err := parseKeys(p.Key, "")
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "a message comes with one key or certificate, not %d", len(keys))
	}
	if svtrust.ParseAddress(p.Address) == "" {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not an email address", p.Address)
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	res, err := st.Seen(keys[0], p.Address, p.Time, p.Source, cl.display(), p.Name)
	if err != nil {
		return nil, err
	}
	out := svrpc.SeenResult{Contact: d.contactView(res.Contact, false, nil), Fingerprint: res.Key.Fingerprint,
		New: res.New, Bound: res.Bound, Warnings: res.Warnings}
	for _, h := range res.Conflicts {
		l, _ := h.Key.BestFor(svtrust.ParseAddress(p.Address))
		out.Conflicts = append(out.Conflicts, svrpc.OtherKey{ContactID: h.Contact.ID, Contact: h.Contact.Name, Fingerprint: h.Key.Fingerprint, Level: string(l)})
	}
	return out, nil
}

// Views: the trust store's types as the protocol has them.

func (d *Daemon) contactView(c *svtrust.Contact, full bool, derived [][]svtrust.Event) svrpc.Contact {
	out := svrpc.Contact{ID: c.ID, Name: c.Name, Emails: c.Emails, Notes: c.Notes, Organisation: c.Organisation,
		Origin: c.Origin, Created: c.Created, Updated: c.Updated}
	now := d.opts.Now()
	best := svtrust.None
	for i, k := range c.Keys {
		var extra []svtrust.Event
		if i < len(derived) {
			extra = derived[i]
		}
		kv := keyView(k, now, full, extra)
		if l := svtrust.Level(kv.Level); l.Rank() > best.Rank() {
			best = l
		}
		out.Keys = append(out.Keys, kv)
	}
	out.Level = string(best)
	return out
}

// keyView describes a key; derived are verifications worked out now.
func keyView(k *svtrust.Key, now time.Time, full bool, derived []svtrust.Event) svrpc.ContactKey {
	level, _ := k.Best()
	for _, e := range derived {
		if e.Level.Rank() > level.Rank() {
			level = e.Level
		}
	}
	out := svrpc.ContactKey{Type: string(k.Type), Fingerprint: k.Fingerprint, Label: k.Label, Addresses: k.Addresses,
		Level: string(level), State: k.State(now), Added: k.Added, Source: k.Source}
	if !full {
		return out
	}
	out.Material, out.Chain, out.Subkeys = k.Material, k.Chain, k.Subkeys
	for i := range k.Events {
		out.Verifications = append(out.Verifications, verificationView(&k.Events[i], false))
	}
	for i := range derived {
		out.Verifications = append(out.Verifications, verificationView(&derived[i], true))
	}
	for i := range k.Seen {
		out.Seen = append(out.Seen, sightingView(&k.Seen[i]))
	}
	return out
}

func verificationView(e *svtrust.Event, derived bool) svrpc.Verification {
	return svrpc.Verification{Level: string(e.Level), Method: e.Method, By: e.By, At: e.At, Source: e.Source,
		Addresses: e.Addresses, Derived: derived, Description: e.Describe()}
}

func sightingView(s *svtrust.Sighting) svrpc.Sighting {
	return svrpc.Sighting{Address: s.Address, First: s.First, Last: s.Last, Count: s.Count, Source: s.Source, Conflicts: s.Conflicts}
}

func (d *Daemon) verdictView(v *svtrust.Verdict, p svtrust.Policy) svrpc.Verdict {
	j := p.Judge(v)
	out := svrpc.Verdict{Fingerprint: v.Fingerprint, From: v.From, Known: v.Key != nil, Level: string(v.Level),
		KeyLevel: string(v.KeyLevel), Bound: v.Bound, Claimed: v.Claimed, State: v.State, Reasons: v.Reasons,
		Trusted: j.Trusted, Status: j.Status}
	if v.Contact != nil {
		out.ContactID, out.Contact = v.Contact.ID, v.Contact.Name
	}
	if v.Key != nil {
		kv := keyView(v.Key, d.opts.Now(), false, nil)
		out.Key = &kv
	}
	if v.Verification != nil {
		vv := verificationView(v.Verification, !containsEvent(v.Key, v.Verification))
		out.Verification = &vv
	}
	if v.Seen != nil {
		s := sightingView(v.Seen)
		out.Seen = &s
	}
	for _, o := range v.Others {
		out.Others = append(out.Others, svrpc.OtherKey{ContactID: o.Contact.ID, Contact: o.Contact.Name, Fingerprint: o.Key.Fingerprint, Level: string(o.Level)})
	}
	return out
}

// containsEvent reports whether e is one of the key's recorded events,
// rather than one worked out now.
func containsEvent(k *svtrust.Key, e *svtrust.Event) bool {
	if k == nil {
		return false
	}
	for _, x := range k.Events {
		if x.Method == e.Method && x.At.Equal(e.At) && x.Source == e.Source && x.By == e.By {
			return true
		}
	}
	return false
}
