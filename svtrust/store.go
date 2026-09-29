package svtrust

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
)

// RecordKind is the vault record kind contacts are kept under.
const RecordKind = "contact"

// Backend is where a Store keeps its contacts: a vault (*svcore.Vault).
type Backend interface {
	Records(kind string) ([]svcore.Record, error)
	PutRecord(kind string, id svformat.ID, data any) (svcore.Record, error)
	DeleteRecord(id svformat.ID) error
}

var (
	// ErrNotFound is a contact or key the store does not have.
	ErrNotFound = errors.New("svtrust: not in your contacts")
	// ErrAmbiguous is a name or address that fits more than one contact.
	ErrAmbiguous = errors.New("svtrust: more than one contact matches")
	// ErrKeyHeld is a key added to a contact while another holds it.
	ErrKeyHeld = errors.New("svtrust: the key is already a contact's")
)

// Store is the contacts of one vault. Each contact is a record, so
// contacts are encrypted, have history and sync like items. Records
// changed on two devices at once are merged when read: addresses, keys,
// verifications and sightings from both are kept.
//
// A Store is safe for concurrent use; changes made through one Store are
// serialised, so keep one per vault.
type Store struct {
	b  Backend
	mu sync.Mutex

	// Now is the clock (tests replace it).
	Now func() time.Time
}

// NewStore returns the store of contacts kept in b.
func NewStore(b Backend) *Store { return &Store{b: b, Now: time.Now} }

func (s *Store) now() time.Time { return s.Now().UTC().Truncate(time.Second) }

// book is every contact, as read at one moment.
type book []*Contact

func (s *Store) load() (book, error) {
	recs, err := s.b.Records(RecordKind)
	if err != nil {
		return nil, err
	}
	var out book
	for _, r := range recs {
		c, err := decodeContact(r.Data)
		if err != nil {
			continue // a record this version cannot read is kept, not shown
		}
		for _, raw := range r.Conflicts {
			if other, err := decodeContact(raw); err == nil {
				c.merge(other)
			}
		}
		c.ID, c.Updated = r.ID.String(), r.Time
		out = append(out, c)
	}
	return out, nil
}

func decodeContact(b []byte) (*Contact, error) {
	var c Contact
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) save(c *Contact) error {
	if c.Version == 0 {
		c.Version = 1 // a newer version's number is kept, as its members are
	}
	var id svformat.ID
	if c.ID != "" {
		var err error
		if id, err = svformat.ParseID(c.ID); err != nil {
			return err
		}
	}
	r, err := s.b.PutRecord(RecordKind, id, c)
	if err != nil {
		return err
	}
	c.ID, c.Updated = r.ID.String(), r.Time
	return nil
}

func (s *Store) remove(c *Contact) error {
	id, err := svformat.ParseID(c.ID)
	if err != nil {
		return err
	}
	return s.b.DeleteRecord(id)
}

// Contacts returns every contact, by name.
func (s *Store) Contacts() ([]*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(b, func(i, j int) bool { return strings.ToLower(b[i].Name) < strings.ToLower(b[j].Name) })
	return b, nil
}

// Find returns the contacts ref names: by ID, then by name (ignoring
// case), then by email address, then by the fingerprint or key ID of one
// of their keys.
func (s *Store) Find(ref string) ([]*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	return b.find(ref), nil
}

// Get returns the one contact ref names (see Find).
func (s *Store) Get(ref string) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	return b.get(ref)
}

// ByEmail returns the contacts with this address, their own or bound to
// one of their keys.
func (s *Store) ByEmail(addr string) ([]*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	return b.withEmail(ParseAddress(addr)), nil
}

// ByFingerprint returns the contact holding the key with this
// fingerprint (any key type), subkey fingerprint or OpenPGP key ID, and
// that key.
func (s *Store) ByFingerprint(fp string) (*Contact, *Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	c, k := b.holding(NormalizeFingerprint(fp))
	if c == nil {
		return nil, nil, fmt.Errorf("%w: no key %s", ErrNotFound, fp)
	}
	return c, k, nil
}

// ByCertificate returns the contact holding a certificate (PEM or DER).
func (s *Store) ByCertificate(cert []byte) (*Contact, *Key, error) {
	der := cert
	if block, _ := pem.Decode(cert); block != nil && block.Type == "CERTIFICATE" {
		der = block.Bytes
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNoKey, err)
	}
	return s.ByFingerprint(certFingerprint(der))
}

func (b book) byID(id string) *Contact {
	for _, c := range b {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (b book) find(ref string) []*Contact {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if c := b.byID(ref); c != nil {
		return []*Contact{c}
	}
	var hits []*Contact
	for _, c := range b {
		if strings.EqualFold(c.Name, ref) {
			hits = append(hits, c)
		}
	}
	if len(hits) > 0 {
		return hits
	}
	if hits = b.withEmail(ParseAddress(ref)); len(hits) > 0 {
		return hits
	}
	if c, _ := b.holding(NormalizeFingerprint(ref)); c != nil {
		return []*Contact{c}
	}
	return nil
}

func (b book) get(ref string) (*Contact, error) {
	hits := b.find(ref)
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("%w: %q", ErrNotFound, ref)
	case 1:
		return hits[0], nil
	}
	var names []string
	for _, c := range hits {
		names = append(names, fmt.Sprintf("%s (%s)", c.Name, c.ID))
	}
	return nil, fmt.Errorf("%w: %q is %s", ErrAmbiguous, ref, strings.Join(names, ", "))
}

func (b book) withEmail(addr string) []*Contact {
	if addr == "" {
		return nil
	}
	var out []*Contact
	for _, c := range b {
		if containsAddr(c.Emails, addr) || slices.ContainsFunc(c.Keys, func(k *Key) bool { return k.Bound(addr) }) {
			out = append(out, c)
		}
	}
	return out
}

// holding finds the contact and key a normalised fingerprint names.
func (b book) holding(fp string) (*Contact, *Key) {
	for _, c := range b {
		if k := c.Key(fp); k != nil {
			return c, k
		}
	}
	return nil, nil
}

// boundTo returns the keys of contacts other than except bound to addr.
func (b book) boundTo(addr string, except *Contact) []Holder {
	var out []Holder
	for _, c := range b {
		if c == except || except != nil && c.ID == except.ID {
			continue
		}
		for _, k := range c.Keys {
			if k.Bound(addr) {
				out = append(out, Holder{c, k})
			}
		}
	}
	return out
}

// bindChecked binds addr to k (in c) unless another contact's key is
// bound to it, in which case it says so and binds nothing.
func (b book) bindChecked(c *Contact, k *Key, addr string) (warning string) {
	if k.Bound(addr) {
		c.addEmail(addr)
		return ""
	}
	if others := b.boundTo(addr, c); len(others) > 0 {
		return fmt.Sprintf("%s already belongs to %s; it was not bound to key %s", addr, describeHolders(others), shortFP(k.Fingerprint))
	}
	c.bind(k, addr)
	return ""
}

func describeHolders(hs []Holder) string {
	var parts []string
	for _, h := range hs {
		who := "a key"
		if !h.Contact.Automatic() {
			who = h.Contact.Name + "'s key"
		}
		parts = append(parts, who+" "+shortFP(h.Key.Fingerprint))
	}
	return strings.Join(parts, " and ")
}

// shortFP shortens a fingerprint for messages: an OpenPGP key ID's worth.
func shortFP(fp string) string {
	if id := keyIDOf(fp); id != "" {
		return id
	}
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

// Add stores a new contact with its keys. Keys another contact holds are
// refused (ErrKeyHeld). Each key's Addresses are bound to it unless
// another contact's key is bound to one of them: that address is left
// unbound, and a warning says so.
func (s *Store) Add(c *Contact) (*Contact, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	c.ID = ""
	if c.Origin == "" {
		c.Origin = OriginAdded
	}
	if c.Created.IsZero() {
		c.Created = now
	}
	var emails []string
	for _, e := range c.Emails {
		if addr := ParseAddress(e); addr != "" && !containsAddr(emails, addr) {
			emails = append(emails, addr)
		} else if addr == "" {
			return nil, nil, fmt.Errorf("svtrust: %q is not an email address", e)
		}
	}
	c.Emails = emails
	keys := c.Keys
	c.Keys = nil
	var warnings []string
	for _, k := range keys {
		if other, _ := b.holding(k.Fingerprint); other != nil {
			return nil, nil, fmt.Errorf("%w: key %s is %s's", ErrKeyHeld, shortFP(k.Fingerprint), other.Name)
		}
		if c.Key(k.Fingerprint) != nil {
			continue
		}
		warnings = append(warnings, b.adopt(c, k, now)...)
	}
	if c.Name = strings.TrimSpace(c.Name); c.Name == "" {
		c.Name = defaultName(c)
	}
	if err := s.save(c); err != nil {
		return nil, nil, err
	}
	return c, warnings, nil
}

// adopt puts a new key in c, binding what it can of its addresses.
func (b book) adopt(c *Contact, k *Key, now time.Time) (warnings []string) {
	if k.Added.IsZero() {
		k.Added = now
	}
	addrs := k.Addresses
	k.Addresses = nil
	c.Keys = append(c.Keys, k)
	for _, addr := range addrs {
		if w := b.bindChecked(c, k, addr); w != "" {
			warnings = append(warnings, w)
		}
	}
	return warnings
}

// defaultName names a contact after its first key: the name in its user
// ID or its label, else an address, else the fingerprint.
func defaultName(c *Contact) string {
	for _, k := range c.Keys {
		if name, _ := SplitUserID(k.Label); name != "" && k.Type == OpenPGP {
			return name
		}
		if k.Type == X509 && k.Label != "" {
			return k.Label
		}
	}
	if len(c.Emails) > 0 {
		return c.Emails[0]
	}
	for _, k := range c.Keys {
		if k.Label != "" {
			return k.Label
		}
		return shortFP(k.Fingerprint)
	}
	return "unnamed"
}

// Edit changes a contact's name, addresses, notes or organisation mark
// with edit, and stores the result. Keys are changed with the other
// methods.
func (s *Store) Edit(ref string, edit func(*Contact) error) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	c, err := b.get(ref)
	if err != nil {
		return nil, err
	}
	keys := c.Keys
	if err := edit(c); err != nil {
		return nil, err
	}
	c.Keys = keys
	if c.Name = strings.TrimSpace(c.Name); c.Name == "" {
		return nil, errors.New("svtrust: a contact needs a name")
	}
	if c.Origin == OriginMail || c.Origin == OriginLookup {
		c.Origin = OriginAdded // you have named it now
	}
	return c, s.save(c)
}

// Remove deletes a contact.
func (s *Store) Remove(ref string) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	c, err := b.get(ref)
	if err != nil {
		return nil, err
	}
	return c, s.remove(c)
}

// RemoveKey removes one key from a contact (ref "" for whichever holds
// it). The contact stays, even with no keys left.
func (s *Store) RemoveKey(ref, fp string) (*Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	fp = NormalizeFingerprint(fp)
	c, k := b.holding(fp)
	if c == nil {
		return nil, fmt.Errorf("%w: no key %s", ErrNotFound, fp)
	}
	if ref != "" {
		want, err := b.get(ref)
		if err != nil {
			return nil, err
		}
		if want.ID != c.ID {
			return nil, fmt.Errorf("%w: key %s is %s's, not %s's", ErrNotFound, shortFP(k.Fingerprint), c.Name, want.Name)
		}
	}
	c.Keys = slices.DeleteFunc(c.Keys, func(x *Key) bool { return x == k })
	return c, s.save(c)
}

// Verify records a verification of the key with fingerprint fp. When ref
// names a contact other than the one holding the key, the key moves to
// it: verifying a key seen in mail as Alice's makes it Alice's. The
// event's Level is its method's; its time is now when zero. The
// addresses it covers (the key's own, when it names none) are bound to
// the key, and added to the contact.
func (s *Store) Verify(ref, fp string, ev Event) (*Contact, error) {
	level := MethodLevel(ev.Method)
	if level == None {
		return nil, fmt.Errorf("svtrust: %q is not a way of verifying a key", ev.Method)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	fp = NormalizeFingerprint(fp)
	from, k := b.holding(fp)
	if from == nil {
		return nil, fmt.Errorf("%w: no key %s (add it first)", ErrNotFound, fp)
	}
	to := from
	if ref != "" {
		if to, err = b.get(ref); err != nil {
			return nil, err
		}
	}
	ev.Level = level
	if ev.At.IsZero() {
		ev.At = s.now()
	}
	var addrs []string
	for _, a := range ev.Addresses {
		addr := ParseAddress(a)
		if addr == "" {
			return nil, fmt.Errorf("svtrust: %q is not an email address", a)
		}
		addrs = append(addrs, addr)
	}
	ev.Addresses = addrs
	if len(addrs) == 0 {
		addrs = k.Claimed()
	}
	if to.ID != from.ID {
		if err := s.move(from, to, k); err != nil {
			return nil, err
		}
	}
	for _, addr := range addrs {
		to.bind(k, addr)
	}
	k.addEvent(ev)
	return to, s.save(to)
}

// move takes k out of from and into to, storing from (or deleting it,
// when it was made automatically and has no keys left).
func (s *Store) move(from, to *Contact, k *Key) error {
	from.Keys = slices.DeleteFunc(from.Keys, func(x *Key) bool { return x == k })
	to.Keys = append(to.Keys, k)
	if len(from.Keys) == 0 && from.Automatic() {
		return s.remove(from)
	}
	return s.save(from)
}

// addEvent records an event unless the key already has the same one.
func (k *Key) addEvent(e Event) {
	for _, x := range k.Events {
		if x.Method == e.Method && x.At.Equal(e.At) && x.By == e.By && x.Source == e.Source && slices.Equal(x.Addresses, e.Addresses) {
			return
		}
	}
	k.Events = append(k.Events, e)
	sort.SliceStable(k.Events, func(i, j int) bool { return k.Events[i].At.Before(k.Events[j].At) })
}

// SeenResult is what recording a key seen in mail did.
type SeenResult struct {
	Contact *Contact
	Key     *Key
	// New says the key was not in the store before.
	New bool
	// Bound says the address is bound to the key now.
	Bound bool
	// Conflicts are the keys of other contacts bound to the address: the
	// key was kept apart from them, not put in their place.
	Conflicts []Holder
	Warnings  []string
}

// Holder is a key and the contact that has it.
type Holder struct {
	Contact *Contact
	Key     *Key
}

// Seen records that key k signed (or came with) a message from addr
// received at time at (zero means now). source describes the message
// ("" writes "mail from ADDR on DATE"), by who recorded it, and name is
// the sender's display name, used to name a new contact.
//
// The first time a key is seen for an address it is trusted on first use:
// the address is bound to the key and a TOFU event recorded, unless the
// key does not name the address itself (then it is only counted), or
// another contact's key is bound to the address. In that last case the
// key is kept apart, in a contact of its own, and the conflict is recorded
// and returned: a different key for an address never silently replaces
// the one you have.
func (s *Store) Seen(k *Key, addr string, at time.Time, source, by, name string) (*SeenResult, error) {
	if a := ParseAddress(addr); a == "" {
		return nil, fmt.Errorf("svtrust: %q is not an email address", addr)
	} else {
		addr = a
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	now := s.now()
	if at.IsZero() || at.After(now.Add(time.Hour)) {
		at = now
	}
	at = at.UTC().Truncate(time.Second)
	if source == "" {
		source = fmt.Sprintf("mail from %s on %s", addr, day(at))
	}
	res := &SeenResult{}
	claimed := k.claims(addr)
	if !claimed {
		res.Warnings = append(res.Warnings, fmt.Sprintf("key %s does not name %s", shortFP(k.Fingerprint), addr))
	}
	c, held := b.holding(k.Fingerprint)
	if held == nil {
		res.New = true
		held = &Key{Type: k.Type, Fingerprint: k.Fingerprint, Material: k.Material, Chain: k.Chain,
			Subkeys: k.Subkeys, Label: k.Label, Added: now, Source: source}
		// A key for an address someone else's key has is kept apart.
		others := b.boundTo(addr, nil)
		if len(others) == 0 {
			for _, cand := range b.withEmail(addr) {
				if c == nil {
					c = cand
				} else {
					c = nil // several contacts have the address: make a new one
					break
				}
			}
		}
		if c == nil {
			// The contact is whoever sent from addr with this key.
			c = &Contact{Name: strings.TrimSpace(name), Emails: []string{addr}, Origin: OriginMail, Created: now}
			// A key kept apart is not named as the sender says: that name
			// may be the one it is pretending to.
			if c.Name == "" || ParseAddress(c.Name) != "" || len(others) > 0 {
				c.Name = addr
			}
		}
		c.Keys = append(c.Keys, held)
	} else {
		held.mergeMaterial(k)
	}
	res.Contact, res.Key = c, held

	sighting := held.Sighting(addr)
	first := sighting == nil
	if first {
		held.Seen = append(held.Seen, Sighting{Address: addr, First: at, Last: at, Count: 1, Source: source})
		sighting = &held.Seen[len(held.Seen)-1]
	} else {
		sighting.Count++
		if at.After(sighting.Last) {
			sighting.Last = at
		}
		if at.Before(sighting.First) {
			sighting.First = at
		}
	}
	others := b.boundTo(addr, c)
	res.Conflicts = others
	switch {
	case held.Bound(addr):
	case len(others) > 0:
		if first {
			for _, h := range others {
				sighting.Conflicts = append(sighting.Conflicts, h.Key.Fingerprint)
			}
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s belongs to %s, not to key %s: this may be an impostor, or a new key",
			addr, describeHolders(others), shortFP(held.Fingerprint)))
	case claimed:
		c.bind(held, addr)
		held.addEvent(Event{Level: TOFU, Method: MethodTOFU, By: by, At: at, Source: source, Addresses: []string{addr}})
	}
	res.Bound = held.Bound(addr)
	if err := s.save(c); err != nil {
		return nil, err
	}
	return res, nil
}

// ImportOptions say where Import puts keys.
type ImportOptions struct {
	// Contact names the contact (name, address, ID or fingerprint) that
	// gets the new keys; "" finds or makes one per key.
	Contact string
	// Name names new contacts; "" takes it from the key.
	Name string
	// Origin is new contacts' origin; OriginAdded when "".
	Origin string
	// By is who imports, written into the keys' events that do not say.
	By string
}

// Imported is what Import did with one key.
type Imported struct {
	Contact  *Contact
	Key      *Key
	New      bool // the store did not have the key
	Warnings []string
}

// Import adds keys (from a file, a lookup or a directory) to the store,
// with the verification events they carry. A key the store has is
// updated: new addresses, events and a newer copy of it (see
// mergeMaterial). A new key goes to opts.Contact; or to the one contact
// that lists one of its addresses without a key bound to it (a contact
// you made with just an address); or to a new contact. Addresses another
// contact's key has are not bound, and a warning says so.
func (s *Store) Import(keys []*Key, opts ImportOptions) ([]Imported, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	var target *Contact
	if opts.Contact != "" {
		if target, err = b.get(opts.Contact); err != nil {
			return nil, err
		}
	}
	now := s.now()
	var out []Imported
	changed := map[*Contact]bool{}
	for _, k := range keys {
		for i := range k.Events {
			if k.Events[i].By == "" {
				k.Events[i].By = opts.By
			}
		}
		res := Imported{Key: k}
		c, held := b.holding(k.Fingerprint)
		if held != nil {
			held.mergeMaterial(k)
			for _, addr := range k.Addresses {
				if w := b.bindChecked(c, held, addr); w != "" {
					res.Warnings = append(res.Warnings, w)
				}
			}
			for _, e := range k.Events {
				held.addEvent(e)
			}
			res.Key = held
		} else {
			res.New = true
			c = target
			if c == nil {
				c = b.homeFor(k)
			}
			if c == nil {
				origin := opts.Origin
				if origin == "" {
					origin = OriginAdded
				}
				c = &Contact{Name: opts.Name, Origin: origin, Created: now}
				b = append(b, c)
			}
			res.Warnings = b.adopt(c, k, now)
			if c.Name == "" {
				c.Name = defaultName(c)
			}
		}
		res.Contact = c
		changed[c] = true
		out = append(out, res)
	}
	for c := range changed {
		if err := s.save(c); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// homeFor is the contact a new key goes to: the one contact listing one
// of its addresses with no key bound to it.
func (b book) homeFor(k *Key) *Contact {
	var home *Contact
	for _, addr := range k.Addresses {
		for _, c := range b.withEmail(addr) {
			if slices.ContainsFunc(c.Keys, func(x *Key) bool { return x.Bound(addr) }) {
				continue
			}
			if home != nil && home != c {
				return nil
			}
			home = c
		}
	}
	return home
}

// Warnings describe what is wrong with a contact's keys: addresses they
// were seen for that belong to other contacts' keys, and keys that are
// revoked or expired.
func (s *Store) Warnings(c *Contact) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.load()
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []string
	for _, k := range c.Keys {
		if st := k.State(now); st != "" {
			out = append(out, fmt.Sprintf("key %s is %s", shortFP(k.Fingerprint), st))
		}
		for _, seen := range k.Seen {
			if k.Bound(seen.Address) {
				continue
			}
			if others := b.boundTo(seen.Address, c); len(others) > 0 {
				out = append(out, fmt.Sprintf("key %s was seen from %s, which belongs to %s", shortFP(k.Fingerprint), seen.Address, describeHolders(others)))
			}
		}
	}
	return out, nil
}

// merge folds another version of the same contact (a sync conflict) into
// this one: every address, key, event and sighting of either.
func (c *Contact) merge(o *Contact) {
	for _, e := range o.Emails {
		c.addEmail(e)
	}
	if c.Notes == "" {
		c.Notes = o.Notes
	}
	for _, ok := range o.Keys {
		k := c.keyByFingerprint(ok.Fingerprint)
		if k == nil {
			c.Keys = append(c.Keys, ok)
			continue
		}
		k.mergeMaterial(ok)
		for _, a := range ok.Addresses {
			if !k.Bound(a) {
				k.Addresses = append(k.Addresses, a)
			}
		}
		for _, e := range ok.Events {
			k.addEvent(e)
		}
		for _, s := range ok.Seen {
			mine := k.Sighting(s.Address)
			if mine == nil {
				k.Seen = append(k.Seen, s)
				continue
			}
			mine.Count = max(mine.Count, s.Count)
			if s.First.Before(mine.First) {
				mine.First, mine.Source = s.First, s.Source
			}
			if s.Last.After(mine.Last) {
				mine.Last = s.Last
			}
			for _, fp := range s.Conflicts {
				if !slices.Contains(mine.Conflicts, fp) {
					mine.Conflicts = append(mine.Conflicts, fp)
				}
			}
		}
	}
}

func (c *Contact) keyByFingerprint(fp string) *Key {
	for _, k := range c.Keys {
		if k.Fingerprint == fp {
			return k
		}
	}
	return nil
}
