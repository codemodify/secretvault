package svtrust

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

// KeyType is the kind of a public key.
type KeyType string

// Key types.
const (
	OpenPGP     KeyType = "openpgp"     // an OpenPGP certificate
	X509        KeyType = "x509"        // an X.509 certificate, for S/MIME
	SSH         KeyType = "ssh"         // an SSH public key
	Secretvault KeyType = "secretvault" // a secretvault identity's recipient
)

// Level is how well a key is verified, from strongest to weakest:
// InPerson, Organisation, Logged, Published, TOFU, and None.
type Level string

// Verification levels.
const (
	None         Level = ""             // nothing says whose the key is
	TOFU         Level = "tofu"         // trusted on first use: seen before, not verified
	Published    Level = "published"    // the address's domain publishes it (WKD), or a keyserver checked the address by email
	Logged       Level = "logged"       // a transparency log records it (reserved: nothing records this yet)
	Organisation Level = "organisation" // an organisation vouches for it: its CA or its directory
	InPerson     Level = "in-person"    // fingerprints compared face to face, or their QR code scanned
)

// Rank orders levels: a higher rank is a stronger verification. Levels
// this version does not know (from a newer one) rank as None.
func (l Level) Rank() int {
	switch l {
	case TOFU:
		return 10
	case Published:
		return 20
	case Logged:
		return 30
	case Organisation:
		return 40
	case InPerson:
		return 50
	}
	return 0
}

// String names the level for people.
func (l Level) String() string {
	switch l {
	case None:
		return "not verified"
	case TOFU:
		return "trusted on first use"
	case Published:
		return "published"
	case Logged:
		return "in a transparency log"
	case Organisation:
		return "vouched for by an organisation"
	case InPerson:
		return "verified in person"
	}
	return string(l)
}

// ParseLevel reads a level by its name ("" and "none" are None).
func ParseLevel(s string) (Level, bool) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	if l == "none" {
		l = None
	}
	if l != None && l.Rank() == 0 {
		return None, false
	}
	return l, true
}

// How a key was verified. Each method implies a level (MethodLevel).
const (
	MethodFingerprint  = "fingerprint"      // fingerprints compared in person
	MethodQR           = "qr"               // their QR code scanned, in person
	MethodOrgCA        = "org-ca"           // the certificate chains to an organisation's CA
	MethodOrgDirectory = "org-directory"    // an organisation's directory lists it
	MethodLog          = "transparency-log" // a transparency log records it (reserved)
	MethodWKD          = "wkd"              // the address's domain publishes it (Web Key Directory)
	MethodKeyserver    = "keyserver-email"  // a keyserver that checks addresses by email (keys.openpgp.org) has it
	MethodTOFU         = "tofu"             // first seen in mail, or accepted as it is
)

var methodLevels = map[string]Level{
	MethodFingerprint:  InPerson,
	MethodQR:           InPerson,
	MethodOrgCA:        Organisation,
	MethodOrgDirectory: Organisation,
	MethodLog:          Logged,
	MethodWKD:          Published,
	MethodKeyserver:    Published,
	MethodTOFU:         TOFU,
}

// MethodLevel is the level a method of verification gives, None for a
// method this version does not know.
func MethodLevel(method string) Level { return methodLevels[method] }

// Contact is a person (or an organisation) and their keys. It is kept in a
// vault as a record of kind "contact" (RecordKind), as JSON; members a
// newer version adds are kept when this version rewrites the record.
type Contact struct {
	// ID is the record's ID; it is not part of the JSON.
	ID string `json:"-"`
	// Updated is when the record was last written; not part of the JSON.
	Updated time.Time `json:"-"`

	// Version is the record's format version, 1.
	Version int `json:"v"`
	// Name is what the person is called: given by you, or, for a contact
	// made from mail, the address it came from.
	Name string `json:"name"`
	// Emails are the person's addresses: those given by you and those
	// bound to their keys.
	Emails []string `json:"emails,omitempty"`
	Notes  string   `json:"notes,omitempty"`
	// Organisation marks an organisation rather than a person: its X.509
	// CA certificates vouch for the certificates they issue.
	Organisation bool `json:"organisation,omitempty"`
	// Origin says how the contact came to be: OriginAdded, OriginMail,
	// OriginLookup or OriginQR.
	Origin  string    `json:"origin,omitempty"`
	Created time.Time `json:"created"`
	Keys    []*Key    `json:"keys,omitempty"`

	unknown map[string]json.RawMessage
}

// Origins of a contact.
const (
	OriginAdded  = "added"  // by you
	OriginMail   = "mail"   // made when a key was first seen in mail
	OriginLookup = "lookup" // made from a WKD, keyserver or directory lookup
	OriginQR     = "qr"     // made from a scanned QR code
)

// Automatic reports whether the contact was made by secretvault rather
// than by you: from mail or a lookup. Its name then says nothing.
func (c *Contact) Automatic() bool { return c.Origin == OriginMail || c.Origin == OriginLookup }

// Key is one public key of a contact, with what is known about it.
type Key struct {
	Type KeyType `json:"type"`
	// Fingerprint identifies the key: for OpenPGP the primary key's
	// fingerprint and for X.509 the SHA-256 of the certificate, both in
	// upper-case hex; for SSH "SHA256:..." as ssh-keygen prints it; for a
	// secretvault recipient the SHA-256 of its text, in hex.
	Fingerprint string `json:"fingerprint"`
	// Material is the key itself: an OpenPGP transferable public key
	// (binary), a certificate (DER), an authorized_keys line, or a
	// recipient's text.
	Material []byte `json:"material"`
	// Chain holds an X.509 certificate's intermediates (DER), for checking
	// it against an organisation's CA.
	Chain [][]byte `json:"chain,omitempty"`
	// Subkeys are an OpenPGP key's subkey fingerprints, so a signature by
	// a subkey finds the key.
	Subkeys []string `json:"subkeys,omitempty"`
	// Label is the key's own description: its primary user ID, its
	// certificate's subject, or its comment.
	Label string `json:"label,omitempty"`
	// Addresses are the addresses bound to the key: a message from one of
	// them, signed by this key, is from this person as far as the key's
	// verification goes.
	Addresses []string  `json:"addresses,omitempty"`
	Added     time.Time `json:"added"`
	// Source says where the key came from: a file, a URL, a message.
	Source string `json:"source,omitempty"`
	// Events are how the key was verified, oldest first.
	Events []Event `json:"events,omitempty"`
	// Seen counts the messages the key signed, per address (trust on
	// first use).
	Seen []Sighting `json:"seen,omitempty"`

	unknown map[string]json.RawMessage
}

// Event is one verification of a key.
type Event struct {
	Level  Level     `json:"level"`
	Method string    `json:"method"`
	By     string    `json:"by,omitempty"` // who recorded it: you, or the program that did
	At     time.Time `json:"at"`
	// Source is where the verification came from: "mail from alice@x on
	// 2026-09-01", a URL, a CA's name.
	Source string `json:"source,omitempty"`
	// Addresses are the addresses the verification covers. None means
	// the key as a whole: it is this person's, at every address bound to
	// it.
	Addresses []string `json:"addresses,omitempty"`

	unknown map[string]json.RawMessage
}

// Sighting is how often a key was seen for an address.
type Sighting struct {
	Address string    `json:"address"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Count   int       `json:"count"`
	Source  string    `json:"source,omitempty"` // where it was first seen
	// Conflicts are the keys (fingerprints) that were already bound to the
	// address when this key was first seen for it: a warning to show.
	Conflicts []string `json:"conflicts,omitempty"`

	unknown map[string]json.RawMessage
}

// covers reports whether the event verifies the key for addr: an event
// for the whole key covers every address bound to it.
func (e *Event) covers(k *Key, addr string) bool {
	if len(e.Addresses) == 0 {
		return addr == "" || k.Bound(addr)
	}
	return containsAddr(e.Addresses, addr)
}

// Bound reports whether addr is bound to the key.
func (k *Key) Bound(addr string) bool { return containsAddr(k.Addresses, addr) }

// Best is the key's strongest verification, and the event behind it (nil
// when there is none).
func (k *Key) Best() (Level, *Event) { return bestOf(k, k.Events, "") }

// BestFor is the key's strongest verification for addr.
func (k *Key) BestFor(addr string) (Level, *Event) { return bestOf(k, k.Events, addr) }

func bestOf(k *Key, events []Event, addr string) (Level, *Event) {
	var best *Event
	for i := range events {
		e := &events[i]
		if addr != "" && !e.covers(k, addr) {
			continue
		}
		if best == nil || e.Level.Rank() > best.Level.Rank() || e.Level.Rank() == best.Level.Rank() && e.At.Before(best.At) {
			best = e
		}
	}
	if best == nil || best.Level.Rank() == 0 {
		return None, nil
	}
	return best.Level, best
}

// Sighting returns the key's sighting for addr.
func (k *Key) Sighting(addr string) *Sighting {
	for i := range k.Seen {
		if sameAddr(k.Seen[i].Address, addr) {
			return &k.Seen[i]
		}
	}
	return nil
}

// Best is the strongest verification of any of the contact's keys.
func (c *Contact) Best() Level {
	best := None
	for _, k := range c.Keys {
		if l, _ := k.Best(); l.Rank() > best.Rank() {
			best = l
		}
	}
	return best
}

// Key returns the contact's key with this fingerprint (or subkey
// fingerprint, or OpenPGP key ID).
func (c *Contact) Key(fp string) *Key {
	fp = NormalizeFingerprint(fp)
	for _, k := range c.Keys {
		if k.matches(fp) {
			return k
		}
	}
	return nil
}

// addEmail adds addr to the contact's addresses unless it is there.
func (c *Contact) addEmail(addr string) {
	if addr != "" && !containsAddr(c.Emails, addr) {
		c.Emails = append(c.Emails, addr)
	}
}

// bind binds addr to the key, and adds it to the contact's addresses.
func (c *Contact) bind(k *Key, addr string) {
	if addr != "" && !k.Bound(addr) {
		k.Addresses = append(k.Addresses, addr)
	}
	c.addEmail(addr)
}

// JSON with unknown members kept. Each type is decoded as a plain copy of
// itself; members its fields do not name are kept and written back.

func (c *Contact) UnmarshalJSON(b []byte) error {
	type plain Contact
	u, err := decodeKeeping(b, (*plain)(c))
	c.unknown = u
	return err
}

func (c Contact) MarshalJSON() ([]byte, error) {
	type plain Contact
	return encodeKeeping(plain(c), c.unknown)
}

func (k *Key) UnmarshalJSON(b []byte) error {
	type plain Key
	u, err := decodeKeeping(b, (*plain)(k))
	k.unknown = u
	return err
}

func (k Key) MarshalJSON() ([]byte, error) {
	type plain Key
	return encodeKeeping(plain(k), k.unknown)
}

func (e *Event) UnmarshalJSON(b []byte) error {
	type plain Event
	u, err := decodeKeeping(b, (*plain)(e))
	e.unknown = u
	return err
}

func (e Event) MarshalJSON() ([]byte, error) {
	type plain Event
	return encodeKeeping(plain(e), e.unknown)
}

func (s *Sighting) UnmarshalJSON(b []byte) error {
	type plain Sighting
	u, err := decodeKeeping(b, (*plain)(s))
	s.unknown = u
	return err
}

func (s Sighting) MarshalJSON() ([]byte, error) {
	type plain Sighting
	return encodeKeeping(plain(s), s.unknown)
}

// decodeKeeping decodes b into v (a pointer to a struct) and returns the
// object's members that no field of v names.
func decodeKeeping(b []byte, v any) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(b, v); err != nil {
		return nil, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	known := jsonNames(reflect.TypeOf(v).Elem())
	for name := range all {
		if slices.ContainsFunc(known, func(k string) bool { return strings.EqualFold(k, name) }) {
			delete(all, name)
		}
	}
	if len(all) == 0 {
		return nil, nil
	}
	return all, nil
}

// encodeKeeping encodes v with the unknown members added back.
func encodeKeeping(v any, unknown map[string]json.RawMessage) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(unknown) == 0 {
		return b, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	for name, raw := range unknown {
		if _, ok := all[name]; !ok {
			all[name] = raw
		}
	}
	return json.Marshal(all)
}

var jsonNamesCache sync.Map // reflect.Type -> []string

// jsonNames are the member names a struct type's fields are encoded as.
func jsonNames(t reflect.Type) []string {
	if names, ok := jsonNamesCache.Load(t); ok {
		return names.([]string)
	}
	var names []string
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = f.Name
		}
		names = append(names, name)
	}
	jsonNamesCache.Store(t, names)
	return names
}
