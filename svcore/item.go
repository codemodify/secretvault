package svcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An Item is one stored secret with everything about it: a password-manager
// login, a Secret Service item, a pass entry, a KV secret, a key. Every face
// of secretvault maps its own notion onto this one shape, so an item created
// through one face is visible through all of them.
type Item struct {
	// Kind says what the item is, as a short lowercase word; see Kinds.
	Kind string `json:"kind"`

	// Name is the item's unique path in its vault, like "web/github.com" or
	// "prod/db/password". It is what pass, Vault KV and the CLI address.
	Name string `json:"name"`

	// Label is a free-form title for people (the Secret Service label).
	Label string `json:"label,omitempty"`

	// Attrs are lookup attributes (the Secret Service attributes: service,
	// username, xdg:schema, ...). They are encrypted like everything else.
	Attrs map[string]string `json:"attrs,omitempty"`

	Tags []string `json:"tags,omitempty"`

	// Fields hold the values, secret or not, in order.
	Fields []Field `json:"fields,omitempty"`
}

// A Field is one named value of an item.
type Field struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value []byte `json:"value"`
}

// Field types. Concealed values are secrets: shown masked, copied with a
// timeout, never logged.
const (
	FieldText      = "text"
	FieldConcealed = "concealed"
	FieldURL       = "url"
	FieldEmail     = "email"
	FieldOTP       = "otp"    // an otpauth:// URI or a base32 TOTP seed
	FieldJSON      = "json"   // structured data, e.g. a Vault KV v2 map
	FieldBinary    = "binary" // raw bytes
	FieldKey       = "key"    // private key material
)

// Kinds are the item kinds the faces know. Others are allowed and kept as
// they are.
var Kinds = []string{
	"login",    // username, password, URLs, OTP
	"password", // a bare password (pass, Secret Service)
	"note",     // secure note
	"card",     // payment card
	"identity", // name, address, documents
	"ssh-key",  // served by the SSH agent face
	"api-key",  // tokens, cloud credentials
	"key",      // a cryptographic key used in place (transit, age identities)
	"kv",       // Vault-style key/value data
	"otp",      // an authenticator entry: an otpauth:// URI and little else
	"generic",
}

// Secret returns the item's primary secret: the field named "password" or
// "secret", else the first concealed or key field.
func (it *Item) Secret() (Field, bool) {
	for _, n := range []string{"password", "secret"} {
		if f, ok := it.Field(n); ok {
			return f, true
		}
	}
	for _, f := range it.Fields {
		if f.Type == FieldConcealed || f.Type == FieldKey {
			return f, true
		}
	}
	return Field{}, false
}

// Field returns the named field.
func (it *Item) Field(name string) (Field, bool) {
	for _, f := range it.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// SetField replaces the named field's value, or appends the field.
func (it *Item) SetField(f Field) {
	for i := range it.Fields {
		if it.Fields[i].Name == f.Name {
			clear(it.Fields[i].Value)
			it.Fields[i] = f
			return
		}
	}
	it.Fields = append(it.Fields, f)
}

// Wipe zeroes every field value. Names and labels are Go strings and cannot
// be zeroed; secrets never go in them.
func (it *Item) Wipe() {
	for i := range it.Fields {
		clear(it.Fields[i].Value)
	}
}

// clone deep-copies the item so callers never share memory with the cache.
func (it Item) clone() Item {
	out := it
	if it.Attrs != nil {
		out.Attrs = make(map[string]string, len(it.Attrs))
		for k, v := range it.Attrs {
			out.Attrs[k] = v
		}
	}
	out.Tags = append([]string(nil), it.Tags...)
	out.Fields = make([]Field, len(it.Fields))
	for i, f := range it.Fields {
		out.Fields[i] = Field{Name: f.Name, Type: f.Type, Value: append([]byte(nil), f.Value...)}
	}
	if len(it.Fields) == 0 {
		out.Fields = nil
	}
	return out
}

// ErrName is an item name that is empty, malformed or too long.
var ErrName = errors.New("svcore: bad item name")

// CheckName accepts path-like names: non-empty UTF-8 segments separated by
// '/', no leading or trailing '/', no "." or ".." segments, no control
// characters, at most 1024 bytes.
func CheckName(name string) error {
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q", ErrName, name)
		}
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %q has a control character", ErrName, name)
		}
	}
	return nil
}

func (it *Item) check() error {
	if err := CheckName(it.Name); err != nil {
		return err
	}
	if it.Kind == "" {
		return fmt.Errorf("svcore: item %q has no kind", it.Name)
	}
	seen := map[string]bool{}
	for _, f := range it.Fields {
		if f.Name == "" || seen[f.Name] {
			return fmt.Errorf("svcore: item %q has an empty or repeated field name %q", it.Name, f.Name)
		}
		seen[f.Name] = true
		if f.Type == "" {
			return fmt.Errorf("svcore: field %q of %q has no type", f.Name, it.Name)
		}
	}
	return nil
}

// payload is the plaintext of a revision.
type payload struct {
	Type    string          `json:"type"` // "item", or a record kind (records.go)
	Deleted bool            `json:"deleted,omitempty"`
	Item    *Item           `json:"item,omitempty"`
	Record  json.RawMessage `json:"record,omitempty"`
}

const payloadItem = "item"

func encodePayload(p payload) ([]byte, error) { return json.Marshal(p) }

func decodePayload(b []byte) (payload, error) {
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("svcore: payload: %w", err)
	}
	if p.Type == "" {
		return p, errors.New("svcore: payload has no type")
	}
	if p.Type != payloadItem {
		// A record (records.go), possibly of a kind from a newer version:
		// it is kept, authenticated, and ignored by whoever does not ask
		// for its kind, so a vault shared with a newer version keeps working.
		return p, nil
	}
	if !p.Deleted {
		if p.Item == nil {
			return p, errors.New("svcore: payload has no item")
		}
		if err := p.Item.check(); err != nil {
			return p, err
		}
	}
	return p, nil
}
