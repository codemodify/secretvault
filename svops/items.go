package svops

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Items as the daemon hands them over, and what every interface says
// about them.

// Wipe zeroes an item's field values.
func Wipe(it *svrpc.Item) {
	for i := range it.Fields {
		clear(it.Fields[i].Value)
	}
}

// Field is the item's field called name.
func Field(it *svrpc.Item, name string) (svrpc.Field, bool) {
	for _, f := range it.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

// SecretField is the item's primary secret, as svcore.Item.Secret picks
// it: its password or secret field, else its first concealed or key one.
func SecretField(it *svrpc.Item) (svrpc.Field, bool) {
	for _, n := range []string{"password", "secret"} {
		if f, ok := Field(it, n); ok {
			return f, true
		}
	}
	for _, f := range it.Fields {
		if f.Type == svcore.FieldConcealed || f.Type == svcore.FieldKey {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

// SetField sets a field, replacing (and wiping) one of the same name.
func SetField(it *svrpc.Item, f svrpc.Field) {
	for i := range it.Fields {
		if it.Fields[i].Name == f.Name {
			clear(it.Fields[i].Value)
			it.Fields[i] = f
			return
		}
	}
	it.Fields = append(it.Fields, f)
}

// Short is the start of a revision, as people are shown it.
func Short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// Author says who wrote a revision, as far as its signature tells: the
// device's label and the first half of its key ID (labels are anyone's to
// choose; keys are not, and 64 bits are too many to grind out a lookalike)
// when the signature verifies, and otherwise what the revision claims,
// marked as a claim.
func Author(e svrpc.Entry) string {
	s := e.Signature
	key := s.Key
	if len(key) > 16 {
		key = key[:16]
	}
	named := strings.TrimSpace(s.Label + " " + key)
	switch s.Status {
	case svrpc.SigVerified:
		switch {
		case s.Mine:
			return s.Label + " (this device)"
		case s.Removed:
			return named + " (removed)"
		case s.Vouched:
			return named + " (vouched for)"
		}
		return named
	case svrpc.SigBad:
		return "BAD SIGNATURE, as " + named
	case svrpc.SigUnverified:
		return "unverified, key " + key
	}
	if len(e.Device) >= 8 {
		return "unsigned, device " + e.Device[:8]
	}
	return "unsigned"
}

// DeviceStanding is how far a device is to be believed, as this device
// sees it.
func DeviceStanding(d svrpc.Device) string {
	switch {
	case d.This && d.Removed:
		return "this device, removed"
	case d.This:
		return "this device"
	case d.Removed:
		return "removed"
	case d.Vouched:
		return "vouched for"
	}
	return "not vouched for"
}

// GroupFingerprint writes a hex fingerprint in groups of four, as people
// compare them; other fingerprints as they are.
func GroupFingerprint(fp string) string {
	if strings.HasPrefix(fp, "SHA256:") || len(fp)%4 != 0 {
		return fp
	}
	var groups []string
	for i := 0; i < len(fp); i += 4 {
		groups = append(groups, fp[i:i+4])
	}
	return strings.Join(groups, " ")
}

var unsafeSegment = regexp.MustCompile(`[\x00-\x1f\x7f/]`)

// PathSafe makes a label usable as one segment of an item name.
func PathSafe(s string) string {
	s = strings.TrimSpace(unsafeSegment.ReplaceAllString(s, "∕"))
	if s == "" || s == "." || s == ".." {
		return "unnamed"
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// UniqueName is name, or name (2), name (3)... if it is taken.
func UniqueName(taken map[string]bool, name string) string {
	if !taken[name] {
		return name
	}
	for n := 2; ; n++ {
		if c := fmt.Sprintf("%s (%d)", name, n); !taken[c] {
			return c
		}
	}
}

// FindItem looks an item up by listing (which shows attributes, never
// secrets).
func FindItem(ctx context.Context, cl *secretvault.Client, vault, item string) (bool, svrpc.Item, error) {
	entries, err := cl.List(ctx, vault, item)
	if err != nil {
		return false, svrpc.Item{}, err
	}
	for _, e := range entries {
		if e.Item.Name == item {
			return true, e.Item, nil
		}
	}
	return false, svrpc.Item{}, nil
}

// VaultName is the name of vault ("" for the default one).
func VaultName(ctx context.Context, cl *secretvault.Client, vault string) (string, error) {
	if vault != "" {
		return vault, nil
	}
	vs, err := cl.Vaults(ctx)
	if err != nil {
		return "", err
	}
	for _, v := range vs {
		if v.Default {
			return v.Name, nil
		}
	}
	return "", errors.New("there is no default vault; create one with 'secretvault init'")
}

// Conflict is an item changed on two devices at once: the version shown
// now, and every version still standing (the current one among them),
// oldest first, with their fields.
type Conflict struct {
	Current  svrpc.Entry   // without its fields
	Versions []svrpc.Entry // the heads, with their fields: the caller wipes them
}

// Conflicts reads an item's conflicting versions; Versions is empty when
// it has none.
func Conflicts(ctx context.Context, cl *secretvault.Client, vault, name string) (*Conflict, error) {
	cur, err := cl.Get(ctx, vault, name)
	if err != nil {
		return nil, err
	}
	Wipe(&cur.Item)
	c := &Conflict{Current: cur}
	if len(cur.Conflicts) == 0 {
		return c, nil
	}
	heads := map[string]bool{cur.Rev: true}
	for _, r := range cur.Conflicts {
		heads[r] = true
	}
	hist, err := cl.History(ctx, vault, name)
	if err != nil {
		return nil, err
	}
	for _, e := range hist {
		if !heads[e.Rev] {
			Wipe(&e.Item)
			continue
		}
		c.Versions = append(c.Versions, e)
	}
	return c, nil
}
