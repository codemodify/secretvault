package svcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svformat"
)

// Devices, signatures and the policy (docs/format.md, "Signatures",
// "Device records", "The policy record").
//
// Everyone who can open a vault holds the same master key, so the key
// cannot tell who wrote what. A handle given a device key (Options.Signer)
// signs every revision it writes; a vault's registry, kept in records of
// the kind "device", says which device each key belongs to. Every
// revision's signature is checked against the registry and reported with
// it (Entry.Signature); a vault whose policy requires signatures counts
// only revisions signed by a registered device.
//
// The registry, like everything in the vault, can be written by anyone
// who can open the vault. What it can still promise:
//
//   - A key is registered only by a record that key signed itself, in the
//     object named after the key (svformat.DeviceKeyID). Nobody can
//     register a key they do not hold, or bind someone else's key to a
//     device of theirs, so no one can claim another's writes.
//   - Nobody can sign as a registered device without its private key, so
//     a verified signature names the device that made it.
//   - A key once registered stays registered: removing a device marks it
//     so, and what it signed still verifies.
//   - Which devices this device vouches for is said only in revisions it
//     signs (VouchDevice). A device is vouched for when this device, or a
//     device it vouches for, vouched for it: nobody else can make a device
//     look vouched for here.
//
// What it cannot promise: that a registered device is the person or
// machine its label says. Anyone who can open the vault can register a
// device of their own under any label; comparing key IDs out of band, and
// vouching, is what tells them apart.

// Record kinds the engine keeps for itself.
const (
	DeviceKind = "device" // a device's registration: a deviceRecord
	PolicyKind = "policy" // the vault's policy: a Policy, in the object PolicyID names
)

// SigStatus is what a revision's signature shows.
type SigStatus string

const (
	// SigUnsigned is a revision that carries no signature.
	SigUnsigned SigStatus = "unsigned"
	// SigUnverified is a signature by a key the registry does not hold
	// (not synced here yet, or never registered), or of an algorithm this
	// version does not know: it says nothing.
	SigUnverified SigStatus = "unverified"
	// SigBad is a signature that does not verify with the registered key
	// it names: the revision was changed, or made by someone posing as
	// that device.
	SigBad SigStatus = "bad"
	// SigVerified is a good signature by a registered device.
	SigVerified SigStatus = "verified"
)

// Signature says who signed a revision, as far as the vault's registry
// tells.
type Signature struct {
	Status SigStatus
	Key    svformat.ID // the key it names (zero when unsigned)
	Device svformat.ID // the device that key is registered to (SigVerified, SigBad)
	Label  string      // that device's label now

	// Removed: the device has since been removed from the vault.
	Removed bool

	// Vouched: vouched for by this handle's device (DeviceInfo.Vouched).
	Vouched bool

	// Mine: made by this handle's own key.
	Mine bool
}

// DeviceInfo is a device registered in a vault.
type DeviceInfo struct {
	Key        svformat.ID // its signing key's ID, and fingerprint
	Public     ed25519.PublicKey
	Device     svformat.ID
	Label      string
	Registered time.Time // when it registered itself, by its own clock
	Removed    bool

	// This is this handle's own key.
	This bool

	// Vouched says this handle's device vouches for it: this device, one
	// it vouched for, or one those vouched for, and so on.
	Vouched bool

	// Vouches are the keys it vouches for.
	Vouches []svformat.ID
}

// Policy is what a vault demands of the revisions it counts. It is kept
// in the vault, the same for every device, and changes only by a
// revision a registered device signed.
type Policy struct {
	// RequireSignatures counts only revisions signed by a registered
	// device; the rest (unsigned, badly signed, or signed by an unknown
	// key) are reported and ignored.
	RequireSignatures bool `json:"require_signatures"`
}

var (
	// ErrBadSignature is a revision whose signature does not verify.
	ErrBadSignature = errors.New("svcore: the signature does not verify: the revision was changed, or made by someone posing as the device it names")

	// ErrUnknownSigner is a revision signed by a key no device registered.
	ErrUnknownSigner = errors.New("svcore: signed by a key no device registered in this vault")

	// ErrSignatureRequired is a revision the policy does not count, or a
	// write this handle cannot sign.
	ErrSignatureRequired = errors.New("svcore: the vault requires revisions signed by a registered device")

	// ErrNoDeviceKey is a device operation on a handle with no key.
	ErrNoDeviceKey = errors.New("svcore: this handle has no device key")

	// ErrNoDevice is a device the registry does not hold.
	ErrNoDevice = errors.New("svcore: no such device in this vault")
)

// deviceRecord is the data of a device record (docs/format.md).
type deviceRecord struct {
	Alg     string        `json:"alg"`    // "ed25519"
	Key     []byte        `json:"key"`    // the public key
	Device  svformat.ID   `json:"device"` // the device it signs for (its revisions' 0x81)
	Label   string        `json:"label,omitempty"`
	Removed bool          `json:"removed,omitempty"`
	Vouches []svformat.ID `json:"vouches,omitempty"` // keys it vouches for: counted only as it signed them

	id svformat.ID // DeviceKeyID(Key)
}

func parseDeviceRecord(b []byte) *deviceRecord {
	var d deviceRecord
	if json.Unmarshal(b, &d) != nil || d.Alg != "ed25519" || len(d.Key) != ed25519.PublicKeySize ||
		d.Device.IsZero() || len(d.Label) > 256 || len(d.Vouches) > 1024 {
		return nil
	}
	d.id = svformat.DeviceKeyID(d.Key)
	return &d
}

// PolicyID is the object that holds a vault's policy: one per vault, so
// that every device writes the same object and conflicts resolve as any
// other.
func PolicyID(vault svformat.ID) svformat.ID {
	sum := sha256.Sum256(append([]byte("secretvault sv1 policy"), vault[:]...))
	var id svformat.ID
	copy(id[:], sum[:])
	return id
}

// deviceEntry is a registered key, as the index settles it.
type deviceEntry struct {
	key        svformat.ID
	pub        ed25519.PublicKey
	device     svformat.ID          // the device its first registration names
	devices    map[svformat.ID]bool // every device it registered for
	registered time.Time
	label      string
	removed    bool
	vouches    []svformat.ID
	vouched    bool
}

// tag names what a signature was checked against: a key's devices only
// ever grow in number.
func (e *deviceEntry) tag() string { return fmt.Sprintf("%x/%d", e.pub, len(e.devices)) }

// check sets r.status from the registry. A status once settled for a key
// is kept until the key's registration changes.
func (x *index) check(r *revision) {
	s := r.hdr.Signature
	if s == nil {
		r.status, r.checkedFor = SigUnsigned, ""
		return
	}
	e := x.reg[s.Key]
	if e == nil || s.Alg != svformat.SigEd25519 {
		r.status, r.checkedFor = SigUnverified, ""
		return
	}
	tag := e.tag()
	if r.checkedFor == tag {
		return
	}
	r.checkedFor = tag
	switch {
	case r.signed == nil, !e.devices[r.hdr.Device], !s.Verify(e.pub, r.signed):
		r.status = SigBad
	default:
		r.status = SigVerified
	}
}

// counts reports whether a revision counts under the vault's policy.
func (x *index) counts(r *revision) bool {
	return !x.policy.RequireSignatures || r.status == SigVerified
}

// proves reports whether r registers the key its object is named after:
// a device record for that key, signed by it, for the device it names.
// What a revision proves never changes, so it is worked out once.
func proves(o *object, r *revision) bool {
	if r.proof == 0 {
		d, s := r.device, r.hdr.Signature
		r.proof = -1
		if d != nil && d.id == o.id && s != nil && s.Key == o.id && r.hdr.Device == d.Device &&
			r.signed != nil && s.Verify(d.Key, r.signed) {
			r.proof = 1
		}
	}
	return r.proof > 0
}

// buildRegistry finds every registered key, and reports whether the set
// of keys (or a key's devices) changed. A key is registered for every
// device it registered itself for: only the key could have made any of
// those registrations, and none undoes another (a key file copied to a
// second device registers it for both). Its first registration names
// the device it is shown as, and when it registered.
func (x *index) buildRegistry() bool {
	reg := map[svformat.ID]*deviceEntry{}
	x.regProblems = x.regProblems[:0]
	for id := range x.deviceObjs {
		o := x.objects[id]
		var proofs []*revision
		for _, r := range o.revs {
			if proves(o, r) {
				proofs = append(proofs, r)
			}
		}
		if len(proofs) == 0 {
			continue
		}
		sort.Slice(proofs, func(i, j int) bool {
			a, b := proofs[i], proofs[j]
			if a.hdr.Time != b.hdr.Time {
				return a.hdr.Time < b.hdr.Time
			}
			return bytes.Compare(a.id[:], b.id[:]) < 0
		})
		first := proofs[0]
		e := &deviceEntry{key: o.id, pub: first.device.Key, device: first.device.Device, devices: map[svformat.ID]bool{},
			registered: time.Unix(0, first.hdr.Time).UTC()}
		for _, r := range proofs {
			e.devices[r.device.Device] = true
		}
		reg[id] = e
	}
	changed := len(reg) != len(x.reg)
	for id, e := range reg {
		if old := x.reg[id]; old == nil || old.tag() != e.tag() || old.device != e.device {
			changed = true
		}
	}
	x.reg = reg
	return changed
}

// ancestors is every revision of o that one of from descends from: its
// parents, their parents, and so on, through any revision of o. A
// revision's parents are part of what its ID (and its signature) cover,
// so a revision that counts supersedes all it descends from, whoever
// wrote what lies between.
//
// Signed revisions with the same signature are one revision: anyone who
// can open the vault can seal a signed revision's payload again, under
// the same content key and so the same signature, as a copy with another
// ID. Such a copy is superseded wherever what it copies is, so it cannot
// bring back a record or a policy that something later replaced.
func ancestors(o *object, from ...*revision) map[svformat.RevID]bool {
	var twins map[string][]svformat.RevID
	seen := map[svformat.RevID]bool{}
	var stack []svformat.RevID
	for _, r := range from {
		stack = append(stack, r.hdr.Parents...)
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		p := o.revs[id]
		if p == nil {
			continue
		}
		stack = append(stack, p.hdr.Parents...)
		if s := p.hdr.Signature; s != nil {
			if twins == nil {
				twins = map[string][]svformat.RevID{}
				for tid, t := range o.revs {
					if ts := t.hdr.Signature; ts != nil {
						k := string(ts.Key[:]) + string(ts.Sig)
						twins[k] = append(twins[k], tid)
					}
				}
			}
			stack = append(stack, twins[string(s.Key[:])+string(s.Sig)]...)
		}
	}
	return seen
}

// headsOf finds the heads among members, revisions of o: those no member
// descends from. Winner first.
func headsOf(o *object, members []*revision) []*revision {
	older := ancestors(o, members...)
	var heads []*revision
	for _, r := range members {
		if !older[r.id] {
			heads = append(heads, r)
		}
	}
	sortHeads(heads)
	return heads
}

func sortHeads(heads []*revision) {
	sort.Slice(heads, func(i, j int) bool {
		a, b := heads[i], heads[j]
		if a.hdr.Time != b.hdr.Time {
			return a.hdr.Time > b.hdr.Time
		}
		return bytes.Compare(a.id[:], b.id[:]) > 0
	})
}

// readPolicy settles the policy from the policy object's revisions that a
// registered device signed, and reports whether it changed.
func (x *index) readPolicy(vault svformat.ID) bool {
	var p Policy
	if o := x.objects[PolicyID(vault)]; o != nil {
		var signed []*revision
		for _, r := range o.revs {
			if r.policy != nil && r.status == SigVerified {
				signed = append(signed, r)
			}
		}
		if heads := headsOf(o, signed); len(heads) > 0 && heads[0].policy != nil {
			p = *heads[0].policy
		}
	}
	changed := p != x.policy
	x.policy = p
	return changed
}

// settleDevices reads each registered device's label, removal and
// vouches, and which of them own vouches for.
//
// The label is the newest record's. A removal holds until a record made
// after it (one that descends from it) says otherwise, so a device that
// registers again without having seen its removal stays removed. Vouches
// are the newest the device itself signed.
func (x *index) settleDevices(own svformat.ID) {
	for id, e := range x.reg {
		o := x.objects[id]
		var state, self, removals, kept []*revision
		for _, r := range o.revs {
			// A badly signed revision is someone's forgery: whatever the
			// policy, it says nothing about a device.
			if r.device == nil || r.device.id != id || !e.devices[r.device.Device] || !x.counts(r) || r.status == SigBad {
				continue
			}
			state = append(state, r)
			if r.device.Removed {
				removals = append(removals, r)
			} else {
				kept = append(kept, r)
			}
			if proves(o, r) {
				self = append(self, r)
			}
		}
		e.label, e.removed, e.vouches, e.vouched = "", false, nil, false
		if heads := headsOf(o, state); len(heads) > 0 {
			e.label = heads[0].device.Label
		}
		if len(removals) > 0 {
			undone := ancestors(o, kept...)
			for _, r := range removals {
				if !undone[r.id] {
					e.removed = true
					break
				}
			}
		}
		if heads := headsOf(o, self); len(heads) > 0 {
			e.vouches = heads[0].device.Vouches
		}
	}
	// Vouched: reachable from own through the vouches of devices not
	// removed.
	start := x.reg[own]
	if start == nil || start.removed {
		return
	}
	start.vouched = true
	queue := []*deviceEntry{start}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		for _, k := range e.vouches {
			if n := x.reg[k]; n != nil && !n.vouched && !n.removed {
				n.vouched = true
				queue = append(queue, n)
			}
		}
	}
}

// signature describes r's signature.
func (x *index) signature(r *revision, own svformat.ID) Signature {
	s := Signature{Status: r.status}
	if r.hdr.Signature == nil {
		return s
	}
	s.Key = r.hdr.Signature.Key
	e := x.reg[s.Key]
	switch {
	case e == nil || r.status == SigUnverified:
	case r.status == SigBad:
		// Whom it poses as, and nothing more.
		s.Device, s.Label = r.hdr.Device, e.label
	default:
		s.Device, s.Label, s.Removed, s.Vouched = r.hdr.Device, e.label, e.removed, e.vouched
		s.Mine = s.Key == own && !own.IsZero()
	}
	return s
}

func (e *deviceEntry) info(own svformat.ID) DeviceInfo {
	return DeviceInfo{Key: e.key, Public: slices.Clone(e.pub), Device: e.device, Label: e.label, Registered: e.registered,
		Removed: e.removed, This: e.key == own && !own.IsZero(), Vouched: e.vouched, Vouches: slices.Clone(e.vouches)}
}

// ownKey is this handle's key ID, zero without one.
func (v *Vault) ownKey() svformat.ID {
	if v.opts.Signer == nil {
		return svformat.ID{}
	}
	return v.opts.Signer.ID()
}

// Devices lists the devices registered in the vault, in the order they
// registered.
func (v *Vault) Devices() ([]DeviceInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	own := v.ownKey()
	var out []DeviceInfo
	for _, e := range v.idx.reg {
		out = append(out, e.info(own))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Registered.Equal(out[j].Registered) {
			return out[i].Registered.Before(out[j].Registered)
		}
		return bytes.Compare(out[i].Key[:], out[j].Key[:]) < 0
	})
	return out, nil
}

// Device finds a registered device by its key ID, or by the first digits
// of it, as people type them. Only keys: a device ID is only what a key
// registered under, and anyone can register a key whose ID starts as
// another device's ID does, or a device whose ID starts as another's key
// ID does.
func (v *Vault) Device(ref string) (DeviceInfo, error) {
	devs, err := v.Devices()
	if err != nil {
		return DeviceInfo{}, err
	}
	ref = strings.ToLower(ref)
	var found []DeviceInfo
	for _, d := range devs {
		if ref != "" && strings.HasPrefix(d.Key.String(), ref) {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return DeviceInfo{}, fmt.Errorf("%w: %q", ErrNoDevice, ref)
	case 1:
		return found[0], nil
	}
	return DeviceInfo{}, fmt.Errorf("svcore: %q names more than one device; give more of its key ID", ref)
}

// RegisterDevice registers this handle's device key in the vault's
// registry, for its device, under label. A key already registered for
// this device, even one since removed, is left as it is (registered
// reports false): a device removed from elsewhere does not come back by
// itself. A key registered for another device (its key file copied here)
// is registered for this one too, keeping its label and standing.
func (v *Vault) RegisterDevice(label string) (info DeviceInfo, registered bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return DeviceInfo{}, false, ErrLocked
	}
	if v.opts.Signer == nil {
		return DeviceInfo{}, false, ErrNoDeviceKey
	}
	own := v.ownKey()
	rec := deviceRecord{Alg: "ed25519", Key: v.opts.Signer.Public(), Device: v.opts.Device, Label: label}
	if e := v.idx.reg[own]; e != nil {
		if e.devices[v.opts.Device] {
			return e.info(own), false, nil
		}
		rec.Label, rec.Removed, rec.Vouches = e.label, e.removed, slices.Clone(e.vouches)
	}
	if err := v.writeDevice(own, rec); err != nil {
		return DeviceInfo{}, false, err
	}
	e := v.idx.reg[own]
	if e == nil {
		return DeviceInfo{}, false, errors.New("svcore: the device record was written but does not register the key")
	}
	return e.info(own), true, nil
}

// LabelDevice gives a registered device a new label. Labelling this
// handle's own device also registers it again if it was removed.
func (v *Vault) LabelDevice(key svformat.ID, label string) (DeviceInfo, error) {
	return v.changeDevice(key, func(d *deviceRecord, own bool) {
		d.Label = label
		if own {
			d.Removed = false
		}
	})
}

// RemoveDevice marks a device removed from the vault. Its signatures still
// verify, and name it as removed; it still opens the vault, and can still
// write, until the vault key is rotated without it (Rotate).
func (v *Vault) RemoveDevice(key svformat.ID) error {
	_, err := v.changeDevice(key, func(d *deviceRecord, _ bool) { d.Removed = true })
	return err
}

// VouchDevice records that this handle's device vouches for another
// device's key (or, with vouch false, no longer does): that someone
// compared its key ID with the one that device shows for itself.
func (v *Vault) VouchDevice(key svformat.ID, vouch bool) (DeviceInfo, error) {
	v.mu.Lock()
	own := v.ownKey()
	locked := v.masters == nil
	var target *deviceEntry
	if !locked {
		target = v.idx.reg[key]
	}
	v.mu.Unlock()
	switch {
	case locked:
		return DeviceInfo{}, ErrLocked
	case own.IsZero():
		return DeviceInfo{}, ErrNoDeviceKey
	case target == nil:
		return DeviceInfo{}, fmt.Errorf("%w: %s", ErrNoDevice, key)
	case key == own:
		return DeviceInfo{}, errors.New("svcore: a device does not vouch for itself")
	}
	if _, err := v.changeDevice(own, func(d *deviceRecord, _ bool) {
		d.Vouches = slices.DeleteFunc(d.Vouches, func(k svformat.ID) bool { return k == key })
		if vouch {
			d.Vouches = append(d.Vouches, key)
		}
	}); err != nil {
		return DeviceInfo{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return DeviceInfo{}, ErrLocked
	}
	e := v.idx.reg[key]
	if e == nil {
		return DeviceInfo{}, fmt.Errorf("%w: %s", ErrNoDevice, key)
	}
	return e.info(own), nil
}

// changeDevice writes a new revision of a registered device's record.
func (v *Vault) changeDevice(key svformat.ID, change func(d *deviceRecord, own bool)) (DeviceInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return DeviceInfo{}, ErrLocked
	}
	e := v.idx.reg[key]
	if e == nil {
		return DeviceInfo{}, fmt.Errorf("%w: %s", ErrNoDevice, key)
	}
	own := v.ownKey()
	rec := deviceRecord{Alg: "ed25519", Key: e.pub, Device: e.device, Label: e.label, Removed: e.removed}
	if key == own {
		// Only a device's own revisions say whom it vouches for; and
		// what it signs for its own device registers the key for it.
		rec.Vouches = slices.Clone(e.vouches)
		rec.Device = v.opts.Device
	}
	change(&rec, key == own)
	if len(rec.Label) > 256 {
		return DeviceInfo{}, errors.New("svcore: a device label is at most 256 bytes")
	}
	if err := v.writeDevice(key, rec); err != nil {
		return DeviceInfo{}, err
	}
	return v.idx.reg[key].info(own), nil
}

// writeDevice writes a device record into the key's object. The caller
// holds v.mu, with the vault open.
func (v *Vault) writeDevice(key svformat.ID, rec deviceRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	var parents []*revision
	if o := v.idx.objects[key]; o != nil {
		parents = o.heads
	}
	_, err = v.write(key, parents, payload{Type: DeviceKind, Record: raw})
	return err
}

// Policy is the vault's policy.
func (v *Vault) Policy() (Policy, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Policy{}, ErrLocked
	}
	return v.idx.policy, nil
}

// SetPolicy changes the vault's policy. Only a registered device can: a
// policy counts only as a registered device signed it.
//
// Requiring signatures first writes again, signed, the current state of
// every object whose winning revision is unsigned, so that nothing
// written before signatures is lost: this device adopts that state as
// its own (its signature on it says it did), and what came before stays
// in the history, reported as not counted. A winner with a bad signature,
// or one by a key the registry does not hold, is not adopted: it is
// ignored from then on, and the object falls back to its newest revision
// that counts.
func (v *Vault) SetPolicy(p Policy) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return ErrLocked
	}
	id := PolicyID(v.desc.ID)
	if !v.canSign(id, payload{Type: PolicyKind}) {
		return fmt.Errorf("%w: register this device first", ErrSignatureRequired)
	}
	if p == v.idx.policy {
		return nil
	}
	if p.RequireSignatures {
		for oid, o := range v.idx.objects {
			if len(o.heads) == 0 || o.heads[0].status != SigUnsigned {
				continue
			}
			if err := v.writeAgain(oid, o, true); err != nil {
				return fmt.Errorf("svcore: signing the current state before requiring signatures: %w", err)
			}
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var parents []*revision
	if o := v.idx.objects[id]; o != nil {
		parents = o.heads
	}
	if _, err := v.write(id, parents, payload{Type: PolicyKind, Record: raw}); err != nil {
		return err
	}
	if v.idx.policy != p {
		return errors.New("svcore: the policy was written, but another change to it wins")
	}
	return nil
}

// writeAgain writes an object's current state again, as this handle's own
// revision (for Rotate and SetPolicy), with tombstones too if asked. It
// leaves alone what is not this handle's to adopt: device and policy
// records (a device record says what that device and those who changed
// it signed, and the policy what a registered device set; both stay
// readable down the epoch chain), and a winner whose signature is bad or
// unverified (a forgery, or a device not known here: signing it would
// vouch for it). The caller holds v.mu.
func (v *Vault) writeAgain(id svformat.ID, o *object, tombstones bool) error {
	if len(o.heads) == 0 || v.idx.deviceObjs[id] || id == PolicyID(v.desc.ID) {
		return nil
	}
	h := o.heads[0]
	if h.kind == DeviceKind || h.kind == PolicyKind || h.status == SigBad || h.status == SigUnverified {
		return nil
	}
	p := payload{Type: h.kind, Deleted: h.deleted}
	switch {
	case h.deleted:
		if !tombstones {
			return nil
		}
	case h.kind == payloadItem && h.item != nil:
		it := h.item.clone()
		defer it.Wipe()
		p.Item = &it
	case h.record != nil:
		p.Record = append([]byte(nil), h.record...)
		defer clear(p.Record)
	default:
		return nil
	}
	_, err := v.write(id, o.heads, p)
	return err
}
