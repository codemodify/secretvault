package svcore

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// signedVault creates a vault as a device with a key of its own, and
// registers it under label.
func signedVault(t *testing.T, store svstore.Backend, label string) *Vault {
	t.Helper()
	cheapKDF(t)
	v, _, err := Create(store, 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, Options{Device: svformat.NewID(), Signer: NewDeviceKey()})
	if err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := v.RegisterDevice(label); err != nil || !fresh {
		t.Fatalf("RegisterDevice = %v, %v", fresh, err)
	}
	return v
}

// device opens the vault as another device, with a key of its own,
// registered under label unless it is "".
func device(t *testing.T, store svstore.Backend, label string) *Vault {
	t.Helper()
	v, err := Open(store, Options{Device: svformat.NewID(), Signer: NewDeviceKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if label != "" {
		if _, _, err := v.RegisterDevice(label); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

// unsignedHandle opens the vault as a version before signatures would:
// no device key.
func unsignedHandle(t *testing.T, store svstore.Backend) *Vault {
	t.Helper()
	v, err := Open(store, Options{Device: svformat.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustGet(t *testing.T, v *Vault, name string) Entry {
	t.Helper()
	if err := v.Refresh(); err != nil {
		t.Fatal(err)
	}
	e, err := v.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func wantSigned(t *testing.T, what string, s Signature, status SigStatus, label string) {
	t.Helper()
	if s.Status != status || s.Label != label {
		t.Fatalf("%s: signature %+v, want %s by %q", what, s, status, label)
	}
}

func historyOf(t *testing.T, v *Vault, name string) map[svformat.RevID]Entry {
	t.Helper()
	hist, err := v.History(name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[svformat.RevID]Entry{}
	for _, e := range hist {
		out[e.Rev] = e
	}
	return out
}

func revisionFile(t *testing.T, store svstore.Backend, id svformat.ID, rev svformat.RevID) []byte {
	t.Helper()
	b, err := store.Read(svformat.RevisionName(id, rev))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// forge writes a revision as anyone who can open the vault can: file's
// header fields changed by edit, and its body sealed again under the same
// content key around payload (the file's own when nil). It opens; only its
// signature can tell.
func forge(t *testing.T, v *Vault, store svstore.Backend, file, payload []byte, edit func([]svformat.Field) []svformat.Field) svformat.RevID {
	t.Helper()
	h, err := svformat.ParseRevision(file)
	if err != nil {
		t.Fatal(err)
	}
	_, own, dek, err := svformat.OpenRevision(file, v.wraps[h.Epoch].Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if payload == nil {
		payload = own
	}
	n := int(binary.BigEndian.Uint16(file[6:8]))
	fields, err := svformat.DecodeTLV(file[8 : 8+n])
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		fields = edit(fields)
	}
	hdr, err := svformat.EncodeTLV(fields)
	if err != nil {
		t.Fatal(err)
	}
	prefix := append(bytes.Clone(file[:6]), byte(len(hdr)>>8), byte(len(hdr)))
	prefix = append(prefix, hdr...)
	framed := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	body, err := h.Suite.Seal(dek, append(framed, payload...), prefix)
	if err != nil {
		t.Fatal(err)
	}
	out := append(prefix, body...)
	id := svformat.RevIDOf(out)
	if err := store.Create(svformat.RevisionName(h.Object, id), out); err != nil {
		t.Fatal(err)
	}
	return id
}

func withField(fields []svformat.Field, tag uint8, v []byte) []svformat.Field {
	out := slices.Clone(fields)
	for i, f := range out {
		if f.Tag == tag {
			out[i].Value = v
			return out
		}
	}
	out = append(out, svformat.Field{Tag: tag, Value: v})
	slices.SortFunc(out, func(a, b svformat.Field) int { return int(a.Tag) - int(b.Tag) })
	return out
}

func fieldValue(t *testing.T, file []byte, tag uint8) []byte {
	t.Helper()
	n := int(binary.BigEndian.Uint16(file[6:8]))
	fields, _ := svformat.DecodeTLV(file[8 : 8+n])
	for _, f := range fields {
		if f.Tag == tag {
			return bytes.Clone(f.Value)
		}
	}
	t.Fatalf("no field 0x%02x", tag)
	return nil
}

func hasProblem(rep Report, rev svformat.RevID, want error) bool {
	for _, p := range rep.Problems {
		if _, r, ok := svformat.ParseRevisionName(p.Name); ok && r == rev && errors.Is(p.Err, want) {
			return true
		}
	}
	return false
}

func TestSignedWritesVerifyOnEveryDevice(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	ea, err := a.Put(login("site", "one"))
	if err != nil {
		t.Fatal(err)
	}
	wantSigned(t, "the writer's own view", ea.Signature, SigVerified, "laptop")
	if !ea.Signature.Mine || ea.Signature.Key != a.opts.Signer.ID() || ea.Signature.Device != a.opts.Device || ea.Device != a.opts.Device {
		t.Fatalf("the writer's own signature: %+v (device %s)", ea.Signature, ea.Device)
	}

	b := device(t, store, "")
	eb := mustGet(t, b, "site")
	wantSigned(t, "another device, not registered itself", eb.Signature, SigVerified, "laptop")
	if eb.Signature.Mine {
		t.Fatal("another device takes the laptop's revision for its own")
	}
	if _, fresh, err := b.RegisterDevice("phone"); err != nil || !fresh {
		t.Fatalf("RegisterDevice = %v, %v", fresh, err)
	}
	if _, fresh, _ := b.RegisterDevice("again"); fresh {
		t.Fatal("a registered device registered again")
	}
	if _, err := b.Put(login("site", "two")); err != nil {
		t.Fatal(err)
	}
	e := mustGet(t, a, "site")
	wantSigned(t, "the phone's change, on the laptop", e.Signature, SigVerified, "phone")
	hist, _ := a.History("site")
	if len(hist) != 2 || hist[0].Signature.Label != "phone" || hist[1].Signature.Label != "laptop" || !hist[1].Signature.Mine {
		t.Fatalf("history: %+v", hist)
	}
	devs, _ := a.Devices()
	if len(devs) != 2 || devs[0].Label != "laptop" || !devs[0].This || devs[1].Label != "phone" || devs[1].This {
		t.Fatalf("Devices = %+v", devs)
	}
	if d, err := a.Device(devs[1].Key.String()[:6]); err != nil || d.Label != "phone" {
		t.Fatalf("Device by key prefix = %+v, %v", d, err)
	}
	if d, err := a.Device(devs[1].Device.String()[:8]); err != nil || d.Key != devs[1].Key {
		t.Fatalf("Device by device-ID prefix = %+v, %v", d, err)
	}
	if rep, err := a.Verify(); err != nil || !rep.OK() {
		t.Fatalf("Verify = %+v, %v", rep.Problems, err)
	}
}

func TestWritesMadeBeforeRegisteringVerifyOnceTheDeviceIs(t *testing.T) {
	store := svstore.NewMem()
	a := newVault(t, store, 0) // a version before signatures
	b := device(t, store, "")
	e, _ := b.Put(login("early", "x"))
	if e.Signature.Status != SigUnverified || e.Signature.Key != b.opts.Signer.ID() || e.Signature.Label != "" {
		t.Fatalf("before registering: %+v", e.Signature)
	}
	if rep, _ := a.Verify(); !hasProblem(rep, e.Rev, ErrUnknownSigner) {
		t.Fatalf("an unregistered signer is not reported: %+v", rep.Problems)
	}
	b.RegisterDevice("late")
	wantSigned(t, "the writer, after registering", mustGet(t, b, "early").Signature, SigVerified, "late")
	wantSigned(t, "an unsigned handle", mustGet(t, a, "early").Signature, SigVerified, "late")
}

func TestUnsignedAndSignedRevisionsMix(t *testing.T) {
	store := svstore.NewMem()
	old := newVault(t, store, 0)
	first, _ := old.Put(login("site", "old"))
	old.Put(login("other", "old"))
	if first.Signature.Status != SigUnsigned {
		t.Fatalf("an unsigned write: %+v", first.Signature)
	}

	b := device(t, store, "new")
	if _, err := b.Put(login("site", "new")); err != nil {
		t.Fatal(err)
	}
	hist := historyOf(t, b, "site")
	if len(hist) != 2 || hist[first.Rev].Signature.Status != SigUnsigned || hist[first.Rev].Ignored {
		t.Fatalf("history: %+v", hist)
	}
	wantSigned(t, "the new write", mustGet(t, b, "site").Signature, SigVerified, "new")
	if e := mustGet(t, b, "other"); e.Signature.Status != SigUnsigned || secretOf(t, e) != "old" {
		t.Fatalf("an old item: %+v", e)
	}
	// The old handle reads the signed revisions as it reads any other.
	if e := mustGet(t, old, "site"); secretOf(t, e) != "new" || e.Signature.Label != "new" {
		t.Fatalf("the old handle: %q %+v", secretOf(t, e), e.Signature)
	}
	for _, v := range []*Vault{old, b} {
		if rep, err := v.Verify(); err != nil || !rep.OK() {
			t.Fatalf("Verify = %+v, %v", rep.Problems, err)
		}
	}
}

// Whoever can open the vault can write any revision. What they cannot do
// is make one pass for a registered device's.
func TestTamperedSignaturesAreBad(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	m := device(t, store, "mallory")
	e, _ := a.Put(login("site", "honest"))
	file := revisionFile(t, store, e.ID, e.Rev)
	em, _ := m.Put(login("mallorys", "x"))
	mfile := revisionFile(t, store, em.ID, em.Rev)
	forged := []byte(`{"type":"item","item":{"kind":"login","name":"site","fields":[{"name":"password","type":"concealed","value":"Zm9yZ2Vk"}]}}`)

	cases := map[string]svformat.RevID{
		"other contents": forge(t, a, store, file, forged, nil),
		"a flipped bit": forge(t, a, store, file, forged, func(fs []svformat.Field) []svformat.Field {
			v := fieldValue(t, file, 0x82)
			v[30] ^= 1
			return withField(fs, 0x82, v)
		}),
		"mallory's key named": forge(t, a, store, file, forged, func(fs []svformat.Field) []svformat.Field {
			v := fieldValue(t, file, 0x82)
			k := m.opts.Signer.ID()
			copy(v[1:17], k[:])
			return withField(fs, 0x82, v)
		}),
		"mallory's signature moved": forge(t, a, store, file, forged, func(fs []svformat.Field) []svformat.Field {
			return withField(fs, 0x82, fieldValue(t, mfile, 0x82))
		}),
		"another device named": forge(t, a, store, file, nil, func(fs []svformat.Field) []svformat.Field {
			return withField(fs, 0x81, m.opts.Device[:])
		}),
	}
	hist := historyOf(t, mustGetVault(t, a), "site")
	for name, rev := range cases {
		s := hist[rev].Signature
		if s.Status != SigBad || s.Mine {
			t.Errorf("%s: %+v", name, s)
		}
	}
	rep, _ := a.Verify()
	for name, rev := range cases {
		if !hasProblem(rep, rev, ErrBadSignature) {
			t.Errorf("%s: not reported by Verify", name)
		}
	}
	// By default they still count (a key holder could as well have left
	// them unsigned); requiring signatures ignores them, and does not
	// adopt one that happens to win.
	if err := a.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, a, "site")
	if secretOf(t, got) != "honest" || len(got.Conflicts) != 0 || got.Rev != e.Rev {
		t.Fatalf("with signatures required: %q %v conflicts %v", secretOf(t, got), got.Rev.Short(), got.Conflicts)
	}
	for name, rev := range cases {
		if !historyOf(t, a, "site")[rev].Ignored {
			t.Errorf("%s: counted although signatures are required", name)
		}
	}
}

// mustGetVault refreshes v and returns it.
func mustGetVault(t *testing.T, v *Vault) *Vault {
	t.Helper()
	if err := v.Refresh(); err != nil {
		t.Fatal(err)
	}
	return v
}

// The registry is records anyone who can open the vault can write. None
// of it lets them claim another device's key, or its writes.
func TestTheRegistryCannotBeTurnedAgainstADevice(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	m := device(t, store, "mallory")
	e, _ := a.Put(login("site", "honest"))
	ka, km := a.opts.Signer, m.opts.Signer
	aDevice := a.opts.Device

	// Mallory's own key, put in the laptop's record: the object is not
	// named after it, so it registers nothing.
	if err := m.writeDevice(ka.ID(), deviceRecord{Alg: "ed25519", Key: km.Public(), Device: m.opts.Device, Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	// The laptop's key bound to Mallory's device: not the device the key
	// registered itself for.
	m.writeDevice(ka.ID(), deviceRecord{Alg: "ed25519", Key: ka.Public(), Device: m.opts.Device, Label: "mine now"})
	// A key Mallory does not hold, registered by Mallory: only a key's own
	// signature registers it.
	stranger := NewDeviceKey()
	m.writeDevice(stranger.ID(), deviceRecord{Alg: "ed25519", Key: stranger.Public(), Device: svformat.NewID(), Label: "stranger"})
	// Vouches written into the laptop's record by Mallory.
	m.writeDevice(ka.ID(), deviceRecord{Alg: "ed25519", Key: ka.Public(), Device: aDevice, Label: "laptop", Vouches: []svformat.ID{km.ID()}})
	// The laptop's own registration, with its label changed, the laptop's
	// signature kept.
	proof := a.idx.reg[ka.ID()]
	var proofRev svformat.RevID
	for id, r := range a.idx.objects[ka.ID()].revs {
		if proves(a.idx.objects[ka.ID()], r) && r.hdr.Time == proof.registered.UnixNano() {
			proofRev = id
		}
	}
	forged := forge(t, a, store, revisionFile(t, store, ka.ID(), proofRev),
		[]byte(`{"type":"device","record":{"alg":"ed25519","key":"`+base64.StdEncoding.EncodeToString(ka.Public())+
			`","device":"`+aDevice.String()+`","label":"forged"}}`), nil)

	wantSigned(t, "the laptop's write", mustGet(t, a, "site").Signature, SigVerified, "laptop")
	devs, _ := a.Devices()
	if len(devs) != 2 {
		t.Fatalf("Devices = %+v", devs)
	}
	for _, d := range devs {
		switch d.Key {
		case ka.ID():
			if d.Device != aDevice || d.Label != "laptop" || d.Removed || !bytes.Equal(d.Public, ka.Public()) {
				t.Fatalf("the laptop: %+v", d)
			}
		case km.ID():
			if d.Vouched {
				t.Fatal("Mallory made itself vouched for, on the laptop")
			}
		default:
			t.Fatalf("a device nobody registered: %+v", d)
		}
	}
	rep, _ := a.Verify()
	if !hasProblem(rep, forged, ErrBadSignature) {
		t.Fatalf("the forged registration is not reported: %+v", rep.Problems)
	}

	// What Mallory can do, openly: rename or remove the laptop. It is
	// still the laptop's key, and its writes still verify.
	if _, err := m.LabelDevice(ka.ID(), "renamed by mallory"); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveDevice(ka.ID()); err != nil {
		t.Fatal(err)
	}
	s := mustGet(t, a, "site").Signature
	if s.Status != SigVerified || s.Label != "renamed by mallory" || !s.Removed || s.Device != aDevice {
		t.Fatalf("after Mallory's changes: %+v", s)
	}
	// The laptop does not come back by itself, but does when it names itself.
	if _, fresh, _ := a.RegisterDevice("laptop"); fresh {
		t.Fatal("a removed device registered again by itself")
	}
	if d, err := a.LabelDevice(ka.ID(), "laptop"); err != nil || d.Removed || d.Label != "laptop" {
		t.Fatalf("the laptop naming itself: %+v, %v", d, err)
	}
	_ = e
}

func TestRequiringSignatures(t *testing.T) {
	store := svstore.NewMem()
	old := newVault(t, store, 0)
	old.Put(login("legacy", "v1"))
	old.Put(login("gone", "x"))
	old.Delete("gone")
	behind := unsignedHandle(t, store) // an older version, which will not hear of the policy

	a := device(t, store, "laptop")
	u := unsignedHandle(t, store)
	if err := u.SetPolicy(Policy{RequireSignatures: true}); !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("a handle that cannot sign set the policy: %v", err)
	}
	if err := a.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	if p, _ := a.Policy(); !p.RequireSignatures {
		t.Fatal("the policy did not change")
	}
	// What was there before is kept, adopted by the device that asked.
	e := mustGet(t, a, "legacy")
	if secretOf(t, e) != "v1" || !e.Signature.Mine {
		t.Fatalf("the legacy item: %q %+v", secretOf(t, e), e.Signature)
	}
	if _, err := a.Get("gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted item came back: %v", err)
	}
	ignored := 0
	for _, h := range historyOf(t, a, "legacy") {
		if h.Ignored {
			ignored++
			if h.Signature.Status != SigUnsigned {
				t.Fatalf("an ignored revision: %+v", h.Signature)
			}
		}
	}
	if ignored != 1 {
		t.Fatalf("%d ignored revisions in the history", ignored)
	}

	// A handle that knows the policy refuses to write what would not count.
	if _, err := mustGetVault(t, u).Put(login("legacy", "unsigned")); !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("an unsigned write under the policy: %v", err)
	}
	// One that does not know it writes anyway: it is ignored, and cannot
	// hide or delete what counts.
	unsignedPut, err := behind.Put(login("legacy", "from an old version"))
	if err != nil {
		t.Fatal(err)
	}
	behind.Delete("legacy")
	behind.Put(login("new-from-old", "x"))
	// Nor can it turn the policy off.
	if _, err := behind.write(PolicyID(behind.ID()), nil, payload{Type: PolicyKind, Record: []byte(`{"require_signatures":false}`)}); err != nil {
		t.Fatal(err)
	}
	e = mustGet(t, a, "legacy")
	if secretOf(t, e) != "v1" || len(e.Conflicts) != 0 {
		t.Fatalf("after unsigned writes: %q, conflicts %v", secretOf(t, e), e.Conflicts)
	}
	if _, err := a.Get("new-from-old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unsigned new item counts: %v", err)
	}
	if p, _ := a.Policy(); !p.RequireSignatures {
		t.Fatal("an unsigned revision turned the policy off")
	}
	if !historyOf(t, a, "legacy")[unsignedPut.Rev].Ignored {
		t.Fatal("the unsigned revision is not marked ignored")
	}
	if rep, _ := a.Verify(); !hasProblem(rep, unsignedPut.Rev, ErrSignatureRequired) {
		t.Fatalf("the ignored revision is not reported: %+v", rep.Problems)
	}

	// A new device registers and writes: both count.
	c := device(t, store, "phone")
	if _, err := c.Put(login("from-phone", "x")); err != nil {
		t.Fatal(err)
	}
	wantSigned(t, "a new device under the policy", mustGet(t, a, "from-phone").Signature, SigVerified, "phone")

	// Turned off (by a registered device), the unsigned revisions count
	// again.
	if err := a.SetPolicy(Policy{}); err != nil {
		t.Fatal(err)
	}
	if _, err := mustGetVault(t, a).Get("new-from-old"); err != nil {
		t.Fatalf("an unsigned item after the policy was turned off: %v", err)
	}
}

func TestRotationSignsWhatItWritesAgainAndKeepsTheRegistry(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	first, _ := b.Put(login("from-phone", "x"))
	if err := a.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	mustGetVault(t, a)
	newPass := []byte("a whole new passphrase")
	if _, err := a.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	e, _ := a.Get("from-phone")
	if e.Signature.Status != SigVerified || !e.Signature.Mine {
		t.Fatalf("the rewritten item: %+v", e.Signature)
	}
	wantSigned(t, "the phone's original, down the epoch chain", historyOf(t, a, "from-phone")[first.Rev].Signature, SigVerified, "phone")

	if err := b.Refresh(); !errors.Is(err, ErrRotated) {
		t.Fatalf("the phone after the rotation: %v", err)
	}
	if err := b.Unlock(Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	devs, _ := b.Devices()
	if len(devs) != 2 {
		t.Fatalf("the registry after the rotation: %+v", devs)
	}
	if p, _ := b.Policy(); !p.RequireSignatures {
		t.Fatal("the policy was lost in the rotation")
	}
	if _, err := b.Put(login("after", "y")); err != nil {
		t.Fatal(err)
	}
	wantSigned(t, "a write after the rotation", mustGet(t, a, "after").Signature, SigVerified, "phone")
	for _, v := range []*Vault{a, b} {
		if rep, err := v.Verify(); err != nil || !rep.OK() {
			t.Fatalf("Verify = %+v, %v", rep.Problems, err)
		}
	}
}

func TestVouchingIsEachDevicesOwnSay(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	c := device(t, store, "tablet")
	m := device(t, store, "mallory")
	c.Put(login("from-tablet", "x"))
	key := func(v *Vault) svformat.ID { return v.opts.Signer.ID() }
	vouched := func(v *Vault) map[string]bool {
		t.Helper()
		mustGetVault(t, v)
		devs, _ := v.Devices()
		out := map[string]bool{}
		for _, d := range devs {
			if d.Vouched {
				out[d.Label] = true
			}
		}
		return out
	}
	if got := vouched(a); len(got) != 1 || !got["laptop"] {
		t.Fatalf("before any vouching: %v", got)
	}
	mustGetVault(t, a)
	if _, err := a.VouchDevice(key(b), true); err != nil {
		t.Fatal(err)
	}
	mustGetVault(t, b)
	if _, err := b.VouchDevice(key(c), true); err != nil {
		t.Fatal(err)
	}
	if got := vouched(a); len(got) != 3 || !got["phone"] || !got["tablet"] {
		t.Fatalf("through the phone: %v", got)
	}
	if s := mustGet(t, a, "from-tablet").Signature; !s.Vouched {
		t.Fatalf("the tablet's write: %+v", s)
	}
	// On the phone, the laptop is not vouched for: the laptop vouching for
	// the phone says nothing the other way.
	if got := vouched(b); got["laptop"] || !got["tablet"] {
		t.Fatalf("on the phone: %v", got)
	}
	// Mallory vouching for itself, in its own record or the laptop's,
	// counts for nothing on the laptop.
	mustGetVault(t, m)
	if _, err := m.VouchDevice(key(m), true); err == nil {
		t.Fatal("a device vouched for itself")
	}
	m.writeDevice(key(a), deviceRecord{Alg: "ed25519", Key: a.opts.Signer.Public(), Device: a.opts.Device, Label: "laptop", Vouches: []svformat.ID{key(m)}})
	if got := vouched(a); got["mallory"] {
		t.Fatalf("Mallory made itself vouched for: %v", got)
	}
	// Removing the phone breaks the chain through it; so does withdrawing.
	if err := a.RemoveDevice(key(b)); err != nil {
		t.Fatal(err)
	}
	if got := vouched(a); got["phone"] || got["tablet"] {
		t.Fatalf("after removing the phone: %v", got)
	}
	a.LabelDevice(key(b), "phone") // not its own: stays removed
	if got := vouched(a); got["phone"] {
		t.Fatalf("relabelling brought the phone back: %v", got)
	}
	if _, err := a.VouchDevice(key(b), false); err != nil {
		t.Fatal(err)
	}
	if d, _ := a.Device(key(a).String()); len(d.Vouches) != 0 {
		t.Fatalf("the laptop still vouches for %v", d.Vouches)
	}
}

func TestEngineRecordsAreWrittenOnlyThroughTheirMethods(t *testing.T) {
	v := signedVault(t, svstore.NewMem(), "laptop")
	for _, kind := range []string{DeviceKind, PolicyKind} {
		if _, err := v.PutRecord(kind, svformat.ID{}, map[string]string{}); err == nil {
			t.Errorf("PutRecord(%q) was accepted", kind)
		}
	}
	if err := v.DeleteRecord(v.opts.Signer.ID()); err == nil {
		t.Error("a device record was deleted as a plain record")
	}
	if _, err := v.Device("nothing"); !errors.Is(err, ErrNoDevice) {
		t.Errorf("Device of nothing: %v", err)
	}
	u, _, _ := Create(svstore.NewMem(), 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, Options{})
	if _, _, err := u.RegisterDevice("x"); !errors.Is(err, ErrNoDeviceKey) {
		t.Errorf("registering without a key: %v", err)
	}
}

func TestTheDeviceKeyIsMadeOnceAndKeptPrivate(t *testing.T) {
	home := t.TempDir()
	a, err := LoadDeviceKey(home)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadDeviceKey(home)
	if err != nil || a.ID() != b.ID() || !bytes.Equal(a.Public(), b.Public()) {
		t.Fatalf("the key changed: %v", err)
	}
	if a.ID() != svformat.DeviceKeyID(a.Public()) {
		t.Fatal("the key's ID is not its DeviceKeyID")
	}
	fi, err := os.Stat(filepath.Join(home, DeviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("the key file is %v", fi.Mode().Perm())
	}
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, DeviceKeyFile), []byte("garbage"), 0o600)
	if _, err := LoadDeviceKey(other); err == nil {
		t.Fatal("garbage loaded as a device key")
	}
}
