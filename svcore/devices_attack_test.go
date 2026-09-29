package svcore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// What someone who can open the vault, but holds no one else's device
// key, might try against the registry and the policy.

func deviceRec(t *testing.T, rec deviceRecord) payload {
	t.Helper()
	rec.Alg = "ed25519"
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return payload{Type: DeviceKind, Record: raw}
}

func headIDs(v *Vault, obj svformat.ID) []svformat.RevID {
	var ids []svformat.RevID
	if o := v.idx.objects[obj]; o != nil {
		for _, h := range o.heads {
			ids = append(ids, h.id)
		}
	}
	return ids
}

// rawWrite writes a revision as v's device, with the time and parents
// given rather than the ones a writer would choose.
func rawWrite(t *testing.T, v *Vault, device, obj svformat.ID, parents []svformat.RevID, at time.Time, p payload) svformat.RevID {
	t.Helper()
	plain, err := encodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	hdr := svformat.RevisionHeader{Suite: v.suite, Vault: v.desc.ID, Object: obj, Epoch: v.epoch(), Time: at.UnixNano(), Parents: parents, Device: device}
	file, err := svformat.SealSignedRevision(hdr, v.wrap().Bytes(), svcrypto.RandomKey(), plain, v.opts.Signer.private())
	if err != nil {
		t.Fatal(err)
	}
	id := svformat.RevIDOf(file)
	if err := v.store.Create(svformat.RevisionName(obj, id), file); err != nil {
		t.Fatal(err)
	}
	return id
}

func vouchedFor(t *testing.T, v *Vault, key svformat.ID) bool {
	t.Helper()
	d, err := mustGetVault(t, v).Device(key.String())
	if err != nil {
		t.Fatal(err)
	}
	return d.Vouched
}

// Rotating the key and requiring signatures write the current state
// again as this device's. Neither may sign what others put in its
// record, or a policy nobody registered set.
func TestWritingAgainAdoptsNoDeviceRecordAndNoPolicy(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	m := device(t, store, "mallory")
	ka, kb, km := a.opts.Signer.ID(), b.opts.Signer.ID(), m.opts.Signer.ID()

	mustGetVault(t, a)
	if _, err := a.VouchDevice(kb, true); err != nil {
		t.Fatal(err)
	}
	// The phone renames the laptop: its record carries no vouches.
	mustGetVault(t, b)
	if _, err := b.LabelDevice(ka, "renamed by the phone"); err != nil {
		t.Fatal(err)
	}
	// Someone with only the vault key puts Mallory in the laptop's vouches,
	// and a policy of their own, unsigned.
	u := unsignedHandle(t, store)
	u.write(ka, u.idx.objects[ka].heads, deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: a.opts.Device, Label: "laptop", Vouches: []svformat.ID{km}}))
	u.write(PolicyID(u.ID()), nil, payload{Type: PolicyKind, Record: []byte(`{"require_signatures":true}`)})

	check := func(when string) {
		t.Helper()
		if vouchedFor(t, a, km) {
			t.Fatalf("%s: Mallory is vouched for", when)
		}
		if !vouchedFor(t, a, kb) {
			t.Fatalf("%s: the laptop lost its vouch for the phone", when)
		}
	}
	check("before")
	if p, _ := a.Policy(); p.RequireSignatures {
		t.Fatal("an unsigned policy counts")
	}
	newPass := []byte("the next passphrase")
	if _, err := a.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	check("after a rotation")
	if p, _ := a.Policy(); p.RequireSignatures {
		t.Fatal("the rotation adopted an unsigned policy")
	}
	if err := a.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	check("after requiring signatures")
	// The phone, unlocking with the new key, agrees.
	b.Unlock(Passphrase(newPass))
	if vouchedFor(t, b, km) {
		t.Fatal("Mallory is vouched for, on the phone")
	}
}

// The newest record is the one nothing that counts came before: by
// descent, not by the clock, which every writer sets.
func TestTheNewestRecordIsByDescentNotByClock(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	future := func() time.Time { return time.Now().Add(1000 * time.Hour) }
	m, err := Open(store, Options{Device: svformat.NewID(), Signer: NewDeviceKey(), Now: future})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	m.RegisterDevice("mallory")
	ka, km := a.opts.Signer.ID(), m.opts.Signer.ID()

	// A policy from the far future, under a record of another kind dated
	// now: the laptop's later policy descends from it, and wins, though
	// its clock is behind the far-future one.
	if err := m.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	pid := PolicyID(m.ID())
	rawWrite(t, m, m.opts.Device, pid, headIDs(m, pid), time.Now(), payload{Type: "grant", Record: []byte(`{}`)})
	mustGetVault(t, a)
	if err := a.SetPolicy(Policy{}); err != nil {
		t.Fatalf("turning a far-future policy off: %v", err)
	}
	if p, _ := unsignedHandle(t, store).Policy(); p.RequireSignatures {
		t.Fatal("the far-future policy still wins")
	}

	// A far-future record in the laptop's object, the laptop's vouch for
	// Mallory after it, then a record of Mallory's after that with an
	// early time: the laptop withdrawing, after a restart, still wins.
	aDev := a.opts.Device
	f := rawWrite(t, m, m.opts.Device, ka, headIDs(mustGetVault(t, m), ka), time.Now().Add(1000*time.Hour),
		deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: aDev, Label: "laptop"}))
	mustGetVault(t, a)
	if _, err := a.VouchDevice(km, true); err != nil {
		t.Fatal(err)
	}
	vouch := a.idx.objects[ka].heads[0].id
	mustGetVault(t, m)
	rawWrite(t, m, m.opts.Device, ka, headIDs(m, ka), time.Now(), deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: aDev, Label: "laptop"}))
	restarted, _ := Open(store, Options{Device: aDev, Signer: a.opts.Signer})
	if err := restarted.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if !vouchedFor(t, restarted, km) {
		t.Fatal("the vouch did not take")
	}
	if _, err := restarted.VouchDevice(km, false); err != nil {
		t.Fatal(err)
	}
	if vouchedFor(t, restarted, km) || vouchedFor(t, a, km) {
		t.Fatal("a withdrawn vouch still counts")
	}
	// A copy of the vouch, sealed again under its content key: the same
	// signature, another ID, the same far-future time. It is superseded
	// with what it copies.
	forge(t, a, store, revisionFile(t, store, ka, vouch), nil, nil)
	if vouchedFor(t, restarted, km) || vouchedFor(t, a, km) {
		t.Fatal("a replayed vouch counts again")
	}
	_ = f
}

// A copy of a signed revision is superseded wherever the revision is: it
// shows as no conflict.
func TestAReplayedRevisionIsSupersededWithWhatItCopies(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	e1, _ := a.Put(login("site", "one"))
	e2, _ := a.Put(login("site", "two"))
	forge(t, a, store, revisionFile(t, store, e1.ID, e1.Rev), nil, nil)
	if e := mustGet(t, a, "site"); e.Rev != e2.Rev || len(e.Conflicts) != 0 {
		t.Fatalf("after a replay of an older revision: %s, conflicts %v", e.Rev.Short(), e.Conflicts)
	}
	if n := len(historyOf(t, a, "site")); n != 3 {
		t.Fatalf("the copy is not in the history: %d revisions", n)
	}
}

func TestRotationDoesNotAdoptAForgery(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	e, _ := a.Put(login("site", "honest"))
	forged := forge(t, a, store, revisionFile(t, store, e.ID, e.Rev),
		[]byte(`{"type":"item","item":{"kind":"login","name":"site","fields":[{"name":"password","type":"concealed","value":"Zm9yZ2Vk"}]}}`),
		func(fs []svformat.Field) []svformat.Field {
			return withField(fs, 0x04, binary.BigEndian.AppendUint64(nil, uint64(e.Time.UnixNano()+1e9)))
		})
	if w := mustGet(t, a, "site"); w.Rev != forged {
		t.Fatalf("the forgery does not win: %s", w.Rev.Short())
	}
	if _, err := a.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: []byte("the next passphrase")}}, false, nil); err != nil {
		t.Fatal(err)
	}
	if w, _ := a.Get("site"); w.Rev != forged || w.Signature.Status != SigBad || w.Signature.Mine {
		t.Fatalf("after the rotation: %s %+v", w.Rev.Short(), w.Signature)
	}
}

func TestOnlyADeviceRegisteredAsItselfSetsThePolicy(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	// The laptop's key, on a device it has not registered for.
	other, _ := Open(store, Options{Device: svformat.NewID(), Signer: a.opts.Signer})
	if err := other.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if err := other.SetPolicy(Policy{RequireSignatures: true}); !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("SetPolicy from a device the key is not registered for: %v", err)
	}
}

// A revision that counts supersedes all it descends from, through one
// that does not: a registered device that built on an ignored revision
// leaves no conflict behind it.
func TestARevisionThatCountsSupersedesThroughIgnoredOnes(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	behind := unsignedHandle(t, store)
	if _, err := a.Put(login("site", "one")); err != nil {
		t.Fatal(err)
	}
	mustGetVault(t, behind)
	if err := a.SetPolicy(Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	u, err := behind.Put(login("site", "unsigned"))
	if err != nil {
		t.Fatal(err)
	}
	it := login("site", "three")
	c := rawWrite(t, mustGetVault(t, b), b.opts.Device, u.ID, []svformat.RevID{u.Rev}, time.Now(), payload{Type: payloadItem, Item: &it})
	if e := mustGet(t, a, "site"); e.Rev != c || len(e.Conflicts) != 0 || secretOf(t, e) != "three" {
		t.Fatalf("after a signed write on top of an ignored one: %s %q, conflicts %v", e.Rev.Short(), secretOf(t, e), e.Conflicts)
	}
}

// A head whose contents were dropped, and whose file is gone when it
// counts again, leaves the index until its file is back.
func TestAHeadThatCannotBeReadAgainIsReadWhenItIsBack(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	behind := unsignedHandle(t, store)
	e1, _ := a.Put(login("site", "one"))
	mustGetVault(t, behind)
	if _, err := behind.Put(login("site", "unsigned")); err != nil {
		t.Fatal(err)
	}
	if e := mustGet(t, a, "site"); secretOf(t, e) != "unsigned" {
		t.Fatalf("before the policy: %q", secretOf(t, e))
	}
	name := svformat.RevisionName(e1.ID, e1.Rev)
	saved, _ := store.Read(name)
	store.Remove(name)
	// The phone requires signatures, without writing anything else.
	pid := PolicyID(b.ID())
	rawWrite(t, mustGetVault(t, b), b.opts.Device, pid, headIDs(b, pid), time.Now(), payload{Type: PolicyKind, Record: []byte(`{"require_signatures":true}`)})
	if err := a.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("with its only counting revision gone: %v", err)
	}
	store.Create(name, saved)
	if e := mustGet(t, a, "site"); e.Rev != e1.Rev || secretOf(t, e) != "one" {
		t.Fatalf("once the file is back: %s %q", e.Rev.Short(), secretOf(t, e))
	}
}

func TestRestoringNeverAdoptsAForgery(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	e, _ := a.Put(login("site", "honest"))
	forged := forge(t, a, store, revisionFile(t, store, e.ID, e.Rev),
		[]byte(`{"type":"item","item":{"kind":"login","name":"site","fields":[{"name":"password","type":"concealed","value":"Zm9yZ2Vk"}]}}`),
		func(fs []svformat.Field) []svformat.Field {
			return withField(fs, 0x04, binary.BigEndian.AppendUint64(nil, uint64(e.Time.UnixNano()+1e9)))
		})
	mustGetVault(t, a)
	if _, err := a.Restore("site", forged.String()[:12]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("restoring a forgery: %v", err)
	}
	if err := a.Delete("site"); err != nil {
		t.Fatal(err)
	}
	r, err := a.Restore("site", "")
	if err != nil || secretOf(t, r) != "honest" || !r.Signature.Mine {
		t.Fatalf("restoring the deleted item: %q %+v, %v", secretOf(t, r), r.Signature, err)
	}
}

// Devices are named by their keys alone: a device ID is anyone's to take.
func TestADeviceIsFoundByItsKeyOnly(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	ka := a.opts.Signer.ID()
	// Mallory registers a device whose ID is the laptop's key ID, and
	// one whose ID is the laptop's device ID.
	for _, dev := range []svformat.ID{ka, a.opts.Device} {
		m, _ := Open(store, Options{Device: dev, Signer: NewDeviceKey()})
		if err := m.Unlock(Passphrase(pass)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.RegisterDevice("laptop"); err != nil {
			t.Fatal(err)
		}
	}
	mustGetVault(t, a)
	for _, ref := range []string{ka.String(), ka.String()[:6], strings.ToUpper(ka.String()[:8])} {
		if d, err := a.Device(ref); err != nil || d.Key != ka {
			t.Fatalf("Device(%q) = %+v, %v", ref, d, err)
		}
	}
	if _, err := a.Device(a.opts.Device.String()); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("a device ID found a device: %v", err)
	}
}

func TestARemovalHoldsUntilARecordThatSawItSaysOtherwise(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	b := device(t, store, "phone")
	kb := b.opts.Signer.ID()
	mustGetVault(t, a)
	if err := a.RemoveDevice(kb); err != nil {
		t.Fatal(err)
	}
	// The phone, from a copy without its own record, registers again.
	if _, err := b.write(kb, nil, deviceRec(t, deviceRecord{Key: b.opts.Signer.Public(), Device: b.opts.Device, Label: "phone again"})); err != nil {
		t.Fatal(err)
	}
	if d, _ := mustGetVault(t, a).Device(kb.String()); !d.Removed {
		t.Fatalf("a registration that never saw the removal undid it: %+v", d)
	}
	// Having seen it, the phone names itself again: it is back.
	mustGetVault(t, b)
	if _, err := b.LabelDevice(kb, "phone"); err != nil {
		t.Fatal(err)
	}
	if d, _ := mustGetVault(t, a).Device(kb.String()); d.Removed || d.Label != "phone" {
		t.Fatalf("after the phone named itself: %+v", d)
	}
}

// A key registers itself for each device it signs as (a key file copied
// to another device, a device ID made again): none undoes another, so no
// registration, however dated, turns what the key signed before bad.
func TestAKeyRegistersItselfForEachDeviceItSignsAs(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	ka := a.opts.Signer.ID()
	a.Put(login("site", "x"))
	other, _ := Open(store, Options{Device: svformat.NewID(), Signer: a.opts.Signer})
	if err := other.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	// Before it registers for its device, what it signs does not verify.
	early, _ := other.Put(login("early", "y"))
	if early.Signature.Status != SigBad {
		t.Fatalf("a write as a device the key is not registered for: %+v", early.Signature)
	}
	// Registering keeps the key's label.
	if d, fresh, err := other.RegisterDevice("copy"); err != nil || !fresh || d.Label != "laptop" {
		t.Fatalf("RegisterDevice for a second device = %+v, %v, %v", d, fresh, err)
	}
	if _, fresh, _ := other.RegisterDevice("again"); fresh {
		t.Fatal("registered twice for one device")
	}
	// A registration for yet another device, dated before everything.
	third := svformat.NewID()
	rawWrite(t, other, third, ka, nil, time.Unix(1, 0), deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: third, Label: "backdated"}))
	for _, name := range []string{"site", "early"} {
		wantSigned(t, name, mustGet(t, a, name).Signature, SigVerified, "laptop")
	}
	if e := mustGet(t, a, "early"); e.Signature.Device != other.opts.Device {
		t.Fatalf("the signature names device %s, not the one that signed", e.Signature.Device)
	}
	// It only changes which device the key is listed under.
	if d, _ := a.Device(ka.String()); d.Device != third || d.Registered.Unix() != 1 || d.Label != "laptop" {
		t.Fatalf("the key's first registration: %+v", d)
	}
	// A revision naming a device the key never registered for is bad.
	e, _ := a.Get("site")
	forged := forge(t, a, store, revisionFile(t, store, e.ID, e.Rev), nil, func(fs []svformat.Field) []svformat.Field {
		n := svformat.NewID()
		return withField(fs, 0x81, n[:])
	})
	if s := historyOf(t, mustGetVault(t, a), "site")[forged].Signature; s.Status != SigBad {
		t.Fatalf("a revision naming a device the key is not registered for: %+v", s)
	}
}
