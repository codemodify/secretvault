package svcore

import (
	"encoding/json"
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
func rawWrite(t *testing.T, v *Vault, obj svformat.ID, parents []svformat.RevID, at time.Time, p payload) svformat.RevID {
	t.Helper()
	plain, err := encodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	hdr := svformat.RevisionHeader{Suite: v.suite, Vault: v.desc.ID, Object: obj, Epoch: v.epoch(), Time: at.UnixNano(), Parents: parents, Device: v.opts.Device}
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
	rawWrite(t, m, pid, headIDs(m, pid), time.Now(), payload{Type: "grant", Record: []byte(`{}`)})
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
	f := rawWrite(t, m, ka, headIDs(mustGetVault(t, m), ka), time.Now().Add(1000*time.Hour),
		deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: aDev, Label: "laptop"}))
	mustGetVault(t, a)
	if _, err := a.VouchDevice(km, true); err != nil {
		t.Fatal(err)
	}
	mustGetVault(t, m)
	rawWrite(t, m, ka, headIDs(m, ka), time.Now(), deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: aDev, Label: "laptop"}))
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
	_ = f
}

func TestADeviceIsFoundByItsKeyFirst(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	ka := a.opts.Signer.ID()
	// Mallory registers a device whose ID is the laptop's key ID.
	m, _ := Open(store, Options{Device: ka, Signer: NewDeviceKey()})
	if err := m.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.RegisterDevice("mallory"); err != nil {
		t.Fatal(err)
	}
	mustGetVault(t, a)
	for _, ref := range []string{ka.String(), ka.String()[:6]} {
		if d, err := a.Device(ref); err != nil || d.Key != ka {
			t.Fatalf("Device(%q) = %+v, %v", ref, d, err)
		}
	}
	// A device ID still finds a device when no key starts with it.
	if d, err := a.Device(a.opts.Device.String()[:12]); err != nil || d.Key != ka {
		t.Fatalf("by device ID: %+v, %v", d, err)
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

func TestAKeyStaysRegisteredForItsFirstDevice(t *testing.T) {
	store := svstore.NewMem()
	a := signedVault(t, store, "laptop")
	e, _ := a.Put(login("site", "x"))
	ka := a.opts.Signer.ID()
	// The same key on a device with another ID (a copied key file, say).
	other, _ := Open(store, Options{Device: svformat.NewID(), Signer: a.opts.Signer})
	if err := other.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.RegisterDevice("copy"); err == nil {
		t.Fatal("a key registered for one device registered again for another")
	}
	second, err := other.write(ka, other.idx.objects[ka].heads, deviceRec(t, deviceRecord{Key: a.opts.Signer.Public(), Device: other.opts.Device, Label: "copy"}))
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := other.Put(login("site2", "y"))
	wantSigned(t, "the first device's write", mustGet(t, a, "site").Signature, SigVerified, "laptop")
	if s := mustGet(t, a, "site2").Signature; s.Status != SigBad {
		t.Fatalf("a write as the second device: %+v", s)
	}
	rep, _ := a.Verify()
	found := false
	for _, p := range rep.Problems {
		if _, r, ok := svformat.ParseRevisionName(p.Name); ok && r == second.Rev {
			found = true
		}
	}
	if !found || !hasProblem(rep, e2.Rev, ErrBadSignature) {
		t.Fatalf("Verify: %+v", rep.Problems)
	}
	_ = e
}
