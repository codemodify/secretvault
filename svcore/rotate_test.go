package svcore

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

var newPass = []byte("a brand new passphrase")

func TestRotationLeavesOnlyTheNewKeysAndKeepsTheHistory(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	v.Put(login("site", "one"))
	v.Put(login("site", "two"))
	v.PutRecord("grant", svformat.ID{}, map[string]string{"app": "x"})
	infos, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPass}}, false, nil)
	if err != nil || len(infos) != 1 {
		t.Fatalf("Rotate = %v, %v", infos, err)
	}
	if v.Epoch() != 2 {
		t.Fatalf("epoch %d", v.Epoch())
	}
	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the old passphrase: %v", err)
	}
	if err := w.Unlock(Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	e, _ := w.Get("site")
	if secretOf(t, e) != "two" {
		t.Fatalf("current = %q", secretOf(t, e))
	}
	if h, _ := w.History("site"); len(h) != 3 || secretOf(t, h[2]) != "one" {
		t.Fatalf("history has %d entries", len(h))
	}
	if recs, _ := w.Records("grant"); len(recs) != 1 {
		t.Fatalf("records after rotation: %d", len(recs))
	}
	if slots, _ := w.Slots(); len(slots) != 1 || slots[0].Epoch != 2 {
		t.Fatalf("slots after rotation: %+v", slots)
	}
	if rep, _ := w.Verify(); !rep.OK() {
		t.Fatalf("Verify: %+v", rep)
	}
}

func TestRotatingCutsOffARecipientAndKeepsTheOthers(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("shared", "before"))
	alice, _ := svcrypto.Modern.NewIdentity()
	bob, _ := svcrypto.Modern.NewIdentity()
	v.AddSlot(NewSlot{Type: svformat.SlotRecipient, Label: "alice", Recipient: alice.Recipient()})
	bobSlot, _ := v.AddSlot(NewSlot{Type: svformat.SlotRecipient, Label: "bob", Recipient: bob.Recipient()})
	// Bob keeps a copy of his keyslot file, as someone leaving might.
	bobFile, _ := store.Read(svformat.SlotName(bobSlot.ID))

	_, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, true,
		func(s SlotInfo) bool { return s.Label == "bob" })
	if err != nil {
		t.Fatal(err)
	}
	v.Put(login("shared", "after"))

	a, _ := Open(store, Options{})
	if err := a.Unlock(IdentityKey(alice)); err != nil {
		t.Fatalf("alice after the rotation: %v", err)
	}
	if e, _ := a.Get("shared"); secretOf(t, e) != "after" {
		t.Fatal("alice cannot read the new state")
	}
	store.Write(svformat.SlotName(bobSlot.ID), bobFile) // bob puts his old slot back
	b, _ := Open(store, Options{})
	if err := b.Unlock(IdentityKey(bob)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("bob after the rotation, with his old keyslot restored: %v", err)
	}
	// Every live revision is under the new epoch: an old key reads none of it.
	names, _ := store.List(svformat.ObjectsDir)
	newer := 0
	for _, n := range names {
		file, _ := store.Read(n)
		if h, err := svformat.ParseRevision(file); err == nil && h.Epoch == 2 {
			newer++
		}
	}
	if newer < 2 {
		t.Fatalf("%d revisions under the new key", newer)
	}
}

func TestAnotherHandleNoticesARotationAndLocks(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	w, _ := Open(store, Options{})
	w.Unlock(Passphrase(pass))
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Refresh(); !errors.Is(err, ErrRotated) {
		t.Fatalf("Refresh after a rotation elsewhere: %v", err)
	}
	if !w.Locked() {
		t.Fatal("the stale handle stayed unlocked")
	}
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatalf("unlocking with the new epoch's slot: %v", err)
	}
}

func TestTwoRotationsAtOnceDoNotFork(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	w, _ := Open(store, Options{})
	w.Unlock(Passphrase(pass))
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := store.List(svformat.SlotsDir)
	if _, err := w.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPass}}, false, nil); !errors.Is(err, ErrRotating) {
		t.Fatalf("the second rotation: %v", err)
	}
	if after, _ := store.List(svformat.SlotsDir); len(after) != len(before) {
		t.Fatalf("the refused rotation left keyslots behind: %d -> %d", len(before), len(after))
	}
}

// failingEpochs refuses to write epoch records: a crash at the commit point.
type failingEpochs struct{ svstore.Backend }

func (f failingEpochs) Create(name string, data []byte) error {
	if len(name) > 7 && name[:7] == "epochs/" {
		return errors.New("disk full")
	}
	return f.Backend.Create(name, data)
}

func TestARotationThatFailsAtItsCommitPointChangesNothing(t *testing.T) {
	mem := svstore.NewMem()
	v := newVault(t, failingEpochs{mem}, 0)
	v.Put(login("x", "1"))
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPass}}, false, nil); err == nil {
		t.Fatal("the rotation reported success")
	}
	w, _ := Open(mem, Options{})
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatalf("the vault no longer opens with its key: %v", err)
	}
	if e, _ := w.Get("x"); secretOf(t, e) != "1" {
		t.Fatal("contents lost")
	}
}

func TestHistorySurvivesSeveralRotations(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.NIST)
	for i, p := range []string{"a", "b", "c"} {
		v.Put(login("s", p))
		if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
	}
	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); err != nil || w.Epoch() != 4 {
		t.Fatalf("unlock at epoch %d: %v", w.Epoch(), err)
	}
	h, _ := w.History("s")
	if got := secretOf(t, h[len(h)-1]); got != "a" {
		t.Fatalf("the oldest revision reads %q", got)
	}
	// The audit-log key stays the same across rotations.
	k1, _ := v.DeriveKey("audit log key", 32)
	k2, _ := w.DeriveKey("audit log key", 32)
	if string(k1) != string(k2) {
		t.Fatal("DeriveKey changed with the epoch")
	}
}
