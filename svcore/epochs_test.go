package svcore

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// plantEpoch writes, as someone with no key to the vault but write access
// to its folder, a well-formed record for epoch n, and a recipient keyslot
// for victim's public key that opens to the forger's own master key: the
// best a forger can do, since both are made of public parts.
func plantEpoch(t *testing.T, store svstore.Backend, v *Vault, n uint32, victim *svcrypto.Identity) {
	t.Helper()
	master := svcrypto.RandomKey()
	prev := make([]byte, 60)
	rand.Read(prev)
	auth := make([]byte, 32)
	rand.Read(auth)
	rec := &svformat.EpochRecord{Format: svformat.EpochFormat, Vault: v.ID(), N: n, Created: time.Now().UTC(),
		Check: svformat.CheckValue(v.ID(), master), Prev: prev, Auth: auth}
	b, _ := jsonIndent(rec)
	if err := store.Create(svformat.EpochName(n), b); err != nil {
		t.Fatal(err)
	}
	if victim == nil {
		return
	}
	s := &svformat.Slot{Format: svformat.SlotFormat, ID: svformat.NewID(), Vault: v.ID(), Epoch: n,
		Type: svformat.SlotRecipient, Label: "planted", Created: time.Now().UTC(), Grants: []string{svformat.GrantContent},
		Recipient: victim.Recipient()}
	var err error
	if s.Wrapped, err = v.Suite().SealTo(s.Recipient, master, s.AAD()); err != nil {
		t.Fatal(err)
	}
	sb, _ := jsonIndent(s)
	if err := store.Create(svformat.SlotName(s.ID), sb); err != nil {
		t.Fatal(err)
	}
}

func problemsNamed(rep Report, name string) []Problem {
	var out []Problem
	for _, p := range rep.Problems {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

func TestAPlantedEpochRecordDoesNotLockAnyoneOut(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("mail", "hunter2"))
	alice, _ := svcrypto.Modern.NewIdentity()
	v.AddSlot(NewSlot{Type: svformat.SlotRecipient, Label: "alice", Recipient: alice.Recipient()})

	plantEpoch(t, store, v, 2, alice)
	// A garbled record past a gap is no reason to refuse the vault either.
	store.Create(svformat.EpochName(7), []byte("{not json"))

	// An open handle hears of it, and neither locks nor trusts it.
	if err := v.Refresh(); err != nil {
		t.Fatalf("Refresh with a planted record: %v", err)
	}
	if v.Locked() || v.Epoch() != 1 {
		t.Fatalf("locked %v, epoch %d", v.Locked(), v.Epoch())
	}

	// Fresh handles open it with the passphrase, and with alice's
	// identity, although a slot for her was planted in the fake epoch.
	for _, k := range []Key{Passphrase(pass), IdentityKey(alice)} {
		w, err := Open(store, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Unlock(k); err != nil {
			t.Fatalf("unlock with a planted record: %v", err)
		}
		if w.Epoch() != 1 {
			t.Fatalf("opened at epoch %d", w.Epoch())
		}
		if e, err := w.Get("mail"); err != nil || secretOf(t, e) != "hunter2" {
			t.Fatalf("read: %v", err)
		}
		if _, err := w.Put(login("new", "x")); err != nil {
			t.Fatalf("write: %v", err)
		}
		rep, _ := w.Verify()
		if ps := problemsNamed(rep, svformat.EpochName(2)); len(ps) != 1 || !strings.Contains(ps[0].Err.Error(), "not made by anyone") {
			t.Fatalf("the planted record is not reported: %+v", rep.Problems)
		}
		if ps := problemsNamed(rep, svformat.EpochName(7)); len(ps) != 1 {
			t.Fatalf("the garbled record is not reported: %+v", rep.Problems)
		}
	}

	// Rotating says what is in the way, rather than "try again".
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err == nil || !strings.Contains(err.Error(), "cannot open the vault") {
		t.Fatalf("rotating past a planted record: %v", err)
	}
	store.Remove(svformat.EpochName(2))
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
		t.Fatalf("rotating once it is removed: %v", err)
	}
}

func TestSomeoneCutOffCannotAddToTheVault(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("shared", "before"))
	bob, _ := svcrypto.Modern.NewIdentity()
	v.AddSlot(NewSlot{Type: svformat.SlotRecipient, Label: "bob", Recipient: bob.Recipient()})

	// Bob has the vault open, and so its key, when he is cut off.
	b, _ := Open(store, Options{})
	if err := b.Unlock(IdentityKey(bob)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, true,
		func(s SlotInfo) bool { return s.Label == "bob" }); err != nil {
		t.Fatal(err)
	}

	// He writes on with the old key: a change, and an item of his own.
	if _, err := b.Put(login("shared", "changed by bob")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Put(login("web/bank", "phished")); err != nil {
		t.Fatal(err)
	}

	for _, w := range []*Vault{v, func() *Vault {
		w, _ := Open(store, Options{})
		if err := w.Unlock(Passphrase(pass)); err != nil {
			t.Fatal(err)
		}
		return w
	}()} {
		if err := w.Refresh(); err != nil {
			t.Fatal(err)
		}
		if e, err := w.Get("shared"); err != nil || secretOf(t, e) != "before" || len(e.Conflicts) != 0 {
			t.Fatalf("bob's change counted: %+v, %v", e, err)
		}
		if _, err := w.Get("web/bank"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("bob's new item counted: %v", err)
		}
		rep, _ := w.Verify()
		late := 0
		for _, p := range rep.Problems {
			if errors.Is(p.Err, ErrLateRevision) {
				late++
			}
		}
		if late != 2 {
			t.Fatalf("late revisions reported: %d, %+v", late, rep.Problems)
		}
	}

	// And what was there before the rotation still reads, down the chain.
	h, err := v.History("shared")
	if err != nil || len(h) < 2 {
		t.Fatalf("history: %d, %v", len(h), err)
	}
}

func TestARealRotationStillLocksTheOtherHandles(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	w, _ := Open(store, Options{})
	w.Unlock(Passphrase(pass))
	plantEpoch(t, store, v, 2, nil)
	store.Remove(svformat.EpochName(2))
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Refresh(); !errors.Is(err, ErrRotated) {
		t.Fatalf("Refresh after a real rotation: %v", err)
	}
	if err := w.Unlock(Passphrase(pass)); err != nil || w.Epoch() != 2 {
		t.Fatalf("unlock after: %v, epoch %d", err, w.Epoch())
	}
}
