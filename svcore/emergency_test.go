package svcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// An emergency slot opens only with the trustee's identity and the
// release key of its own grant together, and stays bound to that grant.
func TestAnEmergencySlotTakesTheIdentityAndTheReleaseKeyTogether(t *testing.T) {
	for _, suite := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		t.Run(suite.String(), func(t *testing.T) {
			store := svstore.NewMem()
			v := newVault(t, store, suite)
			if _, err := v.Put(login("bank", "s3cret")); err != nil {
				t.Fatal(err)
			}
			trustee, _ := suite.NewIdentity()
			stranger, _ := suite.NewIdentity()
			grant, release := svformat.NewID(), svcrypto.RandomKey()
			info, err := v.AddSlot(NewSlot{Type: svformat.SlotEmergency, Label: "emergency", Recipient: trustee.Recipient(), Grant: grant, ReleaseKey: release})
			if err != nil {
				t.Fatal(err)
			}
			if info.Grant != grant || info.Type != svformat.SlotEmergency {
				t.Fatalf("slot info %+v", info)
			}
			// Neither half is a key the other slot types take.
			if _, err := v.AddSlot(NewSlot{Type: svformat.SlotEmergency, Recipient: trustee.Recipient(), Grant: grant, ReleaseKey: release[:16]}); err == nil {
				t.Fatal("a short release key was taken")
			}
			if _, err := v.AddSlot(NewSlot{Type: svformat.SlotEmergency, Recipient: trustee.Recipient(), ReleaseKey: release}); err == nil {
				t.Fatal("an emergency slot without a grant was made")
			}

			w, err := Open(store, Options{})
			if err != nil {
				t.Fatal(err)
			}
			wrongRelease := svcrypto.RandomKey()
			for name, k := range map[string]Key{
				"the identity alone, as a recipient":   IdentityKey(trustee),
				"the identity and another release key": EmergencyKey(trustee, grant, wrongRelease),
				"the release key and another identity": EmergencyKey(stranger, grant, release),
				"another grant":                        EmergencyKey(trustee, svformat.NewID(), release),
			} {
				if err := w.Unlock(k); !errors.Is(err, ErrWrongKey) {
					t.Errorf("%s: %v", name, err)
				}
			}
			if err := w.Unlock(EmergencyKey(trustee, grant, release)); err != nil {
				t.Fatal(err)
			}
			if e, err := w.Get("bank"); err != nil || secretOf(t, e) != "s3cret" {
				t.Fatalf("read with emergency access: %v", err)
			}
			if w.UnlockedBy() != info.ID {
				t.Fatalf("unlocked by %s, want %s", w.UnlockedBy(), info.ID)
			}

			// The slot cannot be pointed at another grant.
			b, _ := store.Read(svformat.SlotName(info.ID))
			var s svformat.Slot
			json.Unmarshal(b, &s)
			other := svformat.NewID()
			s.Emergency.Grant = other
			moved, _ := json.Marshal(s)
			store.Remove(svformat.SlotName(info.ID))
			store.Create(svformat.SlotName(info.ID), moved)
			x, _ := Open(store, Options{})
			if err := x.Unlock(EmergencyKey(trustee, other, release)); !errors.Is(err, ErrWrongKey) {
				t.Fatalf("a slot moved to another grant: %v", err)
			}
		})
	}
}

// A rotation carries an emergency slot over only when it is given again
// with its release key; a trustee whose grant is carried over opens the
// new epoch with the same identity and release key.
func TestARotationKeepsAnEmergencyGrantOnlyWhenGivenIt(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	trustee, _ := svcrypto.Modern.NewIdentity()
	kept, dropped := svformat.NewID(), svformat.NewID()
	rk, rd := svcrypto.RandomKey(), svcrypto.RandomKey()
	for _, g := range []struct {
		id svformat.ID
		rk []byte
	}{{kept, rk}, {dropped, rd}} {
		if _, err := v.AddSlot(NewSlot{Type: svformat.SlotEmergency, Recipient: trustee.Recipient(), Grant: g.id, ReleaseKey: g.rk}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Rotate([]NewSlot{
		{Type: svformat.SlotPassphrase, Label: "main", Passphrase: pass},
		{Type: svformat.SlotEmergency, Recipient: trustee.Recipient(), Grant: kept, ReleaseKey: rk},
	}, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(login("after", "rotation")); err != nil {
		t.Fatal(err)
	}
	w, _ := Open(store, Options{})
	if err := w.Unlock(EmergencyKey(trustee, dropped, rd)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a grant left out of the rotation: %v", err)
	}
	if err := w.Unlock(EmergencyKey(trustee, kept, rk)); err != nil {
		t.Fatalf("a grant carried over: %v", err)
	}
	if w.Epoch() != 2 {
		t.Fatalf("epoch %d", w.Epoch())
	}
	if e, err := w.Get("after"); err != nil || !bytes.Equal([]byte(secretOf(t, e)), []byte("rotation")) {
		t.Fatalf("after the rotation: %v", err)
	}
}
