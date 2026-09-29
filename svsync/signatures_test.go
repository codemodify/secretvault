package svsync

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
)

func signedBy(t *testing.T, what string, e svcore.Entry, label string, mine bool) {
	t.Helper()
	s := e.Signature
	if s.Status != svcore.SigVerified || s.Label != label || s.Mine != mine {
		t.Fatalf("%s: signature %+v, want verified by %q (mine %v)", what, s, label, mine)
	}
}

func get(t *testing.T, v *svcore.Vault, name string) svcore.Entry {
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

// Two devices, each with its own key, share a vault through the server.
// Each device's writes are attributed to it on the other; requiring
// signatures reaches both and shuts out a device that cannot sign; and a
// rotation keeps who wrote what.
func TestTwoDevicesSignaturesAreAttributedOnEachOther(t *testing.T) {
	cheapKDF(t)
	s := newServer(t)

	storeA := dirStore(t)
	va, _, err := svcore.Create(storeA, 0, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: passphrase},
		svcore.Options{Device: svformat.NewID(), Signer: svcore.NewDeviceKey()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := va.RegisterDevice("device A"); err != nil {
		t.Fatal(err)
	}
	va.Put(loginItem("sig/shared", secretOriginal))
	a := s.founder(va.ID().String(), storeA)
	a.mustSync()

	b := a.enrol(dirStore(t))
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	vb, err := svcore.Open(b.store, svcore.Options{Device: svformat.NewID(), Signer: svcore.NewDeviceKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.Unlock(svcore.Passphrase(passphrase)); err != nil {
		t.Fatal(err)
	}
	signedBy(t, "A's write, on B", get(t, vb, "sig/shared"), "device A", false)
	if _, _, err := vb.RegisterDevice("device B"); err != nil {
		t.Fatal(err)
	}

	// Both write before either syncs.
	vb.Put(loginItem("sig/from-b", secretFromB))
	vb.Put(loginItem("sig/shared", secretFromB))
	va.Put(loginItem("sig/from-a", secretFromA))
	b.mustSync()
	a.mustSync()
	b.mustSync()

	signedBy(t, "B's new item, on A", get(t, va, "sig/from-b"), "device B", false)
	signedBy(t, "B's change, on A", get(t, va, "sig/shared"), "device B", false)
	signedBy(t, "A's new item, on B", get(t, vb, "sig/from-a"), "device A", false)
	signedBy(t, "A's own item, on A", get(t, va, "sig/from-a"), "device A", true)
	hist, _ := va.History("sig/shared")
	if len(hist) != 2 || hist[0].Signature.Label != "device B" || hist[1].Signature.Label != "device A" {
		t.Fatalf("the history on A: %+v", hist)
	}
	for _, v := range []*svcore.Vault{va, vb} {
		devs, _ := v.Devices()
		if len(devs) != 2 {
			t.Fatalf("the registry: %+v", devs)
		}
	}

	// A third device joins with a version that cannot sign, and never
	// reads the vault again before it writes.
	c := a.enrol(dirStore(t))
	if _, err := c.clone(); err != nil {
		t.Fatal(err)
	}
	vc, _ := svcore.Open(c.store, svcore.Options{Device: svformat.NewID()})
	if err := vc.Unlock(svcore.Passphrase(passphrase)); err != nil {
		t.Fatal(err)
	}

	// A requires signatures; B hears of it.
	if err := va.SetPolicy(svcore.Policy{RequireSignatures: true}); err != nil {
		t.Fatal(err)
	}
	a.mustSync()
	b.mustSync()
	if err := vb.Refresh(); err != nil {
		t.Fatal(err)
	}
	if p, _ := vb.Policy(); !p.RequireSignatures {
		t.Fatal("the policy did not reach B")
	}
	vb.Put(loginItem("sig/under-policy", secretFromB))
	b.mustSync()

	// C's unsigned writes reach both, and neither counts them.
	unsigned, err := vc.Put(loginItem("sig/shared", secretOriginal))
	if err != nil {
		t.Fatal(err)
	}
	vc.Put(loginItem("sig/from-c", secretOriginal))
	c.mustSync()
	a.mustSync()
	b.mustSync()
	for name, v := range map[string]*svcore.Vault{"A": va, "B": vb} {
		signedBy(t, "the shared item on "+name, get(t, v, "sig/shared"), "device B", name == "B")
		if _, err := v.Get("sig/from-c"); !errors.Is(err, svcore.ErrNotFound) {
			t.Fatalf("%s counts C's unsigned item: %v", name, err)
		}
		ignored := false
		hist, _ := v.History("sig/shared")
		for _, h := range hist {
			if h.Rev == unsigned.Rev {
				ignored = h.Ignored && h.Signature.Status == svcore.SigUnsigned
			}
		}
		if !ignored {
			t.Fatalf("%s does not show C's revision as ignored", name)
		}
	}
	signedBy(t, "B's write under the policy, on A", get(t, va, "sig/under-policy"), "device B", false)
	// And C, once it reads the vault again, refuses to write what would
	// not count.
	get(t, vc, "sig/under-policy")
	if _, err := vc.Put(loginItem("sig/from-c-again", secretOriginal)); !errors.Is(err, svcore.ErrSignatureRequired) {
		t.Fatalf("C wrote unsigned knowing the policy: %v", err)
	}

	// A rotates; B unlocks with the new key and still knows who wrote
	// what.
	if _, err := va.Rotate([]svcore.NewSlot{{Type: svformat.SlotPassphrase, Passphrase: newPassphrase}}, true, nil); err != nil {
		t.Fatal(err)
	}
	a.mustSync()
	b.mustSync()
	if err := vb.Refresh(); !errors.Is(err, svcore.ErrRotated) {
		t.Fatalf("B after the rotation: %v", err)
	}
	if err := vb.Unlock(svcore.Passphrase(newPassphrase)); err != nil {
		t.Fatal(err)
	}
	signedBy(t, "the rotation's rewrite, on B", get(t, vb, "sig/from-b"), "device A", false)
	found := false
	hist, _ = vb.History("sig/from-b")
	for _, h := range hist {
		if h.Signature.Label == "device B" && h.Signature.Mine && h.Signature.Status == svcore.SigVerified {
			found = true
		}
	}
	if !found {
		t.Fatalf("B's original write lost its signature in the rotation: %+v", hist)
	}
	vb.Put(loginItem("sig/after-rotation", secretFromB))
	b.mustSync()
	a.mustSync()
	signedBy(t, "B's write after the rotation, on A", get(t, va, "sig/after-rotation"), "device B", false)
	// What Verify finds is C's two ignored revisions, and nothing else.
	for _, v := range []*svcore.Vault{va, vb} {
		rep, err := v.Verify()
		if err != nil || len(rep.Problems) != 2 || len(rep.Conflicts) != 0 {
			t.Fatalf("Verify: %+v, %v", rep.Problems, err)
		}
		for _, p := range rep.Problems {
			if !errors.Is(p.Err, svcore.ErrSignatureRequired) {
				t.Fatalf("Verify: %s: %v", p.Name, p.Err)
			}
		}
	}
}
