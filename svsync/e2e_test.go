package svsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// cheapKDF makes passphrase slots fast to create and open in tests.
func cheapKDF(t *testing.T) {
	t.Helper()
	a, p := svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	svcrypto.DefaultPBKDF2 = svcrypto.KDFParams{Alg: svcrypto.PBKDF2SHA256, Iterations: 10}
	t.Cleanup(func() { svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2 = a, p })
}

var (
	passphrase    = []byte("e2e passphrase: tangerine-orbit-lantern")
	newPassphrase = []byte("e2e rotated passphrase: cobalt-meadow-vessel")
)

// Strings that must never reach the server in the clear.
const (
	secretOriginal = "SECRET-VALUE-original-4f1c9a"
	secretFromA    = "SECRET-VALUE-from-A-91c2e7"
	secretFromB    = "SECRET-VALUE-from-B-44d0b3"
	secretMerged   = "SECRET-VALUE-merged-0a77fe"
	attrValue      = "ATTRIBUTE-VALUE-mail.example-5e2d"
)

func loginItem(name, secret string) svcore.Item {
	return svcore.Item{Kind: "login", Name: name, Label: "LABEL " + name, Attrs: map[string]string{"service": attrValue}, Fields: []svcore.Field{
		{Name: "username", Type: svcore.FieldText, Value: []byte("USERNAME-ada-lovelace")},
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte(secret)},
	}}
}

func secretOf(t *testing.T, e svcore.Entry) string {
	t.Helper()
	f, ok := e.Item.Secret()
	if !ok {
		t.Fatalf("%q has no secret", e.Item.Name)
	}
	return string(f.Value)
}

func dirStore(t *testing.T) *svstore.Dir {
	t.Helper()
	d, err := svstore.OpenDir(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// sameVault checks that two handles see the same items, the same winning
// revision of each, and the same conflicts.
func sameVault(t *testing.T, a, b *svcore.Vault) []svcore.Entry {
	t.Helper()
	if err := a.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := b.Refresh(); err != nil {
		t.Fatal(err)
	}
	ea, err := a.List("")
	if err != nil {
		t.Fatal(err)
	}
	eb, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(ea) != len(eb) {
		t.Fatalf("A has %d items, B has %d", len(ea), len(eb))
	}
	for i := range ea {
		x, y := ea[i], eb[i]
		if x.Item.Name != y.Item.Name || x.Rev != y.Rev || !slices.Equal(x.Conflicts, y.Conflicts) || secretOf(t, x) != secretOf(t, y) {
			t.Fatalf("the devices disagree about %q:\n A %s %v %q\n B %s %v %q", x.Item.Name,
				x.Rev.Short(), x.Conflicts, secretOf(t, x), y.Rev.Short(), y.Conflicts, secretOf(t, y))
		}
	}
	return ea
}

func slotIDs(t *testing.T, v *svcore.Vault) []svformat.ID {
	t.Helper()
	slots, err := v.Slots()
	if err != nil {
		t.Fatal(err)
	}
	var ids []svformat.ID
	for _, s := range slots {
		ids = append(ids, s.ID)
	}
	return ids
}

// Two devices share a vault through the server. They edit it at the same
// time, each through its own svcore handle; they sync and agree, conflict
// included; a keyslot removal and a key rotation made on one reach the
// other; and nothing the server holds says anything about the items.
func TestTwoDevicesEditingAtOnceConvergeThroughTheServer(t *testing.T) {
	cheapKDF(t)
	s := newServer(t)

	// Device A makes the vault and puts it on the server.
	storeA := dirStore(t)
	va, _, err := svcore.Create(storeA, 0, svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "main", Passphrase: passphrase},
		svcore.Options{Device: svformat.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	va.Put(loginItem("e2e/shared", secretOriginal))
	va.Put(loginItem("e2e/only-on-a", secretOriginal))
	vaultName := va.ID().String()
	a := s.founder(vaultName, storeA)
	a.mustSync()

	// Device B joins and clones it.
	b := a.enrol(dirStore(t))
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	vb, err := svcore.Open(b.store, svcore.Options{Device: svformat.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.Unlock(svcore.Passphrase(passphrase)); err != nil {
		t.Fatal(err)
	}
	sameVault(t, va, vb)

	// Both edit before either syncs: one item on both (a conflict), and
	// items of their own; B deletes one of A's.
	var wg sync.WaitGroup
	wg.Go(func() {
		va.Put(loginItem("e2e/shared", secretFromA))
		va.Put(loginItem("e2e/new-on-a", secretFromA))
	})
	wg.Go(func() {
		vb.Put(loginItem("e2e/shared", secretFromB))
		vb.Put(loginItem("e2e/new-on-b", secretFromB))
		vb.Delete("e2e/only-on-a")
	})
	wg.Wait()
	a.mustSync()
	b.mustSync()
	a.mustSync()
	entries := sameVault(t, va, vb)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Item.Name)
	}
	if !slices.Equal(names, []string{"e2e/new-on-a", "e2e/new-on-b", "e2e/shared"}) {
		t.Fatalf("items after the sync: %q", names)
	}
	shared, _ := va.Get("e2e/shared")
	if len(shared.Conflicts) != 1 {
		t.Fatalf("the concurrent edits did not show as a conflict: %+v", shared.Conflicts)
	}

	// Then both keep writing while syncing, at the same time.
	ctx := context.Background()
	wg.Go(func() {
		for i := range 5 {
			va.Put(loginItem(fmt.Sprintf("e2e/busy-a-%d", i), secretFromA))
			Sync(ctx, a.store, a.client, a.loadState())
		}
	})
	wg.Go(func() {
		for i := range 5 {
			vb.Put(loginItem(fmt.Sprintf("e2e/busy-b-%d", i), secretFromB))
			Sync(ctx, b.store, b.client, b.loadState())
		}
	})
	wg.Wait()
	a.mustSync()
	b.mustSync()
	a.mustSync()
	if entries := sameVault(t, va, vb); len(entries) != 13 {
		t.Fatalf("%d items after the busy phase", len(entries))
	}

	// A merges the conflict; B sees it resolved.
	va.Put(loginItem("e2e/shared", secretMerged))
	a.mustSync()
	b.mustSync()
	sameVault(t, va, vb)
	if e, _ := vb.Get("e2e/shared"); len(e.Conflicts) != 0 || secretOf(t, e) != secretMerged {
		t.Fatalf("B after the merge: %q, conflicts %v", secretOf(t, e), e.Conflicts)
	}

	// A keyslot added on A reaches B, and so does its removal.
	temp, err := va.AddSlot(svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "temporary", Passphrase: []byte("temporary passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	a.mustSync()
	b.mustSync()
	if !slices.Contains(slotIDs(t, vb), temp.ID) {
		t.Fatal("B did not get the new keyslot")
	}
	if err := va.RemoveSlot(temp.ID); err != nil {
		t.Fatal(err)
	}
	if rep := a.mustSync(); rep.Deleted != 1 {
		t.Fatalf("A's sync after removing a keyslot: %+v", rep)
	}
	if rep := b.mustSync(); rep.Removed != 1 {
		t.Fatalf("B's sync after A removed a keyslot: %+v", rep)
	}
	if slices.Contains(slotIDs(t, vb), temp.ID) {
		t.Fatal("B still has the removed keyslot")
	}
	if _, ok := s.files(vaultName)[svformat.SlotName(temp.ID)]; ok {
		t.Fatal("the server still has the removed keyslot")
	}

	// A rotates the key; B finds itself locked, the old passphrase no
	// longer opens its copy, and the new one opens the same contents.
	if _, err := va.Rotate([]svcore.NewSlot{{Type: svformat.SlotPassphrase, Label: "main", Passphrase: newPassphrase}}, true, nil); err != nil {
		t.Fatal(err)
	}
	a.mustSync()
	b.mustSync()
	if err := vb.Refresh(); !errors.Is(err, svcore.ErrRotated) {
		t.Fatalf("B's refresh after the rotation: %v", err)
	}
	if err := vb.Unlock(svcore.Passphrase(passphrase)); !errors.Is(err, svcore.ErrWrongKey) {
		t.Fatalf("the old passphrase on B: %v", err)
	}
	if err := vb.Unlock(svcore.Passphrase(newPassphrase)); err != nil {
		t.Fatalf("the new passphrase on B: %v", err)
	}
	if vb.Epoch() != 2 {
		t.Fatalf("B is at epoch %d", vb.Epoch())
	}
	sameVault(t, va, vb)
	slots, _ := vb.Slots()
	for _, sl := range slots {
		if sl.Epoch != 2 {
			t.Fatalf("B kept a keyslot of epoch %d", sl.Epoch)
		}
	}
	for n, data := range s.files(vaultName) {
		if strings.HasPrefix(n, svformat.SlotsDir+"/") {
			if sl, err := svformat.ParseSlot([]byte(data)); err != nil || sl.Epoch != 2 {
				t.Fatalf("the server kept an old keyslot: %s", n)
			}
		}
	}
	for _, v := range []*svcore.Vault{va, vb} {
		if rep, err := v.Verify(); err != nil || len(rep.Problems) != 0 {
			t.Fatalf("Verify: %+v, %v", rep.Problems, err)
		}
	}

	// Everything on the server is ciphertext: no item name, label,
	// attribute, field or passphrase appears in any file it keeps.
	forbidden := []string{"e2e/", "LABEL", attrValue, "USERNAME-ada", "SECRET-VALUE", string(passphrase), string(newPassphrase), "temporary passphrase"}
	err = filepath.WalkDir(s.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, f := range forbidden {
			if bytes.Contains(data, []byte(f)) {
				t.Errorf("%s holds %q in the clear", p, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Two devices each run Watch, as the daemon would, refreshing their vault
// whenever a sync brings changes. Writes on either side reach the other
// without any explicit sync.
func TestTwoWatchingDevicesStayInStep(t *testing.T) {
	cheapKDF(t)
	s := newServer(t)
	storeA := dirStore(t)
	va, _, err := svcore.Create(storeA, 0, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: passphrase}, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := s.founder(va.ID().String(), storeA)
	a.mustSync()
	b := a.enrol(dirStore(t))
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	vb, _ := svcore.Open(b.store, svcore.Options{})
	if err := vb.Unlock(svcore.Passphrase(passphrase)); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	triggers := map[*svcore.Vault]chan struct{}{}
	for _, d := range []struct {
		dev *device
		v   *svcore.Vault
	}{{a, va}, {b, vb}} {
		trig := make(chan struct{}, 1)
		triggers[d.v] = trig
		st := d.dev.loadState()
		wg.Go(func() {
			Watch(ctx, d.dev.store, d.dev.client, st, WatchOptions{
				Every:   3 * time.Second,
				Wait:    2 * time.Second,
				Trigger: trig,
				Changed: func(Report) { d.v.Refresh() },
				Failed:  func(err error) { t.Logf("sync: %v", err) },
			})
		})
	}
	defer func() {
		cancel()
		wg.Wait()
	}()

	for i := range 3 {
		va.Put(loginItem(fmt.Sprintf("watch/a-%d", i), secretFromA))
		vb.Put(loginItem(fmt.Sprintf("watch/b-%d", i), secretFromB))
		for _, trig := range triggers {
			select {
			case trig <- struct{}{}:
			default:
			}
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		la, _ := va.List("watch/")
		lb, _ := vb.List("watch/")
		if len(la) == 6 && len(lb) == 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 30 s, A has %d items and B %d", len(la), len(lb))
		}
		time.Sleep(50 * time.Millisecond)
	}
	sameVault(t, va, vb)
}
