package svcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// cheapKDF makes passphrase slots fast to create and open in tests.
func cheapKDF(t testing.TB) {
	t.Helper()
	a, p := svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	svcrypto.DefaultPBKDF2 = svcrypto.KDFParams{Alg: svcrypto.PBKDF2SHA256, Iterations: 10}
	t.Cleanup(func() { svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2 = a, p })
}

var pass = []byte("correct horse battery staple")

func newVault(t *testing.T, store svstore.Backend, suite svcrypto.Suite) *Vault {
	t.Helper()
	cheapKDF(t)
	v, _, err := Create(store, suite, NewSlot{Type: svformat.SlotPassphrase, Label: "main", Passphrase: pass}, Options{Device: svformat.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func login(name, password string) Item {
	return Item{Kind: "login", Name: name, Attrs: map[string]string{"service": name}, Fields: []Field{
		{Name: "username", Type: FieldText, Value: []byte("ada")},
		{Name: "password", Type: FieldConcealed, Value: []byte(password)},
	}}
}

func secretOf(t *testing.T, e Entry) string {
	t.Helper()
	f, ok := e.Item.Secret()
	if !ok {
		t.Fatalf("%q has no secret", e.Item.Name)
	}
	return string(f.Value)
}

func TestAVaultOpensOnlyWithItsPassphrase(t *testing.T) {
	for _, suite := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		t.Run(suite.String(), func(t *testing.T) {
			store := svstore.NewMem()
			v := newVault(t, store, suite)
			if _, err := v.Put(login("github.com", "hunter2")); err != nil {
				t.Fatal(err)
			}
			v.Lock()
			if _, err := v.Get("github.com"); !errors.Is(err, ErrLocked) {
				t.Fatalf("Get while locked = %v", err)
			}

			w, err := Open(store, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !w.Locked() || w.Suite() != suite {
				t.Fatal("a fresh handle is not locked, or has the wrong suite")
			}
			if err := w.Unlock(Passphrase([]byte("wrong"))); !errors.Is(err, ErrWrongKey) {
				t.Fatalf("wrong passphrase = %v", err)
			}
			if err := w.Unlock(Passphrase(pass)); err != nil {
				t.Fatal(err)
			}
			e, err := w.Get("github.com")
			if err != nil || secretOf(t, e) != "hunter2" || e.Item.Attrs["service"] != "github.com" {
				t.Fatalf("Get = %+v, %v", e, err)
			}
		})
	}
}

func TestCreateRefusesAnExistingVaultAndOpenAnEmptyPlace(t *testing.T) {
	store := svstore.NewMem()
	newVault(t, store, 0)
	if _, _, err := Create(store, 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, Options{}); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create = %v", err)
	}
	if _, err := Open(svstore.NewMem(), Options{}); !errors.Is(err, ErrNotVault) {
		t.Fatalf("Open of nothing = %v", err)
	}
}

func TestEveryKeyslotTypeOpensTheVault(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("a", "1"))

	rec, err := v.AddSlot(NewSlot{Type: svformat.SlotRecovery, Label: "paper"})
	if err != nil || rec.RecoveryKey == "" {
		t.Fatalf("recovery slot: %+v, %v", rec, err)
	}
	keyfile := svcrypto.RandomBytes(64)
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotKeyfile, Keyfile: keyfile}); err != nil {
		t.Fatal(err)
	}
	id, _ := svcrypto.Modern.NewIdentity()
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotRecipient, Label: "laptop", Recipient: id.Recipient()}); err != nil {
		t.Fatal(err)
	}
	slots, _ := v.Slots()
	if len(slots) != 4 {
		t.Fatalf("%d slots, want 4", len(slots))
	}
	for _, s := range slots {
		if s.RecoveryKey != "" {
			t.Fatal("Slots leaks a recovery key")
		}
	}

	rk, err := svformat.ParseRecoveryKey(rec.RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := svcrypto.Modern.NewIdentity()
	for name, tc := range map[string]struct {
		good, bad Key
	}{
		"recovery":  {RecoveryKey(rk), RecoveryKey(svcrypto.RandomKey())},
		"keyfile":   {Keyfile(keyfile), Keyfile(svcrypto.RandomBytes(64))},
		"recipient": {IdentityKey(id), IdentityKey(other)},
	} {
		w, _ := Open(store, Options{})
		if err := w.Unlock(tc.bad); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s: a wrong key = %v", name, err)
		}
		if err := w.Unlock(tc.good); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if e, err := w.Get("a"); err != nil || secretOf(t, e) != "1" {
			t.Errorf("%s: Get = %v", name, err)
		}
	}
}

func TestRemovingASlotStopsItsKeyButNeverTheLastOne(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	first := v.UnlockedBy()
	if err := v.RemoveSlot(first); !errors.Is(err, ErrLastSlot) {
		t.Fatalf("removing the only slot = %v", err)
	}
	second, err := v.AddSlot(NewSlot{Type: svformat.SlotPassphrase, Passphrase: []byte("new passphrase")})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveSlot(first); err != nil {
		t.Fatal(err)
	}
	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the removed passphrase still opens: %v", err)
	}
	if err := w.Unlock(Passphrase([]byte("new passphrase"))); err != nil || w.UnlockedBy() != second.ID {
		t.Fatalf("the new passphrase: %v", err)
	}
	w.Lock()
	if err := w.RemoveSlot(second.ID); !errors.Is(err, ErrLocked) {
		t.Fatalf("RemoveSlot while locked = %v", err)
	}
}

func TestAPlantedSlotCannotOpenTheVault(t *testing.T) {
	// Someone with write access to the folder adds a slot for this vault
	// with a passphrase they know, wrapping a key they made up.
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("a", "1"))
	evil := &svformat.Slot{Format: svformat.SlotFormat, ID: svformat.NewID(), Vault: v.ID(), Epoch: 1,
		Type: svformat.SlotPassphrase, Created: time.Now(), Grants: []string{svformat.GrantContent}}
	p := svcrypto.Modern.NewKDFParams()
	evil.KDF = &p
	kek, _ := p.DeriveKey([]byte("attacker"))
	evil.Wrapped, _ = svcrypto.Modern.Seal(kek, svcrypto.RandomKey(), evil.AAD())
	b, _ := json.Marshal(evil)
	store.Create(svformat.SlotName(evil.ID), b)

	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase([]byte("attacker"))); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a planted slot unlocked the vault: %v", err)
	}
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatalf("the real passphrase no longer works: %v", err)
	}
}

func TestItemsKeepTheirHistory(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	for _, p := range []string{"one", "two", "three"} {
		if _, err := v.Put(login("site", p)); err != nil {
			t.Fatal(err)
		}
	}
	e, _ := v.Get("site")
	if secretOf(t, e) != "three" || len(e.Conflicts) != 0 {
		t.Fatalf("Get = %q, conflicts %v", secretOf(t, e), e.Conflicts)
	}
	h, err := v.History("site")
	if err != nil || len(h) != 3 {
		t.Fatalf("History = %d entries, %v", len(h), err)
	}
	for i, want := range []string{"three", "two", "one"} {
		if got := secretOf(t, h[i]); got != want || h[i].ID != e.ID {
			t.Errorf("History[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestDeletingHidesAnItemAndItsNameCanBeReused(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	first, _ := v.Put(login("site", "old"))
	v.Put(login("other", "x"))
	if err := v.Delete("site"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v", err)
	}
	if l, _ := v.List(""); len(l) != 1 || l[0].Item.Name != "other" {
		t.Fatalf("List after Delete = %+v", l)
	}
	if err := v.Delete("site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete = %v", err)
	}
	again, _ := v.Put(login("site", "new"))
	if again.ID == first.ID {
		t.Fatal("a re-created item reused the deleted item's identity")
	}
}

func TestPutNewNeverOverwrites(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	if _, err := v.PutNew(login("site", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutNew(login("site", "second")); !errors.Is(err, ErrItemExists) {
		t.Fatalf("PutNew over an item = %v", err)
	}
	if e, _ := v.Get("site"); string(e.Item.Fields[1].Value) != "first" {
		t.Fatalf("the item became %q", e.Item.Fields[1].Value)
	}
	v.Delete("site")
	if _, err := v.PutNew(login("site", "third")); err != nil {
		t.Fatalf("PutNew over a deleted item = %v", err)
	}
}

func TestAnItemIsFoundByItsIDOnlyWhereItsNameLeads(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	w, _ := Open(store, Options{})
	w.Unlock(Passphrase(pass))
	a, _ := v.Put(login("site", "a"))
	if e, err := v.GetID(a.ID); err != nil || e.Item.Name != "site" || secretOf(t, e) != "a" {
		t.Fatalf("GetID = %+v, %v", e, err)
	}
	if _, err := v.GetID(svformat.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetID of nothing = %v", err)
	}
	// Another device makes the same name at once: only the winner is found
	// by ID, so a delete by its name never reaches the other.
	b, _ := w.Put(login("site", "b"))
	v.Refresh()
	winner, _ := v.Get("site")
	loser := a.ID
	if winner.ID == a.ID {
		loser = b.ID
	}
	if _, err := v.GetID(winner.ID); err != nil {
		t.Fatalf("GetID of the name's item = %v", err)
	}
	if _, err := v.GetID(loser); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetID of the shadowed duplicate = %v", err)
	}
	v.Delete("site")
	if _, err := v.GetID(winner.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetID after Delete = %v", err)
	}
	v.Lock()
	if _, err := v.GetID(a.ID); !errors.Is(err, ErrLocked) {
		t.Fatalf("GetID while locked = %v", err)
	}
}

func TestRenameKeepsIdentityAndHistory(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	a, _ := v.Put(login("old/name", "p"))
	v.Put(login("taken", "q"))
	if _, err := v.Rename("old/name", "taken"); err == nil {
		t.Fatal("renamed onto an existing name")
	}
	b, err := v.Rename("old/name", "new/name")
	if err != nil || b.ID != a.ID {
		t.Fatalf("Rename = %+v, %v", b, err)
	}
	if _, err := v.Get("old/name"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the old name still resolves")
	}
	if h, _ := v.History("new/name"); len(h) != 2 {
		t.Fatalf("history after rename has %d entries", len(h))
	}
}

func TestListFiltersByPrefix(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	for _, n := range []string{"web/b", "web/a", "mail/x"} {
		v.Put(login(n, "p"))
	}
	l, _ := v.List("web/")
	if len(l) != 2 || l[0].Item.Name != "web/a" || l[1].Item.Name != "web/b" {
		t.Fatalf("List(web/) = %+v", l)
	}
}

func TestBadNamesAndItemsAreRefused(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	for _, n := range []string{"", "/abs", "trailing/", "a//b", "a/../b", "tab\there"} {
		if _, err := v.Put(login(n, "p")); !errors.Is(err, ErrName) {
			t.Errorf("name %q: %v", n, err)
		}
	}
	it := login("x", "p")
	it.Fields = append(it.Fields, Field{Name: "password", Type: FieldText})
	if _, err := v.Put(it); err == nil {
		t.Error("a repeated field name was accepted")
	}
	if _, err := v.Put(Item{Name: "nokind"}); err == nil {
		t.Error("an item without a kind was accepted")
	}
}

// Two devices share a synced folder and edit the same item before either
// sees the other's change.
func TestConcurrentEditsConflictAgreeOnAWinnerAndMergeOnTheNextWrite(t *testing.T) {
	cheapKDF(t)
	store, _ := svstore.OpenDir(filepath.Join(t.TempDir(), "v"))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, _, err := Create(store, 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass},
		Options{Device: svformat.ID{0xA}, Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	a.Put(login("site", "original"))

	b, _ := Open(store, Options{Device: svformat.ID{0xB}, Now: func() time.Time { return base.Add(time.Hour) }})
	if err := b.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	a.Put(login("site", "from A"))
	b.Put(login("site", "from B")) // later clock: B wins
	a.Refresh()

	ea, _ := a.Get("site")
	eb, _ := b.Get("site")
	if secretOf(t, ea) != "from B" || secretOf(t, eb) != "from B" {
		t.Fatalf("devices disagree: A sees %q, B sees %q", secretOf(t, ea), secretOf(t, eb))
	}
	if len(ea.Conflicts) != 1 || ea.Device != (svformat.ID{0xB}) {
		t.Fatalf("A's view: conflicts %v, device %v", ea.Conflicts, ea.Device)
	}
	if rep, _ := a.Verify(); len(rep.Conflicts) != 1 || rep.OK() {
		t.Fatalf("Verify did not report the conflict: %+v", rep)
	}

	merged, err := a.Put(login("site", "resolved"))
	if err != nil {
		t.Fatal(err)
	}
	b.Refresh()
	eb, _ = b.Get("site")
	if len(merged.Conflicts) != 0 || len(eb.Conflicts) != 0 || secretOf(t, eb) != "resolved" {
		t.Fatalf("the next write did not merge: %v / %v %q", merged.Conflicts, eb.Conflicts, secretOf(t, eb))
	}
	if rep, _ := b.Verify(); !rep.OK() {
		t.Fatalf("Verify after merge: %+v", rep)
	}
}

func TestTheSameNameCreatedTwiceIsReportedAsADuplicate(t *testing.T) {
	store := svstore.NewMem()
	a := newVault(t, store, 0)
	b, _ := Open(store, Options{})
	b.Unlock(Passphrase(pass))
	a.Put(login("site", "a"))
	b.Put(login("site", "b"))
	a.Refresh()
	rep, _ := a.Verify()
	if len(rep.Duplicates["site"]) != 2 {
		t.Fatalf("duplicates = %v", rep.Duplicates)
	}
	ea, _ := a.Get("site")
	eb, _ := b.Get("site")
	if ea.ID != eb.ID {
		t.Fatal("the two handles resolve the name to different items")
	}
}

func TestDamagedAndForeignRevisionsAreSkippedAndReported(t *testing.T) {
	cheapKDF(t)
	dir := filepath.Join(t.TempDir(), "v")
	store, _ := svstore.OpenDir(dir)
	v, _, _ := Create(store, 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, Options{})
	e1, _ := v.Put(login("site", "one"))
	e2, _ := v.Put(login("site", "two"))

	// Flip a byte in the newest revision.
	p := filepath.Join(dir, filepath.FromSlash(svformat.RevisionName(e2.ID, e2.Rev)))
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 1
	os.WriteFile(p, b, 0o600)

	// Copy a revision from another vault into this one, under a valid name.
	otherStore := svstore.NewMem()
	other := newVault(t, otherStore, 0)
	oe, _ := other.Put(login("planted", "x"))
	foreign, _ := otherStore.Read(svformat.RevisionName(oe.ID, oe.Rev))
	store.Create(svformat.RevisionName(oe.ID, oe.Rev), foreign)

	// And a file that is not a revision at all.
	store.Create("objects/zz/junk.svr", []byte("junk"))

	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	rep, _ := w.Verify()
	if len(rep.Problems) != 3 {
		t.Fatalf("Verify found %d problems, want 3: %+v", len(rep.Problems), rep.Problems)
	}
	if _, err := w.Get("planted"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a revision from another vault was accepted")
	}
	// The damaged head is ignored: the item reads as its last good revision.
	// (Detecting that a newer revision should exist is rollback protection,
	// which docs/security.md lists as future work.)
	e, _ := w.Get("site")
	if e.Rev != e1.Rev || secretOf(t, e) != "one" {
		t.Fatalf("Get = %q at %s", secretOf(t, e), e.Rev.Short())
	}
}

func TestLockingWipesDecryptedSecrets(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	e, _ := v.Put(login("site", "hunter2"))
	cached := v.idx.objects[e.ID].heads[0].item.Fields[1].Value
	if string(cached) != "hunter2" {
		t.Fatalf("cache holds %q", cached)
	}
	v.Lock()
	if !bytes.Equal(cached, make([]byte, len(cached))) {
		t.Fatalf("after Lock the cache still holds %q", cached)
	}
	if string(e.Item.Fields[1].Value) != "hunter2" {
		t.Fatal("Lock reached into a copy the caller owns")
	}
}

// recordingStore counts replacing writes.
type recordingStore struct {
	svstore.Backend
	writes []string
}

func (r *recordingStore) Write(name string, data []byte) error {
	r.writes = append(r.writes, name)
	return r.Backend.Write(name, data)
}

func TestAVaultOnlyEverAddsFiles(t *testing.T) {
	// What makes a vault folder safe to sync with anything: no file is ever
	// rewritten, so two devices never edit the same file.
	store := &recordingStore{Backend: svstore.NewMem()}
	v := newVault(t, store, 0)
	v.Put(login("a", "1"))
	v.Put(login("a", "2"))
	v.Rename("a", "b")
	v.AddSlot(NewSlot{Type: svformat.SlotRecovery})
	v.Delete("b")
	if len(store.writes) != 0 {
		t.Fatalf("files were rewritten: %v", store.writes)
	}
}

func TestTheDeviceIDIsCreatedOnceAndKept(t *testing.T) {
	home := t.TempDir()
	a, err := Device(home)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Device(home)
	if a.IsZero() || a != b {
		t.Fatalf("device IDs %s and %s", a, b)
	}
}

func TestHomeHonoursTheOverride(t *testing.T) {
	t.Setenv(EnvHome, "/somewhere/else")
	if h, _ := Home(); h != "/somewhere/else" {
		t.Fatalf("Home = %q", h)
	}
	if d, _ := VaultDir("work"); d != filepath.Join("/somewhere/else", "vaults", "work") {
		t.Fatalf("VaultDir = %q", d)
	}
}

func TestRecordsFromANewerVersionAreKeptButIgnored(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	v.Put(login("site", "p"))
	// A newer version writes a record type this one does not know.
	hdr := svformat.RevisionHeader{Suite: v.Suite(), Vault: v.ID(), Object: svformat.NewID(), Epoch: 1, Time: time.Now().UnixNano()}
	file, err := svformat.SealRevision(hdr, v.wrap().Bytes(), svcrypto.RandomKey(), []byte(`{"type":"grant","app":"/usr/bin/mail"}`))
	if err != nil {
		t.Fatal(err)
	}
	store.Create(svformat.RevisionName(hdr.Object, svformat.RevIDOf(file)), file)

	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if l, _ := w.List(""); len(l) != 1 || l[0].Item.Name != "site" {
		t.Fatalf("List = %+v", l)
	}
	rep, _ := w.Verify()
	if !rep.OK() || rep.Revisions != 2 || rep.Live != 1 {
		t.Fatalf("Verify = %+v", rep)
	}
}

func TestRecordsLiveBesideItemsWithTheirOwnHistory(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	v.Put(login("site", "p"))
	type grant struct{ App, Decision string }
	r, err := v.PutRecord("grant", svformat.ID{}, grant{"/usr/bin/mail", "always"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutRecord("grant", r.ID, grant{"/usr/bin/mail", "deny"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.PutRecord("item", svformat.ID{}, 1); err == nil {
		t.Fatal("a record of kind item was accepted")
	}
	if _, err := v.PutRecord("grant", svformat.NewID(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("updating a missing record: %v", err)
	}

	w, _ := Open(store, Options{})
	w.Unlock(Passphrase(pass))
	recs, err := w.Records("grant")
	if err != nil || len(recs) != 1 {
		t.Fatalf("Records = %v, %v", recs, err)
	}
	var g grant
	json.Unmarshal(recs[0].Data, &g)
	if g.Decision != "deny" {
		t.Fatalf("record = %+v", g)
	}
	if l, _ := w.List(""); len(l) != 1 {
		t.Fatalf("records leak into List: %+v", l)
	}
	if other, _ := w.Records("contact"); len(other) != 0 {
		t.Fatal("records of another kind were returned")
	}
	if err := w.DeleteRecord(recs[0].ID); err != nil {
		t.Fatal(err)
	}
	if recs, _ := w.Records("grant"); len(recs) != 0 {
		t.Fatal("a deleted record is still listed")
	}
	if err := w.DeleteRecord(recs[0].ID); err == nil {
		t.Fatal("deleting twice succeeded")
	}
	if rep, _ := w.Verify(); !rep.OK() {
		t.Fatalf("Verify: %+v", rep)
	}
}

func TestCheckingAKeyLeavesTheVaultAsItWas(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	v.Lock()
	if err := v.CheckKey(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if !v.Locked() {
		t.Fatal("CheckKey unlocked the vault")
	}
	if err := v.CheckKey(Passphrase([]byte("nope"))); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a wrong key: %v", err)
	}
}

func TestConflictingRecordsCarryTheOtherHeads(t *testing.T) {
	cheapKDF(t)
	store, _ := svstore.OpenDir(filepath.Join(t.TempDir(), "v"))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a, _, err := Create(store, 0, NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass},
		Options{Device: svformat.ID{0xA}, Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.PutRecord("contact", svformat.ID{}, "original")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Open(store, Options{Device: svformat.ID{0xB}, Now: func() time.Time { return base.Add(time.Hour) }})
	if err := b.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	a.PutRecord("contact", r.ID, "from A")
	b.PutRecord("contact", r.ID, "from B") // later clock: B wins
	a.Refresh()

	recs, err := a.Records("contact")
	if err != nil || len(recs) != 1 {
		t.Fatalf("Records = %v, %v", recs, err)
	}
	if string(recs[0].Data) != `"from B"` || len(recs[0].Conflicts) != 1 || string(recs[0].Conflicts[0]) != `"from A"` {
		t.Fatalf("record %s with conflicts %s", recs[0].Data, recs[0].Conflicts)
	}
	if _, err := a.PutRecord("contact", r.ID, "merged"); err != nil {
		t.Fatal(err)
	}
	if recs, _ := a.Records("contact"); string(recs[0].Data) != `"merged"` || len(recs[0].Conflicts) != 0 {
		t.Fatalf("the next write did not merge: %s %s", recs[0].Data, recs[0].Conflicts)
	}
}
