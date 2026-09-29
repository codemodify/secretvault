package svbroker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

var pass = []byte("correct horse battery staple")

func newVault(t *testing.T) (*svcore.Vault, svstore.Backend) {
	t.Helper()
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })
	store := svstore.NewMem()
	v, _, err := svcore.Create(store, 0, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return v, store
}

const mail = "exe:/usr/bin/mail"

func check(t *testing.T, b *Broker, v *svcore.Vault, conn any, identity, item string, op Op) (Decision, bool) {
	t.Helper()
	d, found, err := b.Check(v, conn, identity, item, op)
	if err != nil {
		t.Fatal(err)
	}
	return d, found
}

func TestNothingIsAllowedUntilSomeoneDecides(t *testing.T) {
	v, _ := newVault(t)
	b := New(svformat.NewID())
	if _, found := check(t, b, v, nil, mail, "item1", OpRead); found {
		t.Fatal("a decision was found where none was made")
	}
	b.Remember(v, Grant{Identity: mail, Item: "item1", Ops: []Op{OpRead}, Decision: AllowOnce})
	if _, found := check(t, b, v, nil, mail, "item1", OpRead); found {
		t.Fatal("allow-once was remembered")
	}
}

func TestUntilLockLastsUntilTheVaultLocks(t *testing.T) {
	v, _ := newVault(t)
	b := New(svformat.NewID())
	b.Remember(v, Grant{Identity: mail, Item: "item1", Ops: []Op{OpRead}, Decision: AllowUntilLock})
	if d, found := check(t, b, v, nil, mail, "item1", OpRead); !found || !d.Allows() {
		t.Fatal("allow-until-lock was not honoured")
	}
	for _, other := range []struct {
		id, item string
		op       Op
	}{{"exe:/usr/bin/other", "item1", OpRead}, {mail, "item2", OpRead}, {mail, "item1", OpWrite}} {
		if _, found := check(t, b, v, nil, other.id, other.item, other.op); found {
			t.Fatalf("the grant reached %+v", other)
		}
	}
	b.Locked(v.ID())
	if _, found := check(t, b, v, nil, mail, "item1", OpRead); found {
		t.Fatal("allow-until-lock survived the lock")
	}
}

func TestAlwaysIsStoredInTheVaultPerDevice(t *testing.T) {
	v, store := newVault(t)
	device := svformat.NewID()
	b := New(device)
	if err := b.Remember(v, Grant{Identity: mail, Program: "mail", Ops: []Op{OpRead}, Decision: AllowAlways}); err != nil {
		t.Fatal(err)
	}
	// A fresh handle and broker on the same device see it (whole vault: any item).
	w, _ := svcore.Open(store, svcore.Options{})
	w.Unlock(svcore.Passphrase(pass))
	if d, found := check(t, New(device), w, nil, mail, "any-item", OpRead); !found || !d.Allows() {
		t.Fatal("allow-always did not persist")
	}
	// Another device's broker does not: program identities are per machine.
	if _, found := check(t, New(svformat.NewID()), w, nil, mail, "any-item", OpRead); found {
		t.Fatal("a grant crossed to another device")
	}
}

func TestADenyWinsOverAnAllow(t *testing.T) {
	v, _ := newVault(t)
	b := New(svformat.NewID())
	b.Remember(v, Grant{Identity: mail, Ops: []Op{OpRead}, Decision: AllowAlways})
	b.Remember(v, Grant{Identity: mail, Item: "secret-item", Ops: []Op{OpRead}, Decision: DenyAlways})
	if d, _ := check(t, b, v, nil, mail, "secret-item", OpRead); d.Allows() {
		t.Fatal("the deny was overridden")
	}
	if d, _ := check(t, b, v, nil, mail, "other-item", OpRead); !d.Allows() {
		t.Fatal("the vault-wide allow stopped working")
	}
}

func TestAConnectionThatProvedAKeyIsAllowedUntilItLeavesOrTheVaultLocks(t *testing.T) {
	v, _ := newVault(t)
	b := New(svformat.NewID())
	conn := new(int)
	b.AllowConn(conn, v)
	if d, found := check(t, b, v, conn, "anyone", "x", OpDelete); !found || !d.Allows() {
		t.Fatal("the connection grant did not apply")
	}
	if _, found := check(t, b, v, new(int), "anyone", "x", OpDelete); found {
		t.Fatal("another connection inherited the grant")
	}
	b.Locked(v.ID())
	if _, found := check(t, b, v, conn, "anyone", "x", OpDelete); found {
		t.Fatal("the connection grant survived the lock")
	}
	b.AllowConn(conn, v)
	b.DropConn(conn)
	if _, found := check(t, b, v, conn, "anyone", "x", OpDelete); found {
		t.Fatal("the connection grant survived the disconnect")
	}
}

func TestGrantsCanBeListedAndRevoked(t *testing.T) {
	v, _ := newVault(t)
	b := New(svformat.NewID())
	b.Remember(v, Grant{Identity: mail, Ops: []Op{OpRead}, Decision: AllowAlways})
	b.Remember(v, Grant{Identity: "exe:/usr/bin/git", Ops: []Op{OpRead}, Decision: AllowUntilLock})
	views, err := b.List(v)
	if err != nil || len(views) != 2 {
		t.Fatalf("List = %+v, %v", views, err)
	}
	for _, view := range views {
		if err := b.Revoke(v, view.ID); err != nil {
			t.Fatalf("revoke %s: %v", view.Scope, err)
		}
	}
	if views, _ := b.List(v); len(views) != 0 {
		t.Fatalf("after revoking: %+v", views)
	}
	if err := b.Revoke(v, "s:999"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("revoking nothing: %v", err)
	}
}

func TestTheAuditLogIsWritableLockedAndReadableUnlocked(t *testing.T) {
	v, store := newVault(t)
	dir := filepath.Join(t.TempDir(), "audit")
	a := NewAudit(dir)
	// Before the log key is known, entries wait.
	a.Record(v, Entry{Program: "early", Op: OpRead, Outcome: "denied"})
	if err := a.Unlocked(v); err != nil {
		t.Fatal(err)
	}
	a.Record(v, Entry{Program: "mail", Op: OpRead, Item: "imap", Outcome: "allowed"})

	// A new daemon, with the vault locked, can still append...
	locked, _ := svcore.Open(store, svcore.Options{})
	a2 := NewAudit(dir)
	if err := a2.Record(locked, Entry{Program: "probe", Op: OpRead, Outcome: "denied", Reason: "locked"}); err != nil {
		t.Fatal(err)
	}
	// ...but not read.
	if _, err := a2.Read(locked, 0); !errors.Is(err, svcore.ErrLocked) {
		t.Fatalf("read while locked: %v", err)
	}
	locked.Unlock(svcore.Passphrase(pass))
	entries, err := a2.Read(locked, 0)
	if err != nil || len(entries) != 3 {
		t.Fatalf("Read = %+v, %v", entries, err)
	}
	if entries[0].Program != "early" || entries[2].Program != "probe" {
		t.Fatalf("order: %+v", entries)
	}
	if last, _ := a2.Read(locked, 1); len(last) != 1 || last[0].Program != "probe" {
		t.Fatalf("limit: %+v", last)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, v.ID().String()+".log"))
	if bytes.Contains(raw, []byte("mail")) || bytes.Contains(raw, []byte("imap")) {
		t.Fatal("the log is readable on disk")
	}
}

func TestRemovingALogLineShows(t *testing.T) {
	v, _ := newVault(t)
	dir := t.TempDir()
	a := NewAudit(dir)
	a.Unlocked(v)
	for _, p := range []string{"a", "b", "c"} {
		a.Record(v, Entry{Program: p, Op: OpRead, Outcome: "allowed"})
	}
	path := filepath.Join(dir, v.ID().String()+".log")
	raw, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(raw, []byte("\n"))
	os.WriteFile(path, append(lines[0], lines[2]...), 0o600)
	entries, err := NewAudit(dir).Read(v, 0)
	if !errors.Is(err, ErrLogDamaged) || len(entries) != 2 {
		t.Fatalf("Read after removing a line: %d entries, %v", len(entries), err)
	}
}
