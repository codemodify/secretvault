package svcore

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svstore"
)

func TestRestoringAnEarlierRevisionAndADeletedItem(t *testing.T) {
	v := newVault(t, svstore.NewMem(), svcrypto.Modern)
	v.Put(login("bank", "first"))
	v.Attach("bank", "card.pdf", "", []byte("scan"))
	v.Put(login("bank", "second"))
	h, _ := v.History("bank")
	if len(h) != 3 {
		t.Fatalf("history: %d", len(h))
	}
	first := h[1].Rev.String() // with the file, before the change
	if _, err := v.Restore("bank", first[:4]); err == nil {
		t.Fatal("a four-character revision was accepted")
	}
	e, err := v.Restore("bank", first[:10])
	if err != nil {
		t.Fatal(err)
	}
	if secretOf(t, e) != "first" || len(e.Item.Files) != 1 {
		t.Fatalf("restored: %+v", e.Item)
	}
	if _, data, err := v.ReadFile("bank", "card.pdf"); err != nil || string(data) != "scan" {
		t.Fatalf("its file: %q, %v", data, err)
	}

	// Deleted, listed, and brought back.
	if err := v.Delete("bank"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("bank"); !errors.Is(err, ErrNotFound) {
		t.Fatal("still there after delete")
	}
	del, err := v.Deleted("")
	if err != nil || len(del) != 1 || del[0].Name != "bank" {
		t.Fatalf("deleted: %+v, %v", del, err)
	}
	if e, err = v.Restore("bank", ""); err != nil || secretOf(t, e) != "first" {
		t.Fatalf("undelete: %v", err)
	}
	if del, _ := v.Deleted(""); len(del) != 0 {
		t.Fatalf("still listed as deleted: %+v", del)
	}
	if _, err := v.Restore("bank", ""); err == nil {
		t.Fatal("undeleting a live item")
	}

	// A revision under a name another item has taken since is refused.
	v.Put(login("old-name", "x"))
	h, _ = v.History("old-name")
	v.Rename("old-name", "new-name")
	v.Put(login("old-name", "someone else"))
	if _, err := v.Restore("new-name", h[0].Rev.String()); err == nil {
		t.Fatal("restored over another item's name")
	}
}

func TestRestoringSettlesAConflict(t *testing.T) {
	store := svstore.NewMem()
	a := newVault(t, store, svcrypto.Modern)
	a.Put(login("shared", "base"))
	b, _ := Open(store, Options{})
	b.Unlock(Passphrase(pass))
	a.Put(login("shared", "from a"))
	b.Put(login("shared", "from b"))
	a.Refresh()
	e, _ := a.Get("shared")
	if len(e.Conflicts) != 1 {
		t.Fatalf("no conflict: %+v", e)
	}
	loser := e.Conflicts[0].String()
	if e.Rev.String() == loser {
		t.Fatal("the loser is the winner")
	}
	kept := "from a"
	if secretOf(t, e) == "from a" {
		kept = "from b"
	}
	e, err := a.Restore("shared", loser[:12])
	if err != nil {
		t.Fatal(err)
	}
	if secretOf(t, e) != kept || len(e.Conflicts) != 0 {
		t.Fatalf("after keeping the other: %q, conflicts %d", secretOf(t, e), len(e.Conflicts))
	}
	b.Refresh()
	if e, _ := b.Get("shared"); secretOf(t, e) != kept || len(e.Conflicts) != 0 {
		t.Fatal("the other handle disagrees")
	}
}
