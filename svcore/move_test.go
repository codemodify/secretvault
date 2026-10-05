package svcore

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

func TestCopyToCarriesFieldsAndFilesUnderTheOtherVaultsKeys(t *testing.T) {
	srcStore, dstStore := svstore.NewMem(), svstore.NewMem()
	src := newVault(t, srcStore, svcrypto.Modern)
	dst := newVault(t, dstStore, svcrypto.NIST) // another suite: blobs are sealed again
	it := login("bank", "hunter2")
	it.Label, it.Tags = "The bank", []string{"money"}
	src.Put(it)
	scan := bytes.Repeat([]byte("scan "), 1<<14)
	src.Attach("bank", "card.png", "image/png", scan)
	e, _ := src.Get("bank")
	srcFile := fileNamed(t, e, "card.png")

	out, err := src.CopyTo(dst, e.ID, e.Rev)
	if err != nil {
		t.Fatal(err)
	}
	if out.ID == e.ID || out.Item.Name != "bank" || out.Item.Label != "The bank" || out.Item.Attrs["service"] != "bank" ||
		len(out.Item.Tags) != 1 || secretOf(t, out) != "hunter2" {
		t.Fatalf("the copy: %+v", out.Item)
	}
	f := fileNamed(t, out, "card.png")
	if f.Blob == srcFile.Blob || bytes.Equal(f.Key, srcFile.Key) || f.Size != srcFile.Size || !bytes.Equal(f.Hash, srcFile.Hash) {
		t.Fatalf("the file was not sealed again: %+v", f)
	}
	// Its blob is dst's own: it reads there, and is not in src's store.
	_, data, err := dst.ReadFile("bank", "card.png")
	if err != nil || !bytes.Equal(data, scan) {
		t.Fatalf("the file in dst: %d bytes, %v", len(data), err)
	}
	if _, err := dstStore.Read(svformat.BlobName(f.Blob)); err != nil {
		t.Fatal(err)
	}
	if _, err := srcStore.Read(svformat.BlobName(f.Blob)); err == nil {
		t.Fatal("the new blob is in the source's store")
	}
	// No history comes along.
	if h, _ := dst.History("bank"); len(h) != 1 {
		t.Fatalf("history in dst: %d revisions", len(h))
	}
	// The source still has it, untouched.
	if e2, _ := src.Get("bank"); e2.Rev != e.Rev {
		t.Fatal("the source changed")
	}
	// After the lock, from a fresh handle, it still opens.
	dst.Lock()
	again, _ := Open(dstStore, Options{Device: svformat.NewID()})
	if err := again.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, data, err := again.ReadFile("bank", "card.png"); err != nil || !bytes.Equal(data, scan) {
		t.Fatalf("reopened: %v", err)
	}
}

func TestCopyToRefusesATakenNameAChangeAndAConflict(t *testing.T) {
	src := newVault(t, svstore.NewMem(), svcrypto.Modern)
	dst := newVault(t, svstore.NewMem(), svcrypto.Modern)
	src.Put(login("a", "1"))
	src.Attach("a", "f", "", []byte("data"))
	dst.Put(login("a", "theirs"))
	e, _ := src.Get("a")
	before, _ := dst.store.List(svformat.BlobsDir)
	if _, err := src.CopyTo(dst, e.ID, e.Rev); !errors.Is(err, ErrItemExists) {
		t.Fatalf("a taken name: %v", err)
	}
	// Nothing left behind: the blob written for it went again.
	if after, _ := dst.store.List(svformat.BlobsDir); len(after) != len(before) {
		t.Fatalf("blobs left behind: %v", after)
	}
	if d, _ := dst.Get("a"); secretOf(t, d) != "theirs" {
		t.Fatal("the item there was changed")
	}

	src.Put(login("a", "2"))
	if _, err := src.CopyTo(dst, e.ID, e.Rev); !errors.Is(err, ErrChanged) {
		t.Fatalf("a changed item: %v", err)
	}
	if err := src.DeleteRev(e.ID, e.Rev); !errors.Is(err, ErrChanged) {
		t.Fatalf("deleting a changed item: %v", err)
	}
	if _, err := src.CopyTo(src, e.ID, e.Rev); err == nil {
		t.Fatal("copied into its own vault")
	}
	dst.Lock()
	cur, _ := src.Get("a")
	if _, err := src.CopyTo(dst, cur.ID, cur.Rev); !errors.Is(err, ErrLocked) {
		t.Fatalf("a locked vault: %v", err)
	}
}

func TestAConflictIsSettledBeforeAnItemMoves(t *testing.T) {
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
	b.Unlock(Passphrase(pass))
	a.Put(login("site", "from A"))
	b.Put(login("site", "from B"))
	a.Refresh()
	e, _ := a.Get("site")
	if len(e.Conflicts) != 1 {
		t.Fatal("no conflict")
	}
	dst := newVault(t, svstore.NewMem(), svcrypto.Modern)
	if _, err := a.CopyTo(dst, e.ID, e.Rev); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "settle the conflict first") {
		t.Fatalf("a conflict: %v", err)
	}
	if err := a.DeleteRev(e.ID, e.Rev); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleting a conflict: %v", err)
	}
}

func TestDeleteRevIsADeletionThatCanBeUndone(t *testing.T) {
	v := newVault(t, svstore.NewMem(), svcrypto.Modern)
	v.Put(login("a", "1"))
	v.Attach("a", "f", "", []byte("data"))
	e, _ := v.Get("a")
	if err := v.DeleteRev(e.ID, e.Rev); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("still there")
	}
	del, _ := v.Deleted("")
	if len(del) != 1 || del[0].Name != "a" {
		t.Fatalf("deleted items: %+v", del)
	}
	if _, err := v.Restore("a", ""); err != nil {
		t.Fatal(err)
	}
	if _, data, err := v.ReadFile("a", "f"); err != nil || string(data) != "data" {
		t.Fatalf("its file after restoring: %v", err)
	}
}
