package svcore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

func fileNamed(t *testing.T, e Entry, name string) File {
	t.Helper()
	for _, f := range e.Item.Files {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("%s has no file %q: %+v", e.Item.Name, name, e.Item.Files)
	return File{}
}

func TestFilesAttachReadReplaceAndDetach(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("bank", "hunter2"))
	for _, size := range []int{0, 1, svcrypto.StreamChunkSize - 1, svcrypto.StreamChunkSize, svcrypto.StreamChunkSize + 1, 1 << 20} {
		data := make([]byte, size)
		rand.Read(data)
		e, err := v.Attach("bank", "statement.pdf", "application/pdf", data)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if f := fileNamed(t, e, "statement.pdf"); f.Size != int64(size) || f.Type != "application/pdf" {
			t.Fatalf("%d bytes: %+v", size, f)
		}
		f, got, err := v.ReadFile("bank", "statement.pdf")
		if err != nil || !bytes.Equal(got, data) || f.Key != nil {
			t.Fatalf("%d bytes read back: %d bytes, key %v, %v", size, len(got), f.Key != nil, err)
		}
	}
	// Replacing keeps one file of that name; another name adds one.
	v.Attach("bank", "card.png", "image/png", []byte("png"))
	e, _ := v.Get("bank")
	if len(e.Item.Files) != 2 {
		t.Fatalf("files: %+v", e.Item.Files)
	}
	// A program writing the item back without its files keeps them.
	it := e.Item
	it.Files = nil
	it.SetField(Field{Name: "password", Type: FieldConcealed, Value: []byte("changed")})
	if e, _ = v.Put(it); len(e.Item.Files) != 2 {
		t.Fatalf("Put dropped files: %+v", e.Item.Files)
	}
	// Nor can one smuggle in a file of its choosing.
	it.Files = []File{{Name: "evil", Blob: svformat.NewID(), Key: make([]byte, 32)}}
	if e, _ = v.Put(it); len(e.Item.Files) != 2 {
		t.Fatalf("Put took a file from outside: %+v", e.Item.Files)
	}
	// A rename and a rotation keep them readable.
	if _, err := v.Rename("bank", "finance/bank"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}}, false, nil); err != nil {
		t.Fatal(err)
	}
	w, _ := Open(store, Options{})
	if err := w.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, got, err := w.ReadFile("finance/bank", "card.png"); err != nil || string(got) != "png" {
		t.Fatalf("after rename and rotation: %q, %v", got, err)
	}
	if rep, _ := w.Verify(); !rep.OK() {
		t.Fatalf("Verify: %+v", rep.Problems)
	}
	// Detaching.
	if _, err := w.Detach("finance/bank", "card.png"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.ReadFile("finance/bank", "card.png"); !errors.Is(err, ErrNoFile) {
		t.Fatalf("a detached file: %v", err)
	}
	if _, err := w.Detach("finance/bank", "card.png"); !errors.Is(err, ErrNoFile) {
		t.Fatalf("detaching twice: %v", err)
	}
	for _, bad := range []string{"", "a/b", "tab\there", string(make([]byte, 256))} {
		if _, err := w.Attach("finance/bank", bad, "", []byte("x")); err == nil {
			t.Errorf("file name %q accepted", bad)
		}
	}
	if _, err := w.Attach("nothing", "f", "", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attaching to no item: %v", err)
	}
}

func TestADamagedOrSwappedBlobIsRefused(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, svcrypto.Modern)
	v.Put(login("a", "1"))
	v.Put(login("b", "2"))
	ea, _ := v.Attach("a", "f", "", []byte("contents of a"))
	eb, _ := v.Attach("b", "f", "", []byte("contents of b"))
	fa, fb := fileNamed(t, ea, "f"), fileNamed(t, eb, "f")

	// Another item's blob put in its place: bound to its own ID, it fails.
	blobB, _ := store.Read(svformat.BlobName(fb.Blob))
	store.Remove(svformat.BlobName(fa.Blob))
	store.Create(svformat.BlobName(fa.Blob), blobB)
	if _, _, err := v.ReadFile("a", "f"); !errors.Is(err, svformat.ErrBlob) {
		t.Fatalf("a swapped blob: %v", err)
	}
	rep, _ := v.Verify()
	if len(problemsNamed(rep, svformat.BlobName(fa.Blob))) != 1 {
		t.Fatalf("Verify missed the swapped blob: %+v", rep.Problems)
	}
	// Every flipped bit fails.
	orig, _ := store.Read(svformat.BlobName(fb.Blob))
	for i := 0; i < len(orig); i += 7 {
		bad := bytes.Clone(orig)
		bad[i] ^= 1
		if _, err := svformat.OpenBlob(bad, svcrypto.Modern, v.ID(), fb.Blob, fb.Key, fb.Size); err == nil {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
	// A missing blob is reported, not a panic.
	store.Remove(svformat.BlobName(fb.Blob))
	if _, _, err := v.ReadFile("b", "f"); err == nil {
		t.Fatal("a missing blob read")
	}
}

func TestBlobsAreCappedAndNamedCanonically(t *testing.T) {
	id := svformat.NewID()
	if got, ok := svformat.ParseBlobName(svformat.BlobName(id)); !ok || got != id {
		t.Fatal("a blob name does not parse back")
	}
	for _, bad := range []string{"blobs/xx/" + id.String() + ".svb", "blobs/" + id.String() + ".svb", "objects/ab/" + id.String() + ".svb"} {
		if _, ok := svformat.ParseBlobName(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
	if _, err := svformat.SealBlob(svcrypto.Modern, id, id, make([]byte, 32), make([]byte, svformat.MaxBlob+1)); err == nil {
		t.Fatal("a blob over the cap was sealed")
	}
}
