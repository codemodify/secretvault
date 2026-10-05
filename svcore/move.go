package svcore

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// Items going from one vault to another (item.move and item.copy in the
// daemon). An item is written to the other vault as a new item of the
// same name, with its current contents: its kind, label, attributes, tags,
// fields and files. Each file's contents are sealed again, under a new key
// and the other vault's own, into that vault's blob store, and read back
// before the item that refers to them is written, so an item never points
// at a blob only its first vault has. Its history stays behind: the copy
// starts its own with this revision. Taking it out of the first vault is a
// deletion (DeleteRev), so it can be brought back from its deleted items.

var (
	// ErrConflict is an item changed on two devices at once, whose
	// versions are to be settled before it is moved or copied.
	ErrConflict = errors.New("svcore: the item was changed on two devices at once; settle the conflict first")

	// ErrChanged is an item that is not as it was read: changed, deleted
	// or renamed since.
	ErrChanged = errors.New("svcore: the item changed since it was read")
)

// CopyTo writes the live item id of v, at its revision rev, into dst as
// a new item of the same name, and returns it as stored there. It fails
// with ErrItemExists if dst has an item of that name, with ErrConflict if
// the item has competing versions, and with ErrChanged if its current
// revision is not rev. On failure dst is left as it was, but for the
// blobs written for it, which nothing refers to (they are removed when
// that can be done). v and dst are never locked at the same time.
func (v *Vault) CopyTo(dst *Vault, id svformat.ID, rev svformat.RevID) (Entry, error) {
	if v == dst {
		return Entry{}, errors.New("svcore: an item is copied to another vault, not its own")
	}
	it, err := v.current(id, rev)
	if err != nil {
		return Entry{}, err
	}
	defer it.Wipe()

	// Every file into dst first, one at a time, read back before it counts.
	files := make([]File, 0, len(it.Files))
	var written []svformat.ID
	drop := func() {
		for i := range files {
			clear(files[i].Key)
		}
		dst.dropBlobs(written)
	}
	for _, f := range it.Files {
		data, err := v.fileData(f)
		if err != nil {
			drop()
			return Entry{}, err
		}
		nf, err := dst.storeBlob(f, data)
		clear(data)
		if err != nil {
			drop()
			return Entry{}, err
		}
		written = append(written, nf.Blob)
		files = append(files, nf)
	}
	for i := range it.Files {
		clear(it.Files[i].Key)
	}
	it.Files = files // wiped with it

	dst.mu.Lock()
	defer dst.mu.Unlock()
	if dst.masters == nil {
		dst.dropBlobsLocked(written)
		return Entry{}, ErrLocked
	}
	if err := it.check(); err != nil {
		dst.dropBlobsLocked(written)
		return Entry{}, err
	}
	if _, taken := dst.idx.byName[it.Name]; taken {
		dst.dropBlobsLocked(written)
		return Entry{}, fmt.Errorf("%w: %q", ErrItemExists, it.Name)
	}
	e, err := dst.write(svformat.NewID(), nil, payload{Type: payloadItem, Item: &it})
	if err != nil {
		dst.dropBlobsLocked(written)
		return Entry{}, err
	}
	return e, nil
}

// current is a copy of the live item id at revision rev, with its files'
// keys, for CopyTo. The caller wipes it.
func (v *Vault) current(id svformat.ID, rev svformat.RevID) (Item, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Item{}, ErrLocked
	}
	o, ok := v.idx.objects[id]
	if !ok || !o.live() || v.idx.byName[o.heads[0].item.Name] != id {
		return Item{}, fmt.Errorf("%w: item %s", ErrChanged, id)
	}
	if len(o.heads) > 1 {
		return Item{}, fmt.Errorf("%w: %q", ErrConflict, o.heads[0].item.Name)
	}
	if o.heads[0].id != rev {
		return Item{}, fmt.Errorf("%w: %q", ErrChanged, o.heads[0].item.Name)
	}
	return o.heads[0].item.clone(), nil
}

// fileData reads and checks the contents of f, a file of one of v's
// items.
func (v *Vault) fileData(f File) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	return v.openBlob(f)
}

// storeBlob seals data, the contents of f, as a new blob of v under a
// new key, and reads it back to check it opens to the same contents. It
// returns f as it is in v.
func (v *Vault) storeBlob(f File, data []byte) (File, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return File{}, ErrLocked
	}
	sum := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(sum[:], f.Hash) != 1 || int64(len(data)) != f.Size {
		return File{}, fmt.Errorf("svcore: the contents of %q: %w", f.Name, svformat.ErrBlob)
	}
	blob, key := svformat.NewID(), svcrypto.RandomKey()
	nf := File{Name: f.Name, Type: f.Type, Size: f.Size, Hash: bytes.Clone(f.Hash), Blob: blob, Key: key}
	sealed, err := svformat.SealBlob(v.suite, v.desc.ID, blob, key, data)
	if err != nil {
		clear(key)
		return File{}, err
	}
	if err := v.store.Create(svformat.BlobName(blob), sealed); err != nil {
		clear(key)
		return File{}, err
	}
	back, err := v.openBlob(nf)
	if err != nil {
		v.dropBlobsLocked([]svformat.ID{blob})
		clear(key)
		return File{}, fmt.Errorf("svcore: the contents of %q did not read back from the vault: %w", f.Name, err)
	}
	same := bytes.Equal(back, data)
	clear(back)
	if !same {
		v.dropBlobsLocked([]svformat.ID{blob})
		clear(key)
		return File{}, fmt.Errorf("svcore: the contents of %q did not read back the same: %w", f.Name, svformat.ErrBlob)
	}
	return nf, nil
}

// dropBlobs removes blobs written for an item that was not written after
// all. Nothing refers to them; what cannot be removed is left, as a blob
// no item names.
func (v *Vault) dropBlobs(ids []svformat.ID) {
	if len(ids) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dropBlobsLocked(ids)
}

func (v *Vault) dropBlobsLocked(ids []svformat.ID) {
	for _, id := range ids {
		v.store.Remove(svformat.BlobName(id))
	}
}

// DeleteRev deletes the live item id, as Delete does, if its current
// revision is still rev and it has no competing versions; else it fails
// with ErrChanged (or ErrConflict), and nothing is written. It is how an
// item that was copied elsewhere is taken out: only the version that was
// copied, never a newer one.
func (v *Vault) DeleteRev(id svformat.ID, rev svformat.RevID) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return ErrLocked
	}
	o, ok := v.idx.objects[id]
	if !ok || !o.live() || v.idx.byName[o.heads[0].item.Name] != id {
		return fmt.Errorf("%w: item %s", ErrChanged, id)
	}
	if len(o.heads) > 1 {
		return fmt.Errorf("%w: %q", ErrConflict, o.heads[0].item.Name)
	}
	if o.heads[0].id != rev {
		return fmt.Errorf("%w: %q", ErrChanged, o.heads[0].item.Name)
	}
	_, err := v.write(id, o.heads, payload{Type: payloadItem, Deleted: true})
	return err
}
