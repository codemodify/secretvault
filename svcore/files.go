package svcore

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// Attachments. A file's contents go in a blob of their own
// (svformat.SealBlob) under a random key; the item holds the key, with the
// file's name, type, size and hash. Attaching or detaching writes a new
// revision of the item; the blob of a file detached or replaced stays, as
// earlier revisions refer to it.

// ErrNoFile is an item without the file asked for.
var ErrNoFile = errors.New("svcore: the item has no such file")

// checkFileName accepts names people give files: non-empty, at most 255
// bytes of UTF-8, no control characters and no '/'.
func checkFileName(name string) error {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return fmt.Errorf("svcore: bad file name %q", name)
	}
	for _, r := range name {
		if r == '/' || unicode.IsControl(r) {
			return fmt.Errorf("svcore: bad file name %q", name)
		}
	}
	return nil
}

// live finds a live item by name. The caller holds v.mu, with the vault
// open.
func (v *Vault) live(name string) (svformat.ID, *object, error) {
	id, ok := v.idx.byName[name]
	if !ok {
		return svformat.ID{}, nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	o := v.idx.objects[id]
	if len(o.heads) == 0 || o.heads[0].deleted || o.heads[0].item == nil {
		return svformat.ID{}, nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return id, o, nil
}

// Attach stores data as the file named file of the item, replacing a file
// of that name. typ is its media type, or "".
func (v *Vault) Attach(name, file, typ string, data []byte) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	if err := checkFileName(file); err != nil {
		return Entry{}, err
	}
	id, o, err := v.live(name)
	if err != nil {
		return Entry{}, err
	}
	blob, key := svformat.NewID(), svcrypto.RandomKey()
	sealed, err := svformat.SealBlob(v.suite, v.desc.ID, blob, key, data)
	if err != nil {
		clear(key)
		return Entry{}, err
	}
	if err := v.store.Create(svformat.BlobName(blob), sealed); err != nil {
		clear(key)
		return Entry{}, err
	}
	sum := sha256.Sum256(data)
	f := File{Name: file, Type: typ, Size: int64(len(data)), Hash: sum[:], Blob: blob, Key: key}
	it := o.heads[0].item.clone()
	defer it.Wipe()
	replaced := false
	for i := range it.Files {
		if it.Files[i].Name == file {
			clear(it.Files[i].Key)
			it.Files[i], replaced = f, true
		}
	}
	if !replaced {
		it.Files = append(it.Files, f)
	}
	return v.write(id, o.heads, payload{Type: payloadItem, Item: &it})
}

// Detach removes the named file from the item.
func (v *Vault) Detach(name, file string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	id, o, err := v.live(name)
	if err != nil {
		return Entry{}, err
	}
	it := o.heads[0].item.clone()
	defer it.Wipe()
	for i, f := range it.Files {
		if f.Name == file {
			clear(f.Key)
			it.Files = append(it.Files[:i], it.Files[i+1:]...)
			return v.write(id, o.heads, payload{Type: payloadItem, Item: &it})
		}
	}
	return Entry{}, fmt.Errorf("%w: %q in %q", ErrNoFile, file, name)
}

// ReadFile returns the named file of the item: its description (without
// its key) and its contents, checked against the hash the item holds.
func (v *Vault) ReadFile(name, file string) (File, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return File{}, nil, ErrLocked
	}
	_, o, err := v.live(name)
	if err != nil {
		return File{}, nil, err
	}
	for _, f := range o.heads[0].item.Files {
		if f.Name != file {
			continue
		}
		data, err := v.openBlob(f)
		if err != nil {
			return File{}, nil, err
		}
		f.Key = nil
		f.Hash = append([]byte(nil), f.Hash...)
		return f, data, nil
	}
	return File{}, nil, fmt.Errorf("%w: %q in %q", ErrNoFile, file, name)
}

// openBlob reads and checks a file's blob.
func (v *Vault) openBlob(f File) ([]byte, error) {
	b, err := v.store.Read(svformat.BlobName(f.Blob))
	if err != nil {
		return nil, fmt.Errorf("svcore: the contents of %q are missing: %w", f.Name, err)
	}
	data, err := svformat.OpenBlob(b, v.suite, v.desc.ID, f.Blob, f.Key, f.Size)
	if err != nil {
		return nil, fmt.Errorf("svcore: the contents of %q: %w", f.Name, err)
	}
	sum := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(sum[:], f.Hash) != 1 {
		clear(data)
		return nil, fmt.Errorf("svcore: the contents of %q: %w", f.Name, svformat.ErrBlob)
	}
	return data, nil
}
