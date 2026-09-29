package svcore

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svformat"
)

// Going back: an earlier revision of an item, or one that was deleted,
// made current again. Restoring writes a new revision with the old one's
// contents (its files included: their blobs are never removed), naming
// every current head as a parent, so it also settles a conflict: the
// version kept wins, on every device.

// Deleted is an item that was deleted, as it was before.
type Deleted struct {
	ID      svformat.ID
	Name    string
	Kind    string
	Rev     svformat.RevID // its last revision with contents
	Deleted time.Time      // when the tombstone was written
}

// Deleted lists the deleted items whose names start with prefix, newest
// deletion first. It reads the revisions of every deleted object, so it
// is for a person looking, not for every request.
func (v *Vault) Deleted(prefix string) ([]Deleted, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	var out []Deleted
	for id, o := range v.idx.objects {
		if len(o.heads) == 0 || o.heads[0].kind != payloadItem || !o.heads[0].deleted {
			continue
		}
		last, err := v.lastContents(id, o)
		if err != nil || last == nil {
			continue
		}
		if strings.HasPrefix(last.item.Name, prefix) {
			out = append(out, Deleted{ID: id, Name: last.item.Name, Kind: last.item.Kind, Rev: last.id,
				Deleted: time.Unix(0, o.heads[0].hdr.Time).UTC()})
		}
		last.forget()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deleted.After(out[j].Deleted) })
	return out, nil
}

// lastContents is an object's newest revision that is not a deletion,
// loaded. The caller forgets it.
func (v *Vault) lastContents(id svformat.ID, o *object) (*revision, error) {
	var best *revision
	for rid, r := range o.revs {
		if r.deleted {
			continue
		}
		if best != nil && (r.hdr.Time < best.hdr.Time || r.hdr.Time == best.hdr.Time && bytes.Compare(rid[:], best.id[:]) < 0) {
			continue
		}
		best = r
	}
	if best == nil {
		return nil, nil
	}
	return v.loadRevision(svformat.RevisionName(id, best.id), id, best.id)
}

// Restore makes an earlier revision of an item current again. name is the
// item, live or deleted; rev is one of its revisions, which may be given
// by any unique prefix of its ID (hex), or "" for a deleted item's last
// contents.
func (v *Vault) Restore(name, rev string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	id, o, err := v.findForRestore(name)
	if err != nil {
		return Entry{}, err
	}
	var r *revision
	if rev == "" {
		if !o.heads[0].deleted {
			return Entry{}, fmt.Errorf("svcore: %q is not deleted: say which revision to go back to", name)
		}
		if r, err = v.lastContents(id, o); err != nil {
			return Entry{}, err
		}
	} else {
		rid, err := v.revByPrefix(o, rev)
		if err != nil {
			return Entry{}, err
		}
		if r, err = v.loadRevision(svformat.RevisionName(id, rid), id, rid); err != nil {
			return Entry{}, err
		}
	}
	if r == nil || r.deleted || r.item == nil {
		return Entry{}, fmt.Errorf("svcore: that revision of %q is a deletion", name)
	}
	defer r.forget()
	it := r.item.clone()
	defer it.Wipe()
	if other, taken := v.idx.byName[it.Name]; taken && other != id {
		return Entry{}, fmt.Errorf("svcore: another item is called %q now: rename it first", it.Name)
	}
	return v.write(id, o.heads, payload{Type: payloadItem, Item: &it})
}

// findForRestore finds an item by name: the live one, else the deleted
// one most recently deleted.
func (v *Vault) findForRestore(name string) (svformat.ID, *object, error) {
	if id, ok := v.idx.byName[name]; ok {
		return id, v.idx.objects[id], nil
	}
	var found svformat.ID
	var at int64
	for id, o := range v.idx.objects {
		if len(o.heads) == 0 || !o.heads[0].deleted || o.heads[0].kind != payloadItem {
			continue
		}
		last, err := v.lastContents(id, o)
		if err != nil || last == nil {
			continue
		}
		if last.item.Name == name && o.heads[0].hdr.Time >= at {
			found, at = id, o.heads[0].hdr.Time
		}
		last.forget()
	}
	if found.IsZero() {
		return svformat.ID{}, nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return found, v.idx.objects[found], nil
}

// revByPrefix finds a revision of o by a prefix of its hex ID.
func (v *Vault) revByPrefix(o *object, prefix string) (svformat.RevID, error) {
	prefix = strings.ToLower(prefix)
	if len(prefix) < 6 {
		return svformat.RevID{}, fmt.Errorf("svcore: give at least 6 characters of the revision")
	}
	var hit svformat.RevID
	n := 0
	for rid := range o.revs {
		if strings.HasPrefix(rid.String(), prefix) {
			hit = rid
			n++
		}
	}
	switch n {
	case 0:
		return hit, fmt.Errorf("%w: no revision %s", ErrNotFound, prefix)
	case 1:
		return hit, nil
	}
	return hit, fmt.Errorf("svcore: %d revisions start with %s: give more of it", n, prefix)
}
