package svcore

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// Objects and revisions.
//
// Every write adds a revision file naming the revisions it replaces as its
// parents. An object's current state is its head: the revision no other
// revision names as a parent. Two devices editing the same object without
// seeing each other's change produce two heads, a conflict. The winner is
// the head with the latest clock (ties broken by revision ID), so every
// device that sees the same files agrees on it without talking; the other
// heads stay listed as conflicts until the next write, which names all of
// them as parents and so merges them.

// Entry is an item as stored, with where it came from.
type Entry struct {
	ID     svformat.ID
	Rev    svformat.RevID
	Time   time.Time
	Device svformat.ID
	Item   Item

	// Deleted is set on a tombstone (only History returns those).
	Deleted bool

	// Conflicts are the other heads when the object has more than one.
	Conflicts []svformat.RevID
}

// Problem is a file that could not be used: stray, corrupt, forged or from
// another vault. It is skipped, never trusted.
type Problem struct {
	Name string
	Err  error
}

// ErrChecksum is a revision whose contents do not match its name.
var ErrChecksum = errors.New("svcore: revision contents do not match its name")

type revision struct {
	id      svformat.RevID
	hdr     svformat.RevisionHeader
	kind    string // the payload type: "item", or a record kind
	deleted bool
	item    *Item  // decrypted item; kept only while the revision is a head
	record  []byte // decrypted record body (JSON); kept only while a head
}

// forget wipes and drops what was decrypted.
func (r *revision) forget() {
	if r.item != nil {
		r.item.Wipe()
		r.item = nil
	}
	clear(r.record)
	r.record = nil
}

type object struct {
	id    svformat.ID
	revs  map[svformat.RevID]*revision
	heads []*revision // winner first
}

type index struct {
	objects  map[svformat.ID]*object
	byName   map[string]svformat.ID
	dupes    map[string][]svformat.ID
	seen     map[string]bool
	problems []Problem
}

func newIndex() *index {
	return &index{
		objects: map[svformat.ID]*object{},
		byName:  map[string]svformat.ID{},
		dupes:   map[string][]svformat.ID{},
		seen:    map[string]bool{},
	}
}

func (x *index) wipe() {
	for _, o := range x.objects {
		for _, r := range o.revs {
			r.forget()
		}
	}
	x.objects = nil
}

func (x *index) object(id svformat.ID) *object {
	o := x.objects[id]
	if o == nil {
		o = &object{id: id, revs: map[svformat.RevID]*revision{}}
		x.objects[id] = o
	}
	return o
}

// computeHeads finds the object's heads, winner first, and drops the
// decrypted items of revisions that are no longer heads.
func (o *object) computeHeads() {
	parent := map[svformat.RevID]bool{}
	for _, r := range o.revs {
		for _, p := range r.hdr.Parents {
			parent[p] = true
		}
	}
	o.heads = o.heads[:0]
	for id, r := range o.revs {
		if parent[id] {
			r.forget()
			continue
		}
		o.heads = append(o.heads, r)
	}
	sort.Slice(o.heads, func(i, j int) bool {
		a, b := o.heads[i], o.heads[j]
		if a.hdr.Time != b.hdr.Time {
			return a.hdr.Time > b.hdr.Time
		}
		return bytes.Compare(a.id[:], b.id[:]) > 0
	})
}

// live reports whether the object is an item that exists now.
func (o *object) live() bool {
	return len(o.heads) > 0 && o.heads[0].kind == payloadItem && !o.heads[0].deleted && o.heads[0].item != nil
}

func (o *object) entry() Entry {
	w := o.heads[0]
	e := Entry{ID: o.id, Rev: w.id, Time: time.Unix(0, w.hdr.Time).UTC(), Device: w.hdr.Device, Deleted: w.deleted}
	if w.item != nil {
		e.Item = w.item.clone()
	}
	for _, h := range o.heads[1:] {
		e.Conflicts = append(e.Conflicts, h.id)
	}
	return e
}

// rebuildNames maps every live object's name to it. When two live objects
// share a name (two devices created it at once), the most recently written
// wins and the clash is kept for Verify.
func (x *index) rebuildNames() {
	all := map[string][]svformat.ID{}
	for id, o := range x.objects {
		if o.live() {
			name := o.heads[0].item.Name
			all[name] = append(all[name], id)
		}
	}
	x.byName = make(map[string]svformat.ID, len(all))
	x.dupes = map[string][]svformat.ID{}
	for name, ids := range all {
		sort.Slice(ids, func(i, j int) bool {
			a, b := x.objects[ids[i]].heads[0], x.objects[ids[j]].heads[0]
			if a.hdr.Time != b.hdr.Time {
				return a.hdr.Time > b.hdr.Time
			}
			return bytes.Compare(ids[i][:], ids[j][:]) > 0
		})
		x.byName[name] = ids[0]
		if len(ids) > 1 {
			x.dupes[name] = ids
		}
	}
}

// Refresh reads revisions written since the last look: by another handle,
// another process, or another device through a synced folder.
func (v *Vault) Refresh() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return ErrLocked
	}
	if err := v.checkRotation(); err != nil {
		return err
	}
	return v.scan(v.idx)
}

// scan reads every revision file x has not seen yet into x.
func (v *Vault) scan(x *index) error {
	names, err := v.store.List(svformat.ObjectsDir)
	if err != nil {
		return err
	}
	changed := map[svformat.ID]bool{}
	for _, n := range names {
		if x.seen[n] {
			continue
		}
		x.seen[n] = true
		obj, rid, ok := svformat.ParseRevisionName(n)
		if !ok {
			x.problems = append(x.problems, Problem{n, errors.New("not a revision file")})
			continue
		}
		r, err := v.loadRevision(n, obj, rid)
		if err != nil {
			if errors.Is(err, svstore.ErrNotExist) {
				continue // removed between List and Read
			}
			x.problems = append(x.problems, Problem{n, err})
			continue
		}
		x.object(obj).revs[rid] = r
		changed[obj] = true
	}
	for id := range changed {
		x.objects[id].computeHeads()
	}
	x.rebuildNames()
	return nil
}

// loadRevision reads, checks, authenticates and decrypts one revision.
func (v *Vault) loadRevision(name string, obj svformat.ID, rid svformat.RevID) (*revision, error) {
	file, err := v.store.Read(name)
	if err != nil {
		return nil, err
	}
	if svformat.RevIDOf(file) != rid {
		return nil, ErrChecksum
	}
	hdr, err := svformat.ParseRevision(file)
	if err != nil {
		return nil, err
	}
	if hdr.Vault != v.desc.ID || hdr.Object != obj {
		return nil, fmt.Errorf("svcore: revision belongs to vault %s object %s", hdr.Vault, hdr.Object)
	}
	wrap := v.wraps[hdr.Epoch]
	if hdr.Suite != v.suite || wrap == nil {
		return nil, fmt.Errorf("svcore: revision uses suite %v epoch %d", hdr.Suite, hdr.Epoch)
	}
	if !v.committed(hdr.Epoch, rid) {
		return nil, ErrLateRevision
	}
	hdr, plain, dek, err := svformat.OpenRevision(file, wrap.Bytes())
	if err != nil {
		return nil, err
	}
	clear(dek)
	p, err := decodePayload(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	if p.Type != payloadItem {
		return &revision{id: rid, hdr: hdr, kind: p.Type, deleted: p.Deleted, record: []byte(p.Record)}, nil
	}
	return &revision{id: rid, hdr: hdr, kind: payloadItem, deleted: p.Deleted, item: p.Item}, nil
}

// write seals and stores a new revision of obj with the given parents, and
// adds it to the index.
func (v *Vault) write(obj svformat.ID, parents []*revision, p payload) (Entry, error) {
	hdr := svformat.RevisionHeader{
		Suite:  v.suite,
		Vault:  v.desc.ID,
		Object: obj,
		Epoch:  v.epoch(),
		Time:   v.tick(parents),
		Device: v.opts.Device,
	}
	for _, r := range parents {
		hdr.Parents = append(hdr.Parents, r.id)
	}
	plain, err := encodePayload(p)
	if err != nil {
		return Entry{}, err
	}
	// A fresh content key for every revision.
	dek := svcrypto.RandomKey()
	file, err := svformat.SealRevision(hdr, v.wrap().Bytes(), dek, plain)
	clear(dek)
	clear(plain)
	if err != nil {
		return Entry{}, err
	}
	rid := svformat.RevIDOf(file)
	name := svformat.RevisionName(obj, rid)
	if err := v.store.Create(name, file); err != nil {
		return Entry{}, err
	}
	parsed, err := svformat.ParseRevision(file)
	if err != nil {
		return Entry{}, err
	}
	r := &revision{id: rid, hdr: parsed, kind: p.Type, deleted: p.Deleted}
	if p.Item != nil {
		it := p.Item.clone()
		r.item = &it
	}
	if p.Record != nil {
		r.record = bytes.Clone(p.Record)
	}
	v.idx.seen[name] = true
	o := v.idx.object(obj)
	o.revs[rid] = r
	o.computeHeads()
	v.idx.rebuildNames()
	return o.entry(), nil
}

// Put stores an item under its name: a new revision of the item already
// there (merging any conflict), or a new item.
func (v *Vault) Put(it Item) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	if err := it.check(); err != nil {
		return Entry{}, err
	}
	it = it.clone()
	// Files come only from Attach and Detach: an item written back by a
	// program that knows nothing of them keeps its own.
	for i := range it.Files {
		clear(it.Files[i].Key)
	}
	it.Files = nil
	if id, ok := v.idx.byName[it.Name]; ok {
		o := v.idx.objects[id]
		if h := o.heads[0]; !h.deleted && h.item != nil {
			it.Files = cloneFiles(h.item.Files)
		}
		return v.write(id, o.heads, payload{Type: payloadItem, Item: &it})
	}
	return v.write(svformat.NewID(), nil, payload{Type: payloadItem, Item: &it})
}

// PutNew stores a new item, failing with ErrItemExists if its name is
// taken: a Put that can never overwrite, for callers whose check that the
// name is free and whose store must not be separated.
func (v *Vault) PutNew(it Item) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	if err := it.check(); err != nil {
		return Entry{}, err
	}
	if _, taken := v.idx.byName[it.Name]; taken {
		return Entry{}, fmt.Errorf("%w: %q", ErrItemExists, it.Name)
	}
	it = it.clone()
	for i := range it.Files {
		clear(it.Files[i].Key)
	}
	it.Files = nil
	return v.write(svformat.NewID(), nil, payload{Type: payloadItem, Item: &it})
}

// Rename moves an item to a new name, keeping its identity and history.
func (v *Vault) Rename(from, to string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	if err := CheckName(to); err != nil {
		return Entry{}, err
	}
	id, ok := v.idx.byName[from]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %q", ErrNotFound, from)
	}
	if _, taken := v.idx.byName[to]; taken {
		return Entry{}, fmt.Errorf("svcore: %q already exists", to)
	}
	o := v.idx.objects[id]
	it := o.heads[0].item.clone()
	it.Name = to
	return v.write(id, o.heads, payload{Type: payloadItem, Item: &it})
}

// Get returns the item with the given name.
func (v *Vault) Get(name string) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	id, ok := v.idx.byName[name]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return v.idx.objects[id].entry(), nil
}

// GetID returns the item with the given object ID: the one its name
// reaches, so what is done by name next (Put, Delete) is done to it. An
// item whose name another holds as well (see Verify) is not found.
func (v *Vault) GetID(id svformat.ID) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Entry{}, ErrLocked
	}
	o, ok := v.idx.objects[id]
	if !ok || !o.live() || v.idx.byName[o.heads[0].item.Name] != id {
		return Entry{}, fmt.Errorf("%w: item %s", ErrNotFound, id)
	}
	return o.entry(), nil
}

// List returns every item whose name starts with prefix, by name.
func (v *Vault) List(prefix string) ([]Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	var out []Entry
	for name, id := range v.idx.byName {
		if strings.HasPrefix(name, prefix) {
			out = append(out, v.idx.objects[id].entry())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Item.Name < out[j].Item.Name })
	return out, nil
}

// Delete removes an item by writing a tombstone: a revision with no
// contents. Its earlier revisions stay (see History) until pruned.
func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return ErrLocked
	}
	id, ok := v.idx.byName[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	_, err := v.write(id, v.idx.objects[id].heads, payload{Type: payloadItem, Deleted: true})
	return err
}

// History returns every stored revision of the named item, newest first.
func (v *Vault) History(name string) ([]Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	id, ok := v.idx.byName[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	o := v.idx.objects[id]
	var out []Entry
	for rid := range o.revs {
		r, err := v.loadRevision(svformat.RevisionName(id, rid), id, rid)
		if err != nil {
			return nil, err
		}
		e := Entry{ID: id, Rev: rid, Time: time.Unix(0, r.hdr.Time).UTC(), Device: r.hdr.Device, Deleted: r.deleted}
		if r.item != nil {
			e.Item = *r.item
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.After(out[j].Time)
		}
		return bytes.Compare(out[i].Rev[:], out[j].Rev[:]) > 0
	})
	return out, nil
}

// Report is what Verify found.
type Report struct {
	Objects   int
	Revisions int
	Live      int

	// Problems are files that are not valid revisions of this vault.
	Problems []Problem

	// Conflicts are live items with more than one head.
	Conflicts []Entry

	// Duplicates are names held by more than one live item.
	Duplicates map[string][]svformat.ID
}

// OK reports whether nothing needs attention.
func (r Report) OK() bool {
	return len(r.Problems) == 0 && len(r.Conflicts) == 0 && len(r.Duplicates) == 0
}

// Verify re-reads and re-authenticates every file of the vault from the
// backend, ignoring anything cached.
func (v *Vault) Verify() (Report, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Report{}, ErrLocked
	}
	x := newIndex()
	defer x.wipe()
	if err := v.scan(x); err != nil {
		return Report{}, err
	}
	rep := Report{Objects: len(x.objects), Problems: append(slices.Clone(v.epochProblems), x.problems...), Duplicates: x.dupes}
	for _, o := range x.objects {
		rep.Revisions += len(o.revs)
		if !o.live() {
			continue
		}
		rep.Live++
		if len(o.heads) > 1 {
			rep.Conflicts = append(rep.Conflicts, o.entry())
		}
		if h := o.heads[0]; h.item != nil {
			for _, f := range h.item.Files {
				data, err := v.openBlob(f)
				clear(data)
				if err != nil {
					rep.Problems = append(rep.Problems, Problem{svformat.BlobName(f.Blob), err})
				}
			}
		}
	}
	sort.Slice(rep.Conflicts, func(i, j int) bool { return rep.Conflicts[i].Item.Name < rep.Conflicts[j].Item.Name })
	return rep, nil
}
