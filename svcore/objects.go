package svcore

import (
	"bytes"
	"encoding/json"
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
	ID   svformat.ID
	Rev  svformat.RevID
	Time time.Time

	// Device is the device the revision's header names, in the clear.
	// Only Signature says whether that device wrote it.
	Device svformat.ID

	// Signature is who signed the revision, as the vault's registry tells
	// (devices.go).
	Signature Signature

	Item Item

	// Deleted is set on a tombstone (only History returns those).
	Deleted bool

	// Ignored is set on a revision the vault's policy does not count
	// (only History returns those): it requires signatures, and this
	// one's is missing or does not verify.
	Ignored bool

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

	// forgotten: item and record were dropped (forget), and are read
	// again should the revision become a head again.
	forgotten bool

	// signed is what the signature signs (svformat.SignedData), nil when
	// the revision is not signed; status is what the signature shows, as
	// last checked (index.check), against the key checkedFor names.
	signed     []byte
	status     SigStatus
	checkedFor string

	// device and policy are the data of a device or policy record,
	// kept while the revision is in the index: the registry and the
	// policy are read from every revision, not only heads.
	device *deviceRecord
	policy *Policy
}

// forget wipes and drops what was decrypted.
func (r *revision) forget() {
	if r.item != nil {
		r.item.Wipe()
		r.item = nil
	}
	clear(r.record)
	r.record = nil
	r.forgotten = !r.deleted
}

type object struct {
	id    svformat.ID
	revs  map[svformat.RevID]*revision
	heads []*revision // winner first, among the revisions that count
}

type index struct {
	objects  map[svformat.ID]*object
	byName   map[string]svformat.ID
	dupes    map[string][]svformat.ID
	seen     map[string]bool
	problems []Problem

	// The device registry (devices.go): every registered key, and the
	// objects that hold device records. regProblems are keys it refused.
	reg         map[svformat.ID]*deviceEntry
	deviceObjs  map[svformat.ID]bool
	regProblems []Problem

	policy Policy
}

func newIndex() *index {
	return &index{
		objects:    map[svformat.ID]*object{},
		byName:     map[string]svformat.ID{},
		dupes:      map[string][]svformat.ID{},
		seen:       map[string]bool{},
		reg:        map[svformat.ID]*deviceEntry{},
		deviceObjs: map[svformat.ID]bool{},
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

// computeHeads finds the object's heads among the revisions that count,
// winner first, and drops the decrypted items of revisions that are not
// heads. A head whose contents were dropped before (a revision that
// counts again, or whose child no longer counts) is read again. Only
// revisions that count supersede their parents: one the policy refuses
// cannot hide the revision it names. The caller holds v.mu.
func (v *Vault) computeHeads(x *index, o *object) {
	parent := map[svformat.RevID]bool{}
	for _, r := range o.revs {
		if x.counts(r) {
			for _, p := range r.hdr.Parents {
				parent[p] = true
			}
		}
	}
	o.heads = o.heads[:0]
	for id, r := range o.revs {
		if parent[id] || !x.counts(r) {
			r.forget()
			continue
		}
		o.heads = append(o.heads, r)
	}
	sortHeads(o.heads)
	kept := o.heads[:0]
	for _, r := range o.heads {
		if r.forgotten {
			name := svformat.RevisionName(o.id, r.id)
			again, err := v.loadRevision(name, o.id, r.id)
			if err != nil {
				x.problems = append(x.problems, Problem{name, err})
				delete(o.revs, r.id)
				continue
			}
			r.item, r.record, r.forgotten = again.item, again.record, false
		}
		kept = append(kept, r)
	}
	o.heads = kept
}

// evaluate settles what counts once revisions were added to x: the
// device registry, the signatures, the policy, and the heads (of every
// object when the registry or policy changed, else of those added to).
// The caller holds v.mu.
func (v *Vault) evaluate(x *index, added []*revision, objs map[svformat.ID]bool) {
	devices := false
	for id := range objs {
		if x.deviceObjs[id] {
			devices = true
		}
	}
	regChanged := devices && x.buildRegistry()
	if regChanged {
		for _, o := range x.objects {
			for _, r := range o.revs {
				x.check(r)
			}
		}
	} else {
		for _, r := range added {
			x.check(r)
		}
	}
	policyChanged := x.readPolicy(v.desc.ID)
	if regChanged || policyChanged {
		for _, o := range x.objects {
			v.computeHeads(x, o)
		}
	} else {
		for id := range objs {
			v.computeHeads(x, x.objects[id])
		}
	}
	x.settleDevices(v.ownKey())
	x.rebuildNames()
}

// live reports whether the object is an item that exists now.
func (o *object) live() bool {
	return len(o.heads) > 0 && o.heads[0].kind == payloadItem && !o.heads[0].deleted && o.heads[0].item != nil
}

func (v *Vault) entry(x *index, o *object) Entry {
	w := o.heads[0]
	e := Entry{ID: o.id, Rev: w.id, Time: time.Unix(0, w.hdr.Time).UTC(), Device: w.hdr.Device, Deleted: w.deleted,
		Signature: x.signature(w, v.ownKey())}
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
	var added []*revision
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
		x.add(obj, r)
		added = append(added, r)
		changed[obj] = true
	}
	if len(added) > 0 {
		v.evaluate(x, added, changed)
	}
	return nil
}

// add puts a revision into the index, unsettled (evaluate).
func (x *index) add(obj svformat.ID, r *revision) {
	x.object(obj).revs[r.id] = r
	if r.kind == DeviceKind {
		x.deviceObjs[obj] = true
	}
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
	var signed []byte
	if hdr.Signature != nil {
		signed, err = svformat.SignedData(file, dek, plain)
	}
	clear(dek)
	if err != nil {
		clear(plain)
		return nil, err
	}
	p, err := decodePayload(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	return v.newRevision(rid, hdr, p, signed), nil
}

// newRevision is a revision as the index keeps it. It takes p's item and
// record.
func (v *Vault) newRevision(rid svformat.RevID, hdr svformat.RevisionHeader, p payload, signed []byte) *revision {
	r := &revision{id: rid, hdr: hdr, kind: p.Type, deleted: p.Deleted, signed: signed}
	if p.Type == payloadItem {
		r.item = p.Item
		return r
	}
	r.record = []byte(p.Record)
	if !p.Deleted {
		switch {
		case p.Type == DeviceKind:
			r.device = parseDeviceRecord(p.Record)
		case p.Type == PolicyKind && hdr.Object == PolicyID(v.desc.ID):
			var pol Policy
			if json.Unmarshal(p.Record, &pol) == nil {
				r.policy = &pol
			}
		}
	}
	return r
}

// write seals and stores a new revision of obj with the given parents, and
// adds it to the index.
func (v *Vault) write(obj svformat.ID, parents []*revision, p payload) (Entry, error) {
	signer := v.opts.Signer
	if v.idx.policy.RequireSignatures && !v.canSign(obj, p) {
		return Entry{}, fmt.Errorf("%w, and this device is not registered in it", ErrSignatureRequired)
	}
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
	var file, signed []byte
	if signer != nil {
		file, err = svformat.SealSignedRevision(hdr, v.wrap().Bytes(), dek, plain, signer.private())
		if err == nil {
			signed, err = svformat.SignedData(file, dek, plain)
		}
	} else {
		file, err = svformat.SealRevision(hdr, v.wrap().Bytes(), dek, plain)
	}
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
	// The index keeps copies of its own.
	kept := payload{Type: p.Type, Deleted: p.Deleted}
	if p.Item != nil {
		it := p.Item.clone()
		kept.Item = &it
	}
	if p.Record != nil {
		kept.Record = bytes.Clone(p.Record)
	}
	r := v.newRevision(rid, parsed, kept, signed)
	v.idx.seen[name] = true
	v.idx.add(obj, r)
	v.evaluate(v.idx, []*revision{r}, map[svformat.ID]bool{obj: true})
	o := v.idx.objects[obj]
	if len(o.heads) == 0 {
		return Entry{}, fmt.Errorf("%w: what was just written does not count", ErrSignatureRequired)
	}
	return v.entry(v.idx, o), nil
}

// canSign reports whether a write by this handle would count in a vault
// that requires signatures: its key is registered, for its device, or
// the write registers it. The caller holds v.mu.
func (v *Vault) canSign(obj svformat.ID, p payload) bool {
	own := v.ownKey()
	if own.IsZero() {
		return false
	}
	if e := v.idx.reg[own]; e != nil {
		return e.device == v.opts.Device
	}
	return p.Type == DeviceKind && obj == own
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
	return v.entry(v.idx, v.idx.objects[id]), nil
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
	return v.entry(v.idx, o), nil
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
			out = append(out, v.entry(v.idx, v.idx.objects[id]))
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
	own := v.ownKey()
	var out []Entry
	for rid, known := range o.revs {
		r, err := v.loadRevision(svformat.RevisionName(id, rid), id, rid)
		if err != nil {
			return nil, err
		}
		e := Entry{ID: id, Rev: rid, Time: time.Unix(0, r.hdr.Time).UTC(), Device: r.hdr.Device, Deleted: r.deleted,
			Signature: v.idx.signature(known, own), Ignored: !v.idx.counts(known)}
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
	rep.Problems = append(rep.Problems, x.regProblems...)
	for _, o := range x.objects {
		rep.Revisions += len(o.revs)
		for _, r := range o.revs {
			var err error
			switch {
			case r.status == SigBad:
				err = ErrBadSignature
			case r.status == SigUnverified:
				err = ErrUnknownSigner
			case !x.counts(r):
				err = fmt.Errorf("%w; this one is not signed, and is ignored", ErrSignatureRequired)
			case r.kind == DeviceKind && x.reg[o.id] == nil:
				err = errors.New("svcore: a device record its key never signed; ignored")
			}
			if err != nil {
				if r.status != SigVerified && r.status != SigUnsigned && !x.counts(r) {
					err = fmt.Errorf("%w; the vault requires signatures, so it is ignored", err)
				}
				rep.Problems = append(rep.Problems, Problem{svformat.RevisionName(o.id, r.id), err})
			}
		}
		if !o.live() {
			continue
		}
		rep.Live++
		if len(o.heads) > 1 {
			rep.Conflicts = append(rep.Conflicts, v.entry(x, o))
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
