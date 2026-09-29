package svcore

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/codemodify/secretvault/svformat"
)

// Records are vault contents that are not items: remembered access grants
// today, contacts and settings later. They are stored exactly like items
// (encrypted revisions, history, conflicts resolved the same way) but are
// not named, not listed with items, and not visible through the faces that
// serve items. Each record has a kind; a vault can hold records of kinds a
// given version does not know, which that version keeps and ignores.

// Record is the current state of one record.
type Record struct {
	ID     svformat.ID
	Rev    svformat.RevID
	Time   time.Time
	Device svformat.ID // as the header names it, in the clear
	Kind   string
	Data   json.RawMessage // the caller's own JSON; wipe it when done if sensitive

	// Signature is who signed the current revision (devices.go).
	Signature Signature

	// Conflicts hold the data of the record's other heads, when devices
	// changed it at once without seeing each other's change (a deleted
	// head holds none). The next PutRecord replaces them all, so a caller
	// that can merge them should, and write the result.
	Conflicts []json.RawMessage
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func checkKind(kind string) error {
	if kind == payloadItem || !kindPattern.MatchString(kind) {
		return fmt.Errorf("svcore: %q is not a record kind", kind)
	}
	return nil
}

// PutRecord stores a record of the given kind: a new one when id is zero
// (its ID is returned), else a new revision of record id. Device and
// policy records are the engine's own (devices.go).
func (v *Vault) PutRecord(kind string, id svformat.ID, data any) (Record, error) {
	if err := checkKind(kind); err != nil {
		return Record{}, err
	}
	if kind == DeviceKind || kind == PolicyKind {
		return Record{}, fmt.Errorf("svcore: %s records are written through the vault's own methods", kind)
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Record{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return Record{}, ErrLocked
	}
	var parents []*revision
	if id.IsZero() {
		id = svformat.NewID()
	} else if o, ok := v.idx.objects[id]; ok {
		if len(o.heads) > 0 && o.heads[0].kind != kind {
			return Record{}, fmt.Errorf("svcore: object %s is not a %s record", id, kind)
		}
		parents = o.heads
	} else {
		return Record{}, fmt.Errorf("%w: record %s", ErrNotFound, id)
	}
	if _, err := v.write(id, parents, payload{Type: kind, Record: raw}); err != nil {
		return Record{}, err
	}
	return v.record(v.idx.objects[id]), nil
}

// DeleteRecord removes a record by writing a tombstone.
func (v *Vault) DeleteRecord(id svformat.ID) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return ErrLocked
	}
	o, ok := v.idx.objects[id]
	if !ok || len(o.heads) == 0 || o.heads[0].kind == payloadItem || o.heads[0].deleted {
		return fmt.Errorf("%w: record %s", ErrNotFound, id)
	}
	if k := o.heads[0].kind; k == DeviceKind || k == PolicyKind {
		return fmt.Errorf("svcore: %s records are removed through the vault's own methods", k)
	}
	_, err := v.write(id, o.heads, payload{Type: o.heads[0].kind, Deleted: true})
	return err
}

// Records returns every live record of a kind, oldest first.
func (v *Vault) Records(kind string) ([]Record, error) {
	if err := checkKind(kind); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	var out []Record
	for _, o := range v.idx.objects {
		if len(o.heads) == 0 {
			continue
		}
		if h := o.heads[0]; h.kind == kind && !h.deleted && h.record != nil {
			out = append(out, v.record(o))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.Before(out[j].Time)
		}
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out, nil
}

func (v *Vault) record(o *object) Record {
	h := o.heads[0]
	r := Record{
		ID: o.id, Rev: h.id, Time: time.Unix(0, h.hdr.Time).UTC(), Device: h.hdr.Device,
		Signature: v.idx.signature(h, v.ownKey()), Kind: h.kind, Data: append(json.RawMessage(nil), h.record...),
	}
	for _, other := range o.heads[1:] {
		if other.kind == h.kind && !other.deleted && other.record != nil {
			r.Conflicts = append(r.Conflicts, append(json.RawMessage(nil), other.record...))
		}
	}
	return r
}
