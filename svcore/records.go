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
	Device svformat.ID
	Kind   string
	Data   json.RawMessage // the caller's own JSON; wipe it when done if sensitive
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func checkKind(kind string) error {
	if kind == payloadItem || !kindPattern.MatchString(kind) {
		return fmt.Errorf("svcore: %q is not a record kind", kind)
	}
	return nil
}

// PutRecord stores a record of the given kind: a new one when id is zero
// (its ID is returned), else a new revision of record id.
func (v *Vault) PutRecord(kind string, id svformat.ID, data any) (Record, error) {
	if err := checkKind(kind); err != nil {
		return Record{}, err
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
	return v.idx.objects[id].record(), nil
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
			out = append(out, o.record())
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

func (o *object) record() Record {
	h := o.heads[0]
	return Record{
		ID: o.id, Rev: h.id, Time: time.Unix(0, h.hdr.Time).UTC(), Device: h.hdr.Device,
		Kind: h.kind, Data: append(json.RawMessage(nil), h.record...),
	}
}
