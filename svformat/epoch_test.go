package svformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRevisionListsAreSortedAndSearchable(t *testing.T) {
	ids := []RevID{{9}, {1}, {5}, {1}}
	list := RevisionList(ids)
	if len(list) != 3*32 || list[0] != 1 || list[32] != 5 || list[64] != 9 {
		t.Fatalf("RevisionList = %x", list)
	}
	e := &EpochRecord{Revisions: list}
	for _, id := range ids {
		if !e.HasRevision(id) {
			t.Errorf("%x missing", id[:1])
		}
	}
	for _, id := range []RevID{{0}, {2}, {6}, {10}, {9, 1}} {
		if e.HasRevision(id) {
			t.Errorf("%x found", id[:2])
		}
	}
	if (&EpochRecord{}).HasRevision(RevID{}) {
		t.Error("an empty list has a revision")
	}
}

func testEpoch(prevMaster []byte) *EpochRecord {
	e := &EpochRecord{Format: EpochFormat, Vault: ID{1}, N: 2, Created: time.Date(2026, 9, 29, 12, 0, 0, 5, time.UTC),
		Check: bytes.Repeat([]byte{3}, 16), Prev: []byte("sealed"), Revisions: RevisionList([]RevID{{7}, {8}})}
	e.Auth = EpochAuth(prevMaster, e)
	return e
}

func TestAnEpochRecordIsBoundToItsKeyAndEveryField(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	if !CheckEpochAuth(key, testEpoch(key)) {
		t.Fatal("a record does not check against its own key")
	}
	if CheckEpochAuth(bytes.Repeat([]byte{0x43}, 32), testEpoch(key)) {
		t.Fatal("a record checks against another key")
	}
	for name, change := range map[string]func(*EpochRecord){
		"vault":     func(e *EpochRecord) { e.Vault[0]++ },
		"n":         func(e *EpochRecord) { e.N++ },
		"created":   func(e *EpochRecord) { e.Created = e.Created.Add(time.Nanosecond) },
		"check":     func(e *EpochRecord) { e.Check[0]++ },
		"prev":      func(e *EpochRecord) { e.Prev[0]++ },
		"revisions": func(e *EpochRecord) { e.Revisions = e.Revisions[:32] },
	} {
		e := testEpoch(key)
		change(e)
		if CheckEpochAuth(key, e) {
			t.Errorf("changing %s went unnoticed", name)
		}
	}
}

func TestParseEpochRefusesIncompleteRecords(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	good, _ := json.Marshal(testEpoch(key))
	if _, err := ParseEpoch(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*EpochRecord){
		"no auth":        func(e *EpochRecord) { e.Auth = nil },
		"short auth":     func(e *EpochRecord) { e.Auth = e.Auth[:16] },
		"ragged list":    func(e *EpochRecord) { e.Revisions = e.Revisions[:40] },
		"unsorted list":  func(e *EpochRecord) { e.Revisions = append(e.Revisions[32:64:64], e.Revisions[:32]...) },
		"duplicate list": func(e *EpochRecord) { e.Revisions = append(e.Revisions[:32:32], e.Revisions[:32]...) },
		"epoch 1":        func(e *EpochRecord) { e.N = 1 },
	} {
		e := testEpoch(key)
		change(e)
		b, _ := json.Marshal(e)
		if _, err := ParseEpoch(b); !errors.Is(err, ErrEpoch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
