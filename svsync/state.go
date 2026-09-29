package svsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// State is what a device remembers between syncs of one vault with one
// server: how far into the server's change log it has read, and which
// files it knows the server holds. It lives in its own file, outside the
// vault folder (a synced folder must not carry one device's state to
// another), and is replaced atomically each time it is saved.
//
// Losing it is safe: the next sync reads the whole log again and finds
// everything in place. It only forgets which keyslots this device
// removed, so those come back (a keyslot can only ever add a way in).
type State struct {
	mu   sync.Mutex // held for a whole sync
	path string

	// Log is the ID of the server's change log the cursor belongs to.
	Log string

	// Cursor is the sequence number of the last change applied.
	Cursor uint64

	// Known are the files this device knows the server holds.
	Known map[string]bool
}

const stateFormat = "secretvault-sync/v1/state"

type stateDoc struct {
	Format string   `json:"format"`
	Log    string   `json:"log,omitempty"`
	Cursor uint64   `json:"cursor"`
	Known  []string `json:"known"`
}

// LoadState reads the state kept at path; a missing file is a fresh
// start.
func LoadState(path string) (*State, error) {
	st := &State{path: path, Known: map[string]bool{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	var doc stateDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc.Format != stateFormat {
		return nil, fmt.Errorf("svsync: %s is not a sync state file", path)
	}
	st.Log, st.Cursor = doc.Log, doc.Cursor
	for _, n := range doc.Known {
		st.Known[n] = true
	}
	return st, nil
}

// Path is where the state is saved.
func (st *State) Path() string { return st.path }

// reset forgets everything: the server's log is not the one the cursor
// belongs to.
func (st *State) reset(log string) {
	st.Log, st.Cursor, st.Known = log, 0, map[string]bool{}
}

// save writes the state atomically. The caller holds st.mu.
func (st *State) save() error {
	doc := stateDoc{Format: stateFormat, Log: st.Log, Cursor: st.Cursor, Known: make([]string, 0, len(st.Known))}
	for n := range st.Known {
		doc.Known = append(doc.Known, n)
	}
	sort.Strings(doc.Known)
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	dir := filepath.Dir(st.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := writeTemp(dir, b)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(dir)
	return nil
}

// writeTemp writes data to a new, synced, owner-only file in dir.
func writeTemp(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), 0o600)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// syncDir makes a new directory entry durable, where the OS allows it
// (Windows does not open directories this way; NTFS journals entries).
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}
