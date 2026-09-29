package svsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

// Report says what one sync did.
type Report struct {
	Pulled  int // files fetched into the local folder
	Removed int // keyslots removed from the local folder, because they were removed elsewhere
	Pushed  int // files sent to the server
	Deleted int // keyslot removals sent to the server

	// Kept counts keyslot removals from the server that were not applied,
	// because they would have left the local vault with no key of its
	// current epoch. No device removes the last one, so such a removal
	// is a fault or an attack.
	Kept int
}

// Changed reports whether the local folder changed, so an open vault
// should be refreshed.
func (r Report) Changed() bool { return r.Pulled+r.Removed > 0 }

var (
	// ErrDiverged is a file the server holds with other contents than
	// this device's (a *DivergedError says which).
	ErrDiverged = errors.New("svsync: the server and this device hold different files under one name")

	// ErrBadFile is a file from the server that does not match its name
	// or what the server's log says of it. It is not stored.
	ErrBadFile = errors.New("svsync: the server sent a file that does not match its name or its log")

	// ErrNoVault is a Clone from a server that holds no vault by that name.
	ErrNoVault = errors.New("svsync: there is no vault on the server to clone yet")

	// ErrNotEmpty is a Clone into a folder that holds a vault already.
	ErrNotEmpty = errors.New("svsync: that folder holds a vault already")
)

// DivergedError is a file this device and the server hold with different
// contents. Files are written once, so this never heals by itself:
// nothing is overwritten, and the sync stops before it sends anything.
type DivergedError struct {
	Name string
	Kind svserver.FileKind
}

func (e *DivergedError) Error() string {
	switch e.Kind {
	case svserver.Descriptor:
		return "svsync: the server holds a different vault under this name"
	case svserver.Epoch:
		return fmt.Sprintf("svsync: another device rotated the vault key at the same time as this one (%s differs); "+
			"the key history has forked, and this device's rotation must be given up", e.Name)
	}
	return fmt.Sprintf("svsync: the server holds different contents for %s", e.Name)
}

func (e *DivergedError) Is(target error) bool { return target == ErrDiverged }

// Sync brings a local vault folder and the vault on the server level:
//
//  1. It reads the server's change log after st's cursor, fetching every
//     file it lacks and removing every keyslot removed elsewhere.
//  2. It fetches again any file it knew the server held but no longer has
//     locally (keyslots aside: that is how a removal shows).
//  3. It sends every local file the server lacks, then every keyslot
//     removal made here since the last sync.
//  4. It saves st, as it goes and at the end.
//
// Nothing is ever overwritten, and nothing but keyslots is ever removed,
// on either side. A file both sides hold with different contents stops
// the sync (ErrDiverged) before anything is sent. Every step can be
// repeated, so a sync cut short by a crash or a lost connection is
// finished by the next. Syncs of one State are serialised.
//
// Keyslot removals are sent only while the local folder holds a vault
// that opens (its descriptor, and a keyslot of its current epoch):
// a folder that has lost its files fetches them again rather than
// removing them everywhere.
func Sync(ctx context.Context, local svstore.Backend, c *Client, st *State) (Report, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := &syncer{local: local, c: c, st: st}
	err := s.run(ctx)
	if serr := st.save(); err == nil {
		err = serr
	}
	return s.rep, err
}

// Clone fetches the vault on the server into a folder that holds none
// (for a new device), then saves st, which later syncs continue from. A
// clone cut short is finished by calling Clone (or Sync) again with the
// same state.
func Clone(ctx context.Context, c *Client, local svstore.Backend, st *State) (Report, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.Log == "" {
		if _, err := local.Read(svformat.DescriptorName); err == nil {
			return Report{}, ErrNotEmpty
		} else if !errors.Is(err, svstore.ErrNotExist) {
			return Report{}, err
		}
	}
	if _, err := c.Get(ctx, svformat.DescriptorName); errors.Is(err, ErrNotFound) {
		return Report{}, ErrNoVault
	} else if err != nil {
		return Report{}, err
	}
	s := &syncer{local: local, c: c, st: st}
	err := s.run(ctx)
	if serr := st.save(); err == nil {
		err = serr
	}
	return s.rep, err
}

type syncer struct {
	local   svstore.Backend
	c       *Client
	st      *State
	rep     Report
	unsaved int
}

// pageSize is how many changes are read at a time.
const pageSize = 1000

// saveEvery is how many files are sent between saves of the state.
const saveEvery = 256

func (s *syncer) run(ctx context.Context) error {
	if err := s.checkDescriptor(ctx); err != nil {
		return err
	}
	if err := s.pull(ctx); err != nil {
		return err
	}
	return s.push(ctx)
}

// checkDescriptor refuses, before anything else, to mix two vaults: the
// server's descriptor must be this folder's, if both have one.
func (s *syncer) checkDescriptor(ctx context.Context) error {
	name := svformat.DescriptorName
	if s.st.Known[name] {
		return nil
	}
	mine, err := s.local.Read(name)
	if errors.Is(err, svstore.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	theirs, err := s.c.Get(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(mine, theirs) {
		return &DivergedError{Name: name, Kind: svserver.Descriptor}
	}
	s.st.Known[name] = true
	return nil
}

// pull reads the server's change log from the cursor on.
func (s *syncer) pull(ctx context.Context) error {
	resets := 0
	for {
		cs, err := s.c.Changes(ctx, s.st.Cursor, 0, pageSize)
		if err != nil {
			return err
		}
		if cs.Log != s.st.Log || cs.Latest < s.st.Cursor {
			if s.st.Log != "" || s.st.Cursor != 0 {
				// The server's log was started again: the cursor means
				// nothing there, so read it all anew.
				if resets++; resets > 1 {
					return fmt.Errorf("%w: its change log keeps changing", ErrBadFile)
				}
				s.st.reset(cs.Log)
				if err := s.checkDescriptor(ctx); err != nil {
					return err
				}
				continue
			}
			s.st.Log = cs.Log
		}
		prev := s.st.Cursor
		for _, ch := range cs.Changes {
			if ch.Seq <= prev || ch.Seq > cs.Latest {
				return fmt.Errorf("%w: its change log is out of order", ErrBadFile)
			}
			prev = ch.Seq
		}
		if err := s.apply(ctx, cs.Changes); err != nil {
			return err
		}
		s.st.Cursor = prev
		if err := s.st.save(); err != nil {
			return err
		}
		if !cs.More || len(cs.Changes) == 0 {
			return nil
		}
	}
}

// apply brings one page of changes into the local folder. Only the last
// change to each name counts. Every file the server has created is
// checked against the local folder before anything is written, so a
// divergence stops the sync with nothing changed.
func (s *syncer) apply(ctx context.Context, changes []svserver.Change) error {
	final := map[string]svserver.Change{}
	for _, ch := range changes {
		final[ch.Name] = ch
	}
	var fetch, removes []string
	for _, name := range byRank(keys(final)) {
		ch := final[name]
		kind, err := svserver.ClassifyName(name)
		if err != nil {
			continue // not a vault file: nothing a device keeps
		}
		switch ch.Op {
		case svserver.OpCreate:
			if s.st.Known[name] {
				continue
			}
			mine, err := s.local.Read(name)
			switch {
			case err == nil:
				if hashHex(mine) != ch.SHA256 {
					return &DivergedError{Name: name, Kind: kind}
				}
				s.st.Known[name] = true
			case errors.Is(err, svstore.ErrNotExist):
				fetch = append(fetch, name)
			default:
				return err
			}
		case svserver.OpRemove:
			removes = append(removes, name)
		}
	}
	for _, name := range fetch {
		err := s.fetch(ctx, name, final[name].SHA256)
		if errors.Is(err, ErrNotFound) && rank(name) == 0 {
			continue // a keyslot removed since the log was read; the log will say so
		}
		if err != nil {
			return err
		}
	}
	for _, name := range removes {
		if kind, _ := svserver.ClassifyName(name); kind == svserver.Slot {
			if _, err := s.local.Read(name); err == nil {
				removed, err := s.removeSlot(name)
				if err != nil {
					return err
				}
				if !removed {
					continue
				}
			}
		}
		// A file other than a keyslot is removed only when the server
		// lost it: forgetting it here sends it again below.
		delete(s.st.Known, name)
	}
	return nil
}

// removeSlot applies a keyslot removal made elsewhere, unless the slot is
// the local vault's last key of its current epoch: then it is kept (and
// counted in Report.Kept), and marked known so it is not sent back.
func (s *syncer) removeSlot(name string) (bool, error) {
	local, err := s.listLocal()
	if err != nil {
		return false, err
	}
	if cur := s.currentSlots(local); cur[name] && len(cur) == 1 {
		s.rep.Kept++
		s.st.Known[name] = true
		return false, nil
	}
	if err := s.local.Remove(name); err != nil {
		return false, err
	}
	s.rep.Removed++
	return true, nil
}

// listLocal returns the local folder's vault files, by kind.
func (s *syncer) listLocal() (map[string]svserver.FileKind, error) {
	names, err := s.local.List("")
	if err != nil {
		return nil, err
	}
	local := map[string]svserver.FileKind{}
	for _, n := range names {
		if k, err := svserver.ClassifyName(n); err == nil {
			local[n] = k
		}
	}
	return local, nil
}

// fetch copies one file from the server into the local folder, checking
// it against its name (a revision's is its hash) and against the hash the
// server's log gave (want, when known). ErrNotFound means the server has
// no such file.
func (s *syncer) fetch(ctx context.Context, name, want string) error {
	kind, err := svserver.ClassifyName(name)
	if err != nil {
		return err
	}
	data, err := s.c.Get(ctx, name)
	if err != nil {
		return err
	}
	sum := hashHex(data)
	if want != "" && sum != want {
		return fmt.Errorf("%w: %s", ErrBadFile, name)
	}
	if kind == svserver.Revision {
		if _, rev, _ := svformat.ParseRevisionName(name); svformat.RevIDOf(data) != rev {
			return fmt.Errorf("%w: %s", ErrBadFile, name)
		}
	}
	switch err := s.local.Create(name, data); {
	case errors.Is(err, svstore.ErrExist):
		mine, rerr := s.local.Read(name)
		if rerr != nil {
			return rerr
		}
		if !bytes.Equal(mine, data) {
			return &DivergedError{Name: name, Kind: kind}
		}
	case err != nil:
		return err
	default:
		s.rep.Pulled++
	}
	s.st.Known[name] = true
	return nil
}

// push sends what the server lacks, after fetching back what this folder
// lost.
func (s *syncer) push(ctx context.Context) error {
	local, err := s.listLocal()
	if err != nil {
		return err
	}

	// Known on the server, missing here.
	var missing, removed []string
	for n := range s.st.Known {
		if _, ok := local[n]; ok {
			continue
		}
		kind, err := svserver.ClassifyName(n)
		if err != nil {
			delete(s.st.Known, n)
			continue
		}
		if kind == svserver.Slot {
			removed = append(removed, n)
		} else {
			missing = append(missing, n)
		}
	}
	if len(removed) > 0 && !s.opens(local) {
		// Not a vault that opens: the keyslots were lost, not removed.
		missing, removed = append(missing, removed...), nil
	}
	for _, n := range byRank(missing) {
		if err := s.fetch(ctx, n, ""); errors.Is(err, ErrNotFound) {
			delete(s.st.Known, n) // the server lost it too
		} else if err != nil {
			return err
		}
	}

	// New here, in an order that never shows another device a vault it
	// cannot open: keyslots, epoch records, revisions, checkpoints, and
	// the descriptor last.
	var fresh []string
	for n := range local {
		if !s.st.Known[n] {
			fresh = append(fresh, n)
		}
	}
	for _, n := range byRank(fresh) {
		kind := local[n]
		data, err := s.local.Read(n)
		if errors.Is(err, svstore.ErrNotExist) {
			continue // removed meanwhile
		}
		if err != nil {
			return err
		}
		seq, err := s.c.Put(ctx, n, data)
		switch {
		case err == nil:
		case errors.Is(err, ErrConflict):
			return &DivergedError{Name: n, Kind: kind}
		case errors.Is(err, ErrGone) && kind == svserver.Slot:
			// Removed on the server by another device, for good.
			if _, err := s.removeSlot(n); err != nil {
				return err
			}
			continue
		default:
			return err
		}
		s.st.Known[n] = true
		s.advance(seq)
		s.rep.Pushed++
		if err := s.saveNow(); err != nil {
			return err
		}
	}

	// Keyslots removed here.
	sort.Strings(removed)
	for _, n := range removed {
		seq, err := s.c.Delete(ctx, n)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		delete(s.st.Known, n)
		s.advance(seq)
		s.rep.Deleted++
	}
	return nil
}

// advance moves the cursor over a change this device made itself, when
// no one else's came between: there is nothing in it to fetch.
func (s *syncer) advance(seq uint64) {
	if seq == s.st.Cursor+1 {
		s.st.Cursor = seq
	}
}

// saveNow saves the state every saveEvery calls.
func (s *syncer) saveNow() error {
	if s.unsaved++; s.unsaved < saveEvery {
		return nil
	}
	s.unsaved = 0
	return s.st.save()
}

// opens reports whether the local folder holds a vault that opens: its
// descriptor, and a keyslot of its current epoch.
func (s *syncer) opens(local map[string]svserver.FileKind) bool {
	return local[svformat.DescriptorName] == svserver.Descriptor && len(s.currentSlots(local)) > 0
}

// currentSlots are the local keyslots of the vault's current epoch (one
// more than the epoch records there are).
func (s *syncer) currentSlots(local map[string]svserver.FileKind) map[string]bool {
	epoch := uint32(1)
	for _, k := range local {
		if k == svserver.Epoch {
			epoch++
		}
	}
	out := map[string]bool{}
	for n, k := range local {
		if k != svserver.Slot {
			continue
		}
		b, err := s.local.Read(n)
		if err != nil {
			continue
		}
		if slot, err := svformat.ParseSlot(b); err == nil && slot.Epoch == epoch {
			out[n] = true
		}
	}
	return out
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func keys(m map[string]svserver.Change) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// rank orders kinds of files as they must arrive: a keyslot before the
// epoch it opens, an epoch before the revisions under it, and the
// descriptor, which makes a folder a vault, last.
func rank(name string) int {
	k, _ := svserver.ClassifyName(name)
	switch k {
	case svserver.Slot:
		return 0
	case svserver.Epoch:
		return 1
	case svserver.Blob:
		return 2 // before the revisions that refer to them
	case svserver.Revision:
		return 3
	case svserver.Checkpoint:
		return 4
	case svserver.Descriptor:
		return 5
	}
	return 6
}

func byRank(names []string) []string {
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := rank(names[i]), rank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	return names
}
