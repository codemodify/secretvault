package svsync

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

func TestFilesTravelBothWays(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.revision(t, a.store, "one")
	v.revision(t, a.store, "two")
	if rep := a.mustSync(); rep.Pushed != 4 || rep.Pulled != 0 {
		t.Fatalf("first sync: %+v", rep)
	}
	sameFiles(t, "server and A", s.files("v"), files(t, a.store))

	b := a.enrol(nil)
	if rep, err := b.clone(); err != nil || rep.Pulled != 4 {
		t.Fatalf("clone: %+v, %v", rep, err)
	}
	sameFiles(t, "B and A", files(t, b.store), files(t, a.store))

	v.revision(t, b.store, "from B")
	v.slot(t, b.store, 1)
	if rep := b.mustSync(); rep.Pushed != 2 {
		t.Fatalf("B's sync: %+v", rep)
	}
	if rep := a.mustSync(); rep.Pulled != 2 || !rep.Changed() {
		t.Fatalf("A's sync: %+v", rep)
	}
	sameFiles(t, "B and A", files(t, b.store), files(t, a.store))
	if rep := a.mustSync(); rep != (Report{}) {
		t.Fatalf("a sync with nothing to do did %+v", rep)
	}
	if rep := b.mustSync(); rep != (Report{}) {
		t.Fatalf("B's own changes came back to it: %+v", rep)
	}
}

func TestOnlyKeyslotRemovalsTravelAndLostFilesComeBack(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	extra := v.slot(t, a.store, 1)
	rev := v.revision(t, a.store, "r")
	a.mustSync()
	b := a.enrol(nil)
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}

	a.store.Remove(extra) // svcore.RemoveSlot
	a.store.Remove(rev)   // lost, not removed: revisions never are
	if rep := a.mustSync(); rep.Deleted != 1 || rep.Pulled != 1 {
		t.Fatalf("A's sync: %+v", rep)
	}
	if _, err := a.store.Read(rev); err != nil {
		t.Fatalf("the lost revision did not come back: %v", err)
	}
	if _, ok := s.files("v")[extra]; ok {
		t.Fatal("the removed keyslot is still on the server")
	}
	if _, ok := s.files("v")[rev]; !ok {
		t.Fatal("a local loss removed a revision from the server")
	}
	if rep := b.mustSync(); rep.Removed != 1 || !rep.Changed() {
		t.Fatalf("B's sync: %+v", rep)
	}
	sameFiles(t, "B and A", files(t, b.store), files(t, a.store))
}

func TestAFolderThatLostItsFilesFetchesThemRatherThanRemovingThemEverywhere(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.slot(t, a.store, 1)
	v.revision(t, a.store, "r")
	a.mustSync()
	want := files(t, a.store)

	a.store = svstore.NewMem() // the disk was replaced; the state file was kept
	if rep := a.mustSync(); rep.Deleted != 0 || rep.Pulled != len(want) {
		t.Fatalf("sync of an emptied folder: %+v", rep)
	}
	sameFiles(t, "the refilled folder", files(t, a.store), want)
	sameFiles(t, "the server", s.files("v"), want)

	// Only the descriptor is missing: still not a vault that opens.
	a.store.Remove(svformat.DescriptorName)
	for n := range want {
		if strings.HasPrefix(n, "slots/") {
			a.store.Remove(n)
		}
	}
	if rep := a.mustSync(); rep.Deleted != 0 {
		t.Fatalf("keyslots were removed from the server: %+v", rep)
	}
	sameFiles(t, "the refilled folder", files(t, a.store), want)
}

func TestAKeyslotRemovedOnTheServerNeverComesBack(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	slot := v.slot(t, a.store, 1)
	a.mustSync()
	b := a.enrol(nil)
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	a.store.Remove(slot)
	a.mustSync()

	// B lost its state: it holds the slot, and knows nothing of the server.
	os.Remove(b.state)
	if rep := b.mustSync(); rep.Removed != 1 || rep.Pushed != 0 {
		t.Fatalf("B's sync: %+v", rep)
	}
	if _, err := b.store.Read(slot); !errors.Is(err, svstore.ErrNotExist) {
		t.Fatalf("B kept the removed slot: %v", err)
	}
	// Sent directly, it is refused for good.
	if _, err := b.client.Put(context.Background(), slot, []byte(`{}`)); !errors.Is(err, ErrGone) {
		t.Fatalf("PUT of a removed slot: %v", err)
	}
}

func TestNoRemovalFromTheServerTakesAwayTheLastLocalKey(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.slot(t, a.store, 1)
	a.mustSync()

	// A faulty or hostile party removes every keyslot on the server (the
	// server does not read them, so it cannot tell).
	e := a.enrol(nil)
	for n := range files(t, a.store) {
		if strings.HasPrefix(n, svformat.SlotsDir+"/") {
			if _, err := e.client.Delete(context.Background(), n); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rep := a.mustSync(); rep.Removed != 1 || rep.Kept != 1 {
		t.Fatalf("A's sync: %+v", rep)
	}
	local := files(t, a.store)
	slots := 0
	for n := range local {
		if strings.HasPrefix(n, svformat.SlotsDir+"/") {
			slots++
		}
	}
	if slots != 1 {
		t.Fatalf("A holds %d keyslots", slots)
	}
	if rep := a.mustSync(); rep != (Report{}) {
		t.Fatalf("the kept keyslot keeps coming up: %+v", rep)
	}
	// A device that lost its state keeps its last key the same way.
	os.Remove(a.state)
	if rep := a.mustSync(); rep.Kept != 1 || rep.Pushed != 0 {
		t.Fatalf("A's sync without its state: %+v", rep)
	}
	sameFiles(t, "A's folder", files(t, a.store), local)
}

func TestADifferentVaultIsRefusedBeforeAnythingMoves(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.revision(t, a.store, "a")
	a.mustSync()

	b := a.enrol(nil)
	w := newFakeVault(t, b.store) // another vault, pointed at the same name
	w.revision(t, b.store, "b")
	before := files(t, b.store)
	_, err := b.sync()
	var de *DivergedError
	if !errors.As(err, &de) || de.Kind != svserver.Descriptor || !errors.Is(err, ErrDiverged) {
		t.Fatalf("sync of another vault: %v", err)
	}
	sameFiles(t, "B's folder", files(t, b.store), before)
	sameFiles(t, "the server", s.files("v"), files(t, a.store))
	if _, err := b.clone(); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("clone into a folder with a vault: %v", err)
	}
}

func TestRotationsMadeAtOnceOnTwoDevicesAreReportedNotMerged(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	a.mustSync()
	b := a.enrol(nil)
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	// Both rotate while apart: a keyslot for epoch 2, the record, and a
	// revision under the new key.
	for _, d := range []*device{a, b} {
		v.slot(t, d.store, 2)
		v.epoch(t, d.store, 2, d.client.Identity().Key())
		v.revision(t, d.store, "under "+d.client.Identity().Key())
	}
	a.mustSync()
	onServer := s.files("v")
	_, err := b.sync()
	var de *DivergedError
	if !errors.As(err, &de) || de.Kind != svserver.Epoch || de.Name != svformat.EpochName(2) {
		t.Fatalf("B's sync after both rotated: %v", err)
	}
	if !strings.Contains(err.Error(), "forked") {
		t.Fatalf("the error does not say what happened: %v", err)
	}
	sameFiles(t, "the server", s.files("v"), onServer) // B sent nothing
	if got := files(t, b.store)[svformat.EpochName(2)]; !strings.Contains(got, b.client.Identity().Key()) {
		t.Fatal("B's own epoch record was overwritten")
	}
}

func TestCloneNeedsAVaultOnTheServer(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	b := a.enrol(nil)
	if _, err := b.clone(); !errors.Is(err, ErrNoVault) {
		t.Fatalf("clone of an empty vault: %v", err)
	}
	newFakeVault(t, a.store)
	a.mustSync()
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, "B and A", files(t, b.store), files(t, a.store))
}

func TestAServerThatStartedItsLogAgainIsReadAnew(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.revision(t, a.store, "r")
	a.mustSync()

	// The server lost everything and the vault was made again there.
	s2 := newServer(t)
	c, _ := NewClient(s2.remote("v"), a.client.Identity())
	c.HTTP.Transport = a.faults
	if err := c.CreateVault(context.Background(), adminToken, ""); err != nil {
		t.Fatal(err)
	}
	a.client = c
	if rep := a.mustSync(); rep.Pushed != 3 {
		t.Fatalf("sync to the new server: %+v", rep)
	}
	sameFiles(t, "the new server", s2.files("v"), files(t, a.store))
}

func TestFilesTheServerForgedAreNotKept(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	v := newFakeVault(t, a.store)
	v.slot(t, a.store, 1)
	v.revision(t, a.store, "r")
	a.mustSync()

	for _, kind := range []string{"slots/", "objects/"} {
		b := a.enrol(nil)
		b.faults.tamper = func(r *http.Request, body []byte) []byte {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/files/"+kind) {
				return append(bytes.Clone(body), ' ')
			}
			return body
		}
		if _, err := b.clone(); !errors.Is(err, ErrBadFile) {
			t.Fatalf("%s: clone from a lying server: %v", kind, err)
		}
		for n := range files(t, b.store) {
			if strings.HasPrefix(n, kind) {
				t.Fatalf("%s: the forged file was kept", n)
			}
		}
	}
}

func TestTheStateFileIsReplacedWhole(t *testing.T) {
	s := newServer(t)
	a := s.founder("v", nil)
	newFakeVault(t, a.store)
	a.mustSync()
	st := a.loadState()
	if st.Log == "" || st.Cursor != 2 || len(st.Known) != 2 {
		t.Fatalf("state: %+v", st)
	}
	entries, _ := os.ReadDir(filepath.Dir(a.state))
	if len(entries) != 1 {
		t.Fatalf("the state's directory holds %d files", len(entries))
	}
	os.WriteFile(a.state, []byte("{"), 0o600)
	if _, err := LoadState(a.state); err == nil {
		t.Fatal("a damaged state file was accepted")
	}
}
