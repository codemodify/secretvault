package svsync

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"sync"
	"testing"

	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

// flaky is a local folder whose n-th write (Create or Remove) fails.
type flaky struct {
	svstore.Backend
	mu     sync.Mutex
	count  int
	failAt int
}

var errDiskFull = errors.New("injected: disk full")

func (f *flaky) fail() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return f.count == f.failAt
}

func (f *flaky) Create(name string, data []byte) error {
	if f.fail() {
		return errDiskFull
	}
	return f.Backend.Create(name, data)
}

func (f *flaky) Remove(name string) error {
	if f.fail() {
		return errDiskFull
	}
	return f.Backend.Remove(name)
}

func (f *flaky) set(n int) {
	f.mu.Lock()
	f.count, f.failAt = 0, n
	f.mu.Unlock()
}

// crashScenario sets up two devices with work for a sync in each
// direction: A has files to fetch (B's), files to send, and a keyslot
// removal to send; B then has all of that to take in. want is what all
// three should hold in the end.
func crashScenario(t *testing.T) (s *server, a, b *device, want map[string]string) {
	t.Helper()
	s = newServer(t)
	a = s.founder("v", &flaky{Backend: svstore.NewMem()})
	v := newFakeVault(t, a.store)
	first := v.slot(t, a.store, 1)
	v.revision(t, a.store, "base")
	a.mustSync()
	b = a.enrol(&flaky{Backend: svstore.NewMem()})
	if _, err := b.clone(); err != nil {
		t.Fatal(err)
	}
	v.revision(t, b.store, "from B")
	v.slot(t, b.store, 1)
	b.mustSync()

	v.revision(t, a.store, "from A, 1")
	v.revision(t, a.store, "from A, 2")
	v.slot(t, a.store, 1)
	a.store.Remove(first)
	want = files(t, a.store)
	maps.Copy(want, files(t, b.store))
	delete(want, first)
	return s, a, b, want
}

// failingSync runs one sync that fails at the n-th request (or local
// write), then, if crash is set, puts back the state file from before it
// (a crash loses every save the sync made).
func failingSync(t *testing.T, d *device, mode string, n int, crash bool) {
	t.Helper()
	before, _ := os.ReadFile(d.state)
	switch mode {
	case "request lost":
		d.faults.set(n, false)
	case "answer lost":
		d.faults.set(n, true)
	case "local write fails":
		d.store.(*flaky).set(n)
	}
	d.sync() // fails, or not if n is past the end
	d.faults.set(0, false)
	d.store.(*flaky).set(0)
	if crash {
		if before == nil {
			os.Remove(d.state)
		} else {
			os.WriteFile(d.state, before, 0o600)
		}
	}
}

// Every request of a sync is lost in turn, before the server sees it and
// after it has acted on it, and every local write fails in turn; after
// each, the device either carries on or crashes and restarts from its
// last saved state. Whatever the point, the next sync finishes the job,
// both devices and the server end with the same files, and the server's
// log holds each file once.
func TestASyncCutShortAnywhereIsFinishedByTheNext(t *testing.T) {
	// A clean run, to count the requests and writes each sync makes.
	s, a, b, want := crashScenario(t)
	a.faults.set(0, false)
	a.store.(*flaky).set(0)
	a.mustSync()
	aRequests, aWrites := a.faults.requests(), a.store.(*flaky).count
	b.faults.set(0, false)
	b.store.(*flaky).set(0)
	b.mustSync()
	bRequests, bWrites := b.faults.requests(), b.store.(*flaky).count
	sameFiles(t, "a clean run's result", s.files("v"), want)
	if aRequests < 5 || bRequests < 3 || aWrites < 2 || bWrites < 3 {
		t.Fatalf("the scenario is too small: A %d requests %d writes, B %d requests %d writes", aRequests, aWrites, bRequests, bWrites)
	}

	for _, mode := range []string{"request lost", "answer lost", "local write fails"} {
		steps := max(aRequests, bRequests)
		if mode == "local write fails" {
			steps = max(aWrites, bWrites)
		}
		for _, crash := range []bool{false, true} {
			for n := 1; n <= steps; n++ {
				t.Run(fmt.Sprintf("%s at %d, crash %v", mode, n, crash), func(t *testing.T) {
					s, a, b, want := crashScenario(t)
					failingSync(t, a, mode, n, crash)
					a.mustSync()
					failingSync(t, b, mode, n, crash)
					b.mustSync()
					a.mustSync()

					sameFiles(t, "A", files(t, a.store), want)
					sameFiles(t, "B", files(t, b.store), want)
					sameFiles(t, "the server", s.files("v"), want)
					checkLogHoldsEachFileOnce(t, a)
				})
			}
		}
	}
}

func checkLogHoldsEachFileOnce(t *testing.T, d *device) {
	t.Helper()
	cs, err := d.client.Changes(context.Background(), 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	created := map[string]int{}
	for _, c := range cs.Changes {
		if c.Op == svserver.OpCreate {
			created[c.Name]++
		}
	}
	for n, k := range created {
		if k > 1 {
			t.Errorf("%s was logged as created %d times", n, k)
		}
	}
}
