package svsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

const adminToken = "let me in"

// server is a sync server on a TLS test listener.
type server struct {
	t    *testing.T
	root string
	srv  *svserver.Server
	http *httptest.Server
}

func newServer(t *testing.T) *server {
	t.Helper()
	return newServerAt(t, t.TempDir())
}

func newServerAt(t *testing.T, root string) *server {
	t.Helper()
	s, err := svserver.New(svserver.Config{Root: root, AdminToken: adminToken, Rate: -1})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewTLSServer(s)
	t.Cleanup(func() {
		s.Close()
		h.Close()
	})
	return &server{t: t, root: root, srv: s, http: h}
}

func (s *server) remote(vault string) Remote {
	return Remote{URL: s.http.URL, Vault: vault, Fingerprint: svserver.Fingerprint(s.http.Certificate().Raw)}
}

// device is one installation: its own key, folder and sync state.
type device struct {
	t      *testing.T
	client *Client
	store  svstore.Backend
	state  string // the state file's path
	faults *faults
}

func newDevice(t *testing.T, r Remote, store svstore.Backend) *device {
	t.Helper()
	c, err := NewClient(r, NewIdentity())
	if err != nil {
		t.Fatal(err)
	}
	f := &faults{base: c.HTTP.Transport}
	c.HTTP.Transport = f
	if store == nil {
		store = svstore.NewMem()
	}
	return &device{t: t, client: c, store: store, state: filepath.Join(t.TempDir(), "sync.json"), faults: f}
}

// founder makes the vault on the server and returns its first device.
func (s *server) founder(vault string, store svstore.Backend) *device {
	s.t.Helper()
	d := newDevice(s.t, s.remote(vault), store)
	if err := d.client.CreateVault(context.Background(), adminToken, "founder"); err != nil {
		s.t.Fatal(err)
	}
	return d
}

// enrol makes another device of the vault d syncs.
func (d *device) enrol(store svstore.Backend) *device {
	d.t.Helper()
	ctx := context.Background()
	inv, err := d.client.Enrol(ctx)
	if err != nil {
		d.t.Fatal(err)
	}
	e := newDevice(d.t, inv.Remote, store)
	if err := e.client.Join(ctx, inv.Code, "another"); err != nil {
		d.t.Fatal(err)
	}
	return e
}

// loadState reads the device's state from disk, as a restarted daemon
// would.
func (d *device) loadState() *State {
	d.t.Helper()
	st, err := LoadState(d.state)
	if err != nil {
		d.t.Fatal(err)
	}
	return st
}

func (d *device) sync() (Report, error) {
	return Sync(context.Background(), d.store, d.client, d.loadState())
}

func (d *device) mustSync() Report {
	d.t.Helper()
	rep, err := d.sync()
	if err != nil {
		d.t.Fatal(err)
	}
	return rep
}

func (d *device) clone() (Report, error) {
	return Clone(context.Background(), d.client, d.store, d.loadState())
}

// files is everything a backend holds, by name.
func files(t *testing.T, b svstore.Backend) map[string]string {
	t.Helper()
	names, err := b.List("")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, n := range names {
		data, err := b.Read(n)
		if err != nil {
			t.Fatal(err)
		}
		out[n] = string(data)
	}
	return out
}

// serverFiles is everything the server holds for a vault.
func (s *server) files(vault string) map[string]string {
	s.t.Helper()
	d, err := svstore.OpenDir(filepath.Join(s.root, "vaults", vault, "files"))
	if err != nil {
		s.t.Fatal(err)
	}
	return files(s.t, d)
}

func sameFiles(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		gk, wk := slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(want))
		t.Fatalf("%s differ:\n got  %q\n want %q", what, gk, wk)
	}
}

// A fake vault: files with the right names and shapes, and no crypto,
// for testing the sync alone.
type fakeVault struct {
	id svformat.ID
}

func newFakeVault(t *testing.T, store svstore.Backend) *fakeVault {
	t.Helper()
	v := &fakeVault{id: svformat.NewID()}
	v.slot(t, store, 1)
	desc, _ := json.Marshal(map[string]any{"format": svformat.DescriptorFormat, "id": v.id})
	if err := store.Create(svformat.DescriptorName, desc); err != nil {
		t.Fatal(err)
	}
	return v
}

// slot adds a keyslot of epoch n and returns its name.
func (v *fakeVault) slot(t *testing.T, store svstore.Backend, n uint32) string {
	t.Helper()
	s := svformat.Slot{Format: svformat.SlotFormat, ID: svformat.NewID(), Vault: v.id, Epoch: n, Type: svformat.SlotRecovery,
		Created: time.Now().UTC(), Grants: []string{svformat.GrantContent}, Wrapped: []byte("sealed")}
	b, _ := json.Marshal(s)
	name := svformat.SlotName(s.ID)
	if err := store.Create(name, b); err != nil {
		t.Fatal(err)
	}
	return name
}

// revision adds a revision (any bytes, named by their hash).
func (v *fakeVault) revision(t *testing.T, store svstore.Backend, content string) string {
	t.Helper()
	data := []byte(content)
	name := svformat.RevisionName(svformat.NewID(), svformat.RevIDOf(data))
	if err := store.Create(name, data); err != nil {
		t.Fatal(err)
	}
	return name
}

// epoch adds epoch n's record, with contents that tell rotations apart.
func (v *fakeVault) epoch(t *testing.T, store svstore.Backend, n uint32, who string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"format": svformat.EpochFormat, "n": n, "by": who})
	if err := store.Create(svformat.EpochName(n), b); err != nil {
		t.Fatal(err)
	}
	return svformat.EpochName(n)
}

// faults is a transport that loses one request on purpose: before it
// reaches the server, or after the server has done it (so its answer is
// lost), or tampers with what the server sends.
type faults struct {
	base http.RoundTripper

	mu     sync.Mutex
	count  int
	failAt int  // the request to lose (1-based); 0 for none
	after  bool // lose the answer, not the request
	tamper func(r *http.Request, body []byte) []byte
}

var errInjected = errors.New("injected: the connection dropped")

func (f *faults) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.count++
	fail := f.count == f.failAt
	after, tamper := f.after, f.tamper
	f.mu.Unlock()
	if fail && !after {
		return nil, errInjected
	}
	resp, err := f.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if fail {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return nil, errInjected
	}
	if tamper != nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		b = tamper(r, b)
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
	}
	return resp, nil
}

// set arranges for the n-th request from now to be lost.
func (f *faults) set(n int, after bool) {
	f.mu.Lock()
	f.count, f.failAt, f.after = 0, n, after
	f.mu.Unlock()
}

func (f *faults) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}
