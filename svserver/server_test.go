package svserver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svformat"
)

const token = "the admin token"

// clock is a settable clock for the server under test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	t     *testing.T
	root  string
	srv   *Server
	http  *httptest.Server
	clock *clock
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	f := &fixture{t: t, root: cfg.Root, clock: &clock{t: time.Now()}}
	if f.root == "" {
		f.root = t.TempDir()
	}
	cfg.Root = f.root
	if cfg.AdminToken == "" {
		cfg.AdminToken = token
	}
	if cfg.Now == nil {
		cfg.Now = f.clock.now
	}
	if cfg.Rate == 0 {
		cfg.Rate = -1
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = s
	f.http = httptest.NewServer(s)
	t.Cleanup(func() {
		s.Close()
		f.http.Close()
	})
	return f
}

type device struct {
	key ed25519.PrivateKey
}

func newDevice() device {
	_, k, _ := ed25519.GenerateKey(nil)
	return device{k}
}

func (d device) id() string { return EncodeKey(d.key.Public().(ed25519.PublicKey)) }

type response struct {
	status int
	body   []byte
	header http.Header
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("%d %s: %v", r.status, r.body, err)
	}
}

// send makes a request signed by d at the fixture's current time.
func (f *fixture) send(d device, method, target string, body []byte) response {
	return f.sendAt(d, method, target, body, f.clock.now())
}

func (f *fixture) sendAt(d device, method, target string, body []byte, at time.Time) response {
	f.t.Helper()
	return f.raw(method, target, body, Authorization(d.key, method, target, body, at))
}

func (f *fixture) raw(method, target string, body []byte, auth string) response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.http.URL+target, bytes.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, b, resp.Header}
}

func (f *fixture) expect(r response, status int) response {
	f.t.Helper()
	if r.status != status {
		f.t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
	return r
}

// newVault makes vault name with d as its first device.
func (f *fixture) newVault(name string, d device) {
	f.t.Helper()
	body, _ := json.Marshal(CreateVaultRequest{AdminToken: token, Label: "first"})
	f.expect(f.send(d, "POST", "/v1/vaults/"+name, body), http.StatusCreated)
}

func (f *fixture) put(d device, vault, name string, data []byte) response {
	return f.send(d, "PUT", "/v1/vaults/"+vault+"/files/"+name, data)
}

func (f *fixture) changes(d device, vault string, after uint64, query string) Changes {
	f.t.Helper()
	var cs Changes
	f.expect(f.send(d, "GET", fmt.Sprintf("/v1/vaults/%s/changes?after=%d%s", vault, after, query), nil), http.StatusOK).json(f.t, &cs)
	return cs
}

func slotName() string { return svformat.SlotName(svformat.NewID()) }

// revision returns a revision file's name and contents: any bytes, named
// by their hash, which is all the server checks.
func revision(content string) (string, []byte) {
	data := []byte(content)
	return svformat.RevisionName(svformat.NewID(), svformat.RevIDOf(data)), data
}

func TestAFileIsStoredOnceAndRetriesAreHarmless(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	name := slotName()
	var first, again PutResult
	f.expect(f.put(a, "v", name, []byte(`{"slot":1}`)), http.StatusCreated).json(t, &first)
	if got := f.expect(f.send(a, "GET", "/v1/vaults/v/files/"+name, nil), http.StatusOK); string(got.body) != `{"slot":1}` {
		t.Fatalf("GET = %q", got.body)
	}
	f.expect(f.put(a, "v", name, []byte(`{"slot":1}`)), http.StatusOK).json(t, &again)
	if first.Seq != again.Seq || !first.Created || again.Created {
		t.Fatalf("first %+v, retry %+v", first, again)
	}
	f.expect(f.put(a, "v", name, []byte(`{"slot":2}`)), http.StatusConflict)
	if got := f.send(a, "GET", "/v1/vaults/v/files/"+name, nil); string(got.body) != `{"slot":1}` {
		t.Fatalf("the conflicting PUT changed the file: %q", got.body)
	}
	f.expect(f.send(a, "GET", "/v1/vaults/v/files/"+slotName(), nil), http.StatusNotFound)
	if cs := f.changes(a, "v", 0, ""); len(cs.Changes) != 1 || cs.Latest != 1 {
		t.Fatalf("a retry was logged again: %+v", cs)
	}
}

func TestOnlyTheVaultFormatsFileNamesAreAccepted(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	id := svformat.NewID().String()
	rev := strings.Repeat("ab", 32)
	for _, bad := range []string{
		"notes.txt",
		"slots/" + strings.ToUpper(id) + ".json",
		"slots/" + id + ".txt",
		"slots/x/" + id + ".json",
		"epochs/00000001.json", // epoch 1 lives in the descriptor
		"epochs/2.json",
		"objects/zz/" + id + "/" + rev + ".svr",
		"objects/" + id[:2] + "/" + id + "/" + rev + ".json",
		"vault.json.bak",
		"files/vault.json",
		"checkpoints/a/b/c/d",
	} {
		if r := f.put(a, "v", bad, []byte(`{}`)); r.status != http.StatusBadRequest {
			t.Errorf("PUT %s = %d %s", bad, r.status, r.body)
		}
	}
	for _, good := range []string{"vault.json", slotName(), svformat.EpochName(2), "checkpoints/" + id + ".json"} {
		f.expect(f.put(a, "v", good, []byte(`{}`)), http.StatusCreated)
	}
	f.expect(f.send(a, "PUT", "/v1/vaults/Bad.Name/files/vault.json", []byte(`{}`)), http.StatusBadRequest)
}

func TestARevisionMustHashToItsName(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	name, data := revision("sealed bytes")
	f.expect(f.put(a, "v", name, []byte("other bytes")), http.StatusBadRequest)
	f.expect(f.put(a, "v", name, data), http.StatusCreated)
}

func TestJSONFilesMustBeJSONAndSizesAreCapped(t *testing.T) {
	f := newFixture(t, Config{MaxFileSize: 1000})
	a := newDevice()
	f.newVault("v", a)
	f.expect(f.put(a, "v", slotName(), []byte("not json")), http.StatusBadRequest)
	big := []byte(`"` + strings.Repeat("x", MaxJSONFile) + `"`)
	f.expect(f.put(a, "v", slotName(), big), http.StatusRequestEntityTooLarge)
	name, data := revision(strings.Repeat("r", 1001))
	f.expect(f.put(a, "v", name, data), http.StatusRequestEntityTooLarge)
	name, data = revision(strings.Repeat("r", 1000))
	f.expect(f.put(a, "v", name, data), http.StatusCreated)
}

func TestOnlyKeyslotsAreRemovedAndARemovedOneNeverComesBack(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	slot := slotName()
	rev, data := revision("r")
	f.expect(f.put(a, "v", "vault.json", []byte(`{}`)), http.StatusCreated)
	f.expect(f.put(a, "v", slot, []byte(`{}`)), http.StatusCreated)
	f.expect(f.put(a, "v", rev, data), http.StatusCreated)

	f.expect(f.send(a, "DELETE", "/v1/vaults/v/files/vault.json", nil), http.StatusMethodNotAllowed)
	f.expect(f.send(a, "DELETE", "/v1/vaults/v/files/"+rev, nil), http.StatusMethodNotAllowed)
	var del PutResult
	f.expect(f.send(a, "DELETE", "/v1/vaults/v/files/"+slot, nil), http.StatusOK).json(t, &del)
	f.expect(f.send(a, "DELETE", "/v1/vaults/v/files/"+slot, nil), http.StatusNotFound)
	f.expect(f.send(a, "GET", "/v1/vaults/v/files/"+slot, nil), http.StatusNotFound)
	f.expect(f.put(a, "v", slot, []byte(`{}`)), http.StatusGone)

	cs := f.changes(a, "v", 0, "")
	last := cs.Changes[len(cs.Changes)-1]
	if last.Op != OpRemove || last.Name != slot || last.Seq != del.Seq || cs.Latest != 4 {
		t.Fatalf("the removal was not logged: %+v", cs)
	}
	if _, err := os.Stat(filepath.Join(f.root, "vaults", "v", "files", filepath.FromSlash(slot))); !os.IsNotExist(err) {
		t.Fatalf("the slot file is still on disk: %v", err)
	}
}

func TestChangesComeInOrderAndInPages(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	var names []string
	for i := range 5 {
		n, data := revision(fmt.Sprint(i))
		names = append(names, n)
		f.expect(f.put(a, "v", n, data), http.StatusCreated)
	}
	cs := f.changes(a, "v", 0, "&limit=2")
	if len(cs.Changes) != 2 || !cs.More || cs.Latest != 5 || cs.Log == "" {
		t.Fatalf("first page: %+v", cs)
	}
	cs = f.changes(a, "v", 2, "&limit=2")
	if len(cs.Changes) != 2 || cs.Changes[0].Seq != 3 || cs.Changes[0].Name != names[2] || !cs.More {
		t.Fatalf("second page: %+v", cs)
	}
	cs = f.changes(a, "v", 4, "")
	c := cs.Changes[0]
	if len(cs.Changes) != 1 || cs.More || c.Seq != 5 || c.Op != OpCreate || c.Size != 1 || c.SHA256 != revisionHash(names[4]) {
		t.Fatalf("last page: %+v", cs)
	}
	if cs := f.changes(a, "v", 5, ""); len(cs.Changes) != 0 || cs.Latest != 5 {
		t.Fatalf("nothing new: %+v", cs)
	}
}

func TestALongPollAnswersAsSoonAsAChangeArrives(t *testing.T) {
	f := newFixture(t, Config{Now: time.Now})
	a := newDevice()
	f.newVault("v", a)
	got := make(chan Changes, 1)
	start := time.Now()
	go func() {
		var cs Changes
		r := f.send(a, "GET", "/v1/vaults/v/changes?after=0&wait=30", nil)
		json.Unmarshal(r.body, &cs)
		got <- cs
	}()
	time.Sleep(200 * time.Millisecond)
	name, data := revision("x")
	f.expect(f.put(a, "v", name, data), http.StatusCreated)
	select {
	case cs := <-got:
		if len(cs.Changes) != 1 || cs.Changes[0].Name != name {
			t.Fatalf("long poll = %+v", cs)
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("the long poll waited out its time")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the long poll did not answer")
	}
}

func TestALongPollWithNothingNewWaitsItsTimeAndAnswersEmpty(t *testing.T) {
	f := newFixture(t, Config{Now: time.Now})
	a := newDevice()
	f.newVault("v", a)
	start := time.Now()
	cs := f.changes(a, "v", 0, "&wait=1")
	if len(cs.Changes) != 0 || time.Since(start) < time.Second {
		t.Fatalf("after %v: %+v", time.Since(start), cs)
	}
}

func TestClosingTheServerEndsLongPolls(t *testing.T) {
	f := newFixture(t, Config{Now: time.Now})
	a := newDevice()
	f.newVault("v", a)
	done := make(chan response, 1)
	go func() { done <- f.send(a, "GET", "/v1/vaults/v/changes?after=0&wait=60", nil) }()
	time.Sleep(200 * time.Millisecond)
	f.srv.Close()
	select {
	case r := <-done:
		if r.status != http.StatusOK {
			t.Fatalf("status %d", r.status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not end the long poll")
	}
}

func TestUnsignedAndBadlySignedRequestsAreRefused(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	target := "/v1/vaults/v/files/" + slotName()
	now := f.clock.now()
	f.expect(f.raw("PUT", target, []byte(`{}`), ""), http.StatusUnauthorized)
	f.expect(f.raw("PUT", target, []byte(`{}`), "Bearer x"), http.StatusUnauthorized)
	f.expect(f.raw("PUT", target, []byte(`{}`), "SV1 device=x, time=1, nonce=y, sig=z"), http.StatusUnauthorized)
	// Signed for other bytes, another path, or another method.
	f.expect(f.raw("PUT", target, []byte(`{"a":1}`), Authorization(a.key, "PUT", target, []byte(`{}`), now)), http.StatusUnauthorized)
	f.expect(f.raw("PUT", target, []byte(`{}`), Authorization(a.key, "PUT", "/v1/vaults/v/files/"+slotName(), []byte(`{}`), now)), http.StatusUnauthorized)
	f.expect(f.raw("PUT", target, []byte(`{}`), Authorization(a.key, "POST", target, []byte(`{}`), now)), http.StatusUnauthorized)
	// Signed by one key, claiming another.
	b := newDevice()
	forged := strings.Replace(Authorization(b.key, "PUT", target, []byte(`{}`), now), "device="+b.id(), "device="+a.id(), 1)
	f.expect(f.raw("PUT", target, []byte(`{}`), forged), http.StatusUnauthorized)
	f.expect(f.put(a, "v", strings.TrimPrefix(target, "/v1/vaults/v/files/"), []byte(`{}`)), http.StatusCreated)
}

func TestAKeyNotEnrolledInTheVaultIsRefused(t *testing.T) {
	f := newFixture(t, Config{})
	a, b := newDevice(), newDevice()
	f.newVault("va", a)
	f.newVault("vb", b)
	f.expect(f.put(b, "va", slotName(), []byte(`{}`)), http.StatusForbidden)
	f.expect(f.send(b, "GET", "/v1/vaults/va/changes", nil), http.StatusForbidden)
	f.expect(f.send(b, "GET", "/v1/vaults/nosuch/changes", nil), http.StatusForbidden)
	f.expect(f.send(b, "GET", "/v1/vaults/va/devices", nil), http.StatusForbidden)
	f.expect(f.send(b, "POST", "/v1/vaults/va/enrol", nil), http.StatusForbidden)
}

func TestARequestFromAClockTooFarOffIsRefused(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	now := f.clock.now()
	for _, off := range []time.Duration{-6 * time.Minute, 6 * time.Minute} {
		r := f.sendAt(a, "GET", "/v1/vaults/v/changes", nil, now.Add(off))
		if r.status != http.StatusUnauthorized || !strings.Contains(string(r.body), "clock") {
			t.Errorf("%v off: %d %s", off, r.status, r.body)
		}
	}
	for _, off := range []time.Duration{-4 * time.Minute, 4 * time.Minute} {
		f.expect(f.sendAt(a, "GET", "/v1/vaults/v/changes", nil, now.Add(off)), http.StatusOK)
	}
}

func TestARequestCannotBeReplayed(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	target := "/v1/vaults/v/files/" + slotName()
	auth := Authorization(a.key, "DELETE", target, nil, f.clock.now())
	f.expect(f.raw("DELETE", target, nil, auth), http.StatusNotFound) // accepted, nothing there
	f.expect(f.put(a, "v", strings.TrimPrefix(target, "/v1/vaults/v/files/"), []byte(`{}`)), http.StatusCreated)
	r := f.raw("DELETE", target, nil, auth)
	if r.status != http.StatusUnauthorized || !strings.Contains(string(r.body), "already") {
		t.Fatalf("the replay: %d %s", r.status, r.body)
	}
	// Two identical requests in the same second are both fine: each has its
	// own nonce.
	f.expect(f.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusOK)
	f.expect(f.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusOK)
}

func TestMakingAVaultNeedsTheAdminTokenUnlessRegistrationIsOpen(t *testing.T) {
	f := newFixture(t, Config{})
	a, b := newDevice(), newDevice()
	for _, tok := range []string{"", "wrong"} {
		body, _ := json.Marshal(CreateVaultRequest{AdminToken: tok})
		f.expect(f.send(a, "POST", "/v1/vaults/v", body), http.StatusForbidden)
	}
	body, _ := json.Marshal(CreateVaultRequest{AdminToken: token})
	f.expect(f.send(a, "POST", "/v1/vaults/v", body), http.StatusCreated)
	f.expect(f.send(a, "POST", "/v1/vaults/v", body), http.StatusOK) // a retry
	f.expect(f.send(b, "POST", "/v1/vaults/v", body), http.StatusConflict)

	open := newFixture(t, Config{OpenRegistration: true})
	open.expect(open.send(a, "POST", "/v1/vaults/mine", []byte(`{}`)), http.StatusCreated)
	var devs []Device
	open.expect(open.send(a, "GET", "/v1/vaults/mine/devices", nil), http.StatusOK).json(t, &devs)
	if len(devs) != 1 || devs[0].Key != a.id() {
		t.Fatalf("devices: %+v", devs)
	}
}

func (f *fixture) enrol(d device, vault string) Enrolment {
	f.t.Helper()
	var e Enrolment
	f.expect(f.send(d, "POST", "/v1/vaults/"+vault+"/enrol", nil), http.StatusOK).json(f.t, &e)
	return e
}

func (f *fixture) join(d device, vault, code string) response {
	body, _ := json.Marshal(JoinRequest{Code: code, Label: "phone"})
	return f.send(d, "POST", "/v1/vaults/"+vault+"/devices", body)
}

func TestAnEnrolmentCodeEnrolsOneDeviceOnce(t *testing.T) {
	f := newFixture(t, Config{})
	a, b, c := newDevice(), newDevice(), newDevice()
	f.newVault("v", a)
	e := f.enrol(a, "v")
	if len(e.Code) != 26 || !e.Expires.After(f.clock.now()) {
		t.Fatalf("enrolment %+v", e)
	}
	f.expect(f.put(b, "v", slotName(), []byte(`{}`)), http.StatusForbidden)
	f.expect(f.join(b, "v", strings.ToLower(e.Code[:5])+"-"+e.Code[5:]), http.StatusCreated)
	f.expect(f.join(b, "v", e.Code), http.StatusOK) // b retrying
	f.expect(f.join(c, "v", e.Code), http.StatusForbidden)
	f.expect(f.put(b, "v", slotName(), []byte(`{}`)), http.StatusCreated)

	var devs []Device
	f.expect(f.send(b, "GET", "/v1/vaults/v/devices", nil), http.StatusOK).json(t, &devs)
	if len(devs) != 2 || devs[1].Key != b.id() || devs[1].AddedBy != a.id() || devs[1].Label != "phone" || devs[1].LastSeen == nil {
		t.Fatalf("devices: %+v", devs)
	}
}

func TestAnEnrolmentCodeExpires(t *testing.T) {
	f := newFixture(t, Config{EnrolTTL: time.Minute})
	a, b := newDevice(), newDevice()
	f.newVault("v", a)
	e := f.enrol(a, "v")
	f.clock.add(61 * time.Second)
	f.expect(f.join(b, "v", e.Code), http.StatusForbidden)
	f.expect(f.join(b, "v", f.enrol(a, "v").Code), http.StatusCreated)
}

func TestAWrongCodeEnrolsNobodyAndCodesAreRationed(t *testing.T) {
	f := newFixture(t, Config{})
	a, b := newDevice(), newDevice()
	f.newVault("v", a)
	f.enrol(a, "v")
	f.expect(f.join(b, "v", "AAAAAAAAAAAAAAAAAAAAAAAAAA"), http.StatusForbidden)
	f.expect(f.join(b, "nosuch", "AAAAAAAAAAAAAAAAAAAAAAAAAA"), http.StatusForbidden)
	for range maxCodes - 1 {
		f.enrol(a, "v")
	}
	f.expect(f.send(a, "POST", "/v1/vaults/v/enrol", nil), http.StatusTooManyRequests)
}

func TestACodeFromARemovedDeviceIsVoid(t *testing.T) {
	f := newFixture(t, Config{})
	a, b, c := newDevice(), newDevice(), newDevice()
	f.newVault("v", a)
	f.expect(f.join(b, "v", f.enrol(a, "v").Code), http.StatusCreated)
	code := f.enrol(b, "v").Code
	f.expect(f.send(a, "DELETE", "/v1/vaults/v/devices/"+b.id(), nil), http.StatusNoContent)
	f.expect(f.join(c, "v", code), http.StatusForbidden)
}

func TestAnyDeviceCanRemoveAnyOtherButNotTheLast(t *testing.T) {
	f := newFixture(t, Config{})
	a, b := newDevice(), newDevice()
	f.newVault("v", a)
	f.expect(f.join(b, "v", f.enrol(a, "v").Code), http.StatusCreated)
	f.expect(f.send(b, "DELETE", "/v1/vaults/v/devices/"+a.id(), nil), http.StatusNoContent)
	f.expect(f.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusForbidden)
	f.expect(f.send(b, "DELETE", "/v1/vaults/v/devices/"+a.id(), nil), http.StatusNotFound)
	f.expect(f.send(b, "DELETE", "/v1/vaults/v/devices/"+b.id(), nil), http.StatusConflict)
	f.expect(f.send(b, "GET", "/v1/vaults/v/changes", nil), http.StatusOK)

	// The removal is on disk.
	f.srv.Close()
	g := newFixture(t, Config{Root: f.root})
	g.expect(g.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusForbidden)
	g.expect(g.send(b, "GET", "/v1/vaults/v/changes", nil), http.StatusOK)
}

func TestTheLogSurvivesARestartAndIsReconciledAfterACrash(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	kept, gone := slotName(), slotName()
	f.expect(f.put(a, "v", kept, []byte(`{}`)), http.StatusCreated)
	f.expect(f.put(a, "v", gone, []byte(`{}`)), http.StatusCreated)
	before := f.changes(a, "v", 0, "")
	f.srv.Close()

	dir := filepath.Join(f.root, "vaults", "v")
	// A crash mid-append leaves half a line; a crash after a file was
	// stored leaves it unlogged; a file vanishes behind the server's back.
	lf, _ := os.OpenFile(filepath.Join(dir, logFile), os.O_WRONLY|os.O_APPEND, 0)
	lf.WriteString("3 + objects/half")
	lf.Close()
	stray, data := revision("stored, never logged")
	p := filepath.Join(dir, filesDir, filepath.FromSlash(stray))
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, data, 0o600)
	os.Remove(filepath.Join(dir, filesDir, filepath.FromSlash(gone)))

	g := newFixture(t, Config{Root: f.root})
	cs := g.changes(a, "v", 0, "")
	if cs.Log != before.Log {
		t.Fatalf("the log's ID changed: %s -> %s", before.Log, cs.Log)
	}
	if len(cs.Changes) != 4 || cs.Changes[2].Name != stray || cs.Changes[2].Op != OpCreate ||
		cs.Changes[3].Name != gone || cs.Changes[3].Op != OpRemove {
		t.Fatalf("after the restart: %+v", cs.Changes)
	}
	g.expect(g.put(a, "v", kept, []byte(`{}`)), http.StatusOK)
	g.expect(g.put(a, "v", stray, data), http.StatusOK)
	next, data := revision("after")
	var pr PutResult
	g.expect(g.put(a, "v", next, data), http.StatusCreated).json(t, &pr)
	if pr.Seq != 5 {
		t.Fatalf("the next change is %d", pr.Seq)
	}
}

func TestADamagedLogIsRefusedRatherThanGuessedAt(t *testing.T) {
	f := newFixture(t, Config{})
	a := newDevice()
	f.newVault("v", a)
	f.expect(f.put(a, "v", slotName(), []byte(`{}`)), http.StatusCreated)
	f.srv.Close()
	p := filepath.Join(f.root, "vaults", "v", logFile)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(b, []byte("1 +"), []byte("7 +"), 1), 0o600)
	g := newFixture(t, Config{Root: f.root})
	g.expect(g.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusInternalServerError)
}

func TestRequestsAreRateLimited(t *testing.T) {
	f := newFixture(t, Config{Rate: 1}) // bursts of 10; the clock stands still
	a := newDevice()
	f.newVault("v", a)
	var last response
	for range 12 {
		last = f.send(a, "GET", "/v1/vaults/v/changes", nil)
	}
	if last.status != http.StatusTooManyRequests || last.header.Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", last.status, last.header.Get("Retry-After"))
	}
	f.clock.add(5 * time.Second)
	f.expect(f.send(a, "GET", "/v1/vaults/v/changes", nil), http.StatusOK)
}

func TestTheSelfSignedCertificateIsMadeOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	c1, err := SelfSigned(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := SelfSigned(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(c1.Certificate[0]) != Fingerprint(c2.Certificate[0]) || len(Fingerprint(c1.Certificate[0])) != 64 {
		t.Fatal("the certificate changed between runs")
	}
	if fi, err := os.Stat(filepath.Join(dir, KeyFile)); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("key file: %v %v", fi.Mode(), err)
	}
}
