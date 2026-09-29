//go:build linux

package svd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// hostHarness runs a host daemon on temporary directories, and plays
// systemd's side of LoadCredential=: nothing here is root, PID 1, or the
// real /run, /var or /etc.
type hostHarness struct {
	t     *testing.T
	dir   string
	data  string
	run   string
	id    *svcrypto.Identity // the host identity
	opts  Options
	d     *Daemon
	stop  func()
	procs chan *svpeer.Process

	mu   sync.Mutex
	logs []string
}

func newHostHarness(t *testing.T, setup func(h *hostHarness)) *hostHarness {
	t.Helper()
	cheapKDF(t)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	dir, err := os.MkdirTemp("", "svh") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &hostHarness{t: t, dir: dir, data: filepath.Join(dir, "data"), run: filepath.Join(dir, "run"),
		procs: make(chan *svpeer.Process, 16)}
	if h.id, err = svcrypto.Modern.NewIdentity(); err != nil {
		t.Fatal(err)
	}
	h.makeVault("prod", h.id.Recipient())
	h.writeIdentity(filepath.Join(h.data, "host.identity"), h.id, 0o600)
	h.opts = Options{
		Mode: ModeHost, Home: h.data, IdleUnit: time.Hour,
		Log: func(s string) { h.mu.Lock(); h.logs = append(h.logs, s); h.mu.Unlock() },
		// A connection is the program the test announced for it.
		Peer: func(c net.Conn) (*svpeer.Process, error) {
			select {
			case p := <-h.procs:
				return p, nil
			default:
				return nil, errors.New("test: a connection nobody announced")
			}
		},
		Host: HostOptions{Runtime: h.run, FromServiceManager: func(net.Conn) error { return nil }},
	}
	if setup != nil {
		setup(h)
	}
	h.start()
	return h
}

// makeVault makes a vault in the host's data directory, with keyslots for
// a passphrase and for recipient (if any), and three items.
func (h *hostHarness) makeVault(name string, recipient []byte) {
	h.t.Helper()
	store, err := svstore.OpenDir(filepath.Join(h.data, "vaults", name))
	if err != nil {
		h.t.Fatal(err)
	}
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: pass}, svcore.Options{})
	if err != nil {
		h.t.Fatal(err)
	}
	defer v.Lock()
	if recipient != nil {
		if _, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Label: "host", Recipient: recipient}); err != nil {
			h.t.Fatal(err)
		}
	}
	for _, it := range []svcore.Item{
		{Kind: "login", Name: "db/postgres", Fields: []svcore.Field{
			{Name: "username", Type: svcore.FieldText, Value: []byte("app")},
			{Name: "password", Type: svcore.FieldConcealed, Value: []byte("s3cret-" + name)}}},
		{Kind: "api-key", Name: "api/token", Fields: []svcore.Field{{Name: "token", Type: svcore.FieldConcealed, Value: []byte("tok-" + name)}}},
		{Kind: "api-key", Name: "backup/s3", Fields: []svcore.Field{
			{Name: "secret", Type: svcore.FieldConcealed, Value: []byte("s3-" + name)},
			{Name: "region", Type: svcore.FieldText, Value: []byte("eu-west-1")}}},
	} {
		if _, err := v.Put(it); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *hostHarness) writeIdentity(path string, id *svcrypto.Identity, mode os.FileMode) {
	h.t.Helper()
	priv, err := id.Bytes()
	if err != nil {
		h.t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte("# the host\n"+svformat.EncodeIdentity(id.Suite(), priv)+"\n"), mode); err != nil {
		h.t.Fatal(err)
	}
	os.Chmod(path, mode)
}

func (h *hostHarness) start() {
	d, err := New(h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	lns, err := d.ListenHost()
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { d.ServeCredentials(ctx, lns.Credentials); wg.Done() }()
	go func() { d.ServeServices(ctx, lns.Services); wg.Done() }()
	go func() { d.Serve(ctx, lns.Admin); wg.Done() }()
	h.d = d
	h.stop = func() { cancel(); wg.Wait(); lns.Close() }
	h.t.Cleanup(func() {
		if h.stop != nil {
			h.stop()
		}
	})
}

func (h *hostHarness) sock(name string) string { return filepath.Join(h.run, name) }

// loadCredential does what systemd does for LoadCredential=CRED:<socket>
// in UNIT: it connects from an abstract address that names the unit and
// the credential, shuts its own side for writing, and reads to the end.
func (h *hostHarness) loadCredential(unit, cred string) string {
	h.t.Helper()
	return h.loadFrom(fmt.Sprintf("@%x/unit/%s/%s", rand.Uint64(), unit, cred))
}

func (h *hostHarness) loadFrom(local string) string {
	h.t.Helper()
	var laddr *net.UnixAddr
	if local != "" {
		laddr = &net.UnixAddr{Net: "unix", Name: local}
	}
	c, err := net.DialUnix("unix", laddr, &net.UnixAddr{Net: "unix", Name: h.sock(svrpc.HostCredentialSocketName)})
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	c.CloseWrite()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		h.t.Fatalf("reading the credential: %v", err)
	}
	return string(b)
}

// admin connects to the admin socket as root (the daemon's own uid).
func (h *hostHarness) admin() *secretvault.Client {
	h.t.Helper()
	return h.dial(svrpc.HostAdminSocketName, &svpeer.Process{PID: 100, UID: os.Getuid(), Exe: "/usr/bin/secretvault", SystemOwned: true})
}

// service connects to the services socket as a program of uid.
func (h *hostHarness) service(uid int, exe string) *secretvault.Client {
	h.t.Helper()
	return h.dial(svrpc.HostServiceSocketName, &svpeer.Process{PID: 200, UID: uid, Exe: exe, SystemOwned: true})
}

func (h *hostHarness) dial(sock string, p *svpeer.Process) *secretvault.Client {
	h.t.Helper()
	h.procs <- p
	c, err := secretvault.Connect(secretvault.Options{Socket: h.sock(sock), NoStart: true})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func (h *hostHarness) allow(r svrpc.HostRule) svrpc.HostAllowResult {
	h.t.Helper()
	res, err := h.admin().HostAllow(ctx(h.t), r)
	if err != nil {
		h.t.Fatalf("allow %+v: %v", r, err)
	}
	return res
}

func (h *hostHarness) events() []svrpc.HostEvent {
	h.t.Helper()
	evs, err := h.admin().HostAudit(ctx(h.t), 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return evs
}

func TestAUnitGetsWhatThePolicyListsAndNothingElse(t *testing.T) {
	h := newHostHarness(t, nil)
	if res := h.allow(svrpc.HostRule{Unit: "postgresql.service", Credential: "db-password", Ref: "sv://prod/db/postgres#password"}); len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	h.allow(svrpc.HostRule{Unit: "app@*.service", Credential: "api-token", Ref: "sv://-/api/token"})
	h.allow(svrpc.HostRule{Unit: "app@blue.service", Credential: "api-token", Ref: "sv://prod/backup/s3"}) // the exact name wins

	for _, c := range []struct{ unit, cred, want string }{
		{"postgresql.service", "db-password", "s3cret-prod"},
		{"app@green.service", "api-token", "tok-prod"},
		{"app@blue.service", "api-token", "s3-prod"},
		{"app.service", "api-token", ""},            // the glob wants an instance
		{"postgresql.service", "db-username", ""},   // not listed
		{"evil.service", "db-password", ""},         // not listed
		{"postgresql.service", "DB-PASSWORD", ""},   // names are exact
		{"postgresql.service@x", "db-password", ""}, // nor a prefix
	} {
		if got := h.loadCredential(c.unit, c.cred); got != c.want {
			t.Errorf("%s asking for %s got %q, want %q", c.unit, c.cred, got, c.want)
		}
	}

	var delivered, refused int
	for _, ev := range h.events() {
		switch ev.Outcome {
		case "delivered":
			delivered++
			if ev.Ref == "" || ev.Unit == "" {
				t.Errorf("a delivery without its unit or reference: %+v", ev)
			}
		case "refused":
			refused++
			if ev.Reason != "not in the host policy" || ev.Unit == "" {
				t.Errorf("a refusal: %+v", ev)
			}
		}
	}
	if delivered != 3 || refused != 5 {
		t.Fatalf("the log has %d deliveries and %d refusals, want 3 and 5", delivered, refused)
	}
	st, err := h.admin().HostStatus(ctx(t))
	if err != nil || st.Delivered != 3 || st.Refused != 5 || st.Credentials != 3 {
		t.Fatalf("status %+v, %v", st, err)
	}
	// The vault's own audit log has each delivery too.
	audit, err := h.admin().Audit(ctx(t), "prod", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range audit {
		if e.Program == "systemd, for postgresql.service" && e.Item == "db/postgres" && e.Outcome == "allowed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the vault's audit log: %+v", audit)
	}

	// Denying takes effect at once.
	if err := h.admin().HostDeny(ctx(t), svrpc.HostRule{Unit: "postgresql.service", Credential: "db-password"}); err != nil {
		t.Fatal(err)
	}
	if got := h.loadCredential("postgresql.service", "db-password"); got != "" {
		t.Fatalf("after deny: %q", got)
	}
	if err := h.admin().HostDeny(ctx(t), svrpc.HostRule{Unit: "postgresql.service", Credential: "db-password"}); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("denying twice: %v", err)
	}
}

func TestOnlySystemdMayAskForACredential(t *testing.T) {
	h := newHostHarness(t, func(h *hostHarness) { h.opts.Host.FromServiceManager = nil })
	h.allow(svrpc.HostRule{Unit: "postgresql.service", Credential: "db-password", Ref: "sv://prod/db/postgres#password"})
	if os.Getuid() != 0 {
		// The default check: this test is neither PID 1 nor root.
		if got := h.loadCredential("postgresql.service", "db-password"); got != "" {
			t.Fatalf("a process of uid %d got %q", os.Getuid(), got)
		}
		evs := h.events()
		if last := evs[len(evs)-1]; last.Outcome != "refused" || !strings.Contains(last.Reason, "not systemd") || last.UID != os.Getuid() || last.Unit != "postgresql.service" {
			t.Fatalf("the refusal: %+v", last)
		}
	}

	// systemd always binds its end to the unit's name; a connection that
	// is not bound, or bound to anything else, is refused.
	h2 := newHostHarness(t, nil)
	h2.allow(svrpc.HostRule{Unit: "postgresql.service", Credential: "db-password", Ref: "sv://prod/db/postgres#password"})
	for _, local := range []string{"", "@postgresql.service/db-password", "@abc/unit/postgresql.service", "@abc/unit/postgresql.service/db-password/x", "@a-b/unit/postgresql.service/db-password"} {
		if got := h2.loadFrom(local); got != "" {
			t.Errorf("bound to %q: got %q", local, got)
		}
	}
	if got := h2.loadCredential("postgresql.service", "db-password"); got != "s3cret-prod" {
		t.Fatalf("systemd: %q", got)
	}
}

func TestParsingSystemdsAddress(t *testing.T) {
	for _, c := range []struct{ addr, unit, cred string }{
		{"@adf9d86b6eda275e/unit/foobar.service/credx", "foobar.service", "credx"},
		{"@1/unit/app@blue.service/db.pass", "app@blue.service", "db.pass"},
		{`@ff/unit/dev-disk-by\x2dlabel.mount/k`, `dev-disk-by\x2dlabel.mount`, "k"},
		{"adf9/unit/foobar.service/credx", "", ""}, // not abstract
		{"@/unit/foobar.service/credx", "", ""},
		{"@adf9/units/foobar.service/credx", "", ""},
		{"@adf9/unit/foobar.service/", "", ""},
		{"@adf9/unit/foo bar.service/credx", "", ""},
		{"@adf9/unit/foobar.service/a:b", "", ""},
		{"@adf9/unit/foobar.service/..", "", ""},
	} {
		unit, cred, err := parseCredentialPeer(c.addr)
		if unit != c.unit || cred != c.cred || (err == nil) != (c.unit != "") {
			t.Errorf("%q: %q %q %v", c.addr, unit, cred, err)
		}
	}
}

func TestTheHostIdentityOpensVaultsAndNobodyIsAsked(t *testing.T) {
	h := newHostHarness(t, func(h *hostHarness) { h.makeVault("other", nil) }) // other is not shared to the host
	admin := h.admin()
	st, err := admin.HostStatus(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if st.Identity == "" || !strings.HasPrefix(st.Recipient, "sv-recipient-1-modern-") || len(st.Vaults) != 2 {
		t.Fatalf("status %+v", st)
	}
	for _, v := range st.Vaults {
		if want := v.Name == "prod"; v.HostSlot != want || v.Locked == want {
			t.Fatalf("vault %+v", v)
		}
	}
	vaults, _ := admin.Vaults(ctx(t))
	for _, v := range vaults {
		if v.AutoLock.IdleMinutes != 0 || v.AutoLock.OnScreenLock {
			t.Fatalf("a host vault locks on its own: %+v", v)
		}
	}

	// A locked vault is opened again with the identity, not by asking.
	h.allow(svrpc.HostRule{Unit: "a.service", Credential: "p", Ref: "sv://prod/db/postgres"})
	if err := admin.Lock(ctx(t), "", true); err != nil {
		t.Fatal(err)
	}
	if got := h.loadCredential("a.service", "p"); got != "s3cret-prod" {
		t.Fatalf("after locking: %q", got)
	}
	// One the identity does not open stays locked, and says why.
	res := h.allow(svrpc.HostRule{Unit: "b.service", Credential: "p", Ref: "sv://other/db/postgres"})
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "does not open it") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	if got := h.loadCredential("b.service", "p"); got != "" {
		t.Fatalf("a vault the host cannot open gave %q", got)
	}
	evs := h.events()
	if last := evs[len(evs)-1]; last.Outcome != "failed" || !strings.Contains(last.Reason, "does not open it") {
		t.Fatalf("the failure: %+v", last)
	}
	if _, err := admin.Unlock(ctx(t), "other", nil); !errors.Is(err, svrpc.ErrLocked) {
		t.Fatalf("unlocking with nobody to ask: %v", err)
	}
	// root can still unlock it with a key.
	if _, err := admin.Unlock(ctx(t), "other", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: append([]byte(nil), pass...)}); err != nil {
		t.Fatal(err)
	}
	if got := h.loadCredential("b.service", "p"); got != "s3cret-other" {
		t.Fatalf("after root unlocked it: %q", got)
	}

	// The host daemon takes no prompter, and is no keyring.
	if err := admin.RegisterPrompter(ctx(t), "pts/1"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("prompt.register: %v", err)
	}
	if err := admin.ServeKeyring(ctx(t), true); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("keyring.serve: %v", err)
	}
	if st, _ := admin.Status(ctx(t)); st.Mode != "host" || st.SSHAgent != "" {
		t.Fatalf("daemon.status %+v", st)
	}
}

func TestSystemdsCredentialComesBeforeThePlainFile(t *testing.T) {
	var creds string
	h := newHostHarness(t, func(h *hostHarness) {
		// The plain file holds some other identity; systemd's the right one.
		other, _ := svcrypto.Modern.NewIdentity()
		h.writeIdentity(filepath.Join(h.data, "host.identity"), other, 0o600)
		creds = filepath.Join(h.dir, "creds")
		h.writeIdentity(filepath.Join(creds, svrpc.HostIdentityCredential), h.id, 0o400)
		h.opts.Host.Credentials = creds
	})
	st, err := h.admin().HostStatus(ctx(t))
	if err != nil || !strings.Contains(st.Identity, "systemd") || st.Vaults[0].Locked {
		t.Fatalf("status %+v, %v", st, err)
	}

	// An identity others can read is not used.
	h2 := newHostHarness(t, func(h *hostHarness) {
		h.writeIdentity(filepath.Join(h.data, "host.identity"), h.id, 0o644)
	})
	st, err = h2.admin().HostStatus(ctx(t))
	if err != nil || st.Identity != "" || !strings.Contains(st.IdentityError, "mode 0644") || !st.Vaults[0].Locked {
		t.Fatalf("status %+v, %v", st, err)
	}

	// Nor does anything work without one, but root's own key.
	h3 := newHostHarness(t, func(h *hostHarness) { os.Remove(filepath.Join(h.data, "host.identity")) })
	h3.allow(svrpc.HostRule{Unit: "a.service", Credential: "p", Ref: "sv://prod/db/postgres"})
	if got := h3.loadCredential("a.service", "p"); got != "" {
		t.Fatalf("without an identity: %q", got)
	}
}

func TestALocalServiceReadsOnlyItsOwnReferences(t *testing.T) {
	h := newHostHarness(t, nil)
	h.allow(svrpc.HostRule{User: "4242", Program: "/usr/local/bin/backup", Refs: []string{"sv://prod/backup/*"}})
	h.allow(svrpc.HostRule{User: "4243", Refs: []string{"sv://-/api/token#token"}})

	backup := h.service(4242, "/usr/local/bin/backup")
	if v, err := backup.HostResolve(ctx(t), "sv://prod/backup/s3"); err != nil || string(v) != "s3-prod" {
		t.Fatalf("its own: %q, %v", v, err)
	}
	for _, ref := range []string{"sv://prod/backup/s3#region", "sv://prod/db/postgres", "sv://prod/api/token"} {
		if _, err := backup.HostResolve(ctx(t), ref); !errors.Is(err, svrpc.ErrDenied) {
			t.Errorf("%s: %v", ref, err)
		}
	}
	// Nothing but references: no items, no lists, no status.
	if _, err := backup.Get(ctx(t), "prod", "backup/s3"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("item.get: %v", err)
	}
	if _, err := backup.Vaults(ctx(t)); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("vault.list: %v", err)
	}
	if _, err := backup.HostStatus(ctx(t)); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("host.status: %v", err)
	}
	// Another program of the same user, or the same program of another.
	if _, err := h.service(4242, "/usr/bin/curl").HostResolve(ctx(t), "sv://prod/backup/s3"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("another program: %v", err)
	}
	if _, err := h.service(4244, "/usr/local/bin/backup").HostResolve(ctx(t), "sv://prod/backup/s3"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("another user: %v", err)
	}
	// A user with no program named: any of its programs.
	if v, err := h.service(4243, "/usr/bin/python3").HostResolve(ctx(t), "sv://prod/api/token#token"); err != nil || string(v) != "tok-prod" {
		t.Fatalf("user 4243: %q, %v", v, err)
	}
	// root reads anything.
	if v, err := h.admin().HostResolve(ctx(t), "sv://prod/db/postgres#username"); err != nil || string(v) != "app" {
		t.Fatalf("root: %q, %v", v, err)
	}
	// A user may be named rather than numbered.
	if u, err := user.Current(); err == nil {
		h.allow(svrpc.HostRule{User: u.Username, Refs: []string{"sv://prod/db/postgres#username"}})
		uid, _ := strconv.Atoi(u.Uid)
		if v, err := h.service(uid, "/bin/sh").HostResolve(ctx(t), "sv://prod/db/postgres#username"); err != nil || string(v) != "app" {
			t.Fatalf("user %s: %q, %v", u.Username, v, err)
		}
		if err := h.admin().HostDeny(ctx(t), svrpc.HostRule{User: u.Uid}); err != nil { // the same entry, by number
			t.Fatal(err)
		}
	}

	if err := h.admin().HostDeny(ctx(t), svrpc.HostRule{User: "4242", Program: "/usr/local/bin/backup"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service(4242, "/usr/local/bin/backup").HostResolve(ctx(t), "sv://prod/backup/s3"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("after deny: %v", err)
	}
	pol, err := h.admin().HostPolicy(ctx(t))
	if err != nil || len(pol.Clients) != 1 || pol.Clients[0].User != "4243" {
		t.Fatalf("policy %+v, %v", pol, err)
	}
}

func TestThePolicyFileIsReadAgainAndABrokenOneRefusesEverything(t *testing.T) {
	h := newHostHarness(t, nil)
	policy := filepath.Join(h.data, "host.json")
	write := func(s string, mode os.FileMode) {
		t.Helper()
		// A new file each time, as an editor or config management writes it.
		tmp := policy + ".new"
		if err := os.WriteFile(tmp, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(tmp, mode)
		if err := os.Rename(tmp, policy); err != nil {
			t.Fatal(err)
		}
	}
	good := `{"credentials": [{"unit": "a.service", "credential": "p", "ref": "sv://prod/db/postgres"}], "clients": []}`
	write(good, 0o600)
	if got := h.loadCredential("a.service", "p"); got != "s3cret-prod" {
		t.Fatalf("a policy written by hand: %q", got)
	}
	for name, c := range map[string]struct {
		body string
		mode os.FileMode
	}{
		"broken JSON":              {`{"credentials": [`, 0o600},
		"a misspelt field":         {`{"credentials": [{"unit": "a.service", "credential": "p", "ref": "sv://prod/db/postgres", "programme": "x"}]}`, 0o600},
		"a bad unit":               {`{"credentials": [{"unit": "a service", "credential": "p", "ref": "sv://prod/db/postgres"}]}`, 0o600},
		"writable by others":       {good, 0o666},
		"a client with no program": {`{"clients": [{"user": "1", "program": "relative", "refs": ["sv://prod/x"]}]}`, 0o600},
	} {
		write(c.body, c.mode)
		if got := h.loadCredential("a.service", "p"); got != "" {
			t.Errorf("%s: got %q", name, got)
		}
		st, _ := h.admin().HostStatus(ctx(t))
		if st.PolicyError == "" {
			t.Errorf("%s: no error in the status", name)
		}
		if _, err := h.admin().HostAllow(ctx(t), svrpc.HostRule{Unit: "b.service", Credential: "p", Ref: "sv://prod/x"}); err == nil || !strings.Contains(err.Error(), "left alone") {
			t.Errorf("%s: allow went ahead: %v", name, err)
		}
	}
	write(good, 0o600)
	if got := h.loadCredential("a.service", "p"); got != "s3cret-prod" {
		t.Fatalf("mended: %q", got)
	}
	// What the daemon writes is root's alone.
	h.allow(svrpc.HostRule{Unit: "b.service", Credential: "p", Ref: "sv://prod/api/token"})
	if st, err := os.Stat(policy); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the policy file: %v, %v", st.Mode(), err)
	}
	// Bad rules are refused when allowed, not when served.
	for _, r := range []svrpc.HostRule{
		{Unit: "a.service", Credential: "p", Ref: "not a ref"},
		{Unit: "a[.service", Credential: "p", Ref: "sv://prod/x"},
		{Unit: "a.service", Credential: "p:q", Ref: "sv://prod/x"},
		{User: "no-such-user-here", Refs: []string{"sv://prod/x"}},
		{User: "4242"},
		{Ref: "sv://prod/x"},
	} {
		if _, err := h.admin().HostAllow(ctx(t), r); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeInvalidParams}) {
			t.Errorf("allow %+v: %v", r, err)
		}
	}
}

func TestTheHostSocketsAreGuardedAndASecondDaemonIsRefused(t *testing.T) {
	h := newHostHarness(t, nil)
	for name, want := range map[string]os.FileMode{
		svrpc.HostAdminSocketName: 0o600, svrpc.HostCredentialSocketName: 0o600, svrpc.HostServiceSocketName: 0o666,
	} {
		st, err := os.Stat(h.sock(name))
		if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != want {
			t.Errorf("%s: %v, %v", name, st.Mode(), err)
		}
	}
	if st, err := os.Stat(h.run); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("the runtime directory: %v, %v", st.Mode(), err)
	}
	d2, err := New(h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d2.ListenHost(); !errors.Is(err, ErrRunning) {
		t.Fatalf("a second host daemon: %v", err)
	}

	// Someone else on the admin socket is turned away.
	h.procs <- &svpeer.Process{PID: 300, UID: os.Getuid() + 1, Exe: "/usr/bin/secretvault"}
	if c, err := secretvault.Connect(secretvault.Options{Socket: h.sock(svrpc.HostAdminSocketName), NoStart: true}); err == nil {
		c.Close()
		t.Fatal("another uid on the admin socket")
	}
	// A person's daemon has no host methods.
	u := newHarness(t)
	cl := u.connect("/usr/bin/secretvault", nil)
	if _, err := cl.HostStatus(ctx(t)); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeMethodNotFound}) {
		t.Fatalf("host.status on a person's daemon: %v", err)
	}
	if _, err := cl.HostResolve(ctx(t), "sv://-/x"); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeMethodNotFound}) {
		t.Fatalf("host.resolve on a person's daemon: %v", err)
	}
}

func TestSocketsSystemdPassesAreTakenByPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(f.Fd()))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	got := listenersFromFDs([]int{fd}, func(s string) { t.Log(s) })
	passed, ok := got[path]
	if !ok || len(got) != 1 {
		t.Fatalf("listeners %v", got)
	}
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			c.Write([]byte("hi"))
			c.Close()
		}
	}()
	c, err := passed.Accept()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if string(b) != "hi" {
		t.Fatalf("read %q", b)
	}
	// Closing it leaves the socket where systemd made it.
	passed.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the socket was removed: %v", err)
	}
	ln.Close()
}
