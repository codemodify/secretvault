//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// hostCLI runs the CLI against a host daemon on temporary directories
// (SECRETVAULT_HOST_DATA and SECRETVAULT_HOST_RUNTIME), as root or as a
// local service; systemd-creds is a stand-in.
type hostCLI struct {
	t         *testing.T
	dir       string
	data, run string
	root      bool

	creds     func(stdin []byte, args ...string) ([]byte, error)
	credsArgs []string
	credsIn   []byte
}

func newHostCLI(t *testing.T) *hostCLI {
	t.Helper()
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })
	dir, err := os.MkdirTemp("", "svhc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &hostCLI{t: t, dir: dir, data: filepath.Join(dir, "data"), run: filepath.Join(dir, "run"), root: true}
	t.Setenv(svrpc.EnvHostData, h.data)
	t.Setenv(svrpc.EnvHostRuntime, h.run)
	t.Setenv(svrpc.EnvHost, "")
	t.Setenv(EnvVault, "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	h.creds = func(stdin []byte, args ...string) ([]byte, error) {
		h.credsArgs, h.credsIn = args, append([]byte(nil), stdin...)
		return nil, nil
	}
	return h
}

func (h *hostCLI) exec(stdin string, args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	c := &cli{
		stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb,
		ask:          func(string) ([]byte, error) { return nil, errors.New("test: nothing to type") },
		askNew:       func(string, int) ([]byte, error) { return nil, errors.New("test: nothing to type") },
		connect:      secretvault.Connect,
		root:         func() bool { return h.root },
		systemdCreds: h.creds,
	}
	code := c.run(args)
	if c.client != nil {
		c.client.Close()
	}
	return out.String(), errb.String(), code
}

func (h *hostCLI) ok(args ...string) string {
	h.t.Helper()
	out, errs, code := h.exec("", args...)
	if code != 0 {
		h.t.Fatalf("secretvault %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

var recipientText = regexp.MustCompile(`sv-recipient-1-[a-z]+-[A-Za-z0-9_-]+`)

// vaultFor makes vault prod in the host's data directory, shared to the
// recipient.
func (h *hostCLI) vaultFor(recipient string) {
	h.t.Helper()
	_, pub, err := svformat.ParseRecipient(recipient)
	if err != nil {
		h.t.Fatal(err)
	}
	store, err := svstore.OpenDir(filepath.Join(h.data, "vaults", "prod"))
	if err != nil {
		h.t.Fatal(err)
	}
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: []byte("correct horse battery staple")}, svcore.Options{})
	if err != nil {
		h.t.Fatal(err)
	}
	defer v.Lock()
	if _, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Recipient: pub}); err != nil {
		h.t.Fatal(err)
	}
	for _, it := range []svcore.Item{
		{Kind: "login", Name: "db/postgres", Fields: []svcore.Field{
			{Name: "username", Type: svcore.FieldText, Value: []byte("app")},
			{Name: "password", Type: svcore.FieldConcealed, Value: []byte("s3cret")}}},
		{Kind: "api-key", Name: "backup/s3", Fields: []svcore.Field{{Name: "secret", Type: svcore.FieldConcealed, Value: []byte("s3-key")}}},
	} {
		if _, err := v.Put(it); err != nil {
			h.t.Fatal(err)
		}
	}
}

// daemon starts the host daemon. The admin socket's peer is root; the
// services socket's is /usr/local/bin/backup, run by uid 4242.
func (h *hostCLI) daemon() {
	h.t.Helper()
	d, err := svd.New(svd.Options{
		Mode: svd.ModeHost, Home: h.data,
		Host: svd.HostOptions{Runtime: h.run, FromServiceManager: func(net.Conn) error { return nil }},
		Peer: func(c net.Conn) (*svpeer.Process, error) {
			if strings.HasSuffix(c.LocalAddr().String(), svrpc.HostAdminSocketName) {
				return &svpeer.Process{PID: 1, UID: os.Getuid(), Exe: "/usr/bin/secretvault", SystemOwned: true}, nil
			}
			return &svpeer.Process{PID: 2, UID: 4242, Exe: "/usr/local/bin/backup", SystemOwned: true}, nil
		},
	})
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
	h.t.Cleanup(func() { cancel(); wg.Wait(); lns.Close() })
}

func TestHostInitMakesAnIdentityForRootAlone(t *testing.T) {
	h := newHostCLI(t)
	out := h.ok("host", "init")
	file := filepath.Join(h.data, "host.identity")
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the identity file: %v, %v", st, err)
	}
	b, _ := os.ReadFile(file)
	rcpt := recipientText.FindString(out)
	if rcpt == "" || !strings.Contains(string(b), "SV-IDENTITY-1-MODERN-") || !strings.Contains(string(b), rcpt) {
		t.Fatalf("init said:\n%s\nand wrote:\n%s", out, b)
	}
	for _, want := range []string{
		"systemd-creds encrypt --name=secretvault-host.identity " + file + " /etc/credstore.encrypted/secretvault-host.identity",
		"shred -u " + file, "--plain-identity", "share " + rcpt,
		"LoadCredential=CREDENTIAL:" + filepath.Join(h.run, "credentials.sock"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("init did not say %q:\n%s", want, out)
		}
	}
	if h.credsArgs != nil {
		t.Fatal("systemd-creds ran without --seal")
	}
	if _, errs, code := h.exec("", "host", "init"); code != 1 || !strings.Contains(errs, "already") {
		t.Fatalf("a second init: %d %s", code, errs)
	}
}

func TestHostInitSealsWithoutEverWritingTheIdentity(t *testing.T) {
	h := newHostCLI(t)
	credstore := filepath.Join(h.dir, "credstore.encrypted", "secretvault-host.identity")
	out := h.ok("host", "init", "--seal", "--credstore", credstore, "--tpm2-pcrs", "7")
	if got := strings.Join(h.credsArgs, " "); got != "encrypt --name=secretvault-host.identity --tpm2-pcrs=7 - "+credstore {
		t.Fatalf("systemd-creds %s", got)
	}
	rcpt := recipientText.FindString(out)
	if !strings.Contains(string(h.credsIn), "SV-IDENTITY-1-MODERN-") || rcpt == "" || !strings.Contains(string(h.credsIn), rcpt) {
		t.Fatalf("systemd-creds was given:\n%s\ninit said:\n%s", h.credsIn, out)
	}
	if _, err := os.Stat(filepath.Join(h.data, "host.identity")); !os.IsNotExist(err) {
		t.Fatal("the identity was written in the clear")
	}
	if strings.Contains(out, "shred") || strings.Contains(out, "--plain-identity") {
		t.Fatalf("init said:\n%s", out)
	}
	// What systemd-creds says when it fails reaches the person.
	h.creds = func([]byte, ...string) ([]byte, error) {
		return []byte("No TPM2 device found."), errors.New("exit status 1")
	}
	if _, errs, code := h.exec("", "host", "init", "--seal", "--credstore", credstore+"2"); code != 1 || !strings.Contains(errs, "No TPM2 device found.") {
		t.Fatalf("a failed seal: %d %s", code, errs)
	}
}

func TestHostCommandsRunTheHostDaemon(t *testing.T) {
	h := newHostCLI(t)
	rcpt := recipientText.FindString(h.ok("host", "init"))
	h.vaultFor(rcpt)
	h.daemon()

	out := h.ok("host", "allow", "postgresql.service", "db-password", "sv://prod/db/postgres#password")
	if !strings.Contains(out, "LoadCredential=db-password:"+filepath.Join(h.run, "credentials.sock")) {
		t.Fatalf("allow said %q", out)
	}
	h.ok("host", "allow", "--user", "4242", "--program", "/usr/local/bin/backup", "sv://prod/backup/*")
	if _, errs, code := h.exec("", "host", "allow", "a.service", "x", "sv://nope/y"); code != 0 || !strings.Contains(errs, `warning: sv://nope/y: there is no vault named "nope"`) {
		t.Fatalf("allowing a vault that is not here: %d %s", code, errs)
	}
	if _, _, code := h.exec("", "host", "allow", "a.service", "x"); code != 2 {
		t.Fatalf("allow without a reference: %d", code)
	}
	out = h.ok("host", "ls")
	for _, want := range []string{"postgresql.service  db-password  sv://prod/db/postgres#password", "4242", "/usr/local/bin/backup", "sv://prod/backup/*"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls did not say %q:\n%s", want, out)
		}
	}
	out = h.ok("host", "status")
	for _, want := range []string{"identity:    " + filepath.Join(h.data, "host.identity"), "recipient:   " + rcpt, "(2 credentials, 1 local service)", "prod   unlocked  yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("status did not say %q:\n%s", want, out)
		}
	}

	// root reads anything; a local service what its entry lists.
	if got := h.ok("--host", "read", "sv://prod/db/postgres#username"); got != "app\n" {
		t.Fatalf("root read %q", got)
	}
	h.root = false
	if got := h.ok("read", "--host", "sv://prod/backup/s3"); got != "s3-key\n" {
		t.Fatalf("backup read %q", got)
	}
	if _, errs, code := h.exec("", "--host", "read", "sv://prod/db/postgres"); code != 1 || !strings.Contains(errs, "does not let") {
		t.Fatalf("backup reading another item: %d %s", code, errs)
	}
	t.Setenv(svrpc.EnvHost, "1")
	if got := h.ok("run", "--env", "KEY=sv://prod/backup/s3", "--", "sh", "-c", `printf %s "$KEY"`); got != "s3-key" {
		t.Fatalf("run with SECRETVAULT_HOST=1: %q", got)
	}
	t.Setenv(svrpc.EnvHost, "")
	if _, errs, code := h.exec("", "--host", "ls"); code != 1 || !strings.Contains(errs, "only resolves sv:// references") {
		t.Fatalf("a local service listing items: %d %s", code, errs)
	}

	h.root = true
	h.ok("host", "deny", "--user", "4242", "--program", "/usr/local/bin/backup")
	h.root = false
	if _, _, code := h.exec("", "--host", "read", "sv://prod/backup/s3"); code != 1 {
		t.Fatal("read after deny")
	}
	h.root = true
	out = h.ok("host", "audit", "-n", "0")
	for _, want := range []string{"delivered", "refused", "changed", "not in the host policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit did not say %q:\n%s", want, out)
		}
	}
}

func TestWithoutAHostDaemonNothingIsStarted(t *testing.T) {
	h := newHostCLI(t)
	h.root = false
	_, errs, code := h.exec("", "--host", "read", "sv://prod/x")
	if code != 1 || !strings.Contains(errs, "the host daemon does not answer on "+filepath.Join(h.run, "secretvaultd.sock")) {
		t.Fatalf("%d %s", code, errs)
	}
	if _, errs, _ := h.exec("", "host", "status"); !strings.Contains(errs, "root's alone") {
		t.Fatalf("status: %s", errs)
	}
	if _, err := os.Stat(h.run); !os.IsNotExist(err) {
		t.Fatal("something made the host's runtime directory")
	}
}
