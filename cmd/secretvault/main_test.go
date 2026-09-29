package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

type harness struct {
	t        *testing.T
	dir      string
	home     string
	sock     string
	passFile string
	answers  []string  // what the terminal "types", in order
	desk     *fakeDesk // the desktop prompt, for programs other than the CLI
}

// fakeDesk stands in for the desktop prompt: it records what it is asked
// and answers as the test says, cancelling when it has not been told.
type fakeDesk struct {
	mu         sync.Mutex
	asked      []string
	passphrase string // typed when asked for a vault's passphrase
	choice     string // picked when asked to decide about a program
}

func (d *fakeDesk) Passphrase(_ context.Context, q svrpc.PromptAsk) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, "passphrase: "+q.Description)
	if d.passphrase == "" {
		return nil, svrpc.ErrCanceled
	}
	return []byte(d.passphrase), nil
}

func (d *fakeDesk) Choose(_ context.Context, q svrpc.PromptAsk) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, "choose: "+q.Description)
	if d.choice == "" {
		return "", svrpc.ErrCanceled
	}
	return d.choice, nil
}

func (d *fakeDesk) Describe() string { return "test desktop" }

func (d *fakeDesk) questions() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.asked...)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	a, p := svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	svcrypto.DefaultPBKDF2 = svcrypto.KDFParams{Alg: svcrypto.PBKDF2SHA256, Iterations: 10}
	t.Cleanup(func() { svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2 = a, p })
	t.Setenv(EnvVault, "")

	dir, err := os.MkdirTemp("", "svcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, dir: dir, home: filepath.Join(dir, "home"), sock: filepath.Join(dir, "s", "d.sock"), passFile: filepath.Join(dir, "pass"), desk: &fakeDesk{}}
	h.write("pass", "correct horse battery staple\n")

	// A real daemon, in-process, which takes this test binary for the CLI.
	d, err := svd.New(svd.Options{Home: h.home, Socket: h.sock, Desktop: h.desk, IsCLI: func(*svpeer.Process) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ln, cleanup, err := svd.Listen(h.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done; cleanup() })
	return h
}

func (h *harness) write(name, content string) string {
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) terminal(prompt string) ([]byte, error) {
	if len(h.answers) == 0 {
		return nil, errors.New("test: nothing typed at the terminal for " + prompt)
	}
	a := h.answers[0]
	h.answers = h.answers[1:]
	return []byte(a), nil
}

// run runs the CLI with stdin, returning stdout, stderr and the exit code.
func (h *harness) run(stdin string, args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	c := &cli{
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: &errb,
		ask:    h.terminal,
		askNew: func(p string, _ int) ([]byte, error) { return h.terminal(p) },
		canAsk: true,
		connect: func(o secretvault.Options) (*secretvault.Client, error) {
			o.Socket, o.NoStart = h.sock, true
			return secretvault.Connect(o)
		},
	}
	code := c.run(args)
	if c.client != nil {
		c.client.Close()
	}
	return out.String(), errb.String(), code
}

// ok runs the CLI and fails the test unless it exits 0.
func (h *harness) ok(stdin string, args ...string) string {
	h.t.Helper()
	out, errs, code := h.run(stdin, args...)
	if code != 0 {
		h.t.Fatalf("secretvault %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

func (h *harness) init(extra ...string) string {
	return h.ok("", append([]string{"init", "--passphrase-file", h.passFile}, extra...)...)
}

func (h *harness) with(args ...string) []string {
	return append(args, "--passphrase-file", h.passFile)
}

func TestInitSetGetRoundTrip(t *testing.T) {
	h := newHarness(t)
	if out := h.init(); !strings.Contains(out, `Created vault "default"`) {
		t.Fatalf("init said %q", out)
	}
	if _, errs, code := h.run("", "init", "--passphrase-file", h.passFile); code == 0 || !strings.Contains(errs, "already") {
		t.Fatalf("second init: %d %q", code, errs)
	}
	h.ok("hunter2\n", h.with("set", "web/github.com", "--kind", "login", "--field", "username=ada", "--attr", "service=github")...)
	if got := h.ok("", h.with("get", "web/github.com")...); got != "hunter2\n" {
		t.Fatalf("get = %q", got)
	}
	if got := h.ok("", h.with("get", "web/github.com", "--field", "username")...); got != "ada\n" {
		t.Fatalf("get --field = %q", got)
	}
	var j jsonItem
	if err := json.Unmarshal([]byte(h.ok("", h.with("get", "--json", "web/github.com")...)), &j); err != nil {
		t.Fatal(err)
	}
	if j.Kind != "login" || j.Attrs["service"] != "github" || len(j.Fields) != 2 {
		t.Fatalf("--json = %+v", j)
	}
}

func TestATerminalProvesItselfWithThePassphrase(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "x")...)
	// No key given: the daemon asks this terminal for the passphrase.
	h.answers = []string{"wrong", "correct horse battery staple"}
	if got := h.ok("", "get", "x"); got != "v\n" {
		t.Fatalf("get = %q", got)
	}
	h.answers = []string{"no", "nope", "never"}
	if _, errs, code := h.run("", "get", "x"); code != 1 || !strings.Contains(errs, "does not open") {
		t.Fatalf("three wrong passphrases: %d %q", code, errs)
	}
}

func TestLockingAndUnlocking(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "x")...)
	h.ok("", "lock")
	if out := h.ok("", "status"); !regexp.MustCompile(`default \*\s+locked`).MatchString(out) {
		t.Fatalf("status after lock:\n%s", out)
	}
	h.answers = []string{"correct horse battery staple"}
	h.ok("", "unlock")
	if out := h.ok("", "vault", "list"); !strings.Contains(out, "unlocked") {
		t.Fatalf("vault list after unlock:\n%s", out)
	}
	h.ok("", "lock", "--all")
	if got := h.ok("", h.with("get", "x")...); got != "v\n" {
		t.Fatalf("get with a key after lock: %q", got)
	}
}

func TestSeveralVaults(t *testing.T) {
	h := newHarness(t)
	h.init()
	elsewhere := filepath.Join(h.dir, "synced", "work")
	h.ok("", "init", "--name", "work", "--path", elsewhere, "--passphrase-file", h.passFile)
	h.ok("w", h.with("--vault", "work", "set", "w")...)
	if _, _, code := h.run("", h.with("get", "w")...); code != 1 {
		t.Fatal("an item of work showed up in the default vault")
	}
	h.ok("", "vault", "default", "work")
	if got := h.ok("", h.with("get", "w")...); got != "w\n" {
		t.Fatalf("after changing the default: %q", got)
	}
	h.ok("", "vault", "forget", "work")
	h.ok("", "vault", "add", "work2", elsewhere)
	if got := h.ok("", h.with("--vault", "work2", "get", "w")...); got != "w\n" {
		t.Fatalf("a re-added vault: %q", got)
	}
	// --vault after the command works as well as before it.
	if got := h.ok("", h.with("get", "w", "--vault", "work2")...); got != "w\n" {
		t.Fatalf("--vault after the command: %q", got)
	}
}

func TestUpdatingKeepsWhatIsNotGiven(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("s3cret", h.with("set", "db", "--field", "host=db.local")...)
	h.ok("", h.with("set", "db", "--no-secret", "--attr", "env=prod", "--tag", "infra")...)
	var j jsonItem
	json.Unmarshal([]byte(h.ok("", h.with("get", "db", "--json")...)), &j)
	if j.Attrs["env"] != "prod" || len(j.Tags) != 1 || len(j.Fields) != 2 {
		t.Fatalf("after update: %+v", j)
	}
	if got := h.ok("", h.with("get", "db")...); got != "s3cret\n" {
		t.Fatalf("the secret changed: %q", got)
	}
	h.ok("", h.with("set", "db", "--replace", "--no-secret", "--field", "only=this")...)
	var r jsonItem
	json.Unmarshal([]byte(h.ok("", h.with("get", "db", "--json")...)), &r)
	if len(r.Fields) != 1 || r.Attrs != nil || r.Tags != nil {
		t.Fatalf("--replace kept old parts: %+v", r)
	}
}

func TestGeneratedSecretsArePrintedAndStored(t *testing.T) {
	h := newHarness(t)
	h.init()
	gen := strings.TrimSpace(h.ok("", h.with("set", "api", "--generate", "32")...))
	if len(gen) != 32 {
		t.Fatalf("generated %q", gen)
	}
	if got := strings.TrimSpace(h.ok("", h.with("get", "api")...)); got != gen {
		t.Fatalf("stored %q, printed %q", got, gen)
	}
	if p := strings.TrimSpace(h.ok("", "gen", "--length", "40", "--no-symbols")); !regexp.MustCompile(`^[A-Za-z0-9]{40}$`).MatchString(p) {
		t.Fatalf("gen = %q", p)
	}
}

func TestListMoveRemoveAndHistory(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("1", h.with("set", "web/a")...)
	h.ok("2", h.with("set", "web/a")...)
	h.ok("x", h.with("set", "web/b")...)
	h.ok("y", h.with("set", "mail/c")...)
	if got := h.ok("", h.with("ls", "web/")...); got != "web/a\nweb/b\n" {
		t.Fatalf("ls web/ = %q", got)
	}
	h.ok("", h.with("mv", "web/a", "web/renamed")...)
	h.ok("3", h.with("set", "web/renamed")...)
	hist := h.ok("", h.with("history", "web/renamed", "--show")...)
	if strings.Count(hist, "\n") != 4 || !strings.Contains(hist, "current") {
		t.Fatalf("history = %q", hist)
	}
	h.ok("", h.with("rm", "web/b")...)
	if _, errs, code := h.run("", h.with("get", "web/b")...); code != 1 || !strings.Contains(errs, "no such item") {
		t.Fatalf("get after rm: %d %q", code, errs)
	}
}

func TestEveryWayInWorks(t *testing.T) {
	h := newHarness(t)
	out := h.init("--recovery")
	rk := regexp.MustCompile(`SVRK1-[A-Z2-7-]+`).FindString(out)
	if rk == "" {
		t.Fatalf("init --recovery printed no key:\n%s", out)
	}
	h.ok("hunter2", h.with("set", "x")...)

	h.ok("", "lock")
	h.answers = []string{strings.ToLower(rk)}
	if got := h.ok("", "get", "x", "--recovery"); got != "hunter2\n" {
		t.Fatalf("recovery unlock: %q", got)
	}

	kf := filepath.Join(h.dir, "vault.key")
	h.ok("", h.with("slot", "add", "keyfile", kf, "--create", "--label", "usb")...)
	h.ok("", "lock")
	if got := h.ok("", "get", "x", "--keyfile", kf); got != "hunter2\n" {
		t.Fatalf("keyfile unlock: %q", got)
	}

	idFile := filepath.Join(h.dir, "laptop.id")
	rcpt := strings.TrimSpace(h.ok("", "identity", "new", "--out", idFile))
	if got := strings.TrimSpace(h.ok("", "identity", "pub", idFile)); got != rcpt {
		t.Fatalf("identity pub = %q, new printed %q", got, rcpt)
	}
	h.ok("", h.with("slot", "add", "recipient", idFile, "--label", "laptop")...)
	h.ok("", "lock")
	if got := h.ok("", "get", "x", "--identity", idFile); got != "hunter2\n" {
		t.Fatalf("identity unlock: %q", got)
	}

	list := h.ok("", "slot", "list")
	for _, want := range []string{"passphrase", "recovery", "keyfile", "recipient", "usb", "laptop", "argon2id"} {
		if !strings.Contains(list, want) {
			t.Errorf("slot list lacks %q:\n%s", want, list)
		}
	}
}

func TestPasswdRetiresTheOldPassphrase(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "x")...)
	newPass := h.write("newpass", "a much better passphrase\n")
	h.ok("", h.with("passwd", "--new-passphrase-file", newPass)...)
	h.ok("", "lock")
	if _, errs, code := h.run("", h.with("get", "x")...); code != 1 || !strings.Contains(errs, "does not open") {
		t.Fatalf("old passphrase: %d %q", code, errs)
	}
	if got := h.ok("", "get", "x", "--passphrase-file", newPass); got != "v\n" {
		t.Fatalf("new passphrase: %q", got)
	}
	n := 0
	for _, line := range strings.Split(h.ok("", "slot", "list"), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[1] == "passphrase" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d passphrase slots after passwd, want 1", n)
	}
}

func TestShortPassphrasesAreRefused(t *testing.T) {
	h := newHarness(t)
	short := h.write("short", "abc\n")
	if _, errs, code := h.run("", "init", "--passphrase-file", short); code != 1 || !strings.Contains(errs, "too short") {
		t.Fatalf("init with a short passphrase: %d %q", code, errs)
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v1", h.with("set", "x")...)
	h.ok("v2", h.with("set", "x")...)
	if out := h.ok("", h.with("verify")...); !strings.Contains(out, "1 items (1 objects, 2 revisions)") {
		t.Fatalf("verify = %q", out)
	}
	var victim string
	filepath.WalkDir(filepath.Join(h.home, "vaults", "default", svformat.ObjectsDir), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && victim == "" {
			victim = p
		}
		return nil
	})
	b, _ := os.ReadFile(victim)
	b[len(b)/2] ^= 1
	os.WriteFile(victim, b, 0o600)
	out, _, code := h.run("", h.with("verify")...)
	if code != 1 || !strings.Contains(out, "problem:") {
		t.Fatalf("verify after tampering: %d %q", code, out)
	}
}

func TestGrantsAndAuditAreShown(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "x")...)
	h.ok("", h.with("get", "x")...)
	audit := h.ok("", h.with("audit")...)
	if !strings.Contains(audit, "allowed") || !strings.Contains(audit, "read x") {
		t.Fatalf("audit:\n%s", audit)
	}
	if out := h.ok("", h.with("grant", "list")...); !strings.Contains(out, "No program") {
		t.Fatalf("grant list:\n%s", out)
	}
}

func TestNothingReadableReachesTheDisk(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2-hunter2", h.with("set", "bank/very-private-name", "--field", "username=ada.lovelace", "--attr", "service=secret-service-attr")...)
	h.ok("", h.with("get", "bank/very-private-name")...)
	err := filepath.WalkDir(h.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, needle := range []string{"hunter2", "very-private-name", "ada.lovelace", "secret-service-attr", "bank/"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s contains %q in the clear", p, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClipCopiesInsteadOfPrinting(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2", h.with("set", "x")...)
	var got []byte
	var ttl time.Duration
	var out, errb bytes.Buffer
	c := &cli{stdin: strings.NewReader(""), stdout: &out, stderr: &errb, canAsk: true,
		ask: h.terminal, askNew: func(p string, _ int) ([]byte, error) { return h.terminal(p) },
		connect: func(o secretvault.Options) (*secretvault.Client, error) {
			o.Socket, o.NoStart = h.sock, true
			return secretvault.Connect(o)
		},
		clip: func(s []byte, d time.Duration) (string, error) {
			got, ttl = append([]byte(nil), s...), d
			return "test", nil
		},
	}
	if code := c.run(h.with("get", "x", "--clip", "--clip-seconds", "12")); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	c.client.Close()
	if string(got) != "hunter2" || ttl != 12*time.Second || out.Len() != 0 || !strings.Contains(errb.String(), "clears in 12s") {
		t.Fatalf("copied %q for %v; stdout %q; stderr %q", got, ttl, out.String(), errb.String())
	}
}

func TestErrorsAreHelpful(t *testing.T) {
	h := newHarness(t)
	if _, errs, code := h.run("", h.with("get", "x")...); code != 1 || !strings.Contains(errs, "secretvault init") {
		t.Fatalf("no vault: %d %q", code, errs)
	}
	h.init()
	wrong := h.write("wrong", "not the passphrase\n")
	if _, errs, code := h.run("", "get", "x", "--passphrase-file", wrong); code != 1 || !strings.Contains(errs, "does not open") {
		t.Fatalf("wrong passphrase: %d %q", code, errs)
	}
	if _, _, code := h.run("", "frobnicate"); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
	if _, _, code := h.run("", "get"); code != 2 {
		t.Fatalf("missing argument exit %d", code)
	}
	if _, errs, code := h.run("", h.with("set", "x")...); code != 1 || !strings.Contains(errs, "no secret") {
		t.Fatalf("empty stdin: %d %q", code, errs)
	}
	if out := h.ok("", "version"); !strings.HasPrefix(out, "secretvault ") {
		t.Fatalf("version = %q", out)
	}
}

func TestProgramsCanBeAllowedAheadOfTime(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "backup/key")...)
	out := h.ok("", h.with("grant", "allow", "/bin/sh", "--item", "backup/key")...)
	if !strings.Contains(out, "allow-always") || !strings.Contains(out, `"backup/key"`) {
		t.Fatalf("grant allow said %q", out)
	}
	list := h.ok("", h.with("grant", "list")...)
	if !strings.Contains(list, "sh (") || !strings.Contains(list, "backup/key") {
		t.Fatalf("grant list:\n%s", list)
	}
	if _, errs, code := h.run("", h.with("grant", "allow", "/bin/sh", "--ops", "steal")...); code != 1 || !strings.Contains(errs, "unknown operation") {
		t.Fatalf("a bad op: %d %q", code, errs)
	}
	if _, errs, code := h.run("", h.with("grant", "allow", "/no/such/program")...); code != 1 || !strings.Contains(errs, "no such file") {
		t.Fatalf("a missing program: %d %q", code, errs)
	}
}

func TestReferencesResolveInReadRunAndInject(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("tok-123", h.with("set", "ci/api", "--field", "user=bot")...)
	if got := h.ok("", h.with("read", "sv://-/ci/api")...); got != "tok-123\n" {
		t.Fatalf("read = %q", got)
	}
	if got := h.ok("", h.with("read", "sv://default/ci/api#user")...); got != "bot\n" {
		t.Fatalf("read #user = %q", got)
	}
	env := h.write("app.env", "# a comment\nAPI_TOKEN=sv://-/ci/api\nexport PLAIN=\"x\"\n")
	out := h.ok("", "run", "--passphrase-file", h.passFile, "--env-file", env, "--", "sh", "-c", `printf "%s|%s" "$API_TOKEN" "$PLAIN"`)
	if out != "tok-123|x" {
		t.Fatalf("run = %q", out)
	}
	if _, _, code := h.run("", "run", "--", "sh", "-c", "exit 7"); code != 7 {
		t.Fatalf("run passed exit code %d, want 7", code)
	}
	got := h.ok("token: {{ sv://-/ci/api }}\nuser: {{sv://-/ci/api#user}}\n", h.with("inject")...)
	if got != "token: tok-123\nuser: bot\n" {
		t.Fatalf("inject = %q", got)
	}
	if _, errs, code := h.run("", h.with("read", "sv://nope")...); code != 1 || !strings.Contains(errs, "not a reference") {
		t.Fatalf("a bad reference: %d %q", code, errs)
	}
}

func TestGitStoresAndGetsCredentialsThroughTheHelper(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("protocol=https\nhost=github.com\nusername=ada\npassword=ghp_secret\n\n", h.with("git-credential", "store")...)
	got := h.ok("protocol=https\nhost=github.com\n\n", h.with("git-credential", "get")...)
	if got != "username=ada\npassword=ghp_secret\n" {
		t.Fatalf("get = %q", got)
	}
	if got := h.ok("protocol=https\nhost=gitlab.com\n\n", h.with("git-credential", "get")...); got != "" {
		t.Fatalf("another host's get = %q", got)
	}
	h.ok("protocol=https\nhost=github.com\nusername=ada\n\n", h.with("git-credential", "erase")...)
	if got := h.ok("protocol=https\nhost=github.com\n\n", h.with("git-credential", "get")...); got != "" {
		t.Fatalf("after erase = %q", got)
	}
}

func TestDockerStoresAndGetsCredentialsThroughTheHelper(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok(`{"ServerURL":"https://index.docker.io/v1/","Username":"ada","Secret":"dckr_pat"}`, h.with("docker-credential", "store")...)
	got := h.ok("https://index.docker.io/v1/", h.with("docker-credential", "get")...)
	if !strings.Contains(got, `"Username":"ada"`) || !strings.Contains(got, `"Secret":"dckr_pat"`) {
		t.Fatalf("get = %q", got)
	}
	if list := h.ok("", h.with("docker-credential", "list")...); !strings.Contains(list, `"https://index.docker.io/v1/":"ada"`) {
		t.Fatalf("list = %q", list)
	}
	out, _, code := h.run("ghcr.io", h.with("docker-credential", "get")...)
	if code != 1 || !strings.Contains(out, "credentials not found in native keychain") {
		t.Fatalf("a missing server: %d %q", code, out)
	}
}

func TestHelperNamesPickTheirCommand(t *testing.T) {
	for argv0, want := range map[string]string{
		"/usr/bin/git-credential-secretvault":   "git-credential",
		"docker-credential-secretvault.exe":     "docker-credential",
		"/usr/local/bin/age-plugin-secretvault": "age-plugin",
		"/usr/bin/secretvault":                  "",
	} {
		if got := helperName(argv0); got != want {
			t.Errorf("helperName(%q) = %q", argv0, got)
		}
	}
}

func TestUnsharingCutsAPersonOffForGood(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("before", h.with("set", "x")...)
	idFile := filepath.Join(h.dir, "friend.id")
	h.ok("", "identity", "new", "--out", idFile)
	out := h.ok("", h.with("share", idFile, "--label", "friend")...)
	slot := regexp.MustCompile(`keyslot ([0-9a-f]{32})`).FindStringSubmatch(out)
	if slot == nil {
		t.Fatalf("share said %q", out)
	}
	h.ok("", "lock")
	if got := h.ok("", "get", "x", "--identity", idFile); got != "before\n" {
		t.Fatalf("the friend reads %q", got)
	}
	out = h.ok("", "unshare", slot[1], "--passphrase-file", h.passFile, "--new-passphrase-file", h.passFile)
	if !strings.Contains(out, "epoch 2") {
		t.Fatalf("unshare said %q", out)
	}
	h.ok("after", h.with("set", "x")...)
	h.ok("", "lock")
	if _, errs, code := h.run("", "get", "x", "--identity", idFile); code != 1 || !strings.Contains(errs, "does not open") {
		t.Fatalf("the friend after unsharing: %d %q", code, errs)
	}
	if got := h.ok("", h.with("get", "x")...); got != "after\n" {
		t.Fatalf("the owner reads %q", got)
	}
}

func TestARecoveryKeyInSharesOpensWithAnyThreshold(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2", h.with("set", "x")...)
	out := h.ok("", h.with("slot", "add", "recovery", "--split", "5", "--threshold", "3")...)
	if strings.Contains(out, "SVRK1-") {
		t.Fatalf("the whole recovery key was printed:\n%s", out)
	}
	shares := regexp.MustCompile(`SVRS1-[A-Z2-7-]+`).FindAllString(out, -1)
	if len(shares) != 5 || !strings.Contains(out, "any 3 of them") {
		t.Fatalf("shares printed:\n%s", out)
	}
	if list := h.ok("", "slot", "ls"); !strings.Contains(list, "recovery key, 3 of 5 shares") {
		t.Fatalf("slot label:\n%s", list)
	}

	// Any three, in any order; a typo on the way is asked again.
	h.ok("", "lock")
	typo := shares[4][:len(shares[4])-2] + "ZZ"
	h.answers = []string{shares[4], typo, strings.ToLower(shares[1]), shares[2]}
	if got := h.ok("", "get", "x", "--shares"); got != "hunter2\n" {
		t.Fatalf("unlock with shares: %q", got)
	}
	// Two are not enough: they make some other key, which opens nothing.
	h.ok("", "lock")
	h.answers = []string{shares[0], shares[3]}
	if _, _, code := h.run("", "get", "x", "--shares"); code == 0 {
		t.Fatal("two shares of three opened the vault")
	}

	if _, errs, code := h.run("", h.with("slot", "add", "recovery", "--split", "3", "--threshold", "4")...); code == 0 || !strings.Contains(errs, "threshold") {
		t.Fatalf("a threshold above the shares: %d %s", code, errs)
	}
}

func TestFilesAttachToItemsAndComeBack(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2", h.with("set", "bank")...)
	scan := filepath.Join(h.dir, "passport scan.pdf")
	contents := bytes.Repeat([]byte("%PDF-1.7 scan "), 5000)
	os.WriteFile(scan, contents, 0o600)
	if out := h.ok("", h.with("attach", "bank", scan)...); !strings.Contains(out, "Attached passport scan.pdf (70000 bytes)") {
		t.Fatalf("attach: %s", out)
	}
	h.ok("", h.with("attach", "bank", "-", "--name", "pin.txt")...)
	if out := h.ok("", h.with("file", "ls", "bank")...); !strings.Contains(out, "passport scan.pdf  70000  application/pdf") || !strings.Contains(out, "pin.txt") {
		t.Fatalf("file ls:\n%s", out)
	}
	// Changing the item leaves its files alone.
	h.ok("changed", h.with("set", "bank")...)

	out := filepath.Join(h.dir, "out.pdf")
	h.ok("", h.with("file", "get", "bank", "passport scan.pdf", "-o", out)...)
	if got, _ := os.ReadFile(out); !bytes.Equal(got, contents) {
		t.Fatal("the file came back different")
	}
	if _, errs, code := h.run("", h.with("file", "get", "bank", "passport scan.pdf", "-o", out)...); code == 0 || !strings.Contains(errs, "exists") {
		t.Fatalf("overwriting without --force: %d %s", code, errs)
	}
	if got := h.ok("", h.with("file", "get", "bank", "pin.txt", "-o", "-")...); got != "" {
		t.Fatalf("pin.txt from empty stdin: %q", got)
	}
	h.ok("", h.with("file", "rm", "bank", "pin.txt")...)
	if _, _, code := h.run("", h.with("file", "get", "bank", "pin.txt", "-o", "-")...); code == 0 {
		t.Fatal("a removed file came back")
	}
	if !strings.Contains(h.ok("", h.with("get", "bank", "--json")...), `"passport scan.pdf"`) {
		t.Fatal("get --json does not list the files")
	}
}
