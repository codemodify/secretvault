package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

type harness struct {
	t        *testing.T
	dir      string // scratch
	vault    string
	passFile string
	answers  []string // what the terminal "types", in order
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	a, p := svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	svcrypto.DefaultPBKDF2 = svcrypto.KDFParams{Alg: svcrypto.PBKDF2SHA256, Iterations: 10}
	t.Cleanup(func() { svcrypto.DefaultArgon2, svcrypto.DefaultPBKDF2 = a, p })

	dir := t.TempDir()
	t.Setenv(svcore.EnvHome, filepath.Join(dir, "home"))
	t.Setenv(EnvVault, "")
	h := &harness{t: t, dir: dir, vault: filepath.Join(dir, "vault"), passFile: filepath.Join(dir, "pass")}
	h.write("pass", "correct horse battery staple\n")
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
	}
	code := c.run(append([]string{"--vault", h.vault}, args...))
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

func (h *harness) pf() []string { return []string{"--passphrase-file", h.passFile} }

func (h *harness) with(args ...string) []string { return append(args, h.pf()...) }

func TestInitSetGetRoundTrip(t *testing.T) {
	h := newHarness(t)
	if out := h.init(); !strings.Contains(out, "Created vault") {
		t.Fatalf("init said %q", out)
	}
	if _, errs, code := h.run("", "init", "--passphrase-file", h.passFile); code == 0 || !strings.Contains(errs, "already exists") {
		t.Fatalf("second init: %d %q", code, errs)
	}
	h.ok("hunter2\n", h.with("set", "web/github.com", "--kind", "login", "--field", "username=ada", "--attr", "service=github")...)
	if got := h.ok("", h.with("get", "web/github.com")...); got != "hunter2\n" {
		t.Fatalf("get = %q", got)
	}
	// Flags may follow the name.
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
	if got := h.ok("", h.with("ls", "-l")...); strings.Count(got, "\n") != 3 || !strings.Contains(got, "password") {
		t.Fatalf("ls -l = %q", got)
	}
	h.ok("", h.with("mv", "web/a", "web/renamed")...)
	h.ok("3", h.with("set", "web/renamed")...)
	hist := h.ok("", h.with("history", "web/renamed", "--show")...)
	if strings.Count(hist, "\n") != 4 || !strings.Contains(hist, "current") || !strings.Contains(hist, "\t1") && !strings.Contains(hist, " 1\n") {
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

	// Recovery key, typed at the terminal.
	h.answers = []string{strings.ToLower(rk)}
	if got := h.ok("", "get", "x", "--recovery"); got != "hunter2\n" {
		t.Fatalf("recovery unlock: %q", got)
	}

	// Keyfile.
	kf := filepath.Join(h.dir, "vault.key")
	h.ok("", h.with("slot", "add", "keyfile", kf, "--create", "--label", "usb")...)
	if got := h.ok("", "get", "x", "--keyfile", kf); got != "hunter2\n" {
		t.Fatalf("keyfile unlock: %q", got)
	}

	// Identity (a device key).
	idFile := filepath.Join(h.dir, "laptop.id")
	rcpt := strings.TrimSpace(h.ok("", "identity", "new", "--out", idFile))
	if got := strings.TrimSpace(h.ok("", "identity", "pub", idFile)); got != rcpt {
		t.Fatalf("identity pub = %q, new printed %q", got, rcpt)
	}
	h.ok("", h.with("slot", "add", "recipient", idFile, "--label", "laptop")...)
	if got := h.ok("", "get", "x", "--identity", idFile); got != "hunter2\n" {
		t.Fatalf("identity unlock: %q", got)
	}

	list := h.ok("", "slot", "list") // works while locked, without a key
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
	filepath.WalkDir(filepath.Join(h.vault, svformat.ObjectsDir), func(p string, d fs.DirEntry, err error) error {
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

func TestNothingReadableReachesTheDisk(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2-hunter2", h.with("set", "bank/very-private-name", "--field", "username=ada.lovelace", "--attr", "service=secret-service-attr")...)
	err := filepath.WalkDir(h.vault, func(p string, d fs.DirEntry, err error) error {
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
