package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

type harness struct {
	t     *testing.T
	dir   string
	env   map[string]string
	flags []string // --server and --fingerprint, once the server runs
}

// run runs a command with stdin, returning stdout, stderr and the exit
// code. There is no terminal: shares are read from stdin.
func (h *harness) run(stdin string, args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: &errb,
		getenv: func(k string) string { return h.env[k] },
		client: svdeliver.NewClient,
	}
	if len(args) > 0 && args[0] != "init" {
		// Connection flags go after the command's own words.
		args = append(append([]string{}, args...), h.flags...)
	}
	code := a.run(args)
	return out.String(), errb.String(), code
}

func (h *harness) must(stdin string, args ...string) string {
	h.t.Helper()
	out, errs, code := h.run(stdin, args...)
	if code != 0 {
		h.t.Fatalf("secretvault-server %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

var shareRE = regexp.MustCompile(`SVUS1-[A-Z0-9-]+`)

func TestTheDeliverySideFromTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, env: map[string]string{}}
	deliverDir := filepath.Join(dir, "deliver")
	tokenFile := filepath.Join(dir, "admin.token")
	credFile := filepath.Join(dir, "unseal.cred")

	out := h.must("", "init", "--delivery-dir", deliverDir, "--shares", "3", "--threshold", "2",
		"--admin-token-file", tokenFile, "--credential-file", credFile)
	shares := shareRE.FindAllString(out, -1)
	if len(shares) != 3 || !strings.Contains(out, "any 2 of them unseal") || !strings.Contains(out, "systemd-creds encrypt") {
		t.Fatalf("init said:\n%s", out)
	}
	recipient := regexp.MustCompile(`sv-recipient-1-modern-\S+`).FindString(out)
	if recipient == "" {
		t.Fatalf("init printed no recipient:\n%s", out)
	}
	for _, f := range []string{tokenFile, credFile} {
		if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, st, err)
		}
	}
	if _, _, code := h.run("", "init", "--delivery-dir", deliverDir); code == 0 {
		t.Fatal("init ran twice on one directory")
	}
	os.WriteFile(filepath.Join(deliverDir, svdeliver.ConfigFile), []byte(`{"rate": -1}`), 0o600)

	// The owner's vault, shared with the server.
	vaultDir := filepath.Join(dir, "vault")
	store, _ := svstore.OpenDir(vaultDir)
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: svcrypto.RandomBytes(32)}, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Put(svcore.Item{Kind: "password", Name: "prod/db", Fields: []svcore.Field{{Name: "password", Type: svcore.FieldConcealed, Value: []byte("hunter2")}}})
	_, pub, _ := svformat.ParseRecipient(recipient)
	if _, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Recipient: pub}); err != nil {
		t.Fatal(err)
	}

	// The server.
	srv, err := svdeliver.New(svdeliver.Config{Dir: deliverDir, CredentialsDir: filepath.Join(dir, "no-creds")})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewUnstartedServer(srv)
	hs.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	hs.StartTLS()
	t.Cleanup(func() { hs.Close(); srv.Close() })
	sum := sha256.Sum256(hs.Certificate().Raw)
	h.flags = []string{"--server", hs.URL, "--fingerprint", hex.EncodeToString(sum[:])}
	h.env["SECRETVAULT_ADMIN_TOKEN_FILE"] = tokenFile

	if out := h.must("", "status"); !strings.Contains(out, "Sealed: 2 of the 3") {
		t.Fatalf("status: %s", out)
	}
	if out := h.must(shares[2]+"\n", "unseal"); !strings.Contains(out, "1 of 2 shares given") {
		t.Fatalf("first share: %s", out)
	}
	shareFile := filepath.Join(dir, "share")
	os.WriteFile(shareFile, []byte(shares[0]), 0o600)
	if out := h.must("", "unseal", "--share-file", shareFile); !strings.Contains(out, "Unsealed") {
		t.Fatalf("second share: %s", out)
	}

	out = h.must("", "deliver", "add-vault", "main", vaultDir)
	if !strings.Contains(out, "shared with the server already, and open") {
		t.Fatalf("add-vault: %s", out)
	}
	tok := strings.TrimSpace(h.must("", "token", "create", "app", "--cidr", "127.0.0.0/8", "--ttl", "24h"))
	if !strings.HasPrefix(tok, "svdt_") {
		t.Fatalf("token create printed %q", tok)
	}
	h.must("", "role", "set", "app", "--token", "app", "--allow", "main:prod/*:read,list")
	if out := h.must("", "role", "ls"); !strings.Contains(out, "app  for token app") || !strings.Contains(out, "read,list main:prod/*") {
		t.Fatalf("role ls: %s", out)
	}
	if out := h.must("", "token", "ls"); !strings.Contains(out, "127.0.0.0/8") {
		t.Fatalf("token ls: %s", out)
	}
	if out := h.must("", "deliver", "ls"); !strings.Contains(out, "main  open") {
		t.Fatalf("deliver ls: %s", out)
	}
	cl, _ := svdeliver.NewClient(svdeliver.ClientOptions{URL: hs.URL, Fingerprint: h.flags[3], Token: tok})
	if val, err := cl.Value(context.Background(), "main", "prod/db", ""); err != nil || string(val) != "hunter2" {
		t.Fatalf("reading with the new token: %q %v", val, err)
	}
	if out := h.must("", "audit"); !strings.Contains(out, "allowed  read main/prod/db token:app (app)") {
		t.Fatalf("audit:\n%s", out)
	}
	// A role for a pipeline, from flags.
	h.must("", "issuer", "set", "github", "--url", "https://token.actions.githubusercontent.com", "--audience", "https://secrets.example.com")
	h.must("", "role", "set", "deploy", "--oidc", "github", "--claim", "repository=acme/app", "--claim", "ref=refs/heads/main", "--allow", "main:prod/*")
	if _, errs, code := h.run("", "role", "set", "any", "--oidc", "github", "--claim", "repository=*", "--allow", "main:*"); code == 0 || !strings.Contains(errs, "other than wildcards") {
		t.Fatalf("a role for every repository was taken: %d %s", code, errs)
	}

	// Rekey: the admin starts it, two operators give their shares, the
	// second gets the new ones.
	h.must("", "rekey", "--shares", "4", "--threshold", "3", "--credential", "new")
	if out := h.must(shares[1]+"\n", "rekey"); !strings.Contains(out, "1 of 2 given") {
		t.Fatalf("first rekey share: %s", out)
	}
	newCred := filepath.Join(dir, "new.cred")
	out = h.must(shares[2]+"\n", "rekey", "--credential-file", newCred)
	newShares := shareRE.FindAllString(out, -1)
	if len(newShares) != 4 || !strings.Contains(out, "no longer unseal") {
		t.Fatalf("second rekey share:\n%s", out)
	}
	if b, err := os.ReadFile(newCred); err != nil || !strings.HasPrefix(string(b), "SVUK1-") {
		t.Fatalf("the new credential: %q %v", b, err)
	}

	h.must("", "seal")
	if out := h.must("", "status"); !strings.Contains(out, "Sealed: 3 of the 4") {
		t.Fatalf("after sealing: %s", out)
	}
	// Admin commands need the admin token.
	delete(h.env, "SECRETVAULT_ADMIN_TOKEN_FILE")
	if _, errs, code := h.run("", "token", "ls"); code != 1 || !strings.Contains(errs, "admin token") {
		t.Fatalf("token ls without the admin token: %d %s", code, errs)
	}
}

func TestAuditLinesCannotDriveTheTerminal(t *testing.T) {
	if got := printable("login x (\x1b]0;owned\x07\x1b[2J): no\r\n"); got != "login x (?]0;owned??[2J): no??" {
		t.Fatalf("%q", got)
	}
}

func TestParseAllow(t *testing.T) {
	cases := map[string]string{
		"main:prod/*":           "main prod/* [read]",
		"main:prod/*:list":      "main prod/* [list]",
		"main:prod/*:read,list": "main prod/* [read list]",
		"main:a:b/*":            "main a:b/* [read]", // a colon in the glob, not before capabilities
	}
	for in, want := range cases {
		r, err := parseAllow(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := r.Vault + " " + r.Items + " [" + strings.Join(r.Capabilities, " ") + "]"; got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"main", ":x", "main:"} {
		if _, err := parseAllow(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
