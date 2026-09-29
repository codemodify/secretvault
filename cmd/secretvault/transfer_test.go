package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const chromeCSV = "name,url,username,password,note\n" +
	"github.com,https://github.com/login,ada,gh-p4ss,work account\n" +
	"example.org,https://example.org,ada,ex-p4ss,\n"

func TestImportStoresItemsAndSkipsWhatExists(t *testing.T) {
	h := newHarness(t)
	h.init()
	file := h.write("Chrome Passwords.csv", chromeCSV)
	out, errs, code := h.run("", h.with("import", "auto", file, "--prefix", "imported/chrome")...)
	if code != 0 || !strings.Contains(out, "Imported 2 items, skipped 0") || !strings.Contains(errs, "as csv") {
		t.Fatalf("import: %d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out+errs, "gh-p4ss") {
		t.Fatal("the import printed a secret")
	}
	if got := h.ok("", h.with("get", "imported/chrome/github.com")...); got != "gh-p4ss\n" {
		t.Fatalf("get = %q", got)
	}
	var j jsonItem
	json.Unmarshal([]byte(h.ok("", h.with("get", "--json", "imported/chrome/github.com")...)), &j)
	if j.Kind != "login" || j.Label != "github.com" || len(j.Fields) != 4 {
		t.Fatalf("imported item: %+v", j)
	}

	// Again: both exist now, and are left alone.
	h.write("Chrome Passwords.csv", strings.Replace(chromeCSV, "gh-p4ss", "changed", 1))
	out, errs, _ = h.run("", h.with("import", "csv", file, "--prefix", "imported/chrome")...)
	if !strings.Contains(out, "Imported 0 items, skipped 2") || !strings.Contains(errs, "imported/chrome/github.com: already exists") {
		t.Fatalf("second import:\n%s\n%s", out, errs)
	}
	if got := h.ok("", h.with("get", "imported/chrome/github.com")...); got != "gh-p4ss\n" {
		t.Fatalf("an existing item was changed: %q", got)
	}
	out = h.ok("", h.with("import", "csv", file, "--prefix", "imported/chrome", "--overwrite")...)
	if !strings.Contains(out, "Imported 2 items, skipped 0") {
		t.Fatalf("--overwrite: %s", out)
	}
	if got := h.ok("", h.with("get", "imported/chrome/github.com")...); got != "changed\n" {
		t.Fatalf("--overwrite did not replace: %q", got)
	}
}

func TestImportDryRunListsNamesAndStoresNothing(t *testing.T) {
	h := newHarness(t)
	h.init()
	file := h.write("export.csv", chromeCSV)
	// No vault key given: a dry run never talks to the vault.
	out, errs, code := h.run("", "import", "csv", file, "--dry-run", "--prefix", "x")
	if code != 0 || out != "x/github.com\nx/example.org\n" || !strings.Contains(errs, "nothing was stored") {
		t.Fatalf("dry run: %d %q %q", code, out, errs)
	}
	if got := h.ok("", h.with("ls")...); got != "" {
		t.Fatalf("a dry run stored %q", got)
	}
}

func TestAnEncryptedExportAsksForItsOwnPassphrase(t *testing.T) {
	h := newHarness(t)
	h.init()
	file := filepath.Join("..", "..", "svimport", "testdata", "bitwarden-encrypted-pbkdf2.json")
	h.answers = []string{"not it", "correct horse battery staple"}
	out, errs, code := h.run("", h.with("import", "auto", file)...)
	if code != 0 || !strings.Contains(errs, "does not open") || !strings.Contains(out, "Imported 2 items") {
		t.Fatalf("import: %d\n%s\n%s", code, out, errs)
	}
	if got := h.ok("", h.with("get", "Work/Servers/db.example")...); got != "pg-secret\n" {
		t.Fatalf("get = %q", got)
	}

	// From a file instead, and a wrong one is not asked about again.
	h.write("bwpass", "wrong\n")
	if _, errs, code := h.run("", h.with("import", "bitwarden", file, "--source-passphrase-file", filepath.Join(h.dir, "bwpass"), "--dry-run")...); code != 1 || !strings.Contains(errs, "does not open") {
		t.Fatalf("a wrong passphrase file: %d %q", code, errs)
	}
	kdbx := filepath.Join("..", "..", "svimport", "testdata", "kdbx4-chacha20-argon2d.kdbx")
	keyx := filepath.Join("..", "..", "svimport", "testdata", "kdbx4-chacha20-argon2d.keyx")
	out = h.ok("", h.with("import", "kdbx", kdbx, "--source-passphrase-file", h.passFile, "--source-keyfile", keyx, "--dry-run")...)
	if !strings.Contains(out, "Mail & Chat/Mailbox") {
		t.Fatalf("a KDBX file with a key file: %q", out)
	}
	// For real: the entry's attachment comes along.
	out = h.ok("", h.with("import", "kdbx", kdbx, "--source-passphrase-file", h.passFile, "--source-keyfile", keyx, "--prefix", "kp")...)
	if !strings.Contains(out, "(1 files)") {
		t.Fatalf("importing with an attachment: %q", out)
	}
	if got := h.ok("", h.with("file", "get", "kp/Mail & Chat/Mailbox", "backup-codes.txt", "-o", "-")...); got != "code-1 code-2 code-3" {
		t.Fatalf("the imported attachment: %q", got)
	}
}

func TestExportWritesNewPrivateFilesThatImportBack(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("hunter2", h.with("set", "web/github.com", "--kind", "login", "--field", "username=ada", "--tag", "dev")...)
	h.ok("s3cret", h.with("set", "db/prod", "--attr", "env=prod")...)
	h.ok("x", h.with("set", "other/x")...)

	kdbx := filepath.Join(h.dir, "out.kdbx")
	newPass := h.write("newpass", "file passphrase 1\n")
	out := h.ok("", h.with("export", "kdbx", kdbx, "--new-passphrase-file", newPass, "--prefix", "web/")...)
	if !strings.Contains(out, "Exported 1 items") {
		t.Fatalf("export: %q", out)
	}
	cxf := filepath.Join(h.dir, "out.cxf.json")
	out, errs, code := h.run("", h.with("export", "cxf", cxf)...)
	if code != 0 || !strings.Contains(out, "Exported 3 items") || !strings.Contains(errs, "not encrypted") {
		t.Fatalf("cxf export: %d %q %q", code, out, errs)
	}
	for _, f := range []string{kdbx, cxf} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", f, st.Mode().Perm())
		}
	}
	if _, errs, code := h.run("", h.with("export", "cxf", cxf)...); code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatalf("an export over an existing file: %d %q", code, errs)
	}

	// The KDBX file asks for its passphrase when imported.
	h.answers = []string{"file passphrase 1"}
	h.ok("", h.with("import", "auto", kdbx, "--prefix", "from-kdbx")...)
	if got := h.ok("", h.with("get", "from-kdbx/web/github.com")...); got != "hunter2\n" {
		t.Fatalf("from KDBX: %q", got)
	}
	var j jsonItem
	json.Unmarshal([]byte(h.ok("", h.with("get", "--json", "from-kdbx/web/github.com")...)), &j)
	if j.Kind != "login" || len(j.Tags) != 1 || j.Tags[0] != "dev" {
		t.Fatalf("from KDBX: %+v", j)
	}
	h.ok("", h.with("import", "auto", cxf, "--prefix", "from-cxf")...)
	json.Unmarshal([]byte(h.ok("", h.with("get", "--json", "from-cxf/db/prod")...)), &j)
	if j.Attrs["env"] != "prod" || j.Fields[0].Value != "s3cret" {
		t.Fatalf("from CXF: %+v", j)
	}
}

func TestImportExplainsWhatItCannotRead(t *testing.T) {
	h := newHarness(t)
	h.init()
	if _, errs, code := h.run("", h.with("import", "pass", h.dir)...); code != 1 || !strings.Contains(errs, "M5") {
		t.Fatalf("pass: %d %q", code, errs)
	}
	pgp := h.write("Proton Pass_export.pgp", "-----BEGIN PGP MESSAGE-----\n\nwy4ECQMI\n-----END PGP MESSAGE-----\n")
	if _, errs, code := h.run("", h.with("import", "auto", pgp)...); code != 1 || !strings.Contains(errs, "M5") {
		t.Fatalf("an encrypted Proton Pass export: %d %q", code, errs)
	}
	unknown := h.write("notes.txt", "dear diary\n")
	if _, errs, code := h.run("", h.with("import", "auto", unknown)...); code != 1 || !strings.Contains(errs, "cannot tell") {
		t.Fatalf("an unknown file: %d %q", code, errs)
	}
	if _, errs, code := h.run("", h.with("export", "json", filepath.Join(h.dir, "x"))...); code != 1 || !strings.Contains(errs, "cxf and kdbx") {
		t.Fatalf("an unknown export format: %d %q", code, errs)
	}
	if _, _, code := h.run("", "import", "csv"); code != 2 {
		t.Fatalf("a missing argument: exit %d", code)
	}
}
