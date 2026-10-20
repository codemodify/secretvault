package main

import (
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// mv --to and cp --to: items go to another vault inside the daemon; the
// command is the person's say-so, --dry-run shows what would go, and a
// vault others read takes --yes.
func TestItemsMoveAndCopyToAnotherVault(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("", "init", "--name", "team", "--passphrase-file", h.passFile)
	for _, n := range []string{"pgp/a", "pgp/b", "web/c"} {
		h.ok("secret-"+n, h.with("set", n)...)
	}
	pass := "correct horse battery staple"

	// What would go; nothing goes.
	h.answers = []string{pass}
	out := h.ok("", h.with("mv", "--to", "team", "pgp/a", "pgp/b", "--dry-run")...)
	for _, want := range []string{"Move 2 items to team?", `2 items go from vault default to vault team: "pgp/a" and "pgp/b".`, "deleted items", "  pgp/b"} {
		if !strings.Contains(out, want) {
			t.Errorf("--dry-run does not say %q:\n%s", want, out)
		}
	}
	if got := h.ok("", h.with("ls")...); got != "pgp/a\npgp/b\nweb/c\n" {
		t.Fatalf("a dry run moved something: %q", got)
	}

	h.answers = []string{pass}
	if out := h.ok("", h.with("mv", "--to", "team", "pgp/a")...); out != "Moved 1 item to vault team. Vault default's deleted items can bring them back.\n" {
		t.Fatalf("mv said %q", out)
	}
	h.answers = []string{pass}
	if got := h.ok("", h.with("get", "pgp/a", "--vault", "team")...); got != "secret-pgp/a\n" {
		t.Fatalf("in team: %q", got)
	}
	if _, _, code := h.run("", h.with("get", "pgp/a")...); code != 1 {
		t.Fatal("still in default")
	}
	if got := h.ok("", h.with("ls", "--deleted")...); !strings.Contains(got, "pgp/a") {
		t.Fatalf("not in the deleted items: %q", got)
	}

	h.answers = []string{pass}
	if out := h.ok("", h.with("cp", "--to", "team", "web/c")...); out != "Copied 1 item to vault team.\n" {
		t.Fatalf("cp said %q", out)
	}
	// A name team has already: nothing is written, and the error says it.
	h.answers = []string{pass}
	if _, errs, code := h.run("", h.with("cp", "--to", "team", "--all")...); code != 1 || !strings.Contains(errs, `"web/c"`) || !strings.Contains(errs, "nothing was copied") {
		t.Fatalf("a clash: %d %q", code, errs)
	}
	if got := h.ok("", h.with("get", "web/c")...); got != "secret-web/c\n" {
		t.Fatalf("cp took it from default: %q", got)
	}

	// Renaming in one vault is as it was.
	h.ok("", h.with("mv", "web/c", "web/d")...)
	if got := h.ok("", h.with("get", "web/d")...); got != "secret-web/c\n" {
		t.Fatalf("after mv FROM TO: %q", got)
	}

	// Into a vault someone else reads, only with --yes.
	id, err := svcrypto.Modern.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	h.ok("", h.with("--vault", "team", "share", svformat.EncodeRecipient(svcrypto.Modern, id.Recipient()), "--label", "alice")...)
	h.answers = []string{pass}
	_, errs, code := h.run("", h.with("mv", "--to", "team", "pgp/b")...)
	if code != 1 || !strings.Contains(errs, `Vault team is not yours alone: "alice" opens it with a key of their own.`) || !strings.Contains(errs, "--yes") {
		t.Fatalf("into a shared vault without --yes: %d %q", code, errs)
	}
	h.answers = []string{pass}
	h.ok("", h.with("mv", "--to", "team", "pgp/b", "--yes")...)
	if got := h.ok("", h.with("ls")...); got != "web/d\n" {
		t.Fatalf("default has %q", got)
	}

	// Usage.
	for _, args := range [][]string{
		{"mv", "--to", "team"},
		{"mv", "--to", "team", "--all", "x"},
		{"mv", "--to", "team", "--prefix", "pgp/"},
		{"cp", "x"},
	} {
		if _, _, code := h.run("", h.with(args...)...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}
