package svops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
)

func TestAgeKeyEntriesAreTheItemsWithARecipient(t *testing.T) {
	es := []svrpc.Entry{
		{Item: svrpc.Item{Name: "age/a", Kind: "key", Attrs: map[string]string{AgeRecipientName: "age1xyz"}}},
		{Item: svrpc.Item{Name: "pgp/b", Kind: "key", Attrs: map[string]string{svrpc.PGPFingerprint: "AB"}}},
		{Item: svrpc.Item{Name: "web/c", Kind: "login"}},
	}
	if got := AgeKeyEntries(es); len(got) != 1 || got[0].Item.Name != "age/a" {
		t.Fatalf("AgeKeyEntries = %+v", got)
	}
}

func TestHelperLinksSayWhichAreTheCLIs(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "secretvault")
	os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o755)
	os.Symlink("secretvault", filepath.Join(dir, "git-credential-secretvault"))
	os.WriteFile(filepath.Join(dir, "docker-credential-secretvault"), []byte("other"), 0o755)
	t.Setenv("PATH", dir)
	links := HelperLinks(cli)
	if len(links) != len(Helpers) {
		t.Fatalf("%d links for %d helpers", len(links), len(Helpers))
	}
	for _, l := range links {
		switch l.Name {
		case "git-credential-secretvault":
			if !l.Exists || !l.Ours || l.OnPath == "" {
				t.Errorf("git's: %+v", l)
			}
		case "docker-credential-secretvault":
			if !l.Exists || l.Ours {
				t.Errorf("docker's, not ours: %+v", l)
			}
		default:
			if l.Exists || l.Ours || l.OnPath != "" || l.Path != filepath.Join(dir, l.Name) {
				t.Errorf("%s: %+v", l.Name, l)
			}
		}
	}
	if none := HelperLinks(""); none[0].Path != "" || none[0].Exists {
		t.Errorf("with no CLI: %+v", none[0])
	}
}

// The errors a manager words in its own way (it tells them apart with
// errors.Is) keep the CLI's text exactly.
func TestTheCLIsWordsAreKeptWhereAManagerRewordsThem(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("%s already exists; pick another name with --item (%w)", "pgp/x", ErrKeyExists): "pgp/x already exists; pick another name with --item (a key is never replaced)",
		fmt.Errorf("%s does not hold exactly one secret key (%w)", "f", ErrNotOneSecretKey):        "f does not hold exactly one secret key (someone's public key goes to 'secretvault contact add')",
		fmt.Errorf("%s has no field %q (%w)", "i", AgeIdentityField, ErrNoAgeIdentity):             `i has no field "age_identity" (make one with 'secretvault age keygen')`,
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err, want)
		}
	}
	for _, err := range []error{ErrNoOwnKeys, ErrNoDefaultVault, ErrNoGnuPGKey} {
		if !strings.Contains(err.Error(), "'secretvault ") {
			t.Errorf("%q lost the CLI's words", err)
		}
	}
}
