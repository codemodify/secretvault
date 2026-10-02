package svops

import (
	"fmt"
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
