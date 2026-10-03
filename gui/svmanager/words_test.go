package svmanager

import (
	"fmt"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// What the daemon and svops say in the CLI's words is said here in this
// program's: a command becomes where the same is done here, and advice
// to use a flag goes.
func TestMessagesAreSaidInThisProgramsWords(t *testing.T) {
	for in, want := range map[string]string{
		"keyslot 1a2b is emergency access (grant 3c4d): end it with 'secretvault emergency revoke 3c4d', with --rotate to cut the trustee off": "end it with Vault › Sharing › Emergency access › Revoke… (with the key rotated)",
		"revoke it and rotate the vault key: 'secretvault --vault personal emergency revoke 3c4d --rotate'.":                                   "rotate the vault key: Vault › Sharing › Emergency access › Revoke… (with the key rotated).",
		"it is yours: 'secretvault emergency open ada --identity FILE'.":                                                                       "it is yours: File › Emergency access › Open the vault….",
		"create one with 'secretvault init'":              "create one with File › New vault…",
		"GnuPG's gpg is not on PATH (name it with --gpg)": "GnuPG's gpg is not on PATH",
		"an unknown 'secretvault frobnicate' stays":       "an unknown 'secretvault frobnicate' stays",
	} {
		if got := guiWords(in); !strings.Contains(got, want) {
			t.Errorf("guiWords(%q) = %q, want it to hold %q", in, got, want)
		}
	}
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	for _, err := range []error{
		svops.ErrNoOwnKeys, svops.ErrNoDefaultVault, svops.ErrNoGnuPGKey, svops.ErrNoCLI,
		fmt.Errorf("x already exists; pick another name with --item (%w)", svops.ErrKeyExists),
		fmt.Errorf("f does not hold exactly one secret key (%w)", svops.ErrNotOneSecretKey),
		fmt.Errorf("i has no field %q (%w)", "age_identity", svops.ErrNoAgeIdentity),
		fmt.Errorf("the browsers were set up for /x; %w", svops.ErrUninstallFirst),
		&svrpc.Error{Code: svrpc.CodeFailed, Message: "vault \"p\" does not sync: 'secretvault sync setup URL' first"},
	} {
		if got := h.m.describe(err); strings.Contains(got, "'secretvault") || strings.Contains(got, "--") {
			t.Errorf("%v is said as %q", err, got)
		}
	}
}

// A recipient typed is shared with, never the first contact instead; a
// contact and a recipient both given are refused.
func TestSharingTakesTheRecipientTyped(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	rcpt, _, err := svops.NewIdentity("modern", "identity")
	if err != nil {
		t.Fatal(err)
	}
	h.prove()
	other, _, _ := svops.NewIdentity("modern", "identity")
	if _, err := h.admin.AddContact(h.ctx(), svrpc.ContactAddParams{Name: "Carol", Keys: [][]byte{[]byte(other)}}); err != nil {
		t.Fatal(err)
	}
	p := h.openVaultPage(tabSharing)
	h.pressOn("Share with…")
	h.waitText("Share vault personal")
	h.fill("Their public key", rcpt)
	h.press("Share the vault")
	h.said("Shared vault personal")
	h.idle()
	if len(p.shared) != 1 || p.shared[0].Recipient != rcpt {
		t.Fatalf("shared with %+v, not the recipient typed", p.shared)
	}
	h.pressOn("Share with…")
	h.waitText("Share vault personal")
	h.choose("With", 1)
	h.fill("Their public key", rcpt)
	h.press("Share the vault")
	if got := h.problem(); !strings.Contains(got, "not both") {
		t.Fatalf("a contact and a recipient both: %q", got)
	}
}
