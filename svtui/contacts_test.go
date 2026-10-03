package svtui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

func newPGP(t *testing.T, uid string) *svpgp.Key {
	t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 6, UserIDs: []string{uid}})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// publicKeyFile writes k's public key, armored, in the test's directory.
func (h *harness) publicKeyFile(name string, k *svpgp.Key) string {
	h.t.Helper()
	b, err := k.Public().Armor(false)
	if err != nil {
		h.t.Fatal(err)
	}
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func TestContactsAreAddedVerifiedCheckedAndRemoved(t *testing.T) {
	h := newHarness(t)
	alice := newPGP(t, "Alice Example <alice@example.org>")
	file := h.publicKeyFile("alice.asc", alice)
	fp := fmt.Sprintf("%X", alice.Fingerprint())
	h.start(Options{}, "")
	h.unlock()
	h.typeText("C")
	h.waitFor("Contacts · in personal")
	h.waitFor("No contacts")

	h.typeText("a")
	h.waitFor("Add a contact")
	h.typeText(file)
	h.tabs(3)
	h.typeText("met at FOSDEM")
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Added Alice Example with 1 key(s)")
	h.key(tcell.KeyEscape)
	h.waitFor("not verified")

	// Not verified yet: the verdict says so.
	h.typeText("t")
	h.waitFor("Check a signer")
	h.typeText(fp)
	h.tabs(2)
	h.typeText("alice@example.org")
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("unverified")
	h.waitFor("which you have not verified")
	h.key(tcell.KeyEscape)

	// Her keys; verify the one, in person, with the fingerprint as read out.
	h.key(tcell.KeyEnter)
	h.waitFor("met at FOSDEM")
	h.waitFor(svops.GroupFingerprint(fp))
	h.typeText("v")
	h.waitFor("Verify a key")
	h.tabs(5)
	h.key(tcell.KeyEnter)
	h.waitFor("verified in person")
	h.key(tcell.KeyEnter)
	h.waitFor("fingerprint compared in person on")
	h.key(tcell.KeyEscape)
	h.key(tcell.KeyEscape) // back to the list
	h.waitGone("met at FOSDEM")

	// Someone else's key for her address, seen in mail.
	mallory := newPGP(t, "Alice Example <alice@example.org>")
	h.typeText("s")
	h.waitFor("Record a key seen in mail")
	h.typeText(h.publicKeyFile("m.asc", mallory))
	h.tabs(1)
	h.typeText("alice@example.org")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("belongs to Alice Example's key")
	h.key(tcell.KeyEscape)
	h.waitFor("alice@example.org (from mail)")

	// Removed.
	selectWhere(h, func(c svrpc.Contact) bool { return c.Name == "Alice Example" })
	h.typeText("x")
	h.waitFor("Remove Alice Example")
	h.typeText("y")
	h.waitFor("Removed Alice Example")
}

func TestMyQRCodeAndAScannedOne(t *testing.T) {
	h := newHarness(t)
	h.unlockAdmin("")
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}}); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.menu("show my qr")
	h.waitFor("My QR code")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("For them to scan")
	h.waitFor("▀")
	uri := h.onceSecrets()
	if len(uri) != 1 || !strings.HasPrefix(uri[0], "secretvault-contact:") {
		t.Fatalf("the code's URI: %q", uri)
	}
	h.key(tcell.KeyEscape) // nothing shown once: it closes at once
	h.eventually("the code closing", func() bool { return h.u.once == nil })

	// A look-up, with no network: nothing found, and where it asked.
	h.typeText("C")
	h.waitFor("Contacts · in personal")
	h.typeText("l")
	h.waitFor("Look up keys")
	h.typeText("bob@example.org")
	h.tabs(5)
	h.key(tcell.KeyEnter)
	h.waitFor("No key found for bob@example.org")

	// A scanned code naming a key not here: nothing to verify.
	h.typeText("m")
	h.waitFor("Import keys")
	h.typeText("openpgp4fpr:" + strings.Repeat("AB", 32))
	h.tabs(5)
	h.key(tcell.KeyEnter)
	h.waitFor("Not found: openpgp")
	h.waitFor("Nothing was imported")
	h.key(tcell.KeyEscape)

	// Where contacts live.
	h.typeText("v")
	h.waitFor("Keep contacts in")
	h.key(tcell.KeyEnter)
	h.waitFor("Contacts are kept in vault personal now")
	h.key(tcell.KeyEscape)

	// Directories: added, listed, removed.
	h.menu("directories: add")
	h.waitFor("Directories")
	h.typeText("a")
	h.waitFor("Add a directory")
	h.typeText("corp")
	h.tabs(1)
	h.typeText("ldaps://ldap.example.com")
	h.tabs(1)
	h.typeText("dc=example,dc=com")
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("Lookups of an address now ask corp first")
	h.waitFor("anonymous")
	h.typeText("x")
	h.waitFor("Remove the directory corp?")
	h.typeText("y")
	h.waitFor("None (a adds one)")
}
