package svmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

func svrpcPGP(name, email string) svrpc.PGPGenerateParams {
	return svrpc.PGPGenerateParams{Name: name, Emails: []string{email}, Version: 4}
}

// publicKeyFile writes someone's new OpenPGP public key to a file, and
// returns the file and the key's fingerprint.
func (h *harness) publicKeyFile(name, uid string) (string, string) {
	h.t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{uid}})
	if err != nil {
		h.t.Fatal(err)
	}
	b, err := k.Public().Armor(false)
	if err != nil {
		h.t.Fatal(err)
	}
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p, fmt.Sprintf("%X", k.Fingerprint())
}

func TestContactsAreAddedVerifiedAndRemoved(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	file, fp := h.publicKeyFile("alice.asc", "Alice Example <alice@example.org>")
	h.m.showContactsPage(tabPeople)
	h.waitFor("the contacts page", h.m.showingVaultPage)
	h.idle()
	p := h.m.cpage
	if !strings.Contains(h.text(), "No contacts yet.") {
		t.Fatalf("no contacts yet:\n%s", h.text())
	}
	h.pressOn("Add…")
	h.fill("Key files", file)
	h.fill("Notes", "met at FOSDEM")
	h.press("Add the contact")
	h.waitText("Added Alice Example with 1 key.")
	h.press("Close")
	h.idle()
	if len(p.list) != 1 || p.shown == nil || p.shown.Name != "Alice Example" {
		t.Fatalf("listed %+v, shown %+v", p.list, p.shown)
	}
	if !strings.Contains(h.text(), "met at FOSDEM") || !strings.Contains(h.text(), "not verified") {
		t.Fatalf("the contact:\n%s", h.text())
	}

	// Verifying takes the fingerprint as it was compared.
	h.pressOn("Verify…")
	h.fill("Fingerprint", "0000 0000")
	h.press("Mark as verified")
	if !strings.Contains(h.problem(), "not this key's fingerprint") {
		t.Fatalf("a wrong fingerprint: %q", h.problem())
	}
	h.fill("Fingerprint", fp)
	h.press("Mark as verified")
	h.said("verified in person")
	h.idle()

	// The search narrows the list.
	search := find(h.m.ui.main, func(f *widgets.TextField) bool { return f.AccessibleName() == "Search the contacts" })
	h.win().FocusOn(search)
	h.win().Type("nobody")
	search.OnSubmit(search.Text)
	h.idle()
	if len(p.list) != 0 {
		t.Fatalf("the search found %+v", p.list)
	}
	search = find(h.m.ui.main, func(f *widgets.TextField) bool { return f.AccessibleName() == "Search the contacts" })
	search.SetText("")
	search.OnSubmit("")
	h.idle()

	// The signer's verdict.
	h.m.checkSigner()
	h.pump()
	h.fill("Fingerprint", fp)
	h.fill("From", "alice@example.org")
	h.press("Check")
	h.waitText("The signer")
	if !strings.Contains(h.text(), "in person") {
		t.Fatalf("the verdict:\n%s", h.text())
	}
	h.press("Close")

	// A key seen in mail, from someone new.
	bob, _ := h.publicKeyFile("bob.asc", "Bob <bob@example.org>")
	h.m.recordSeen()
	h.pump()
	h.fill("Key", bob)
	h.fill("From", "bob@example.org")
	h.fill("Received", "2026-09-01")
	h.press("Record")
	h.waitText("A new key:")
	h.press("Close")
	h.idle()
	if len(p.list) != 2 {
		t.Fatalf("after the sighting: %+v", p.list)
	}

	// Removing the contact.
	for i, c := range p.list {
		if c.Name == "Alice Example" {
			p.ctable.Selected = i
			h.m.showContact(p, i)
		}
	}
	h.idle()
	h.pressOn("Remove…")
	h.press("Remove")
	h.said("Removed Alice Example.")
	h.idle()
	if len(p.list) != 1 {
		t.Fatalf("after removing: %+v", p.list)
	}

	// Import: many keys from a file.
	carol, _ := h.publicKeyFile("carol.asc", "Carol <carol@example.org>")
	h.m.importContacts()
	h.pump()
	h.fill("File or code", carol)
	h.press("Import")
	h.waitText("Added: openpgp")
	h.press("Close")
	h.idle()
	if len(p.list) != 2 {
		t.Fatalf("after importing: %+v", p.list)
	}
}

func TestMyQRCodeAndContactsVaultAndDirectories(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.showMyQR()
	h.idle()
	h.press("Show the code")
	if got := h.failed(); !strings.Contains(got, "no key of yours") || strings.Contains(got, "--key") {
		t.Fatalf("no keys: %q", got)
	}
	h.press("Cancel")
	h.prove()
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpcPGP("Ada", "ada@example.org")); err != nil {
		t.Fatal(err)
	}
	h.m.showMyQR()
	h.idle()
	h.press("Show the code")
	// The code and its text in one dialog.
	h.waitText("QR code of the contact code")
	code := find(h.overlay(), func(*qrView) bool { return true })
	if code == nil || !strings.Contains(h.text(), "secretvault-contact:") || len(h.win().Overlays()) != 1 {
		t.Fatalf("no QR code, or not beside its text, in one dialog (%d up)", len(h.win().Overlays()))
	}
	h.press("Close")
	if h.overlay() != nil || code.code != nil {
		t.Fatal("the contact code's dialog stayed, or its QR code outlived it")
	}

	h.m.contactsVault()
	h.waitText("Contacts are kept in vault personal now.")
	h.press("Keep contacts there")
	h.said("Contacts are kept in vault personal now.")

	h.m.showContactsPage(tabDirectories)
	h.waitFor("the contacts page", h.m.showingVaultPage)
	h.idle()
	h.pressOn("Add…")
	h.fill("Name", "example")
	h.fill("Address", "ldaps://ldap.example.com")
	h.fill("People under", "dc=example,dc=com")
	h.press("Add the directory")
	h.said("Lookups of an address now ask example first")
	h.idle()
	if len(h.m.cpage.dirs) != 1 {
		t.Fatalf("directories: %+v", h.m.cpage.dirs)
	}
	h.pressOn("Remove…")
	h.press("Remove the directory")
	h.said("Removed directory example.")

	// Looking up asks no network here: the daemon says what failed.
	h.m.lookupContact()
	h.waitText("Look up keys")
	h.fill("Address or fingerprint", "nobody@example.org")
	h.press("Look up")
	if got := h.failed(); !strings.Contains(got, "No key found for nobody@example.org") || !strings.Contains(got, "no network in tests") {
		t.Fatalf("the lookup said %q", got)
	}
}
