package svtui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svops"
)

// I, in steps: where the passwords are now, how to export them from
// there (svops.ImportSources' words), the names, the import, and the offer
// to delete an export that held them in the clear. Every file is the
// test's own: no browser's profile is read.

// firefoxCSV is what Firefox's about:logins › Export Passwords… writes.
const firefoxCSV = `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://www.mozilla.org","ada","moz-pass",,"https://www.mozilla.org","{0b5f8b1c}","1600000000000","1600000000000","1600000000000"
"chrome://FirefoxAccounts","sync","ignored",,,"{1}","1","1","1"
"https://intranet.example:8443","ada","basic-pass","Intranet",,"{2}","1","1","1"
`

func TestImportFromFirefoxShowsItsStepsStoresAndDeletesTheFile(t *testing.T) {
	h := newHarness(t)
	file := h.file("logins.csv", firefoxCSV)
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.typeText("I")
	h.waitFor("Where are your passwords now?")
	for _, s := range svops.ImportSources {
		h.waitFor(s.Label)
	}
	h.key(tcell.KeyEnter) // Firefox, the first
	h.waitFor("What to do in Firefox")
	h.waitFor("about:logins")
	h.waitFor("unencrypted")
	screen := h.text()
	for _, f := range []string{"File password", "Master password", "Aegis password", "Key file"} {
		if strings.Contains(screen, f) {
			t.Errorf("Firefox's export needs no %s, but it is asked for:\n%s", f, screen)
		}
	}
	h.typeText(file)
	h.tabs(2) // replace, Read it
	h.key(tcell.KeyEnter)
	h.waitForWords("2 items from logins.csv will be added to vault personal")
	h.details()
	h.waitFor("www.mozilla.org")
	if strings.Contains(h.text(), "moz-pass") {
		t.Fatal("the plan shows a password")
	}
	h.key(tcell.KeyBacktab) // Import 2 items
	h.key(tcell.KeyEnter)
	h.waitFor("2 items were imported.")
	h.waitFor("Delete logins.csv?")
	if s := h.text(); !strings.Contains(s, "unencrypted") || strings.Contains(strings.ToLower(s), "secure") {
		t.Errorf("the offer:\n%s", s)
	}
	h.typeText("y")
	h.waitSaid("Deleted " + file)
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatalf("the export is still there: %v", err)
	}
	if e, err := h.get("www.mozilla.org"); err != nil || field(e, "password") != "moz-pass" {
		t.Fatalf("imported: %v %+v", err, e.Item)
	}
}

// Each source asks only for what its export needs, and Back goes back to
// the list; an encrypted export is not offered for deletion.
func TestImportAsksOnlyWhatTheSourceNeeds(t *testing.T) {
	h := newHarness(t)
	data, err := os.ReadFile(filepath.Join("..", "svimport", "testdata", "bitwarden-encrypted-pbkdf2.json"))
	if err != nil {
		t.Fatal(err)
	}
	file := h.file("bitwarden_export.json", string(data))
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()

	// KeePass: the database's master password and its key file.
	h.typeText("I")
	h.waitFor("Where are your passwords now?")
	for range 5 {
		h.key(tcell.KeyDown)
	}
	h.key(tcell.KeyEnter)
	h.waitFor("What to do in KeePass or KeePassXC")
	h.waitFor("Master password")
	h.waitFor("Key file")
	if strings.Contains(h.text(), "unencrypted") {
		t.Error("a KeePass database is said to be unencrypted")
	}
	h.tabs(6) // master password, key file, replace, Read it, Cancel, Back
	h.key(tcell.KeyEnter)
	h.waitFor("Where are your passwords now?")
	h.waitGone("What to do in KeePass")

	// Bitwarden, from the list Back went to (still at KeePass): its
	// file's password, and no key file.
	for range 2 {
		h.key(tcell.KeyUp)
	}
	h.key(tcell.KeyEnter)
	h.waitFor("What to do in Bitwarden")
	h.waitFor("File password")
	if strings.Contains(h.text(), "Key file") {
		t.Error("Bitwarden asks for a key file")
	}
	h.typeText(file)
	h.tabs(1)
	h.typeText(pass)
	h.tabs(2) // replace, Read it
	h.key(tcell.KeyEnter)
	h.waitForWords("2 items from bitwarden_export.json will be added to vault personal")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("2 items were imported.")
	if strings.Contains(h.text(), "Delete bitwarden_export.json?") {
		t.Fatal("an encrypted export was offered for deletion")
	}
	h.key(tcell.KeyEscape)
	h.waitGone("2 items were imported.") // the report; the status line says it otherwise
	if strings.Contains(h.text(), "Delete bitwarden_export.json?") {
		t.Fatal("an encrypted export was offered for deletion")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
}
