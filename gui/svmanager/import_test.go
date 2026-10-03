package svmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/a11y/a11ytest"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
)

// File › Import…, in steps: where the passwords are now, how to export
// them from there (svops.ImportSources' words), the preview, the import,
// and the offer to delete an export that held them in the clear. Every
// file is the test's own: no browser's profile is read.

// firefoxCSV is what Firefox's about:logins › Export Passwords… writes.
const firefoxCSV = `"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"
"https://www.mozilla.org","ada","moz-pass",,"https://www.mozilla.org","{0b5f8b1c}","1600000000000","1600000000000","1600000000000"
"chrome://FirefoxAccounts","sync","ignored",,,"{1}","1","1","1"
"https://intranet.example:8443","ada","basic-pass","Intranet",,"{2}","1","1","1"
`

// sourceIndex is where the source called name is in the list.
func sourceIndex(t *testing.T, name string) int {
	t.Helper()
	for i, s := range svops.ImportSources {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no source %s", name)
	return -1
}

// importFrom goes through the import's steps as a person does: the
// source chosen, Next, the file chosen in the file dialog, the folder
// under More options, and Preview.
func (h *harness) importFrom(source, file, folder string) {
	h.t.Helper()
	h.m.importItems()
	h.pump()
	h.waitText(importQuestion)
	h.choose(importQuestion, sourceIndex(h.t, source))
	h.press("Next")
	h.waitText("Choose the export file…")
	h.picks = append(h.picks, file)
	h.press("Choose the export file…")
	if folder != "" {
		h.expand("More options")
		h.fill("Put them in a folder", folder)
	}
	h.press("Preview")
}

// expand opens the section of the dialog up titled title.
func (h *harness) expand(title string) {
	h.t.Helper()
	e := find(h.overlay(), func(e *widgets.Expander) bool { return e.Title == title })
	if e == nil {
		h.t.Fatalf("no section %q; the window says:\n%s", title, h.text())
	}
	if !e.Expanded {
		h.win().ClickComponent(e)
		h.pump()
	}
	if !e.Expanded {
		h.t.Fatalf("section %q did not open", title)
	}
}

// field shown reports whether the dialog up shows a field named name.
func (h *harness) fieldShown(name string) bool {
	root := h.overlay()
	if f := find(root, func(c *widgets.TextField) bool { return c.AccessibleName() == name }); f != nil {
		return shown(f)
	}
	if f := find(root, func(c *widgets.SecretField) bool { return c.AccessibleName() == name }); f != nil {
		return shown(f)
	}
	return false
}

func TestImportAsksWhereThePasswordsAreThenShowsHowToExportThem(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.importItems()
	h.pump()
	h.waitText(importQuestion)
	list := named[*widgets.RadioGroup](h, h.overlay(), importQuestion)
	if list.Selected() != 0 || list.Buttons()[0].Text != "Firefox" || len(list.Buttons()) != len(svops.ImportSources) {
		t.Fatalf("the list: Firefox is not first and chosen, or a source is missing")
	}
	for _, s := range svops.ImportSources {
		if !strings.Contains(h.text(), s.Label) {
			t.Errorf("%s is not offered", s.Label)
		}
	}
	a11ytest.Audit(t, "the import's first step", h.win().AccessibleTree())

	// Firefox: its steps, the file, and nothing an encrypted export needs.
	h.press("Next")
	h.waitText("Import from Firefox")
	for _, step := range svops.ImportSources[0].NumberedSteps() {
		if !strings.Contains(h.text(), step) {
			t.Errorf("step %q is not shown", step)
		}
	}
	if !strings.Contains(h.text(), "about:logins") || !strings.Contains(h.text(), "unencrypted") {
		t.Errorf("Firefox's steps:\n%s", h.text())
	}
	if b := button(h.overlay(), "Choose the export file…"); b == nil || h.win().Focus() != b {
		t.Fatalf("the keyboard does not start on Choose the export file…: %T", h.win().Focus())
	}
	for _, f := range []string{"File password", "Master password", "Aegis password", "Key file"} {
		if h.fieldShown(f) {
			t.Errorf("Firefox's export needs no %s, but it is asked for", f)
		}
	}
	if h.fieldShown("Put them in a folder") {
		t.Error("the folder is shown before More options is opened")
	}
	h.expand("More options")
	if !h.fieldShown("Put them in a folder") || find(h.overlay(), func(c *widgets.Checkbox) bool { return strings.HasPrefix(c.Text, "Replace items that exist") }) == nil {
		t.Errorf("More options holds the folder and replacing:\n%s", h.text())
	}
	a11ytest.Audit(t, "the import's second step", h.win().AccessibleTree())
	h.press("Preview")
	if p := h.problem(); p != "Choose the export file first." {
		t.Errorf("Preview with no file: %q", p)
	}

	// Back to the list, where Firefox is still chosen; then Bitwarden,
	// whose export may be password-protected.
	h.press("Back")
	h.waitText(importQuestion)
	if named[*widgets.RadioGroup](h, h.overlay(), importQuestion).Selected() != 0 {
		t.Error("Back lost the choice")
	}
	h.choose(importQuestion, sourceIndex(t, "bitwarden"))
	h.press("Next")
	h.waitText("Import from Bitwarden")
	if !strings.Contains(h.text(), "Tools › Export vault") || !h.fieldShown("File password") || h.fieldShown("Key file") {
		t.Errorf("Bitwarden's step:\n%s", h.text())
	}

	// KeePass: the database itself, its master password and key file.
	h.press("Back")
	h.choose(importQuestion, sourceIndex(t, "keepass"))
	h.press("Next")
	h.waitText("Import from KeePass or KeePassXC")
	if !h.fieldShown("Master password") || !h.fieldShown("Key file") || strings.Contains(h.text(), "unencrypted") {
		t.Errorf("KeePass's step:\n%s", h.text())
	}
	h.escape()
	if h.overlay() != nil {
		t.Error("Escape left the import up")
	}
}

func TestAFirefoxExportIsImportedAndThenDeleted(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	in := filepath.Join(h.dir, "logins.csv")
	if err := os.WriteFile(in, []byte(firefoxCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	h.importFrom("firefox", in, "")
	h.waitText("2 items from logins.csv will be added to vault personal.")
	h.expand("Show details")
	if !strings.Contains(h.text(), "www.mozilla.org") || !strings.Contains(h.text(), "intranet.example") {
		t.Fatalf("the preview:\n%s", h.text())
	}
	if strings.Contains(h.text(), "moz-pass") {
		t.Fatal("the preview shows a password")
	}
	h.press("Import 2 items")
	h.waitText("2 items were imported.")
	h.press("Close")
	h.waitText("Delete logins.csv?")
	if !strings.Contains(h.text(), "unencrypted") || strings.Contains(strings.ToLower(h.text()), "secure") {
		t.Errorf("the offer:\n%s", h.text())
	}
	h.press("Delete the file")
	h.said("Deleted " + in)
	if _, err := os.Lstat(in); !os.IsNotExist(err) {
		t.Fatalf("the export is still there: %v", err)
	}
	if e, err := h.get("www.mozilla.org"); err != nil || field(e, "password") != "moz-pass" {
		t.Fatalf("imported %v, %v", e.Item, err)
	}
}

// An encrypted export asks for its password where it is chosen, and is
// not offered for deletion: it never held the secrets in the clear.
func TestAnEncryptedExportIsNotOfferedForDeletion(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	data, err := os.ReadFile(filepath.Join("..", "..", "svimport", "testdata", "bitwarden-encrypted-pbkdf2.json"))
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(h.dir, "bitwarden_export.json")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	h.importFrom("bitwarden", in, "bw")
	if p := h.failed(); !strings.Contains(p, "is encrypted: type its file password") {
		t.Fatalf("no password: %q", p)
	}
	h.fill("File password", pass)
	h.press("Preview")
	h.waitText("2 items from bitwarden_export.json will be added")
	h.press("Import 2 items")
	h.waitText("2 items were imported.")
	h.press("Close")
	h.idle()
	if h.overlay() != nil {
		t.Fatalf("something is up after the import:\n%s", h.text())
	}
	if _, err := os.Stat(in); err != nil {
		t.Fatal(err)
	}
}
