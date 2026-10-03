package svmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svrpc"
)

func TestDeletedItemsAreListedAndRestored(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	if err := h.admin.Delete(h.ctx(), "", "web/gitlab.com"); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the item gone", func() bool { return h.m.entry("web/gitlab.com") == nil })
	h.m.showDeleted()
	h.waitText("Items deleted from vault personal")
	if !strings.Contains(h.text(), "web/gitlab.com") {
		t.Fatalf("the deleted item is not listed:\n%s", h.text())
	}
	h.press("Restore")
	h.said("Restored web/gitlab.com")
	h.waitFor("the item back", func() bool { return h.m.entry("web/gitlab.com") != nil })
	if e, err := h.get("web/gitlab.com"); err != nil || field(e, "password") != "gitlab-pass-42" {
		t.Fatalf("restored %v, %v", e.Item, err)
	}
}

func TestARevisionIsMadeCurrentAndAConflictSettled(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	gh, err := h.get("web/github.com")
	if err != nil {
		t.Fatal(err)
	}
	gh.Item.Fields[1].Value = []byte("changed")
	if _, err := h.admin.Put(h.ctx(), "", gh.Item); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the change", func() bool { return true })
	h.selectItem("web/github.com")
	h.m.showHistory()
	h.waitFor("the history", h.m.showingHistory)
	h.idle()
	h.m.hist.table.Selected = 1
	h.m.openRevision(1)
	h.pump()
	h.click(h.win(), button(h.m.ui.pane, "Make this revision current…"))
	h.press("Make current")
	h.said("Restored web/github.com")
	if e, _ := h.get("web/github.com"); field(e, "password") != "hunter2-github" {
		t.Fatalf("the password is %q", field(e, "password"))
	}

	// A conflict: the other version is kept, on every device.
	c := newHarness(t)
	c.addConflicted()
	c.start(Options{Vault: "shared"})
	c.waitText("Vault shared is locked")
	c.unlockAgain()
	c.selectItem("site")
	c.m.showHistory()
	c.waitFor("the history", c.m.showingHistory)
	c.idle()
	for i, e := range c.m.hist.entries {
		if c.m.hist.heads[e.Rev] {
			c.m.hist.table.Selected = i
			c.m.openRevision(i)
		}
	}
	c.pump()
	c.click(c.win(), button(c.m.ui.pane, "Keep this version on every device…"))
	c.press("Keep it")
	c.said("the conflict is settled")
	c.prove2("shared")
	e, err := c.admin.Get(c.ctx(), "shared", "site")
	if err != nil || len(e.Conflicts) != 0 || field(e, "password") != "from laptop" {
		t.Fatalf("after keeping: %q, conflicts %v, %v", field(e, "password"), e.Conflicts, err)
	}
}

// prove2 presents the passphrase of vault on the admin connection.
func (h *harness) prove2(vault string) {
	h.t.Helper()
	if _, err := h.admin.Unlock(h.ctx(), vault, &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
}

func TestAReferenceIsCopied(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	h.m.copyReference()
	h.pump()
	h.choose("To", 2) // the field password
	h.press("Copy")
	if got := h.clip.last(); got == nil || got.text != "sv://personal/web/github.com#password" {
		t.Fatalf("copied %+v", got)
	}
	h.m.copyReference()
	h.pump()
	h.tick("Name the vault", false)
	h.press("Copy")
	if got := h.clip.last(); got.text != "sv://-/web/github.com" {
		t.Fatalf("copied %q", got.text)
	}
}

const chromeCSV = "name,url,username,password,note\n" +
	"github.com,https://github.com/login,ada,gh-p4ss,work account\n" +
	"example.org,https://example.org,ada,ex-p4ss,\n"

func TestImportShowsWhatItWouldMakeAndExportWritesANewFile(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	in := filepath.Join(h.dir, "Chrome Passwords.csv")
	if err := os.WriteFile(in, []byte(chromeCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	h.importFrom("chrome", in, "imported/chrome")
	h.waitText("Chrome Passwords.csv holds 2 items to import into vault personal.")
	if !strings.Contains(h.text(), "imported/chrome/github.com") {
		t.Fatalf("the preview:\n%s", h.text())
	}
	if h.m.entry("imported/chrome/github.com") != nil {
		t.Fatal("the preview stored something")
	}
	h.press("Import")
	h.waitText("Imported 2 items, skipped 0")
	h.press("Close")
	h.waitFor("the items", func() bool { return h.m.entry("imported/chrome/example.org") != nil })
	// The file held them in the clear: deleting it is offered, and
	// declined here.
	h.waitText("Delete Chrome Passwords.csv?")
	h.press("Keep it")
	if _, err := os.Stat(in); err != nil {
		t.Fatalf("kept, but: %v", err)
	}

	// Again: what exists is skipped, in this program's words.
	h.importFrom("chrome", in, "imported/chrome")
	h.waitText("2 items to import")
	h.press("Import")
	h.waitText("Imported 0 items, skipped 2")
	if !strings.Contains(h.text(), "Replace items that exist replaces it") || strings.Contains(h.text(), "--overwrite") {
		t.Fatalf("the warnings:\n%s", h.text())
	}
	h.press("Close")
	h.waitText("Delete Chrome Passwords.csv?")
	h.escape()
	if _, err := os.Stat(in); err != nil {
		t.Fatalf("Escape deleted it: %v", err)
	}

	// Export, to KeePass: a new file, under a passphrase.
	out := filepath.Join(h.dir, "out.kdbx")
	h.m.exportItems()
	h.pump()
	h.fill("File", out)
	h.fill("Its passphrase", "export passphrase 1")
	h.fill("Repeat", "export passphrase 1")
	h.press("Export")
	h.said("Exported 6 items to " + out)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svimport.Import(svimport.FormatKDBX, data, svimport.Options{Passphrase: []byte("export passphrase 1")})
	if err != nil || len(res.Items) != 6 {
		t.Fatalf("the export reads back as %v, %v", res, err)
	}
	h.m.exportItems()
	h.pump()
	h.fill("File", out)
	h.press("Export")
	if !strings.Contains(h.problem(), "already exists") {
		t.Fatalf("an export over a file: %q", h.problem())
	}
}
