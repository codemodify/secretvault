package svtui

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// unlockAdmin unlocks the vault for the admin connection, to set things
// up as the CLI would; lockAll locks every vault again after.
func (h *harness) unlockAdmin(vault string) {
	h.t.Helper()
	if _, err := h.admin.Unlock(h.ctx(), vault, &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) lockAll() {
	h.t.Helper()
	if err := h.admin.Lock(h.ctx(), "", true); err != nil {
		h.t.Fatal(err)
	}
}

func TestTheHistorySaysWhoSignedAndRestoresARevision(t *testing.T) {
	h := newHarness(t)
	h.unlockAdmin("")
	if _, err := h.admin.Put(h.ctx(), "", login("web/gitlab.com", "ada", "the newer one")); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.open("web/gitlab.com")
	h.typeText("h")
	h.waitFor("History of web/gitlab.com")
	h.waitFor("SIGNED BY")
	h.waitFor("(this device)")
	h.waitFor("current")
	h.key(tcell.KeyDown) // the older revision
	h.typeText("R")
	h.waitFor("current again?")
	h.typeText("y")
	h.waitFor("Restored web/gitlab.com")
	if e, err := h.get("web/gitlab.com"); err != nil || field(e, "password") != "gitlab-pass-42" {
		t.Fatalf("after restoring: %v %q", err, field(e, "password"))
	}
	h.key(tcell.KeyEscape)
	h.waitGone("History of")
}

func TestAConflictIsSettledByKeepingOneVersion(t *testing.T) {
	h := newHarness(t)
	h.unlockAdmin("")
	vs := h.vaults()
	// A second handle on the vault's folder, as another device would
	// write it: both change the item without seeing the other's change.
	store, err := svstore.OpenDir(vs["personal"].Path)
	if err != nil {
		t.Fatal(err)
	}
	other, err := svcore.Open(store, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Unlock(svcore.Passphrase([]byte(pass))); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Put(h.ctx(), "", login("web/gitlab.com", "ada", "from here")); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Put(svcore.Item{Kind: "login", Name: "web/gitlab.com", Fields: []svcore.Field{
		{Name: "username", Type: svcore.FieldText, Value: []byte("ada")},
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte("from there")},
	}}); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("gitlab.com !")
	h.open("web/gitlab.com")
	h.menu("resolve")
	h.waitFor("Resolve web/gitlab.com")
	h.waitFor("changed on two devices at once")
	h.waitFor("(shown now)")
	// Keep the version not shown now.
	cur, err := h.get("web/gitlab.com")
	if err != nil {
		t.Fatal(err)
	}
	want := "from here"
	if field(cur, "password") == "from here" {
		want = "from there"
	}
	h.do(func() {
		for i, e := range h.u.history {
			if field(e, "password") == want {
				h.u.panels[pagePanel].t.Select(i+1, 0)
			}
		}
	})
	h.key(tcell.KeyEnter)
	h.waitFor("(read-only)")
	h.typeText("r")
	h.waitFor(want)
	h.key(tcell.KeyEscape)
	h.waitGone("(read-only)")
	h.typeText("k")
	h.waitFor("on every device?")
	h.typeText("y")
	h.waitFor("the conflict is settled")
	e, err := h.get("web/gitlab.com")
	if err != nil || field(e, "password") != want || len(e.Conflicts) != 0 {
		t.Fatalf("after keeping %q: %q, conflicts %v, %v", want, field(e, "password"), e.Conflicts, err)
	}
	h.waitFor("No conflict")
}

func TestDeletedItemsComeBack(t *testing.T) {
	h := newHarness(t)
	h.unlockAdmin("")
	if err := h.admin.Delete(h.ctx(), "", "mail/fastmail"); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.typeText("R")
	h.waitFor("Deleted items · personal")
	h.waitFor("mail/fastmail")
	h.key(tcell.KeyEnter)
	h.waitFor("Bring mail/fastmail back")
	h.typeText("y")
	h.waitFor("Restored mail/fastmail")
	h.waitFor("Nothing deleted")
	if e, err := h.get("mail/fastmail"); err != nil || field(e, "password") != "fastmail-secret" {
		t.Fatalf("after restoring: %v", err)
	}
}

func TestAnItemsFilesAreAttachedSavedAndRemoved(t *testing.T) {
	h := newHarness(t)
	scan := filepath.Join(h.dir, "passport.pdf")
	contents := bytes.Repeat([]byte("%PDF-1.7 scan "), 500)
	if err := os.WriteFile(scan, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.open("web/github.com")
	h.typeText("f")
	h.waitFor("Files of web/github.com")
	h.waitFor("No files")
	h.typeText("a")
	h.waitFor("Attach a file to web/github.com")
	h.typeText(scan)
	h.tabs(3)
	h.key(tcell.KeyEnter)
	h.waitFor("Attached passport.pdf (7000 bytes)")
	h.waitFor("application/pdf")

	out := filepath.Join(h.dir, "out.pdf")
	h.typeText("s")
	h.waitFor("Save passport.pdf")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(out)
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("Wrote " + out)
	if got, _ := os.ReadFile(out); !bytes.Equal(got, contents) {
		t.Fatal("the file came back different")
	}
	// Not over a file that is there, unless asked.
	h.typeText("s")
	h.waitFor("Save passport.pdf")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText(out)
	h.tabs(2)
	h.key(tcell.KeyEnter)
	h.waitFor("tick Replace")
	h.key(tcell.KeyEscape)
	h.waitGone("Save passport.pdf")

	h.typeText("x")
	h.waitFor("Remove passport.pdf from web/github.com?")
	h.typeText("y")
	h.waitFor("No files")
	if e, _ := h.get("web/github.com"); len(e.Item.Files) != 0 {
		t.Fatalf("still attached: %+v", e.Item.Files)
	}
}

const chromeCSV = "name,url,username,password,note\n" +
	"github.com,https://github.com/login,ada,gh-p4ss,work account\n" +
	"example.org,https://example.org,ada,ex-p4ss,\n"

func TestImportShowsTheNamesFirstThenStores(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(h.dir, "Chrome Passwords.csv")
	if err := os.WriteFile(file, []byte(chromeCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	h.lockAll()
	h.start(Options{}, "")
	h.unlock()
	h.typeText("I")
	h.waitFor("Import into personal")
	h.typeText(file)
	h.tabs(2)
	h.typeText("imported/chrome")
	h.tabs(4) // replace, passphrase, key file, Read it
	h.key(tcell.KeyEnter)
	h.waitFor("Reading " + file + " as csv")
	h.waitFor("2 items to import into personal")
	h.waitFor("imported/chrome/github.com")
	if _, err := h.get("imported/chrome/github.com"); err == nil {
		t.Fatal("something was stored before the plan was accepted")
	}
	h.key(tcell.KeyTab)
	h.key(tcell.KeyTab) // Cancel, then Import
	h.key(tcell.KeyEnter)
	h.waitFor("Imported 2 items, skipped 0")
	if e, err := h.get("imported/chrome/github.com"); err != nil || field(e, "password") != "gh-p4ss" {
		t.Fatalf("imported: %v %+v", err, e.Item)
	}
}

func TestExportWritesANewKeePassFile(t *testing.T) {
	h := newHarness(t)
	const filePass = "a file passphrase"
	h.start(Options{}, filePass)
	h.unlock()
	out := filepath.Join(h.dir, "out.kdbx")
	h.typeText("X")
	h.waitFor("Export from personal")
	h.tabs(1) // kdbx is chosen already
	h.typeText(out)
	h.tabs(2)
	h.typeText(filePass)
	h.tabs(1)
	h.typeText(filePass)
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("Exported 4 items to " + out)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svimport.Import(svimport.FormatKDBX, data, svimport.Options{Passphrase: []byte(filePass)})
	if err != nil || len(res.Items) != 4 {
		t.Fatalf("reading the export back: %v", err)
	}
	if h.leaked.Load() {
		t.Fatal("the file's passphrase was drawn")
	}
	// Never over a file that is there.
	h.typeText("X")
	h.waitFor("Export from personal")
	h.tabs(1)
	h.typeText(out)
	h.tabs(4)
	h.key(tcell.KeyEnter)
	h.waitFor("already exists")
}
