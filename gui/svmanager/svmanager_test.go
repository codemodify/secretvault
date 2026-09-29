package svmanager

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/a11y/a11ytest"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// shaped reports whether the look's faces have shaped (and so cached)
// text holding s: what painting s as a string would leave behind.
func shaped(h *harness, s string) bool {
	lk := h.win().Look()
	for _, f := range []*style.Font{lk.Font(), lk.MonoFont(), lk.TitleFont(), lk.MutedFont()} {
		for _, k := range style.ShapeCacheKeysForTest(f) {
			if strings.Contains(k, s) {
				h.t.Logf("shaped: %q", k)
				return true
			}
		}
	}
	return false
}

func TestUnlockingAsksForThePassphraseInItsOwnWindow(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	if !strings.Contains(h.text(), "personal: locked") {
		t.Fatalf("the status bar does not say the vault is locked:\n%s", h.text())
	}

	h.win().Press(platform.KeyU, platform.ModCtrl)
	d := h.asking()
	if d.win == h.win() || d.win.Title() != "Unlock vault personal" {
		t.Fatalf("the question is not in a window of its own: %q", d.win.Title())
	}
	if s := windowText(d.win); !strings.Contains(s, `Enter the passphrase of vault "personal"`) {
		t.Fatalf("the dialog says:\n%s", s)
	}
	field := d.fields[0]
	if d.win.Focus() != field {
		t.Fatalf("the passphrase field does not have the keyboard: %T", d.win.Focus())
	}
	d.win.Type("not the passphrase")
	if s := windowText(d.win); strings.Contains(s, "not the passphrase") {
		t.Fatalf("what was typed shows:\n%s", s)
	}
	d.win.Press(platform.KeyReturn)
	if !field.Empty() {
		t.Fatal("the passphrase was not wiped from the field once sent")
	}
	h.waitFor("the second question", func() bool { return h.m.asking != nil && h.m.asking.id != d.id })
	if !d.win.Closed() {
		t.Fatal("the first dialog is still open")
	}
	d = h.asking()
	if s := windowText(d.win); !strings.Contains(s, "That passphrase does not open this vault.") {
		t.Fatalf("the retry does not say why:\n%s", s)
	}
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
	h.idle()
	if !d.win.Closed() || h.m.asking != nil {
		t.Fatal("the dialog stayed up")
	}
	for _, want := range []string{"web/github.com", "mail/fastmail", "2fa/example", "personal: unlocked, 4 items", "All items (4)", "web (2)"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("the window lacks %q", want)
		}
	}
	if strings.Contains(h.text(), pass) || shaped(h, pass) {
		t.Fatal("the passphrase was drawn as text")
	}
}

// A vault the CLI unlocked is not the GUI's to use until it too shows it
// knows the passphrase: the daemon asks it, in its own window, as the
// program it is.
func TestAVaultUnlockedElsewhereAsksTheGUIToProveItself(t *testing.T) {
	h := newHarness(t)
	h.prove() // the CLI unlocks it
	h.start(Options{})
	d := h.asking()
	if d.win.Title() != "Allow svmanager.test" || !strings.Contains(windowText(d.win), "has not used vault") {
		t.Fatalf("the GUI was asked %q:\n%s", d.win.Title(), windowText(d.win))
	}
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
	// Proved once, on this connection: nothing more is asked.
	h.open("web/github.com")
	if h.m.asking != nil {
		t.Fatal("asked again")
	}
}

// A vault unlocked elsewhere while it shows locked here says so, and is
// listed when asked, not before: listing it means a question.
func TestAVaultUnlockedWhileShownLockedWaitsToBeAsked(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.prove()
	h.waitText("Vault personal is unlocked")
	if h.m.asking != nil {
		t.Fatal("the GUI asked without being asked to")
	}
	h.click(h.win(), button(h.m.ui.pane, "Show its items"))
	d := h.asking()
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
}

func TestCancellingThePromptSaysSo(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.win().Press(platform.KeyU, platform.ModCtrl)
	d := h.asking()
	d.win.Type("half a pass")
	field := d.fields[0]
	d.win.Press(platform.KeyEscape)
	h.waitText("Canceled.")
	if !field.Empty() || !d.win.Closed() {
		t.Fatal("the dialog was not wiped and closed")
	}
	h.waitText("Vault personal is locked")

	// A question the daemon gives up on goes away too.
	h.win().Press(platform.KeyU, platform.ModCtrl)
	d = h.asking()
	h.stopDaemon()
	h.waitFor("the dialog to go", func() bool { return h.m.asking == nil })
	if !d.win.Closed() {
		t.Fatal("the withdrawn question's window is still open")
	}
}

func TestTheListFiltersAsYouTypeAndFoldersNarrowIt(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	if n := h.m.ui.items.RowCount; n != 4 {
		t.Fatalf("%d items listed, want 4", n)
	}
	h.win().Press(platform.KeyF, platform.ModCtrl)
	if h.win().Focus() != h.m.ui.search {
		t.Fatalf("Ctrl+F put the keyboard on %T", h.win().Focus())
	}
	h.win().Type("git")
	if n := h.m.ui.items.RowCount; n != 2 {
		t.Fatalf("%d items match git, want 2", n)
	}
	h.waitText("2 of 4 items")
	// Down goes from the search to the results, the best match selected.
	h.win().Press(platform.KeyDown)
	if h.win().Focus() != h.m.ui.items || h.m.ui.items.Selected != 0 || h.m.cursor != "web/github.com" {
		t.Fatalf("Down: the keyboard is on %T, row %d, %q selected", h.win().Focus(), h.m.ui.items.Selected, h.m.cursor)
	}
	h.win().FocusOn(h.m.ui.search)
	h.win().Press(platform.KeyEnd)
	h.win().Type("lab")
	if n := h.m.ui.items.RowCount; n != 1 || h.m.itemCell(0, 0) != "web/gitlab.com" {
		t.Fatalf("gitlab: %d rows, first %q", n, h.m.itemCell(0, 0))
	}
	// The search finds labels, tags and attributes too, never values.
	for q, want := range map[string]int{"GitHub": 1, "dev": 1, "service": 1, "gitlab-pass": 0, "ada@": 0, "otp": 1, "LOGIN": 3} {
		h.m.ui.search.SetText(q)
		if n := h.m.ui.items.RowCount; n != want {
			t.Errorf("searching %q found %d, want %d", q, n, want)
		}
	}
	h.m.ui.search.SetText("fast")
	// Enter in the search opens the match, and the list takes the keyboard.
	h.win().Press(platform.KeyReturn)
	h.waitFor("mail/fastmail to open", func() bool { return h.m.cur != nil && h.m.cur.Item.Name == "mail/fastmail" })
	if h.win().Focus() != h.m.ui.items {
		t.Fatalf("after Enter the keyboard is on %T", h.win().Focus())
	}
	h.win().FocusOn(h.m.ui.search)
	h.win().Press(platform.KeyEscape) // the field's own: it empties
	h.win().Press(platform.KeyEscape)
	if n := h.m.ui.items.RowCount; n != 4 || h.m.query != "" {
		t.Fatalf("after Escape: %d rows, search %q", n, h.m.query)
	}

	// Folders come from the names; a folder shows what is in it.
	web := h.m.findFolder("web/")
	if web == nil || web.Label != "web (2)" {
		t.Fatalf("the web folder: %+v", web)
	}
	h.m.ui.folders.Selected = web
	h.m.folderSelected(web)
	h.pump()
	if n := h.m.ui.items.RowCount; n != 2 || h.m.itemCell(0, 0) != "github.com" {
		t.Fatalf("in web/: %d rows, first %q", n, h.m.itemCell(0, 0))
	}
	h.m.folderSelected(h.m.findFolder(""))
	if n := h.m.ui.items.RowCount; n != 4 {
		t.Fatalf("all items: %d rows", n)
	}
}

func TestAnItemIsMaskedUntilRevealed(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()

	// Selecting an item shows what the list knows; its fields are fetched
	// only when it is opened.
	h.selectItem("web/github.com")
	if h.m.cur != nil || h.m.ui.view.open() {
		t.Fatal("selecting an item opened it")
	}
	h.waitText("Enter opens it")
	h.open("web/github.com")
	screen := h.text()
	for _, want := range []string{"web/github.com", "login · GitHub", "username", "ada", "password", mask, "https://github.com", "dev", "service", "github", "No files."} {
		if !strings.Contains(screen, want) {
			t.Errorf("the item lacks %q", want)
		}
	}
	h.pump()
	if strings.Contains(screen, "hunter2-github") || shaped(h, "hunter2") {
		t.Fatalf("the password shows before it was revealed:\n%s", screen)
	}
	sr := h.m.ui.view.secrets[1]
	if sr == nil || sr.text.Revealed() {
		t.Fatal("the password is not masked")
	}
	before := h.win().Capture()

	// One field at a time.
	h.click(h.win(), button(h.m.ui.pane, "Show"))
	if !sr.text.Revealed() || sr.show.Text != "Hide" || !h.m.excluded {
		t.Fatal("Show did not reveal the password")
	}
	h.pump()
	after := h.win().Capture()
	if bytes.Equal(before.Pix, after.Pix) {
		t.Fatal("revealing drew nothing")
	}
	// It was drawn from its bytes: not as a string, not into the shape
	// cache, not into the accessibility tree.
	if shaped(h, "hunter2") {
		t.Fatal("the revealed password went through the string path")
	}
	if strings.Contains(h.text(), "hunter2-github") {
		t.Fatal("the revealed password reached the accessibility tree")
	}
	h.click(h.win(), button(h.m.ui.pane, "Hide"))
	if sr.text.Revealed() || h.m.excluded {
		t.Fatal("Hide did not hide it")
	}

	// Ctrl+R shows them all, and hides them again.
	h.win().Press(platform.KeyR, platform.ModCtrl)
	if !sr.text.Revealed() {
		t.Fatal("Ctrl+R did not reveal")
	}
	h.win().Press(platform.KeyR, platform.ModCtrl)
	if sr.text.Revealed() {
		t.Fatal("Ctrl+R did not hide")
	}

	// Leaving the item wipes what was fetched, and the screen lets go.
	h.win().Press(platform.KeyR, platform.ModCtrl)
	value := h.m.cur.Item.Fields[1].Value
	if string(value) != "hunter2-github" {
		t.Fatalf("the open item holds %q", value)
	}
	h.selectItem("web/gitlab.com")
	if !allZero(value) {
		t.Fatalf("the password was not wiped on leaving the item: %q", value)
	}
	if sr.text.value != nil || sr.text.Revealed() {
		t.Fatal("the screen still holds the password")
	}
}

func TestOneTimeCodesCountDown(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("2fa/example")
	k, err := svotp.Parse(totpURI)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := k.Code(h.now)
	cr := h.m.ui.view.codes[0]
	if cr == nil || string(cr.text.value) != groupCode(code) {
		t.Fatalf("the code shown is not %s", code)
	}
	if !strings.Contains(h.text(), "20 s") {
		t.Fatalf("the countdown is not 20 s:\n%s", h.text())
	}
	h.now = h.now.Add(25 * time.Second)
	h.m.drawCodes()
	next, _ := k.Code(h.now)
	if string(cr.text.value) != groupCode(next) || !strings.Contains(h.text(), "25 s") {
		t.Fatalf("the code did not move on: %q", cr.text.value)
	}
	// The key stays masked until asked for.
	if sr := h.m.ui.view.secrets[0]; sr == nil || sr.text.Revealed() {
		t.Fatal("the one-time password key shows")
	}
	if shaped(h, next) || shaped(h, code) {
		t.Fatal("a code went into the shape cache")
	}
}

func TestCopiesGoToTheClipboardAndAreTakenBack(t *testing.T) {
	h := newHarness(t)
	minimised := 0
	h.start(Options{})
	h.m.minimiseHook = func() { minimised++ }
	h.unlock()

	// Ctrl+C in the list copies the selected item's password: fetched for
	// the purpose, and wiped afterwards.
	h.selectItem("web/gitlab.com")
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyC, platform.ModCtrl)
	h.waitFor("a copy", func() bool { return h.clip.count() == 1 })
	c := h.clip.last()
	if c.text != "gitlab-pass-42" || c.ttl != 30*time.Second {
		t.Fatalf("copied %q for %v", c.text, c.ttl)
	}
	h.waitText("on the clipboard for 30 seconds")

	h.open("web/github.com")
	h.win().Press(platform.KeyB, platform.ModCtrl)
	if c := h.clip.last(); c.text != "ada" {
		t.Fatalf("Ctrl+B copied %q", c.text)
	}
	h.click(h.win(), button(h.m.ui.pane, "Copy password"))
	if c := h.clip.last(); c.text != "hunter2-github" {
		t.Fatalf("Copy password copied %q", c.text)
	}
	// The clipboard gets a copy of its own: the item's bytes stay the
	// item's.
	if &h.clip.last().data[0] == &h.m.cur.Item.Fields[1].Value[0] {
		t.Fatal("the clipboard was handed the item's own bytes")
	}

	// Copy and minimise.
	h.win().Press(platform.KeyC, platform.ModCtrl|platform.ModShift)
	if minimised != 1 || h.clip.last().text != "hunter2-github" {
		t.Fatalf("copy and minimise: minimised %d times, copied %q", minimised, h.clip.last().text)
	}

	// In the search, with no text selected, Ctrl+C copies the password too.
	h.win().FocusOn(h.m.ui.search)
	n := h.clip.count()
	h.win().Press(platform.KeyC, platform.ModCtrl)
	if h.clip.count() != n+1 || h.clip.last().text != "hunter2-github" {
		t.Fatal("Ctrl+C in an empty search did not copy the password")
	}

	// The one-time code.
	h.open("2fa/example")
	h.win().Press(platform.KeyT, platform.ModCtrl)
	k, _ := svotp.Parse(totpURI)
	code, _ := k.Code(h.now)
	if c := h.clip.last(); c.text != code {
		t.Fatalf("Ctrl+T copied %q, want %q", c.text, code)
	}

	// Locking takes the copy back, and wipes it.
	last := h.clip.last()
	h.win().Press(platform.KeyL, platform.ModCtrl)
	if !last.wiped() {
		t.Fatal("locking left the copy on the clipboard")
	}
}

func TestEditingAndSaving(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	ed := h.m.editor
	if ed == nil {
		t.Fatal("Ctrl+E opened no editor")
	}
	if h.m.cur != nil {
		t.Fatal("the item stayed open under the editor")
	}
	var pw *widgets.SecretField
	for _, fe := range ed.fields {
		if fe.name == "password" {
			pw = fe.secret
		}
	}
	if pw == nil || pw.Len() != len("hunter2-github") {
		t.Fatal("the password is not in a secret field")
	}
	h.win().FocusOn(ed.label)
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("GitHub (work)")
	h.win().FocusOn(pw)
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("a whole new secret")
	h.win().Press(platform.KeyS, platform.ModCtrl)
	h.waitFor("the save", func() bool { return h.m.editor == nil && h.m.cur != nil })
	h.idle()
	if !pw.Empty() {
		t.Fatal("the editor's secret field was not wiped")
	}
	e, err := h.get("web/github.com")
	if err != nil || e.Item.Label != "GitHub (work)" || field(e, "password") != "a whole new secret" || field(e, "username") != "ada" {
		t.Fatalf("saved %+v, %v", e.Item, err)
	}

	// A new item, from the kind's starter fields.
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyN, platform.ModCtrl)
	ed = h.m.editor
	if ed == nil || ed.orig != "" {
		t.Fatal("Ctrl+N opened no editor")
	}
	var names []string
	for _, fe := range ed.fields {
		names = append(names, fe.name)
	}
	if !slices.Equal(names, []string{"username", "password", "url", "otp"}) {
		t.Fatalf("a new login starts with %v", names)
	}
	// Another kind, before anything is typed, brings its own fields.
	ed.kind.Select(slices.Index(ed.kinds, "card"))
	names = names[:0]
	for _, fe := range ed.fields {
		names = append(names, fe.name)
	}
	if !slices.Equal(names, []string{"cardholder", "number", "expiry", "cvv"}) {
		t.Fatalf("a new card starts with %v", names)
	}
	ed.kind.Select(slices.Index(ed.kinds, "login"))
	ed = h.m.editor
	h.win().FocusOn(ed.name)
	h.win().Type("web/example.org")
	h.win().FocusOn(ed.fields[0].input)
	h.win().Type("bob")
	h.win().FocusOn(ed.fields[1].secret)
	h.win().Type("bobs-password")

	// A field added, and one taken away.
	h.click(h.win(), button(h.m.ui.pane, "Add field…"))
	d := h.overlay()
	if d == nil {
		t.Fatal("Add field showed no dialog")
	}
	h.win().Type("pin")
	typ := find(d, func(*widgets.ComboBox) bool { return true })
	typ.Select(slices.Index(fieldTypes, "concealed"))
	h.win().FocusOn(find(d, func(f *widgets.TextField) bool { return f.Text == "pin" }))
	h.win().Press(platform.KeyReturn)
	if h.overlay() != nil || len(ed.fields) != 5 || ed.fields[4].name != "pin" || ed.fields[4].secret == nil {
		t.Fatal("the pin field was not added as a secret")
	}
	if h.win().Focus() != ed.fields[4].secret {
		t.Fatal("the new field does not have the keyboard")
	}
	h.win().Type("1234")
	h.click(h.win(), ed.fields[3].remove) // the otp field
	h.win().Press(platform.KeyS, platform.ModCtrl)
	h.waitFor("the save", func() bool { return h.m.editor == nil })
	h.idle()
	e, err = h.get("web/example.org")
	if err != nil || field(e, "username") != "bob" || field(e, "password") != "bobs-password" || field(e, "pin") != "1234" || len(e.Item.Fields) != 3 {
		t.Fatalf("the new item: %+v, %v", e.Item, err)
	}
	h.waitFor("the new item in the list", func() bool { return h.m.entry("web/example.org") != nil })

	// Escape leaves the editor, keeping nothing.
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	ed = h.m.editor
	h.win().FocusOn(ed.fields[1].secret)
	h.win().Type("never saved")
	secret := ed.fields[1].secret
	h.win().Press(platform.KeyEscape)
	if h.m.editor != nil || !secret.Empty() {
		t.Fatal("Escape did not close and wipe the editor")
	}
}

func TestRenameAndDelete(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.selectItem("mail/fastmail")
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyF2)
	if h.overlay() == nil {
		t.Fatal("F2 asked nothing")
	}
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("mail/fastmail.com")
	h.win().Press(platform.KeyReturn)
	h.waitFor("the rename", func() bool { return h.m.entry("mail/fastmail.com") != nil })
	if _, err := h.get("mail/fastmail.com"); err != nil {
		t.Fatal(err)
	}

	h.selectItem("mail/fastmail.com")
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyDelete)
	d := h.overlay()
	if d == nil || !strings.Contains(h.text(), "Delete mail/fastmail.com from vault personal?") {
		t.Fatalf("Delete did not ask first:\n%s", h.text())
	}
	// The safe answer is the one Enter gives.
	h.win().Press(platform.KeyReturn)
	h.idle()
	if h.m.entry("mail/fastmail.com") == nil {
		t.Fatal("Enter deleted the item")
	}
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyDelete)
	h.click(h.win(), button(h.overlay(), "Delete"))
	h.waitFor("the deletion", func() bool { return h.m.entry("mail/fastmail.com") == nil })
	if _, err := h.get("mail/fastmail.com"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("after deleting: %v", err)
	}

	// Delete in the folders, or in a field, deletes nothing.
	h.win().FocusOn(h.m.ui.folders)
	h.win().Press(platform.KeyDelete)
	if h.overlay() != nil {
		t.Fatal("Delete in the folders offered to delete an item")
	}
}

func TestTheGenerator(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()

	// On its own, it copies, or makes an item.
	h.win().Press(platform.KeyG, platform.ModCtrl)
	d := h.overlay()
	preview := find(d, func(*secretText) bool { return true })
	pw := string(preview.value)
	if len(pw) != 24 || !strings.ContainsAny(pw, svcrypto.Symbols) || !strings.ContainsAny(pw, svcrypto.Digits) {
		t.Fatalf("generated %q", pw)
	}
	if shaped(h, pw) || strings.Contains(h.text(), pw) {
		t.Fatal("the generated password went through a string")
	}
	symbols := find(d, func(c *widgets.Checkbox) bool { return c.Text == "Symbols (!#$…)" })
	symbols.SetChecked(false)
	pw = string(preview.value)
	if strings.ContainsAny(pw, svcrypto.Symbols) {
		t.Fatalf("symbols were turned off, yet %q", pw)
	}
	held := preview.value
	h.click(h.win(), button(d, "Copy"))
	if c := h.clip.last(); c == nil || c.text != pw {
		t.Fatal("Copy did not copy the password")
	}
	h.win().Press(platform.KeyEscape)
	if h.overlay() != nil || !allZero(held) {
		t.Fatal("closing the generator did not wipe the password")
	}

	// Words.
	h.win().Press(platform.KeyG, platform.ModCtrl)
	d = h.overlay()
	preview = find(d, func(*secretText) bool { return true })
	find(d, func(*widgets.Segmented) bool { return true }).OnChange(1)
	words := strings.Split(string(preview.value), "-")
	if len(words) != 5 {
		t.Fatalf("a passphrase of %q", preview.value)
	}
	for _, w := range words {
		if !slices.Contains(wordList(), w) {
			t.Fatalf("%q is not one of the words", w)
		}
	}
	h.win().Press(platform.KeyEscape)
	h.m.gen = defaultGenerator()

	// From the editor, it fills in the password.
	h.open("web/gitlab.com")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.win().Press(platform.KeyG, platform.ModCtrl)
	d = h.overlay()
	preview = find(d, func(*secretText) bool { return true })
	pw = string(preview.value)
	h.click(h.win(), button(d, "Use"))
	var got []byte
	for _, fe := range h.m.editor.fields {
		if fe.name == "password" {
			got = fe.secret.Bytes()
		}
	}
	if string(got) != pw {
		t.Fatalf("the password field holds %q, the generator made %q", got, pw)
	}
	h.win().Press(platform.KeyS, platform.ModCtrl)
	h.waitFor("the save", func() bool { return h.m.editor == nil })
	h.idle()
	if e, err := h.get("web/gitlab.com"); err != nil || field(e, "password") != pw {
		t.Fatalf("saved %q, %v", field(e, "password"), err)
	}
}

func TestTheWordListIsLongEnough(t *testing.T) {
	w := wordList()
	if len(w) < 1024 {
		t.Fatalf("%d words: under 10 bits a word", len(w))
	}
	for _, s := range w {
		if s != strings.ToLower(s) || strings.ContainsAny(s, " -._") {
			t.Fatalf("the word %q", s)
		}
	}
}

func TestFilesAreAttachedSavedAndRemoved(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	in := filepath.Join(h.dir, "recovery-codes.txt")
	if err := os.WriteFile(in, []byte("1111 2222 3333"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.picks = []string{in}
	h.click(h.win(), button(h.m.ui.pane, "Add file…"))
	h.waitText("recovery-codes.txt")
	h.idle()
	h.prove()
	fd, err := h.admin.File(h.ctx(), "", "web/github.com", "recovery-codes.txt")
	if err != nil || string(fd.Data) != "1111 2222 3333" {
		t.Fatalf("attached %q, %v", fd.Data, err)
	}
	if h.m.cur == nil || len(h.m.cur.Item.Files) != 1 {
		t.Fatal("the open item does not show its new file")
	}

	out := filepath.Join(h.dir, "saved.txt")
	h.picks = []string{out}
	h.click(h.win(), button(h.m.ui.pane, "Save…"))
	h.idle()
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "1111 2222 3333" {
		t.Fatalf("saved %q, %v", b, err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("saved with mode %v", st.Mode().Perm())
	}

	h.click(h.win(), button(h.m.ui.pane, "Remove…"))
	h.click(h.win(), button(h.overlay(), "Remove"))
	h.waitText("No files.")
	if _, err := h.admin.File(h.ctx(), "", "web/github.com", "recovery-codes.txt"); err == nil {
		t.Fatal("the file is still attached")
	}
}

func TestLockingClearsTheScreenAndWipesWhatWasHeld(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	h.win().Press(platform.KeyR, platform.ModCtrl)
	sr := h.m.ui.view.secrets[1]
	held := h.m.cur.Item.Fields[1].Value
	if !sr.text.Revealed() || string(held) != "hunter2-github" {
		t.Fatal("the password is not showing")
	}
	h.click(h.win(), button(h.m.ui.pane, "Copy password"))
	copied := h.clip.last()

	// Ctrl+L: everything goes at once, before the daemon has answered.
	h.win().Press(platform.KeyL, platform.ModCtrl)
	if !allZero(held) {
		t.Fatalf("the password was not wiped: %q", held)
	}
	if h.m.cur != nil || sr.text.value != nil || sr.text.Revealed() {
		t.Fatal("the item is still held")
	}
	if !copied.wiped() {
		t.Fatal("the copy was not taken back")
	}
	h.pump()
	screen := h.text()
	if strings.Contains(screen, "web/github.com") || strings.Contains(screen, "ada") {
		t.Fatalf("the locked vault's items still show:\n%s", screen)
	}
	h.waitText("Vault personal is locked")
	h.idle()
	if v, err := h.admin.Vaults(h.ctx()); err != nil || !v[0].Locked {
		t.Fatalf("the daemon did not lock it: %+v %v", v, err)
	}

	// The same when the vault locks elsewhere: the daemon says so, and the
	// open item, its history and an editor all go.
	h.unlockAgain()
	h.open("web/github.com")
	held = h.m.cur.Item.Fields[1].Value
	if err := h.admin.Lock(h.ctx(), "", true); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the lock to reach the window", func() bool { return h.m.cur == nil })
	if !allZero(held) {
		t.Fatal("vault.locked did not wipe the open item")
	}

	h.unlockAgain()
	h.selectItem("web/github.com")
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	var secret *widgets.SecretField
	for _, fe := range h.m.editor.fields {
		if fe.name == "password" {
			secret = fe.secret
		}
	}
	if err := h.admin.Lock(h.ctx(), "", true); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the editor to go", func() bool { return h.m.editor == nil })
	if !secret.Empty() {
		t.Fatal("the editor's password was not wiped")
	}
	h.waitText("the edit was discarded")
}

// unlockAgain unlocks the vault from the manager, answering the prompt.
func (h *harness) unlockAgain() {
	h.t.Helper()
	h.win().Press(platform.KeyU, platform.ModCtrl)
	d := h.asking()
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) > 0 })
	h.idle()
}

func TestGrantsAreListedAndRevoked(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	prog, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Grant(h.ctx(), svrpc.GrantAddParams{Program: prog, Item: "web/github.com", Decision: "allow-always"}); err != nil {
		t.Fatal(err)
	}
	h.win().Press(platform.KeyG, platform.ModCtrl|platform.ModShift)
	h.waitFor("the vault's page", h.m.showingVaultPage)
	h.idle()
	p := h.m.vpage
	if len(p.grants) != 1 || p.gtable.RowCount != 1 || p.gtable.CellText(0, 0) != "allow-always" || p.gtable.CellText(0, 2) != "web/github.com" {
		t.Fatalf("grants: %+v", p.grants)
	}
	if len(p.audit) == 0 {
		t.Fatal("the audit log is empty")
	}
	p.tabs.Select(1)
	h.pump()
	if !strings.Contains(h.text(), "presented a key on this connection") {
		t.Fatalf("the audit log does not show:\n%s", h.text())
	}
	p.tabs.Select(0)
	h.pump()
	h.win().FocusOn(p.gtable)
	h.win().Press(platform.KeyDelete)
	if !strings.Contains(h.text(), "It will be asked about again.") {
		t.Fatalf("revoking did not ask first:\n%s", h.text())
	}
	h.click(h.win(), button(h.overlay(), "Revoke"))
	h.waitFor("the revocation", func() bool { return h.m.vpage != nil && len(h.m.vpage.grants) == 0 })
	if g, err := h.admin.Grants(h.ctx(), ""); err != nil || len(g) != 0 {
		t.Fatalf("the daemon still has %+v, %v", g, err)
	}
	h.waitText("No program has a remembered decision about this vault.")
	h.win().Press(platform.KeyEscape)
	if h.m.showingVaultPage() {
		t.Fatal("Escape did not leave the vault's page")
	}
}

func TestChangesElsewhereShowAtOnce(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	h.win().Press(platform.KeyR, platform.ModCtrl)
	c := h.ctx()
	h.prove()
	gh, err := h.admin.Get(c, "", "web/github.com")
	if err != nil {
		t.Fatal(err)
	}
	gh.Item.Fields[1].Value = []byte("changed-elsewhere")
	if _, err := h.admin.Put(c, "", gh.Item); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Put(c, "", login("web/new.example", "eve", "x")); err != nil {
		t.Fatal(err)
	}
	h.waitFor("the new item", func() bool { return h.m.entry("web/new.example") != nil })
	h.waitFor("the open item to be fetched again", func() bool {
		return h.m.cur != nil && string(h.m.cur.Item.Fields[1].Value) == "changed-elsewhere"
	})
	if !h.m.ui.view.secrets[1].text.Revealed() {
		t.Fatal("what was revealed was hidden again by the refresh")
	}
	if err := h.admin.Delete(c, "", "web/github.com"); err != nil {
		t.Fatal(err)
	}
	h.waitText("web/github.com was deleted.")
}

func TestWhenTheDaemonGoesAwayItSaysSoAndReconnects(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	held := h.m.cur.Item.Fields[1].Value
	h.stopDaemon()
	h.waitText("No connection to secretvaultd")
	if !allZero(held) || h.m.cur != nil {
		t.Fatal("the open item was kept")
	}
	if strings.Contains(h.text(), "web/github.com") {
		t.Fatal("items still show")
	}
	// Nothing can be done meanwhile, and saying so is all that happens.
	h.win().Press(platform.KeyN, platform.ModCtrl)
	if h.m.editor != nil {
		t.Fatal("an editor opened with no daemon")
	}
	h.startDaemon()
	h.click(h.win(), button(h.m.ui.pane, "Reconnect"))
	h.waitText("Vault personal is locked") // a new daemon: locked again
	h.unlockAgain()
	if len(h.m.entries) != 4 {
		t.Fatalf("%d items after reconnecting", len(h.m.entries))
	}
}

func TestHistoryShowsTheConflictAndItsWinner(t *testing.T) {
	h := newHarness(t)
	h.addConflicted()
	h.start(Options{Vault: "shared"})
	h.waitText("Vault shared is locked")
	h.unlockAgain()
	h.open("site")
	if !strings.Contains(h.text(), "1 other version was saved at the same time") {
		t.Fatalf("the conflict is not shown:\n%s", h.text())
	}
	if icon, _ := h.m.itemIcon(0, 0); icon != style.IconWarning {
		t.Fatal("the list does not mark the conflict")
	}
	h.win().Press(platform.KeyH, platform.ModCtrl)
	h.waitFor("the history", h.m.showingHistory)
	hist := h.m.hist
	var marks []string
	for i := range hist.entries {
		marks = append(marks, hist.table.CellText(i, 3))
	}
	if !slices.Contains(marks, "current") || !slices.Contains(marks, "conflict") {
		t.Fatalf("the history marks %v", marks)
	}
	// The winner is the current one; the other head can be opened, and
	// copied from.
	for i, e := range hist.entries {
		if hist.heads[e.Rev] {
			hist.table.Selected = i
			h.m.openRevision(i)
		}
	}
	h.pump()
	h.click(h.win(), button(h.m.ui.pane, "Copy"))
	if c := h.clip.last(); c == nil || c.text != "from laptop" {
		t.Fatalf("copied %v from the conflicting version", c)
	}
	var cur string
	for _, e := range hist.entries {
		if e.Rev == hist.cur {
			cur = field(e, "password")
		}
	}
	if cur != "from desktop" {
		t.Fatalf("the current version is %q", cur)
	}
	revs := hist.entries
	h.win().Press(platform.KeyEscape)
	if h.m.hist != nil {
		t.Fatal("the history stayed")
	}
	for _, e := range revs {
		for _, f := range e.Item.Fields {
			if !allZero(f.Value) {
				t.Fatal("a revision was not wiped on leaving the history")
			}
		}
	}
}

func TestANewVaultShowsItsRecoveryKeyOnce(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.m.newVault()
	d := h.overlay()
	name := find(d, func(f *widgets.TextField) bool { return f.Placeholder == "personal, work…" })
	fields := []*widgets.SecretField{}
	for _, ph := range []string{"At least 8 characters", "The same again"} {
		fields = append(fields, find(d, func(f *widgets.SecretField) bool { return f.Placeholder == ph }))
	}
	h.win().FocusOn(name)
	h.win().Type("work")
	h.win().FocusOn(fields[0])
	h.win().Type("short")
	h.win().FocusOn(fields[1])
	h.win().Type("short")
	h.win().Press(platform.KeyReturn)
	if !strings.Contains(h.text(), "at least 8 characters") {
		t.Fatalf("a short passphrase was taken:\n%s", h.text())
	}
	h.win().FocusOn(fields[0])
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("work passphrase 1")
	h.win().FocusOn(fields[1])
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("work passphrase 2")
	h.win().Press(platform.KeyReturn)
	if !strings.Contains(h.text(), "The two passphrases differ.") || !fields[0].Empty() || !fields[1].Empty() {
		t.Fatal("differing passphrases were not refused, and wiped")
	}
	h.win().FocusOn(fields[0])
	h.win().Type("work passphrase 1")
	h.win().FocusOn(fields[1])
	h.win().Type("work passphrase 1")
	h.win().Press(platform.KeyReturn)
	if !fields[0].Empty() || !fields[1].Empty() {
		t.Fatal("the passphrase fields were not wiped")
	}
	h.waitText("Recovery key for work")
	key := find(h.overlay(), func(*secretText) bool { return true })
	rk := append([]byte(nil), key.value...)
	held := key.value
	if shaped(h, string(rk)) || strings.Contains(h.text(), string(rk)) {
		t.Fatal("the recovery key went through a string on the screen")
	}
	h.click(h.win(), button(h.overlay(), "I have written it down"))
	if !allZero(held) {
		t.Fatal("the recovery key was not wiped")
	}
	h.idle()
	// It opens the vault.
	if err := h.admin.Lock(h.ctx(), "work", false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Unlock(h.ctx(), "work", &svrpc.Key{Type: "recovery", Secret: rk}); err != nil {
		t.Fatalf("the recovery key shown does not open the vault: %v", err)
	}
	// And the GUI may make it the default, as the CLI may.
	h.waitFor("work in the list", func() bool { return h.m.vaultInfo("work") != nil })
	h.m.showVault("work", false)
	h.m.makeDefault()
	h.waitFor("work to be the default", func() bool { v := h.m.vaultInfo("work"); return v != nil && v.Default })
}

func TestTheTray(t *testing.T) {
	h := newHarness(t)
	h.start(Options{Tray: true})
	tray, ok := h.m.tray.(*platform.FakeStatusItem)
	if !ok {
		t.Fatalf("the tray is a %T", h.m.tray)
	}
	var texts []string
	for _, it := range tray.Menu() {
		texts = append(texts, it.Text)
	}
	if !slices.Equal(texts, []string{"Open secretvault", "Search…", "Lock all vaults", "", "Quit"}) {
		t.Fatalf("the tray menu is %q", texts)
	}
	h.unlock()
	h.open("web/github.com")
	held := h.m.cur.Item.Fields[1].Value

	// Closing the window hides it in the tray, and lets go of the item.
	h.win().RequestClose()
	h.pump()
	h.pump()
	if h.win().Closed() || !h.m.hidden || !allZero(held) {
		t.Fatalf("closing: closed %v, hidden %v", h.win().Closed(), h.m.hidden)
	}
	// Search brings it back, ready to type.
	tray.Menu()[1].OnClick()
	h.pump()
	if h.m.hidden || h.win().Focus() != h.m.ui.search {
		t.Fatal("Search did not bring the window back with the search ready")
	}
	// Lock all locks every vault in the daemon.
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "work", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	tray.Menu()[2].OnClick()
	h.waitFor("every vault to lock", func() bool {
		vs, err := h.admin.Vaults(c)
		if err != nil {
			return false
		}
		for _, v := range vs {
			if !v.Locked {
				return false
			}
		}
		return true
	})
	h.waitText("Vault personal is locked")
}

// Every control carries a name, a box and a way for the keyboard to reach
// it; and no secret is in the tree, revealed or not.
func TestTheWindowsAreAccessible(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	a11ytest.Audit(t, "locked", h.win().AccessibleTree())
	h.win().Press(platform.KeyU, platform.ModCtrl)
	d := h.asking()
	d.win.Type(pass)
	tree := a11ytest.Audit(t, "the passphrase dialog", d.win.AccessibleTree())
	if a11ytest.Count(tree, a11y.RolePasswordField) != 1 {
		t.Error("the dialog has no password field")
	}
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed })
	h.idle()
	h.open("web/github.com")
	h.win().Press(platform.KeyR, platform.ModCtrl)
	tree = a11ytest.Audit(t, "an item", h.win().AccessibleTree())
	if strings.Contains(windowText(h.win()), "hunter2") {
		t.Error("a revealed password is in the accessibility tree")
	}
	var concealed *a11y.Node
	tree.Walk(func(n *a11y.Node) bool {
		if n.Name == "password" && strings.HasPrefix(n.Description, "concealed") {
			concealed = n
		}
		return true
	})
	if concealed == nil || concealed.Value != mask {
		t.Errorf("the concealed value is, to assistive technology, %+v", concealed)
	}
	h.win().Press(platform.KeyE, platform.ModCtrl)
	a11ytest.Audit(t, "the editor", h.win().AccessibleTree())
	h.win().Press(platform.KeyG, platform.ModCtrl)
	a11ytest.Audit(t, "the generator", h.win().AccessibleTree())
}

func TestWithNoTrayClosingTheWindowQuits(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	held := h.m.cur.Item.Fields[1].Value
	h.win().RequestClose()
	h.pump()
	h.pump()
	if !h.win().Closed() || !h.m.quitting() || !allZero(held) {
		t.Fatalf("closing: closed %v, quit %v", h.win().Closed(), h.m.quitting())
	}
}
