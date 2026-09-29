package svmanager

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Things that happen out of the usual order: a page replaced by another,
// an answer that arrives after the screen has moved on, a dialog that
// outlives what opened it. Whatever held secrets is wiped, and nothing
// acts on what is no longer shown.

// concealedWiped reports whether every concealed value in entries is
// zeros.
func concealedWiped(entries []svrpc.Entry) bool {
	for _, e := range entries {
		for _, f := range e.Item.Fields {
			if f.Type == svcore.FieldConcealed && !allZero(f.Value) {
				return false
			}
		}
	}
	return true
}

// withWork adds a second vault, "work", locked like the first.
func withWork(h *harness) {
	h.t.Helper()
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "work", Passphrase: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
	if err := h.admin.Lock(c, "", true); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) vaultRow(name string) int {
	for i, v := range h.m.vaults {
		if v.Name == name {
			return i
		}
	}
	h.t.Fatalf("no vault %s", name)
	return -1
}

func (h *harness) history() []svrpc.Entry {
	h.t.Helper()
	h.win().Press(platform.KeyH, platform.ModCtrl)
	h.waitFor("the history", h.m.showingHistory)
	h.idle()
	return h.m.hist.entries
}

// Whatever replaces the history wipes its revisions; and while it is up,
// Ctrl+R is about the revision it shows.
func TestLeavingTheHistoryWipesItsRevisions(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	revs := h.history()

	h.win().Press(platform.KeyR, platform.ModCtrl)
	h.pump()
	if !h.m.showingHistory() || len(h.m.hist.view.revealedFields()) == 0 || h.m.cur != nil {
		t.Fatalf("Ctrl+R in the history: history %v, revision revealed %v, item open %v",
			h.m.showingHistory(), h.m.hist != nil && len(h.m.hist.view.revealedFields()) > 0, h.m.cur != nil)
	}
	if !h.m.excluded {
		t.Fatal("a revealed revision is not kept out of screen captures")
	}

	// The editor in its place.
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	h.idle()
	if h.m.hist != nil || !concealedWiped(revs) {
		t.Fatal("the editor took the history's place and left its revisions unwiped")
	}
	h.win().Press(platform.KeyEscape)
	h.idle()

	// The item, opened from the list, in its place.
	revs = h.history()
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyReturn)
	h.waitFor("the item", func() bool { return h.m.cur != nil })
	h.idle()
	if h.m.hist != nil || !concealedWiped(revs) {
		t.Fatal("the item took the history's place and left its revisions unwiped")
	}

	// Delete there is not a request to delete the item.
	h.history()
	h.win().FocusOn(h.m.hist.table)
	h.win().Press(platform.KeyDelete)
	h.pump()
	if h.overlay() != nil {
		t.Fatalf("Delete in the history asked:\n%s", h.text())
	}
}

// An edit is only ever ended by saving or cancelling it: a new item,
// the generator's "New item with it", and another vault all wait.
func TestAnOpenEditIsNeverThrownAway(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()
	h.open("web/github.com")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	h.idle()
	ed := h.m.editor
	h.win().FocusOn(ed.label)
	h.win().Press(platform.KeyEnd)
	h.win().Type(" typed")

	kept := func(what string) {
		t.Helper()
		h.pump()
		if h.m.editor != ed || ed.closed || !strings.HasSuffix(ed.label.Text, " typed") {
			t.Fatalf("%s: the edit was thrown away", what)
		}
		if h.m.ui.message != "Save or cancel the edit first." {
			t.Fatalf("%s: the status bar says %q", what, h.m.ui.message)
		}
		h.m.ui.message = ""
	}
	h.win().Press(platform.KeyN, platform.ModCtrl)
	kept("Ctrl+N")

	d := h.m.showGenerator(nil)
	h.pump()
	h.click(h.win(), button(h.overlay(), "New item with it"))
	kept("New item with it")
	if !d.closed {
		t.Fatal("the generator stayed up")
	}

	h.m.ui.vaultList.Selected = h.vaultRow("work")
	h.m.vaultSelected(h.vaultRow("work"))
	kept("another vault")
	if h.m.vault != "personal" || h.m.ui.vaultList.Selected != h.vaultRow("personal") {
		t.Fatalf("showing %s, with row %d selected", h.m.vault, h.m.ui.vaultList.Selected)
	}
	h.m.vaultActivated(h.vaultRow("work"))
	kept("Enter on another vault")
}

// The vault's page covers the items: keys that act on an item do
// nothing while it is up, rather than act on a pane nobody sees.
func TestTheVaultPageKeepsItemKeysOffTheHiddenPane(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	held := h.m.cur.Item.Fields[1].Value
	h.win().Press(platform.KeyG, platform.ModCtrl|platform.ModShift)
	h.waitFor("the vault's page", h.m.showingVaultPage)
	h.idle()
	if h.m.cur != nil || !allZero(held) {
		t.Fatal("the item open under the vault's page was kept")
	}
	for _, k := range []platform.Key{platform.KeyN, platform.KeyR, platform.KeyE, platform.KeyH} {
		h.win().Press(k, platform.ModCtrl)
		h.idle()
	}
	if h.m.editor != nil || h.m.cur != nil || h.m.hist != nil || !h.m.showingVaultPage() {
		t.Fatalf("under the vault's page: editor %v, item open %v, history %v",
			h.m.editor != nil, h.m.cur != nil, h.m.hist != nil)
	}
	h.m.closeVaultPage()
	h.pump()
	if h.m.editor != nil || h.m.showing(pageEditor) {
		t.Fatal("an editor was waiting under the vault's page")
	}
}

// An answer that comes back after the vault shown has changed, or
// locked, is dropped, wiped: it would act on the wrong vault's screen.
func TestAnAnswerForAVaultNoLongerShownIsDropped(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()
	personal := func() {
		t.Helper()
		h.m.showVault("personal", false)
		h.waitFor("the items", func() bool { return h.m.listed })
		h.idle()
		h.selectItem("web/github.com")
	}

	personal()
	h.m.editItem() // on its way
	h.m.showVault("work", false)
	h.idle()
	if h.m.editor != nil {
		t.Fatalf("personal's item opened in an editor over vault %s", h.m.vault)
	}

	personal()
	h.m.copySecret()
	h.m.showVault("work", false)
	h.idle()
	if h.clip.count() != 0 {
		t.Fatal("personal's password was copied after another vault was shown")
	}

	personal()
	h.m.showHistory()
	h.m.vaultLocked("personal")
	h.idle()
	if h.m.hist != nil || h.m.showingHistory() {
		t.Fatal("the history of a vault that locked went up")
	}
}

// Switching vaults shows nothing of the last one while the next one's
// items are fetched (and its passphrase asked for).
func TestSwitchingVaultsShowsNothingOfTheLastOne(t *testing.T) {
	h := newHarness(t)
	withWork(h)
	h.start(Options{Vault: "personal"})
	h.unlock()
	h.open("web/github.com")
	if _, err := h.admin.Unlock(h.ctx(), "work", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	h.m.showVault("work", true)
	d := h.asking() // this program has to show it knows work's passphrase too
	for _, gone := range []string{"GitHub", "web/github.com", "mail/fastmail", "All items"} {
		if strings.Contains(h.text(), gone) {
			t.Fatalf("while work is listed, %q still shows:\n%s", gone, h.text())
		}
	}
	if h.m.ui.items.RowCount != 0 || !strings.Contains(h.text(), "Vault work") {
		t.Fatalf("while work is listed:\n%s", h.text())
	}
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("work's items", func() bool { return h.m.listed })
}

// Dialogs the editor opened go when it does, and what they would have
// handed it goes nowhere.
func TestWhatTheEditorOpenedGoesWithIt(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()

	secrets := func(ed *editor) int {
		n := 0
		for _, fe := range ed.fields {
			if fe.secret != nil {
				n += fe.secret.Len()
			}
		}
		return n
	}

	// The generator, and its Use pressed after the edit ended.
	h.win().Press(platform.KeyN, platform.ModCtrl)
	ed := h.m.editor
	h.win().Press(platform.KeyG, platform.ModCtrl)
	h.pump()
	use := button(h.overlay(), "Use")
	if use == nil {
		t.Fatal("no generator")
	}
	h.m.vaultLocked("personal")
	h.pump()
	if h.m.editor != nil || h.overlay() != nil {
		t.Fatal("the generator outlived the editor")
	}
	use.OnClick()
	if secrets(ed) != 0 || ed.lastSecret != nil {
		t.Fatal("the generated password went into the closed editor")
	}
	h.m.reloadVaults()
	h.idle()
	h.m.showVault("personal", true)
	h.waitFor("the items", func() bool { return h.m.listed })

	// "Add a field".
	h.win().Press(platform.KeyN, platform.ModCtrl)
	ed = h.m.editor
	ed.askField()
	h.pump()
	add := button(h.overlay(), "Add")
	ed.close()
	h.pump()
	if h.overlay() != nil {
		t.Fatal("\"Add a field\" outlived the editor")
	}
	n := len(ed.fields)
	add.OnClick()
	if len(ed.fields) != n {
		t.Fatal("a field was added to the closed editor")
	}

	// A file chosen for a field after the edit ended is not read into it.
	h.prove()
	key := svrpc.Item{Kind: "ssh-key", Name: "ssh/laptop", Fields: []svrpc.Field{
		{Name: "private-key", Type: svcore.FieldKey, Value: []byte("-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n")}}}
	if _, err := h.admin.Put(h.ctx(), "", key); err != nil {
		t.Fatal(err)
	}
	h.waitFor("ssh/laptop", func() bool { return h.m.entry("ssh/laptop") != nil })
	h.open("ssh/laptop")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	ed = h.m.editor
	var pick func(string)
	h.m.opts.PickFile = func(_ bool, _ string, done func(string)) { pick = done }
	h.click(h.win(), button(h.m.ui.pane, "Replace from file…"))
	if pick == nil {
		t.Fatal("no file was asked for")
	}
	kept := ed.fields[0].kept
	ed.close()
	in := filepath.Join(h.dir, "new-key")
	if err := os.WriteFile(in, []byte("NEW KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	pick(in)
	if !allZero(kept) || !allZero(ed.fields[0].kept) {
		t.Fatal("the closed editor holds a key")
	}
}

// Typing into a secret field the editor shows keeps the window out of
// screen captures from the first character.
func TestTypingARevealedSecretKeepsTheWindowOutOfCaptures(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.win().Press(platform.KeyN, platform.ModCtrl)
	ed := h.m.editor
	h.win().Press(platform.KeyR, platform.ModCtrl)
	var pw *widgets.SecretField
	for _, fe := range ed.fields {
		if fe.name == "password" {
			pw = fe.secret
		}
	}
	h.win().FocusOn(pw)
	if h.m.excluded {
		t.Fatal("excluded with nothing to hide")
	}
	h.win().Type("x")
	if !h.m.excluded || !h.win().Surface().(*platform.Offscreen).ExcludeFromCapture() {
		t.Fatal("the secret typed shows, and the window is not kept out of captures")
	}
}

// What a call would send is wiped even when there is no daemon to send
// it to, and the call is never made.
func TestWhatIsSentIsWipedWhenThereIsNoDaemon(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.gone = true
	secret := []byte("a passphrase")
	ran, answered := false, error(nil)
	h.m.call(func(context.Context, *secretvault.Client) error { ran = true; return nil },
		func(err error) { answered = err }, secret)
	if ran || answered != errGone || !allZero(secret) {
		t.Fatalf("ran %v, answered %v, wiped %v", ran, answered, allZero(secret))
	}
}

// A second recovery key waits for the first to be written down, and a
// dialog up when one arrives is left to be finished with.
func TestARecoveryKeyWaitsItsTurn(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.confirm("Something else", "Busy", "OK", func() {})
	h.pump()
	first, second := []byte("RK-FIRST-1234"), []byte("RK-SECOND-5678")
	h.m.showRecoveryKey("a", first)
	h.m.showRecoveryKey("b", second)
	h.pump()
	if !strings.Contains(h.text(), "Busy") || allZero(first) || allZero(second) {
		t.Fatalf("the dialog up was replaced, or a key wiped unread:\n%s", h.text())
	}
	h.click(h.win(), button(h.overlay(), "Cancel"))
	h.waitText("Recovery key for a")
	h.click(h.win(), button(h.overlay(), "I have written it down"))
	if !allZero(first) || allZero(second) {
		t.Fatal("the first key was not wiped, or the second was")
	}
	h.waitText("Recovery key for b")

	// One still waiting when the program quits is wiped.
	third := []byte("RK-THIRD-9012")
	h.m.showRecoveryKey("c", third)
	h.m.Close()
	if !allZero(second) || !allZero(third) {
		t.Fatal("recovery keys outlived the program")
	}
}

// The copy on the clipboard is taken back when the daemon goes: its
// vault's locking can no longer be heard of.
func TestTheDaemonGoingTakesTheCopyBack(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.selectItem("web/github.com")
	h.win().Press(platform.KeyC, platform.ModCtrl)
	h.waitFor("the copy", func() bool { return h.clip.count() == 1 })
	h.stopDaemon()
	h.waitText("No connection to secretvaultd")
	if !h.clip.last().wiped() {
		t.Fatal("the copy stayed on the clipboard")
	}
}

// An answer typed after the daemon gave up on the question is wiped, not
// left in the channel it was sent on.
func TestALateAnswerIsWiped(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan svrpc.PromptAnswer, 1)
	go func() {
		a, _ := h.m.prompt(ctx, svrpc.PromptAsk{Kind: svrpc.PromptPassphrase, Title: "Unlock vault personal"})
		got <- a
	}()
	d := h.asking()
	d.win.Type("typed too late")
	answers := d.answer
	cancel()
	time.Sleep(30 * time.Millisecond) // the question is being taken down
	d.win.Press(platform.KeyReturn)
	var a svrpc.PromptAnswer
	h.waitFor("the question to end", func() bool {
		select {
		case a = <-got:
			return true
		default:
			return false
		}
	})
	if !a.Canceled || a.Secret != nil || len(answers) != 0 {
		t.Fatalf("canceled %v, secret %q, %d answers left unread", a.Canceled, a.Secret, len(answers))
	}
}

// Saving a file over one that was there leaves it readable by its owner
// only, whatever the old one's mode was.
func TestAFileSavedOverAnotherIsTheOwnersOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codes.txt")
	if err := os.WriteFile(path, []byte("an old, longer file that was readable by all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, []byte("1111")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	st, _ := os.Stat(path)
	if err != nil || string(b) != "1111" || st.Mode().Perm() != 0o600 {
		t.Fatalf("%q, mode %v, %v", b, st.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".codes.txt.*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

// Coloured labels take their colour from the look they are drawn in,
// with nothing keeping them (uitoolkit-gaps.md, 24).
func TestTonesFollowTheLook(t *testing.T) {
	l := toned("Locked", toneDanger)
	for _, lk := range []style.LookAndFeel{style.DarkLook(), style.LightLook()} {
		l.SetLook(lk)
		l.Measure(layout.Loose(400, 100))
		if l.Color != toneColor(lk, toneDanger) {
			t.Fatalf("on %v the label is %v", lk.Palette().Background, l.Color)
		}
	}
}
