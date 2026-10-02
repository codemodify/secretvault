package svmanager

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/diag"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
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
	h.m.opts.PickFile = func(_ PickMode, _ string, done func(string)) { pick = done }
	h.click(h.win(), button(h.m.ui.pane, "Replace from file…"))
	if pick == nil {
		t.Fatal("no file was asked for")
	}
	area := ed.fields[0].secret
	ed.close()
	in := filepath.Join(h.dir, "new-key")
	if err := os.WriteFile(in, []byte("NEW KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	pick(in)
	if area == nil || !area.Empty() {
		t.Fatal("the closed editor holds a key")
	}
}

// A key is edited in a secret area, several lines and all: pasted,
// shown, read from a file, and saved as it is. What the editor held is
// wiped when it closes.
func TestAKeyIsEditedInASecretArea(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	pem := "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n"
	key := svrpc.Item{Kind: "ssh-key", Name: "ssh/laptop", Fields: []svrpc.Field{
		{Name: "private-key", Type: svcore.FieldKey, Value: []byte(pem)},
		{Name: "pin", Type: svcore.FieldConcealed, Value: []byte("1234")},
		{Name: "blob", Type: svcore.FieldBinary, Value: []byte{0, 1, 2}}}}
	if _, err := h.admin.Put(h.ctx(), "", key); err != nil {
		t.Fatal(err)
	}
	h.waitFor("ssh/laptop", func() bool { return h.m.entry("ssh/laptop") != nil })
	h.open("ssh/laptop")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	ed := h.m.editor
	kf, pin, blob := ed.fields[0], ed.fields[1], ed.fields[2]
	area, ok := kf.box.(*widgets.SecretArea)
	if !ok || kf.kept != nil {
		t.Fatalf("the key is in a %T, kept %v", kf.box, kf.kept != nil)
	}
	if got := kf.secret.Bytes(); string(got) != pem {
		t.Fatalf("the area holds %q", got)
	}
	if _, ok := pin.box.(*widgets.SecretField); !ok || blob.kept == nil {
		t.Fatalf("a one-line secret is in a %T; binary kept %v", pin.box, blob.kept != nil)
	}
	h.win().Press(platform.KeyR, platform.ModCtrl)
	if !area.Reveal || !h.m.excluded {
		t.Fatal("the key is not shown, or shown with the window in captures")
	}
	h.win().Press(platform.KeyR, platform.ModCtrl)

	// Read from a file into the area.
	var pick func(string)
	h.m.opts.PickFile = func(_ PickMode, _ string, done func(string)) { pick = done }
	h.click(h.win(), button(h.m.ui.pane, "Replace from file…"))
	next := "-----BEGIN KEY-----\nCCCC\n-----END KEY-----\n"
	in := filepath.Join(h.dir, "next-key")
	if err := os.WriteFile(in, []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	pick(in)
	if got := kf.secret.Bytes(); string(got) != next {
		t.Fatalf("after reading the file the area holds %q", got)
	}
	h.win().Press(platform.KeyS, platform.ModCtrl)
	h.waitFor("the save", func() bool { return h.m.editor == nil })
	e, err := h.get("ssh/laptop")
	if err != nil {
		t.Fatal(err)
	}
	if field(e, "private-key") != next || field(e, "pin") != "1234" || field(e, "blob") != "\x00\x01\x02" {
		t.Fatalf("saved %q, %q, %q", field(e, "private-key"), field(e, "pin"), field(e, "blob"))
	}
	if !kf.secret.Empty() || !pin.secret.Empty() || !allZero(blob.kept) {
		t.Fatal("the closed editor holds a secret")
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

// A recovery key goes over whatever dialog is up, which is there as it
// was once the key has been written down; and a key up when the program
// quits is wiped, under another dialog or not.
func TestARecoveryKeyGoesOverTheDialogUp(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.confirm("Something else", "Busy", "OK", func() {})
	h.pump()
	busy := h.overlay()
	first, second := []byte("RK-FIRST-1234"), []byte("RK-SECOND-5678")
	h.m.showRecoveryKey("a", first)
	h.m.showRecoveryKey("b", second)
	h.pump()
	if n := len(h.win().Overlays()); n != 3 || allZero(first) || allZero(second) {
		t.Fatalf("%d dialogs up, or a key wiped unread:\n%s", n, h.text())
	}
	h.waitText("Recovery key for b")
	h.click(h.win(), button(h.overlay(), "I have written it down"))
	if !allZero(second) || allZero(first) {
		t.Fatal("the key written down was not wiped, or the other one was")
	}
	h.waitText("Recovery key for a")
	h.click(h.win(), button(h.overlay(), "I have written it down"))
	if !allZero(first) {
		t.Fatal("the first key was not wiped")
	}
	if h.overlay() != busy || !strings.Contains(h.text(), "Busy") {
		t.Fatalf("the dialog that was up is gone:\n%s", h.text())
	}

	// Keys still up when the program quits are wiped, the one under the
	// other too.
	third, fourth := []byte("RK-THIRD-9012"), []byte("RK-FOURTH-3456")
	h.m.showRecoveryKey("c", third)
	h.m.showRecoveryKey("d", fourth)
	h.m.Close()
	if !allZero(third) || !allZero(fourth) || len(h.win().Overlays()) != 0 {
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

// Coloured labels say what they mean, and uitoolkit colours them from the
// look they are drawn in, with nothing keeping them (uitoolkit-gaps.md,
// 24): readable on it, and still red (29, 31).
func TestTonesFollowTheLook(t *testing.T) {
	l := toned("Locked", widgets.ToneDanger)
	if l.Tone != widgets.ToneDanger || l.Color != (paintengine2d.Color{}) {
		t.Fatalf("tone %v, colour %v: a fixed colour would not follow the look", l.Tone, l.Color)
	}
	for _, lk := range []style.LookAndFeel{style.DarkLook(), style.LightLook(), style.Appearance{Name: "plastik-night"}.Look()} {
		p := lk.Palette()
		c := p.DangerInk()
		if r := style.ContrastRatio(c, p.Background); r < style.MinInkContrast {
			t.Fatalf("on %v the danger is %.1f:1", p.Background, r)
		}
		if c.R < c.G+0.2 || c.R < c.B+0.2 {
			t.Fatalf("on %v the danger is %v, not red", p.Background, c)
		}
	}
}

// A dialog raised over another leaves it as it was: its fields still hold
// what was typed, and closing the one on top closes that one only. A file
// chooser taken down unanswered takes down only itself.
func TestADialogOverAnotherLeavesItAsItWas(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.newVault()
	nv := h.overlay()
	pass := find(nv, func(f *widgets.SecretField) bool { return f.Placeholder == "At least 8 characters" })
	h.win().FocusOn(pass)
	h.win().Type("half a passphrase")

	h.m.showKeys()
	h.pump()
	if n := len(h.win().Overlays()); n != 2 || pass.Len() != 17 {
		t.Fatalf("%d dialogs up, and the passphrase field holds %d", n, pass.Len())
	}
	h.win().Press(platform.KeyEscape)
	if h.overlay() != nv || pass.Len() != 17 {
		t.Fatal("closing the dialog on top closed, or wiped, the one under it")
	}

	h.m.opts.PickFile = nil // uitoolkit's own chooser
	t.Setenv("HOME", t.TempDir())
	cancel := h.m.pickFile(PickOpen, "", func(string) {})
	h.pump()
	if n := len(h.win().Overlays()); n != 2 {
		t.Fatalf("%d dialogs up with the file chooser", n)
	}
	cancel()
	h.pump()
	if h.overlay() != nv || pass.Len() != 17 {
		t.Fatal("taking the chooser down took the dialog under it too")
	}
	h.win().Press(platform.KeyEscape)
	if h.overlay() != nil || !pass.Empty() {
		t.Fatal("the new vault's dialog did not close, or kept what was typed")
	}
}

// The window hides in the tray only while somebody shows the tray icon,
// and comes back if the tray goes while it is hidden there.
func TestTheWindowHidesOnlyInATrayThatIsShown(t *testing.T) {
	h := newHarness(t)
	h.start(Options{Tray: true})
	tray := h.m.tray.(*platform.FakeStatusItem)
	h.win().RequestClose()
	h.pump()
	if !h.m.hidden {
		t.Fatal("not hidden in a tray that is shown")
	}
	tray.SetShown(false)
	h.waitFor("the window back", func() bool { return !h.m.hidden })
	if !h.win().Visible() {
		t.Fatal("the tray went and the window stayed hidden")
	}
	h.win().RequestClose()
	h.pump()
	h.pump()
	if !h.win().Closed() || !h.m.quitting() {
		t.Fatal("with no tray shown, closing the window did not quit")
	}
}

// At the narrowest the window may be, the editor fits beside the lists:
// the window's minimum is what its content needs (widget.MinWidthOf),
// stated as the editor opens, the splitters keep the pane at least as
// wide as the editor needs, and every field and its button is inside the
// window. A window narrower than that when the editor opens is widened,
// and a resize does not take the minimum away (uitoolkit-gaps.md, 44).
func TestTheEditorFitsTheNarrowestWindow(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.selectItem("web/github.com")
	browsing, _ := h.win().MinSize()
	h.win().SetSize(int(browsing), 700)
	h.pump()
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	h.idle()
	floor, _ := h.win().MinSize()
	if need := float32(math.Ceil(float64(widget.MinWidthOf(h.win().Content()) / h.win().Scale()))); floor != need || floor <= browsing {
		t.Fatalf("with the editor up the window's minimum is %v, its content's %v, the items' %v", floor, need, browsing)
	}
	if w, _ := h.win().Size(); float32(w) < floor {
		t.Fatalf("the window is %d wide, under the editor's %v", w, floor)
	}
	for _, w := range []int{1120, int(floor)} {
		h.win().SetSize(w, 700)
		h.pump()
		h.pump()
		if mw, _ := h.win().MinSize(); mw != floor {
			t.Errorf("%d wide: the window's minimum is %v after the resize", w, mw)
		}
		pane := h.m.ui.pane
		if need := widget.MinWidthOf(h.m.editor.page); pane.Bounds().Dx() < need {
			t.Errorf("%d wide: the pane is %v, the editor needs %v", w, pane.Bounds().Dx(), need)
		}
		pw, _ := h.win().PixelSize()
		for _, fe := range h.m.editor.fields {
			if right := widget.DeviceOrigin(fe.remove).X + fe.remove.Bounds().Dx(); right > float32(pw) {
				t.Errorf("%d wide: %s's Remove ends at %v", w, fe.name, right)
			}
		}
	}
}

// A rename the daemon does not make is said in the rename dialog, which
// stays up with the name that was typed, rather than after it has gone.
func TestARefusedRenameIsSaidInTheDialog(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.selectItem("mail/fastmail")
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyF2)
	h.stopDaemon()
	h.win().Press(platform.KeyA, platform.ModCtrl)
	h.win().Type("mail/fastmail.com")
	h.win().Press(platform.KeyReturn)
	h.waitFor("the refusal", func() bool { return strings.Contains(windowText(h.win()), "secretvaultd is not running") })
	f := find(h.overlay(), func(*widgets.TextField) bool { return true })
	if h.overlay() == nil || f == nil || f.Text != "mail/fastmail.com" {
		t.Fatal("the rename dialog went, or lost what was typed")
	}
}

// uitoolkit did everything the manager told it, through the pages a
// person goes through: no finding at warning level (its diagnostics).
func TestTheToolkitDidWhatItWasTold(t *testing.T) {
	h := newHarness(t)
	h.start(Options{Tray: true})
	h.unlock()
	h.open("web/github.com")
	h.win().Press(platform.KeyE, platform.ModCtrl)
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	h.win().Press(platform.KeyG, platform.ModCtrl)
	h.pump()
	for _, f := range uitoolkit.Diagnostics() {
		if f.Level == diag.Warn {
			t.Errorf("%v", f)
		}
	}
}

// A dialog taller than the window scrolls its body and keeps its buttons
// in view (uitoolkit-gaps.md, 40): an invite, wrapped to the dialog's
// width rather than at a fixed count (39), and its QR code under it, in
// one dialog, in the shortest window there may be. A short dialog is no
// taller than what it holds.
func TestATallDialogKeepsItsButtonsInView(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.confirm("Delete?", "Delete it?", "Delete", func() {})
	h.pump()
	short := find(h.overlay(), func(p *widgets.Panel) bool { return true })
	_, ph := h.win().PixelSize()
	if hgt := widget.DeviceBounds(short).Dy(); hgt > float32(ph)/2 {
		t.Fatalf("a dialog of one line is %v tall in a window %d tall", hgt, ph)
	}
	h.win().Press(platform.KeyEscape)

	h.win().SetSize(1120, minWindowHeight)
	h.pump()
	invite := []byte("svsync1:" + strings.Repeat("Qm9vdHN0cmFwIGludml0ZQ", 8))
	h.m.showSecrets("Invite a device to personal", "Paste it on the new device, or scan it.",
		[]secretShown{{label: "Invite", value: invite}}, true, "Done")
	h.pump()
	_, ph = h.win().PixelSize()
	done := button(h.overlay(), "Done")
	if b := widget.DeviceBounds(done); b.Dy() <= 0 || b.Max.Y > float32(ph) {
		t.Fatalf("the dialog's button is at %v, in a window %d tall", b, ph)
	}
	scroll := find(h.overlay(), func(*widgets.ScrollView) bool { return true })
	if scroll == nil || scroll.MaxOffset() <= 0 || find(h.overlay(), func(*qrView) bool { return true }) == nil {
		t.Fatal("the invite and its QR code are not in one dialog that scrolls")
	}
	text := find(h.overlay(), func(*secretText) bool { return true })
	lines := text.wrapped(text.Bounds().Dx() - 2)
	tb, sb := widget.DeviceBounds(text), widget.DeviceBounds(scroll)
	if len(lines) < 2 || len(lines[0]) <= 48 || tb.Max.X > sb.Max.X {
		t.Fatalf("the invite is %d lines, the first %d long, ending at %v in a dialog ending at %v", len(lines), len(lines[0]), tb.Max.X, sb.Max.X)
	}
	h.click(h.win(), done)
	if !allZero(invite) || h.overlay() != nil {
		t.Fatal("the invite outlived its dialog")
	}
}

// A long secret shown in an item wraps to the values' column (a
// widgets.Share column, uitoolkit-gaps.md 39), at the narrowest the window
// may be: inside the pane, its buttons beside it.
func TestALongSecretWrapsInItsColumn(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	long := strings.Repeat("correct-horse-battery-staple-", 8)
	it := svrpc.Item{Kind: "login", Name: "web/long", Fields: []svrpc.Field{
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte(long)}}}
	if _, err := h.admin.Put(h.ctx(), "", it); err != nil {
		t.Fatal(err)
	}
	h.waitFor("web/long", func() bool { return h.m.entry("web/long") != nil })
	h.open("web/long")
	floor, _ := h.win().MinSize()
	h.win().SetSize(int(floor), 700)
	h.pump()
	h.win().Press(platform.KeyR, platform.ModCtrl)
	h.pump()
	text := find(h.m.ui.pane, func(s *secretText) bool { return s.AccessibleName() == "password" })
	if text == nil || !text.Revealed() {
		t.Fatal("the password is not shown")
	}
	lines := text.wrapped(text.Bounds().Dx() - 2)
	tb, pb := widget.DeviceBounds(text), widget.DeviceBounds(h.m.ui.pane)
	hide := widget.DeviceBounds(button(h.m.ui.pane, "Hide"))
	if len(lines) < 2 || tb.Max.X > pb.Max.X || hide.Min.X < tb.Max.X || hide.Max.X > pb.Max.X {
		t.Fatalf("a password of %d characters is %d lines, ending at %v, its Hide at %v, in a pane ending at %v", len(long), len(lines), tb.Max.X, hide, pb.Max.X)
	}
	if mw, _ := h.win().MinSize(); mw != floor {
		t.Fatalf("showing the password moved the window's floor from %v to %v", floor, mw)
	}
}
