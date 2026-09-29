package svtui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

var pass = "correct horse battery staple"

const totpURI = "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// nobody is the desktop in these tests: there is nobody there to ask, so
// nothing ever pops up on the machine running them.
type nobody struct{}

func (nobody) Passphrase(context.Context, svrpc.PromptAsk) ([]byte, error) {
	return nil, svrpc.ErrCanceled
}
func (nobody) Choose(context.Context, svrpc.PromptAsk) (string, error) { return "", svrpc.ErrCanceled }
func (nobody) Describe() string                                        { return "nobody" }

func login(name, user, password string) svrpc.Item {
	return svrpc.Item{Kind: "login", Name: name, Fields: []svrpc.Field{
		{Name: "username", Type: "text", Value: []byte(user)},
		{Name: "password", Type: "concealed", Value: []byte(password)},
	}}
}

// harness is a real daemon in this process, a vault with a few items, and
// the manager on a simulated screen, typed at through injected keys.
type harness struct {
	t      *testing.T
	sock   string
	admin  *secretvault.Client // sets things up and checks them, as the CLI would
	u      *UI
	screen tcell.SimulationScreen

	mu     sync.Mutex
	clips  []string
	leaked atomic.Bool // a watched secret was drawn
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })

	dir, err := os.MkdirTemp("", "svtui") // short: socket paths have a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, sock: filepath.Join(dir, "s", "d.sock")}
	d, err := svd.New(svd.Options{Home: filepath.Join(dir, "home"), Socket: h.sock, Desktop: nobody{},
		IsCLI: func(*svpeer.Process) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ln, cleanup, err := svd.Listen(h.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done; cleanup() })

	h.admin, err = secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true, Name: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.admin.Close() })
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "personal", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	gh := login("web/github.com", "ada", "hunter2-github")
	gh.Label, gh.Tags, gh.Attrs = "GitHub", []string{"dev"}, map[string]string{"service": "github"}
	for _, it := range []svrpc.Item{
		gh,
		login("web/gitlab.com", "ada", "gitlab-pass-42"),
		login("mail/fastmail", "ada@fastmail.com", "fastmail-secret"),
		{Kind: "otp", Name: "2fa/example", Fields: []svrpc.Field{{Name: "otp", Type: "otp", Value: []byte(totpURI)}}},
	} {
		if _, err := h.admin.Put(c, "", it); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.admin.Lock(c, "", true); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h.t.Cleanup(cancel)
	return c
}

func (h *harness) clip(secret []byte, ttl time.Duration) (string, error) {
	if ttl != 30*time.Second {
		return "", errors.New("unexpected ttl " + ttl.String())
	}
	h.mu.Lock()
	h.clips = append(h.clips, string(secret))
	h.mu.Unlock()
	return "test", nil
}

func (h *harness) copies() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.clips...)
}

// start runs the manager. Any frame that draws watch (if set) is noted.
func (h *harness) start(opts Options, watch string) {
	h.t.Helper()
	h.screen = tcell.NewSimulationScreen("UTF-8")
	opts.Screen = h.screen
	opts.Connect = func(o secretvault.Options) (*secretvault.Client, error) {
		o.Socket, o.NoStart = h.sock, true
		return secretvault.Connect(o)
	}
	if opts.Clip == nil {
		opts.Clip = h.clip
	}
	u, err := New(opts) // initialises the screen
	if err != nil {
		h.t.Fatal(err)
	}
	h.u = u
	h.screen.SetSize(120, 36)
	if watch != "" {
		u.app.SetAfterDrawFunc(func(s tcell.Screen) {
			if strings.Contains(cellText(s), watch) {
				h.leaked.Store(true)
			}
		})
	}
	done := make(chan error, 1)
	go func() { done <- u.Run() }()
	h.t.Cleanup(func() {
		u.post(u.quit)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			h.t.Error("the manager did not stop")
		}
	})
}

// cellText is what the screen shows, row by row.
func cellText(s tcell.Screen) string {
	w, hgt := s.Size()
	var b strings.Builder
	for y := range hgt {
		for x := range w {
			r, _, _, _ := s.GetContent(x, y)
			if r == 0 {
				r = ' '
			}
			b.WriteRune(r)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// do runs fn on the manager's goroutine and waits for it.
func (h *harness) do(fn func()) {
	h.t.Helper()
	ch := make(chan struct{})
	go h.u.app.QueueUpdate(func() { fn(); close(ch) })
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		h.t.Fatal("the manager did not answer")
	}
}

func (h *harness) text() string {
	var s string
	h.do(func() { s = cellText(h.screen) })
	return s
}

func (h *harness) waitFor(want string) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(h.text(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("%q never appeared:\n%s", want, h.text())
}

func (h *harness) waitGone(gone string) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !strings.Contains(h.text(), gone) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("%q never went away:\n%s", gone, h.text())
}

func (h *harness) key(k tcell.Key) { h.screen.InjectKey(k, 0, tcell.ModNone) }

func (h *harness) ctrl(k tcell.Key) { h.screen.InjectKey(k, 0, tcell.ModCtrl) }

func (h *harness) typeText(s string) {
	for _, r := range s {
		h.screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
}

func (h *harness) tabs(n int) {
	for range n {
		h.key(tcell.KeyTab)
	}
}

// unlock answers the passphrase dialog the first listing brings up.
func (h *harness) unlock() {
	h.t.Helper()
	h.waitFor("Locked: Enter unlocks")
	h.key(tcell.KeyEnter)
	h.waitFor("Unlock vault personal")
	h.typeText(pass)
	h.key(tcell.KeyEnter)
	h.waitFor("web/github.com")
}

// open opens an item through the filter.
func (h *harness) open(name string) {
	h.t.Helper()
	h.typeText("/" + name)
	h.key(tcell.KeyEnter)
	h.key(tcell.KeyEnter)
	h.waitFor(" " + name + " ─")
	h.waitFor("revision")
	h.key(tcell.KeyEscape) // clear the filter
	h.waitGone("/ " + name)
}

// get reads an item as the CLI would, presenting the key.
func (h *harness) get(name string) (svrpc.Entry, error) {
	c := h.ctx()
	if _, err := h.admin.Unlock(c, "", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		return svrpc.Entry{}, err
	}
	return h.admin.Get(c, "", name)
}

func field(e svrpc.Entry, name string) string {
	for _, f := range e.Item.Fields {
		if f.Name == name {
			return string(f.Value)
		}
	}
	return ""
}

func TestUnlockingAsksForThePassphraseInADialog(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, pass)
	h.waitFor("personal *  locked")
	h.waitFor("Locked: Enter unlocks")
	h.key(tcell.KeyEnter)
	h.waitFor("Unlock vault personal")
	h.typeText("not the passphrase")
	h.key(tcell.KeyEnter)
	h.waitFor("That passphrase does not open this vault.")
	if strings.Contains(h.text(), "not the passphrase") {
		t.Fatalf("the passphrase was drawn:\n%s", h.text())
	}
	h.typeText(pass)
	h.waitFor(strings.Repeat("•", len(pass)))
	h.key(tcell.KeyEnter)
	h.waitFor("web/github.com")
	h.waitFor("personal *  unlocked")
	h.waitFor("4 items")
	if h.leaked.Load() {
		t.Fatal("the passphrase was drawn")
	}
}

func TestCancellingTheDialogSaysSo(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.key(tcell.KeyEnter)
	h.waitFor("Unlock vault personal")
	h.key(tcell.KeyEscape)
	h.waitFor("Canceled.")
	h.waitGone("Unlock vault personal")
	h.waitFor("Locked: Enter unlocks")
}

// The daemon asks terminal programs for a vault's passphrase, a security
// key's PIN and its touch; the other questions are answered all the same.
func TestTheDaemonsOtherQuestionsAreAnswered(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	ask := func(q svrpc.PromptAsk) <-chan svrpc.PromptAnswer {
		ch := make(chan svrpc.PromptAnswer, 1)
		go func() {
			a, err := h.u.prompt(context.Background(), q)
			if err != nil {
				t.Error(err)
			}
			ch <- a
		}()
		return ch
	}
	answer := func(ch <-chan svrpc.PromptAnswer) svrpc.PromptAnswer {
		t.Helper()
		select {
		case a := <-ch:
			return a
		case <-time.After(10 * time.Second):
			t.Fatalf("no answer:\n%s", h.text())
		}
		return svrpc.PromptAnswer{}
	}

	ch := ask(svrpc.PromptAsk{Kind: svrpc.PromptNewPassphrase, Title: "New passphrase for work", Description: "Choose one."})
	h.waitFor("New passphrase for work")
	h.typeText("short")
	h.key(tcell.KeyEnter)
	h.typeText("short")
	h.key(tcell.KeyEnter)
	h.waitFor("Use at least 8 characters.")
	h.typeText("long enough 1")
	h.key(tcell.KeyTab)
	h.typeText("long enough 2")
	h.key(tcell.KeyEnter)
	h.waitFor("The two passphrases differ.")
	h.typeText("long enough 1")
	h.key(tcell.KeyTab)
	h.typeText("long enough 1")
	h.key(tcell.KeyEnter)
	if a := answer(ch); string(a.Secret) != "long enough 1" || a.Canceled {
		t.Fatalf("answered %+v", a)
	}
	h.waitGone("New passphrase for work")

	ch = ask(svrpc.PromptAsk{Kind: svrpc.PromptChoose, Title: "Allow access?", Description: "A program asks.",
		Choices: []svrpc.Choice{{ID: svrpc.ChoiceOnce, Label: "Allow once"}, {ID: svrpc.ChoiceLock, Label: "Allow until the vault locks"}}})
	h.waitFor("Allow until the vault locks")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	if a := answer(ch); a.Choice != svrpc.ChoiceLock {
		t.Fatalf("answered %+v", a)
	}

	// A security key's PIN, like a passphrase: never drawn.
	ch = ask(svrpc.PromptAsk{Kind: svrpc.PromptPIN, Title: "Unlock vault personal", Description: "Enter the PIN of your security key (YubiKey).", Prompt: "PIN:"})
	h.waitFor("Enter the PIN of your security key")
	h.typeText("975312")
	h.key(tcell.KeyEnter)
	if a := answer(ch); string(a.Secret) != "975312" || a.Canceled {
		t.Fatalf("the PIN was answered %+v", a)
	}
	if strings.Contains(h.text(), "975312") {
		t.Fatalf("the PIN was drawn:\n%s", h.text())
	}
	// "Touch your security key" is said, and needs no answer.
	if a := answer(ask(svrpc.PromptAsk{Kind: svrpc.PromptNotice, Description: "Touch your security key.\n(YubiKey)"})); a.Canceled {
		t.Fatalf("a notice was answered %+v", a)
	}
	h.waitFor("Touch your security key. (YubiKey)")

	if a := answer(ask(svrpc.PromptAsk{Kind: "something new"})); !a.Canceled {
		t.Fatalf("an unknown question was answered %+v", a)
	}

	// A question the daemon gives up on goes away.
	ctx, cancel := context.WithCancel(context.Background())
	go h.u.prompt(ctx, svrpc.PromptAsk{Kind: svrpc.PromptPassphrase, Title: "Soon withdrawn"})
	h.waitFor("Soon withdrawn")
	cancel()
	h.waitGone("Soon withdrawn")
}

func TestAnotherVaultIsOneEnterAway(t *testing.T) {
	h := newHarness(t)
	// A second vault, left unlocked by the CLI.
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "work", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Put(c, "work", login("work/vpn", "ada", "vpn-secret")); err != nil {
		t.Fatal(err)
	}
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("work  unlocked")
	h.key(tcell.KeyLeft) // to the vaults
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	// This terminal has not shown it knows work's passphrase, unless the
	// CLI proved it from the same terminal session (as when these tests
	// run in one): then the daemon asks nothing. Run with no terminal, the
	// program is what is asked about.
	deadline := time.Now().Add(10 * time.Second)
	for s := h.text(); !strings.Contains(s, "work/vpn"); s = h.text() {
		if strings.Contains(s, "has not used vault") {
			h.typeText(pass)
			h.key(tcell.KeyEnter)
			h.waitGone("has not used vault")
		}
		if time.Now().After(deadline) {
			t.Fatalf("work's items never showed:\n%s", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.waitFor("work unlocked · 1 item")
	h.waitFor("Items · work")
	if s := h.text(); strings.Contains(s, "web/github.com") {
		t.Fatalf("personal's items still show:\n%s", s)
	}
}

func TestTheListFiltersAsYouType(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.waitFor("2fa/example")
	count := func() (n int) {
		h.do(func() { n = h.u.itemList.GetItemCount() })
		return n
	}
	if n := count(); n != 4 {
		t.Fatalf("%d items listed, want 4", n)
	}
	h.typeText("/git")
	h.waitFor("2 of 4")
	if n := count(); n != 2 {
		t.Fatalf("%d items match git, want 2", n)
	}
	h.typeText("lab")
	h.waitFor("1 of 4")
	h.key(tcell.KeyEscape)
	h.waitGone("of 4")
	if n := count(); n != 4 {
		t.Fatalf("%d items after clearing the filter, want 4", n)
	}
}

func TestAnItemIsMaskedUntilRevealed(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.open("web/github.com")
	screen := h.text()
	for _, want := range []string{"login", "GitHub", "dev", "service", "github", "username", "ada", "password", mask, "concealed"} {
		if !strings.Contains(screen, want) {
			t.Errorf("the item view lacks %q", want)
		}
	}
	if strings.Contains(screen, "hunter2-github") {
		t.Fatalf("the password shows before it was revealed:\n%s", screen)
	}
	h.typeText("r")
	h.waitFor("hunter2-github")
	h.typeText("r")
	h.waitGone("hunter2-github")

	// Revealed values are hidden again on leaving the item.
	h.typeText("r")
	h.waitFor("hunter2-github")
	h.open("web/gitlab.com")
	if s := h.text(); strings.Contains(s, "hunter2-github") || strings.Contains(s, "gitlab-pass-42") {
		t.Fatalf("a secret shows after moving to another item:\n%s", s)
	}
}

func TestCopyingHandsTheSecretToTheClipboardWithoutDrawingIt(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "hunter2-github")
	h.unlock()
	h.open("web/github.com")
	h.typeText("c")
	h.waitFor("Copied (clears in 30s)")
	h.typeText("u")
	deadline := time.Now().Add(5 * time.Second)
	for len(h.copies()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.copies(); len(got) != 2 || got[0] != "hunter2-github" || got[1] != "ada" {
		t.Fatalf("copied %q, want the password then the username", got)
	}
	if h.leaked.Load() {
		t.Fatal("the copied password was drawn on the screen")
	}

	// In the item pane, c copies the field selected there.
	h.key(tcell.KeyRight)
	h.key(tcell.KeyEnd)
	h.typeText("c")
	deadline = time.Now().Add(5 * time.Second)
	for len(h.copies()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.copies(); len(got) != 3 || got[2] != "hunter2-github" {
		t.Fatalf("copied %q, want the selected password field", got)
	}
	if h.leaked.Load() {
		t.Fatal("the copied password was drawn on the screen")
	}
}

func TestACopyThatFailsSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.start(Options{Clip: func([]byte, time.Duration) (string, error) {
		return "", errors.New("no clipboard here")
	}}, "")
	h.unlock()
	h.open("web/github.com")
	h.typeText("c")
	h.waitFor("Could not copy: no clipboard here")
}

func TestNewAndEditedItemsRoundTripThroughTheDaemon(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()

	h.typeText("n")
	h.waitFor("New item in personal")
	h.typeText("web/new.example")
	h.tabs(4) // label, tags, attributes, username
	h.typeText("grace")
	h.tabs(1)
	h.typeText("s3cret-new")
	h.waitFor("••••••••••")
	if strings.Contains(h.text(), "s3cret-new") {
		t.Fatal("a concealed value was drawn while it was typed")
	}
	h.ctrl(tcell.KeyCtrlR)
	h.waitFor("s3cret-new")
	h.ctrl(tcell.KeyCtrlS)
	h.waitFor("Saved web/new.example")
	h.waitGone("New item in personal")
	e, err := h.get("web/new.example")
	if err != nil {
		t.Fatal(err)
	}
	if e.Item.Kind != "login" || field(e, "username") != "grace" || field(e, "password") != "s3cret-new" || len(e.Item.Fields) != 2 {
		t.Fatalf("stored %+v", e.Item)
	}

	// Edit it: a label, an attribute, and a new password.
	h.waitFor("revision")
	h.waitFor("5 items")
	h.typeText("e")
	h.waitFor("Edit web/new.example")
	h.tabs(1)
	h.typeText("Grace's")
	h.tabs(2)
	h.typeText("env=test")
	h.tabs(2) // username, password
	h.ctrl(tcell.KeyCtrlU)
	h.typeText("changed-pass")
	h.ctrl(tcell.KeyCtrlS)
	h.waitGone("Edit web/new.example")
	e, err = h.get("web/new.example")
	if err != nil {
		t.Fatal(err)
	}
	if e.Item.Label != "Grace's" || e.Item.Attrs["env"] != "test" || field(e, "password") != "changed-pass" || field(e, "username") != "grace" {
		t.Fatalf("after the edit: %+v", e.Item)
	}

	// Both revisions are in the history, and the old one opens read-only.
	h.waitFor("Grace's")
	h.typeText("h")
	h.waitFor("History of web/new.example")
	h.waitFor("current")
	h.key(tcell.KeyDown)
	h.key(tcell.KeyEnter)
	h.waitFor("(read-only)")
	if strings.Contains(h.text(), "s3cret-new") {
		t.Fatal("the old revision's password shows before it was revealed")
	}
	h.typeText("r")
	h.waitFor("s3cret-new")
	h.key(tcell.KeyEscape)
	h.waitGone("(read-only)")
	h.key(tcell.KeyEscape)
	h.waitGone("History of")
	if strings.Contains(h.text(), "s3cret-new") {
		t.Fatal("the old password still shows after the history closed")
	}
}

func TestTheGeneratorFillsInThePassword(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.typeText("n")
	h.waitFor("New item in personal")
	h.typeText("api/generated")
	h.ctrl(tcell.KeyCtrlG)
	h.waitFor("Password generator")
	h.tabs(2) // symbols, then (past the preview) Use
	h.key(tcell.KeyEnter)
	h.waitGone("Password generator")
	h.ctrl(tcell.KeyCtrlS)
	h.waitFor("Saved api/generated")
	e, err := h.get("api/generated")
	if err != nil {
		t.Fatal(err)
	}
	if p := field(e, "password"); len(p) != 24 {
		t.Fatalf("stored password %q, want 24 generated characters", p)
	}
}

func TestDeletingAsksFirst(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.open("web/gitlab.com")
	h.typeText("d")
	h.waitFor(`Delete "web/gitlab.com"`)
	h.typeText("n")
	h.waitGone("Delete \"web/gitlab.com\"")
	if _, err := h.get("web/gitlab.com"); err != nil {
		t.Fatalf("declining deleted it: %v", err)
	}
	h.typeText("d")
	h.waitFor(`Delete "web/gitlab.com"`)
	h.typeText("y")
	h.waitFor("Deleted web/gitlab.com")
	if _, err := h.get("web/gitlab.com"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("after deleting: %v", err)
	}
	h.waitFor("3 items")
}

func TestRenamingMovesTheItem(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.open("web/gitlab.com")
	h.typeText("m")
	h.waitFor("Rename web/gitlab.com")
	h.ctrl(tcell.KeyCtrlU)
	h.typeText("code/gitlab.com")
	h.key(tcell.KeyEnter)
	h.waitFor("Renamed web/gitlab.com to code/gitlab.com")
	if e, err := h.get("code/gitlab.com"); err != nil || field(e, "password") != "gitlab-pass-42" {
		t.Fatalf("after renaming: %v", err)
	}
}

func TestLockingClearsSecretsFromTheScreenAndMemory(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.open("web/github.com")
	h.typeText("r")
	h.waitFor("hunter2-github")
	var held []byte
	h.do(func() { held = h.u.cur.Item.Fields[1].Value })

	// Locked from elsewhere: the daemon's event clears the screen.
	if _, err := h.get("web/github.com"); err != nil {
		t.Fatal(err)
	}
	if err := h.admin.Lock(h.ctx(), "personal", false); err != nil {
		t.Fatal(err)
	}
	h.waitGone("hunter2-github")
	h.waitFor("personal *  locked")
	h.do(func() {
		if h.u.cur != nil || !bytes.Equal(held, make([]byte, len(held))) {
			t.Errorf("the password is still held after the vault locked: %q", held)
		}
	})

	// Locked from here.
	h.typeText("U")
	h.waitFor("Unlock vault personal")
	h.typeText(pass)
	h.key(tcell.KeyEnter)
	h.waitFor("web/github.com")
	h.open("web/github.com")
	h.typeText("r")
	h.waitFor("hunter2-github")
	h.typeText("l")
	h.waitGone("hunter2-github")
	h.waitFor("Locked: Enter unlocks")
	h.waitFor("Locked personal")

	// And every vault at once.
	h.key(tcell.KeyEnter)
	h.waitFor("Unlock vault personal")
	h.typeText(pass)
	h.key(tcell.KeyEnter)
	h.waitFor("web/github.com")
	h.open("web/github.com")
	h.typeText("r")
	h.waitFor("hunter2-github")
	h.typeText("L")
	h.waitGone("hunter2-github")
	h.waitFor("Locked every vault")
}

func TestOneTimeCodesShowAndCopy(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 9, 29, 12, 0, 10, 0, time.UTC)
	h.start(Options{Now: func() time.Time { return now }}, "JBSWY3DPEHPK3PXP")
	h.unlock()
	k, err := svotp.Parse(totpURI)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := k.Code(now)
	h.open("2fa/example")
	h.waitFor(groupCode(code))
	h.waitFor("20s left")
	h.typeText("o")
	h.waitFor("Copied (clears in 30s)")
	if got := h.copies(); len(got) != 1 || got[0] != code {
		t.Fatalf("copied %q, want the code %s", got, code)
	}
	if h.leaked.Load() {
		t.Fatal("the key's secret was drawn while hidden")
	}
}

func TestGrantsAndTheAuditLogAreShown(t *testing.T) {
	h := newHarness(t)
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Grant(h.ctx(), svrpc.GrantAddParams{Program: "/bin/sh", Item: "web/gitlab.com", Decision: "allow-always"}); err != nil {
		t.Fatal(err)
	}
	if err := h.admin.Lock(h.ctx(), "", true); err != nil {
		t.Fatal(err)
	}
	h.start(Options{}, "")
	h.unlock()
	h.typeText("G")
	h.waitFor("Grants · personal")
	h.waitFor("allow-always")
	h.waitFor("web/gitlab.com")
	h.typeText("x")
	h.waitFor("Revoke")
	h.typeText("y")
	h.waitGone("allow-always")
	h.key(tcell.KeyEscape)
	h.waitGone("Grants · personal")

	h.typeText("A")
	h.waitFor("Audit log · personal")
	h.waitFor("allowed")
	h.waitFor("proved the passphrase")
	h.key(tcell.KeyEscape)
	h.waitGone("Audit log · personal")
}

func TestTheHelpListsTheKeys(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.typeText("?")
	h.waitFor("the password generator")
	h.waitFor("lock every vault")
	h.key(tcell.KeyEscape)
	h.waitGone("the password generator")
}

func TestTheDaemonGoingAwayIsSaidPlainly(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "hunter2-github")
	h.unlock()
	h.open("web/github.com")
	h.u.client.Close()
	h.waitFor("secretvaultd went away")
	h.do(func() {
		if h.u.cur != nil {
			t.Error("an item is still held after the daemon went away")
		}
	})
}

func TestErrorsReadAsPlainWords(t *testing.T) {
	u := &UI{}
	for err, want := range map[error]string{
		svrpc.ErrCanceled: "Canceled.",
		svrpc.ErrWrongKey: "That passphrase does not open this vault.",
		svrpc.Errorf(svrpc.CodeDenied, "access to vault %q was denied", "personal"): `Access to vault "personal" was denied.`,
		svrpc.Errorf(svrpc.CodeLocked, "vault is locked"):                           "The vault is locked; U unlocks it.",
		svrpc.Errorf(svrpc.CodeNoPrompter, "nobody"):                                "Nobody could be asked for permission: nobody",
		svrpc.Errorf(svrpc.CodeNotFound, "no such item %q", "x"):                    `No such item "x".`,
		context.DeadlineExceeded:                                                    "secretvaultd took too long to answer.",
	} {
		if got := u.describe(err); got != want {
			t.Errorf("describe(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestGrowingASecretWipesWhatItLeaves(t *testing.T) {
	buf := appendSecret(nil, []byte("abc"))
	old := buf[:cap(buf)]
	buf = appendSecret(buf, bytes.Repeat([]byte("x"), cap(buf)))
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatalf("the old array still holds %q", old)
	}
	if !bytes.HasPrefix(buf, []byte("abcxxx")) {
		t.Fatalf("grown to %q", buf)
	}
}

func TestTheClipboardHelperIsAskedLikeTheCLIAsksIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script")
	}
	dir := t.TempDir()
	got := filepath.Join(dir, "got")
	helper := filepath.Join(dir, "secretvault")
	script := "#!/bin/sh\ncat > " + got + "\necho \"$1 $2\" >> " + got + "\necho 'ok fake-clipboard'\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	backend, err := clipWith(helper, []byte("hunter2"), 30*time.Second)
	if err != nil || backend != "fake-clipboard" {
		t.Fatalf("clipWith = %q, %v", backend, err)
	}
	b, _ := os.ReadFile(got)
	if string(b) != "hunter2__clip 30\n" {
		t.Fatalf("the helper got %q", b)
	}

	failing := filepath.Join(dir, "failing")
	os.WriteFile(failing, []byte("#!/bin/sh\ncat >/dev/null\necho 'error: no display'\n"), 0o700)
	if _, err := clipWith(failing, []byte("x"), 30*time.Second); err == nil || err.Error() != "no display" {
		t.Fatalf("a failing helper: %v", err)
	}
}
