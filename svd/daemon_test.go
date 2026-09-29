package svd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

var pass = []byte("correct horse battery staple")

// program is a fake peer: every connection is announced before it is
// made, so tests can be several programs at once from one process.
type harness struct {
	t     *testing.T
	home  string
	sock  string
	d     *Daemon
	stop  func()
	procs chan *svpeer.Process
	desk  *scripted
	opts  Options
}

// scripted is a desktop (or terminal) prompter that answers from a script
// and records what it was asked.
type scripted struct {
	mu      sync.Mutex
	answers []string // "pass:<p>", "choose:<id>", "cancel"
	asked   []svrpc.PromptAsk
}

func (s *scripted) next(q svrpc.PromptAsk) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, q)
	if len(s.answers) == 0 {
		return "", errors.New("test: prompt with no scripted answer: " + q.Title)
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	if a == "cancel" {
		return "", svrpc.ErrCanceled
	}
	return a, nil
}

func (s *scripted) Passphrase(_ context.Context, q svrpc.PromptAsk) ([]byte, error) {
	a, err := s.next(q)
	if err != nil {
		return nil, err
	}
	p, ok := strings.CutPrefix(a, "pass:")
	if !ok {
		return nil, errors.New("test: expected a passphrase prompt, script says " + a)
	}
	return []byte(p), nil
}

func (s *scripted) Choose(_ context.Context, q svrpc.PromptAsk) (string, error) {
	a, err := s.next(q)
	if err != nil {
		return "", err
	}
	c, ok := strings.CutPrefix(a, "choose:")
	if !ok {
		return "", errors.New("test: expected a choice prompt, script says " + a)
	}
	return c, nil
}

func (s *scripted) Describe() string { return "scripted" }

func (s *scripted) script(answers ...string) {
	s.mu.Lock()
	s.answers = append(s.answers, answers...)
	s.mu.Unlock()
}

func (s *scripted) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.asked)
}

func (s *scripted) done(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.answers) != 0 {
		t.Fatalf("prompts never asked: %v", s.answers)
	}
}

func cheapKDF(t *testing.T) {
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	cheapKDF(t)
	dir, err := os.MkdirTemp("", "svd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, home: filepath.Join(dir, "home"), sock: filepath.Join(dir, "s", "d.sock"),
		procs: make(chan *svpeer.Process, 16), desk: &scripted{}}
	h.opts = Options{
		Home: h.home, Socket: h.sock, Desktop: h.desk, IdleUnit: time.Hour,
		Peer:          func(net.Conn) (*svpeer.Process, error) { return <-h.procs, nil },
		IsCLI:         func(p *svpeer.Process) bool { return filepath.Base(p.Exe) == "secretvault" },
		IsPromptAgent: func(p *svpeer.Process) bool { return filepath.Base(p.Exe) == "secretvault-tui-prompt" },
	}
	h.start()
	return h
}

func (h *harness) start() {
	d, err := New(h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	ln, cleanup, err := Listen(h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Serve(ctx, ln); close(done) }()
	h.d = d
	h.stop = func() { cancel(); <-done; cleanup() }
	h.t.Cleanup(func() {
		if h.stop != nil {
			h.stop()
		}
	})
}

func (h *harness) restart() {
	h.stop()
	h.stop = nil
	h.start()
}

// connect connects as a program at exe; with terminal, as the CLI whose
// terminal answers from term.
func (h *harness) connect(exe string, term *scripted) *secretvault.Client {
	h.t.Helper()
	h.procs <- &svpeer.Process{PID: 4242, Exe: exe, SystemOwned: true}
	opts := secretvault.Options{Socket: h.sock, NoStart: true}
	if term != nil {
		opts.Prompter = func(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
			if q.Kind == svrpc.PromptChoose {
				c, err := term.Choose(ctx, q)
				return svrpc.PromptAnswer{Choice: c}, err
			}
			p, err := term.Passphrase(ctx, q)
			if errors.Is(err, svrpc.ErrCanceled) {
				return svrpc.PromptAnswer{Canceled: true}, nil
			}
			return svrpc.PromptAnswer{Secret: p}, err
		}
	}
	c, err := secretvault.Connect(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func login(name, secret string) svrpc.Item {
	return svrpc.Item{Kind: "login", Name: name, Fields: []svrpc.Field{{Name: "password", Type: "concealed", Value: []byte(secret)}}}
}

// setup creates the default vault from a CLI and stores one item.
func (h *harness) setup() *secretvault.Client {
	h.t.Helper()
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.CreateVault(ctx(h.t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		h.t.Fatal(err)
	}
	if _, err := cli.Put(ctx(h.t), "", login("mail/imap", "hunter2")); err != nil {
		h.t.Fatal(err)
	}
	return cli
}

func secretOf(e svrpc.Entry) string {
	for _, f := range e.Item.Fields {
		if f.Name == "password" {
			return string(f.Value)
		}
	}
	return ""
}

func TestTheCreatorOfAVaultMayUseIt(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	e, err := cli.Get(ctx(t), "", "mail/imap")
	if err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("Get = %+v, %v", e, err)
	}
	if h.desk.count() != 0 {
		t.Fatal("the creator was prompted")
	}
	vaults, _ := cli.Vaults(ctx(t))
	if len(vaults) != 1 || !vaults[0].Default || vaults[0].Locked || vaults[0].Name != "personal" {
		t.Fatalf("vaults = %+v", vaults)
	}
}

func TestAProgramIsAskedAndTheAnswerIsRemembered(t *testing.T) {
	h := newHarness(t)
	h.setup()
	mail := h.connect("/usr/bin/mail", nil)

	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if e, err := mail.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("allow once: %v", err)
	}
	q := h.desk.asked[0]
	if !strings.Contains(q.Description, "mail (/usr/bin/mail) wants to read \"mail/imap\"") || len(q.Choices) != 4 {
		t.Fatalf("the prompt said %q with %d choices", q.Description, len(q.Choices))
	}

	h.desk.script("choose:" + svrpc.ChoiceLock)
	mail.Get(ctx(t), "", "mail/imap") // once was once: asked again
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if h.desk.count() != 2 {
		t.Fatalf("asked %d times, want 2", h.desk.count())
	}
	h.desk.done(t)

	// Another program is asked on its own account.
	git := h.connect("/usr/bin/git", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := git.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("deny: %v", err)
	}
	// A denial is not remembered unless chosen so; listing is a new question.
	h.desk.script("cancel")
	if _, err := git.List(ctx(t), "", ""); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a dismissed prompt: %v", err)
	}
	h.desk.done(t)
}

func TestAlwaysSurvivesARestartAndLockingNeedsTheKeyAgain(t *testing.T) {
	h := newHarness(t)
	h.setup()
	mail := h.connect("/usr/bin/mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	h.restart() // vaults come back locked

	mail = h.connect("/usr/bin/mail", nil)
	// Locked: the desktop asks for the passphrase, naming the program;
	// that unlock is consent for this request, and "always" covers later
	// ones: one prompt in all.
	h.desk.script("pass:wrong passphrase", "pass:"+string(pass))
	if e, err := mail.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("after restart: %v", err)
	}
	if q := h.desk.asked[1]; q.Kind != svrpc.PromptPassphrase || !strings.Contains(q.Description, "mail (/usr/bin/mail)") {
		t.Fatalf("unlock prompt %+v", q)
	}
	if q := h.desk.asked[2]; q.Error == "" {
		t.Fatal("the retry did not say the first passphrase was wrong")
	}
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	h.desk.done(t)
}

func TestTheCLIProvesItselfWithThePassphraseOnItsTerminal(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.d.LockAll("test")
	term := &scripted{}
	cli := h.connect("/usr/bin/secretvault", term)
	term.script("pass:" + string(pass))
	if e, err := cli.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("Get = %v", err)
	}
	if h.desk.count() != 0 {
		t.Fatal("the desktop was asked on the CLI's behalf")
	}

	// A second CLI, vault already unlocked: it must prove itself too, with
	// the passphrase, never with a yes/no.
	term2 := &scripted{}
	cli2 := h.connect("/usr/bin/secretvault", term2)
	term2.script("pass:nope", "pass:"+string(pass))
	if _, err := cli2.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatalf("second CLI: %v", err)
	}
	if term2.asked[0].Kind != svrpc.PromptPassphrase || term2.asked[1].Error == "" {
		t.Fatalf("second CLI was asked %+v", term2.asked)
	}
	term.done(t)
	term2.done(t)
}

func TestAProgramIsNeverAskedToCollectAPassphrase(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.d.LockAll("test")
	// This program offers to prompt; it is not secretvault's CLI, so the
	// desktop asks instead.
	sneaky := &scripted{}
	p := h.connect("/home/user/bin/helper", sneaky)
	h.desk.script("pass:" + string(pass))
	if _, err := p.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if sneaky.count() != 0 {
		t.Fatal("a program was handed a passphrase prompt")
	}
}

func TestWithNobodyToAskTheAnswerIsNo(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.d.desktop = nil
	mail := h.connect("/usr/bin/mail", nil)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrNoPrompter) {
		t.Fatalf("unlocked, nobody to ask: %v", err)
	}
	h.d.LockAll("test")
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrLocked) {
		t.Fatalf("locked, nobody to ask: %v", err)
	}
}

func TestATerminalAgentCanStandInForTheDesktop(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.d.desktop = nil
	// Only secretvault's own prompt program may register.
	impostor := h.connect("/home/user/bin/secretvault-tui-prompt-not", &scripted{})
	if err := impostor.RegisterPrompter(ctx(t), "pts/9"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("an impostor registered: %v", err)
	}
	agentTerm := &scripted{}
	agent := h.connect("/usr/bin/secretvault-tui-prompt", agentTerm)
	if err := agent.RegisterPrompter(ctx(t), "pts/1"); err != nil {
		t.Fatal(err)
	}
	mail := h.connect("/usr/bin/mail", nil)
	agentTerm.script("choose:" + svrpc.ChoiceOnce)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	agentTerm.done(t)
}

func TestGrantsAndTheAuditLogAreVisibleAndRevocable(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	mail := h.connect("/usr/bin/mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	mail.Get(ctx(t), "", "mail/imap")

	grants, err := cli.Grants(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	var stored *svrpc.Grant
	for i := range grants {
		if grants[i].Scope == "stored" {
			stored = &grants[i]
		}
	}
	if stored == nil || stored.Program != "mail (/usr/bin/mail)" || stored.Item != "mail/imap" || stored.Decision != "allow-always" {
		t.Fatalf("grants = %+v", grants)
	}
	if err := cli.Revoke(ctx(t), "", stored.ID); err != nil {
		t.Fatal(err)
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("after revoke: %v", err)
	}

	log, err := cli.Audit(ctx(t), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, e := range log {
		if e.Program == "mail (/usr/bin/mail)" {
			outcomes = append(outcomes, e.Outcome)
		}
	}
	if strings.Join(outcomes, ",") != "allowed,denied" {
		t.Fatalf("mail's audit trail: %v (full log %+v)", outcomes, log)
	}
}

func TestIdleVaultsLockThemselvesAndClientsHear(t *testing.T) {
	h := newHarness(t)
	h.stop()
	h.opts.IdleUnit = 50 * time.Millisecond
	h.start()
	events := make(chan string, 8)
	h.procs <- &svpeer.Process{PID: 1, Exe: "/usr/bin/secretvault"}
	cli, err := secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true,
		OnEvent: func(m string, ev svrpc.VaultEvent) { events <- m + ":" + ev.Vault }})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "v", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev == svrpc.EVaultLocked+":v" {
				return
			}
		case <-deadline:
			t.Fatal("the idle vault never locked")
		}
	}
}

func TestVaultsCanBeRegisteredForgottenAndChosen(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	// A second vault elsewhere, registered by path.
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "work", Path: filepath.Join(h.home, "elsewhere"), Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "work", Passphrase: pass}); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a duplicate name: %v", err)
	}
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "../evil", Passphrase: pass}); err == nil {
		t.Fatal("a path-like vault name was accepted")
	}
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "short", Passphrase: []byte("abc")}); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
	if err := cli.SetDefault(ctx(t), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Put(ctx(t), "", login("w", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Get(ctx(t), "work", "w"); err != nil {
		t.Fatal("the default vault is not work")
	}
	if err := cli.ForgetVault(ctx(t), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddVault(ctx(t), "work-again", filepath.Join(h.home, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	h.restart()
	cli = h.connect("/usr/bin/secretvault", &scripted{})
	vaults, _ := cli.Vaults(ctx(t))
	var names []string
	for _, v := range vaults {
		names = append(names, v.Name)
	}
	if strings.Join(names, ",") != "personal,work-again" {
		t.Fatalf("after restart: %v", names)
	}
}

func TestASecondDaemonOnTheSameSocketIsRefused(t *testing.T) {
	h := newHarness(t)
	if _, _, err := Listen(h.sock); !errors.Is(err, ErrRunning) {
		t.Fatalf("second Listen = %v", err)
	}
}
