package svd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// What the security review of vault.request found, held.

// The prompt names the program as the system knows it: the script an
// interpreter runs, beside the interpreter, and a file name that would
// redraw the prompt spelled out instead.
func TestTheQuestionNamesTheProgramAsItIs(t *testing.T) {
	h := newHarness(t)
	h.setup()
	py := h.connectAs(&svpeer.Process{PID: 51, Exe: "/usr/bin/python3", Script: "/tmp/x/thunderbird", SystemOwned: true}, nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	py.RequestVault(ctx(t), "mail")
	q := h.desk.questions()[0]
	if !strings.HasPrefix(q.Title, "thunderbird wants") || !strings.Contains(q.Description, "Program: /usr/bin/python3\nScript: /tmp/x/thunderbird\nProcess: 51") {
		t.Fatalf("an interpreter's script: %q\n%s", q.Title, q.Description)
	}
	odd := h.connectAs(&svpeer.Process{PID: 52, Exe: "/tmp/q/\n\nProgram: /usr/bin/thunderbird", SystemOwned: true}, nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	odd.RequestVault(ctx(t), "mail")
	q = h.desk.questions()[1]
	if strings.Contains(q.Description, "\nProgram: /usr/bin/thunderbird") || !strings.Contains(q.Description, `Program: /tmp/q/\n\nProgram: /usr/bin/thunderbird`) {
		t.Fatalf("a name with line breaks: %q", q.Description)
	}
}

// Refusals that ask nobody are written once a minute at most: a program
// asking in a loop does not bury the audit log.
func TestARequestInALoopDoesNotFloodTheAuditLog(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	for range 20 {
		if _, err := mail.RequestVault(ctx(t), "personal"); !errors.Is(err, svrpc.ErrExists) {
			t.Fatal(err)
		}
	}
	log, err := cli.Audit(ctx(t), "personal", 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range log {
		if e.Op == "create-vault" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d entries for 20 refusals", n)
	}
}

// A vault's folder is made where nothing is: not through a link.
func TestARequestDoesNotFollowALinkInTheDataFolder(t *testing.T) {
	h := newHarness(t)
	h.setup()
	elsewhere := filepath.Join(h.home, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(h.home, "vaults", "mail")); err != nil {
		t.Fatal(err)
	}
	mail := h.connect("/usr/bin/comms-mail", nil)
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a link: %v", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 || h.desk.count() != 0 {
		t.Fatal("something was made through the link")
	}
}

// "Don't keep a recovery key", answered after the vault locked (the
// screen locked while it was shown): the keyslot goes at the next unlock.
func TestARecoveryKeyNotKeptGoesEvenIfTheVaultLockedMeanwhile(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	g := &gate{entered: make(chan struct{}, 4), release: make(chan struct{})}
	h.d.desktop = g
	mail := h.connect("/usr/bin/comms-mail", nil)
	g.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceNoRecovery)
	done := make(chan error, 1)
	go func() {
		_, err := mail.RequestVault(ctx(t), "mail")
		done <- err
	}()
	<-g.entered // the question
	g.release <- struct{}{}
	<-g.entered // the recovery key, on screen
	h.d.LockAll("the screen locked")
	g.release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	slots, _ := cli.Slots(ctx(t), "mail")
	if len(slots) != 2 {
		t.Fatalf("locked, the vault has %d keyslots", len(slots))
	}
	if _, err := cli.Unlock(ctx(t), "mail", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(newPass)}); err != nil {
		t.Fatal(err)
	}
	slots, _ = cli.Slots(ctx(t), "mail")
	for _, s := range slots {
		if s.Type == svformat.SlotRecovery {
			t.Fatalf("the recovery keyslot is still there: %+v", slots)
		}
	}
}

// Only secretvault's own programs see whom the person told not to ask
// for new vaults: a program that may manage a vault does not.
func TestProgramsDoNotSeeTheNewVaultDecisions(t *testing.T) {
	h := newHarness(t)
	h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceNever)
	mail.RequestVault(ctx(t), "mail")
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	grants, err := mail.Grants(ctx(t), "personal")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.NewVaults {
			t.Fatalf("a program saw %+v", g)
		}
	}
}

// A terminal agent answers for the person: where somebody answers now,
// it is let in by them; and it is asked one thing at a time.
func TestATerminalAgentIsLetInByThePersonAndAskedOneThingAtATime(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	agent := h.connect("/usr/bin/secretvault-tui-prompt", &scripted{})
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if err := agent.RegisterPrompter(ctx(t), "pts/1"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("not let in: %v", err)
	}
	if q := h.desk.questions()[0]; !strings.Contains(q.Description, "Let it only if you started it yourself") || ids(q.Choices) != "once,deny" {
		t.Fatalf("the question: %+v", q)
	}

	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "work", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Put(ctx(t), "work", login("w", "1")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	inFlight, most := 0, 0
	h.procs <- &svpeer.Process{PID: 4243, Exe: "/usr/bin/secretvault-tui-prompt", SystemOwned: true}
	busy, err := secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true,
		Prompter: func(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
			mu.Lock()
			inFlight++
			most = max(most, inFlight)
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			return svrpc.PromptAnswer{Choice: svrpc.ChoiceOnce}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if err := busy.RegisterPrompter(ctx(t), "pts/2"); err != nil {
		t.Fatal(err)
	}
	h.desk.done(t)

	// Two programs asking at once, about two vaults: the agent's
	// terminal is asked one thing, then the other.
	a, b := h.connect("/usr/bin/mail", nil), h.connect("/usr/bin/git", nil)
	var wg sync.WaitGroup
	for _, call := range []func() error{
		func() error { _, err := a.Get(ctx(t), "personal", "mail/imap"); return err },
		func() error { _, err := b.Get(ctx(t), "work", "w"); return err },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := call(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Fatalf("the agent was asked %d things at once", most)
	}
}
