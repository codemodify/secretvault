package svd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// A program asking for a vault of its own (vault.request): the person is
// asked through the daemon's prompter, chooses its passphrase there, and
// sees its recovery key once; the program gets the name, and nothing
// else, and still asks before it uses the vault.

const newPass = "a passphrase for mail"

// logLines collects what the daemon logs.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) add(s string) {
	l.mu.Lock()
	l.lines = append(l.lines, s)
	l.mu.Unlock()
}

func (l *logLines) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func ids(cs []svrpc.Choice) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return strings.Join(out, ",")
}

func TestAProgramAsksForAVaultAndThePersonMakesIt(t *testing.T) {
	logs := &logLines{}
	h := newHarness(t, func(o *Options) { o.Log = logs.add })
	cliTerm := &scripted{}
	cli := h.connect("/usr/bin/secretvault", cliTerm)
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	mail := h.connect("/usr/bin/comms-mail", nil)

	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceWritten)
	var raw json.RawMessage
	if err := mail.Call(ctx(t), svrpc.MVaultRequest, svrpc.VaultRequestParams{Name: "mail"}, &raw); err != nil {
		t.Fatal(err)
	}
	h.desk.done(t)
	// The reply is the vault's name, and nothing else.
	if string(raw) != `{"vault":"mail"}` {
		t.Fatalf("the reply is %s", raw)
	}

	qs := h.desk.questions()
	if len(qs) != 3 {
		t.Fatalf("%d questions", len(qs))
	}
	ask, newp, rec := qs[0], qs[1], qs[2]
	if ask.Kind != svrpc.PromptChoose || ask.Title != `comms-mail wants a new vault called "mail"` ||
		ids(ask.Choices) != "create,never,deny" {
		t.Fatalf("the question: %+v", ask)
	}
	for _, want := range []string{"never sees it", "will still have to ask you before it reads or stores anything", "Program: /usr/bin/comms-mail", "Process: 4242"} {
		if !strings.Contains(ask.Description, want) {
			t.Errorf("the question does not say %q: %q", want, ask.Description)
		}
	}
	for _, c := range ask.Choices {
		if c.Label == "OK" || c.Label == "Yes" {
			t.Errorf("a button says %q", c.Label)
		}
	}
	if newp.Kind != svrpc.PromptNewPassphrase || !strings.Contains(newp.Description, "comms-mail never sees it") {
		t.Fatalf("the passphrase question: %+v", newp)
	}
	if rec.Kind != svrpc.PromptShowSecret || ids(rec.Choices) != "no-recovery,written" || strings.Contains(rec.Description, rec.Show) {
		t.Fatalf("the recovery key's showing: %+v", rec)
	}
	recovery := rec.Show
	if _, err := svformat.ParseRecoveryKey(recovery); err != nil {
		t.Fatalf("what was shown is no recovery key: %v", err)
	}

	// In the data folder, with the default suite, unlocked, not the
	// default; and marked as asked for.
	var info *svrpc.VaultInfo
	vaults, _ := cli.Vaults(ctx(t))
	for i := range vaults {
		if vaults[i].Name == "mail" {
			info = &vaults[i]
		}
	}
	if info == nil || info.Path != filepath.Join(h.home, "vaults", "mail") || info.Suite != svcrypto.Modern.String() ||
		info.Locked || info.Default {
		t.Fatalf("the new vault: %+v", info)
	}

	// The program still asks before it stores anything: nothing was
	// granted to it.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.Put(ctx(t), "mail", login("comms-mail/key", "k")); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a write right after: %v", err)
	}
	if q := h.desk.questions()[3]; q.Kind != svrpc.PromptChoose || !strings.Contains(q.Description, "comms-mail (/usr/bin/comms-mail) wants to change") {
		t.Fatalf("the write was not asked about: %+v", q)
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if _, err := mail.Put(ctx(t), "mail", login("comms-mail/key", "k")); err != nil {
		t.Fatal(err)
	}

	// The passphrase and the recovery key open it; neither is in the
	// reply, the audit logs, the daemon's log or its config.
	h.d.LockAll("test")
	if _, err := cli.Unlock(ctx(t), "mail", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: []byte(newPass)}); err != nil {
		t.Fatalf("the passphrase chosen: %v", err)
	}
	if _, err := cli.Unlock(ctx(t), "mail", &svrpc.Key{Type: svformat.SlotRecovery, Secret: []byte(recovery)}); err != nil {
		t.Fatalf("the recovery key shown: %v", err)
	}
	cliTerm.script("pass:" + string(pass))
	personal, err := cli.Audit(ctx(t), "personal", 0)
	if err != nil {
		t.Fatal(err)
	}
	own, err := cli.Audit(ctx(t), "mail", 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(h.home, "config.json"))
	audits, _ := json.Marshal([]any{personal, own})
	for what, text := range map[string]string{"the reply": string(raw), "the audit logs": string(audits), "the log": logs.all(), "the config": string(cfg)} {
		for _, secret := range []string{newPass, recovery} {
			if strings.Contains(text, secret) {
				t.Errorf("%s holds a secret", what)
			}
		}
	}
	// The request is in both logs, said for people.
	for name, log := range map[string][]svrpc.AuditEntry{"personal": personal, "mail": own} {
		found := false
		for _, e := range log {
			if e.Op == "create-vault" && e.Item == "mail" && e.Outcome == "allowed" && e.Program == "comms-mail (/usr/bin/comms-mail)" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s's audit log does not have the request: %+v", name, log)
		}
	}
	if !strings.Contains(string(cfg), `"requested_by": "comms-mail (/usr/bin/comms-mail)"`) {
		t.Errorf("the config does not say who asked: %s", cfg)
	}
}

func TestARequestRefusedDismissedOrForGood(t *testing.T) {
	h := newHarness(t)
	cliTerm := &scripted{}
	cli := h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	none := func(name string) {
		t.Helper()
		vs, _ := cli.Vaults(ctx(t))
		for _, v := range vs {
			if v.Name == name {
				t.Fatalf("vault %s was made", name)
			}
		}
		if _, err := os.Lstat(filepath.Join(h.home, "vaults", name)); err == nil {
			t.Fatalf("vault %s's folder was made", name)
		}
	}

	// No: denied, and asked again next time.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("no: %v", err)
	}
	none("mail")
	// Dismissed: canceled, not denied.
	h.desk.script("cancel")
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrCanceled) {
		t.Fatalf("dismissed: %v", err)
	}
	// Yes, then no passphrase: canceled, and nothing made.
	h.desk.script("choose:"+svrpc.ChoiceCreate, "cancel")
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrCanceled) {
		t.Fatalf("no passphrase: %v", err)
	}
	none("mail")
	// Too short three times: canceled.
	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:short", "pass:short", "pass:short")
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrCanceled) {
		t.Fatalf("too short: %v", err)
	}
	if q := h.desk.questions(); !strings.Contains(q[len(q)-1].Error, "too short") {
		t.Fatalf("a short passphrase was not said: %+v", q[len(q)-1])
	}
	none("mail")
	h.desk.done(t)

	// Don't ask again: denied now and from then on, without asking.
	h.desk.script("choose:" + svrpc.ChoiceNever)
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("never: %v", err)
	}
	n := h.desk.count()
	if _, err := mail.RequestVault(ctx(t), "other"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("after never: %v", err)
	}
	h.restart()
	cli = h.connect("/usr/bin/secretvault", cliTerm)
	mail = h.connect("/usr/bin/comms-mail", nil)
	if _, err := mail.RequestVault(ctx(t), "other"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("after never, and a restart: %v", err)
	}
	if h.desk.count() != n {
		t.Fatal("asked again after don't ask again")
	}
	// Another program is asked on its own account.
	other := h.connect("/usr/bin/other-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := other.RequestVault(ctx(t), "x"); !errors.Is(err, svrpc.ErrDenied) || h.desk.count() != n+1 {
		t.Fatalf("another program: %v", err)
	}

	// The decision is in every vault's grants, and only secretvault's
	// own programs forget it.
	cliTerm.script("pass:" + string(pass))
	grants, err := cli.Grants(ctx(t), "personal")
	if err != nil {
		t.Fatal(err)
	}
	var g *svrpc.Grant
	for i := range grants {
		if grants[i].NewVaults {
			g = &grants[i]
		}
	}
	if g == nil || g.Program != "comms-mail (/usr/bin/comms-mail)" || g.Decision != "deny-always" || g.Vault != "personal" {
		t.Fatalf("grants: %+v", grants)
	}
	h.desk.script("choose:" + svrpc.ChoiceAlways) // mail may manage the vault...
	if err := mail.Revoke(ctx(t), "personal", g.ID); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("the program forgot its own refusal: %v", err)
	}
	if err := cli.Revoke(ctx(t), "personal", g.ID); err != nil {
		t.Fatal(err)
	}
	if err := cli.Revoke(ctx(t), "personal", g.ID); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("forgotten twice: %v", err)
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatal(err)
	}
	h.desk.done(t)

	// Every request, and how it ended, is in the default vault's log.
	log, err := cli.Audit(ctx(t), "personal", 0)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, e := range log {
		if e.Op == "create-vault" && e.Program == "comms-mail (/usr/bin/comms-mail)" {
			outcomes = append(outcomes, e.Outcome)
		}
	}
	want := "denied,canceled,canceled,canceled,denied,denied,denied,denied"
	if strings.Join(outcomes, ",") != want {
		t.Fatalf("the requests' trail: %v, want %s", outcomes, want)
	}
}

func TestARequestForAVaultThatExistsAsksNobody(t *testing.T) {
	h := newHarness(t)
	h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	if _, err := mail.RequestVault(ctx(t), "personal"); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a registered vault: %v", err)
	}
	// A folder of that name in the data folder (a forgotten vault's).
	if err := os.MkdirAll(filepath.Join(h.home, "vaults", "old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := mail.RequestVault(ctx(t), "old"); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("a folder: %v", err)
	}
	for _, bad := range []string{"", "../evil", "a/b", ".hidden", strings.Repeat("x", 65)} {
		if _, err := mail.RequestVault(ctx(t), bad); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeInvalidParams}) {
			t.Fatalf("name %q: %v", bad, err)
		}
	}
	if h.desk.count() != 0 {
		t.Fatal("somebody was asked")
	}
}

func TestARequestChoosesNoPathSuiteOrPassphrase(t *testing.T) {
	h := newHarness(t)
	h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	elsewhere := filepath.Join(h.home, "elsewhere")
	for _, params := range []map[string]any{
		{"name": "mail", "path": elsewhere},
		{"name": "mail", "suite": "classic"},
		{"name": "mail", "passphrase": []byte("chosen by the program")},
		{"name": "mail", "recovery": false},
		{"name": "mail", "default": true},
	} {
		if err := mail.Call(ctx(t), svrpc.MVaultRequest, params, nil); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeInvalidParams}) {
			t.Fatalf("%v: %v", params, err)
		}
	}
	if _, err := os.Stat(elsewhere); err == nil || h.desk.count() != 0 {
		t.Fatal("a refused request did something")
	}
	// And vault.create, which takes a passphrase, stays secretvault's own.
	if _, err := mail.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "mail", Passphrase: pass}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("vault.create from a program: %v", err)
	}
}

func TestWithNobodyToAskNoVaultIsMade(t *testing.T) {
	h := newHarness(t)
	h.setup()
	h.d.desktop = nil
	mail := h.connect("/usr/bin/comms-mail", nil)
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrNoPrompter) {
		t.Fatalf("nobody to ask: %v", err)
	}
	// The program itself is never the one asked, even secretvault's CLI.
	term := &scripted{}
	cli := h.connect("/usr/bin/secretvault", term)
	if _, err := cli.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrNoPrompter) || term.count() != 0 {
		t.Fatalf("the CLI's request: %v, its terminal asked %d times", err, term.count())
	}
	// A registered terminal agent asks.
	agentTerm := &scripted{}
	agent := h.connect("/usr/bin/secretvault-tui-prompt", agentTerm)
	if err := agent.RegisterPrompter(ctx(t), "pts/1"); err != nil {
		t.Fatal(err)
	}
	agentTerm.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceWritten)
	if v, err := mail.RequestVault(ctx(t), "mail"); err != nil || v != "mail" {
		t.Fatalf("through the agent: %q, %v", v, err)
	}
	agentTerm.done(t)
}

// gate is a prompter whose questions wait until let go.
type gate struct {
	scripted
	entered chan struct{}
	release chan struct{}
}

func (g *gate) Choose(ctx context.Context, q svrpc.PromptAsk) (string, error) {
	g.entered <- struct{}{}
	select {
	case <-g.release:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return g.scripted.Choose(ctx, q)
}

func TestAProgramHasOneRequestWaitingAtATime(t *testing.T) {
	h := newHarness(t)
	h.setup()
	g := &gate{entered: make(chan struct{}, 4), release: make(chan struct{})}
	h.d.desktop = g
	mail := h.connect("/usr/bin/comms-mail", nil)
	again := h.connect("/usr/bin/comms-mail", nil) // the same program, another connection
	other := h.connect("/usr/bin/other-mail", nil)

	g.script("choose:" + svrpc.ChoiceDeny)
	first := make(chan error, 1)
	go func() {
		_, err := mail.RequestVault(ctx(t), "mail")
		first <- err
	}()
	<-g.entered
	for _, c := range []interface {
		RequestVault(context.Context, string) (string, error)
	}{mail, again} {
		if _, err := c.RequestVault(ctx(t), "mail2"); !errors.Is(err, &svrpc.Error{Code: svrpc.CodeFailed}) ||
			!strings.Contains(err.Error(), "not answered yet") {
			t.Fatalf("a second request: %v", err)
		}
	}
	// Another program's waits its turn: one question on screen at a time.
	second := make(chan error, 1)
	g.script("choose:" + svrpc.ChoiceDeny)
	go func() {
		_, err := other.RequestVault(ctx(t), "other")
		second <- err
	}()
	select {
	case <-g.entered:
		t.Fatal("two questions about new vaults were on screen at once")
	case <-time.After(100 * time.Millisecond):
	}
	g.release <- struct{}{}
	if err := <-first; !errors.Is(err, svrpc.ErrDenied) {
		t.Fatal(err)
	}
	<-g.entered
	g.release <- struct{}{}
	if err := <-second; !errors.Is(err, svrpc.ErrDenied) {
		t.Fatal(err)
	}
	// Once answered, the program may ask again.
	g.script("choose:" + svrpc.ChoiceDeny)
	go func() { <-g.entered; g.release <- struct{}{} }()
	if _, err := mail.RequestVault(ctx(t), "mail"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatal(err)
	}
}

func TestTheRecoveryKeyIsKeptUnlessThePersonSaysNot(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	mail := h.connect("/usr/bin/comms-mail", nil)
	recoverySlots := func(vault string) int {
		t.Helper()
		slots, err := cli.Slots(ctx(t), vault)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, s := range slots {
			if s.Type == svformat.SlotRecovery {
				n++
			}
		}
		return n
	}
	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceNoRecovery)
	if _, err := mail.RequestVault(ctx(t), "without"); err != nil {
		t.Fatal(err)
	}
	if n := recoverySlots("without"); n != 0 {
		t.Fatalf("not kept, yet %d recovery keyslots", n)
	}
	// Closed without an answer: it may have been written down.
	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "cancel")
	if _, err := mail.RequestVault(ctx(t), "closed"); err != nil {
		t.Fatal(err)
	}
	if n := recoverySlots("closed"); n != 1 {
		t.Fatalf("closed: %d recovery keyslots", n)
	}
	h.desk.done(t)
}

func TestAVaultAskedForIsNeverMadeTheDefault(t *testing.T) {
	h := newHarness(t)
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceWritten)
	if _, err := mail.RequestVault(ctx(t), "mail"); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		cli := h.connect("/usr/bin/secretvault", &scripted{})
		vs, _ := cli.Vaults(ctx(t))
		if len(vs) != 1 || vs[0].Default {
			t.Fatalf("%s: %+v", when, vs)
		}
		if _, err := mail.Get(ctx(t), "", "x"); !errors.Is(err, svrpc.ErrNoVault) {
			t.Fatalf("%s: the default vault: %v", when, err)
		}
	}
	check("made")
	h.restart()
	mail = h.connect("/usr/bin/comms-mail", nil)
	check("after a restart")
	// The next vault the person makes is the default.
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	vs, _ := cli.Vaults(ctx(t))
	for _, v := range vs {
		if v.Default != (v.Name == "personal") {
			t.Fatalf("defaults: %+v", vs)
		}
	}
}

// An unidentified program (known by its process ID only) cannot be
// remembered: it is offered no "don't ask again".
func TestNoLastingRefusalForAnUnidentifiedProgram(t *testing.T) {
	h := newHarness(t)
	h.setup()
	ghost := h.connectAs(&svpeer.Process{PID: 777, Comm: "ghost"}, nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := ghost.RequestVault(ctx(t), "g"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatal(err)
	}
	q := h.desk.questions()[0]
	if ids(q.Choices) != "create,deny" || !strings.HasPrefix(q.Title, "An unidentified program wants") {
		t.Fatalf("%+v", q)
	}
}
