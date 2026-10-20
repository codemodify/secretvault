//go:build linux

package svd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svrpc"
)

// ssHarness is a daemon serving the Secret Service on a private bus, with
// a "personal" vault (the default) and a scripted desktop prompt. Real
// clients (secret-tool, libsecret through Python) talk to it.
type ssHarness struct {
	*harness
	bus *svdbus.Conn
}

func newSSHarness(t *testing.T) *ssHarness {
	t.Helper()
	dbustest.PrivateBus(t)
	h := newHarness(t)
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	// Programs on the bus are identified by the bus's own credentials,
	// not by the harness's stand-in for socket clients.
	bus, err := svdbus.ConnectSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bus.Close() })
	c, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := h.d.ServeSecretService(c, bus, false); err != nil {
		t.Fatal(err)
	}
	return &ssHarness{harness: h, bus: bus}
}

func need(t *testing.T, bin string) string {
	p, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("%s is not installed", bin)
	}
	return p
}

// run runs a real client with the private bus in its environment.
func run(t *testing.T, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = os.Environ()
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-c.Done():
		cmd.Process.Kill()
		<-done
		t.Fatalf("%s %v hung", name, args)
	}
	return string(out), err
}

func TestSecretToolStoresAndReadsBackWithOneConsent(t *testing.T) {
	st := need(t, "secret-tool")
	h := newSSHarness(t)
	// Storing: secret-tool is asked about once, as a program that wants to
	// change the vault.
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if out, err := run(t, "s3cr3t-pa55", st, "store", "--label=Test login", "service", "myapp", "username", "alice"); err != nil {
		t.Fatalf("secret-tool store: %v\n%s", err, out)
	}
	if n := h.desk.count(); n != 1 || !strings.Contains(h.desk.asked[0].Description, "secret-tool") {
		t.Fatalf("prompts: %+v", h.desk.asked)
	}
	// Reading back: the program that stored it may read it, unasked.
	out, err := run(t, "", st, "lookup", "service", "myapp", "username", "alice")
	if err != nil || out != "s3cr3t-pa55" {
		t.Fatalf("secret-tool lookup = %q, %v", out, err)
	}
	if h.desk.count() != 1 {
		t.Fatal("reading back its own secret prompted")
	}
	// The item is an ordinary item: the CLI's view of it.
	term := &scripted{}
	term.script("pass:" + string(pass))
	cli := h.connect("/usr/bin/secretvault", term)
	e, err := cli.Get(ctx(t), "", "Test login")
	if err != nil || secretField(e) != "s3cr3t-pa55" || e.Item.Attrs["service"] != "myapp" {
		t.Fatalf("the item as the CLI sees it: %+v, %v", e, err)
	}
	// Deleting: allowed to the program that made it.
	if out, err := run(t, "", st, "clear", "service", "myapp", "username", "alice"); err != nil {
		t.Fatalf("secret-tool clear: %v\n%s", err, out)
	}
	if _, err := cli.Get(ctx(t), "", "Test login"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("after clear: %v", err)
	}
}

func secretField(e svrpc.Entry) string {
	for _, f := range e.Item.Fields {
		if f.Name == "secret" || f.Name == "password" {
			return string(f.Value)
		}
	}
	return ""
}

const pyLookup = `
import sys, gi
gi.require_version("Secret", "1")
from gi.repository import Secret
schema = Secret.Schema.new("org.example.Test", Secret.SchemaFlags.DONT_MATCH_NAME,
    {"service": Secret.SchemaAttributeType.STRING, "username": Secret.SchemaAttributeType.STRING})
pw = Secret.password_lookup_sync(schema, {"service": "myapp", "username": "alice"}, None)
print("NONE" if pw is None else pw, end="")
`

func pythonLibsecret(t *testing.T) string {
	py := need(t, "python3")
	if out, err := exec.Command(py, "-c", `import gi; gi.require_version("Secret", "1")`).CombinedOutput(); err != nil {
		t.Skipf("python3 has no libsecret bindings: %s", out)
	}
	script := filepath.Join(t.TempDir(), "lookup.py")
	os.WriteFile(script, []byte(pyLookup), 0o600)
	return script
}

func TestAnotherProgramMustBeAllowed(t *testing.T) {
	st := need(t, "secret-tool")
	script := pythonLibsecret(t)
	h := newSSHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if out, err := run(t, "s3cr3t-pa55", st, "store", "--label=Test login", "service", "myapp", "username", "alice"); err != nil {
		t.Fatalf("store: %v\n%s", err, out)
	}

	// A different program: the item is locked to it until the person says so.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	out, err := run(t, "", "python3", script)
	if err != nil || out != "NONE" {
		t.Fatalf("denied lookup = %q, %v", out, err)
	}
	q := h.desk.asked[len(h.desk.asked)-1]
	if !strings.Contains(q.Description, "lookup.py") || !strings.Contains(q.Description, "wants to read") {
		t.Fatalf("the consent prompt said %q", q.Description)
	}

	h.desk.script("choose:" + svrpc.ChoiceLock)
	if out, err := run(t, "", "python3", script); err != nil || out != "s3cr3t-pa55" {
		t.Fatalf("allowed lookup = %q, %v", out, err)
	}
	// Allowed until the vault locks: no prompt the second time.
	before := h.desk.count()
	if out, _ := run(t, "", "python3", script); out != "s3cr3t-pa55" || h.desk.count() != before {
		t.Fatalf("second lookup = %q with %d new prompts", out, h.desk.count()-before)
	}
	h.desk.done(t)
}

func TestALockedVaultIsUnlockedWhenAProgramLooks(t *testing.T) {
	st := need(t, "secret-tool")
	h := newSSHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	if out, err := run(t, "v", st, "store", "--label=x", "service", "s"); err != nil {
		t.Fatalf("store: %v\n%s", err, out)
	}
	h.d.LockAll("test")
	// secret-tool searches; every vault is locked, so the person is asked
	// for the default vault's passphrase, naming the program.
	h.desk.script("pass:" + string(pass))
	out, err := run(t, "", st, "lookup", "service", "s")
	if err != nil || out != "v" {
		t.Fatalf("lookup after lock = %q, %v", out, err)
	}
	q := h.desk.asked[len(h.desk.asked)-1]
	if q.Kind != svrpc.PromptPassphrase || !strings.Contains(q.Description, "secret-tool") {
		t.Fatalf("unlock prompt %+v", q)
	}
}

// A client of our own, over a plain session, for the protocol's edges.
func TestSessionsAndLocksAreEnforcedPerCaller(t *testing.T) {
	st := need(t, "secret-tool")
	h := newSSHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if out, err := run(t, "v", st, "store", "--label=x", "service", "s"); err != nil {
		t.Fatalf("store: %v\n%s", err, out)
	}
	c, err := svdbus.ConnectSession()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	call := func(path svdbus.ObjectPath, iface, member string, args ...any) (*svdbus.Message, error) {
		return c.Call(ctx(t), ssBusName, path, iface, member, args...)
	}
	r, err := call(ssRoot, ifService, "OpenSession", "plain", svdbus.MakeVariant(""))
	if err != nil {
		t.Fatal(err)
	}
	var out svdbus.Variant
	var session svdbus.ObjectPath
	r.Decode(&out, &session)
	r, err = call(ssRoot, ifService, "SearchItems", map[string]string{"service": "s"})
	if err != nil {
		t.Fatal(err)
	}
	var unlocked, locked []svdbus.ObjectPath
	r.Decode(&unlocked, &locked)
	if len(unlocked) != 0 || len(locked) != 1 {
		t.Fatalf("this client found unlocked %v, locked %v", unlocked, locked)
	}
	// Reading an item it was not allowed: IsLocked.
	if _, err := call(locked[0], ifItem, "GetSecret", session); !isDBusError(err, errIsLocked) {
		t.Fatalf("GetSecret without consent: %v", err)
	}
	// Someone else's session: refused.
	if _, err := call(ssRoot, ifService, "GetSecrets", locked, svdbus.ObjectPath(ssSessions+"999")); !isDBusError(err, errNoSession) {
		t.Fatalf("a session that is not ours: %v", err)
	}
	// Unlock gives a prompt; Dismiss completes it as dismissed.
	r, err = call(ssRoot, ifService, "Unlock", locked)
	if err != nil {
		t.Fatal(err)
	}
	var done []svdbus.ObjectPath
	var prompt svdbus.ObjectPath
	r.Decode(&done, &prompt)
	if len(done) != 0 || prompt == ssNoPrompt {
		t.Fatalf("Unlock = %v, %s", done, prompt)
	}
	sub, err := c.Subscribe(ctx(t), svdbus.MatchRule{Type: svdbus.TypeSignal, Path: prompt, Interface: ifPrompt, Member: "Completed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := call(prompt, ifPrompt, "Dismiss"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-sub.C:
		var dismissed bool
		var result svdbus.Variant
		if m.Decode(&dismissed, &result) != nil || !dismissed {
			t.Fatalf("Completed = %v", m.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no Completed signal")
	}
}

func isDBusError(err error, name string) bool {
	var e *svdbus.Error
	return errors.As(err, &e) && e.Name == name
}

func TestAnotherKeyringHoldingTheNameIsReported(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	other, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.RequestName(ctx(t), ssBusName, svdbus.NameDoNotQueue); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	bus, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := h.d.ServeSecretService(context.Background(), bus, false); !errors.Is(err, ErrSecretServiceTaken) {
		t.Fatalf("err = %v", err)
	}
}

func TestAQueuedDaemonTakesOverWhenTheOtherKeyringLetsGo(t *testing.T) {
	addr := dbustest.PrivateBus(t)
	other, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.RequestName(ctx(t), ssBusName, 0); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	bus, err := svdbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := h.d.ServeSecretService(context.Background(), bus, true); err != nil {
		t.Fatal(err)
	}
	other.Close() // the old keyring stops
	deadline := time.Now().Add(5 * time.Second)
	for {
		owner, _ := bus.GetNameOwner(ctx(t), ssBusName)
		if owner == bus.UniqueName() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the name went to %q, not us", owner)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
