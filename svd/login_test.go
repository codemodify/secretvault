package svd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// fakeSealer stands in for the OS: it "seals" by XOR with a machine key,
// bound to the name, and can be told to fail.
type fakeSealer struct {
	machine []byte
	broken  bool
}

func (f *fakeSealer) Name() string { return "the test's sealer" }

func (f *fakeSealer) Available() error {
	if f.broken {
		return errors.New("no sealing here")
	}
	return nil
}

func (f *fakeSealer) xor(b []byte) []byte {
	out := bytes.Clone(b)
	for i := range out {
		out[i] ^= f.machine[i%len(f.machine)]
	}
	return out
}

func (f *fakeSealer) Seal(name string, secret []byte) ([]byte, error) {
	return f.xor(append([]byte(name+":"), secret...)), nil
}

func (f *fakeSealer) Unseal(name string, sealed []byte) ([]byte, error) {
	if f.broken {
		return nil, errors.New("the TPM said no")
	}
	rest, ok := bytes.CutPrefix(f.xor(sealed), []byte(name+":"))
	if !ok {
		return nil, errors.New("sealed under another name")
	}
	return rest, nil
}

func TestAVaultSetToOpenAtLoginOpensWithoutAsking(t *testing.T) {
	h := newHarness(t)
	sealer := &fakeSealer{machine: []byte("this machine, this user")}
	h.opts.Sealer = sealer
	h.restart()
	cli := h.setup()

	v, err := cli.SetLoginUnlock(ctx(t), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !v.LoginUnlock || v.AutoLock != (svrpc.AutoLock{}) {
		t.Fatalf("after turning it on: %+v", v)
	}
	slots, _ := cli.Slots(ctx(t), "")
	login := 0
	for _, s := range slots {
		if s.Label == "login" && s.Type == svformat.SlotKeyfile {
			login++
		}
	}
	if login != 1 {
		t.Fatalf("login slots: %+v", slots)
	}
	if _, err := cli.SetLoginUnlock(ctx(t), "", true); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("turning it on twice: %v", err)
	}

	// The next session: the daemon starts, and the vault is open before
	// anyone asks; programs still need consent.
	h.restart()
	h.d.UnlockAtLogin()
	cli = h.connect("/usr/bin/secretvault", &scripted{})
	vs, _ := cli.Vaults(ctx(t))
	if len(vs) != 1 || vs[0].Locked {
		t.Fatalf("after login: %+v", vs)
	}
	app := h.connect("/usr/bin/mail-client", nil)
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if e, err := app.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("a program after login: %v", err)
	}
	if h.desk.count() != 1 {
		t.Fatal("a program read without being asked about")
	}

	// A key the OS will not open leaves the vault locked, and says why.
	var logged []string
	h.opts.Log = func(s string) { logged = append(logged, s) }
	h.restart()
	sealer.broken = true
	h.d.UnlockAtLogin()
	sealer.broken = false
	if vs, _ := h.connect("/usr/bin/secretvault", &scripted{}).Vaults(ctx(t)); !vs[0].Locked || len(logged) == 0 {
		t.Fatalf("a refused key: locked %v, log %q", vs[0].Locked, logged)
	}

	// Turning it off takes the slot and the sealed key away.
	cli = h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: "passphrase", Secret: pass}); err != nil {
		t.Fatal(err)
	}
	v, err = cli.SetLoginUnlock(ctx(t), "", false)
	if err != nil || v.LoginUnlock || v.AutoLock != DefaultAutoLock {
		t.Fatalf("turning it off: %+v, %v", v, err)
	}
	if files, _ := filepath.Glob(filepath.Join(h.home, "login", "*")); len(files) != 0 {
		t.Fatalf("sealed keys left: %v", files)
	}
	slots, _ = cli.Slots(ctx(t), "")
	for _, s := range slots {
		if s.Label == "login" {
			t.Fatal("the login slot stayed")
		}
	}
}

func TestOnlySecretvaultTurnsOnOpeningAtLogin(t *testing.T) {
	h := newHarness(t)
	h.opts.Sealer = &fakeSealer{machine: []byte("m")}
	h.restart()
	h.setup()
	if _, err := h.connect("/usr/bin/some-app", nil).SetLoginUnlock(ctx(t), "", true); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("another program: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.home, "login")); err == nil {
		t.Fatal("a refused request left a sealed key")
	}
}

func TestNoSealingMeansNoLoginUnlock(t *testing.T) {
	h := newHarness(t)
	h.opts.Sealer = &fakeSealer{machine: []byte("m"), broken: true}
	h.restart()
	cli := h.setup()
	if _, err := cli.SetLoginUnlock(ctx(t), "", true); err == nil {
		t.Fatal("login unlock without a sealer")
	}
	if slots, _ := cli.Slots(ctx(t), ""); len(slots) != 1 {
		t.Fatalf("a failed attempt added a slot: %+v", slots)
	}
}
