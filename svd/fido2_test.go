package svd

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svfido"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// rack is the security keys plugged in to a test's daemon: software keys.
type rack struct {
	mu   sync.Mutex
	keys []*fidotest.Authenticator
}

// plug plugs in a software key that takes a moment to be touched, so it
// says it is waiting for the touch as a real one does.
func (r *rack) plug(t *testing.T, o fidotest.Options) *fidotest.Authenticator {
	t.Helper()
	if o.Touch == nil {
		o.Touch = func(ctx context.Context) error {
			select {
			case <-time.After(40 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		o.Keepalive = 10 * time.Millisecond
	}
	a := fidotest.New(o)
	t.Cleanup(a.Stop)
	r.mu.Lock()
	r.keys = append(r.keys, a)
	r.mu.Unlock()
	return a
}

func (r *rack) unplug(a *fidotest.Authenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = slices.DeleteFunc(r.keys, func(k *fidotest.Authenticator) bool { return k == a })
}

func (r *rack) open(ctx context.Context) ([]*svfido.Device, error) {
	r.mu.Lock()
	keys := append([]*fidotest.Authenticator(nil), r.keys...)
	r.mu.Unlock()
	var out []*svfido.Device
	for _, a := range keys {
		t := a.Transport()
		d, err := svfido.NewDevice(ctx, t, a.Name())
		if err != nil {
			t.Close()
			return nil, err
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, svfido.ErrNoDevice
	}
	return out, nil
}

// withTerminal creates the default vault from a CLI whose terminal
// answers from term, and stores one item.
func (h *harness) withTerminal(term *scripted) *secretvault.Client {
	h.t.Helper()
	cli := h.connect("/usr/bin/secretvault", term)
	if _, err := cli.CreateVault(ctx(h.t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		h.t.Fatal(err)
	}
	if _, err := cli.Put(ctx(h.t), "", login("mail/imap", "hunter2")); err != nil {
		h.t.Fatal(err)
	}
	return cli
}

func addKey(t *testing.T, cli *secretvault.Client, uv *bool) svrpc.SlotInfo {
	t.Helper()
	info, err := cli.AddSlot(ctx(t), svrpc.SlotAddParams{Type: svformat.SlotFIDO2, UV: uv})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestASecurityKeyIsAddedAndUnlocksTheVault(t *testing.T) {
	h := newHarness(t)
	term := &scripted{}
	cli := h.withTerminal(term)
	key := h.keys.plug(t, fidotest.Options{Name: "YubiKey 5", PIN: "123456"})

	term.script("pass:123456")
	info := addKey(t, cli, nil)
	if info.Type != svformat.SlotFIDO2 || info.Label != "YubiKey 5" || !strings.HasPrefix(info.Detail, "PIN and touch, model ") {
		t.Fatalf("slot %+v", info)
	}
	q := term.questions()
	if len(q) != 1 || q[0].Kind != svrpc.PromptPIN || q[0].Prompt != "PIN:" ||
		!strings.Contains(q[0].Description, "asks to add a security key to vault \"personal\"") ||
		!strings.Contains(q[0].Description, "YubiKey 5") || !strings.Contains(q[0].Description, "8 more wrong PINs") {
		t.Fatalf("asked %+v", q)
	}
	told := term.told()
	if len(told) != 2 || !strings.Contains(told[0].Description, "(1 of 2)") || !strings.Contains(told[1].Description, "(2 of 2)") ||
		told[0].Kind != svrpc.PromptNotice {
		t.Fatalf("told %+v", told)
	}
	if key.Touches() != 2 {
		t.Fatalf("%d touches to enrol", key.Touches())
	}
	slots, _ := cli.Slots(ctx(t), "")
	if len(slots) != 2 || slots[1].Type != svformat.SlotFIDO2 {
		t.Fatalf("slots %+v", slots)
	}

	// secretvault unlock --fido2
	h.d.LockAll("test")
	term.script("pass:123456")
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: svformat.SlotFIDO2}); err != nil {
		t.Fatal(err)
	}
	if e, err := cli.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("Get after the key unlocked: %v", err)
	}
	if key.Touches() != 3 || len(term.told()) != 3 || h.desk.count() != 0 {
		t.Fatalf("unlocking: %d touches, told %d times, desktop asked %d", key.Touches(), len(term.told()), h.desk.count())
	}
	term.done(t)

	// Enrolling the same key again is refused, without a touch.
	if _, err := cli.AddSlot(ctx(t), svrpc.SlotAddParams{Type: svformat.SlotFIDO2}); err == nil ||
		!strings.Contains(err.Error(), "already a keyslot") || key.Touches() != 3 {
		t.Fatalf("the same key again: %v", err)
	}
}

func TestThePluggedInKeyIsTriedBeforeThePassphrase(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	key := h.keys.plug(t, fidotest.Options{Name: "Solo"})
	no := false
	if info := addKey(t, cli, &no); info.Detail[:5] != "touch" {
		t.Fatalf("a key without a PIN: %+v", info)
	}
	h.d.LockAll("test")

	// Another program asks: the desktop says to touch the key, and asks
	// nothing; the unlock is consent for this request.
	mail := h.connect("/usr/bin/mail", nil)
	if e, err := mail.Get(ctx(t), "", "mail/imap"); err != nil || secretOf(e) != "hunter2" {
		t.Fatalf("Get: %v", err)
	}
	told := h.desk.told()
	if h.desk.count() != 0 || len(told) != 1 || !strings.Contains(told[0].Description, "mail (/usr/bin/mail) wants to read") ||
		!strings.Contains(told[0].Description, "Touch your security key. (Solo)") {
		t.Fatalf("asked %+v, told %+v", h.desk.questions(), told)
	}

	// Without the key, the passphrase, as ever.
	h.keys.unplug(key)
	h.d.LockAll("test")
	h.desk.script("pass:" + string(pass))
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if q := h.desk.questions(); len(q) != 1 || q[0].Kind != svrpc.PromptPassphrase || q[0].Error != "" {
		t.Fatalf("without the key: %+v", q)
	}

	// With someone else's key, the passphrase too, and that key is never
	// touched: it was only asked, silently, whether it holds the vault's.
	other := h.keys.plug(t, fidotest.Options{Name: "theirs"})
	h.d.LockAll("test")
	h.desk.script("pass:" + string(pass))
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if other.Touches() != 0 || other.Count("probe") == 0 || len(h.desk.told()) != 1 {
		t.Fatalf("the other key: %d touches, %d probes", other.Touches(), other.Count("probe"))
	}
	h.desk.done(t)
}

func TestWrongPINsAreCountedAloudThenThePassphraseIsAsked(t *testing.T) {
	h := newHarness(t)
	term := &scripted{}
	cli := h.withTerminal(term)
	key := h.keys.plug(t, fidotest.Options{Name: "Key", PIN: "2468"})
	term.script("pass:2468")
	addKey(t, cli, nil)
	h.d.LockAll("test")

	mail := h.connect("/usr/bin/mail", nil)
	h.desk.script("pass:1111", "pass:2222", "pass:3333", "pass:"+string(pass))
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	q := h.desk.questions()
	if len(q) != 4 {
		t.Fatalf("asked %d questions: %+v", len(q), q)
	}
	for i, want := range []string{"", "Wrong PIN. 7 tries left", "Wrong PIN. 6 tries left"} {
		if q[i].Kind != svrpc.PromptPIN || !strings.HasPrefix(q[i].Error, want) {
			t.Errorf("question %d: %s %q", i, q[i].Kind, q[i].Error)
		}
	}
	if !strings.Contains(q[0].Description, "8 more wrong PINs") || !strings.Contains(q[0].Description, "wants to read") ||
		strings.Contains(q[1].Description, "wants to read") {
		t.Errorf("the first PIN prompt says %q; the second %q", q[0].Description, q[1].Description)
	}
	if q[3].Kind != svrpc.PromptPassphrase || !strings.Contains(q[3].Error, "The security key did not open the vault") ||
		!strings.Contains(q[3].Error, "unplug the security key") || !strings.Contains(q[3].Error, "5 tries left") {
		t.Fatalf("then: %s %q", q[3].Kind, q[3].Error)
	}
	if key.Retries() != 5 {
		t.Fatalf("the key has %d tries left", key.Retries())
	}

	// Calling the PIN prompt off goes to the passphrase, without a word.
	key.PowerCycle()
	h.d.LockAll("test")
	h.desk.script("cancel", "pass:"+string(pass))
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	q = h.desk.questions()
	if last := q[len(q)-1]; last.Kind != svrpc.PromptPassphrase || last.Error != "" {
		t.Fatalf("after cancelling: %s %q", last.Kind, last.Error)
	}
	h.desk.done(t)
}

// On the desktop, "touch your security key" has a Cancel button: pressing
// it stops the key waiting and asks for the passphrase instead.
func TestCallingOffTheTouchAsksForThePassphrase(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	var nobody atomic.Bool // nobody touches the key
	key := h.keys.plug(t, fidotest.Options{Name: "Solo", Keepalive: 10 * time.Millisecond, Touch: func(ctx context.Context) error {
		if !nobody.Load() {
			select {
			case <-time.After(30 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}})
	addKey(t, cli, nil)
	nobody.Store(true)
	h.d.LockAll("test")

	h.desk.mu.Lock()
	h.desk.dismiss = true
	h.desk.mu.Unlock()
	h.desk.script("pass:" + string(pass))
	mail := h.connect("/usr/bin/mail", nil)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if q := h.desk.questions(); len(q) != 1 || q[0].Kind != svrpc.PromptPassphrase || q[0].Error != "" {
		t.Fatalf("asked %+v", q)
	}
	if key.Count("cancel") != 1 {
		t.Fatalf("the key heard %d cancels", key.Count("cancel"))
	}
}

// A vault whose passphrase slot was removed, leaving the key: nobody is
// asked for a passphrase that could not open it.
func TestAVaultWithOnlyAKeyIsNotOpenedByPassphrase(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	key := h.keys.plug(t, fidotest.Options{Name: "Solo"})
	addKey(t, cli, nil)
	slots, _ := cli.Slots(ctx(t), "")
	if err := cli.RemoveSlot(ctx(t), "", slots[0].ID); err != nil {
		t.Fatal(err)
	}
	h.keys.unplug(key)
	h.d.LockAll("test")
	mail := h.connect("/usr/bin/mail", nil)
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrLocked) || !strings.Contains(err.Error(), "plug in its security key") {
		t.Fatalf("without the key: %v", err)
	}
	if h.desk.count() != 0 {
		t.Fatal("a passphrase was asked for")
	}
	h.keys.plug(t, fidotest.Options{Name: "Solo again"}) // someone else's
	if _, err := mail.Get(ctx(t), "", "mail/imap"); !errors.Is(err, svrpc.ErrLocked) {
		t.Fatalf("with another key: %v", err)
	}
	h.keys.mu.Lock()
	h.keys.keys = append(h.keys.keys, key)
	h.keys.mu.Unlock()
	if _, err := mail.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatalf("with the key: %v", err)
	}
}

func TestANewTerminalProvesItselfWithTheKey(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	h.keys.plug(t, fidotest.Options{Name: "Solo"})
	addKey(t, cli, nil)

	// The vault is unlocked; a second terminal proves itself with a touch.
	term := &scripted{}
	cli2 := h.connect("/usr/bin/secretvault", term)
	if _, err := cli2.Get(ctx(t), "", "mail/imap"); err != nil {
		t.Fatal(err)
	}
	if len(term.questions()) != 0 || len(term.told()) != 1 || !strings.Contains(term.told()[0].Description, "This terminal has not used vault") {
		t.Fatalf("asked %+v, told %+v", term.questions(), term.told())
	}
}

func TestAKeyThatIsNotHereSaysSo(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	if _, err := cli.AddSlot(ctx(t), svrpc.SlotAddParams{Type: svformat.SlotFIDO2}); !errors.Is(err, svrpc.ErrNotFound) ||
		!strings.Contains(err.Error(), "no security key is plugged in") {
		t.Fatalf("no key to enrol: %v", err)
	}
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: svformat.SlotFIDO2}); err == nil {
		t.Fatal("a vault with no fido2 slot was unlocked with a key")
	}
	h.keys.plug(t, fidotest.Options{Name: "U2F only", NoHMAC: true})
	if _, err := cli.AddSlot(ctx(t), svrpc.SlotAddParams{Type: svformat.SlotFIDO2}); err == nil || !strings.Contains(err.Error(), "hmac-secret") {
		t.Fatalf("a key without hmac-secret: %v", err)
	}
}

func TestTheKeysPluggedInAreListed(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	if keys, err := cli.SecurityKeys(ctx(t)); err != nil || len(keys) != 0 {
		t.Fatalf("none plugged in: %+v, %v", keys, err)
	}
	h.keys.plug(t, fidotest.Options{Name: "A", PIN: "1234", AAGUID: [16]byte{0xcb, 0x69, 0x48, 0x1e}})
	h.keys.plug(t, fidotest.Options{Name: "B", CTAP20: true, NoHMAC: true})
	keys, err := cli.SecurityKeys(ctx(t))
	if err != nil || len(keys) != 2 {
		t.Fatalf("%+v, %v", keys, err)
	}
	a, b := keys[0], keys[1]
	if a.Name != "A" || a.PIN != "set" || a.Retries != 8 || !a.HMACSecret || a.Problem != "" ||
		a.AAGUID != "cb69481e-0000-0000-0000-000000000000" || !slices.Contains(a.Versions, "FIDO_2_1") {
		t.Fatalf("A: %+v", a)
	}
	if b.PIN != "not set" || b.HMACSecret || !strings.Contains(b.Problem, "hmac-secret") {
		t.Fatalf("B: %+v", b)
	}
}

func TestARotationSaysWhichKeysMustBeAddedAgain(t *testing.T) {
	h := newHarness(t)
	cli := h.withTerminal(&scripted{})
	h.keys.plug(t, fidotest.Options{Name: "Solo"})
	slot := addKey(t, cli, nil)
	res, err := cli.Rotate(ctx(t), svrpc.RotateParams{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].ID != slot.ID {
		t.Fatalf("dropped %+v", res.Dropped)
	}
}
