package svfido_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svfido"
)

const rpID = "secretvault:"

var salt = bytes.Repeat([]byte{0x5a}, 32)

// person answers Keys' prompts from a script, and remembers what it was
// told.
type person struct {
	mu      sync.Mutex
	pins    []string // typed, in order; "" cancels
	asked   []string // "pin <key> <retries> <problem>"
	notices []string
	// onNotice, when set, runs for each notice (to call it off, say).
	onNotice func(cancel func())
}

func (p *person) PIN(_ context.Context, key string, retries int, problem string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, fmt.Sprintf("pin %s %d %s", key, retries, problem))
	if len(p.pins) == 0 {
		return nil, errors.New("test: a PIN was asked for and none was scripted")
	}
	pin := p.pins[0]
	p.pins = p.pins[1:]
	return []byte(pin), nil
}

func (p *person) Touch(_ context.Context, key, what string, cancel func()) func() {
	p.mu.Lock()
	p.notices = append(p.notices, key+": "+what)
	f := p.onNotice
	p.mu.Unlock()
	if f != nil {
		f(cancel)
	}
	return func() {}
}

func (p *person) questions() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.asked...)
}

func (p *person) told() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.notices...)
}

func plug(t *testing.T, o fidotest.Options) *fidotest.Authenticator {
	t.Helper()
	a := fidotest.New(o)
	t.Cleanup(a.Stop)
	return a
}

// keys is Keys over software keys: each Open opens a fresh handle on
// each, as a real Open would.
func keys(p svfido.Prompts, auths ...*fidotest.Authenticator) *svfido.Keys {
	return &svfido.Keys{
		Prompts: p,
		Open: func(ctx context.Context) ([]*svfido.Device, error) {
			var out []*svfido.Device
			for _, a := range auths {
				t := a.Transport()
				d, err := svfido.NewDevice(ctx, t, a.Name())
				if err != nil {
					t.Close()
					return nil, err
				}
				out = append(out, d)
			}
			return out, nil
		},
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func no() *bool  { f := false; return &f }
func yes() *bool { t := true; return &t }

// touchAfter is a person who takes d to touch the key.
func touchAfter(d time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestEnrollThenEvaluateWithoutAPIN(t *testing.T) {
	for _, o := range []fidotest.Options{{Name: "CTAP 2.1"}, {Name: "CTAP 2.0", CTAP20: true}, {Name: "protocol 1 only", Protocols: []int{1}}} {
		t.Run(o.Name, func(t *testing.T) {
			// Slow enough that the key says it waits for the touch.
			o.Touch, o.Keepalive = touchAfter(60*time.Millisecond), 10*time.Millisecond
			a := plug(t, o)
			p := &person{}
			k := keys(p, a)
			e, err := k.Enroll(ctx(t), rpID, nil, salt, nil)
			if err != nil {
				t.Fatal(err)
			}
			if e.UV || len(e.Output) != 32 || e.RPID != rpID || !bytes.Equal(e.Salt, salt) || e.Name != o.Name {
				t.Fatalf("enrolment %+v", e)
			}
			if a.Touches() != 2 {
				t.Fatalf("enrolment took %d touches, want 2", a.Touches())
			}
			i, out, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential})
			if err != nil || i != 0 || !bytes.Equal(out, e.Output) {
				t.Fatalf("Evaluate = %d, %x, %v; enrolled %x", i, out, err, e.Output)
			}
			if len(p.questions()) != 0 {
				t.Fatalf("a key without a PIN asked for one: %v", p.questions())
			}
			if n := len(p.told()); n != 3 {
				t.Fatalf("told to touch %d times, want 3: %v", n, p.told())
			}
			// Another salt, another secret.
			other := e.Credential
			other.Salt = bytes.Repeat([]byte{1}, 32)
			if _, out2, err := k.Evaluate(ctx(t), []svfido.Credential{other}); err != nil || bytes.Equal(out2, out) {
				t.Fatalf("another salt gave %x, %v", out2, err)
			}
		})
	}
}

func TestAKeyWithAPINIsUsedWithItByDefault(t *testing.T) {
	for _, o := range []fidotest.Options{{Name: "CTAP 2.1", PIN: "1234"}, {Name: "CTAP 2.0", CTAP20: true, PIN: "1234"}} {
		t.Run(o.Name, func(t *testing.T) {
			a := plug(t, o)
			p := &person{pins: []string{"1234", "1234"}}
			k := keys(p, a)
			e, err := k.Enroll(ctx(t), rpID, nil, salt, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !e.UV {
				t.Fatal("a key with a PIN was enrolled without it")
			}
			_, out, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential})
			if err != nil || !bytes.Equal(out, e.Output) {
				t.Fatalf("Evaluate = %x, %v", out, err)
			}
			if q := p.questions(); len(q) != 2 || q[0] != "pin "+o.Name+" 8 " {
				t.Fatalf("asked %q", q)
			}
			// Without the PIN, the key's other secret answers: no match.
			noPIN := e.Credential
			noPIN.UV = false
			if _, out2, err := k.Evaluate(ctx(t), []svfido.Credential{noPIN}); err != nil || bytes.Equal(out2, out) {
				t.Fatalf("without the PIN: %x, %v", out2, err)
			}
		})
	}
}

func TestAKeyWithAPINCanBeEnrolledWithoutIt(t *testing.T) {
	a := plug(t, fidotest.Options{PIN: "1234"})
	p := &person{}
	k := keys(p, a)
	e, err := k.Enroll(ctx(t), rpID, no(), salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.UV || len(p.questions()) != 0 {
		t.Fatalf("UV %v, asked %v", e.UV, p.questions())
	}
	if _, _, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential}); err != nil {
		t.Fatal(err)
	}

	// A CTAP 2.0 key with a PIN wants it to make any credential, but the
	// credential is still used without it.
	a20 := plug(t, fidotest.Options{CTAP20: true, PIN: "1234"})
	p = &person{pins: []string{"1234"}}
	k = keys(p, a20)
	if e, err = k.Enroll(ctx(t), rpID, no(), salt, nil); err != nil || e.UV {
		t.Fatalf("CTAP 2.0 without UV: %+v, %v", e, err)
	}
	if _, _, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential}); err != nil || len(p.questions()) != 1 {
		t.Fatalf("Evaluate: %v, asked %v", err, p.questions())
	}
}

func TestWhatAKeyCannotDoIsSaidPlainly(t *testing.T) {
	k := keys(&person{}, plug(t, fidotest.Options{}))
	if _, err := k.Enroll(ctx(t), rpID, yes(), salt, nil); err == nil || !strings.Contains(err.Error(), "has no PIN yet") {
		t.Fatalf("--uv on a key without a PIN: %v", err)
	}
	k = keys(&person{}, plug(t, fidotest.Options{NoHMAC: true}))
	if _, err := k.Enroll(ctx(t), rpID, nil, salt, nil); !errors.Is(err, svfido.ErrNoHMACSecret) {
		t.Fatalf("no hmac-secret: %v", err)
	}
	k = keys(&person{pins: []string{"1234", "1234"}}, plug(t, fidotest.Options{PIN: "1234", AlwaysUV: true}))
	if _, err := k.Enroll(ctx(t), rpID, no(), salt, nil); err == nil || !strings.Contains(err.Error(), "every use") {
		t.Fatalf("--no-uv on an alwaysUv key: %v", err)
	}
	if e, err := k.Enroll(ctx(t), rpID, nil, salt, nil); err != nil || !e.UV {
		t.Fatalf("an alwaysUv key: %+v, %v", e, err)
	}
	k = keys(&person{})
	if _, err := k.Enroll(ctx(t), rpID, nil, salt, nil); !errors.Is(err, svfido.ErrNoDevice) {
		t.Fatalf("no key: %v", err)
	}
}

func TestAWrongPINSaysHowManyTriesAreLeft(t *testing.T) {
	a := plug(t, fidotest.Options{PIN: "4321", Name: "key"})
	p := &person{pins: []string{"4321", "4321"}}
	k := keys(p, a)
	e, err := k.Enroll(ctx(t), rpID, nil, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.pins, p.asked = []string{"12", "1111", "4321"}, nil
	if _, _, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential}); err != nil {
		t.Fatal(err)
	}
	q := p.questions()
	if len(q) != 3 || !strings.Contains(q[1], "Nothing was used up") || !strings.HasPrefix(q[1], "pin key 8 ") ||
		q[2] != "pin key 7 Wrong PIN. 7 tries left before the key blocks its PIN for good." {
		t.Fatalf("asked:\n%s", strings.Join(q, "\n"))
	}
	if a.Retries() != 8 {
		t.Fatalf("the right PIN left %d retries", a.Retries())
	}

	// Three wrong in a row: stop, and say what to do.
	p.pins, p.asked = []string{"1111", "2222", "3333", "4321"}, nil
	_, _, err = k.Evaluate(ctx(t), []svfido.Credential{e.Credential})
	if !errors.Is(err, svfido.StatusPINAuthBlocked) || !strings.Contains(err.Error(), "unplug the security key and plug it in again") ||
		!strings.Contains(err.Error(), "5 tries left") {
		t.Fatalf("three wrong PINs: %v", err)
	}
	if len(p.questions()) != 3 {
		t.Fatalf("asked %d times after three wrong PINs", len(p.questions()))
	}
	// The key itself now refuses until it is plugged in again.
	p.pins = []string{"4321"}
	if _, _, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential}); !errors.Is(err, svfido.StatusPINAuthBlocked) {
		t.Fatalf("a fourth PIN: %v", err)
	}
	a.PowerCycle()
	p.pins = []string{"4321"}
	if _, _, err := k.Evaluate(ctx(t), []svfido.Credential{e.Credential}); err != nil {
		t.Fatalf("after plugging in again: %v", err)
	}
}

func TestABlockedPINIsFinal(t *testing.T) {
	a := plug(t, fidotest.Options{PIN: "4321"})
	p := &person{pins: []string{"4321", "4321"}}
	k := keys(p, a)
	e, err := k.Enroll(ctx(t), rpID, nil, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	for a.Retries() > 0 {
		p.pins = []string{"0000", "0000", "0000"}
		k.Evaluate(ctx(t), []svfido.Credential{e.Credential})
		a.PowerCycle()
	}
	p.pins, p.asked = []string{"4321"}, nil
	_, _, err = k.Evaluate(ctx(t), []svfido.Credential{e.Credential})
	if !errors.Is(err, svfido.StatusPINBlocked) || !strings.Contains(err.Error(), "must be reset") {
		t.Fatalf("a blocked PIN: %v", err)
	}
	if len(p.questions()) != 0 {
		t.Fatal("a PIN was asked for on a key that will take none")
	}
}

func TestTheWrongKeyIsNeverTouched(t *testing.T) {
	mine := plug(t, fidotest.Options{Name: "mine"})
	e, err := keys(&person{}, mine).Enroll(ctx(t), rpID, nil, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	theirs := plug(t, fidotest.Options{Name: "theirs"})
	p := &person{}
	_, _, err = keys(p, theirs).Evaluate(ctx(t), []svfido.Credential{e.Credential})
	if !errors.Is(err, svfido.ErrNotEnrolled) {
		t.Fatalf("the wrong key: %v", err)
	}
	if theirs.Touches() != 0 || theirs.Count("probe") != 1 || len(p.told()) != 0 {
		t.Fatalf("the wrong key was touched %d times, probed %d, notices %v", theirs.Touches(), theirs.Count("probe"), p.told())
	}
	if found, err := keys(nil, theirs).Find(ctx(t), []svfido.Credential{e.Credential}); found || err != nil {
		t.Fatalf("Find on the wrong key = %v, %v", found, err)
	}
	if found, err := keys(nil, theirs, mine).Find(ctx(t), []svfido.Credential{e.Credential}); !found || err != nil {
		t.Fatalf("Find with both = %v, %v", found, err)
	}
}

func TestOfTwoKeysOnlyTheOneHoldingACredentialIsTouched(t *testing.T) {
	a := plug(t, fidotest.Options{Name: "A"})
	b := plug(t, fidotest.Options{Name: "B", PIN: "2468"})
	ea, err := keys(&person{}, a).Enroll(ctx(t), rpID, nil, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := keys(&person{pins: []string{"2468", "2468"}}, b).Enroll(ctx(t), rpID, nil, bytes.Repeat([]byte{7}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := []svfido.Credential{ea.Credential, eb.Credential}
	ta, tb := a.Touches(), b.Touches()

	p := &person{pins: []string{"2468"}}
	i, out, err := keys(p, b, a).Evaluate(ctx(t), creds)
	if err != nil || i != 1 || !bytes.Equal(out, eb.Output) {
		t.Fatalf("B first: %d, %v", i, err)
	}
	if a.Touches() != ta || b.Touches() != tb+1 {
		t.Fatal("a key other than the one used was touched")
	}
	i, out, err = keys(&person{}, a, b).Evaluate(ctx(t), creds)
	if err != nil || i != 0 || !bytes.Equal(out, ea.Output) {
		t.Fatalf("A first: %d, %v", i, err)
	}
	if b.Touches() != tb+1 {
		t.Fatal("B was touched when A answered")
	}
}

func TestOfSeveralKeysTheOneTouchedIsEnrolled(t *testing.T) {
	untouched := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	touched := func(ctx context.Context) error {
		select {
		case <-time.After(100 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	idle := plug(t, fidotest.Options{Name: "idle", Touch: untouched})
	idle20 := plug(t, fidotest.Options{Name: "idle 2.0", CTAP20: true, Touch: untouched})
	chosen := plug(t, fidotest.Options{Name: "chosen", Touch: touched})
	p := &person{}
	e, err := keys(p, idle, idle20, chosen).Enroll(ctx(t), rpID, nil, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "chosen" || chosen.Touches() != 3 || idle.Touches() != 0 || idle20.Touches() != 0 {
		t.Fatalf("enrolled %q; touches %d %d %d", e.Name, chosen.Touches(), idle.Touches(), idle20.Touches())
	}
	if idle.Count("cancel") != 1 || idle20.Count("cancel") != 1 {
		t.Fatal("the keys not chosen were not told to stop waiting")
	}
	if n := p.told(); len(n) == 0 || !strings.Contains(n[0], "touch the one to add") {
		t.Fatalf("told %v", n)
	}
	// The same key again is refused before any touch.
	before := chosen.Touches()
	_, err = keys(p, chosen).Enroll(ctx(t), rpID, nil, salt, []svfido.Credential{e.Credential})
	if !errors.Is(err, svfido.ErrAlreadyEnrolled) || chosen.Touches() != before {
		t.Fatalf("enrolling twice: %v", err)
	}
}

// A key waiting for its touch keeps the host waiting with keepalives,
// however much longer than the host's silence limit that takes.
func TestKeepalivesKeepTheHostWaiting(t *testing.T) {
	slow := func(ctx context.Context) error {
		select {
		case <-time.After(600 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a := plug(t, fidotest.Options{Touch: slow, Keepalive: 10 * time.Millisecond})
	p := &person{}
	k := keys(p, a)
	open := k.Open
	k.Open = func(ctx context.Context) ([]*svfido.Device, error) {
		devs, err := open(ctx)
		for _, d := range devs {
			d.SetTimeout(150 * time.Millisecond)
		}
		return devs, err
	}
	if _, err := k.Enroll(ctx(t), rpID, nil, salt, nil); err != nil {
		t.Fatal(err)
	}
	if len(p.told()) != 2 {
		t.Fatalf("told %v", p.told())
	}
}

func TestCallingOffTheTouchCancelsOnTheKey(t *testing.T) {
	a := plug(t, fidotest.Options{Touch: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }})

	// The person dismisses the notice: the key is told to stop waiting.
	p := &person{onNotice: func(cancel func()) { go func() { time.Sleep(50 * time.Millisecond); cancel() }() }}
	_, err := keys(p, a).Enroll(ctx(t), rpID, nil, salt, nil)
	if !errors.Is(err, svfido.ErrCanceled) {
		t.Fatalf("called off: %v", err)
	}
	if a.Count("cancel") != 1 {
		t.Fatalf("the key heard %d cancels", a.Count("cancel"))
	}

	// The caller giving up cancels too, and says so as a context error.
	c, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = keys(&person{}, a).Enroll(c, rpID, nil, salt, nil)
	if !errors.Is(err, context.DeadlineExceeded) || a.Count("cancel") != 2 {
		t.Fatalf("the caller gave up: %v, %d cancels", err, a.Count("cancel"))
	}

	// The key still answers afterwards.
	if _, err := svfido.NewDevice(ctx(t), a.Transport(), "again"); err != nil {
		t.Fatal(err)
	}
}

func TestADeclinedOrUntouchedKeySaysSo(t *testing.T) {
	for want, touch := range map[error]func(context.Context) error{
		svfido.StatusOperationDenied:   func(context.Context) error { return fidotest.ErrDenied },
		svfido.StatusUserActionTimeout: func(context.Context) error { return fidotest.ErrNoTouch },
	} {
		a := plug(t, fidotest.Options{Touch: touch})
		_, err := keys(&person{}, a).Enroll(ctx(t), rpID, nil, salt, nil)
		if !errors.Is(err, want) {
			t.Errorf("%v: got %v", want, err)
		}
	}
}

func TestPINTokensAreRefusedWhereTheyDoNotApply(t *testing.T) {
	a := plug(t, fidotest.Options{PIN: "1234"})
	b := plug(t, fidotest.Options{PIN: "1234"})
	c := context.Background()
	da, err := svfido.NewDevice(c, a.Transport(), "a")
	if err != nil {
		t.Fatal(err)
	}
	db, err := svfido.NewDevice(c, b.Transport(), "b")
	if err != nil {
		t.Fatal(err)
	}
	cdh := bytes.Repeat([]byte{1}, 32)
	mc := func(d *svfido.Device, tok *svfido.PINToken, rp string) error {
		_, err := d.MakeCredential(c, &svfido.MakeCredentialRequest{ClientDataHash: cdh, RPID: rp, UserID: []byte{1}, PIN: tok})
		return err
	}
	tok, err := da.PINToken(c, []byte("1234"), svfido.PermGetAssertion, rpID)
	if err != nil {
		t.Fatal(err)
	}
	if err := mc(db, tok, rpID); !errors.Is(err, svfido.ErrTokenMisuse) {
		t.Fatalf("another key's token: %v", err)
	}
	if err := mc(da, tok, rpID); !errors.Is(err, svfido.ErrTokenMisuse) {
		t.Fatalf("a getAssertion token for makeCredential: %v", err)
	}
	tok, _ = da.PINToken(c, []byte("1234"), svfido.PermMakeCredential, rpID)
	if err := mc(da, tok, "evil.example"); !errors.Is(err, svfido.ErrTokenMisuse) {
		t.Fatalf("a token for another site: %v", err)
	}
	if err := mc(da, tok, rpID); err != nil {
		t.Fatalf("the token where it applies: %v", err)
	}
	if err := mc(da, tok, rpID); !errors.Is(err, svfido.ErrTokenMisuse) {
		t.Fatalf("a CTAP 2.1 token used twice: %v", err)
	}
	// Wiped tokens are dead.
	tok, _ = da.PINToken(c, []byte("1234"), svfido.PermMakeCredential, rpID)
	tok.Wipe()
	if err := mc(da, tok, rpID); !errors.Is(err, svfido.ErrTokenMisuse) {
		t.Fatalf("a wiped token: %v", err)
	}
}

// hmac-secret takes one salt or two; two give the outputs each would.
func TestTwoSaltsGiveTwoOutputs(t *testing.T) {
	for _, o := range []fidotest.Options{{Name: "protocol 2"}, {Name: "protocol 1", CTAP20: true}} {
		a := plug(t, o)
		e, err := keys(&person{}, a).Enroll(ctx(t), rpID, nil, salt, nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := svfido.NewDevice(ctx(t), a.Transport(), "k")
		if err != nil {
			t.Fatal(err)
		}
		other := bytes.Repeat([]byte{9}, 32)
		as, err := d.GetAssertion(ctx(t), &svfido.AssertionRequest{ClientDataHash: make([]byte, 32), RPID: rpID,
			Allow: [][]byte{e.ID}, Salts: [][]byte{salt, other}})
		if err != nil {
			t.Fatal(err)
		}
		_, one, err := keys(&person{}, a).Evaluate(ctx(t), []svfido.Credential{{ID: e.ID, RPID: rpID, Salt: other}})
		if err != nil {
			t.Fatal(err)
		}
		if len(as.HMACSecret) != 2 || !bytes.Equal(as.HMACSecret[0], e.Output) || !bytes.Equal(as.HMACSecret[1], one) {
			t.Fatalf("%s: two salts gave %x", o.Name, as.HMACSecret)
		}
		if _, err := d.GetAssertion(ctx(t), &svfido.AssertionRequest{ClientDataHash: make([]byte, 32), RPID: rpID,
			Allow: [][]byte{e.ID}, Salts: [][]byte{salt, other, salt}}); err == nil {
			t.Fatal("three salts were sent")
		}
		d.Close()
	}
}

func TestAnUnpluggedKeyIsSaidToBeGone(t *testing.T) {
	a := plug(t, fidotest.Options{Touch: func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	}})
	d, err := svfido.NewDevice(context.Background(), a.Transport(), "k")
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(30 * time.Millisecond); a.Unplug() }()
	err = d.Select(ctx(t), nil)
	if err == nil {
		t.Fatal("a key unplugged mid-request answered")
	}
}
