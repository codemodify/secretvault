package svfido

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// Keys is what a vault's keyslots need from security keys: enrolling
// one, and evaluating an enrolled credential's hmac-secret on whichever
// key holds it, asking the person for the PIN and the touch on the way.
//
// Unlocking finds its key without disturbing anyone: each key plugged in
// is asked, without a touch (up=false), whether it holds each of the
// vault's credentials. Only the key that does is then asked for the PIN
// (if its keyslot needs one) and the touch.
type Keys struct {
	// Open opens the security keys plugged in (OpenAll when nil).
	Open func(ctx context.Context) ([]*Device, error)

	// Prompts reaches the person. Without it no PIN can be asked and
	// nobody is told to touch anything.
	Prompts Prompts
}

// Prompts is how Keys reaches the person while it works.
type Prompts interface {
	// PIN asks for the PIN of the named key. retries is how many wrong
	// PINs the key still takes before it blocks its PIN; problem says why
	// the previous answer failed ("" the first time). Keys wipes what it
	// is given.
	PIN(ctx context.Context, key string, retries int, problem string) ([]byte, error)

	// Touch tells the person to touch the named key, until done is
	// called. If the person says never mind first, the prompter calls
	// cancel, which abandons the wait.
	Touch(ctx context.Context, key, what string, cancel func()) (done func())
}

// Credential is an enrolled credential, as a keyslot records it.
type Credential struct {
	ID   []byte // the credential ID: the device's own sealed record of the credential
	RPID string // the relying party it was made for
	Salt []byte // the 32 bytes the device evaluates hmac-secret at
	UV   bool   // evaluated with the PIN (a device keeps two secrets per credential: with and without)
}

// Enrolment is a new credential, and its hmac-secret at the salt asked
// for.
type Enrolment struct {
	Credential
	AAGUID [16]byte // the key's model
	Name   string   // the key's name, for people
	Output []byte   // the hmac-secret output: the caller's key material, to be wiped
}

var (
	// ErrAlreadyEnrolled is a key that already holds one of the
	// credentials an enrolment was told to avoid.
	ErrAlreadyEnrolled = errors.New("this security key is already a keyslot of this vault")

	// ErrCanceled is a wait for the person that the person called off.
	ErrCanceled = errors.New("the security key was not used: cancelled")

	// ErrNoPrompts is a key that asks for its PIN when there is no way
	// to ask the person.
	ErrNoPrompts = errors.New("the security key needs its PIN, and there is no way to ask for it here")
)

func (k *Keys) open(ctx context.Context) ([]*Device, error) {
	if k.Open != nil {
		devs, err := k.Open(ctx)
		if err == nil && len(devs) == 0 {
			err = ErrNoDevice
		}
		return devs, err
	}
	return OpenAll(ctx)
}

func closeAll(devs []*Device) {
	for _, d := range devs {
		d.Close()
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// Enroll makes a new non-discoverable credential with hmac-secret for
// rpID and evaluates it once at salt. With several keys plugged in, the
// person picks one by touching it. uv says whether the credential is
// used with the PIN from now on; nil means yes if the key has a PIN.
// A key that already holds one of exclude is refused.
//
// That takes two touches: one to make the credential and one to evaluate
// it, since CTAP 2.1 devices return hmac-secret only from assertions.
func (k *Keys) Enroll(ctx context.Context, rpID string, uv *bool, salt []byte, exclude []Credential) (*Enrolment, error) {
	if len(salt) != 32 {
		return nil, errors.New("svfido: an hmac-secret salt is 32 bytes")
	}
	devs, err := k.open(ctx)
	if err != nil {
		return nil, err
	}
	defer closeAll(devs)
	var usable []*Device
	var why error
	for _, d := range devs {
		if !d.info.HMACSecret() {
			why = fmt.Errorf("%s: %w", d.Name(), ErrNoHMACSecret)
			continue
		}
		usable = append(usable, d)
	}
	if len(usable) == 0 {
		return nil, why
	}
	d := usable[0]
	if len(usable) > 1 {
		if d, err = k.choose(ctx, usable); err != nil {
			return nil, err
		}
	}
	if _, found, err := k.probe(ctx, d, exclude); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("%s: %w", d.Name(), ErrAlreadyEnrolled)
	}

	info := d.info
	wantUV := info.PINSet()
	if uv != nil {
		wantUV = *uv
	}
	if info.AlwaysUV() {
		if uv != nil && !*uv {
			return nil, fmt.Errorf("%s asks for its PIN on every use (alwaysUv), so it cannot be added without the PIN", d.Name())
		}
		wantUV = true
	}
	if wantUV && !info.PINSet() {
		return nil, fmt.Errorf("%s has no PIN yet: set one with its maker's tool (or 'fido2-token -S'), or add it without the PIN", d.Name())
	}
	// A key with a PIN may want it for any new credential, whether or
	// not the credential is used with it later.
	needPIN := wantUV || (info.PINSet() && !info.Options["makeCredUvNotRqd"])
	var pin []byte
	var mcToken *PINToken
	if needPIN {
		if mcToken, pin, err = k.pinToken(ctx, d, PermMakeCredential|PermGetAssertion, rpID); err != nil {
			return nil, err
		}
		defer clear(pin)
		defer mcToken.Wipe()
	}

	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	onTouch, done := k.touching(ctx, d, "Touch your security key to add it to the vault (1 of 2).", cancel)
	att, err := d.MakeCredential(opCtx, &MakeCredentialRequest{
		ClientDataHash: random(32), RPID: rpID, RPName: "secretvault", UserID: random(16),
		HMACSecret: true, PIN: mcToken, OnTouch: onTouch,
	})
	done()
	if err != nil {
		return nil, k.canceled(ctx, err)
	}
	id := att.AuthData.CredentialID

	var gaToken *PINToken
	if wantUV {
		if !mcToken.scoped && !mcToken.used {
			gaToken = mcToken // a CTAP 2.0 token lasts
		} else if gaToken, err = d.PINToken(ctx, pin, PermGetAssertion, rpID); err != nil {
			return nil, err
		}
		defer gaToken.Wipe()
	}
	onTouch, done = k.touching(ctx, d, "Touch your security key again to finish (2 of 2).", cancel)
	as, err := d.GetAssertion(opCtx, &AssertionRequest{
		ClientDataHash: random(32), RPID: rpID, Allow: [][]byte{id},
		Salts: [][]byte{salt}, PIN: gaToken, OnTouch: onTouch,
	})
	done()
	if err != nil {
		return nil, k.canceled(ctx, err)
	}
	e := &Enrolment{
		Credential: Credential{ID: id, RPID: rpID, Salt: append([]byte(nil), salt...), UV: as.AuthData.Flags&FlagUV != 0},
		AAGUID:     att.AuthData.AAGUID,
		Name:       d.Name(),
		Output:     as.HMACSecret[0],
	}
	if e.AAGUID == ([16]byte{}) {
		e.AAGUID = info.AAGUID
	}
	return e, nil
}

// Evaluate finds a key plugged in that holds one of creds, and evaluates
// that credential's hmac-secret at its salt: with the PIN if the
// credential was enrolled with it, and a touch. It returns which of creds
// answered, and the output, which the caller wipes.
func (k *Keys) Evaluate(ctx context.Context, creds []Credential) (int, []byte, error) {
	devs, err := k.open(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer closeAll(devs)
	d, i, err := k.locate(ctx, devs, creds)
	if err != nil {
		return 0, nil, err
	}
	c := creds[i]
	var token *PINToken
	if c.UV {
		var pin []byte
		if token, pin, err = k.pinToken(ctx, d, PermGetAssertion, c.RPID); err != nil {
			return 0, nil, err
		}
		clear(pin)
		defer token.Wipe()
	}
	opCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	onTouch, done := k.touching(ctx, d, "Touch your security key.", cancel)
	as, err := d.GetAssertion(opCtx, &AssertionRequest{
		ClientDataHash: random(32), RPID: c.RPID, Allow: [][]byte{c.ID},
		Salts: [][]byte{c.Salt}, PIN: token, OnTouch: onTouch,
	})
	done()
	if err != nil {
		return 0, nil, k.canceled(ctx, err)
	}
	if verified := as.AuthData.Flags&FlagUV != 0; verified != c.UV {
		clear(as.HMACSecret[0])
		return 0, nil, fmt.Errorf("%s verified the PIN on its own (it may have been set to always ask for it since this keyslot was made), so its answer cannot match the keyslot", d.Name())
	}
	return i, as.HMACSecret[0], nil
}

// Find reports, without disturbing anyone, whether a key plugged in holds
// one of creds.
func (k *Keys) Find(ctx context.Context, creds []Credential) (bool, error) {
	devs, err := k.open(ctx)
	if err != nil {
		return false, err
	}
	defer closeAll(devs)
	_, _, err = k.locate(ctx, devs, creds)
	if errors.Is(err, ErrNotEnrolled) {
		return false, nil
	}
	return err == nil, err
}

// locate asks each device, without a touch, which of creds it holds.
func (k *Keys) locate(ctx context.Context, devs []*Device, creds []Credential) (*Device, int, error) {
	var why error
	for _, d := range devs {
		if !d.info.HMACSecret() {
			continue
		}
		i, found, err := k.probe(ctx, d, creds)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			if why == nil {
				why = fmt.Errorf("%s: %w", d.Name(), err)
			}
			continue
		}
		if found {
			return d, i, nil
		}
	}
	if why != nil {
		return nil, 0, why
	}
	return nil, 0, ErrNotEnrolled
}

// probe asks one device, credential by credential and without a touch,
// whether it holds any of creds.
func (k *Keys) probe(ctx context.Context, d *Device, creds []Credential) (int, bool, error) {
	for i, c := range creds {
		if len(c.ID) == 0 || (d.info.MaxCredentialIDLength > 0 && len(c.ID) > d.info.MaxCredentialIDLength) {
			continue // not one this device could have made
		}
		_, err := d.GetAssertion(ctx, &AssertionRequest{ClientDataHash: random(32), RPID: c.RPID, Allow: [][]byte{c.ID}, NoTouch: true})
		switch {
		case err == nil:
			return i, true, nil
		case errors.Is(err, StatusNoCredentials):
			continue
		case errors.Is(err, StatusPUATRequired) && c.UV:
			// A key that verifies on every use (alwaysUv) will not even
			// be probed without its PIN; the PIN is asked for anyway.
			return i, true, nil
		default:
			return 0, false, err
		}
	}
	return 0, false, nil
}

// choose has the person pick one of several keys by touching it.
func (k *Keys) choose(ctx context.Context, devs []*Device) (*Device, error) {
	selCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := func() {}
	if k.Prompts != nil {
		done = k.Prompts.Touch(ctx, fmt.Sprintf("%d security keys", len(devs)),
			"Several security keys are plugged in: touch the one to add.", cancel)
	}
	defer done()
	type result struct {
		d   *Device
		err error
	}
	results := make(chan result, len(devs))
	for _, d := range devs {
		go func() { results <- result{d, d.Select(selCtx, nil)} }()
	}
	var chosen *Device
	var why error
	for range devs {
		r := <-results
		switch {
		case r.err == nil && chosen == nil:
			chosen = r.d
			cancel() // the others stop waiting
		case r.err != nil && why == nil && !errors.Is(r.err, context.Canceled):
			why = r.err
		}
	}
	if chosen != nil {
		return chosen, nil
	}
	if why == nil {
		why = context.Canceled
	}
	return nil, k.canceled(ctx, why)
}

// pinToken asks for the PIN until the device takes it, and returns a
// token and the PIN (for a second token; the caller wipes it). The person
// is told each time how many tries are left, and why the last one failed.
// It stops at three wrong PINs, which is when the device wants to be
// plugged in again anyway.
func (k *Keys) pinToken(ctx context.Context, d *Device, perms Permission, rpID string) (*PINToken, []byte, error) {
	if k.Prompts == nil {
		return nil, nil, ErrNoPrompts
	}
	problem := ""
	wrong := 0
	for asked := 0; asked < 6; asked++ {
		retries, err := d.PINRetries(ctx)
		if err != nil {
			return nil, nil, err
		}
		if retries == 0 {
			return nil, nil, StatusPINBlocked
		}
		pin, err := k.Prompts.PIN(ctx, d.Name(), retries, problem)
		if err != nil {
			return nil, nil, err
		}
		if len(pin) == 0 {
			return nil, nil, ErrCanceled
		}
		token, err := d.PINToken(ctx, pin, perms, rpID)
		if err == nil {
			return token, pin, nil
		}
		clear(pin)
		var short *PINLengthError
		switch {
		case errors.As(err, &short):
			problem = "That cannot be the PIN: " + short.Error() + ". Nothing was used up."
		case errors.Is(err, StatusPINInvalid):
			wrong++
			if wrong >= 3 {
				return nil, nil, fmt.Errorf("%w (%d tries left before its PIN blocks for good)", StatusPINAuthBlocked, retries-1)
			}
			problem = fmt.Sprintf("Wrong PIN. %d tries left before the key blocks its PIN for good.", retries-1)
		case errors.Is(err, StatusPINAuthBlocked) && retries > 1:
			// The third wrong PIN in a row is answered this way.
			return nil, nil, fmt.Errorf("%w (%d tries left before its PIN blocks for good)", err, retries-1)
		default:
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("svfido: too many PINs that cannot be right")
}

// touching makes a request's OnTouch, which tells the person to touch d
// once the device waits for it, and done, which takes the notice down.
// The person calling the notice off cancels the request.
func (k *Keys) touching(ctx context.Context, d *Device, what string, cancel func()) (onTouch func(), done func()) {
	var mu sync.Mutex
	var stop func()
	over := false
	onTouch = func() {
		mu.Lock()
		defer mu.Unlock()
		if over || stop != nil || k.Prompts == nil {
			return
		}
		stop = k.Prompts.Touch(ctx, d.Name(), what, cancel)
	}
	done = func() {
		mu.Lock()
		over = true
		s := stop
		mu.Unlock()
		if s != nil {
			s()
		}
	}
	return onTouch, done
}

// canceled turns the cancellation of a request by the person (rather
// than by the caller) into ErrCanceled.
func (k *Keys) canceled(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return ErrCanceled
	}
	if errors.Is(err, StatusKeepaliveCancel) {
		return ErrCanceled
	}
	return err
}
