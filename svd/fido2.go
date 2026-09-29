package svd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svfido"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// Security keys: fido2 keyslots. The daemon holds the unlocked vault, so
// it is the one that enrols a key and the one that uses it, through
// svfido. It asks for the key's PIN and says "touch your security key"
// through the prompter that would ask for the passphrase: the CLI's
// terminal, the terminal agent, or the desktop.
//
// Unlocking tries the key first. When a vault with fido2 slots is to be
// unlocked, every key plugged in is asked, without a touch, whether it
// holds one of them. If one does, the person is asked for its PIN (when
// the slot needs it) and to touch it; if that fails or the person calls
// it off, the passphrase is asked for as before, saying why.

func init() {
	registerMethod(svrpc.MFIDO2List, func(d *Daemon, ctx context.Context, cl *client, _ func(any) error) (any, error) {
		return d.fido2Devices(ctx)
	})
}

// openKeys opens the security keys plugged in.
func (d *Daemon) openKeys(ctx context.Context) ([]*svfido.Device, error) {
	if d.opts.SecurityKeys != nil {
		return d.opts.SecurityKeys(ctx)
	}
	return svfido.OpenAll(ctx)
}

// securityKeys lends svcore the keys for one request, asking the person
// through p (nil: nobody can be asked, so only a key that needs no PIN can
// be used, and silently).
func (d *Daemon) securityKeys(ctx context.Context, p Prompter, title, why string) svcore.SecurityKeys {
	k := &svfido.Keys{Open: d.openKeys}
	if p != nil {
		k.Prompts = &tokenPrompts{p: p, title: title, why: why}
	}
	return coreKeys{ctx: ctx, keys: k}
}

// coreKeys is svfido's Keys as svcore.SecurityKeys.
type coreKeys struct {
	ctx  context.Context
	keys *svfido.Keys
}

func toCredentials(creds []svcore.FIDO2Credential) []svfido.Credential {
	out := make([]svfido.Credential, len(creds))
	for i, c := range creds {
		out[i] = svfido.Credential{ID: c.ID, RPID: c.RPID, Salt: c.Salt, UV: c.UV}
	}
	return out
}

func (c coreKeys) Enroll(rpID string, uv *bool, salt []byte, exclude []svcore.FIDO2Credential) (svcore.FIDO2Enrolment, error) {
	e, err := c.keys.Enroll(c.ctx, rpID, uv, salt, toCredentials(exclude))
	if err != nil {
		return svcore.FIDO2Enrolment{}, tokenError(err)
	}
	return svcore.FIDO2Enrolment{ID: e.ID, AAGUID: e.AAGUID, UV: e.UV, Name: e.Name, Output: e.Output}, nil
}

func (c coreKeys) Evaluate(creds []svcore.FIDO2Credential) (int, []byte, error) {
	i, out, err := c.keys.Evaluate(c.ctx, toCredentials(creds))
	return i, out, tokenError(err)
}

// tokenError gives a security key's errors their protocol codes.
func tokenError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, svfido.ErrCanceled), errors.Is(err, svrpc.ErrCanceled):
		return svrpc.ErrCanceled
	case errors.Is(err, svfido.ErrNoDevice), errors.Is(err, svfido.ErrNotEnrolled):
		return svrpc.Errorf(svrpc.CodeNotFound, "%v", err)
	}
	return err
}

// tokenPrompts asks about a security key through a Prompter: the PIN as
// a PIN prompt, and "touch it" as a notice. The first question also says
// why the key is wanted.
type tokenPrompts struct {
	p     Prompter
	title string
	why   string

	mu   sync.Mutex
	told bool
}

// context is why the key is wanted, the first time only.
func (t *tokenPrompts) context() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.told || t.why == "" {
		return ""
	}
	t.told = true
	return t.why + "\n\n"
}

func (t *tokenPrompts) PIN(ctx context.Context, key string, retries int, problem string) ([]byte, error) {
	tries := fmt.Sprintf("It takes %d more wrong PINs before it blocks its PIN for good.", retries)
	if retries == 1 {
		tries = "One more wrong PIN blocks its PIN for good, and only resetting the key (which erases it) undoes that."
	}
	return t.p.Passphrase(ctx, svrpc.PromptAsk{
		Kind:        svrpc.PromptPIN,
		Title:       t.title,
		Description: fmt.Sprintf("%sEnter the PIN of your security key (%s). %s", t.context(), key, tries),
		Prompt:      "PIN:",
		Error:       problem,
	})
}

func (t *tokenPrompts) Touch(ctx context.Context, key, what string, cancel func()) func() {
	n, ok := t.p.(noticer)
	if !ok {
		return func() {}
	}
	return n.Notice(ctx, svrpc.PromptAsk{
		Kind:        svrpc.PromptNotice,
		Title:       t.title,
		Description: fmt.Sprintf("%s%s (%s)", t.context(), what, key),
	}, cancel)
}

// tokenPresent reports, disturbing nobody, whether a security key that
// opens mv is plugged in.
func (d *Daemon) tokenPresent(ctx context.Context, mv *managedVault) bool {
	creds, err := mv.v.FIDO2Credentials()
	if err != nil || len(creds) == 0 {
		return false
	}
	found, err := (&svfido.Keys{Open: d.openKeys}).Find(ctx, toCredentials(creds))
	if err != nil && !errors.Is(err, svfido.ErrNoDevice) {
		d.opts.Log(fmt.Sprintf("security keys for %s: %v", mv.cfg.Name, err))
	}
	return found
}

// tryToken unlocks mv with a security key when one that opens it is
// plugged in, asking through p; with check, it only proves the key opens
// the vault. tried is false when no such key is there.
func (d *Daemon) tryToken(ctx context.Context, p Prompter, mv *managedVault, why string, check bool) (tried bool, err error) {
	if !d.tokenPresent(ctx, mv) {
		return false, nil
	}
	key := svcore.SecurityKey(d.securityKeys(ctx, p, "Unlock vault "+mv.cfg.Name, why))
	if check {
		return true, mv.v.CheckKey(key)
	}
	return true, d.unlockWith(mv, key)
}

// afterToken is what the passphrase prompt says after a security key did
// not open the vault ("" when the person called it off).
func afterToken(err error) string {
	if errors.Is(err, svrpc.ErrCanceled) {
		return ""
	}
	msg := strings.TrimPrefix(mapErr(err).Error(), "svcore: ")
	return "The security key did not open the vault (" + msg + "). Enter the passphrase instead."
}

// hasPassphrase reports whether mv opens with a passphrase at all: a
// passphrase slot of the key this handle knows, or of a newer one (a
// rotation made elsewhere, which the handle learns of as it unlocks).
func hasPassphrase(mv *managedVault) bool {
	slots, err := mv.v.Slots()
	if err != nil {
		return true // let the passphrase prompt find out
	}
	for _, s := range slots {
		if s.Type == svformat.SlotPassphrase && s.Epoch >= mv.v.Epoch() {
			return true
		}
	}
	return false
}

// fido2Devices describes the security keys the daemon can see.
func (d *Daemon) fido2Devices(ctx context.Context) ([]svrpc.FIDO2Device, error) {
	out := []svrpc.FIDO2Device{}
	if d.opts.SecurityKeys != nil {
		devs, err := d.opts.SecurityKeys(ctx)
		if err != nil && !errors.Is(err, svfido.ErrNoDevice) {
			return nil, err
		}
		for _, dev := range devs {
			out = append(out, describeKey(ctx, dev))
			dev.Close()
		}
		return out, nil
	}
	infos, err := svfido.Devices()
	if err != nil {
		return nil, err
	}
	for _, info := range infos {
		dev, err := svfido.Open(ctx, info)
		if err != nil {
			out = append(out, svrpc.FIDO2Device{Path: info.Path, Name: info.String(), Problem: err.Error()})
			continue
		}
		out = append(out, describeKey(ctx, dev))
		dev.Close()
	}
	return out, nil
}

func describeKey(ctx context.Context, dev *svfido.Device) svrpc.FIDO2Device {
	info := dev.Info()
	out := svrpc.FIDO2Device{Path: dev.Path(), Name: dev.Name(), Versions: info.Versions, AAGUID: uuid(info.AAGUID[:]), HMACSecret: info.HMACSecret()}
	switch {
	case info.PINSet():
		out.PIN = "set"
		if n, err := dev.PINRetries(ctx); err == nil {
			out.Retries = n
		}
	case info.PINSupported():
		out.PIN = "not set"
	}
	if !info.HMACSecret() {
		out.Problem = svfido.ErrNoHMACSecret.Error()
	}
	return out
}

// uuid writes 16 bytes as a UUID, as AAGUIDs are written.
func uuid(b []byte) string {
	if len(b) != 16 {
		return fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
