package svd

import (
	"context"
	"errors"
	"fmt"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// The consent flow. Every request that touches a vault's contents goes
// through authorize:
//
//  1. The vault must be unlocked. If it is not, the person is asked for
//     its passphrase: on the requesting CLI's own terminal, else by the
//     registered terminal agent, else by the desktop prompt.
//  2. A remembered decision (svbroker) settles it if there is one.
//  3. Otherwise the person is asked. secretvault's CLI on a terminal
//     proves it is the person by taking the passphrase there (a "y" typed
//     into a terminal proves nothing: a program can type into a terminal
//     it created). Any other program gets a consent prompt on the desktop:
//     allow once, until the vault locks, always, or deny.
//
// Every outcome is written to the vault's audit log.

var verbs = map[svbroker.Op]string{
	svbroker.OpRead:   "read",
	svbroker.OpList:   "list the items of",
	svbroker.OpWrite:  "change",
	svbroker.OpDelete: "delete",
	svbroker.OpManage: "manage",
	svbroker.OpSign:   "sign with",
}

func describeRequest(cl *client, mv *managedVault, itemName string, op svbroker.Op) string {
	if itemName == "" {
		return fmt.Sprintf("%s wants to %s vault %q.", cl.display(), verbs[op], mv.cfg.Name)
	}
	return fmt.Sprintf("%s wants to %s %q in vault %q.", cl.display(), verbs[op], itemName, mv.cfg.Name)
}

// passphrasePrompter picks who asks for a passphrase on cl's behalf. own
// is true when it is cl itself (its terminal), whose knowing the
// passphrase then also proves who it is.
func (d *Daemon) passphrasePrompter(cl *client) (p Prompter, own bool) {
	if cl != nil && cl.mayPrompt() {
		return rpcPrompter{c: cl, desc: "its terminal"}, true
	}
	d.mu.Lock()
	agent := d.agent
	d.mu.Unlock()
	if agent != nil {
		return rpcPrompter{c: agent, desc: "terminal agent"}, false
	}
	if d.desktop != nil {
		return d.desktop, false
	}
	return nil, false
}

// consentPrompter picks who asks a person to decide about a program:
// never the program itself.
func (d *Daemon) consentPrompter(cl *client) Prompter {
	d.mu.Lock()
	agent := d.agent
	d.mu.Unlock()
	if agent != nil && agent != cl {
		return rpcPrompter{c: agent, desc: "terminal agent"}
	}
	return d.desktop
}

// ensureUnlocked unlocks mv, asking for its passphrase if needed. prompted
// is true when a person was just asked (and so saw why), own when cl
// itself took the passphrase.
func (d *Daemon) ensureUnlocked(ctx context.Context, cl *client, mv *managedVault, why string) (prompted, own bool, err error) {
	d.fresh(mv)
	if !mv.v.Locked() {
		return false, false, nil
	}
	mv.prompt.Lock()
	defer mv.prompt.Unlock()
	if !mv.v.Locked() {
		return false, false, nil
	}
	p, own := d.passphrasePrompter(cl)
	if p == nil {
		return false, false, svrpc.Errorf(svrpc.CodeLocked,
			"vault %q is locked and there is no way to ask for its passphrase here; unlock it with 'secretvault unlock %s'", mv.cfg.Name, mv.cfg.Name)
	}
	q := svrpc.PromptAsk{
		Kind:        svrpc.PromptPassphrase,
		Title:       "Unlock vault " + mv.cfg.Name,
		Description: why + "\n\nEnter the passphrase of vault \"" + mv.cfg.Name + "\" to unlock it.",
		Prompt:      "Passphrase:",
	}
	for range 3 {
		pass, err := p.Passphrase(ctx, q)
		if err != nil {
			return true, own, err
		}
		err = d.unlockWith(mv, svcore.Passphrase(pass))
		clear(pass)
		if err == nil {
			if own {
				d.proved(cl, mv)
			}
			return true, own, nil
		}
		if !errors.Is(err, svcore.ErrWrongKey) {
			return true, own, err
		}
		q.Error = "That passphrase does not open this vault."
	}
	return true, own, svrpc.ErrWrongKey
}

// proved records that cl showed it holds a key of mv: the connection may
// use the vault until it locks, and so may the CLI's whole terminal
// session.
func (d *Daemon) proved(cl *client, mv *managedVault) {
	d.broker.AllowConn(cl, mv.v)
	if cl.cli && cl.proc.Terminal != "" {
		d.broker.Remember(mv.v, svbroker.Grant{
			Identity: cl.identity(), Program: cl.display(),
			Ops: svbroker.AllOps, Decision: svbroker.AllowUntilLock,
		})
	}
}

// authorize decides whether cl may do op to an item (object ID and name;
// both "" for vault-wide operations) of mv, asking a person if need be.
func (d *Daemon) authorize(ctx context.Context, cl *client, mv *managedVault, item, itemName string, op svbroker.Op) error {
	why := describeRequest(cl, mv, itemName, op)
	record := d.recorder(cl, mv, itemName, op)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		record(outcomeOf(err), err.Error())
		return err
	}
	return d.decide(ctx, cl, mv, item, itemName, op, why, prompted, own, record)
}

// authorizeEveryTime is authorize for items that must be confirmed on
// every use (an SSH key added with ssh-add -c): nothing remembered applies,
// the person is always asked, and only "once" or "deny" can be answered.
func (d *Daemon) authorizeEveryTime(ctx context.Context, cl *client, mv *managedVault, item, itemName string, op svbroker.Op) error {
	why := describeRequest(cl, mv, itemName, op) + "\n(This item is confirmed on every use.)"
	record := d.recorder(cl, mv, itemName, op)
	if _, _, err := d.ensureUnlocked(ctx, cl, mv, why); err != nil {
		record(outcomeOf(err), err.Error())
		return err
	}
	return d.ask(ctx, cl, mv, item, itemName, op, why, record, true)
}

// decide is authorize after the vault is unlocked. prompted and own say
// how that unlock went (see ensureUnlocked).
func (d *Daemon) decide(ctx context.Context, cl *client, mv *managedVault, item, itemName string, op svbroker.Op, why string, prompted, own bool, record func(string, string)) error {
	if own {
		record("allowed", "proved the passphrase")
		d.touch(mv)
		return nil
	}
	if d.broker.ConnAllowed(cl, mv.v) {
		record("allowed", "presented a key on this connection")
		d.touch(mv)
		return nil
	}
	if dec, found, err := d.broker.Check(mv.v, cl, cl.identity(), item, op); err != nil {
		return err
	} else if found {
		if !dec.Allows() {
			record("denied", "remembered decision")
			return denied(mv)
		}
		record("allowed", "remembered decision")
		d.touch(mv)
		return nil
	}
	if prompted {
		// The person was just shown this request and unlocked the vault
		// for it: that is consent for this request.
		record("allowed", "unlocked for this request")
		d.touch(mv)
		return nil
	}
	return d.ask(ctx, cl, mv, item, itemName, op, why, record, false)
}

// recorder returns a function that writes an outcome to mv's audit log.
func (d *Daemon) recorder(cl *client, mv *managedVault, itemName string, op svbroker.Op) func(string, string) {
	return func(outcome, reason string) {
		d.audit.Record(mv.v, svbroker.Entry{
			Program: cl.display(), Identity: cl.identity(), PID: cl.proc.PID,
			Op: op, Item: itemName, Outcome: outcome, Reason: reason,
		})
	}
}

func denied(mv *managedVault) error {
	return svrpc.Errorf(svrpc.CodeDenied, "access to vault %q was denied", mv.cfg.Name)
}

func outcomeOf(err error) string {
	switch {
	case errors.Is(err, svrpc.ErrCanceled):
		return "canceled"
	case errors.Is(err, svrpc.ErrDenied):
		return "denied"
	}
	return "failed"
}

// ask puts the request to a person and records the decision.
func (d *Daemon) ask(ctx context.Context, cl *client, mv *managedVault, item, itemName string, op svbroker.Op, why string, record func(string, string), everyTime bool) error {
	mv.prompt.Lock()
	defer mv.prompt.Unlock()
	// Someone may have decided while we waited for the prompt lock.
	if dec, found, err := d.broker.Check(mv.v, cl, cl.identity(), item, op); err == nil && found && !everyTime {
		if dec.Allows() {
			record("allowed", "remembered decision")
			return nil
		}
		record("denied", "remembered decision")
		return denied(mv)
	}

	if cl.mayPrompt() && !everyTime {
		// The CLI proves it is the person with the passphrase, as sudo does.
		p := rpcPrompter{c: cl}
		q := svrpc.PromptAsk{
			Kind:  svrpc.PromptPassphrase,
			Title: "Allow this terminal",
			Description: fmt.Sprintf("This terminal has not used vault %q since it was unlocked.\n"+
				"Enter the vault's passphrase to allow this terminal until the vault locks.", mv.cfg.Name),
			Prompt: "Passphrase:",
		}
		for range 3 {
			pass, err := p.Passphrase(ctx, q)
			if err != nil {
				record(outcomeOf(err), err.Error())
				return err
			}
			err = mv.v.CheckKey(svcore.Passphrase(pass))
			clear(pass)
			if err == nil {
				d.proved(cl, mv)
				record("allowed", "proved the passphrase")
				d.touch(mv)
				return nil
			}
			q.Error = "That passphrase does not open this vault."
		}
		record("denied", "wrong passphrase")
		return svrpc.ErrWrongKey
	}

	p := d.consentPrompter(cl)
	if p == nil {
		err := svrpc.Errorf(svrpc.CodeNoPrompter,
			"%s needs your permission, but there is no way to ask you here (no desktop prompt, no 'secretvault-tui-prompt --agent'); "+
				"allow it with 'secretvault grant allow %s'", cl.display(), cl.proc.Exe)
		record("denied", "no way to ask")
		return err
	}
	choices := []svrpc.Choice{
		{ID: svrpc.ChoiceOnce, Label: "Allow once"},
		{ID: svrpc.ChoiceLock, Label: "Allow until the vault locks"},
		{ID: svrpc.ChoiceAlways, Label: "Always allow"},
		{ID: svrpc.ChoiceDeny, Label: "Deny"},
	}
	if everyTime {
		choices = []svrpc.Choice{{ID: svrpc.ChoiceOnce, Label: "Allow"}, {ID: svrpc.ChoiceDeny, Label: "Deny"}}
	}
	choice, err := p.Choose(ctx, svrpc.PromptAsk{
		Kind:        svrpc.PromptChoose,
		Title:       "Allow access to vault " + mv.cfg.Name + "?",
		Description: fmt.Sprintf("%s\n\nProgram: %s\nProcess: %d", why, cl.proc.Exe, cl.proc.PID),
		Choices:     choices,
	})
	if err != nil {
		record(outcomeOf(err), err.Error())
		if errors.Is(err, svrpc.ErrCanceled) {
			return denied(mv)
		}
		return err
	}
	dec := map[string]svbroker.Decision{
		svrpc.ChoiceOnce: svbroker.AllowOnce, svrpc.ChoiceLock: svbroker.AllowUntilLock,
		svrpc.ChoiceAlways: svbroker.AllowAlways, svrpc.ChoiceDeny: svbroker.DenyOnce,
	}[choice]
	if everyTime && dec != svbroker.AllowOnce {
		dec = svbroker.DenyOnce
	}
	if err := d.broker.Remember(mv.v, svbroker.Grant{
		Identity: cl.identity(), Program: cl.display(), Item: item, ItemName: itemName,
		Ops: []svbroker.Op{op}, Decision: dec,
	}); err != nil {
		return err
	}
	if !dec.Allows() {
		record("denied", "the person said no")
		return denied(mv)
	}
	record("allowed", "the person said "+choice)
	d.touch(mv)
	return nil
}
