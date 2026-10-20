package svd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// A program asking for a vault of its own (vault.request).
//
// vault.create takes the new vault's passphrase from its caller, so only
// secretvault's own programs may call it. A program (a mail client
// keeping its key in a vault of its own) asks for one by name instead,
// and the daemon does the rest through its own prompter, never through
// the program:
//
//  1. The person is asked: "comms-mail wants a new vault called "mail"":
//     create it, don't, or don't, and don't ask again for this program.
//  2. They choose its passphrase, typed twice.
//  3. The vault is made, in the data folder with the default suite, with
//     a recovery key (as the managers' New vault makes one), which is
//     shown once for them to write down, and kept unless they say not to.
//
// The program gets the vault's name back, never its passphrase or its
// recovery key. It chooses neither where the vault goes nor its suite,
// and the vault never becomes the default by itself. It is unlocked, as
// any vault just made is, and locks itself as any does; the program asks
// before it reads or stores anything in it, as for any vault: nothing is
// granted to it.
//
// A program has one request waiting at a time, and one such question is
// on screen at a time. "Don't ask again" is kept in the daemon's config
// (Config.NoVaultRequests), listed with every vault's grants and revoked
// there. Every request, and how it ended, goes to the default vault's
// audit log, and a vault made to its own as well.

func init() { registerMethod(svrpc.MVaultRequest, (*Daemon).requestVault) }

// requestTimeout bounds the recovery key's showing, which goes on after
// the program has its answer or has gone: the person reads it in their
// own time, not the program's.
const requestTimeout = 10 * time.Minute

func errVaultExists(name string) error {
	return svrpc.Errorf(svrpc.CodeExists, "there is already a vault called %q", name)
}

// requestVault serves vault.request.
func (d *Daemon) requestVault(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var raw map[string]json.RawMessage
	if err := decode(&raw); err != nil {
		return nil, err
	}
	for k := range raw {
		if k != "name" {
			// So that no program believes it chose them.
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams,
				"vault.request takes only a name, not %q: where the vault is kept, its cipher suite and its passphrase are chosen by secretvault and the person", k)
		}
	}
	var name string
	if r, ok := raw["name"]; ok {
		if err := json.Unmarshal(r, &name); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "bad parameters for %s: the name is not a string", svrpc.MVaultRequest)
		}
	}
	if err := checkVaultName(name); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	record := func(outcome, reason string) { d.recordRequest(cl, name, nil, outcome, reason) }
	// What is refused without asking anybody is written once a minute at
	// most, so that a program asking in a loop cannot bury the log.
	quietly := func(outcome, reason string) {
		if d.firstInAWhile(cl, name, reason) {
			record(outcome, reason)
		}
	}

	if d.noVaultRequests(cl) {
		quietly("denied", "remembered decision")
		return nil, errNoNewVaults(cl)
	}
	if !d.startRequest(cl) {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "%s has asked for a new vault already, and the person has not answered yet", cl.display())
	}
	defer d.endRequest(cl)
	if err := d.vaultTaken(name); err != nil {
		quietly("failed", "a vault of that name exists")
		return nil, err
	}
	p := d.consentPrompter(cl)
	if p == nil {
		record("denied", "no way to ask")
		return nil, svrpc.Errorf(svrpc.CodeNoPrompter,
			"%s asks for a new vault, but there is no way to ask you here (no desktop prompt, no 'secretvault-tui-prompt --agent'); "+
				"make one with 'secretvault vault create %s' instead", cl.display(), name)
	}

	// One question about a new vault on screen at a time.
	select {
	case d.asking <- struct{}{}:
		defer func() { <-d.asking }()
	case <-ctx.Done():
		record("canceled", "the program went away")
		return nil, ctx.Err()
	}
	// What was decided, or made, while this one waited its turn.
	if d.noVaultRequests(cl) {
		record("denied", "remembered decision")
		return nil, errNoNewVaults(cl)
	}
	if err := d.vaultTaken(name); err != nil {
		record("failed", "a vault of that name exists")
		return nil, err
	}

	who := shortName(cl.proc)
	// The program as the system knows it: its file, and the script an
	// interpreter runs, whose name is what the title says.
	facts := "Program: " + svpeer.Printable(cl.proc.Exe)
	if cl.proc.Exe == "" {
		facts = "Program: " + cl.display()
	}
	if cl.proc.Script != "" {
		facts += "\nScript: " + svpeer.Printable(cl.proc.Script)
	}
	choices := []svrpc.Choice{{ID: svrpc.ChoiceCreate, Label: "Create the vault"}}
	if lasting(cl.proc) {
		choices = append(choices, svrpc.Choice{ID: svrpc.ChoiceNever, Label: "Don't ask again for this program"})
	}
	// Refusing comes last, which secretvault's prompts make the default
	// and a plain pinentry its Cancel (Escape).
	choices = append(choices, svrpc.Choice{ID: svrpc.ChoiceDeny, Label: "Don't create it"})
	choice, err := p.Choose(ctx, svrpc.PromptAsk{
		Kind:  svrpc.PromptChoose,
		Title: fmt.Sprintf("%s wants a new vault called %q", who, name),
		Description: fmt.Sprintf("%s asks for a new, empty vault called %q, kept with your other vaults.\n\n"+
			"If you create it, you choose its passphrase next, and %s never sees it. "+
			"%s will still have to ask you before it reads or stores anything in the vault.\n\n"+
			"%s\nProcess: %d", who, name, who, who, facts, cl.proc.PID),
		Choices: choices,
	})
	switch {
	case errors.Is(err, svrpc.ErrCanceled):
		record("canceled", "the person dismissed the question")
		return nil, svrpc.Errorf(svrpc.CodeCanceled, "the person did not answer whether to create vault %q", name)
	case err != nil:
		record(outcomeOf(err), err.Error())
		return nil, err
	case choice == svrpc.ChoiceNever && lasting(cl.proc):
		if err := d.refuseVaultRequests(cl); err != nil {
			d.opts.Log("remembering not to ask again for " + cl.display() + ": " + err.Error())
		}
		record("denied", "the person said no, and not to ask again")
		return nil, errNoNewVaults(cl)
	case choice != svrpc.ChoiceCreate:
		record("denied", "the person said no")
		return nil, svrpc.Errorf(svrpc.CodeDenied, "the person chose not to create vault %q", name)
	}

	pass, err := d.newPassphrase(ctx, p, who, name)
	if err != nil {
		record(outcomeOf(err), "no passphrase was chosen")
		return nil, err
	}
	mv, recovery, err := d.createVault(svrpc.VaultCreateParams{Name: name, Passphrase: pass, Recovery: true}, cl.display())
	clear(pass)
	if err != nil {
		reason := "it could not be made"
		if errors.Is(err, svrpc.ErrExists) {
			reason = "a vault of that name exists"
		}
		record("failed", reason)
		d.opts.Log(fmt.Sprintf("making vault %q for %s: %v", name, cl.display(), err))
		return nil, err
	}
	d.opts.Log(fmt.Sprintf("made vault %s for %s", name, cl.display()))

	// The recovery key is the person's to read in their own time, even
	// once the program has stopped waiting.
	kept := d.showRecovery(context.WithoutCancel(ctx), p, mv, who, recovery)
	reason := "the person created it and chose its passphrase; recovery key kept"
	if !kept {
		reason = "the person created it and chose its passphrase; no recovery key"
	}
	d.recordRequest(cl, name, mv, "allowed", reason)
	d.notify(svrpc.EVaultUnlocked, svrpc.VaultEvent{Vault: name})
	return svrpc.VaultRequestResult{Vault: name}, nil
}

// newPassphrase asks for the new vault's passphrase, twice, until one is
// long enough.
func (d *Daemon) newPassphrase(ctx context.Context, p Prompter, who, name string) ([]byte, error) {
	q := svrpc.PromptAsk{
		Kind:  svrpc.PromptNewPassphrase,
		Title: "Choose a passphrase for vault " + name,
		Description: fmt.Sprintf("The passphrase opens the new vault %q. %s never sees it. Use at least %d characters.",
			name, who, MinPassphrase),
		Prompt: "Passphrase:",
		OK:     "Set the passphrase",
	}
	for range 3 {
		pass, err := p.Passphrase(ctx, q)
		if err != nil {
			if errors.Is(err, svrpc.ErrCanceled) {
				return nil, svrpc.Errorf(svrpc.CodeCanceled, "the person did not choose a passphrase for vault %q", name)
			}
			return nil, err
		}
		if len(pass) >= MinPassphrase {
			return pass, nil
		}
		clear(pass)
		q.Error = fmt.Sprintf("That passphrase is too short: use at least %d characters.", MinPassphrase)
	}
	return nil, svrpc.Errorf(svrpc.CodeCanceled, "no passphrase long enough was chosen for vault %q", name)
}

// showRecovery shows the new vault's recovery key once, through the
// prompter, and reports whether it is kept. It is kept unless the person
// says not to keep it, or it could not be shown at all (a key nobody
// read is of no use, and is taken off). Closing the prompt keeps it: it
// may have been written down.
func (d *Daemon) showRecovery(ctx context.Context, p Prompter, mv *managedVault, who, recovery string) bool {
	if recovery == "" {
		return false
	}
	slot, err := recoverySlot(mv)
	if err != nil {
		d.opts.Log(fmt.Sprintf("vault %s's recovery keyslot: %v", mv.cfg.Name, err))
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	choice, err := p.Choose(ctx, svrpc.PromptAsk{
		Kind:  svrpc.PromptShowSecret,
		Title: "Recovery key for vault " + mv.cfg.Name,
		Description: fmt.Sprintf("Write this recovery key down and keep it somewhere safe. It opens vault %s if the passphrase is lost, "+
			"and it is shown only now: it is stored nowhere, and %s does not see it.", mv.cfg.Name, who),
		Show: recovery,
		// The last is the default.
		Choices: []svrpc.Choice{
			{ID: svrpc.ChoiceNoRecovery, Label: "Don't keep a recovery key"},
			{ID: svrpc.ChoiceWritten, Label: "I have written it down"},
		},
	})
	switch {
	case err == nil && choice != svrpc.ChoiceNoRecovery,
		errors.Is(err, svrpc.ErrCanceled):
		return true
	case err != nil:
		d.opts.Log(fmt.Sprintf("showing vault %s's recovery key: %v; it is not kept", mv.cfg.Name, err))
	}
	if err := mv.v.RemoveSlot(slot); err != nil {
		if !mv.v.Locked() {
			d.opts.Log(fmt.Sprintf("taking vault %s's recovery key off: %v", mv.cfg.Name, err))
			return true
		}
		// It locked while the key was on screen (the screen locked,
		// say): the keyslot goes when it is next unlocked.
		mv.mu.Lock()
		mv.dropSlot = slot
		mv.mu.Unlock()
		d.opts.Log(fmt.Sprintf("vault %s locked before its recovery key could be taken off; it is taken off when the vault is next unlocked", mv.cfg.Name))
	}
	return false
}

// recoverySlot is a new vault's recovery keyslot.
func recoverySlot(mv *managedVault) (svformat.ID, error) {
	slots, err := mv.v.Slots()
	if err != nil {
		return svformat.ID{}, err
	}
	for _, s := range slots {
		if s.Type == svformat.SlotRecovery {
			return s.ID, nil
		}
	}
	return svformat.ID{}, errors.New("it has none")
}

// firstInAWhile reports whether a refusal of cl's request for name, for
// why, was last written a minute ago or more (or never), and notes it.
func (d *Daemon) firstInAWhile(cl *client, name, why string) bool {
	key := cl.identity() + "\x00" + name + "\x00" + why
	now := d.opts.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.refused[key]; ok && now.Sub(last) < time.Minute && !now.Before(last) {
		return false
	}
	if len(d.refused) > 1000 {
		for k, t := range d.refused {
			if now.Sub(t) >= time.Minute {
				delete(d.refused, k)
			}
		}
	}
	d.refused[key] = now
	return true
}

// vaultTaken is an error when a vault called name is registered, or its
// folder is in the data folder already. That is no news to a program:
// vault.list names every registered vault, and the data folder is the
// person's, which their programs can look in.
func (d *Daemon) vaultTaken(name string) error {
	d.mu.Lock()
	_, taken := d.vaults[name]
	d.mu.Unlock()
	if taken {
		return errVaultExists(name)
	}
	if _, err := os.Lstat(filepath.Join(d.home, "vaults", name)); err == nil {
		return errVaultExists(name)
	}
	return nil
}

// startRequest marks cl's program as waiting for an answer to a request,
// unless it already is.
func (d *Daemon) startRequest(cl *client) bool {
	id := cl.identity()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.requesting[id] {
		return false
	}
	d.requesting[id] = true
	return true
}

func (d *Daemon) endRequest(cl *client) {
	d.mu.Lock()
	delete(d.requesting, cl.identity())
	d.mu.Unlock()
}

// lasting reports whether a decision can be remembered for p: not for a
// program known only by its process ID.
func lasting(p *svpeer.Process) bool {
	return !strings.HasPrefix(p.Identity(), "unknown:")
}

// shortName is how a program is named in a title: "comms-mail".
func shortName(p *svpeer.Process) string {
	switch {
	case p.Flatpak != "":
		return svpeer.Printable(p.Flatpak)
	case p.Snap != "":
		return svpeer.Printable(p.Snap)
	case p.Script != "":
		return filepath.Base(svpeer.Printable(p.Script))
	case p.Exe != "":
		return filepath.Base(svpeer.Printable(p.Exe))
	}
	return "An unidentified program"
}

func errNoNewVaults(cl *client) error {
	return svrpc.Errorf(svrpc.CodeDenied, "the person chose not to be asked for new vaults by %s", cl.display())
}

// noVaultRequests reports whether the person said not to ask again for
// cl's program.
func (d *Daemon) noVaultRequests(cl *client) bool {
	id := cl.identity()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.cfg.NoVaultRequests {
		if r.Identity == id {
			return true
		}
	}
	return false
}

// refuseVaultRequests remembers not to ask again for cl's program.
func (d *Daemon) refuseVaultRequests(cl *client) error {
	id := cl.identity()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.cfg.NoVaultRequests {
		if r.Identity == id {
			return nil
		}
	}
	d.cfg.NoVaultRequests = append(d.cfg.NoVaultRequests, ProgramDecision{Identity: id, Program: cl.display(), Created: d.opts.Now().UTC()})
	if err := d.cfg.save(d.config); err != nil {
		d.cfg.NoVaultRequests = d.cfg.NoVaultRequests[:len(d.cfg.NoVaultRequests)-1]
		return err
	}
	return nil
}

// noVaultRequestsPrefix starts the IDs of the decisions about asking for
// new vaults, as grant.list gives them.
const noVaultRequestsPrefix = "nv:"

func noVaultRequestsID(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return noVaultRequestsPrefix + hex.EncodeToString(sum[:8])
}

// vaultRequestGrants are the decisions about asking for new vaults, as
// grants listed with vault's.
func (d *Daemon) vaultRequestGrants(vault string) []svrpc.Grant {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []svrpc.Grant
	for _, r := range d.cfg.NoVaultRequests {
		out = append(out, svrpc.Grant{ID: noVaultRequestsID(r.Identity), Vault: vault, Program: r.Program, Identity: r.Identity,
			Ops: []string{string(svbroker.OpCreateVault)}, Decision: string(svbroker.DenyAlways), Created: r.Created,
			Scope: "stored", NewVaults: true})
	}
	return out
}

// forgetVaultRequests forgets the decision with ID id: its program is
// asked again.
func (d *Daemon) forgetVaultRequests(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, r := range d.cfg.NoVaultRequests {
		if noVaultRequestsID(r.Identity) != id {
			continue
		}
		old := d.cfg.NoVaultRequests
		d.cfg.NoVaultRequests = append(append([]ProgramDecision(nil), old[:i]...), old[i+1:]...)
		if err := d.cfg.save(d.config); err != nil {
			d.cfg.NoVaultRequests = old
			return err
		}
		return nil
	}
	return svbroker.ErrNoGrant
}

// recordRequest writes a request for a new vault, and how it ended, to
// the default vault's audit log (there is no vault of its own to write
// it to until it is made), and when one was made (mv), to its log too;
// and a line to the daemon's log. Nothing secret is in any of them.
func (d *Daemon) recordRequest(cl *client, name string, mv *managedVault, outcome, reason string) {
	d.opts.Log(fmt.Sprintf("%s asked for a new vault %q: %s (%s)", cl.display(), name, outcome, reason))
	e := svbroker.Entry{Program: cl.display(), Identity: cl.identity(), PID: cl.proc.PID,
		Op: svbroker.OpCreateVault, Item: name, Outcome: outcome, Reason: reason}
	if def, err := d.vault(""); err == nil && (mv == nil || def != mv) {
		d.audit.Record(def.v, e)
	}
	if mv != nil {
		d.audit.Record(mv.v, e)
	}
}
