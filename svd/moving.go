package svd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// Items going from one vault to another (item.move, item.copy), inside
// the daemon: a program never holds what it moves, private keys
// included, and the person decides once, in one question that names both
// vaults, what goes, and who else reads the vault it goes to.
//
//  1. The parameters are checked: the other vault is named, and is
//     another; names or a prefix, not both; at most svrpc.MaxMoveItems.
//  2. Both vaults are unlocked, each through the daemon's own unlock
//     prompt if need be.
//  3. The items are resolved, and every check that could refuse the whole
//     request is made before anything is asked or written: a name that is
//     not there (-32003), an item with competing versions ("settle the
//     conflict first"), a name the other vault has already (-32006).
//  4. Consent. A program is asked once, every time: nothing remembered
//     allows it (a remembered "deny" refuses it), and neither "always"
//     nor "until the vault locks" is offered. Copying is asked the same
//     way: a copy in a vault others read is a disclosure to them, which
//     no grant to read an item was about. secretvault's own programs
//     confirm it in their own words, and the daemon asks of them what it
//     asks for any use of the two vaults (authorize): read (and, for a
//     move, delete) in the first, write in the other.
//  5. Every item is written to the other vault (svcore.CopyTo: its files
//     sealed again there, and read back). Only when all are written are
//     they taken out of the first vault, each a deletion of the version
//     that was copied (svcore.DeleteRev), so it can be brought back from
//     its deleted items. A failure midway leaves duplicates, never a
//     loss, and the reply says which items are where.
//
// Both vaults' audit logs say what went, which program asked, and how it
// ended; nothing secret is in them, in the reply or in the daemon's log.

func init() {
	registerMethod(svrpc.MItemMove, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		return d.moveItems(ctx, cl, decode, false)
	})
	registerMethod(svrpc.MItemCopy, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		return d.moveItems(ctx, cl, decode, true)
	})
}

// moveStep is called before each item is written to the other vault
// (stage "write") and before each is taken out of the first ("remove"):
// an error stops the request there, as a failure would. Tests stand in
// for it.
var moveStep = func(stage, name string) error { return nil }

// moving is an item on its way, as it was when it was resolved.
type moving struct {
	id   svformat.ID
	rev  svformat.RevID
	name string
}

func movingNames(items []moving) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.name
	}
	return out
}

// moveError is an error whose Data is res.
func moveError(code int, res svrpc.MoveResult, format string, args ...any) error {
	e := svrpc.Errorf(code, format, args...)
	e.Data, _ = json.Marshal(res)
	return e
}

// moveItems serves item.move (copy false) and item.copy.
func (d *Daemon) moveItems(ctx context.Context, cl *client, decode func(any) error, copy bool) (any, error) {
	var p svrpc.MoveParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	verb := "move"
	if copy {
		verb = "copy"
	}
	names, err := moveParams(&p, verb)
	if err != nil {
		return nil, err
	}
	// The person's own programs, which confirm it in their own words; any
	// other program is asked here.
	own := cl.role == roleAdmin || cl.mayPrompt()
	if p.Plan && !own {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "only secretvault's own programs may see what a %s would do before it is asked about", verb)
	}
	src, err := d.vault(p.Vault)
	if err != nil {
		return nil, err
	}
	dst, err := d.vault(p.To)
	if err != nil {
		return nil, err
	}
	if src == dst {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the items are in vault %q already: name another vault to %s them to", dst.cfg.Name, verb)
	}
	if dst.cfg.Emergency != "" {
		return nil, errTheirs(dst)
	}
	if !copy && src.cfg.Emergency != "" {
		return nil, errTheirs(src)
	}

	srcOp := svbroker.OpDelete
	if copy {
		srcOp = svbroker.OpRead
	}
	recSrc := d.recorder(cl, src, "", srcOp)
	recDst := d.recorder(cl, dst, "", svbroker.OpWrite)
	both := func(outcome, reason string) {
		recSrc(outcome, reason)
		recDst(outcome, reason)
	}

	if own {
		// What the daemon asks of secretvault's own programs for any use
		// of these vaults: the passphrase on its terminal, or in its
		// window, once until the vault locks.
		ops := []struct {
			mv *managedVault
			op svbroker.Op
		}{{src, svbroker.OpRead}, {dst, svbroker.OpWrite}}
		if !copy {
			ops = append(ops, struct {
				mv *managedVault
				op svbroker.Op
			}{src, svbroker.OpDelete})
		}
		for _, o := range ops {
			if err := d.authorize(ctx, cl, o.mv, "", "", o.op); err != nil {
				return nil, err
			}
		}
	} else {
		why := fmt.Sprintf("%s wants to %s items from vault %q to vault %q.", cl.display(), verb, src.cfg.Name, dst.cfg.Name)
		for _, mv := range []*managedVault{src, dst} {
			if _, _, err := d.ensureUnlocked(ctx, cl, mv, why); err != nil {
				both(outcomeOf(err), fmt.Sprintf("%s from vault %q to vault %q: %v", verb, src.cfg.Name, dst.cfg.Name, err))
				return nil, err
			}
		}
	}

	items, err := d.resolveMove(src, dst, p, names, verb)
	if err != nil {
		both("failed", fmt.Sprintf("%s from vault %q to vault %q: %v", verb, src.cfg.Name, dst.cfg.Name, err))
		return nil, err
	}
	if p.Plan {
		return svrpc.MoveResult{Vault: src.cfg.Name, To: dst.cfg.Name, Items: movingNames(items), Readers: d.readers(dst), Done: []string{}}, nil
	}
	what := fmt.Sprintf("%s %s from vault %q to vault %q", verb, svops.CountItems(len(items)), src.cfg.Name, dst.cfg.Name)
	if own {
		both("allowed", what+": secretvault's own program, which confirmed it")
	} else if err := d.askMove(ctx, cl, src, dst, items, copy); err != nil {
		both(outcomeOf(err), what+": "+reasonOf(err))
		return nil, err
	} else {
		both("allowed", what+": the person said yes")
	}
	return d.carryOut(cl, src, dst, items, copy)
}

// reasonOf is an error's message, for an audit log.
func reasonOf(err error) string {
	var e *svrpc.Error
	if errors.As(err, &e) {
		return e.Message
	}
	return err.Error()
}

// moveParams checks p's shape, and returns the names it gives, each once.
func moveParams(p *svrpc.MoveParams, verb string) ([]string, error) {
	switch {
	case p.To == "":
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "name the vault to %s the items to (to)", verb)
	case p.Names != nil && p.Prefix != nil:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "give the items' names or a prefix of them, not both")
	case p.Prefix == nil && len(p.Names) == 0:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "name the items to %s (names), or give what their names start with (prefix; \"\" for every item)", verb)
	case p.Vault == p.To:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the items are in vault %q already: name another vault to %s them to", p.To, verb)
	}
	if p.Prefix != nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range p.Names {
		if err := svcore.CheckName(n); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svcore: "))
		}
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) > svrpc.MaxMoveItems {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%d items named: at most %d %s in one request; %s the rest in another", len(names), svrpc.MaxMoveItems, verb, verb)
	}
	return names, nil
}

// resolveMove finds the items p names in src, as they are now, and makes
// every check that refuses the whole request before anything is written.
func (d *Daemon) resolveMove(src, dst *managedVault, p svrpc.MoveParams, names []string, verb string) ([]moving, error) {
	res := svrpc.MoveResult{Vault: src.cfg.Name, To: dst.cfg.Name, Done: []string{}}
	var items []moving
	var conflicts []string
	take := func(e svcore.Entry) {
		e.Item.Wipe()
		if len(e.Conflicts) > 0 {
			conflicts = append(conflicts, e.Item.Name)
		}
		items = append(items, moving{id: e.ID, rev: e.Rev, name: e.Item.Name})
	}
	if p.Prefix != nil {
		entries, err := src.v.List(*p.Prefix)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			take(e)
		}
		switch {
		case len(items) == 0 && *p.Prefix == "":
			return nil, moveError(svrpc.CodeNotFound, res, "vault %q has no items to %s", src.cfg.Name, verb)
		case len(items) == 0:
			return nil, moveError(svrpc.CodeNotFound, res, "no item of vault %q has a name that starts with %q", src.cfg.Name, *p.Prefix)
		case len(items) > svrpc.MaxMoveItems:
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams,
				"%d items of vault %q start with %q: at most %d %s in one request; give a longer prefix, or name them",
				len(items), src.cfg.Name, *p.Prefix, svrpc.MaxMoveItems, verb)
		}
	} else {
		for _, n := range names {
			e, err := src.v.Get(n)
			if errors.Is(err, svcore.ErrNotFound) {
				res.Missing = append(res.Missing, n)
				continue
			}
			if err != nil {
				return nil, err
			}
			take(e)
		}
		if len(res.Missing) > 0 {
			return nil, moveError(svrpc.CodeNotFound, res, "vault %q has no item called %s: nothing was %s", src.cfg.Name, svops.ItemsPhrase(res.Missing), pastOf(verb))
		}
	}
	if len(conflicts) > 0 {
		res.Conflicts = conflicts
		return nil, moveError(svrpc.CodeFailed, res,
			"%s changed on two devices at once: settle the conflict first (keep one version: 'secretvault resolve NAME', or the item's History); nothing was %s",
			svops.ItemsPhrase(conflicts), pastOf(verb))
	}
	for _, it := range items {
		e, err := dst.v.Get(it.name)
		if err == nil {
			e.Item.Wipe()
			res.Clashes = append(res.Clashes, it.name)
			continue
		}
		if !errors.Is(err, svcore.ErrNotFound) {
			return nil, err
		}
	}
	if len(res.Clashes) > 0 {
		return nil, moveError(svrpc.CodeExists, res, "vault %q has %s already: nothing was %s; rename or delete one of each first",
			dst.cfg.Name, svops.ItemsPhrase(res.Clashes), pastOf(verb))
	}
	return items, nil
}

func pastOf(verb string) string {
	if verb == "copy" {
		return "copied"
	}
	return "moved"
}

// askMove asks the person whether cl may move (or copy) items from src
// to dst: once, every time, with no answer remembered.
func (d *Daemon) askMove(ctx context.Context, cl *client, src, dst *managedVault, items []moving, copy bool) error {
	verb := "move"
	srcOp := svbroker.OpDelete
	if copy {
		verb, srcOp = "copy", svbroker.OpRead
	}
	// A "deny" remembered for this program, about either vault or any
	// of the items, holds; nothing remembered allows it.
	refused := func(mv *managedVault, item string, op svbroker.Op) bool {
		dec, found, err := d.broker.Check(mv.v, cl, cl.identity(), item, op)
		return err == nil && found && !dec.Allows()
	}
	if refused(dst, "", svbroker.OpWrite) || refused(src, "", srcOp) || refused(src, "", svbroker.OpRead) {
		return svrpc.Errorf(svrpc.CodeDenied, "access was denied: a remembered decision says no")
	}
	for _, it := range items {
		if refused(src, it.id.String(), svbroker.OpRead) || refused(src, it.id.String(), srcOp) {
			return svrpc.Errorf(svrpc.CodeDenied, "access to %q was denied: a remembered decision says no", it.name)
		}
	}

	p := d.consentPrompter(cl)
	if p == nil {
		return svrpc.Errorf(svrpc.CodeNoPrompter,
			"%s asks to %s items from vault %q to vault %q, but there is no way to ask you here (no desktop prompt, no 'secretvault-tui-prompt --agent'); "+
				"%s them yourself with 'secretvault %s --vault %s --to %s NAME...'",
			cl.display(), verb, src.cfg.Name, dst.cfg.Name, verb, map[bool]string{false: "mv", true: "cp"}[copy], src.cfg.Name, dst.cfg.Name)
	}
	// One question about each vault on screen at a time, taken in the
	// same order by every request, so two never wait on each other.
	first, second := src, dst
	if second.cfg.Name < first.cfg.Name {
		first, second = second, first
	}
	first.prompt.Lock()
	defer first.prompt.Unlock()
	second.prompt.Lock()
	defer second.prompt.Unlock()

	who := shortName(cl.proc)
	names := movingNames(items)
	count := svops.CountItems(len(items))
	facts := "Program: " + svpeer.Printable(cl.proc.Exe)
	if cl.proc.Exe == "" {
		facts = "Program: " + cl.display()
	}
	if cl.proc.Script != "" {
		facts += "\nScript: " + svpeer.Printable(cl.proc.Script)
	}
	var what string
	if copy {
		what = fmt.Sprintf("%s asks to copy %s from vault %q to vault %q: %s. Vault %q keeps them as they are. "+
			"Their attached files go with the copies, and %s does not see what is in them.",
			who, count, src.cfg.Name, dst.cfg.Name, svops.ItemsPhrase(names), src.cfg.Name, who)
	} else {
		what = fmt.Sprintf("%s asks to move %s from vault %q to vault %q: %s. They leave %q, and can be brought back from its deleted items. "+
			"Their attached files go with them, and %s does not see what is in them.",
			who, count, src.cfg.Name, dst.cfg.Name, svops.ItemsPhrase(names), src.cfg.Name, who)
	}
	desc := what
	if readers := svops.ReadersText(dst.cfg.Name, d.readers(dst)); readers != "" {
		desc += "\n\n" + readers
	}
	desc += fmt.Sprintf("\n\n%s\nProcess: %d", facts, cl.proc.PID)
	action, refuse := "Move "+count, "Don't move them"
	if copy {
		action, refuse = "Copy "+count, "Don't copy them"
	}
	choice, err := p.Choose(ctx, svrpc.PromptAsk{
		Kind:  svrpc.PromptChoose,
		Title: fmt.Sprintf("%s wants to %s %s to vault %s", who, verb, count, dst.cfg.Name),
		// Refusing comes last, which secretvault's prompts make the
		// default and a plain pinentry its Cancel (Escape).
		Description: desc,
		Choices:     []svrpc.Choice{{ID: svrpc.ChoiceOnce, Label: action}, {ID: svrpc.ChoiceDeny, Label: refuse}},
	})
	switch {
	case errors.Is(err, svrpc.ErrCanceled):
		return svrpc.Errorf(svrpc.CodeCanceled, "the person did not answer whether to %s the items", verb)
	case err != nil:
		return err
	case choice != svrpc.ChoiceOnce:
		return svrpc.Errorf(svrpc.CodeDenied, "the person chose not to %s the items to vault %q", verb, dst.cfg.Name)
	}
	d.touch(src)
	d.touch(dst)
	return nil
}

// carryOut writes every item to dst and then, for a move, takes each out
// of src, and says what became of them.
func (d *Daemon) carryOut(cl *client, src, dst *managedVault, items []moving, copy bool) (any, error) {
	verb, srcOp := "moved", svbroker.OpDelete
	if copy {
		verb, srcOp = "copied", svbroker.OpRead
	}
	res := svrpc.MoveResult{Vault: src.cfg.Name, To: dst.cfg.Name, Done: []string{}}
	var written []moving
	var failed error
	for i, it := range items {
		err := moveStep("write", it.name)
		if err == nil {
			var e svcore.Entry
			e, err = src.v.CopyTo(dst.v, it.id, it.rev)
			e.Item.Wipe()
		}
		if err != nil {
			failed = fmt.Errorf("%q was not written to vault %q: %s", it.name, dst.cfg.Name, strings.TrimPrefix(err.Error(), "svcore: "))
			res.NotDone = movingNames(items[i:])
			d.recorder(cl, dst, it.name, svbroker.OpWrite)("failed", fmt.Sprintf("not %s from vault %q: %s", verb, src.cfg.Name, strings.TrimPrefix(err.Error(), "svcore: ")))
			break
		}
		written = append(written, it)
		d.recorder(cl, dst, it.name, svbroker.OpWrite)("allowed", fmt.Sprintf("%s from vault %q", verb, src.cfg.Name))
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: dst.cfg.Name, Item: it.name})
	}

	switch {
	case copy:
		res.Done = append(res.Done, movingNames(written)...)
		for _, it := range written {
			d.recorder(cl, src, it.name, srcOp)("allowed", fmt.Sprintf("copied to vault %q", dst.cfg.Name))
		}
	case failed != nil:
		// Nothing is taken out of src: what was written is in both.
		res.Both = movingNames(written)
		for _, it := range written {
			d.recorder(cl, src, it.name, srcOp)("failed", fmt.Sprintf("copied to vault %q, and left here: the move stopped before taking anything out", dst.cfg.Name))
		}
	default:
		stopped := false
		for _, it := range written {
			err := errors.New("an earlier item could not be taken out")
			if !stopped {
				if err = moveStep("remove", it.name); err == nil {
					err = src.v.DeleteRev(it.id, it.rev)
				}
			}
			if err != nil {
				res.Both = append(res.Both, it.name)
				why := strings.TrimPrefix(err.Error(), "svcore: ")
				d.recorder(cl, src, it.name, srcOp)("failed", fmt.Sprintf("copied to vault %q, and left here: %s", dst.cfg.Name, why))
				if failed == nil {
					failed = fmt.Errorf("%q is in both vaults: %s", it.name, why)
				}
				// An item changed meanwhile stays, and the rest go on;
				// anything else stops the taking out.
				if !errors.Is(err, svcore.ErrChanged) && !errors.Is(err, svcore.ErrConflict) {
					stopped = true
				}
				continue
			}
			res.Done = append(res.Done, it.name)
			d.recorder(cl, src, it.name, srcOp)("allowed", fmt.Sprintf("moved to vault %q (in the deleted items here)", dst.cfg.Name))
			d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: src.cfg.Name, Item: it.name})
		}
	}
	d.opts.Log(fmt.Sprintf("%s %s %s from %s to %s; %d in both, %d not %s",
		cl.display(), verb, svops.CountItems(len(res.Done)), src.cfg.Name, dst.cfg.Name, len(res.Both), len(res.NotDone), verb))
	if failed != nil {
		return nil, moveError(svrpc.CodeFailed, res, "%s (%v)", svops.MovedText(res, copy), failed)
	}
	return res, nil
}

// readers says who besides the person and this device can read what is
// in mv, which is unlocked; nil when nobody can.
func (d *Daemon) readers(mv *managedVault) *svrpc.VaultReaders {
	var r svrpc.VaultReaders
	epoch := mv.v.Epoch()
	if slots, err := mv.v.Slots(); err == nil {
		trustees := map[string]string{}
		if recs, err := grantRecords(mv.v); err == nil {
			for id, g := range recs {
				trustees[id] = g.Trustee
			}
			wipeGrants(recs)
		}
		for _, s := range slots {
			if s.Epoch != epoch {
				continue // cut off: it opens nothing written now
			}
			switch s.Type {
			case svformat.SlotRecipient:
				r.People = append(r.People, s.Label)
			case svformat.SlotEmergency:
				r.Trustees = append(r.Trustees, trustees[s.Grant.String()])
			}
		}
	}
	if devs, err := mv.v.Devices(); err == nil {
		for _, dv := range devs {
			if !dv.This && !dv.Removed && dv.Device != d.svOpts.Device {
				r.Devices = append(r.Devices, dv.Label)
			}
		}
	}
	if mv.cfg.Sync != nil {
		r.Sync = mv.cfg.Sync.URL
		if u, err := url.Parse(mv.cfg.Sync.URL); err == nil && u.Host != "" {
			r.Sync = u.Hostname()
		}
	}
	if !r.Anyone() {
		return nil
	}
	return &r
}
