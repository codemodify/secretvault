package svd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// handle serves one request from a client.
func (d *Daemon) handle(ctx context.Context, conn *svrpc.Conn, method string, params json.RawMessage) (any, error) {
	cl := conn.Value.(*client)
	decode := func(v any) error {
		if len(params) == 0 {
			return nil
		}
		if err := json.Unmarshal(params, v); err != nil {
			return svrpc.Errorf(svrpc.CodeInvalidParams, "bad parameters for %s: %v", method, err)
		}
		return nil
	}
	res, err := d.dispatch(ctx, cl, method, decode)
	return res, mapErr(err)
}

// mapErr gives engine errors their protocol codes.
func mapErr(err error) error {
	var e *svrpc.Error
	switch {
	case err == nil, errors.As(err, &e):
		return err
	case errors.Is(err, svcore.ErrLocked):
		return svrpc.Errorf(svrpc.CodeLocked, "%v", err)
	case errors.Is(err, svcore.ErrNotFound):
		return svrpc.Errorf(svrpc.CodeNotFound, "%s", strings.TrimPrefix(err.Error(), "svcore: "))
	case errors.Is(err, svcore.ErrWrongKey):
		return svrpc.ErrWrongKey
	case errors.Is(err, svbroker.ErrNoGrant):
		return svrpc.Errorf(svrpc.CodeNotFound, "no such grant")
	}
	return svrpc.Errorf(svrpc.CodeFailed, "%s", strings.TrimPrefix(err.Error(), "svcore: "))
}

func (d *Daemon) dispatch(ctx context.Context, cl *client, method string, decode func(any) error) (any, error) {
	switch method {
	case svrpc.MHello:
		var p svrpc.HelloParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		cl.name, cl.canPrompt = p.Client, p.CanPrompt
		return svrpc.HelloResult{Daemon: "secretvaultd", Version: secretvault.Version, Caller: cl.display()}, nil

	case svrpc.MStatus:
		st := d.Status()
		st.SecretService = d.secretServiceState(ctx)
		if d.SSHAgentEnabled() {
			st.SSHAgent = svrpc.SSHAgentSocket()
		}
		return st, nil

	case svrpc.MKeyringServe:
		var p svrpc.KeyringServeParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, svrpc.Errorf(svrpc.CodeDenied, "%v", errNotCLI)
		}
		return nil, d.setSecretService(ctx, p.Enable)

	case svrpc.MVaultList:
		return d.vaultInfos(), nil

	case svrpc.MVaultCreate:
		var p svrpc.VaultCreateParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			clear(p.Passphrase)
			return nil, errOwnPrograms
		}
		mv, recovery, err := d.createVault(p)
		clear(p.Passphrase)
		if err != nil {
			return nil, err
		}
		d.proved(cl, mv)
		return svrpc.VaultCreateResult{Vault: d.info(mv), RecoveryKey: recovery}, nil

	case svrpc.MVaultAdd:
		var p svrpc.VaultAddParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		// A program that could register a folder of its own, or make it
		// the default, would have the next secrets stored where it can
		// read them.
		if !cl.cli {
			return nil, errOwnPrograms
		}
		mv, err := d.addVault(p)
		if err != nil {
			return nil, err
		}
		return d.info(mv), nil

	case svrpc.MVaultForget:
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, errOwnPrograms
		}
		return nil, d.forgetVault(p.Vault)

	case svrpc.MVaultDefault:
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, errOwnPrograms
		}
		return nil, d.setDefault(p.Vault)

	case svrpc.MVaultUnlock:
		var p svrpc.UnlockParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.vault(p.Vault)
		if err != nil {
			return nil, err
		}
		if p.Key == nil {
			if _, _, err := d.ensureUnlocked(ctx, cl, mv, cl.display()+" asks to unlock the vault."); err != nil {
				return nil, err
			}
			return d.info(mv), nil
		}
		var key svcore.Key
		wipe := func() {}
		if p.Key.Type == svformat.SlotFIDO2 {
			// The key plugged in; its PIN and touch are asked for like a
			// passphrase would be, one question about the vault at a time.
			if creds, err := mv.v.FIDO2Credentials(); err != nil {
				return nil, err
			} else if len(creds) == 0 {
				return nil, svrpc.Errorf(svrpc.CodeNotFound, "vault %q has no security key keyslot; add one with 'secretvault slot add fido2'", mv.cfg.Name)
			}
			pr, _ := d.passphrasePrompter(cl)
			key = svcore.SecurityKey(d.securityKeys(ctx, pr, "Unlock vault "+mv.cfg.Name,
				fmt.Sprintf("%s asks to unlock vault %q with a security key.", cl.display(), mv.cfg.Name)))
			mv.prompt.Lock()
			defer mv.prompt.Unlock()
		} else if key, wipe, err = keyFrom(mv, p.Key); err != nil {
			return nil, err
		}
		defer wipe()
		if mv.v.Locked() {
			err = d.unlockWith(mv, key)
		} else {
			err = mv.v.CheckKey(key)
		}
		if err != nil {
			d.audit.Record(mv.v, svbroker.Entry{Program: cl.display(), Identity: cl.identity(), PID: cl.proc.PID, Op: svbroker.OpManage, Outcome: "denied", Reason: "wrong key"})
			return nil, err
		}
		d.proved(cl, mv)
		d.audit.Record(mv.v, svbroker.Entry{Program: cl.display(), Identity: cl.identity(), PID: cl.proc.PID, Op: svbroker.OpManage, Outcome: "allowed", Reason: "unlocked with a " + p.Key.Type})
		return d.info(mv), nil

	case svrpc.MVaultLock:
		var p svrpc.LockParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		if p.All {
			d.LockAll("asked by " + cl.display())
			return nil, nil
		}
		mv, err := d.vault(p.Vault)
		if err != nil {
			return nil, err
		}
		d.lock(mv, "asked by "+cl.display())
		return nil, nil

	case svrpc.MVaultVerify:
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		rep, err := mv.v.Verify()
		if err != nil {
			return nil, err
		}
		out := svrpc.VerifyResult{Objects: rep.Objects, Revisions: rep.Revisions, Live: rep.Live}
		for _, pr := range rep.Problems {
			out.Problems = append(out.Problems, pr.Name+": "+pr.Err.Error())
		}
		for _, e := range rep.Conflicts {
			out.Conflicts = append(out.Conflicts, fmt.Sprintf("%s (%d competing revisions)", e.Item.Name, 1+len(e.Conflicts)))
			e.Item.Wipe()
		}
		if len(rep.Duplicates) > 0 {
			out.Duplicates = map[string][]string{}
			for name, ids := range rep.Duplicates {
				for _, id := range ids {
					out.Duplicates[name] = append(out.Duplicates[name], id.String())
				}
			}
		}
		return out, nil

	case svrpc.MVaultPasswd:
		var p svrpc.PasswdParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		defer clear(p.Passphrase)
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		if len(p.Passphrase) < MinPassphrase {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the passphrase is too short: use at least %d characters", MinPassphrase)
		}
		old := mv.v.UnlockedBy()
		info, err := mv.v.AddSlot(svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "passphrase", Passphrase: p.Passphrase})
		if err != nil {
			return nil, err
		}
		slots, err := mv.v.Slots()
		if err != nil {
			return nil, err
		}
		for _, s := range slots {
			if s.ID == old && s.Type == svformat.SlotPassphrase {
				if err := mv.v.RemoveSlot(old); err != nil {
					return nil, err
				}
			}
		}
		return slotInfo(mv, info), nil

	case svrpc.MVaultRotate:
		var p svrpc.RotateParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		defer clear(p.Passphrase)
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		if len(p.Passphrase) < MinPassphrase {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the passphrase is too short: use at least %d characters", MinPassphrase)
		}
		// Two devices rotating apart would fork the vault: rotate the
		// newest copy, and send the new epoch out at once (hook).
		if err := d.syncBefore(ctx, mv, "rotating its key"); err != nil {
			return nil, err
		}
		specs := []svcore.NewSlot{{Type: svformat.SlotPassphrase, Label: "passphrase", Passphrase: p.Passphrase}}
		if p.Recovery {
			specs = append(specs, svcore.NewSlot{Type: svformat.SlotRecovery, Label: "recovery key"})
		}
		drop := map[string]bool{}
		for _, id := range p.Drop {
			drop[id] = true
		}
		// A vault that opens at login keeps doing so: its login key gets a
		// slot for the new vault key too. If the OS will not open that key
		// now, the rotation goes ahead (cutting someone off matters more)
		// and the vault stops opening at login.
		var login *loginFile
		if mv.cfg.LoginUnlock {
			lf, key, err := d.loginKey(mv)
			if err == nil {
				defer clear(key)
				login = &lf
				specs = append(specs, svcore.NewSlot{Type: svformat.SlotKeyfile, Label: "login", Keyfile: key})
			} else {
				d.opts.Log(fmt.Sprintf("rotating %s: its login key could not be opened, so it will no longer open at login: %v", mv.cfg.Name, err))
			}
		}
		before, err := mv.v.Slots()
		if err != nil {
			return nil, err
		}
		epoch := mv.v.Epoch()
		infos, err := mv.v.Rotate(specs, true, func(s svcore.SlotInfo) bool { return drop[s.ID.String()] })
		if err != nil {
			return nil, err
		}
		carried := map[svformat.ID]bool{}
		if mv.cfg.LoginUnlock {
			moved := false
			for _, info := range infos {
				if login != nil && info.Type == svformat.SlotKeyfile && info.Label == "login" {
					moved = d.loginRotated(mv, *login, info.ID) == nil
				}
			}
			if moved {
				carried[login.Slot] = true
			} else if err := d.loginOff(mv); err != nil {
				d.opts.Log(fmt.Sprintf("rotating %s: turning login unlock off: %v", mv.cfg.Name, err))
			}
		}
		d.broker.Locked(mv.v.ID()) // decisions tied to the old key's session go
		d.proved(cl, mv)
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("rotated the vault key to epoch %d", mv.v.Epoch()))
		out := svrpc.RotateResult{Epoch: mv.v.Epoch()}
		for _, info := range infos {
			out.Slots = append(out.Slots, slotInfo(mv, info))
			if info.RecoveryKey != "" {
				out.RecoveryKey = info.RecoveryKey
			}
		}
		for _, s := range before {
			if s.Epoch == epoch && (s.Type == svformat.SlotKeyfile || s.Type == svformat.SlotFIDO2) && !carried[s.ID] {
				out.Dropped = append(out.Dropped, slotInfo(mv, s))
			}
		}
		return out, nil

	case svrpc.MSlotList:
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.vault(p.Vault)
		if err != nil {
			return nil, err
		}
		slots, err := mv.v.Slots()
		if err != nil {
			return nil, err
		}
		out := []svrpc.SlotInfo{}
		for _, s := range slots {
			out = append(out, slotInfo(mv, s))
		}
		return out, nil

	case svrpc.MSlotAdd:
		var p svrpc.SlotAddParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		defer clear(p.Secret)
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		ns := svcore.NewSlot{Type: p.Type, Label: p.Label}
		switch p.Type {
		case svformat.SlotFIDO2:
			// The key's PIN and touches are asked for where a passphrase
			// would be, one question about the vault at a time.
			pr, _ := d.passphrasePrompter(cl)
			ns.SecurityKeys = d.securityKeys(ctx, pr, "Add a security key to vault "+mv.cfg.Name,
				fmt.Sprintf("%s asks to add a security key to vault %q.", cl.display(), mv.cfg.Name))
			ns.FIDO2UV = p.UV
			mv.prompt.Lock()
			defer mv.prompt.Unlock()
		case svformat.SlotPassphrase:
			if len(p.Secret) < MinPassphrase {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the passphrase is too short: use at least %d characters", MinPassphrase)
			}
			ns.Passphrase = p.Secret
		case svformat.SlotKeyfile:
			ns.Keyfile = p.Secret
		case svformat.SlotRecipient:
			suite, pub, err := svformat.ParseRecipient(string(p.Secret))
			if err != nil {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
			}
			if suite != mv.v.Suite() {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "that recipient is for %v; this vault uses %v", suite, mv.v.Suite())
			}
			ns.Recipient = pub
		}
		info, err := mv.v.AddSlot(ns)
		if err != nil {
			return nil, err
		}
		out := slotInfo(mv, info)
		out.RecoveryKey = info.RecoveryKey
		return out, nil

	case svrpc.MSlotRemove:
		var p svrpc.SlotRemoveParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		id, err := svformat.ParseID(p.ID)
		if err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		return nil, mv.v.RemoveSlot(id)

	case svrpc.MItemGet, svrpc.MItemHistory:
		var p svrpc.ItemRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, e, err := d.item(ctx, cl, p.Vault, p.Name, svbroker.OpRead)
		if err != nil {
			return nil, err
		}
		if method == svrpc.MItemGet {
			return toEntry(e, true), nil
		}
		e.Item.Wipe()
		hist, err := mv.v.History(p.Name)
		if err != nil {
			return nil, err
		}
		out := []svrpc.Entry{}
		for _, h := range hist {
			out = append(out, toEntry(h, true))
			h.Item.Wipe()
		}
		return out, nil

	case svrpc.MItemList:
		var p svrpc.ListParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpList)
		if err != nil {
			return nil, err
		}
		entries, err := mv.v.List(p.Prefix)
		if err != nil {
			return nil, err
		}
		out := []svrpc.Entry{}
		for _, e := range entries {
			out = append(out, toEntry(e, false))
			e.Item.Wipe()
		}
		return out, nil

	case svrpc.MItemPut:
		var p svrpc.PutParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		it := fromItem(p.Item)
		defer it.Wipe()
		if err := svcore.CheckName(it.Name); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		mv, err := d.vault(p.Vault)
		if err != nil {
			return nil, err
		}
		// Changing an item needs consent for that item; creating one, for
		// the vault.
		itemID := ""
		if !mv.v.Locked() {
			if e, err := mv.v.Get(it.Name); err == nil {
				itemID = e.ID.String()
				e.Item.Wipe()
			}
		}
		if _, err := d.managed(ctx, cl, p.Vault, itemID, it.Name, svbroker.OpWrite); err != nil {
			return nil, err
		}
		e, err := mv.v.Put(it)
		if err != nil {
			return nil, err
		}
		defer e.Item.Wipe()
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: it.Name})
		return toEntry(e, false), nil

	case svrpc.MItemDelete:
		var p svrpc.ItemRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, e, err := d.item(ctx, cl, p.Vault, p.Name, svbroker.OpDelete)
		if err != nil {
			return nil, err
		}
		e.Item.Wipe()
		if err := mv.v.Delete(p.Name); err != nil {
			return nil, err
		}
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Name})
		return nil, nil

	case svrpc.MItemRename:
		var p svrpc.RenameParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, e, err := d.item(ctx, cl, p.Vault, p.From, svbroker.OpWrite)
		if err != nil {
			return nil, err
		}
		e.Item.Wipe()
		ne, err := mv.v.Rename(p.From, p.To)
		if err != nil {
			return nil, err
		}
		defer ne.Item.Wipe()
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.To})
		return toEntry(ne, false), nil

	case svrpc.MGrantList:
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		views, err := d.broker.List(mv.v)
		if err != nil {
			return nil, err
		}
		out := []svrpc.Grant{}
		for _, v := range views {
			var ops []string
			for _, op := range v.Grant.Ops {
				ops = append(ops, string(op))
			}
			out = append(out, svrpc.Grant{ID: v.ID, Vault: mv.cfg.Name, Program: v.Grant.Program, Identity: v.Grant.Identity,
				Item: v.Grant.ItemName, Ops: ops, Decision: string(v.Grant.Decision), Created: v.Grant.Created, Scope: v.Scope})
		}
		return out, nil

	case svrpc.MGrantRevoke:
		var p svrpc.GrantRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		return nil, d.broker.Revoke(mv.v, p.ID)

	case svrpc.MGrantAdd:
		var p svrpc.GrantAddParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		prog, err := svpeer.ForPath(p.Program)
		if err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		g := svbroker.Grant{Identity: prog.Identity(), Program: prog.Display(), ItemName: p.Item, Decision: svbroker.Decision(p.Decision)}
		if p.Contacts {
			if p.Item != "" {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "a decision is about an item or about contacts, not both")
			}
			g.Item, g.ItemName = contactsScope, contactsName
		}
		switch g.Decision {
		case svbroker.AllowAlways, svbroker.AllowUntilLock, svbroker.DenyAlways:
		default:
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "decision %q is not allow-always, allow-until-lock or deny-always", p.Decision)
		}
		if p.Item != "" {
			e, err := mv.v.Get(p.Item)
			if err != nil {
				return nil, err
			}
			g.Item = e.ID.String()
			e.Item.Wipe()
		}
		if len(p.Ops) == 0 {
			p.Ops = []string{string(svbroker.OpRead)}
		}
		for _, op := range p.Ops {
			if _, known := verbs[svbroker.Op(op)]; !known {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "unknown operation %q (read, list, write, delete, manage, sign, decrypt)", op)
			}
			g.Ops = append(g.Ops, svbroker.Op(op))
		}
		if err := d.broker.Remember(mv.v, g); err != nil {
			return nil, err
		}
		return svrpc.Grant{Vault: mv.cfg.Name, Program: g.Program, Identity: g.Identity, Item: g.ItemName, Ops: p.Ops, Decision: p.Decision}, nil

	case svrpc.MAuditList:
		var p svrpc.AuditParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		entries, rerr := d.audit.Read(mv.v, p.Limit)
		out := []svrpc.AuditEntry{}
		for _, e := range entries {
			out = append(out, svrpc.AuditEntry{Time: e.Time, Program: e.Program, PID: e.PID, Op: string(e.Op), Item: e.Item, Outcome: e.Outcome, Reason: e.Reason})
		}
		if errors.Is(rerr, svbroker.ErrLogDamaged) {
			out = append(out, svrpc.AuditEntry{Outcome: "log-damaged", Reason: "lines of this log were removed or changed"})
			rerr = nil
		}
		return out, rerr

	case svrpc.MPromptRegister:
		var p svrpc.PromptRegisterParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		// The prompter sees the passphrases typed into it: only
		// secretvault's own programs may be it.
		if !cl.cli && !d.opts.IsPromptAgent(cl.proc) {
			return nil, svrpc.Errorf(svrpc.CodeDenied, "only secretvault-tui-prompt may register as the prompter")
		}
		d.mu.Lock()
		d.agent = cl
		d.mu.Unlock()
		return nil, nil
	}
	if h, ok := handlers[method]; ok {
		return h(d, ctx, cl, decode)
	}
	return nil, svrpc.Errorf(svrpc.CodeMethodNotFound, "no method %q", method)
}

// handler serves one method. decode reads the request's parameters.
type handler func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error)

// handlers holds the methods served outside dispatch's switch: each area
// (sync, containers, contacts, ...) registers its own from an init
// function in its own file.
var handlers = map[string]handler{}

// registerMethod makes h method's handler. It is called from init
// functions only.
func registerMethod(method string, h handler) {
	if _, dup := handlers[method]; dup {
		panic("svd: two handlers for " + method)
	}
	handlers[method] = h
}

// managed resolves a vault and authorizes a vault-wide (or item) operation.
func (d *Daemon) managed(ctx context.Context, cl *client, vault, item, itemName string, op svbroker.Op) (*managedVault, error) {
	mv, err := d.vault(vault)
	if err != nil {
		return nil, err
	}
	if err := d.authorize(ctx, cl, mv, item, itemName, op); err != nil {
		return nil, err
	}
	return mv, nil
}

// item resolves and authorizes an operation on a named item. The vault is
// unlocked first (if need be) to find the item's identity, so the
// decision is about this item, not its name.
func (d *Daemon) item(ctx context.Context, cl *client, vault, name string, op svbroker.Op) (*managedVault, svcore.Entry, error) {
	mv, err := d.vault(vault)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	why := describeRequest(cl, mv, name, op)
	record := d.recorder(cl, mv, name, op)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		record(outcomeOf(err), err.Error())
		return nil, svcore.Entry{}, err
	}
	e, err := mv.v.Get(name)
	if err != nil {
		return nil, svcore.Entry{}, err
	}
	if err := d.decide(ctx, cl, mv, e.ID.String(), name, op, why, prompted, own, record); err != nil {
		e.Item.Wipe()
		return nil, svcore.Entry{}, err
	}
	return mv, e, nil
}

// keyFrom turns a presented key into an engine key.
func keyFrom(mv *managedVault, k *svrpc.Key) (svcore.Key, func(), error) {
	wipe := func() { clear(k.Secret) }
	switch k.Type {
	case svformat.SlotPassphrase:
		return svcore.Passphrase(k.Secret), wipe, nil
	case svformat.SlotKeyfile:
		return svcore.Keyfile(k.Secret), wipe, nil
	case svformat.SlotRecovery:
		rk, err := svformat.ParseRecoveryKey(string(k.Secret))
		if err != nil {
			return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		return svcore.RecoveryKey(rk), func() { clear(rk); wipe() }, nil
	case "identity":
		for _, line := range strings.Split(string(k.Secret), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			suite, priv, err := svformat.ParseIdentity(line)
			if err != nil {
				return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
			}
			id, err := suite.ParseIdentity(priv)
			clear(priv)
			if err != nil {
				return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
			}
			return svcore.IdentityKey(id), wipe, nil
		}
		return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "no identity in what was given")
	}
	return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "unknown key type %q", k.Type)
}

func slotInfo(mv *managedVault, s svcore.SlotInfo) svrpc.SlotInfo {
	out := svrpc.SlotInfo{ID: s.ID.String(), Type: s.Type, Label: s.Label, Created: s.Created}
	switch {
	case s.KDF != nil && s.KDF.Alg == svcrypto.Argon2id:
		mem := fmt.Sprintf("%dKiB", s.KDF.MemoryKiB)
		if s.KDF.MemoryKiB%1024 == 0 {
			mem = fmt.Sprintf("%dMiB", s.KDF.MemoryKiB/1024)
		}
		out.Detail = fmt.Sprintf("argon2id t=%d m=%s p=%d", s.KDF.Time, mem, s.KDF.Threads)
	case s.KDF != nil:
		out.Detail = fmt.Sprintf("%s i=%d", s.KDF.Alg, s.KDF.Iterations)
	case s.Recipient != nil:
		out.Recipient = svformat.EncodeRecipient(mv.v.Suite(), s.Recipient)
	case s.FIDO2 != nil:
		out.Detail = "touch"
		if s.FIDO2.UV {
			out.Detail = "PIN and touch"
		}
		out.Detail += ", model " + uuid(s.FIDO2.AAGUID)
	}
	return out
}

func toEntry(e svcore.Entry, withFields bool) svrpc.Entry {
	out := svrpc.Entry{ID: e.ID.String(), Rev: e.Rev.String(), Time: e.Time, Deleted: e.Deleted,
		Item: svrpc.Item{Kind: e.Item.Kind, Name: e.Item.Name, Label: e.Item.Label, Attrs: e.Item.Attrs, Tags: e.Item.Tags}}
	if !e.Device.IsZero() {
		out.Device = e.Device.String()
	}
	for _, r := range e.Conflicts {
		out.Conflicts = append(out.Conflicts, r.String())
	}
	for _, f := range e.Item.Files {
		out.Item.Files = append(out.Item.Files, fileInfo(f))
	}
	if withFields {
		for _, f := range e.Item.Fields {
			out.Item.Fields = append(out.Item.Fields, svrpc.Field{Name: f.Name, Type: f.Type, Value: append([]byte(nil), f.Value...)})
		}
	}
	return out
}

func fromItem(it svrpc.Item) svcore.Item {
	out := svcore.Item{Kind: it.Kind, Name: it.Name, Label: it.Label, Attrs: it.Attrs, Tags: it.Tags}
	for _, f := range it.Fields {
		out.Fields = append(out.Fields, svcore.Field{Name: f.Name, Type: f.Type, Value: f.Value})
	}
	return out
}
