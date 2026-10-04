package svd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// Passkeys, for the secretvault extension (svext/webauthn.go,
// docs/browser.md). The extension's request names the page's origin, the
// rpId and the clientDataJSON it built; svext.Session has checked that
// the rpId fits the origin and that clientDataJSON says what the request
// says. Here:
//
//   - Listing the passkeys for an rpId (names and user names) is listing
//     the vault (OpList), decided as for any program.
//   - Making one is a write (OpWrite): the key pair is made here, kept in
//     the vault as a "passkey" item, and only its public half leaves.
//   - Signing with one is the broker's sign (OpSign) on that item:
//     decided like any other use, remembered or asked. The private key
//     never leaves the daemon.
//   - When the page requires user verification, the person is asked for
//     the vault's passphrase in secretvault's own prompt, which is the
//     consent as well (a remembered no still refuses), and only then is
//     the UV flag set. Nothing else sets it.
//
// The person has already chosen in the extension's own window (a click
// the page cannot make); these are the daemon's own decisions on top.

// passkeyFolder is where new passkeys go.
const passkeyFolder = "passkeys"

// passkeyFlags are the flags of every passkey's authenticatorData: the
// person was present (they chose it in secretvault's window), and the
// credential is backup eligible and backed up (it is in a vault, which
// may be synced). UV is added only when the person was verified.
const passkeyFlags = svext.FlagUP | svext.FlagBE | svext.FlagBS

// passkeysOf are mv's passkeys for rpID (those in allow, when not empty),
// read without their keys, best first: by title. The caller wipes the
// entries.
func passkeysOf(mv *managedVault, rpID string, allow [][]byte) ([]svcore.Entry, []*svext.PasskeyRecord, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return nil, nil, err
	}
	var es []svcore.Entry
	var rs []*svext.PasskeyRecord
	for _, e := range entries {
		if e.Item.Kind != svext.PasskeyKind {
			e.Item.Wipe()
			continue
		}
		r, err := svext.ReadPasskey(svext.ItemField(&e.Item), false)
		if err != nil || r.RPID != rpID || len(allow) > 0 && !inList(allow, r.CredentialID) {
			e.Item.Wipe()
			continue
		}
		es = append(es, e)
		rs = append(rs, r)
	}
	idx := make([]int, len(es))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return strings.ToLower(title(&es[idx[a]])) < strings.ToLower(title(&es[idx[b]]))
	})
	outE, outR := make([]svcore.Entry, len(es)), make([]*svext.PasskeyRecord, len(es))
	for i, j := range idx {
		outE[i], outR[i] = es[j], rs[j]
	}
	return outE, outR, nil
}

func inList(list [][]byte, id []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

func (b *extSession) Passkeys(ctx context.Context, vault string, o svext.Origin, rpID string, allow [][]byte) ([]svext.PasskeyEntry, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return nil, err
	}
	why := fmt.Sprintf("%s wants to see which passkeys in vault %q are for %s (their names and user names), for %s%s", b.app.display(), mv.cfg.Name, rpID, o, through)
	if err := b.decide(ctx, mv, "", "", svbroker.OpList, why); err != nil {
		return nil, err
	}
	es, rs, err := passkeysOf(mv, rpID, allow)
	if err != nil {
		return nil, b.fail(err)
	}
	defer wipeAll(es)
	out := []svext.PasskeyEntry{}
	for i := range es {
		out = append(out, svext.PasskeyEntry{ID: es[i].ID.String(), CredentialID: svext.B64.EncodeToString(rs[i].CredentialID), Title: clip(title(&es[i]), 256),
			UserName: clip(rs[i].UserName, 256), DisplayName: clip(rs[i].DisplayName, 256)})
	}
	return out, nil
}

// verified asks the person for mv's passphrase, to verify it is them (a
// page that requires user verification): it is the consent too. A
// remembered no still refuses.
func (b *extSession) verified(ctx context.Context, mv *managedVault, item, itemName string, op svbroker.Op, why string) error {
	record := b.d.recorder(b.app, mv, itemName, op)
	if dec, found, err := b.d.broker.Check(mv.v, b.app, b.app.identity(), item, op); err != nil {
		return b.fail(err)
	} else if found && !dec.Allows() {
		record("denied", "remembered decision")
		return b.fail(denied(mv))
	}
	if !hasPassphrase(mv) {
		record("denied", "no passphrase to verify the person with")
		return svext.Errorf(svext.CodeUnsupported, "vault %q has no passphrase to verify you with", mv.cfg.Name)
	}
	p := b.d.consentPrompter(b.app)
	if p == nil {
		record("denied", "no way to ask")
		return svext.Errorf(svext.CodeDenied, "there is no way to ask you for the passphrase here")
	}
	mv.prompt.Lock()
	defer mv.prompt.Unlock()
	q := svrpc.PromptAsk{
		Kind:  svrpc.PromptPassphrase,
		Title: "Confirm it is you",
		Description: why + "\n\nThe site asks secretvault to check that it is you. Enter the passphrase of vault \"" +
			mv.cfg.Name + "\" to go on, or cancel.",
		Prompt: "Passphrase:",
	}
	for range 3 {
		pass, err := p.Passphrase(ctx, q)
		if err != nil {
			record(outcomeOf(err), err.Error())
			if errors.Is(err, svrpc.ErrCanceled) {
				return b.fail(denied(mv))
			}
			return b.fail(err)
		}
		err = mv.v.CheckKey(svcore.Passphrase(pass))
		clear(pass)
		if err == nil {
			record("allowed", "verified the passphrase")
			b.d.touch(mv)
			return b.stillOpen(mv)
		}
		if !errors.Is(err, svcore.ErrWrongKey) {
			return b.fail(err)
		}
		q.Error = "That passphrase does not open this vault."
	}
	record("denied", "wrong passphrase")
	return b.fail(svrpc.ErrWrongKey)
}

func (b *extSession) CreatePasskey(ctx context.Context, vault string, o svext.Origin, c svext.PasskeyCreate) (svext.PasskeyCreated, error) {
	var none svext.PasskeyCreated
	mv, err := b.unlocked(vault)
	if err != nil {
		return none, err
	}
	alg, ok := svext.ChooseAlgorithm(c.Algorithms)
	if !ok {
		return none, svext.Errorf(svext.CodeUnsupported, "the site takes no key secretvault can make (it makes ES256 and Ed25519)")
	}
	b.save.Lock()
	defer b.save.Unlock()
	// A credential the page excluded (one this account has already) is
	// refused, as an authenticator does, after the person chose to save.
	if len(c.Exclude) > 0 {
		es, _, err := passkeysOf(mv, c.RPID, c.Exclude)
		if err != nil {
			return none, b.fail(err)
		}
		n := len(es)
		wipeAll(es)
		if n > 0 {
			return none, svext.Errorf(svext.CodeExcluded, "vault %q already holds a passkey for this account on %s", mv.cfg.Name, c.RPID)
		}
	}
	name := freeName(mv, passkeyFolder, c.RPID, c.UserName)
	who := c.UserName
	if who == "" {
		who = c.UserDisplayName
	}
	why := fmt.Sprintf("%s wants to save a new passkey %q for %s (account %q), for %s%s", b.app.display(), name, c.RPID, who, o, through)
	flags := passkeyFlags
	if c.UV == svext.UVRequired {
		if err := b.verified(ctx, mv, "", name, svbroker.OpWrite, why); err != nil {
			return none, err
		}
		flags |= svext.FlagUV
	} else if err := b.decide(ctx, mv, "", name, svbroker.OpWrite, why); err != nil {
		return none, err
	}
	if e, err := mv.v.Get(name); err == nil {
		// Taken while the person was deciding.
		e.Item.Wipe()
		name = freeName(mv, passkeyFolder, c.RPID, c.UserName)
	}
	kp, err := svext.NewKeyPair(alg)
	if err != nil {
		return none, b.fail(err)
	}
	defer clear(kp.Private)
	rec := &svext.PasskeyRecord{RPID: c.RPID, UserName: c.UserName, DisplayName: c.UserDisplayName, CredentialID: svext.NewCredentialID(),
		UserHandle: bytes.Clone(c.UserHandle), Alg: alg, PrivateKey: kp.Private, Created: b.d.opts.Now()}
	label := c.Title
	if label == "" {
		label = c.RPName
	}
	if label == "" {
		label = c.RPID
	}
	it := svcore.Item{Kind: svext.PasskeyKind, Name: name, Label: label, Fields: rec.Fields()}
	defer it.Wipe()
	e, err := mv.v.Put(it)
	if err != nil {
		return none, b.fail(err)
	}
	e.Item.Wipe()
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	authData := svext.AuthenticatorData(c.RPID, flags, 0, svext.AttestedCredentialData(rec.CredentialID, kp.COSE))
	return svext.PasskeyCreated{Login: e.ID.String(), CredentialID: rec.CredentialID, AuthenticatorData: authData,
		AttestationObject: svext.AttestationObject(authData), PublicKey: kp.SPKI, Algorithm: alg}, nil
}

func (b *extSession) GetPasskey(ctx context.Context, vault string, o svext.Origin, g svext.PasskeyGet) (svext.PasskeyAssertion, error) {
	var none svext.PasskeyAssertion
	mv, err := b.unlocked(vault)
	if err != nil {
		return none, err
	}
	nf := svext.Errorf(svext.CodeNotFound, "no such passkey for %s", g.RPID)
	oid, err := svformat.ParseID(g.Login)
	if err != nil {
		return none, nf
	}
	e, err := mv.v.GetID(oid)
	if err != nil {
		if errors.Is(err, svcore.ErrNotFound) {
			return none, nf
		}
		return none, b.fail(err)
	}
	defer e.Item.Wipe()
	if e.Item.Kind != svext.PasskeyKind {
		return none, nf
	}
	// Its rpId, credential ID and user, without its key for now.
	r, err := svext.ReadPasskey(svext.ItemField(&e.Item), false)
	if err != nil || r.RPID != g.RPID || len(g.Allow) > 0 && !inList(g.Allow, r.CredentialID) {
		return none, nf
	}
	who := r.UserName
	if who == "" {
		who = r.DisplayName
	}
	why := fmt.Sprintf("%s wants to sign in to %s as %q with the passkey %q, for %s%s", b.app.display(), g.RPID, who, e.Item.Name, o, through)
	flags := passkeyFlags
	if g.UV == svext.UVRequired {
		if err := b.verified(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpSign, why); err != nil {
			return none, err
		}
		flags |= svext.FlagUV
	} else if g.Confirm {
		if err := b.confirm(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpSign, why, "It was chosen in a panel inside the page"); err != nil {
			return none, err
		}
	} else if err := b.decide(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpSign, why); err != nil {
		return none, err
	}
	r, err = svext.ReadPasskey(svext.ItemField(&e.Item), true)
	if err != nil {
		return none, svext.Errorf(svext.CodeFailed, "the passkey %q: %v", e.Item.Name, err)
	}
	defer r.Wipe()
	authData := svext.AuthenticatorData(g.RPID, flags, 0, nil)
	sig, err := svext.SignAssertion(r.PrivateKey, authData, g.ClientDataHash)
	if err != nil {
		return none, b.fail(err)
	}
	b.d.touch(mv)
	return svext.PasskeyAssertion{CredentialID: r.CredentialID, AuthenticatorData: authData, Signature: sig, UserHandle: r.UserHandle}, nil
}
