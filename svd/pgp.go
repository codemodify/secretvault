package svd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Your own OpenPGP keys, kept in vault items (svrpc.PGP*): made, and
// used to sign and decrypt, inside the daemon, so the secret key never
// leaves it. Signing is asked about as OpSign on the key's item and
// decrypting as OpDecrypt, per program, like any access; neither lets a
// program read the key. An item with the attribute confirm=always is
// asked about on every use, as SSH keys are. Verifying other people's
// signatures reads your contacts.

func init() {
	for m, h := range map[string]handler{
		svrpc.MPGPGenerate: (*Daemon).pgpGenerate,
		svrpc.MPGPPublic:   (*Daemon).pgpPublic,
		svrpc.MPGPSign:     (*Daemon).pgpSign,
		svrpc.MPGPDecrypt:  (*Daemon).pgpDecrypt,
		svrpc.MPGPVerify:   (*Daemon).pgpVerify,
	} {
		registerMethod(m, trustErrors(h))
	}
}

// pgpItem is an OpenPGP key item with its public key.
type pgpItem struct {
	e   svcore.Entry // with its fields: wipe it when done
	pub *svpgp.Key
}

// pgpItems lists a vault's OpenPGP key items. The caller wipes them.
func pgpItems(mv *managedVault) ([]pgpItem, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return nil, err
	}
	var out []pgpItem
	for _, e := range entries {
		if e.Item.Kind == svrpc.PGPItemKind && e.Item.Attrs[svrpc.PGPFingerprint] != "" {
			if pub := pgpPublicOf(&e.Item); pub != nil {
				out = append(out, pgpItem{e, pub})
				continue
			}
		}
		e.Item.Wipe()
	}
	return out, nil
}

// pgpPublicOf reads an item's public key: its public key field, else its
// secret key's public half.
func pgpPublicOf(it *svcore.Item) *svpgp.Key {
	if f, ok := it.Field(svrpc.PGPPublicField); ok {
		if k, err := svpgp.ReadKey(bytes.NewReader(f.Value)); err == nil {
			return k.Public()
		}
	}
	if f, ok := it.Field(svrpc.PGPSecretField); ok {
		if k, err := svpgp.ReadKey(bytes.NewReader(f.Value)); err == nil {
			pub := k.Public()
			k.Close()
			return pub
		}
	}
	return nil
}

// pgpSecretOf reads an item's secret key, unlocked with the item's
// passphrase field if it is protected. The caller closes it.
func pgpSecretOf(it *svcore.Item) (*svpgp.Key, error) {
	f, ok := it.Field(svrpc.PGPSecretField)
	if !ok {
		return nil, fmt.Errorf("%s has no %s field", it.Name, svrpc.PGPSecretField)
	}
	k, err := svpgp.ReadKey(bytes.NewReader(f.Value))
	if err != nil {
		return nil, err
	}
	if k.Locked() {
		pass, ok := it.Field(svrpc.PGPPassField)
		if !ok {
			k.Close()
			return nil, fmt.Errorf("%s is protected by a passphrase the item does not hold", it.Name)
		}
		if err := k.Unlock(pass.Value); err != nil {
			k.Close()
			return nil, fmt.Errorf("%s: %w", it.Name, err)
		}
	}
	return k, nil
}

func hexFP(b []byte) string { return fmt.Sprintf("%X", b) }

// matches reports whether ref names the item: by its name, an address in
// its user IDs, or the fingerprint or key ID of the key or a subkey.
func (it pgpItem) matches(ref string) bool {
	if it.e.Item.Name == ref {
		return true
	}
	if addr := svtrust.ParseAddress(ref); addr != "" {
		return slices.ContainsFunc(it.pub.UserIDs(), func(uid string) bool {
			_, a := svtrust.SplitUserID(uid)
			return strings.EqualFold(a, addr)
		})
	}
	fp := svtrust.NormalizeFingerprint(ref)
	if fp == hexFP(it.pub.Fingerprint()) || fp == fmt.Sprintf("%016X", it.pub.KeyID()) {
		return true
	}
	return slices.ContainsFunc(it.pub.Subkeys(), func(s svpgp.SubkeyInfo) bool {
		return fp == hexFP(s.Fingerprint) || fp == fmt.Sprintf("%016X", s.KeyID)
	})
}

// named picks the item ref names, or the only one when ref is "".
func named(ref string) func(*managedVault, []pgpItem) ([]pgpItem, error) {
	return func(mv *managedVault, items []pgpItem) ([]pgpItem, error) {
		var hits []pgpItem
		for _, it := range items {
			if ref == "" || it.matches(ref) {
				hits = append(hits, it)
			}
		}
		switch {
		case len(hits) == 1:
			return hits, nil
		case len(items) == 0:
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "vault %q holds no OpenPGP key (make one with 'secretvault pgp new')", mv.cfg.Name)
		case len(hits) == 0:
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "no OpenPGP key in vault %q is %q", mv.cfg.Name, ref)
		case ref == "":
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "vault %q holds %d OpenPGP keys: say which", mv.cfg.Name, len(hits))
		}
		// An item's own name wins over its addresses.
		for _, it := range hits {
			if it.e.Item.Name == ref {
				return []pgpItem{it}, nil
			}
		}
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%d OpenPGP keys in vault %q are %q: name the item", len(hits), mv.cfg.Name, ref)
	}
}

// recipientOf picks the item a message is encrypted to.
func recipientOf(r *svpgp.Recipients) func(*managedVault, []pgpItem) ([]pgpItem, error) {
	return func(mv *managedVault, items []pgpItem) ([]pgpItem, error) {
		for _, it := range items {
			ids := []uint64{it.pub.KeyID()}
			fps := [][]byte{it.pub.Fingerprint()}
			for _, s := range it.pub.Subkeys() {
				ids = append(ids, s.KeyID)
				fps = append(fps, s.Fingerprint)
			}
			for _, id := range r.KeyIDs {
				if slices.Contains(ids, id) {
					return []pgpItem{it}, nil
				}
			}
			for _, fp := range r.Fingerprints {
				if slices.ContainsFunc(fps, func(b []byte) bool { return bytes.Equal(b, fp) }) {
					return []pgpItem{it}, nil
				}
			}
		}
		if r.Anonymous && len(items) == 1 {
			return items, nil
		}
		if r.Anonymous {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the message hides whom it is for: say which key to decrypt it with")
		}
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "the message is not encrypted to any OpenPGP key in vault %q", mv.cfg.Name)
	}
}

// pgpKey finds one of a vault's OpenPGP key items with pick and
// authorizes op on it, unlocking the vault first if need be. The caller
// wipes the item.
func (d *Daemon) pgpKey(ctx context.Context, cl *client, vault string, op svbroker.Op,
	pick func(*managedVault, []pgpItem) ([]pgpItem, error)) (*managedVault, pgpItem, error) {
	mv, err := d.vault(vault)
	if err != nil {
		return nil, pgpItem{}, err
	}
	why := fmt.Sprintf("%s wants to %s your OpenPGP key in vault %q.", cl.display(), verbs[op], mv.cfg.Name)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		d.recorder(cl, mv, "", op)(outcomeOf(err), err.Error())
		return nil, pgpItem{}, err
	}
	items, err := pgpItems(mv)
	if err != nil {
		return nil, pgpItem{}, err
	}
	picked, err := pick(mv, items)
	for _, it := range items {
		if err != nil || it.e.ID != picked[0].e.ID {
			it.e.Item.Wipe()
		}
	}
	if err != nil {
		return nil, pgpItem{}, err
	}
	it := picked[0]
	name := it.e.Item.Name
	if it.e.Item.Attrs["confirm"] == "always" && op != svbroker.OpList {
		err = d.authorizeEveryTime(ctx, cl, mv, it.e.ID.String(), name, op)
	} else {
		err = d.decide(ctx, cl, mv, it.e.ID.String(), name, op, describeRequest(cl, mv, name, op), prompted, own, d.recorder(cl, mv, name, op))
	}
	if err != nil {
		it.e.Item.Wipe()
		return nil, pgpItem{}, err
	}
	return mv, it, nil
}

func pgpKeyView(mv *managedVault, name string, pub *svpgp.Key) (svrpc.PGPKey, error) {
	armored, err := pub.Armor(false)
	if err != nil {
		return svrpc.PGPKey{}, err
	}
	return svrpc.PGPKey{Vault: mv.cfg.Name, Item: name, Fingerprint: hexFP(pub.Fingerprint()), Version: pub.Version(),
		UserIDs: pub.UserIDs(), Created: pub.CreatedAt(), Expires: pub.ExpiresAt(), PublicKey: string(armored)}, nil
}

func (d *Daemon) pgpGenerate(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.PGPGenerateParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	version := p.Version
	if version == 0 {
		version = 6
	}
	if version != 4 && version != 6 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "an OpenPGP key is version 6 or 4, not %d", version)
	}
	name := strings.TrimSpace(p.Name)
	var uids []string
	for _, e := range p.Emails {
		addr := svtrust.ParseAddress(e)
		if addr == "" {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not an email address", e)
		}
		uid := "<" + addr + ">"
		if name != "" {
			uid = name + " " + uid
		}
		uids = append(uids, uid)
	}
	if len(uids) == 0 && name != "" {
		uids = []string{name}
	}
	if len(uids) == 0 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "a key needs a name or an address")
	}
	item := p.Item
	if item == "" {
		_, addr := svtrust.SplitUserID(uids[0])
		if addr == "" {
			addr = name
		}
		item = svrpc.PGPItemPrefix + addr
	}
	if err := svcore.CheckName(item); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	if p.LifetimeDays < 0 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "a key's lifetime is not negative")
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", item, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	// Never replace a key: what was encrypted to it would be lost.
	if e, err := mv.v.Get(item); err == nil {
		e.Item.Wipe()
		return nil, svrpc.Errorf(svrpc.CodeExists, "%s already exists; pick another name (an OpenPGP key is never replaced)", item)
	}
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: version, UserIDs: uids, Lifetime: time.Duration(p.LifetimeDays) * 24 * time.Hour})
	if err != nil {
		return nil, err
	}
	defer k.Close()
	secret, err := k.Armor(true)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	pub := k.Public()
	public, err := pub.Armor(false)
	if err != nil {
		return nil, err
	}
	fp := hexFP(k.Fingerprint())
	it := svcore.Item{Kind: svrpc.PGPItemKind, Name: item, Label: "OpenPGP key " + k.PrimaryUserID(),
		Attrs: map[string]string{svrpc.PGPFingerprint: fp, svrpc.PGPUserID: k.PrimaryUserID()},
		Fields: []svcore.Field{
			{Name: svrpc.PGPSecretField, Type: svcore.FieldKey, Value: secret},
			{Name: svrpc.PGPPublicField, Type: svcore.FieldText, Value: public},
		}}
	e, err := mv.v.Put(it)
	if err != nil {
		return nil, err
	}
	e.Item.Wipe()
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: item})
	return pgpKeyView(mv, item, pub)
}

func (d *Daemon) pgpPublic(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.PGPKeyRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, it, err := d.pgpKey(ctx, cl, p.Vault, svbroker.OpList, named(p.Key))
	if err != nil {
		return nil, err
	}
	defer it.e.Item.Wipe()
	return pgpKeyView(mv, it.e.Item.Name, it.pub)
}

func (d *Daemon) pgpSign(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.PGPSignParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	var mode svpgp.SignMode
	switch p.Mode {
	case "", svrpc.SignDetached:
		mode = svpgp.SignDetached
	case svrpc.SignInline:
		mode = svpgp.SignInline
	case svrpc.SignCleartext:
		mode = svpgp.SignCleartext
	default:
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "sign %q? detached, inline or cleartext", p.Mode)
	}
	_, it, err := d.pgpKey(ctx, cl, p.Vault, svbroker.OpSign, named(p.Key))
	if err != nil {
		return nil, err
	}
	defer it.e.Item.Wipe()
	k, err := pgpSecretOf(&it.e.Item)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	var out bytes.Buffer
	if err := svpgp.Sign(&out, bytes.NewReader(p.Data), k, svpgp.SignOptions{Mode: mode, Text: p.Text, Armor: p.Armor}); err != nil {
		return nil, err
	}
	return svrpc.PGPSignResult{Signature: out.Bytes(), Item: it.e.Item.Name, Fingerprint: hexFP(k.Fingerprint())}, nil
}

func (d *Daemon) pgpDecrypt(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.PGPDecryptParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	rcpts, err := svpgp.EncryptedTo(bytes.NewReader(p.Data))
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
	}
	var st *svtrust.Store
	var keyring []*svpgp.Key
	if p.Verify {
		if _, st, err = d.contacts(ctx, cl, "", svbroker.OpRead); err != nil {
			return nil, err
		}
		if keyring, err = contactKeys(st); err != nil {
			return nil, err
		}
	}
	pick := recipientOf(rcpts)
	if p.Key != "" {
		pick = named(p.Key)
	}
	_, it, err := d.pgpKey(ctx, cl, p.Vault, svbroker.OpDecrypt, pick)
	if err != nil {
		return nil, err
	}
	defer it.e.Item.Wipe()
	k, err := pgpSecretOf(&it.e.Item)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	msg, err := svpgp.Decrypt(bytes.NewReader(p.Data), append([]*svpgp.Key{k}, keyring...), nil)
	if errors.Is(err, svpgp.ErrDecryption) {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the message could not be decrypted with %s", it.e.Item.Name)
	}
	if err != nil {
		return nil, err
	}
	out := svrpc.PGPDecryptResult{Body: msg.Body, FileName: msg.FileName, Item: it.e.Item.Name,
		Fingerprint: hexFP(msg.DecryptionKey), Warnings: msg.Warnings}
	out.Signatures = d.signatures(st, msg.Signatures, p.From)
	return out, nil
}

func (d *Daemon) pgpVerify(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.PGPVerifyParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	_, st, err := d.contacts(ctx, cl, p.Vault, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	keyring, err := contactKeys(st)
	if err != nil {
		return nil, err
	}
	var out svrpc.PGPVerifyResult
	var results []svpgp.SignatureResult
	if len(p.Signature) == 0 {
		msg, err := svpgp.VerifyInline(bytes.NewReader(p.Data), keyring, time.Time{})
		if err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
		}
		out.Body, results = msg.Body, msg.Signatures
	} else {
		results, err = svpgp.Verify(bytes.NewReader(p.Data), bytes.NewReader(p.Signature), keyring, time.Time{})
		if err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svpgp: "))
		}
	}
	out.Signatures = d.signatures(st, results, p.From)
	return out, nil
}

// contactKeys are the OpenPGP keys of every contact, to verify with.
func contactKeys(st *svtrust.Store) ([]*svpgp.Key, error) {
	cs, err := st.Contacts()
	if err != nil {
		return nil, err
	}
	var out []*svpgp.Key
	for _, c := range cs {
		for _, k := range c.Keys {
			if k.Type != svtrust.OpenPGP {
				continue
			}
			if pk, err := svpgp.ReadKey(bytes.NewReader(k.Material)); err == nil {
				out = append(out, pk)
			}
		}
	}
	return out, nil
}

// signatures describes signature results, each with the trust store's
// verdict on its signer when st is set. A signature that is not valid is
// never trusted, whoever made it.
func (d *Daemon) signatures(st *svtrust.Store, results []svpgp.SignatureResult, from string) []svrpc.PGPSignature {
	var out []svrpc.PGPSignature
	for _, r := range results {
		s := svrpc.PGPSignature{Valid: r.Valid, Created: r.CreatedAt}
		if r.Err != nil {
			s.Error = strings.TrimPrefix(r.Err.Error(), "svpgp: ")
		}
		switch {
		case r.IssuerFingerprint != nil:
			s.Issuer = hexFP(r.IssuerFingerprint)
		case r.IssuerKeyID != 0:
			s.Issuer = fmt.Sprintf("%016X", r.IssuerKeyID)
		}
		who := s.Issuer
		if r.Key != nil {
			s.Signer, s.SigningKey = hexFP(r.Key.Fingerprint()), hexFP(r.SigningKey)
			who = s.Signer
		}
		if st != nil && who != "" {
			if v, err := st.Check(svtrust.Query{Fingerprint: who, From: from}); err == nil {
				vv := d.verdictView(v, svtrust.DefaultPolicy)
				if !r.Valid {
					vv.Trusted, vv.Status = false, "invalid"
					vv.Reasons = append([]string{"The signature is not valid: " + s.Error + "."}, vv.Reasons...)
				}
				s.Verdict = &vv
			}
		}
		out = append(out, s)
	}
	return out
}
