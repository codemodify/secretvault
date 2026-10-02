package svops

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Your own OpenPGP keys, kept in vault items of kind "key". The daemon
// makes them, signs and decrypts with them; taking one in from a file,
// and protecting one taken out, happen here.

// The errors below keep the CLI's words, which name its commands and
// flags; a manager tells them apart with errors.Is and says them in its
// own.
var (
	// ErrNotOneSecretKey is a file to import that is not one secret key.
	ErrNotOneSecretKey = errors.New("someone's public key goes to 'secretvault contact add'")
	// ErrKeyExists is a key to store under a name already taken.
	ErrKeyExists = errors.New("a key is never replaced")
)

// PGPKeyEntries are the entries of a listing that are OpenPGP keys.
func PGPKeyEntries(entries []svrpc.Entry) []svrpc.Entry {
	var out []svrpc.Entry
	for _, e := range entries {
		if e.Item.Kind == svrpc.PGPItemKind && e.Item.Attrs[svrpc.PGPFingerprint] != "" {
			out = append(out, e)
		}
	}
	return out
}

// PGPImportItem reads one secret key (data, from source) into the item to
// store it as: item, or pgp/ADDRESS by default. A key protected by a
// passphrase is unlocked with what passphrase gives, which the item keeps
// beside it. It returns the key's fingerprint too. The caller wipes the
// item.
func PGPImportItem(data []byte, source, item string, passphrase func() ([]byte, error)) (svrpc.Item, string, error) {
	keys, err := svpgp.ReadKeys(bytes.NewReader(data))
	if err != nil {
		return svrpc.Item{}, "", err
	}
	if len(keys) != 1 || !keys[0].HasSecret() {
		for _, k := range keys {
			k.Close()
		}
		return svrpc.Item{}, "", fmt.Errorf("%s does not hold exactly one secret key (%w)", source, ErrNotOneSecretKey)
	}
	k := keys[0]
	defer k.Close()
	var pass []byte
	if k.Locked() {
		if pass, err = passphrase(); err != nil {
			return svrpc.Item{}, "", err
		}
		if err := k.Unlock(pass); err != nil {
			clear(pass)
			return svrpc.Item{}, "", err
		}
	}
	secret, err := k.Armor(true)
	if err != nil {
		clear(pass)
		return svrpc.Item{}, "", err
	}
	public, err := k.Public().Armor(false)
	if err != nil {
		clear(pass)
		clear(secret)
		return svrpc.Item{}, "", err
	}
	fp := fmt.Sprintf("%X", k.Fingerprint())
	uid := k.PrimaryUserID()
	name := item
	if name == "" {
		_, addr := svtrust.SplitUserID(uid)
		if addr == "" {
			addr = fp
		}
		name = svrpc.PGPItemPrefix + addr
	}
	if err := svcore.CheckName(name); err != nil {
		clear(pass)
		clear(secret)
		return svrpc.Item{}, "", err
	}
	it := svrpc.Item{Kind: svrpc.PGPItemKind, Name: name, Label: "OpenPGP key " + uid,
		Attrs: map[string]string{svrpc.PGPFingerprint: fp, svrpc.PGPUserID: uid},
		Fields: []svrpc.Field{
			{Name: svrpc.PGPSecretField, Type: svcore.FieldKey, Value: secret},
			{Name: svrpc.PGPPublicField, Type: svcore.FieldText, Value: public},
		}}
	if pass != nil {
		it.Fields = append(it.Fields, svrpc.Field{Name: svrpc.PGPPassField, Type: svcore.FieldConcealed, Value: pass})
	}
	return it, fp, nil
}

// StorePGPKey stores an item PGPImportItem made, which must be new: a key
// is never replaced.
func StorePGPKey(ctx context.Context, cl *secretvault.Client, vault string, it svrpc.Item) error {
	if found, _, err := FindItem(ctx, cl, vault, it.Name); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%s already exists; pick another name with --item (%w)", it.Name, ErrKeyExists)
	}
	_, err := cl.Put(ctx, vault, it)
	return err
}

// ProtectPGPKey returns an item's secret key protected with a new
// passphrase (from newPass, asked once the key is known to open). The
// caller clears it.
func ProtectPGPKey(it *svrpc.Item, newPass func() ([]byte, error)) ([]byte, error) {
	f, _ := Field(it, svrpc.PGPSecretField)
	k, err := svpgp.ReadKey(bytes.NewReader(f.Value))
	if err != nil {
		return nil, err
	}
	defer k.Close()
	if k.Locked() {
		pass, ok := Field(it, svrpc.PGPPassField)
		if !ok {
			return nil, errors.New("the key is protected by a passphrase its item does not hold")
		}
		if err := k.Unlock(pass.Value); err != nil {
			return nil, err
		}
	}
	p, err := newPass()
	if err != nil {
		return nil, err
	}
	defer clear(p)
	if err := k.Lock(p, nil); err != nil {
		return nil, err
	}
	return k.Armor(true)
}
