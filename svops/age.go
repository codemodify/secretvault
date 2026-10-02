package svops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// age files with vault-held keys.
//
// An age identity lives in an item of kind "key": the field age_identity
// (type "key") holds the AGE-SECRET-KEY-1... or AGE-SECRET-KEY-PQ-1...
// text, and the attribute and field age_recipient its public half. The
// recipient is a plain age recipient, so anyone can encrypt to it without
// secretvault. Decrypting takes the identity from the daemon, which asks
// the person first as it does for any other item; age, rage and SOPS get
// there through age-plugin-secretvault, whose identity string names the
// item (AgePluginIdentity).

const (
	AgeIdentityField = "age_identity"
	AgeRecipientName = "age_recipient" // the field and the attribute
	AgePluginName    = "secretvault"
)

// AgeItemRef reads an ITEM argument: a name in vault, or sv://VAULT/ITEM.
func AgeItemRef(vault, arg string) (svrpc.Ref, error) {
	if strings.HasPrefix(arg, "sv://") {
		return svrpc.ParseRef(arg)
	}
	if err := svcore.CheckName(arg); err != nil {
		return svrpc.Ref{}, err
	}
	return svrpc.Ref{Vault: vault, Item: arg}, nil
}

// AgePluginIdentity is the AGE-PLUGIN-SECRETVAULT-1... string naming an
// item.
func AgePluginIdentity(vault, item string) (string, error) {
	return svage.EncodePluginIdentity(AgePluginName, []byte(vault+"/"+item))
}

// ItemOfPluginIdentity reads what AgePluginIdentity wrote: "VAULT/ITEM",
// with "-" (or nothing) for the default vault.
func ItemOfPluginIdentity(data []byte) (svrpc.Ref, error) {
	vault, item, ok := strings.Cut(string(data), "/")
	if !ok {
		return svrpc.Ref{}, errors.New("the identity does not name a vault item")
	}
	if err := svcore.CheckName(item); err != nil {
		return svrpc.Ref{}, err
	}
	if vault == "-" {
		vault = ""
	}
	return svrpc.Ref{Vault: vault, Item: item}, nil
}

// AgeKey is an age identity just made and stored.
type AgeKey struct {
	Entry     svrpc.Entry // the item's new revision
	Kind      string      // "X25519" or "post-quantum"
	Recipient string      // its public key, for anyone to encrypt to
	Vault     string      // the vault's name
	Plugin    string      // the identity line for age and SOPS
	File      []byte      // a key file holding that line, with comments
}

// NewAgeIdentity is a new age identity, not stored yet.
type NewAgeIdentity struct {
	Text      []byte // AGE-SECRET-KEY-1... (or -PQ-1...): wiped by Wipe
	Recipient string
	Kind      string // "X25519" or "post-quantum"
}

// Wipe clears the identity.
func (n *NewAgeIdentity) Wipe() { clear(n.Text) }

// GenerateAgeIdentity makes an age identity: post-quantum (ML-KEM-768 with
// X25519) with pq, else X25519.
func GenerateAgeIdentity(pq bool) (*NewAgeIdentity, error) {
	if pq {
		id, err := svage.GenerateHybridIdentity()
		if err != nil {
			return nil, err
		}
		text, err := id.AppendText(nil)
		if err != nil {
			return nil, err
		}
		return &NewAgeIdentity{Text: text, Recipient: id.Recipient().String(), Kind: "post-quantum"}, nil
	}
	id, err := svage.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	text, _ := id.AppendText(nil)
	return &NewAgeIdentity{Text: text, Recipient: id.Recipient().String(), Kind: "X25519"}, nil
}

// AgeKeygen makes an age identity (post-quantum with pq) and stores it as
// the item r names (StoreAgeIdentity).
func AgeKeygen(ctx context.Context, cl *secretvault.Client, r svrpc.Ref, pq bool) (*AgeKey, error) {
	n, err := GenerateAgeIdentity(pq)
	if err != nil {
		return nil, err
	}
	defer n.Wipe()
	return StoreAgeIdentity(ctx, cl, r, n)
}

// StoreAgeIdentity stores a new age identity as the item r names, which
// must not exist: an age identity is never replaced, or files encrypted
// to it would be lost.
func StoreAgeIdentity(ctx context.Context, cl *secretvault.Client, r svrpc.Ref, n *NewAgeIdentity) (*AgeKey, error) {
	idText, rcpt, kind := n.Text, n.Recipient, n.Kind
	if found, _, err := FindItem(ctx, cl, r.Vault, r.Item); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("%s already exists; pick another name (an age identity is never replaced)", r.Item)
	}
	it := svrpc.Item{
		Kind: "key", Name: r.Item, Label: "age identity",
		Attrs: map[string]string{AgeRecipientName: rcpt},
		Fields: []svrpc.Field{
			{Name: AgeIdentityField, Type: svcore.FieldKey, Value: idText},
			{Name: AgeRecipientName, Type: svcore.FieldText, Value: []byte(rcpt)},
		},
	}
	e, err := cl.Put(ctx, r.Vault, it)
	if err != nil {
		return nil, err
	}
	vault, err := VaultName(ctx, cl, r.Vault)
	if err != nil {
		return nil, err
	}
	plugin, err := AgePluginIdentity(vault, r.Item)
	if err != nil {
		return nil, err
	}
	file := fmt.Sprintf("# secretvault age identity (%s): item %q in vault %q\n# created: %s\n# recipient: %s\n%s\n",
		kind, r.Item, vault, e.Time.UTC().Format(time.RFC3339), rcpt, plugin)
	return &AgeKey{Entry: e, Kind: kind, Recipient: rcpt, Vault: vault, Plugin: plugin, File: []byte(file)}, nil
}

// AgeItemRecipient is the age recipient of the identity in an item: from
// its attribute when it has one, else worked out from the identity.
func AgeItemRecipient(ctx context.Context, cl *secretvault.Client, r svrpc.Ref) (string, error) {
	found, it, err := FindItem(ctx, cl, r.Vault, r.Item)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%s: %w", r.Item, svrpc.ErrNotFound)
	}
	if rc := it.Attrs[AgeRecipientName]; rc != "" && r.Field == "" {
		return rc, nil
	}
	id, err := LoadAgeIdentity(ctx, cl, r)
	if err != nil {
		return "", err
	}
	switch id := id.(type) {
	case *svage.X25519Identity:
		return id.Recipient().String(), nil
	case *svage.HybridIdentity:
		return id.Recipient().String(), nil
	}
	return "", fmt.Errorf("%s does not hold an age identity", r.Item)
}

// LoadAgeIdentity reads the age identity in an item (its age_identity
// field, or r.Field), wiping the item once it is parsed.
func LoadAgeIdentity(ctx context.Context, cl *secretvault.Client, r svrpc.Ref) (svage.Identity, error) {
	e, err := cl.Get(ctx, r.Vault, r.Item)
	if err != nil {
		return nil, err
	}
	defer Wipe(&e.Item)
	name := r.Field
	if name == "" {
		name = AgeIdentityField
	}
	f, ok := Field(&e.Item, name)
	if !ok {
		return nil, fmt.Errorf("%s has no field %q (make one with 'secretvault age keygen')", r.Item, name)
	}
	id, err := svage.ParseIdentityBytes(f.Value)
	if err != nil {
		return nil, fmt.Errorf("%s: field %q: %w", r.Item, name, err)
	}
	return id, nil
}

// VaultIdentity is an age identity kept in a vault item. Fetch gets it
// (through the daemon, which asks the person as it always does) the first
// time a stanza it could open turns up, and it is kept for the rest of
// the run.
type VaultIdentity struct {
	Ref   svrpc.Ref
	Fetch func(svrpc.Ref) (svage.Identity, error)
	id    svage.Identity
}

// Unwrap is svage.Identity's.
func (v *VaultIdentity) Unwrap(stanzas []*svage.Stanza) ([]byte, error) {
	if v.id == nil {
		native := false
		for _, s := range stanzas {
			native = native || s.Type == "X25519" || s.Type == "mlkem768x25519"
		}
		if !native {
			// Not worth asking anyone about.
			return nil, fmt.Errorf("%w: the file has no X25519 or post-quantum stanza", svage.ErrIncorrectIdentity)
		}
		id, err := v.Fetch(v.Ref)
		if err != nil {
			return nil, err
		}
		v.id = id
	}
	return v.id.Unwrap(stanzas)
}

// PassphraseIdentity is the identity used when none is given: a
// passphrase, asked for (Ask) only if the file turns out to be encrypted
// to one.
type PassphraseIdentity struct {
	Ask func() ([]byte, error)
}

// Unwrap is svage.Identity's.
func (a PassphraseIdentity) Unwrap(stanzas []*svage.Stanza) ([]byte, error) {
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, fmt.Errorf("%w: the file is not encrypted to a passphrase; give an identity with -i", svage.ErrIncorrectIdentity)
	}
	p, err := a.Ask()
	if err != nil {
		return nil, err
	}
	defer clear(p)
	id, err := svage.NewScryptIdentity(p)
	if err != nil {
		return nil, err
	}
	defer id.Wipe()
	return id.Unwrap(stanzas)
}

// AgeRecipient reads a recipient argument: any recipient age knows, or
// sv://VAULT/ITEM for the recipient of an identity kept in a vault, which
// itemRecipient (AgeItemRecipient, through the caller's connection) works
// out. Another plugin's recipient talks to the person through ui.
func AgeRecipient(arg string, itemRecipient func(svrpc.Ref) (string, error), ui *svage.PluginUI) (svage.Recipient, error) {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "sv://") {
		r, err := svrpc.ParseRef(arg)
		if err != nil {
			return nil, err
		}
		rc, err := itemRecipient(r)
		if err != nil {
			return nil, err
		}
		arg = rc
	}
	if strings.HasPrefix(arg, "AGE-") {
		return nil, errors.New("that is an identity (a secret key), not a recipient")
	}
	r, err := svage.ParseRecipient(arg)
	if err != nil {
		return nil, err
	}
	if _, ok := r.(*svage.PluginRecipient); ok {
		// Another plugin's: let it talk to the person.
		pr, err := svage.NewPluginRecipient(arg, ui)
		if err != nil {
			return nil, err
		}
		return pr, nil
	}
	return r, nil
}

// EachKeyLine calls f for each line of a key file that is not blank or a
// "#" comment, numbering lines from 1.
func EachKeyLine(b []byte, f func(n int, line []byte) error) error {
	for n, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if err := f(n+1, line); err != nil {
			return err
		}
	}
	return nil
}

// AgeIdentityOptions say how the identities an argument names are used.
type AgeIdentityOptions struct {
	// Vault is an identity kept in a vault: sv://... arguments, and
	// secretvault's own plugin identities, which go straight to the daemon
	// with no plugin process (a *VaultIdentity, usually).
	Vault func(svrpc.Ref) svage.Identity
	// UI lets other plugins (a YubiKey's, say) talk to the person.
	UI *svage.PluginUI
	// SSHPassphrase asks for an encrypted SSH key's passphrase.
	SSHPassphrase func(path string) ([]byte, error)
}

// AgeIdentities reads an identity argument: sv://VAULT/ITEM[#FIELD], or a
// file of identities (age's, plugins', ours) or an SSH private key.
func AgeIdentities(arg string, o AgeIdentityOptions) ([]svage.Identity, error) {
	if o.Vault == nil || o.SSHPassphrase == nil {
		return nil, errors.New("svops: AgeIdentities needs Vault and SSHPassphrase")
	}
	if strings.HasPrefix(arg, "sv://") {
		r, err := svrpc.ParseRef(arg)
		if err != nil {
			return nil, err
		}
		return []svage.Identity{o.Vault(r)}, nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if bytes.Contains(b, []byte("PRIVATE KEY-----")) {
		id, err := svage.ParseSSHIdentity(b, func() ([]byte, error) { return o.SSHPassphrase(arg) })
		if err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		return []svage.Identity{id}, nil
	}
	var ids []svage.Identity
	err = EachKeyLine(b, func(n int, line []byte) error {
		var id svage.Identity
		var err error
		switch {
		case bytes.HasPrefix(line, []byte("AGE-PLUGIN-")):
			var name string
			var data []byte
			if name, data, err = svage.ParsePluginIdentity(string(line)); err != nil {
				break
			}
			if name == AgePluginName {
				var r svrpc.Ref
				if r, err = ItemOfPluginIdentity(data); err == nil {
					id = o.Vault(r)
				}
			} else {
				id, err = svage.NewPluginIdentity(string(line), o.UI)
			}
		default:
			id, err = svage.ParseIdentityBytes(line)
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %w", arg, n, err)
		}
		ids = append(ids, id)
		return nil
	})
	if err == nil && len(ids) == 0 {
		err = fmt.Errorf("%s holds no identities", arg)
	}
	return ids, err
}

// AgeEncrypt encrypts src to recipients into dst, armored with armor;
// mixed lets post-quantum and classical recipients share the file.
func AgeEncrypt(dst io.Writer, src io.Reader, recipients []svage.Recipient, armor, mixed bool) error {
	var aw io.WriteCloser
	if armor {
		aw = svage.NewArmorWriter(dst)
		dst = aw
	}
	w, err := svage.Options{AllowMixedPostQuantum: mixed}.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if aw != nil {
		return aw.Close()
	}
	return nil
}

// AgeDecrypt opens an age file, armored or not, with the first of ids
// that can; when none can, the error says what the file is encrypted to
// (and, with one identity, why it could not).
func AgeDecrypt(src io.Reader, ids []svage.Identity) (io.Reader, error) {
	br := bufio.NewReader(src)
	var in io.Reader = br
	if peek, _ := br.Peek(2048); svage.IsArmored(peek) {
		in = svage.NewArmorReader(br)
	}
	r, err := svage.Decrypt(in, ids...)
	var nm *svage.NoIdentityMatchError
	if errors.As(err, &nm) {
		msg := "no identity given can open this file"
		if len(nm.Errors) == 1 {
			// With one identity, say what it said ("wrong passphrase", say).
			prefix := svage.ErrIncorrectIdentity.Error() + ": "
			if why, ok := strings.CutPrefix(nm.Errors[0].Error(), prefix); ok {
				msg = why
			}
		}
		return nil, fmt.Errorf("%s (it is encrypted to: %s)", msg, strings.Join(nm.StanzaTypes, ", "))
	}
	return r, err
}
