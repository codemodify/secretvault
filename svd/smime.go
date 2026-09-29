package svd

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// S/MIME keys of your own: a certificate and its private key, imported
// from a PKCS #12 file into a vault item, used inside the daemon to
// decrypt mail sent to you and to sign mail you send, as your OpenPGP keys
// are. Signing is asked about as the sign operation on the item and
// decrypting as decrypt; neither lets a program read the key.

func init() {
	registerMethod(svrpc.MSMIMEImport, (*Daemon).smimeImport)
	registerMethod(svrpc.MSMIMEList, (*Daemon).smimeList)
}

// smimeItem is one S/MIME key item, with its certificate parsed.
type smimeItem struct {
	e     svcore.Entry
	cert  *x509.Certificate
	chain []*x509.Certificate
}

// privateKey parses the item's private key. The key object cannot be
// wiped (the standard library's); the item's bytes are, by the caller.
func (it smimeItem) privateKey() (crypto.PrivateKey, error) {
	f, ok := it.e.Item.Field(svrpc.SMIMEKeyField)
	if !ok {
		return nil, fmt.Errorf("%s holds no private key", it.e.Item.Name)
	}
	return x509.ParsePKCS8PrivateKey(f.Value)
}

func smimeItems(mv *managedVault) ([]smimeItem, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return nil, err
	}
	var out []smimeItem
	for _, e := range entries {
		if e.Item.Attrs[svrpc.SMIMEFingerprint] == "" {
			e.Item.Wipe()
			continue
		}
		f, ok := e.Item.Field(svrpc.SMIMECertField)
		cert, err := x509.ParseCertificate(f.Value)
		if !ok || err != nil {
			e.Item.Wipe()
			continue
		}
		it := smimeItem{e: e, cert: cert}
		if f, ok := e.Item.Field(svrpc.SMIMEChainField); ok {
			var ders [][]byte
			if json.Unmarshal(f.Value, &ders) == nil {
				for _, der := range ders {
					if c, err := x509.ParseCertificate(der); err == nil {
						it.chain = append(it.chain, c)
					}
				}
			}
		}
		out = append(out, it)
	}
	return out, nil
}

func certSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func smimeView(mv *managedVault, it smimeItem, warnings []string) svrpc.SMIMEKey {
	return svrpc.SMIMEKey{Vault: mv.cfg.Name, Item: it.e.Item.Name, Subject: it.cert.Subject.String(),
		Issuer: it.cert.Issuer.String(), Emails: svcms.CertificateEmails(it.cert), SHA256: certSHA256(it.cert),
		NotAfter: it.cert.NotAfter, Certificate: it.cert.Raw, Warnings: warnings}
}

// smimeKey finds one of a vault's S/MIME key items with pick and
// authorizes op on it, unlocking the vault first if need be. The caller
// wipes the item.
func (d *Daemon) smimeKey(ctx context.Context, cl *client, vault string, op svbroker.Op, pick func([]smimeItem) (int, error)) (*managedVault, smimeItem, error) {
	mv, err := d.vault(vault)
	if err != nil {
		return nil, smimeItem{}, err
	}
	why := fmt.Sprintf("%s wants to %s your S/MIME key in vault %q.", cl.display(), verbs[op], mv.cfg.Name)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		d.recorder(cl, mv, "", op)(outcomeOf(err), err.Error())
		return nil, smimeItem{}, err
	}
	items, err := smimeItems(mv)
	if err != nil {
		return nil, smimeItem{}, err
	}
	i, err := pick(items)
	for j, it := range items {
		if err != nil || j != i {
			it.e.Item.Wipe()
		}
	}
	if err != nil {
		return nil, smimeItem{}, err
	}
	it := items[i]
	name := it.e.Item.Name
	if it.e.Item.Attrs["confirm"] == "always" {
		err = d.authorizeEveryTime(ctx, cl, mv, it.e.ID.String(), name, op)
	} else {
		err = d.decide(ctx, cl, mv, it.e.ID.String(), name, op, describeRequest(cl, mv, name, op), prompted, own, d.recorder(cl, mv, name, op))
	}
	if err != nil {
		it.e.Item.Wipe()
		return nil, smimeItem{}, err
	}
	return mv, it, nil
}

// smimeFor picks the key for an address, or the one named by ref (an
// item, a SHA-256 or an address).
func smimeFor(ref, addr string) func([]smimeItem) (int, error) {
	return func(items []smimeItem) (int, error) {
		for i, it := range items {
			switch {
			case ref != "" && (it.e.Item.Name == ref || strings.EqualFold(certSHA256(it.cert), ref) || svcms.MatchEmail(it.cert, ref)):
				return i, nil
			case ref == "" && addr != "" && svcms.MatchEmail(it.cert, addr):
				return i, nil
			}
		}
		want := ref
		if want == "" {
			want = addr
		}
		return 0, svrpc.Errorf(svrpc.CodeNotFound, "no S/MIME key of yours for %s", want)
	}
}

// smimeRecipient picks the key a message is encrypted to.
func smimeRecipient(r *svcms.Recipient) func([]smimeItem) (int, error) {
	return func(items []smimeItem) (int, error) {
		for i, it := range items {
			if r.Matches(it.cert) {
				return i, nil
			}
		}
		return 0, fmt.Errorf("%w: no S/MIME key of yours is this message's recipient", svcms.ErrNotRecipient)
	}
}

func (d *Daemon) smimeImport(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.SMIMEImportParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	defer clear(p.Password)
	defer clear(p.PKCS12)
	b, err := svcms.DecodePKCS12(p.PKCS12, p.Password, nil)
	if errors.Is(err, svcms.ErrPassword) {
		return nil, svrpc.Errorf(svrpc.CodeWrongKey, "that password does not open the file")
	}
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svcms: "))
	}
	defer clear(b.PrivateKeyPKCS8)
	if b.PrivateKey == nil || b.Certificate == nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the file holds no private key with its certificate")
	}
	emails := svcms.CertificateEmails(b.Certificate)
	name := p.Item
	if name == "" {
		if len(emails) == 0 {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the certificate names no address: say what to call the item")
		}
		name = svrpc.SMIMEItemPrefix + strings.ToLower(emails[0])
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", name, svbroker.OpWrite)
	if err != nil {
		return nil, err
	}
	var chain [][]byte
	for _, c := range b.CACertificates {
		chain = append(chain, c.Raw)
	}
	chainJSON, _ := json.Marshal(chain)
	it := svcore.Item{Kind: svrpc.PGPItemKind, Name: name, Label: "S/MIME: " + b.Certificate.Subject.CommonName,
		Attrs: map[string]string{svrpc.SMIMEFingerprint: certSHA256(b.Certificate)},
		Fields: []svcore.Field{
			{Name: svrpc.SMIMECertField, Type: svcore.FieldBinary, Value: b.Certificate.Raw},
			{Name: svrpc.SMIMEChainField, Type: svcore.FieldJSON, Value: chainJSON},
			{Name: svrpc.SMIMEKeyField, Type: svcore.FieldKey, Value: append([]byte(nil), b.PrivateKeyPKCS8...)},
		}}
	if len(emails) > 0 {
		it.Attrs[svrpc.SMIMEAddress] = strings.ToLower(emails[0])
	}
	defer it.Wipe()
	if _, err := mv.v.PutNew(it); err != nil {
		if errors.Is(err, svcore.ErrItemExists) {
			return nil, svrpc.Errorf(svrpc.CodeExists, "there is already an item %q", name)
		}
		return nil, err
	}
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	return smimeView(mv, smimeItem{e: svcore.Entry{Item: svcore.Item{Name: name}}, cert: b.Certificate}, b.Warnings), nil
}

func (d *Daemon) smimeList(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.VaultRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpList)
	if err != nil {
		return nil, err
	}
	items, err := smimeItems(mv)
	if err != nil {
		return nil, err
	}
	out := []svrpc.SMIMEKey{}
	for _, it := range items {
		out = append(out, smimeView(mv, it, nil))
		it.e.Item.Wipe()
	}
	return out, nil
}
