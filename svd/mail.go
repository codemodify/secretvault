package svd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// The mail face: a mail client hands over a message as received, and gets
// back what it is (svmail's report) and what the trust store knows of each
// signer. Reading the contacts is asked about as reading them; decrypting,
// only when the client asks for it, as the decrypt operation on the key's
// item, so a program allowed to read your mail is not thereby allowed to
// read your key.

func init() {
	registerMethod(svrpc.MMailInspect, trustErrors((*Daemon).mailInspect))
	registerMethod(svrpc.MMailCompose, trustErrors((*Daemon).mailCompose))
}

// mailKeys gives svmail the keys the daemon holds: contacts' keys to
// verify with, and your own OpenPGP keys to decrypt with, behind consent.
type mailKeys struct {
	d       *Daemon
	ctx     context.Context
	cl      *client
	vault   string
	decrypt bool
	st      *svtrust.Store
	pgp     []*svpgp.Key // contacts' OpenPGP keys
	roots   []*x509.Certificate
	inter   []*x509.Certificate
}

func newMailKeys(ctx context.Context, d *Daemon, cl *client, st *svtrust.Store, vault string, decrypt bool) (*mailKeys, error) {
	k := &mailKeys{d: d, ctx: ctx, cl: cl, vault: vault, decrypt: decrypt, st: st}
	cs, err := st.Contacts()
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		for _, key := range c.Keys {
			switch key.Type {
			case svtrust.OpenPGP:
				if pk, err := svpgp.ReadKey(bytes.NewReader(key.Material)); err == nil {
					k.pgp = append(k.pgp, pk)
				}
			case svtrust.X509:
				cert, err := x509.ParseCertificate(key.Material)
				if err != nil {
					continue
				}
				// An organisation's CA certificates are the roots its
				// members' certificates are checked against.
				if c.Organisation && cert.IsCA {
					k.roots = append(k.roots, cert)
				} else {
					k.inter = append(k.inter, cert)
				}
				for _, der := range key.Chain {
					if ic, err := x509.ParseCertificate(der); err == nil {
						k.inter = append(k.inter, ic)
					}
				}
			}
		}
	}
	return k, nil
}

func (k *mailKeys) match(ok func(*svpgp.Key) bool) ([]*svpgp.Key, error) {
	var out []*svpgp.Key
	for _, pk := range k.pgp {
		if ok(pk) {
			out = append(out, pk)
		}
	}
	return out, nil
}

func (k *mailKeys) PGPKeysByFingerprint(fp []byte) ([]*svpgp.Key, error) {
	return k.match(func(pk *svpgp.Key) bool {
		if bytes.Equal(pk.Fingerprint(), fp) {
			return true
		}
		for _, s := range pk.Subkeys() {
			if bytes.Equal(s.Fingerprint, fp) {
				return true
			}
		}
		return false
	})
}

func (k *mailKeys) PGPKeysByKeyID(id uint64) ([]*svpgp.Key, error) {
	return k.match(func(pk *svpgp.Key) bool {
		if pk.KeyID() == id {
			return true
		}
		for _, s := range pk.Subkeys() {
			if s.KeyID == id {
				return true
			}
		}
		return false
	})
}

func (k *mailKeys) PGPKeysByEmail(addr string) ([]*svpgp.Key, error) {
	addr = strings.ToLower(addr)
	return k.match(func(pk *svpgp.Key) bool {
		for _, u := range pk.UserIDs() {
			if strings.Contains(strings.ToLower(u), "<"+addr+">") || strings.EqualFold(u, addr) {
				return true
			}
		}
		return false
	})
}

// errNotAsked is an encrypted message the client did not ask to decrypt.
var errNotAsked = errors.New("not asked to decrypt: pass decrypt to have your key used")

func (k *mailKeys) DecryptPGP(req *svmail.PGPDecryptRequest) (*svpgp.Message, error) {
	if !k.decrypt {
		return nil, errNotAsked
	}
	rcpts, err := svpgp.EncryptedTo(bytes.NewReader(req.Message))
	if err != nil {
		return nil, err
	}
	_, it, err := k.d.pgpKey(k.ctx, k.cl, k.vault, svbroker.OpDecrypt, recipientOf(rcpts))
	if err != nil {
		return nil, err
	}
	defer it.e.Item.Wipe()
	sk, err := pgpSecretOf(&it.e.Item)
	if err != nil {
		return nil, err
	}
	defer sk.Close()
	keyring := append([]*svpgp.Key{sk}, req.Verify...)
	keyring = append(keyring, k.pgp...)
	return svpgp.Decrypt(bytes.NewReader(req.Message), keyring, nil)
}

func (k *mailKeys) SMIMERoots() ([]*x509.Certificate, error)         { return k.roots, nil }
func (k *mailKeys) SMIMEIntermediates() ([]*x509.Certificate, error) { return k.inter, nil }

// SMIMEContentKey unwraps the content key with your S/MIME key for r,
// asked about as decrypting with it.
func (k *mailKeys) SMIMEContentKey(r *svcms.Recipient) ([]byte, error) {
	if !k.decrypt {
		return nil, fmt.Errorf("%w: %v", svcms.ErrNotRecipient, errNotAsked)
	}
	_, it, err := k.d.smimeKey(k.ctx, k.cl, k.vault, svbroker.OpDecrypt, smimeRecipient(r))
	if err != nil {
		return nil, err
	}
	defer it.e.Item.Wipe()
	key, err := it.privateKey()
	if err != nil {
		return nil, err
	}
	dec, err := svcms.KeyDecrypter(it.cert, key)
	if err != nil {
		return nil, err
	}
	return dec.ContentKey(r)
}

func (d *Daemon) mailInspect(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.MailInspectParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	min, ok := svtrust.ParseLevel(p.MinLevel)
	if !ok {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not a verification level (tofu, published, logged, organisation, in-person)", p.MinLevel)
	}
	if len(p.Message) == 0 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "no message")
	}
	_, st, err := d.contacts(ctx, cl, p.Contacts, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	keys, err := newMailKeys(ctx, d, cl, st, p.Vault, p.Decrypt)
	if err != nil {
		return nil, err
	}
	rep, err := svmail.InspectWith(p.Message, keys, svmail.Options{Time: d.opts.Now()})
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", strings.TrimPrefix(err.Error(), "svmail: "))
	}
	out := svrpc.MailInspectResult{Verdicts: d.mailVerdicts(st, rep, svtrust.Policy{MinLevel: min})}
	if out.Report, err = json.Marshal(rep); err != nil {
		return nil, err
	}
	return out, nil
}

// mailVerdicts asks the trust store about the signer of every signature
// in the report, for the address it claims to be from. A signature that
// is not valid is never trusted, whoever made it.
func (d *Daemon) mailVerdicts(st *svtrust.Store, rep *svmail.Report, pol svtrust.Policy) []svrpc.MailVerdict {
	var out []svrpc.MailVerdict
	for _, l := range rep.Layers {
		for i, s := range l.Signatures {
			q := svtrust.Query{From: s.SenderAddress}
			switch {
			case s.Fingerprint != "":
				q.Fingerprint = s.Fingerprint
			case s.Certificate != nil && len(s.Certificate.DER) > 0:
				q.Key = s.Certificate.DER
			case s.Issuer != "":
				q.Fingerprint = s.Issuer
			default:
				continue
			}
			v, err := st.Check(q)
			if err != nil {
				continue
			}
			vv := d.verdictView(v, pol)
			if s.Status != svmail.StatusValid {
				vv.Trusted, vv.Status = false, "invalid"
				why := s.Error
				if why == "" {
					why = s.Status
				}
				vv.Reasons = append([]string{"The signature is not valid: " + why + "."}, vv.Reasons...)
			}
			out = append(out, svrpc.MailVerdict{Layer: l.ID, Index: i, Verdict: vv})
		}
	}
	return out
}

// mailCompose signs or encrypts an outgoing message with your keys and
// your contacts'. Signing is asked about as the sign operation on your
// key; encrypting reads the contacts. A key the trust store says may be
// an impostor's is never encrypted to.
func (d *Daemon) mailCompose(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.MailComposeParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !p.Sign && !p.Encrypt {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "neither signing nor encrypting: nothing to do")
	}
	if p.Format != "" && p.Format != "openpgp" && p.Format != "smime" {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not a format (openpgp, smime)", p.Format)
	}
	hdr, err := mail.ReadMessage(bytes.NewReader(p.Message))
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "not a mail message: %v", err)
	}
	from, err := mail.ParseAddress(hdr.Header.Get("From"))
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the message has no usable From: %v", err)
	}
	var to []string
	for _, h := range []string{"To", "Cc", "Bcc"} {
		if v := hdr.Header.Get(h); v != "" {
			list, err := mail.ParseAddressList(v)
			if err != nil {
				return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s: %v", h, err)
			}
			for _, a := range list {
				to = append(to, strings.ToLower(a.Address))
			}
		}
	}
	if p.Encrypt && len(to) == 0 {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "no recipients to encrypt to")
	}
	var st *svtrust.Store
	if p.Encrypt {
		if _, st, err = d.contacts(ctx, cl, p.Contacts, svbroker.OpRead); err != nil {
			return nil, err
		}
	}
	format := p.Format
	if format == "" {
		format = d.pickFormat(st, to, p.Encrypt)
	}
	opts := &svmail.ComposeOptions{ProtectHeaders: !p.NoProtectedHeaders, Time: d.opts.Now()}
	out := svrpc.MailComposeResult{Format: format}
	ref := p.Key
	if ref == "" {
		ref = from.Address
	}
	switch format {
	case "openpgp":
		var signer *svpgp.Key
		if p.Sign {
			_, it, err := d.pgpKey(ctx, cl, p.Vault, svbroker.OpSign, named(ref))
			if err != nil {
				return nil, err
			}
			defer it.e.Item.Wipe()
			if signer, err = pgpSecretOf(&it.e.Item); err != nil {
				return nil, err
			}
			defer signer.Close()
			out.SignedWith = it.e.Item.Name
		}
		if !p.Encrypt {
			out.Message, err = svmail.SignPGPMIME(p.Message, signer, opts)
			break
		}
		var keys []*svpgp.Key
		var missing []string
		for _, addr := range to {
			ks := d.recipientPGP(st, addr)
			if len(ks) == 0 {
				missing = append(missing, addr)
			}
			keys = append(keys, ks...)
		}
		if len(missing) > 0 {
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "no OpenPGP key to encrypt to for %s", strings.Join(missing, ", "))
		}
		if signer != nil {
			keys = append(keys, signer.Public())
		}
		out.EncryptedTo = to
		out.Message, err = svmail.EncryptPGPMIME(p.Message, keys, signer, opts)
	case "smime":
		var key crypto.Signer
		var chain []*x509.Certificate
		if p.Sign {
			_, it, err := d.smimeKey(ctx, cl, p.Vault, svbroker.OpSign, smimeFor(p.Key, from.Address))
			if err != nil {
				return nil, err
			}
			defer it.e.Item.Wipe()
			pk, err := it.privateKey()
			if err != nil {
				return nil, err
			}
			s, ok := pk.(crypto.Signer)
			if !ok {
				return nil, svrpc.Errorf(svrpc.CodeFailed, "%s's key cannot sign", it.e.Item.Name)
			}
			key, chain = s, append([]*x509.Certificate{it.cert}, it.chain...)
			out.SignedWith = it.e.Item.Name
		}
		if !p.Encrypt {
			out.Message, err = svmail.SignSMIME(p.Message, key, chain, opts)
			break
		}
		var certs []*x509.Certificate
		var missing []string
		for _, addr := range to {
			c := d.recipientCert(st, addr)
			if c == nil {
				missing = append(missing, addr)
				continue
			}
			certs = append(certs, c)
		}
		if len(missing) > 0 {
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "no S/MIME certificate to encrypt to for %s", strings.Join(missing, ", "))
		}
		if len(chain) > 0 {
			certs = append(certs, chain[0])
		}
		out.EncryptedTo = to
		out.Message, err = svmail.EncryptSMIME(p.Message, certs, key, chain, opts)
	}
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "%s", strings.TrimPrefix(err.Error(), "svmail: "))
	}
	return out, nil
}

// pickFormat chooses OpenPGP unless encrypting to someone who has only
// an S/MIME certificate.
func (d *Daemon) pickFormat(st *svtrust.Store, to []string, encrypt bool) string {
	if !encrypt {
		return "openpgp"
	}
	for _, addr := range to {
		if len(d.recipientPGP(st, addr)) == 0 && d.recipientCert(st, addr) != nil {
			return "smime"
		}
	}
	return "openpgp"
}

// usable reports whether a contact's key may be encrypted to for addr:
// not one the trust store says may be an impostor's.
func (d *Daemon) usable(st *svtrust.Store, fp, addr string) bool {
	v, err := st.Check(svtrust.Query{Fingerprint: fp, From: addr})
	return err == nil && d.verdictView(v, svtrust.DefaultPolicy).Status != "suspicious"
}

// recipientPGP are the OpenPGP keys the contacts hold for addr.
func (d *Daemon) recipientPGP(st *svtrust.Store, addr string) []*svpgp.Key {
	cs, err := st.ByEmail(addr)
	if err != nil {
		return nil
	}
	var out []*svpgp.Key
	for _, c := range cs {
		for _, k := range c.Keys {
			if k.Type != svtrust.OpenPGP || !d.usable(st, k.Fingerprint, addr) {
				continue
			}
			if pk, err := svpgp.ReadKey(bytes.NewReader(k.Material)); err == nil && pk.Valid(d.opts.Now()) == nil {
				out = append(out, pk)
			}
		}
	}
	return out
}

// recipientCert is the S/MIME certificate the contacts hold for addr.
func (d *Daemon) recipientCert(st *svtrust.Store, addr string) *x509.Certificate {
	cs, err := st.ByEmail(addr)
	if err != nil {
		return nil
	}
	now := d.opts.Now()
	for _, c := range cs {
		for _, k := range c.Keys {
			if k.Type != svtrust.X509 || !d.usable(st, k.Fingerprint, addr) {
				continue
			}
			cert, err := x509.ParseCertificate(k.Material)
			if err == nil && svcms.MatchEmail(cert, addr) && now.After(cert.NotBefore) && now.Before(cert.NotAfter) {
				return cert
			}
		}
	}
	return nil
}
