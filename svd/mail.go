package svd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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

// SMIMEContentKey: S/MIME keys of your own are not kept in the daemon yet.
func (k *mailKeys) SMIMEContentKey(r *svcms.Recipient) ([]byte, error) {
	return nil, fmt.Errorf("%w: secretvault holds no S/MIME key of yours yet", svcms.ErrNotRecipient)
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
