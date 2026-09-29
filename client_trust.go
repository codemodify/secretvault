package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// The trust store and your OpenPGP keys (see svrpc's trust methods). The
// contacts vault is the configured one, else the default vault, when
// vault is "". A mail client asks, for each signed message:
//
//	v, err := c.CheckSigner(ctx, svrpc.TrustCheckParams{Fingerprint: fp, From: "alice@example.org"})
//	v.Trusted, v.Status, v.Reasons  // "Signed by Alice Example's key, which you verified in person on 2026-09-01."
//
// and, for each key that comes with a message (an Autocrypt header, an
// S/MIME certificate):
//
//	c.KeySeen(ctx, svrpc.TrustSeenParams{Key: keyData, Address: from, Time: received})

// Contacts lists contacts (their keys summarised) whose name or an
// address contains query ("" for all).
func (c *Client) Contacts(ctx context.Context, vault, query string) (out []svrpc.Contact, err error) {
	err = c.conn.Call(ctx, svrpc.MContactList, svrpc.ContactListParams{Vault: vault, Query: query}, &out)
	return
}

// Contact returns one contact, with its keys, their verifications and
// sightings, named by ID, name, address or a key's fingerprint.
func (c *Client) Contact(ctx context.Context, vault, ref string) (out svrpc.Contact, err error) {
	err = c.conn.Call(ctx, svrpc.MContactGet, svrpc.ContactRef{Vault: vault, Ref: ref}, &out)
	return
}

// AddContact makes a new contact with the keys given.
func (c *Client) AddContact(ctx context.Context, p svrpc.ContactAddParams) (out svrpc.ContactChange, err error) {
	err = c.conn.Call(ctx, svrpc.MContactAdd, p, &out)
	return
}

// ImportContacts adds the keys of a key file to the contacts, or records a
// scanned secretvault-contact or openpgp4fpr URI.
func (c *Client) ImportContacts(ctx context.Context, p svrpc.ContactImportParams) (out svrpc.ContactImportResult, err error) {
	err = c.conn.Call(ctx, svrpc.MContactImport, p, &out)
	return
}

// RemoveContact removes a contact, or with fingerprint only that key.
func (c *Client) RemoveContact(ctx context.Context, vault, ref, fingerprint string) (out svrpc.Contact, err error) {
	err = c.conn.Call(ctx, svrpc.MContactRemove, svrpc.ContactRemoveParams{Vault: vault, Ref: ref, Fingerprint: fingerprint}, &out)
	return
}

// VerifyContact records a verification of one of a contact's keys.
func (c *Client) VerifyContact(ctx context.Context, p svrpc.ContactVerifyParams) (out svrpc.Contact, err error) {
	err = c.conn.Call(ctx, svrpc.MContactVerify, p, &out)
	return
}

// LookupContact looks keys up by WKD and keyservers.
func (c *Client) LookupContact(ctx context.Context, p svrpc.ContactLookupParams) (out svrpc.ContactLookupResult, err error) {
	err = c.conn.Call(ctx, svrpc.MContactLookup, p, &out)
	return
}

// ContactsVault returns the vault contacts are kept in; with vault set
// ("-" for the default vault), it keeps them there from now on (only
// secretvault's own CLI may).
func (c *Client) ContactsVault(ctx context.Context, vault string) (string, error) {
	var out svrpc.VaultRef
	err := c.conn.Call(ctx, svrpc.MContactVault, svrpc.VaultRef{Vault: vault}, &out)
	return out.Vault, err
}

// CheckSigner gives the trust store's verdict on a message's signer.
func (c *Client) CheckSigner(ctx context.Context, p svrpc.TrustCheckParams) (out svrpc.Verdict, err error) {
	err = c.conn.Call(ctx, svrpc.MTrustCheck, p, &out)
	return
}

// KeySeen records a key that came with a message: trust on first use.
func (c *Client) KeySeen(ctx context.Context, p svrpc.TrustSeenParams) (out svrpc.SeenResult, err error) {
	err = c.conn.Call(ctx, svrpc.MTrustSeen, p, &out)
	return
}

// GeneratePGP makes a new OpenPGP key in a vault.
func (c *Client) GeneratePGP(ctx context.Context, p svrpc.PGPGenerateParams) (out svrpc.PGPKey, err error) {
	err = c.conn.Call(ctx, svrpc.MPGPGenerate, p, &out)
	return
}

// PGPPublicKey returns one of your OpenPGP keys' public key.
func (c *Client) PGPPublicKey(ctx context.Context, vault, key string) (out svrpc.PGPKey, err error) {
	err = c.conn.Call(ctx, svrpc.MPGPPublic, svrpc.PGPKeyRef{Vault: vault, Key: key}, &out)
	return
}

// SignPGP signs with one of your OpenPGP keys, inside the daemon.
func (c *Client) SignPGP(ctx context.Context, p svrpc.PGPSignParams) (out svrpc.PGPSignResult, err error) {
	err = c.conn.Call(ctx, svrpc.MPGPSign, p, &out)
	return
}

// DecryptPGP decrypts a message with one of your OpenPGP keys, inside the
// daemon. The caller should zero the body when done with it.
func (c *Client) DecryptPGP(ctx context.Context, p svrpc.PGPDecryptParams) (out svrpc.PGPDecryptResult, err error) {
	err = c.conn.Call(ctx, svrpc.MPGPDecrypt, p, &out)
	return
}

// VerifyPGP verifies a signed message against your contacts.
func (c *Client) VerifyPGP(ctx context.Context, p svrpc.PGPVerifyParams) (out svrpc.PGPVerifyResult, err error) {
	err = c.conn.Call(ctx, svrpc.MPGPVerify, p, &out)
	return
}

// LinkGnuPG points a GnuPG home at the daemon's gpg-agent face, or with
// Remove takes it away (only secretvault's own programs may).
func (c *Client) LinkGnuPG(ctx context.Context, p svrpc.GnuPGLinkParams) (out svrpc.GnuPGLinkResult, err error) {
	err = c.conn.Call(ctx, svrpc.MGnuPGLink, p, &out)
	return
}

// InspectMail takes a raw message apart: its signatures, checked and
// judged against your contacts, and, with Decrypt, its encrypted parts,
// decrypted with your keys.
func (c *Client) InspectMail(ctx context.Context, p svrpc.MailInspectParams) (out svrpc.MailInspectResult, err error) {
	err = c.conn.Call(ctx, svrpc.MMailInspect, p, &out)
	return
}

// ImportSMIME imports your S/MIME key and certificate from a PKCS #12 file.
func (c *Client) ImportSMIME(ctx context.Context, p svrpc.SMIMEImportParams) (out svrpc.SMIMEKey, err error) {
	err = c.conn.Call(ctx, svrpc.MSMIMEImport, p, &out)
	return
}

// SMIMEKeys lists your S/MIME keys, without their private keys.
func (c *Client) SMIMEKeys(ctx context.Context, vault string) (out []svrpc.SMIMEKey, err error) {
	err = c.conn.Call(ctx, svrpc.MSMIMEList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// ComposeMail signs or encrypts an outgoing message with your keys and
// your contacts' keys.
func (c *Client) ComposeMail(ctx context.Context, p svrpc.MailComposeParams) (out svrpc.MailComposeResult, err error) {
	err = c.conn.Call(ctx, svrpc.MMailCompose, p, &out)
	return
}

// AddDirectory adds an organisation's LDAP directory to ask for keys.
func (c *Client) AddDirectory(ctx context.Context, p svrpc.DirectoryConfig) error {
	return c.conn.Call(ctx, svrpc.MDirectoryAdd, p, nil)
}

// Directories lists the directories asked for keys.
func (c *Client) Directories(ctx context.Context) (out []svrpc.DirectoryConfig, err error) {
	err = c.conn.Call(ctx, svrpc.MDirectoryList, nil, &out)
	return
}

// RemoveDirectory stops asking a directory.
func (c *Client) RemoveDirectory(ctx context.Context, name string) error {
	return c.conn.Call(ctx, svrpc.MDirectoryRemove, svrpc.DirectoryRef{Name: name}, nil)
}
