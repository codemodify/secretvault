package svrpc

import (
	"encoding/json"
	"time"
)

// Mail: whole messages, as a mail client has them.
const (
	MMailInspect = "mail.inspect" // MailInspectParams -> MailInspectResult
)

// MailInspectParams ask about a raw message (RFC 5322, as received).
type MailInspectParams struct {
	Message []byte `json:"message"`

	// Decrypt lets the daemon decrypt the message with your keys, which
	// is asked about as the decrypt operation on the key's item. Without
	// it, encrypted parts are reported and left alone.
	Decrypt bool `json:"decrypt,omitempty"`

	// Vault holds your OpenPGP keys ("" for the default); Contacts is the
	// contacts vault ("" for the configured one).
	Vault    string `json:"vault,omitempty"`
	Contacts string `json:"contacts,omitempty"`

	// MinLevel is the verification level a signer's key must have to be
	// trusted: tofu, published, logged, organisation or in-person ("" for
	// the default policy).
	MinLevel string `json:"min_level,omitempty"`
}

// MailInspectResult is what a message is. Report is svmail's report
// (svmail.Report, as JSON): the headers and protected headers, every
// signature and encryption layer and what it covers, the parts with their
// text, the decrypted content, keys the message carries, and warnings.
// Verdicts say, for each signature in it, what the trust store knows of
// its signer.
type MailInspectResult struct {
	Report   json.RawMessage `json:"report"`
	Verdicts []MailVerdict   `json:"verdicts,omitempty"`
}

// MailVerdict is the trust store's verdict on one signature of a report:
// the Index-th signature of the layer numbered Layer.
type MailVerdict struct {
	Layer   int     `json:"layer"`
	Index   int     `json:"index"`
	Verdict Verdict `json:"verdict"`
}

// S/MIME keys of your own, and outgoing mail.
const (
	MSMIMEImport = "smime.import" // SMIMEImportParams -> SMIMEKey
	MSMIMEList   = "smime.list"   // VaultRef -> []SMIMEKey
	MMailCompose = "mail.compose" // MailComposeParams -> MailComposeResult
)

// The item an S/MIME key of your own is kept in: kind "key", with the
// certificate (DER), its chain (DER, as JSON) and the private key (PKCS #8
// DER) as fields, and the certificate's SHA-256 and first address as
// attributes.
const (
	SMIMEItemPrefix  = "smime/"
	SMIMECertField   = "smime_certificate"
	SMIMEChainField  = "smime_chain"
	SMIMEKeyField    = "smime_private_key"
	SMIMEFingerprint = "smime_sha256" // attribute
	SMIMEAddress     = "smime_email"  // attribute
)

// SMIMEImportParams import a PKCS #12 (.p12, .pfx) file holding your key
// and certificate, as item Item ("" for smime/ADDRESS).
type SMIMEImportParams struct {
	Vault    string `json:"vault,omitempty"`
	Item     string `json:"item,omitempty"`
	PKCS12   []byte `json:"pkcs12"`
	Password []byte `json:"password,omitempty"`
}

// SMIMEKey is an S/MIME key of yours, without its private key.
type SMIMEKey struct {
	Vault       string    `json:"vault"`
	Item        string    `json:"item"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Emails      []string  `json:"emails,omitempty"`
	SHA256      string    `json:"sha256"`
	NotAfter    time.Time `json:"not_after"`
	Certificate []byte    `json:"certificate"` // DER
	Warnings    []string  `json:"warnings,omitempty"`
}

// MailComposeParams sign or encrypt (or both) an outgoing message, given
// as a plain RFC 5322 message. Signing uses your key for the From address
// (or Key), asked about as the sign operation; encrypting is to the
// contacts' keys for every To, Cc and Bcc address, and to your own.
type MailComposeParams struct {
	Message []byte `json:"message"`
	Sign    bool   `json:"sign,omitempty"`
	Encrypt bool   `json:"encrypt,omitempty"`

	// Format is "openpgp" or "smime"; "" picks OpenPGP when you have an
	// OpenPGP key for From (and, to encrypt, every recipient has one),
	// else S/MIME.
	Format string `json:"format,omitempty"`

	// Key names your key to sign with (an item, fingerprint or address);
	// "" for the one matching From.
	Key string `json:"key,omitempty"`

	// NoProtectedHeaders leaves the header fields out of the signed or
	// encrypted part (RFC 9788); by default they are protected.
	NoProtectedHeaders bool `json:"no_protected_headers,omitempty"`

	Vault    string `json:"vault,omitempty"`
	Contacts string `json:"contacts,omitempty"`
}

// MailComposeResult is the message to send.
type MailComposeResult struct {
	Message     []byte   `json:"message"`
	Format      string   `json:"format"`
	SignedWith  string   `json:"signed_with,omitempty"`  // your key's item
	EncryptedTo []string `json:"encrypted_to,omitempty"` // the addresses, each with its key
}
