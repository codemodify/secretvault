package svmail

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

// Report is what Inspect found in a message: its structure, every
// cryptographic layer with its verdict, the content once those layers are
// removed, the keys it carries, and what to warn the person about. It is
// meant to go over RPC as JSON as it is.
type Report struct {
	// Headers are the message's own header fields, decoded for showing.
	Headers Headers `json:"headers"`

	// Protected holds the header fields a signature or encryption
	// protects (RFC 9788, or the older "Memory Hole" form), when the
	// message has them. Those are the ones to show.
	Protected *ProtectedHeaders `json:"protected_headers,omitempty"`

	// Signed and Encrypted say how much of the message the layers cover:
	// "none", "partial" (some parts only) or "full". They describe the
	// structure; whether each signature is valid is in Layers.
	Signed    string `json:"signed"`
	Encrypted string `json:"encrypted"`

	// Layers are the signature and encryption layers, in the order they
	// were met: outermost first, and depth first.
	Layers []*Layer `json:"layers,omitempty"`

	// Content is the message once the layers that cover all of it are
	// removed: the decrypted (or unwrapped) inner message.
	Content *Content `json:"content,omitempty"`

	// Parts are the message's leaf parts, with the text of text parts.
	Parts []*PartInfo `json:"parts"`

	// Keys are keys and certificates the message carries: its Autocrypt
	// and gossip headers, and the certificates of S/MIME signatures. They
	// are offered, not trusted.
	Keys []*DiscoveredKey `json:"keys,omitempty"`

	// Warnings are what the person should be told.
	Warnings []Warning `json:"warnings,omitempty"`
}

// Coverage values.
const (
	CoverNone    = "none"
	CoverPartial = "partial"
	CoverFull    = "full"
)

// Headers are header fields decoded for showing (RFC 2047 undone).
type Headers struct {
	From      string `json:"from,omitempty"`
	Sender    string `json:"sender,omitempty"`
	ReplyTo   string `json:"reply_to,omitempty"`
	To        string `json:"to,omitempty"`
	Cc        string `json:"cc,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Date      string `json:"date,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	// FromAddress is the bare address in From, "" if it does not parse.
	FromAddress string `json:"from_address,omitempty"`
}

// Layer kinds and formats.
const (
	KindSignature  = "signature"
	KindEncryption = "encryption"

	FormatPGPMIME            = "pgp-mime"            // RFC 3156
	FormatPGPInline          = "pgp-inline"          // armored blocks in text
	FormatSMIMEDetached      = "smime-detached"      // multipart/signed
	FormatSMIMEOpaque        = "smime-opaque"        // application/pkcs7-mime; smime-type=signed-data
	FormatSMIMEEnveloped     = "smime-enveloped"     // enveloped-data
	FormatSMIMEAuthEnveloped = "smime-authenveloped" // authEnveloped-data
)

// Layer is one signature or encryption layer.
type Layer struct {
	// ID numbers the layer from 1. Parent is the layer whose decrypted or
	// unwrapped content this one was found in, 0 for the message itself.
	ID     int `json:"id"`
	Parent int `json:"parent,omitempty"`

	Kind   string `json:"kind"`
	Format string `json:"format"`

	// Part is where the layer is: a path of part numbers ("1.2" is the
	// second part of the first part; "" the whole) within the message, or
	// within Parent's content.
	Part string `json:"part"`

	// Covers is "message" when the layer covers the whole message (its
	// body; header fields only as Protected says), "part" when it covers
	// only one part, which is worth a warning.
	Covers string `json:"covers"`

	Signatures []*Signature `json:"signatures,omitempty"`
	Encryption *Encryption  `json:"encryption,omitempty"`

	// Error is why the layer could not be read at all.
	Error string `json:"error,omitempty"`
}

// Signature statuses.
const (
	StatusValid                = "valid"
	StatusBad                  = "bad"            // the data or the signature was changed
	StatusUnknownKey           = "unknown-key"    // no key or certificate to check it with
	StatusExpiredKey           = "expired-key"    // the key or certificate had expired
	StatusRevokedKey           = "revoked-key"    // the key is revoked
	StatusInvalidKey           = "invalid-key"    // the key may not sign, or the chain is otherwise invalid
	StatusUntrustedRoot        = "untrusted-root" // the certificate does not chain to a known root
	StatusWrongUsage           = "wrong-usage"    // the certificate may not sign mail
	StatusWeakAlgorithm        = "weak-algorithm" // SHA-1 after 2023, MD5, a small key
	StatusExpiredSignature     = "expired-signature"
	StatusFutureSignature      = "future-signature"
	StatusNotIntendedRecipient = "not-intended-recipient"
	StatusMalformed            = "malformed"
	StatusUnsupported          = "unsupported"
	StatusError                = "error"
)

// Signature is the verdict on one signature.
type Signature struct {
	// Status is "valid" only when the signature verifies, its key or
	// certificate was valid for signing, and it passes the policy.
	// Otherwise it is the most important reason it is not; Problems lists
	// them all, and Error says it in words.
	Status   string   `json:"status"`
	Problems []string `json:"problems,omitempty"`
	Error    string   `json:"error,omitempty"`

	// Verified says the signature is mathematically correct for this data
	// and the key or certificate below, whatever the key's state: the
	// data has not changed since that key signed it.
	Verified bool `json:"verified"`

	SignedAt  *time.Time `json:"signed_at,omitempty"`
	Hash      string     `json:"hash,omitempty"`
	Algorithm string     `json:"algorithm,omitempty"`

	// OpenPGP: the fingerprint of the key that signed, the (sub)key that
	// made the signature, and the key's user IDs, when the key is known;
	// Issuer is what the signature itself names (a fingerprint or key
	// ID), known key or not.
	Fingerprint string   `json:"fingerprint,omitempty"`
	SigningKey  string   `json:"signing_key,omitempty"`
	UserIDs     []string `json:"user_ids,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`

	// S/MIME: the signer's certificate, and the chain built to a root.
	Certificate *Certificate   `json:"certificate,omitempty"`
	Chain       []*Certificate `json:"chain,omitempty"`

	// SenderAddress is the From address the signer was compared with;
	// SenderMatch whether the key's user IDs or the certificate name it.
	SenderAddress string `json:"sender_address,omitempty"`
	SenderMatch   bool   `json:"sender_match"`
}

// Certificate describes an X.509 certificate.
type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	Emails    []string  `json:"emails,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// SHA256 is the certificate's SHA-256 fingerprint, in hex.
	SHA256 string `json:"sha256"`
	// DER is the certificate itself.
	DER []byte `json:"der"`
}

// Encryption describes an encryption layer.
type Encryption struct {
	Recipients []*Recipient `json:"recipients"`
	// Decrypted says whether it was decrypted, and DecryptedWith with
	// what: an OpenPGP (sub)key fingerprint, or the recipient's
	// certificate issuer and serial.
	Decrypted     bool   `json:"decrypted"`
	DecryptedWith string `json:"decrypted_with,omitempty"`
	// Cipher is the content cipher, such as "AES-256-GCM" or "AES256
	// OCB"; Integrity is "aead", "mdc" or "none".
	Cipher    string `json:"cipher,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	// Error is why it was not decrypted.
	Error string `json:"error,omitempty"`
}

// Recipient is one recipient an encrypted layer names.
type Recipient struct {
	// OpenPGP: the key ID and, in version 6 packets, fingerprint, or a
	// passphrase.
	KeyID       string `json:"key_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Passphrase  bool   `json:"passphrase,omitempty"`
	// S/MIME: the certificate's issuer and serial number, or its subject
	// key identifier.
	Issuer       string `json:"issuer,omitempty"`
	Serial       string `json:"serial,omitempty"`
	SubjectKeyID string `json:"subject_key_id,omitempty"`
	// Algorithm is how the key is protected for this recipient.
	Algorithm string `json:"algorithm,omitempty"`
}

// Content is the message with the layers that cover all of it removed.
type Content struct {
	// Layer is the innermost layer covering the whole message, whose
	// content this is.
	Layer int `json:"layer"`
	// Raw is that content exactly: a MIME entity, header and body, or
	// for inline OpenPGP the plain text.
	Raw []byte `json:"raw"`
}

// PartInfo describes one leaf part.
type PartInfo struct {
	// Tree is 0 for a part of the message itself, or the ID of the layer
	// whose content it is part of; Part is its path there.
	Tree int    `json:"tree"`
	Part string `json:"part"`

	ContentType string `json:"content_type"`
	Charset     string `json:"charset,omitempty"`
	Disposition string `json:"disposition,omitempty"`
	Filename    string `json:"filename,omitempty"`
	// Size is the decoded size in bytes.
	Size int `json:"size"`

	// SignedBy and EncryptedBy are the layers covering the part, whatever
	// their verdicts: a part is signed by someone only as far as one of
	// those layers has a valid signature.
	SignedBy    []int `json:"signed_by,omitempty"`
	EncryptedBy []int `json:"encrypted_by,omitempty"`

	// Text is the text of a text part, decoded to UTF-8 with LF line
	// endings; empty when its charset is not supported (see Problems).
	Text string `json:"text,omitempty"`

	// LegacyDisplay marks a part that only repeats protected header
	// fields for clients that do not read them (RFC 9788, section 4.5):
	// do not show it as body text.
	LegacyDisplay bool `json:"legacy_display,omitempty"`

	Problems []string `json:"problems,omitempty"`

	container bool // its text is only inline OpenPGP blocks, reported as their own parts
}

// DiscoveredKey is a key or certificate found in a message. Nothing about
// it is trusted: it is offered to the trust store.
type DiscoveredKey struct {
	// Source is "autocrypt", "autocrypt-gossip", "smime-signature" or
	// "smime-certs-only".
	Source string `json:"source"`
	// Type is "openpgp" or "x509".
	Type string `json:"type"`
	// Address is the address it is for: the Autocrypt addr, or the
	// certificate's first address.
	Address       string `json:"address,omitempty"`
	PreferEncrypt string `json:"prefer_encrypt,omitempty"`
	// Protected says it was found inside a signed or encrypted part (a
	// gossip header), not in the message's own header.
	Protected bool `json:"protected,omitempty"`

	Fingerprint string       `json:"fingerprint,omitempty"`
	UserIDs     []string     `json:"user_ids,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	// Data is the key: a binary OpenPGP certificate or DER X.509.
	Data []byte `json:"data,omitempty"`
	// Error is why it is unusable, when it is.
	Error string `json:"error,omitempty"`
}

// Warning codes.
const (
	WarnPartialSignature  = "partial-signature"  // a signature covers only a part
	WarnUnsignedPart      = "unsigned-part"      // signed parts mixed with unsigned ones
	WarnPartialEncryption = "partial-encryption" // encryption covers only a part
	WarnUnencryptedPart   = "unencrypted-part"   // encrypted parts mixed with plain ones
	WarnNoIntegrity       = "no-integrity"       // encrypted without integrity protection
	WarnWeakCipher        = "weak-cipher"        // obsolete encryption
	WarnSenderMismatch    = "sender-mismatch"    // the signer is not the From address
	WarnHeaderMismatch    = "header-mismatch"    // an outer header differs from its protected copy
	WarnUnprotectedText   = "unprotected-text"   // text around an inline OpenPGP block
	WarnDecryption        = "decryption-failed"
	WarnVerification      = "verification-failed"
	WarnCharset           = "charset"
	WarnStructure         = "structure" // MIME that is malformed or nested too deep
	WarnKeys              = "keys"      // a key lookup failed, or a discovered key is bad
)

// Warning is one thing to tell the person.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Layer is the layer it is about, if any.
	Layer int `json:"layer,omitempty"`
}

func describeCert(c *x509.Certificate) *Certificate {
	sum := sha256.Sum256(c.Raw)
	return &Certificate{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		Serial:    strings.ToUpper(c.SerialNumber.Text(16)),
		Emails:    certEmails(c),
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		SHA256:    strings.ToUpper(hex.EncodeToString(sum[:])),
		DER:       c.Raw,
	}
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
