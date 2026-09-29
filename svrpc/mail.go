package svrpc

import "encoding/json"

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
