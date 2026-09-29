package svdeliver

import "time"

// The wire protocol, shared with the client (client.go). Everything is
// JSON; errors are {"error": "..."}.

// Status answers GET /v1/deliver/status, and the unseal and seal calls.
type Status struct {
	Sealed    bool `json:"sealed"`
	Threshold int  `json:"threshold"` // shares it takes to unseal
	Shares    int  `json:"shares"`    // shares there are

	// Progress is how many shares have been given towards unsealing,
	// until ProgressExpires, when they are forgotten.
	Progress        int       `json:"progress"`
	ProgressExpires time.Time `json:"progress_expires,omitzero"`

	// AutoUnseal says whether the server can unseal itself from a systemd
	// credential.
	AutoUnseal bool `json:"auto_unseal"`

	Rekey   *RekeyStatus `json:"rekey,omitempty"`
	Version string       `json:"version"`
}

// UnsealRequest is the body of POST /v1/deliver/unseal: one share, or a
// reset that forgets the shares given so far.
type UnsealRequest struct {
	Share string `json:"share,omitempty"`
	Reset bool   `json:"reset,omitempty"`
}

// LoginRequest is the body of POST /v1/deliver/login/oidc.
type LoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

// Session answers a login: a token to send as "Authorization: Bearer".
type Session struct {
	Token    string    `json:"token"`
	Expires  time.Time `json:"expires"`
	Role     string    `json:"role"`
	Identity string    `json:"identity"`
}

// Secret answers GET /v1/deliver/secret/{vault}/{item}: every field, or
// with ?field=NAME that one. Values that are not UTF-8 text come in
// base64 instead (FieldsBase64, ValueBase64).
type Secret struct {
	Vault   string    `json:"vault"`
	Item    string    `json:"item"`
	Kind    string    `json:"kind,omitempty"`
	Version string    `json:"version"` // changes whenever the item does
	Updated time.Time `json:"updated"`

	// The whole item.
	SecretField  string            `json:"secret_field,omitempty"` // the field that is the item's secret
	Fields       map[string]string `json:"fields,omitempty"`
	FieldsBase64 map[string]string `json:"fields_base64,omitempty"`

	// One field.
	Field       string  `json:"field,omitempty"`
	Value       *string `json:"value,omitempty"`
	ValueBase64 *string `json:"value_base64,omitempty"`
}

// List answers GET /v1/deliver/list/{vault}/{prefix}: the names the
// caller may list.
type List struct {
	Vault  string   `json:"vault"`
	Prefix string   `json:"prefix"`
	Items  []string `json:"items"`
}

// TokenRequest is the body of POST /v1/deliver/admin/tokens.
type TokenRequest struct {
	Name  string   `json:"name"`
	TTL   string   `json:"ttl,omitempty"`   // how long it lasts, like "720h"; empty for ever
	CIDRs []string `json:"cidrs,omitempty"` // where it may be used from; empty for anywhere
}

// TokenInfo describes a token, without the token.
type TokenInfo struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitzero"`
	CIDRs   []string  `json:"cidrs,omitempty"`
}

// NewToken answers the creation of a token: the only time it is shown.
type NewToken struct {
	TokenInfo
	Token string `json:"token"`
}

// VaultRequest is the body of POST /v1/deliver/admin/vaults: a vault
// folder by its path, or by its name on this server's sync hub.
type VaultRequest struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	Sync string `json:"sync,omitempty"`
}

// VaultInfo describes a delivery vault.
type VaultInfo struct {
	Name  string    `json:"name"`
	Path  string    `json:"path"`
	ID    string    `json:"id"`
	Added time.Time `json:"added"`

	// Suite is the vault's cipher suite, and Recipient the server's
	// identity for it: what the vault's owner shares it with
	// (secretvault share RECIPIENT).
	Suite     string `json:"suite,omitempty"`
	Recipient string `json:"recipient,omitempty"`

	// Open says whether the server holds it open; Problem, why not.
	Open    bool   `json:"open"`
	Problem string `json:"problem,omitempty"`
}

// ClientCA is the body of PUT /v1/deliver/admin/client-ca, and its answer.
type ClientCA struct {
	PEM      string   `json:"pem"`
	Subjects []string `json:"subjects,omitempty"`
}

// RekeyRequest is the body of POST /v1/deliver/admin/rekey: the new split,
// and what to do with the auto-unseal credential.
type RekeyRequest struct {
	Shares     int    `json:"shares"`
	Threshold  int    `json:"threshold"`
	Credential string `json:"credential,omitempty"` // keep (default), new or remove
}

// RekeyStatus is a rekey in progress.
type RekeyStatus struct {
	Nonce        string    `json:"nonce"`
	Progress     int       `json:"progress"`
	Threshold    int       `json:"threshold"` // current shares it takes
	NewShares    int       `json:"new_shares"`
	NewThreshold int       `json:"new_threshold"`
	Credential   string    `json:"credential"`
	Expires      time.Time `json:"expires,omitzero"`
}

// RekeyShare is the body of POST /v1/deliver/rekey: one current share
// towards a rekey.
type RekeyShare struct {
	Nonce string `json:"nonce"`
	Share string `json:"share"`
}

// RekeyResult answers a share towards a rekey. When Done, it carries the
// new shares, and the new credential key if one was asked for: the only
// time they are shown.
type RekeyResult struct {
	RekeyStatus
	Done       bool     `json:"done"`
	Shares     []string `json:"shares,omitempty"`
	Credential string   `json:"credential_key,omitempty"`
}

// AdminToken answers POST /v1/deliver/admin/admin-token: the new admin
// token, which replaces the old one.
type AdminToken struct {
	Token string `json:"token"`
}

// Identity answers GET /v1/deliver/admin/identity: the server's
// recipients, by cipher suite.
type Identity struct {
	Recipients map[string]string `json:"recipients"`
}

// AuditLog answers GET /v1/deliver/admin/audit.
type AuditLog struct {
	Entries []AuditEntry `json:"entries"`
	Intact  bool         `json:"intact"`
	Problem string       `json:"problem,omitempty"`
}

// ErrorBody is how every error is answered.
type ErrorBody struct {
	Error string `json:"error"`
}
