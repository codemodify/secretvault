// Package svext speaks the protocol of secretvault's own browser
// extension (browser/extension, docs/browser.md): a versioned JSON
// protocol of its own, carried in native-messaging frames.
//
// The browser starts the native-messaging host, io.github.codemodify.secretvault,
// which is the secretvault CLI (secretvault browser-host). The host checks
// that the browser started it for this extension and no other, checks
// each request's shape and size (ParseRequest), answers generate itself,
// and passes the rest to secretvaultd (browser.open with Protocol, then
// browser.message), where a Session answers them from the vaults, through
// the consent broker: the program asking is the browser, which the daemon
// identifies for itself, and the page is the origin the extension names.
//
// Nothing here caches a secret: fill hands one login's username and
// password over, once, for the extension to put into the page's fields.
package svext

import (
	"context"
	"errors"
	"slices"
)

// The names the extension and its host go by. They are in the extension's
// manifest.json too (a test keeps them the same); changing them before
// the extension is published changes both.
const (
	// HostName is the native-messaging host's name, and its manifest's
	// file name (without .json).
	HostName = "io.github.codemodify.secretvault"

	// FirefoxID is the extension's ID in Firefox
	// (browser_specific_settings.gecko.id).
	FirefoxID = "secretvault@codemodify.github.io"

	// ChromeID is its ID in Chromium-family browsers, which the "key" in
	// manifest.json fixes.
	ChromeID = "bfikbjjlppgnacljfdjhfoiccclkpkde"

	// Protocol names this protocol to the daemon (svrpc.BrowserOpenParams).
	Protocol = "secretvault-extension/1"
)

// ChromeOrigin is the extension's origin in Chromium-family browsers, as
// a host manifest's allowed_origins names it and the browser passes it
// to the host.
const ChromeOrigin = "chrome-extension://" + ChromeID + "/"

// Ours reports whether a browser started the host for this extension:
// origin is what it passed (the Firefox ID, or the Chromium origin).
func Ours(origin string) bool { return origin == FirefoxID || origin == ChromeOrigin }

// Vault is a vault as the extension shows it.
type Vault struct {
	Name    string `json:"name"`
	Locked  bool   `json:"locked"`
	Default bool   `json:"default"`
}

// SortVaults puts the default first, then the rest by name.
func SortVaults(vs []Vault) {
	slices.SortStableFunc(vs, func(a, b Vault) int {
		switch {
		case a.Default && !b.Default:
			return -1
		case b.Default && !a.Default:
			return 1
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
}

// Login is a login offered for a page: nothing secret.
type Login struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Username string `json:"username"`
	URL      string `json:"url"`   // the stored URL that fits
	Match    string `json:"match"` // "host" or "site"
	TOTP     bool   `json:"totp"`  // it has a one-time code
}

// Credentials are what fill hands over. Password is wiped once sent.
type Credentials struct {
	Username string
	Password []byte
	TOTP     string // the current one-time code, if the login has a key
}

// SaveLogin is a login to store: a new one, or a change to Login's.
type SaveLogin struct {
	Login    string // "" for a new login
	Username string
	Password []byte
	Title    string
}

// Check statuses: is the login a page just sent new, a change to one
// kept, or one kept already?
const (
	StatusNew     = "new"
	StatusChanged = "changed"
	StatusKnown   = "known"
)

// CheckResult is what check found: Login is the login it is about, for
// StatusChanged and StatusKnown.
type CheckResult struct {
	Status string
	Login  string
}

// PasskeyEntry is a passkey offered for a page: nothing secret.
type PasskeyEntry struct {
	ID           string `json:"id"`           // the item's
	CredentialID string `json:"credentialId"` // base64url: the site knows it, and names it in allowCredentials
	Title        string `json:"title"`
	UserName     string `json:"userName"`
	DisplayName  string `json:"userDisplayName"`
}

// PasskeyCreate is a passkey to make (navigator.credentials.create),
// checked: the rpId fits the origin, and ClientDataHash is the hash of
// clientDataJSON as checked.
type PasskeyCreate struct {
	RPID            string
	RPName          string
	UserHandle      []byte
	UserName        string
	UserDisplayName string
	Algorithms      []int
	Exclude         [][]byte
	UV              string
	Title           string
	ClientDataHash  [32]byte
}

// PasskeyCreated is the new credential.
type PasskeyCreated struct {
	Login             string // the item's ID
	CredentialID      []byte
	AuthenticatorData []byte
	AttestationObject []byte
	PublicKey         []byte // SubjectPublicKeyInfo
	Algorithm         int
}

// PasskeyGet is an assertion to make (navigator.credentials.get) with the
// passkey Login, checked as PasskeyCreate is.
type PasskeyGet struct {
	RPID           string
	Login          string
	Allow          [][]byte
	UV             string
	Confirm        bool // chosen in a panel inside the page: asked every time
	ClientDataHash [32]byte
}

// PasskeyAssertion is a passkey's signature.
type PasskeyAssertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

// Hello is what the daemon says of itself and of the browser.
type Hello struct {
	Browser string // the browser, as prompts and the audit log name it
	Version string // secretvault's
}

// Backend answers the extension: secretvaultd's vaults and consent
// broker (svd/browser_ext.go). Vault "" is the default vault. Errors that
// are *Error go to the extension as they are; others as CodeFailed.
type Backend interface {
	Hello(ctx context.Context) (Hello, error)
	Vaults(ctx context.Context) ([]Vault, error)
	// Unlock unlocks a vault, the daemon asking the person for its
	// passphrase in a prompt of its own.
	Unlock(ctx context.Context, vault string) error
	Lock(ctx context.Context, vault string) error
	// Logins lists the logins that fit origin, best first, if the person
	// allows the browser to list the vault.
	Logins(ctx context.Context, vault string, o Origin) ([]Login, error)
	// Fill reads a login that fits origin, if the person allows; with
	// confirm, the person is asked whatever was remembered (but a no).
	Fill(ctx context.Context, vault string, o Origin, login string, confirm bool) (Credentials, error)
	// TOTP is a login's current one-time code, if the person allows.
	TOTP(ctx context.Context, vault string, o Origin, login string, confirm bool) (string, error)
	// Check says whether a username and password a page at origin sent
	// are new, a change, or known: the comparison is the daemon's, and
	// nothing stored leaves it.
	Check(ctx context.Context, vault string, o Origin, username string, password []byte) (CheckResult, error)
	// Save stores a login for origin, if the person allows.
	Save(ctx context.Context, vault string, o Origin, s SaveLogin) (string, bool, error)

	// Passkeys lists the passkeys for rpID (only those in allow, when it
	// is not empty), if the person allows the browser to list the vault.
	Passkeys(ctx context.Context, vault string, o Origin, rpID string, allow [][]byte) ([]PasskeyEntry, error)
	// CreatePasskey makes and stores a passkey, if the person allows.
	CreatePasskey(ctx context.Context, vault string, o Origin, c PasskeyCreate) (PasskeyCreated, error)
	// GetPasskey signs with a passkey, if the person allows.
	GetPasskey(ctx context.Context, vault string, o Origin, g PasskeyGet) (PasskeyAssertion, error)
}

// Session answers one extension's requests from a Backend. It is safe
// for concurrent use.
type Session struct{ b Backend }

// NewSession starts answering from b.
func NewSession(b Backend) *Session { return &Session{b: b} }

// Handle answers one frame; the caller wipes the answer once sent.
func (s *Session) Handle(ctx context.Context, frame []byte) []byte {
	r, err := ParseRequest(frame)
	if err != nil {
		id := ""
		if r != nil {
			id = r.ID
		}
		return Refusal(id, err)
	}
	defer r.Wipe()
	out, err := s.serve(ctx, r)
	if err != nil {
		return Refusal(r.ID, err)
	}
	return out
}

func (s *Session) serve(ctx context.Context, r *Request) ([]byte, error) {
	out := newReply(r.ID)
	switch r.Op {
	case OpHello:
		h, err := s.b.Hello(ctx)
		if err != nil {
			return nil, err
		}
		out.set("protocol", Version)
		out.set("secretvault", h.Version)
		out.set("browser", h.Browser)

	case OpState:
		return s.vaults(ctx, out)

	case OpUnlock:
		if err := s.b.Unlock(ctx, r.Vault); err != nil {
			return nil, err
		}
		return s.vaults(ctx, out)

	case OpLock:
		if err := s.b.Lock(ctx, r.Vault); err != nil {
			return nil, err
		}
		return s.vaults(ctx, out)

	case OpLogins:
		logins, err := s.b.Logins(ctx, r.Vault, r.Origin)
		if err != nil {
			return nil, err
		}
		if len(logins) > MaxLogins {
			logins = logins[:MaxLogins]
		}
		if logins == nil {
			logins = []Login{}
		}
		out.set("origin", r.Origin.String())
		out.set("logins", logins)

	case OpFill:
		c, err := s.b.Fill(ctx, r.Vault, r.Origin, r.Login, r.Confirm)
		defer clear(c.Password)
		if err != nil {
			return nil, err
		}
		out.set("username", c.Username)
		out.secret("password", c.Password)
		if c.TOTP != "" {
			out.set("totp", c.TOTP)
		}

	case OpTOTP:
		code, err := s.b.TOTP(ctx, r.Vault, r.Origin, r.Login, r.Confirm)
		if err != nil {
			return nil, err
		}
		if code == "" {
			return nil, Errorf(CodeNotFound, "that login has no one-time code")
		}
		out.set("code", code)

	case OpCheck:
		c, err := s.b.Check(ctx, r.Vault, r.Origin, r.Username, r.Password)
		if err != nil {
			return nil, err
		}
		out.set("status", c.Status)
		if c.Login != "" {
			out.set("login", c.Login)
		}

	case OpSave:
		id, created, err := s.b.Save(ctx, r.Vault, r.Origin, SaveLogin{Login: r.Login, Username: r.Username, Password: r.Password, Title: r.Title})
		if err != nil {
			return nil, err
		}
		out.set("login", id)
		out.set("created", created)

	case OpPasskeys:
		if err := CheckRPID(Suffixes(), r.RPID, r.Origin); err != nil {
			return nil, Errorf(CodeBadRequest, "%v", err)
		}
		ps, err := s.b.Passkeys(ctx, r.Vault, r.Origin, r.RPID, r.Allow)
		if err != nil {
			return nil, err
		}
		if len(ps) > MaxLogins {
			ps = ps[:MaxLogins]
		}
		if ps == nil {
			ps = []PasskeyEntry{}
		}
		out.set("rpId", r.RPID)
		out.set("passkeys", ps)

	case OpPasskeyCreate:
		if err := CheckRPID(Suffixes(), r.RPID, r.Origin); err != nil {
			return nil, Errorf(CodeBadRequest, "%v", err)
		}
		h, err := CheckClientData(r.ClientData, ClientCreate, r.Origin)
		if err != nil {
			return nil, err
		}
		c, err := s.b.CreatePasskey(ctx, r.Vault, r.Origin, PasskeyCreate{RPID: r.RPID, RPName: r.RPName, UserHandle: r.UserHandle,
			UserName: r.UserName, UserDisplayName: r.UserDisplayName, Algorithms: r.Algorithms, Exclude: r.Exclude, UV: r.UV,
			Title: r.Title, ClientDataHash: h})
		if err != nil {
			return nil, err
		}
		out.set("login", c.Login)
		out.set("credentialId", B64.EncodeToString(c.CredentialID))
		out.set("authenticatorData", B64.EncodeToString(c.AuthenticatorData))
		out.set("attestationObject", B64.EncodeToString(c.AttestationObject))
		out.set("publicKey", B64.EncodeToString(c.PublicKey))
		out.set("algorithm", c.Algorithm)

	case OpPasskeyGet:
		if err := CheckRPID(Suffixes(), r.RPID, r.Origin); err != nil {
			return nil, Errorf(CodeBadRequest, "%v", err)
		}
		h, err := CheckClientData(r.ClientData, ClientGet, r.Origin)
		if err != nil {
			return nil, err
		}
		a, err := s.b.GetPasskey(ctx, r.Vault, r.Origin, PasskeyGet{RPID: r.RPID, Login: r.Login, Allow: r.Allow, UV: r.UV, Confirm: r.Confirm, ClientDataHash: h})
		if err != nil {
			return nil, err
		}
		out.set("credentialId", B64.EncodeToString(a.CredentialID))
		out.set("authenticatorData", B64.EncodeToString(a.AuthenticatorData))
		out.set("signature", B64.EncodeToString(a.Signature))
		out.set("userHandle", B64.EncodeToString(a.UserHandle))

	case OpGenerate:
		return nil, Errorf(CodeUnknownOp, "generate is the host's to answer")

	default:
		return nil, Errorf(CodeUnknownOp, "no operation %q", r.Op)
	}
	return out.done(), nil
}

func (s *Session) vaults(ctx context.Context, out *reply) ([]byte, error) {
	vs, err := s.b.Vaults(ctx)
	if err != nil {
		return nil, err
	}
	if vs == nil {
		vs = []Vault{}
	}
	SortVaults(vs)
	out.set("vaults", vs)
	return out.done(), nil
}

// IsCode reports whether err is an *Error with code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
