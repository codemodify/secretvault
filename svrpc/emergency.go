package svrpc

import "time"

// Emergency access: a person you trust (a contact with a secretvault
// identity) can open a vault of yours after a waiting period, during which
// any of your devices can refuse. The vault must sync with a server, which
// keeps the wait and the escrowed release key (docs/security.md,
// "Emergency access").
//
// The owner's methods (grant, deny, revoke, and the grants in list) take
// a vault ("" for the default) and are asked about as managing it. The
// trustee's (accept, request, open) name an access by what it is called
// on the trustee's device. All of them are for secretvault's own programs
// only.
const (
	MEmergencyGrant   = "emergency.grant"   // EmergencyGrantParams -> EmergencyGrantResult
	MEmergencyList    = "emergency.list"    // VaultRef -> EmergencyList
	MEmergencyDeny    = "emergency.deny"    // EmergencyRef -> EmergencyGrant
	MEmergencyRevoke  = "emergency.revoke"  // EmergencyRef -> EmergencyGrant (as it was)
	MEmergencyAccept  = "emergency.accept"  // EmergencyAcceptParams -> EmergencyAccess
	MEmergencyRequest = "emergency.request" // EmergencyAccessRef -> EmergencyAccess
	MEmergencyOpen    = "emergency.open"    // EmergencyOpenParams -> VaultInfo

	// EEmergency tells clients that a grant of one of the vaults changed
	// on its server (a request, a denial, a release): VaultEvent. What
	// changed is in emergency.list and daemon.status.
	EEmergency = "emergency.changed"
)

// States of a grant, as its server keeps it.
const (
	GrantInvited   = "invited"   // the trustee has not accepted it yet
	GrantAccepted  = "accepted"  // accepted; no request is pending
	GrantRequested = "requested" // the trustee asked; the wait is running
	GrantReleased  = "released"  // the trustee was given the release key
)

// EmergencyGrantParams give a person emergency access to a vault.
type EmergencyGrantParams struct {
	Vault string `json:"vault,omitempty"`

	// Contact is who: a contact (by name, address, ID or a key's
	// fingerprint) with a secretvault key, or a recipient's text
	// (sv-recipient-1-...).
	Contact string `json:"contact"`

	// Fingerprint picks one of the contact's secretvault keys, when they
	// have more than one for the vault's suite.
	Fingerprint string `json:"fingerprint,omitempty"`

	// Wait is the waiting period in seconds: from an hour to a year; 0
	// for the default, 7 days.
	Wait int64 `json:"wait,omitempty"`

	// Name is what the invite calls the vault ("" for its name here).
	Name string `json:"name,omitempty"`
}

// EmergencyGrant is a grant of emergency access to a vault of yours.
type EmergencyGrant struct {
	ID    string `json:"id"`
	Vault string `json:"vault"`

	// Trustee is the person, as the vault's record of the grant names
	// them, with their recipient and how well their key was verified when
	// it was granted. Empty when the vault is locked.
	Trustee   string `json:"trustee,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Level     string `json:"level,omitempty"`

	Wait    int64     `json:"wait"` // seconds
	Created time.Time `json:"created,omitzero"`

	// State is the server's (GrantInvited, ...); "" when it could not be
	// asked or does not hold the grant.
	State string `json:"state,omitempty"`

	// Device is the trustee's device, as it named itself when it accepted.
	Device   string     `json:"device,omitempty"`
	Accepted *time.Time `json:"accepted,omitempty"`

	Requested  *time.Time `json:"requested,omitempty"`
	ReleasesAt *time.Time `json:"releases_at,omitempty"`
	Denied     *time.Time `json:"denied,omitempty"`
	Released   *time.Time `json:"released,omitempty"`

	// Problems say what is amiss: no keyslot for it, not on the server,
	// the server unreachable.
	Problems []string `json:"problems,omitempty"`
}

// EmergencyGrantResult is a new grant, and the invite to send the
// trustee. The invite holds no secret: accepting it takes the trustee's
// identity.
type EmergencyGrantResult struct {
	Grant  EmergencyGrant `json:"grant"`
	Invite string         `json:"invite"`

	// Warning is something the person should know, such as a trustee's
	// key that was never verified.
	Warning string `json:"warning,omitempty"`
}

// EmergencyRef names a grant of a vault: its ID, or enough of its start
// to tell it from the others.
type EmergencyRef struct {
	Vault string `json:"vault,omitempty"`
	Grant string `json:"grant"`
}

// EmergencyAcceptParams accept an invite on the trustee's device.
type EmergencyAcceptParams struct {
	Invite string `json:"invite"`

	// Identity is the text of the identity file the grant was made for
	// (SV-IDENTITY-1-...). It is used to open the grant's challenge, and
	// is not kept.
	Identity []byte `json:"identity"`

	// Name is what this device calls the access, and the vault once it is
	// opened ("" for the invite's name).
	Name string `json:"name,omitempty"`

	// Label names this device to the owner ("" for the host name).
	Label string `json:"label,omitempty"`
}

// EmergencyAccess is emergency access this device holds to someone else's
// vault.
type EmergencyAccess struct {
	Name  string `json:"name"`
	Owner string `json:"owner,omitempty"` // what the owner calls the vault
	URL   string `json:"url"`
	Grant string `json:"grant"`
	Vault string `json:"vault,omitempty"` // the vault here, once opened

	// State and the times are the server's, as it last answered; Error
	// says why it could not be asked.
	State      string     `json:"state,omitempty"`
	Wait       int64      `json:"wait,omitempty"`
	Requested  *time.Time `json:"requested,omitempty"`
	ReleasesAt *time.Time `json:"releases_at,omitempty"`
	Denied     *time.Time `json:"denied,omitempty"`
	Released   *time.Time `json:"released,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// EmergencyAccessRef names emergency access this device holds.
type EmergencyAccessRef struct {
	Name string `json:"name"`
}

// EmergencyOpenParams open a vault with emergency access, once the wait
// is over: it is fetched from the server into Path ("" for the data
// directory), registered under the access's name, read-only, and
// unlocked with the identity. Once it is here, it opens again with
// 'unlock --identity'.
type EmergencyOpenParams struct {
	Name     string `json:"name"`
	Identity []byte `json:"identity"`
	Path     string `json:"path,omitempty"`
}

// EmergencyList is every grant of a vault, and every access this device
// holds.
type EmergencyList struct {
	Given []EmergencyGrant  `json:"given"`
	Held  []EmergencyAccess `json:"held"`
}

// EmergencyNotice is something about emergency access the person should
// see: a request of a vault of theirs that is waiting, or was released;
// or their own request of someone else's.
type EmergencyNotice struct {
	Vault      string     `json:"vault"` // the vault here (or, for access held, its name)
	Grant      string     `json:"grant"`
	Trustee    string     `json:"trustee,omitempty"`
	State      string     `json:"state"`
	ReleasesAt *time.Time `json:"releases_at,omitempty"`
	Released   *time.Time `json:"released,omitempty"`
	Held       bool       `json:"held,omitempty"` // access this device holds, not a grant of its vaults

	// Text says it in words, with what to do.
	Text string `json:"text"`
}
