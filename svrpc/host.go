package svrpc

import (
	"os"
	"path/filepath"
	"time"
)

// Host mode: secretvaultd --host, the machine's system service, serving
// secrets to its services (docs/architecture.md, "Daemon modes"). It has
// three sockets in its runtime directory:
//
//	credentials.sock  systemd's LoadCredential= (0600: systemd runs as root)
//	secretvaultd.sock local services that are not units, by uid and program (0666)
//	admin.sock        root, for 'secretvault host ...' (0600)

// Host methods. host.resolve is the only one besides client.hello that
// local services may call; the rest are for root on the admin socket.
const (
	MHostStatus  = "host.status"  // nil -> HostStatus
	MHostList    = "host.list"    // nil -> HostPolicy
	MHostAllow   = "host.allow"   // HostRule -> HostAllowResult
	MHostDeny    = "host.deny"    // HostRule -> nil
	MHostResolve = "host.resolve" // HostResolveParams -> HostResolveResult
	MHostAudit   = "host.audit"   // AuditParams (Limit only) -> []HostEvent
)

// Where host mode keeps things. Each has an environment variable, so a
// test (or an unusual system) can move it.
const (
	// EnvHost, set to 1, makes the CLI talk to the host daemon, as --host
	// does.
	EnvHost = "SECRETVAULT_HOST"
	// EnvHostData is the host daemon's data directory (/var/lib/secretvault).
	EnvHostData = "SECRETVAULT_HOST_DATA"
	// EnvHostRuntime is where its sockets are (/run/secretvault).
	EnvHostRuntime = "SECRETVAULT_HOST_RUNTIME"

	// HostIdentityCredential is the name of the systemd credential that
	// carries the host identity (LoadCredentialEncrypted=).
	HostIdentityCredential = "secretvault-host.identity"

	// HostCredstore is where systemd-creds puts the sealed host identity.
	HostCredstore = "/etc/credstore.encrypted/" + HostIdentityCredential
)

// HostDataDir is the host daemon's data directory: $SECRETVAULT_HOST_DATA,
// else /var/lib/secretvault.
func HostDataDir() string {
	if d := os.Getenv(EnvHostData); d != "" {
		return d
	}
	return "/var/lib/secretvault"
}

// HostRuntimeDir is where the host daemon's sockets are:
// $SECRETVAULT_HOST_RUNTIME, else /run/secretvault.
func HostRuntimeDir() string {
	if d := os.Getenv(EnvHostRuntime); d != "" {
		return d
	}
	return "/run/secretvault"
}

// The host daemon's sockets, in its runtime directory.
const (
	HostCredentialSocketName = "credentials.sock"
	HostServiceSocketName    = "secretvaultd.sock"
	HostAdminSocketName      = "admin.sock"
)

// HostCredentialSocket is the socket units name in LoadCredential=.
func HostCredentialSocket() string {
	return filepath.Join(HostRuntimeDir(), HostCredentialSocketName)
}

// HostSocket is the socket local services use.
func HostSocket() string { return filepath.Join(HostRuntimeDir(), HostServiceSocketName) }

// HostAdminSocket is root's socket.
func HostAdminSocket() string { return filepath.Join(HostRuntimeDir(), HostAdminSocketName) }

// HostIdentityFile is the plain host identity file, read when systemd
// passes no credential: <data>/host.identity.
func HostIdentityFile() string { return filepath.Join(HostDataDir(), "host.identity") }

// HostPolicy is what the host daemon serves, and to whom. It is also the
// policy file's format (<data>/host.json). Anything it does not list is
// refused.
type HostPolicy struct {
	Credentials []HostCredential `json:"credentials"`
	Clients     []HostClient     `json:"clients"`
}

// HostCredential answers systemd's LoadCredential=CREDENTIAL:<credentials
// socket> for units whose name matches Unit: an exact name, or a glob
// such as app@*.service. An exact name wins over a glob; between globs,
// the first listed.
type HostCredential struct {
	Unit       string `json:"unit"`
	Credential string `json:"credential"`
	Ref        string `json:"ref"`
}

// HostClient lets a local service that is not a unit read references
// over the services socket. User is a user name or a numeric uid;
// Program, when set, is the executable (or the script an interpreter
// runs) it must be. Refs may use globs in the item and field
// (sv://prod/backup/*).
type HostClient struct {
	User    string   `json:"user"`
	Program string   `json:"program,omitempty"`
	Refs    []string `json:"refs"`
}

// HostRule is one change to the policy, for host.allow and host.deny:
// either a unit's credential (Unit, Credential, and Ref to allow) or a
// local service's references (User, Program, Refs; host.deny with no
// Refs removes the whole entry).
type HostRule struct {
	Unit       string   `json:"unit,omitempty"`
	Credential string   `json:"credential,omitempty"`
	Ref        string   `json:"ref,omitempty"`
	User       string   `json:"user,omitempty"`
	Program    string   `json:"program,omitempty"`
	Refs       []string `json:"refs,omitempty"`
}

// HostAllowResult says what might keep an allowed rule from working yet:
// a vault not here, an item not in it.
type HostAllowResult struct {
	Warnings []string `json:"warnings,omitempty"`
}

// HostResolveParams ask for one reference.
type HostResolveParams struct {
	Ref string `json:"ref"`
}

// HostResolveResult is the value a reference names.
type HostResolveResult struct {
	Value []byte `json:"value"`
}

// HostStatus describes the host daemon.
type HostStatus struct {
	Version string `json:"version"`
	PID     int    `json:"pid"`
	Data    string `json:"data"`

	CredentialSocket string `json:"credential_socket"`
	ServiceSocket    string `json:"service_socket"`
	AdminSocket      string `json:"admin_socket"`

	// Identity says where the host identity came from, "" when there is
	// none (IdentityError then says why, if one was found and refused);
	// Recipient is its public half, which vaults are shared to.
	Identity      string `json:"identity,omitempty"`
	IdentityError string `json:"identity_error,omitempty"`
	Recipient     string `json:"recipient,omitempty"`

	Policy      string `json:"policy"`
	PolicyError string `json:"policy_error,omitempty"` // while set, everything is refused
	Credentials int    `json:"credentials"`
	Clients     int    `json:"clients"`

	Vaults []HostVault `json:"vaults"`

	// Delivered and Refused count since the daemon started.
	Delivered int `json:"delivered"`
	Refused   int `json:"refused"`
}

// HostVault is a vault as the host sees it.
type HostVault struct {
	Name    string `json:"name"`
	Locked  bool   `json:"locked"`
	Missing bool   `json:"missing,omitempty"`
	// HostSlot says the vault has a keyslot for the host identity, so the
	// host can open it on its own.
	HostSlot bool `json:"host_slot"`
}

// HostEvent is one line of the host's log: a credential delivered or
// refused, a local service's read, a change to the policy.
type HostEvent struct {
	Time       time.Time `json:"time"`
	Outcome    string    `json:"outcome"` // delivered, refused, failed, changed
	Unit       string    `json:"unit,omitempty"`
	Credential string    `json:"credential,omitempty"`
	Program    string    `json:"program,omitempty"` // a local service or an administrator, as identified
	UID        int       `json:"uid"`
	PID        int       `json:"pid,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}
