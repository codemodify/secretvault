package svrpc

import "time"

// Sync methods: a vault kept in step with a sync server (svserver).
const (
	MSyncSetup   = "sync.setup"   // SyncSetupParams -> SyncStatus
	MSyncJoin    = "sync.join"    // SyncJoinParams -> VaultInfo
	MSyncInvite  = "sync.invite"  // VaultRef -> SyncInvite
	MSyncStatus  = "sync.status"  // VaultRef ("" for every synced vault) -> []SyncStatus
	MSyncNow     = "sync.now"     // VaultRef -> SyncStatus
	MSyncDevices = "sync.devices" // VaultRef -> []SyncDevice
	MSyncRemove  = "sync.remove"  // SyncRemoveParams -> nil
	MSyncOff     = "sync.off"     // VaultRef -> nil
)

// SyncSetupParams starts syncing a vault that is not synced yet: the vault
// is made on the server, with this device as its first device.
type SyncSetupParams struct {
	Vault string `json:"vault,omitempty"`

	// URL is the server, like https://sync.example.com:8443.
	URL string `json:"url"`

	// Fingerprint pins a self-signed server certificate by its SHA-256
	// (as secretvault-server prints it).
	Fingerprint string `json:"fingerprint,omitempty"`

	// AdminToken is the server's, when it does not let anyone make vaults.
	AdminToken string `json:"admin_token,omitempty"`

	// Label names this device to the others.
	Label string `json:"label,omitempty"`
}

// SyncJoinParams fetches a vault from a sync server onto this device,
// with an invite from a device already syncing it, and registers it here.
type SyncJoinParams struct {
	Invite string `json:"invite"`
	Name   string `json:"name"`           // the vault's name on this device
	Path   string `json:"path,omitempty"` // "" for the data directory
	Label  string `json:"label,omitempty"`
}

// SyncInvite lets one more device join a synced vault. Invite is a
// secretvault-sync: URI; it holds a one-time code, so it is shown once.
type SyncInvite struct {
	Invite  string    `json:"invite"`
	Expires time.Time `json:"expires"`
}

// SyncStatus is how a synced vault is doing.
type SyncStatus struct {
	Vault       string    `json:"vault"`
	URL         string    `json:"url"`
	ServerVault string    `json:"server_vault"`
	Device      string    `json:"device"` // this device's key on the server
	Last        time.Time `json:"last,omitzero"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	Error       string    `json:"error,omitempty"` // the last sync's, if it failed

	// Pulled, Pushed and Removed add up what every sync since the daemon
	// started has done. Kept counts keyslot removals refused because they
	// would have left no key: a fault, or an attack.
	Pulled  int `json:"pulled"`
	Pushed  int `json:"pushed"`
	Removed int `json:"removed"`
	Kept    int `json:"kept,omitempty"`
}

// SyncDevice is a device enrolled in a synced vault.
type SyncDevice struct {
	Key      string     `json:"key"`
	Label    string     `json:"label,omitempty"`
	Added    time.Time  `json:"added"`
	AddedBy  string     `json:"added_by,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
	This     bool       `json:"this,omitempty"` // the asking daemon's own
}

// SyncRemoveParams removes a device from a synced vault on the server.
type SyncRemoveParams struct {
	Vault string `json:"vault,omitempty"`
	Key   string `json:"key"`
}
