package svrpc

import "time"

// Device methods: the devices registered in a vault, whose keys sign the
// revisions they write, and the vault's policy on signatures.
const (
	MDeviceList   = "device.list"   // VaultRef -> []Device
	MDeviceLabel  = "device.label"  // DeviceLabelParams -> Device
	MDeviceRemove = "device.remove" // DeviceRef -> Device
	MDeviceVouch  = "device.vouch"  // DeviceVouchParams -> Device

	MVaultSignatures = "vault.signatures" // SignaturesParams -> SignaturePolicy
)

// Device is a device registered in a vault.
type Device struct {
	// Key is the ID of the device's signing key: what to compare with the
	// key the device itself shows, before vouching for it.
	Key        string    `json:"key"`
	Device     string    `json:"device"`
	Label      string    `json:"label,omitempty"`
	Registered time.Time `json:"registered"`
	Removed    bool      `json:"removed,omitempty"`

	// This is the asking daemon's own device.
	This bool `json:"this,omitempty"`

	// Vouched: this daemon's device vouches for it, directly or through
	// devices it vouched for.
	Vouched bool `json:"vouched,omitempty"`

	// Vouches are the keys it vouches for.
	Vouches []string `json:"vouches,omitempty"`
}

// DeviceRef names a device of a vault by its key ID, or the first digits
// of it (never by its device ID, which anyone could register a key
// under).
type DeviceRef struct {
	Vault  string `json:"vault,omitempty"`
	Device string `json:"device"`
}

// DeviceLabelParams give a device a new label ("" Device: this one).
type DeviceLabelParams struct {
	Vault  string `json:"vault,omitempty"`
	Device string `json:"device,omitempty"`
	Label  string `json:"label"`
}

// DeviceVouchParams record that this device vouches for another, or
// (Withdraw) no longer does.
type DeviceVouchParams struct {
	Vault    string `json:"vault,omitempty"`
	Device   string `json:"device"`
	Withdraw bool   `json:"withdraw,omitempty"`
}

// SignaturesParams read a vault's policy on signatures, or with Require
// set, change it.
type SignaturesParams struct {
	Vault   string `json:"vault,omitempty"`
	Require *bool  `json:"require,omitempty"`
}

// SignaturePolicy is a vault's policy on signatures.
type SignaturePolicy struct {
	Vault string `json:"vault"`

	// Require: only revisions signed by a registered device count.
	Require bool `json:"require"`
}

// Signature says who signed a revision, as the vault's registry tells.
type Signature struct {
	// Status is "verified" (a good signature by a registered device),
	// "unsigned", "unverified" (by a key no device registered here), or
	// "bad" (it does not verify: changed, or someone posing as the
	// device it names).
	Status  string `json:"status"`
	Key     string `json:"key,omitempty"`
	Device  string `json:"device,omitempty"`
	Label   string `json:"label,omitempty"`
	Removed bool   `json:"removed,omitempty"`
	Vouched bool   `json:"vouched,omitempty"`
	Mine    bool   `json:"mine,omitempty"` // made by the asking daemon's device
}

// Signature statuses.
const (
	SigVerified   = "verified"
	SigUnsigned   = "unsigned"
	SigUnverified = "unverified"
	SigBad        = "bad"
)
