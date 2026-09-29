// Package svseal protects a small secret so that only this user, on this
// machine, can open it: the operating system's own sealing, used to open a
// vault at login without asking (a "login" keyslot).
//
//	Linux    systemd-creds --user: the host key, and the TPM2 when there is one
//	Windows  DPAPI (CryptProtectData), bound to the user's logon credentials
//	macOS    the login keychain, through /usr/bin/security
//
// What that is worth depends on the OS. A sealed secret opens for any
// program running as the user while they are logged in, which is the
// point, and for no one else on a running machine. Against a stolen disk
// it holds on Windows and macOS, and on Linux with a TPM2; without one,
// systemd's host key sits on the same disk, so only full-disk encryption
// protects it.
package svseal

import "errors"

// A Sealer seals and opens secrets for the current user. name binds a
// sealed secret to its purpose: one sealed under another name does not
// open.
type Sealer interface {
	// Name says what does the sealing, for people.
	Name() string
	// Available reports why the sealer cannot work here, or nil.
	Available() error
	Seal(name string, secret []byte) ([]byte, error)
	Unseal(name string, sealed []byte) ([]byte, error)
}

// ErrUnavailable is a machine without the OS's sealing.
var ErrUnavailable = errors.New("svseal: this system cannot seal secrets to the user")

// Default is the OS's sealer.
func Default() Sealer { return platform() }
