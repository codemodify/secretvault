//go:build !linux

package svfido

import "runtime"

// Windows needs webauthn.dll (WebAuthn API version 3 or later, for
// hmac-secret salts): since Windows 10 1903 only administrators may talk
// to FIDO devices over raw HID. macOS needs IOKit's HID manager, which
// takes cgo, and secretvault builds without it. Both are planned.
func unsupported() string {
	switch runtime.GOOS {
	case "windows":
		return "security keys are not yet supported on Windows (they need webauthn.dll, which is not wired in yet)"
	case "darwin":
		return "security keys are not yet supported on macOS (they need IOKit, which is not wired in yet)"
	}
	return "security keys are not yet supported on " + runtime.GOOS
}

// Devices lists the FIDO security keys plugged in. Not yet on this system.
func Devices() ([]DeviceInfo, error) { return nil, ErrUnsupported }

func openTransport(DeviceInfo) (Transport, error) { return nil, ErrUnsupported }
