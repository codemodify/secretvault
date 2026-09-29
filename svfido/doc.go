// Package svfido talks to FIDO2 security keys, in secretvault's own code:
// CTAPHID over HID reports, CTAP2 messages in CBOR, and the PIN/UV auth
// protocols, after the FIDO Alliance's Client to Authenticator Protocol
// 2.1 (and 2.2, which changes nothing used here).
//
// secretvault uses a key for one thing: the hmac-secret extension, which
// turns a salt into 32 bytes that only that key, holding that credential,
// can produce. A vault's fido2 keyslot is sealed under a key derived from
// them (docs/format.md). The key's secret never leaves it.
//
// The layers, bottom up:
//
//   - Transport: 64-byte HID reports to one device. On Linux, a
//     /dev/hidraw node, found by the FIDO usage page (0xF1D0) in its
//     report descriptor in sysfs (Devices). Windows (through webauthn.dll)
//     and macOS (through IOKit, which needs cgo) come later; there,
//     Devices returns ErrUnsupported.
//   - CTAPHID framing (ctaphid.go): channels, messages cut into packets,
//     KEEPALIVE while the device waits for a touch, CANCEL, and errors.
//   - Device (ctap.go, pin.go): getInfo, makeCredential, getAssertion with
//     hmac-secret, selection, and clientPIN with PIN/UV auth protocols 2
//     and 1. Every answer's shape is checked, and PIN tokens are refused
//     where they do not apply before anything is sent.
//   - Keys (keys.go): enrolling a key and evaluating an enrolled credential
//     across every key plugged in, asking the person for the PIN and the
//     touch through Prompts.
//
// Tests run against a software authenticator (internal/fidotest), never a
// real device.
package svfido
