package svfido

import (
	"errors"
	"fmt"
)

// Status is a CTAP status code other than success (CTAP 2.1 §8.2), as an
// error. errors.Is(err, StatusNoCredentials) and the like test for one.
type Status byte

// The statuses secretvault acts on. The rest are reported by their
// message.
const (
	StatusInvalidCommand     Status = 0x01
	StatusInvalidParameter   Status = 0x02
	StatusInvalidLength      Status = 0x03
	StatusChannelBusy        Status = 0x06
	StatusInvalidCBOR        Status = 0x12
	StatusMissingParameter   Status = 0x14
	StatusLimitExceeded      Status = 0x15
	StatusCredentialExcluded Status = 0x19
	StatusUnsupportedAlg     Status = 0x26
	StatusOperationDenied    Status = 0x27
	StatusUnsupportedOption  Status = 0x2B
	StatusInvalidOption      Status = 0x2C
	StatusKeepaliveCancel    Status = 0x2D
	StatusNoCredentials      Status = 0x2E
	StatusUserActionTimeout  Status = 0x2F
	StatusNotAllowed         Status = 0x30
	StatusPINInvalid         Status = 0x31
	StatusPINBlocked         Status = 0x32
	StatusPINAuthInvalid     Status = 0x33
	StatusPINAuthBlocked     Status = 0x34
	StatusPINNotSet          Status = 0x35
	StatusPUATRequired       Status = 0x36 // PIN_REQUIRED in CTAP 2.0
	StatusPINPolicyViolation Status = 0x37
	StatusRequestTooLarge    Status = 0x39
	StatusActionTimeout      Status = 0x3A
	StatusUPRequired         Status = 0x3B
	StatusUVBlocked          Status = 0x3C
	StatusUVInvalid          Status = 0x3F
	StatusUnauthorizedPerm   Status = 0x40
	StatusOther              Status = 0x7F
)

var statusText = map[Status]string{
	StatusInvalidCommand:     "the security key does not know that command",
	StatusInvalidParameter:   "the security key refused a parameter",
	StatusInvalidLength:      "the security key refused the length of the message",
	0x04:                     "the security key received a message out of order",
	0x05:                     "the security key gave up waiting for the rest of a message",
	StatusChannelBusy:        "the security key is busy with another program",
	0x0A:                     "the security key is locked by another program",
	0x0B:                     "the security key does not know this channel",
	0x11:                     "the security key could not read the request",
	StatusInvalidCBOR:        "the security key could not read the request",
	StatusMissingParameter:   "the security key says a parameter is missing",
	StatusLimitExceeded:      "the request asks more than the security key allows",
	StatusCredentialExcluded: "this security key is already enrolled",
	StatusUnsupportedAlg:     "the security key does not support the algorithm asked for",
	StatusOperationDenied:    "the security key refused the operation",
	0x28:                     "the security key has no room for another credential",
	StatusUnsupportedOption:  "the security key does not support an option asked for",
	StatusInvalidOption:      "the security key refused an option",
	StatusKeepaliveCancel:    "the operation was cancelled",
	StatusNoCredentials:      "the security key holds no credential for this",
	StatusUserActionTimeout:  "nobody touched the security key in time",
	StatusNotAllowed:         "the security key does not allow that",
	StatusPINInvalid:         "wrong PIN",
	StatusPINBlocked:         "the security key's PIN is blocked after too many wrong tries; the key must be reset, which erases every credential on it",
	StatusPINAuthInvalid:     "the security key refused the PIN's authorisation",
	StatusPINAuthBlocked:     "too many wrong PINs in a row: unplug the security key and plug it in again before trying another",
	StatusPINNotSet:          "the security key has no PIN set",
	StatusPUATRequired:       "the security key asks for its PIN for this",
	StatusPINPolicyViolation: "the PIN does not meet the security key's rules",
	StatusRequestTooLarge:    "the request is larger than the security key accepts",
	StatusActionTimeout:      "the security key timed out",
	StatusUPRequired:         "the security key needs a touch for this",
	StatusUVBlocked:          "the security key's built-in verification is blocked; its PIN still works",
	0x3D:                     "the security key reports an integrity failure",
	0x3E:                     "the security key does not know that subcommand",
	StatusUVInvalid:          "the security key could not verify you",
	StatusUnauthorizedPerm:   "the PIN token does not permit this",
	StatusOther:              "the security key reported an unspecified error",
}

func (s Status) Error() string {
	if t, ok := statusText[s]; ok {
		return t
	}
	return fmt.Sprintf("the security key answered with error 0x%02x", byte(s))
}

// HIDError is a CTAPHID_ERROR from the device: the transport, rather than
// a command, failed.
type HIDError byte

func (e HIDError) Error() string {
	if t, ok := statusText[Status(e)]; ok && e < 0x10 {
		return t
	}
	return fmt.Sprintf("the security key reported transport error 0x%02x", byte(e))
}

const hidErrChannelBusy HIDError = 0x06

var (
	// ErrUnsupported is a system where secretvault cannot reach security
	// keys yet (Windows and macOS, today).
	ErrUnsupported = errors.New(unsupported())

	// ErrNoDevice is a machine with no FIDO security key plugged in.
	ErrNoDevice = errors.New("no security key is plugged in")

	// ErrMalformed is an answer from a device that does not follow CTAP.
	ErrMalformed = errors.New("the security key sent a malformed answer")

	// ErrNotCTAP2 is a device that speaks only U2F (CTAP1).
	ErrNotCTAP2 = errors.New("the security key speaks only U2F; secretvault needs a FIDO2 key")

	// ErrNoHMACSecret is a FIDO2 device without the hmac-secret
	// extension, which secretvault's keyslots are built on.
	ErrNoHMACSecret = errors.New("the security key does not support hmac-secret, which secretvault needs")

	// ErrNotEnrolled is an unlock where no key present holds any of the
	// vault's credentials.
	ErrNotEnrolled = errors.New("none of the security keys plugged in is a keyslot of this vault")

	// ErrTimeout is a device that stopped answering.
	ErrTimeout = errors.New("the security key stopped answering")

	// ErrGone is a device that was unplugged while in use.
	ErrGone = errors.New("the security key was unplugged")

	// ErrTokenMisuse is a PIN token presented where it does not apply: to
	// another device, for another site, for a command it does not permit,
	// or after it was used up. It is refused before anything is sent.
	ErrTokenMisuse = errors.New("svfido: that PIN token does not apply here")
)

// PermissionError is a security key this user may not open. It carries
// the usual fix, since on Linux the answer is almost always a udev rule.
type PermissionError struct {
	Path string // /dev/hidrawN
	Name string // the product, when known
	Err  error
}

func (e *PermissionError) Error() string {
	what := e.Path
	if e.Name != "" {
		what = e.Name + " at " + e.Path
	}
	return fmt.Sprintf("you have no permission to use the security key (%s). "+
		"Security keys need a udev rule that gives the logged-in user access: systemd 244 and later ship one "+
		"(60-fido-id.rules, which tags FIDO keys for the active session); on other systems install the "+
		"libfido2 or u2f-udev package, which carries the rules. Then unplug the key and plug it in again", what)
}

func (e *PermissionError) Unwrap() error { return e.Err }

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}
