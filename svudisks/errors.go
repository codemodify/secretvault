package svudisks

import (
	"errors"
	"strings"

	"github.com/codemodify/secretvault/svdbus"
)

// Error is a refusal or failure from UDisks2, polkit or the bus, told in
// plain words.
type Error struct {
	Op     string // what was being done: "mounting it"
	Name   string // the D-Bus error name
	Detail string // UDisks2's own message
}

// UDisks2's error names (udisks/udiskserror.h), and the bus's.
const (
	errPrefix                 = "org.freedesktop.UDisks2.Error."
	ErrorNotAuthorized        = errPrefix + "NotAuthorized"
	ErrorNotAuthorizedObtain  = errPrefix + "NotAuthorizedCanObtain"
	ErrorNotAuthorizedDismiss = errPrefix + "NotAuthorizedDismissed"
	ErrorDeviceBusy           = errPrefix + "DeviceBusy"
	ErrorAlreadyMounted       = errPrefix + "AlreadyMounted"
	ErrorNotMounted           = errPrefix + "NotMounted"
	ErrorOptionNotPermitted   = errPrefix + "OptionNotPermitted"
	ErrorMountedByOtherUser   = errPrefix + "MountedByOtherUser"
	ErrorCancelled            = errPrefix + "Cancelled"
	ErrorTimedout             = errPrefix + "Timedout"
	ErrorNotSupported         = errPrefix + "NotSupported"
	ErrorFailed               = errPrefix + "Failed"
)

var plain = map[string]string{
	ErrorNotAuthorized:                           "not authorized: your session is not active, or polkit does not allow this here (do it from your desktop session, not over ssh or from a service)",
	ErrorNotAuthorizedObtain:                     "not authorized: polkit wants an administrator's password for this, and there was no way to ask for it",
	ErrorNotAuthorizedDismiss:                    "not authorized: the password prompt was dismissed",
	ErrorDeviceBusy:                              "it is busy: close the files and programs using it, then try again",
	ErrorAlreadyMounted:                          "it is already mounted",
	ErrorNotMounted:                              "it is not mounted",
	ErrorOptionNotPermitted:                      "UDisks2 does not allow that mount option",
	ErrorMountedByOtherUser:                      "another user mounted it",
	ErrorCancelled:                               "canceled",
	ErrorTimedout:                                "UDisks2 gave up waiting",
	ErrorNotSupported:                            "UDisks2 cannot do that here",
	svdbus.ErrorServiceUnknown:                   "UDisks2 is not running (install the udisks2 package; the system starts it when asked)",
	svdbus.ErrorNameHasNoOwner:                   "UDisks2 is not running (install the udisks2 package; the system starts it when asked)",
	svdbus.ErrorAccessDenied:                     "the system bus refused the call",
	svdbus.ErrorNoReply:                          "UDisks2 did not answer",
	svdbus.ErrorTimeout:                          "UDisks2 did not answer",
	svdbus.ErrorInteractiveAuthorizationRequired: "not authorized: this needs an administrator's password",
}

func (e *Error) Error() string {
	why, detail := plain[e.Name], strings.TrimSpace(e.Detail)
	switch {
	case why == "" && detail == "":
		return e.Op + ": " + e.Name
	case why == "":
		return e.Op + ": " + detail
	case detail == "":
		return e.Op + ": " + why
	}
	return e.Op + ": " + why + " (UDisks2 said: " + detail + ")"
}

// Sentinels for errors.Is.
var (
	// ErrNotAuthorized is polkit saying no, for whatever reason.
	ErrNotAuthorized = errors.New("not authorized")
	// ErrBusy is a filesystem still in use.
	ErrBusy = errors.New("busy")
	// ErrNotRunning is a system with no UDisks2 on its bus.
	ErrNotRunning = errors.New("UDisks2 is not running")
)

func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotAuthorized:
		return strings.HasPrefix(e.Name, ErrorNotAuthorized) || e.Name == svdbus.ErrorInteractiveAuthorizationRequired
	case ErrBusy:
		return e.Name == ErrorDeviceBusy
	case ErrNotRunning:
		return e.Name == svdbus.ErrorServiceUnknown || e.Name == svdbus.ErrorNameHasNoOwner
	}
	return false
}

// explain turns a failed call's error into an *Error naming op.
func explain(op string, err error) error {
	if err == nil {
		return nil
	}
	var de *svdbus.Error
	if errors.As(err, &de) {
		return &Error{Op: op, Name: de.Name, Detail: de.Message()}
	}
	return &Error{Op: op, Detail: err.Error()}
}
