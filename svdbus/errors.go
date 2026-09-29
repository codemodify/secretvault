package svdbus

// Error is a D-Bus error: the reply a method call gets when it fails, and
// what a handler returns to make one. Body is the error's arguments; by
// convention the first is a human-readable message.
type Error struct {
	Name string
	Body []any
}

// NewError makes an error with a message.
func NewError(name, message string) *Error {
	return &Error{Name: name, Body: []any{message}}
}

// Message returns the error's human-readable message, if it has one.
func (e *Error) Message() string {
	if len(e.Body) > 0 {
		if s, ok := e.Body[0].(string); ok {
			return s
		}
	}
	return ""
}

func (e *Error) Error() string {
	if m := e.Message(); m != "" {
		return e.Name + ": " + m
	}
	return e.Name
}

// Standard error names, from the specification and the reference bus.
const (
	ErrorFailed                           = "org.freedesktop.DBus.Error.Failed"
	ErrorNoMemory                         = "org.freedesktop.DBus.Error.NoMemory"
	ErrorServiceUnknown                   = "org.freedesktop.DBus.Error.ServiceUnknown"
	ErrorNameHasNoOwner                   = "org.freedesktop.DBus.Error.NameHasNoOwner"
	ErrorNoReply                          = "org.freedesktop.DBus.Error.NoReply"
	ErrorTimeout                          = "org.freedesktop.DBus.Error.Timeout"
	ErrorDisconnected                     = "org.freedesktop.DBus.Error.Disconnected"
	ErrorAccessDenied                     = "org.freedesktop.DBus.Error.AccessDenied"
	ErrorNotSupported                     = "org.freedesktop.DBus.Error.NotSupported"
	ErrorLimitsExceeded                   = "org.freedesktop.DBus.Error.LimitsExceeded"
	ErrorInvalidArgs                      = "org.freedesktop.DBus.Error.InvalidArgs"
	ErrorUnknownMethod                    = "org.freedesktop.DBus.Error.UnknownMethod"
	ErrorUnknownObject                    = "org.freedesktop.DBus.Error.UnknownObject"
	ErrorUnknownInterface                 = "org.freedesktop.DBus.Error.UnknownInterface"
	ErrorUnknownProperty                  = "org.freedesktop.DBus.Error.UnknownProperty"
	ErrorPropertyReadOnly                 = "org.freedesktop.DBus.Error.PropertyReadOnly"
	ErrorInteractiveAuthorizationRequired = "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
	ErrorMatchRuleNotFound                = "org.freedesktop.DBus.Error.MatchRuleNotFound"
	ErrorMatchRuleInvalid                 = "org.freedesktop.DBus.Error.MatchRuleInvalid"
	ErrorUnixProcessIDUnknown             = "org.freedesktop.DBus.Error.UnixProcessIdUnknown"
	ErrorSELinuxSecurityContextUnknown    = "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"
	ErrorInconsistentMessage              = "org.freedesktop.DBus.Error.InconsistentMessage"
)
