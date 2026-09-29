package svdbus

import (
	"errors"
	"fmt"
	"reflect"
)

// Limits from the D-Bus specification.
const (
	// MaxMessageSize is the largest message, header and body together.
	MaxMessageSize = 1 << 27

	// MaxArraySize is the largest array, in bytes of marshalled elements.
	MaxArraySize = 1 << 26

	// MaxSignatureLength is the longest signature.
	MaxSignatureLength = 255

	// MaxNameLength is the longest bus, interface, member or error name.
	MaxNameLength = 255

	// MaxDepth is the deepest nesting of containers (arrays, structs, dict
	// entries and variants) in one message.
	MaxDepth = 64

	// MaxUnixFDs is the most file descriptors one message may carry: the
	// most the Linux kernel passes in one sendmsg.
	MaxUnixFDs = 253
)

var (
	// ErrInvalid is D-Bus data that breaks the specification: a malformed
	// message, name, path, signature or address, or a Go value that cannot
	// be encoded as asked.
	ErrInvalid = errors.New("svdbus: invalid")

	// ErrClosed is an operation on a connection that has been closed, or
	// that the bus has dropped.
	ErrClosed = errors.New("svdbus: connection closed")

	// ErrUnsupported is an address or feature this build cannot use, such as
	// a tcp: address, or any transport on a platform without unix sockets.
	ErrUnsupported = errors.New("svdbus: unsupported")

	// ErrAuth is a bus that refused to authenticate us.
	ErrAuth = errors.New("svdbus: authentication failed")
)

// invalidf wraps ErrInvalid with detail.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ObjectPath is a D-Bus object path, such as /org/freedesktop/secrets.
type ObjectPath string

// Validate reports whether p is a well-formed object path.
func (p ObjectPath) Validate() error { return validateObjectPath(string(p)) }

// IsValid reports whether p is a well-formed object path.
func (p ObjectPath) IsValid() bool { return p.Validate() == nil }

// Signature is a D-Bus type signature: zero or more complete types, such as
// "sa{sv}".
type Signature string

// Validate reports whether s is a well-formed signature within the
// specification's length and nesting limits.
func (s Signature) Validate() error {
	_, err := parseSignature(string(s))
	return err
}

// IsValid reports whether s is a well-formed signature.
func (s Signature) IsValid() bool { return s.Validate() == nil }

// UnixFD is a file descriptor passed out of band with a message (SCM_RIGHTS).
// On the wire it is an index into the message's descriptors; in Go it is the
// descriptor itself. See the package documentation for who closes it.
type UnixFD int

// Variant is a value together with its D-Bus type: the Go form of v.
type Variant struct {
	Signature Signature
	Value     any
}

// MakeVariant wraps v, inferring its signature from its Go type. A value
// whose signature cannot be inferred gets an empty one, and encoding it
// fails.
func MakeVariant(v any) Variant {
	sig, err := SignatureOf(v)
	if err != nil {
		return Variant{Value: v}
	}
	return Variant{Signature: sig, Value: v}
}

// Store decodes the variant's value into dst, which must be a non-nil
// pointer, by the rules of Store.
func (v Variant) Store(dst any) error { return Store([]any{v.Value}, dst) }

// String formats the variant for debugging, as <signature value>.
func (v Variant) String() string { return fmt.Sprintf("<%s %v>", v.Signature, v.Value) }

// MessageType is the kind of a message.
type MessageType uint8

// The four kinds of message.
const (
	TypeMethodCall   MessageType = 1
	TypeMethodReturn MessageType = 2
	TypeError        MessageType = 3
	TypeSignal       MessageType = 4
)

// String returns the name match rules use: method_call, method_return,
// error or signal.
func (t MessageType) String() string {
	switch t {
	case TypeMethodCall:
		return "method_call"
	case TypeMethodReturn:
		return "method_return"
	case TypeError:
		return "error"
	case TypeSignal:
		return "signal"
	}
	return fmt.Sprintf("type%d", uint8(t))
}

// Flags are a message's header flags.
type Flags uint8

const (
	// FlagNoReplyExpected is a method call whose caller will not wait for a
	// reply, so none should be sent.
	FlagNoReplyExpected Flags = 0x1

	// FlagNoAutoStart asks the bus not to start the destination's service.
	FlagNoAutoStart Flags = 0x2

	// FlagAllowInteractiveAuthorization tells the callee the caller is
	// prepared to wait for an interactive authorization (a prompt).
	FlagAllowInteractiveAuthorization Flags = 0x4
)

var (
	variantType    = reflect.TypeFor[Variant]()
	objectPathType = reflect.TypeFor[ObjectPath]()
	signatureType  = reflect.TypeFor[Signature]()
	unixFDType     = reflect.TypeFor[UnixFD]()
	anyType        = reflect.TypeFor[any]()
	bytesType      = reflect.TypeFor[[]byte]()
)
