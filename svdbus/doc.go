// Package svdbus is secretvault's own D-Bus implementation, written against
// the D-Bus specification with no library underneath: addresses, the SASL
// handshake, the wire format, a message bus connection with method calls,
// signals and name ownership, and exported objects with introspection and
// properties.
//
// The daemon uses it to own org.freedesktop.secrets and serve the Secret
// Service and the Secret portal backend (org.freedesktop.impl.portal.Secret),
// to follow logind and the screensaver so it can lock vaults, and to find
// out which process is behind a caller (GetConnectionCredentials).
//
// # Connecting
//
// ConnectSession and ConnectSystem find the bus from the environment
// (DBUS_SESSION_BUS_ADDRESS, DBUS_SYSTEM_BUS_ADDRESS) and Connect takes an
// address. Only the unix transport is implemented (unix:path=,
// unix:abstract=, unix:runtime=yes, and launchd:env= on macOS), with the
// EXTERNAL mechanism; on other platforms the encoding parts work and
// connecting fails with ErrUnsupported.
//
// # Go and D-Bus types
//
// Values are encoded and decoded as follows.
//
//	D-Bus        code   Go, when sending                  Go, when received (generic)
//	BYTE         y      uint8                              byte
//	BOOLEAN      b      bool                               bool
//	INT16        n      int16                              int16
//	UINT16       q      uint16                             uint16
//	INT32        i      int32                              int32
//	UINT32       u      uint32                             uint32
//	INT64        x      int64                              int64
//	UINT64       t      uint64                             uint64
//	DOUBLE       d      float64                            float64
//	STRING       s      string                             string
//	OBJECT_PATH  o      ObjectPath                         ObjectPath
//	SIGNATURE    g      Signature                          Signature
//	UNIX_FD      h      UnixFD                             UnixFD
//	VARIANT      v      Variant, or any interface value    Variant
//	ARRAY        aT     []T or [N]T; []byte is ay          see below
//	DICT         a{KV}  map[K]V (K a basic type)           see below
//	STRUCT       (...)  a struct: exported fields in order []any
//
// Signature inference (SignatureOf, and every call that is not given a
// signature) works from Go types alone, by the "when sending" column. An
// interface type, such as the elements of []any or the values of
// map[string]any, is a variant. Types with no fixed D-Bus size (int, uint,
// float32, ...) cannot be inferred; use a sized type, or give a signature.
// Struct fields tagged `dbus:"-"` are skipped.
//
// When a signature is given (Marshal, Message.Signature, the declared
// arguments of an exported method or property), encoding is looser: any
// integer kind that fits encodes as any integer type, a string-kinded value
// as s, o or g (validated), []any of the right length as a struct, and a
// non-Variant value where a variant is expected is wrapped with its inferred
// signature.
//
// Received values are decoded into a small, fixed set of Go types, so a peer
// cannot make the process build new types: arrays of basic types become
// typed slices ([]string, []byte, []uint32, ...), av becomes []Variant, any
// other array []any; a dict whose value is basic becomes a typed map
// (map[string]string), whose value is a variant map[K]Variant, and any other
// map[K]any; a struct becomes []any. Message.Decode, Variant.Store and Store
// then convert those into typed Go values given by pointer, in the manner of
// encoding/json: structs from []any field by field, typed slices and maps
// element by element, variants unwrapped into concrete targets, and
// integers into any integer kind they fit.
//
// # File descriptors
//
// A UnixFD sent is duplicated by the kernel; the sender keeps its own. A
// UnixFD received belongs to whoever receives the message: the caller of
// Call for a reply, the handler for a method call, the subscriber for a
// signal (each subscriber gets its own duplicate). Descriptors that arrive
// with a message but are not referenced by its body, or that arrive on a
// message nobody takes, are closed by the connection.
//
// # Limits
//
// Everything read is checked before it is trusted: message size (128 MiB,
// or less with WithMaxMessageSize), array size (64 MiB), signature length
// (255) and nesting (32 arrays, 32 structs, 64 containers in all, variants
// included), names and object paths, UTF-8, boolean values, padding bytes,
// and descriptor counts. A malformed message is refused; a malformed stream
// closes the connection. Nothing a peer sends can make the package panic.
//
// # Concurrency
//
// A Conn is safe for concurrent use. One goroutine reads; replies go to
// their callers, signals to subscriptions (each with its own goroutine and
// queue), and method calls to handlers, each in its own goroutine, so a
// handler may itself make calls on the same connection.
package svdbus
