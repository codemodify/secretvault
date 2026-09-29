package svdbus

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Message is one D-Bus message. Serial is set by the connection when the
// message is sent. Body holds the arguments: on messages built here any Go
// values (encoded by Signature, or with inferred types when Signature is
// empty); on messages received, generic decoded values.
type Message struct {
	Type   MessageType
	Flags  Flags
	Serial uint32

	Path        ObjectPath
	Interface   string
	Member      string
	ErrorName   string
	ReplySerial uint32
	Destination string
	Sender      string
	Signature   Signature

	Body []any

	fds      []UnixFD         // received descriptors by index; -1 once closed or not referenced
	handOver bool             // close the descriptors in the body once sent (a handler's reply)
	bodyErr  error            // why a received body could not be decoded
	raw      []byte           // a received signal's body, kept to hand each subscriber its own descriptors
	order    binary.ByteOrder // raw's byte order
}

// Header field codes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
	fieldUnixFDs     = 9
)

// fieldTypes is the one type each known header field must have.
var fieldTypes = [...]string{
	fieldPath:        "o",
	fieldInterface:   "s",
	fieldMember:      "s",
	fieldErrorName:   "s",
	fieldReplySerial: "u",
	fieldDestination: "s",
	fieldSender:      "s",
	fieldSignature:   "g",
	fieldUnixFDs:     "u",
}

// NewMethodCall makes a method call. dest may be empty on a peer-to-peer
// connection, and iface may be empty to let the callee pick the method by
// name alone.
func NewMethodCall(dest string, path ObjectPath, iface, member string, args ...any) *Message {
	return &Message{Type: TypeMethodCall, Destination: dest, Path: path, Interface: iface, Member: member, Body: args}
}

// NewSignal makes a signal, broadcast unless Destination is then set.
func NewSignal(path ObjectPath, iface, member string, args ...any) *Message {
	return &Message{Type: TypeSignal, Path: path, Interface: iface, Member: member, Body: args}
}

// NewMethodReturn makes the successful reply to call.
func NewMethodReturn(call *Message, args ...any) *Message {
	return &Message{Type: TypeMethodReturn, ReplySerial: call.Serial, Destination: call.Sender, Body: args}
}

// NewErrorReply makes the error reply to call.
func NewErrorReply(call *Message, name string, args ...any) *Message {
	return &Message{Type: TypeError, ReplySerial: call.Serial, Destination: call.Sender, ErrorName: name, Body: args}
}

// Err returns the D-Bus error an error message carries, or nil for any other
// message.
func (m *Message) Err() error {
	if m.Type != TypeError {
		return nil
	}
	return &Error{Name: m.ErrorName, Body: m.Body}
}

// Decode stores the body's values into dst, one pointer per value, by the
// rules of Store.
func (m *Message) Decode(dst ...any) error {
	if m.bodyErr != nil {
		return m.bodyErr
	}
	return Store(m.Body, dst...)
}

// FDs returns the descriptors that came with a received message and that its
// body refers to. The receiver owns them.
func (m *Message) FDs() []UnixFD {
	var out []UnixFD
	for _, fd := range m.fds {
		if fd >= 0 {
			out = append(out, fd)
		}
	}
	return out
}

// CloseFDs closes every descriptor that came with a received message. A
// receiver that wants none of them calls it once and forgets them.
func (m *Message) CloseFDs() {
	for i, fd := range m.fds {
		if fd >= 0 {
			closeFD(fd)
			m.fds[i] = -1
		}
	}
}

// String describes the header for debugging. It leaves out the body, which
// may hold secrets.
func (m *Message) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s serial=%d", m.Type, m.Serial)
	add := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	add("sender", m.Sender)
	add("destination", m.Destination)
	add("path", string(m.Path))
	add("interface", m.Interface)
	add("member", m.Member)
	add("error", m.ErrorName)
	if m.ReplySerial != 0 {
		fmt.Fprintf(&b, " reply_serial=%d", m.ReplySerial)
	}
	fmt.Fprintf(&b, " signature=%q", m.Signature)
	return b.String()
}

// validate checks the header: the fields each type requires, and the form of
// every name.
func (m *Message) validate() error {
	switch m.Type {
	case TypeMethodCall:
		if m.Path == "" || m.Member == "" {
			return invalidf("method call without a path and a member")
		}
	case TypeSignal:
		if m.Path == "" || m.Interface == "" || m.Member == "" {
			return invalidf("signal without a path, an interface and a member")
		}
	case TypeMethodReturn:
		if m.ReplySerial == 0 {
			return invalidf("method return without a reply serial")
		}
	case TypeError:
		if m.ErrorName == "" || m.ReplySerial == 0 {
			return invalidf("error without a name and a reply serial")
		}
	}
	if m.Path != "" {
		if err := m.Path.Validate(); err != nil {
			return err
		}
	}
	if m.Interface != "" {
		if err := ValidateInterfaceName(m.Interface); err != nil {
			return err
		}
	}
	if m.Member != "" {
		if err := ValidateMemberName(m.Member); err != nil {
			return err
		}
	}
	if m.ErrorName != "" {
		if err := ValidateErrorName(m.ErrorName); err != nil {
			return err
		}
	}
	if m.Destination != "" {
		if err := ValidateBusName(m.Destination); err != nil {
			return err
		}
	}
	if m.Sender != "" {
		if err := ValidateBusName(m.Sender); err != nil {
			return err
		}
	}
	return nil
}

// Marshal encodes the message, little-endian, with the serial m.Serial
// (which must not be zero). It returns the bytes and the descriptors to send
// with them.
func (m *Message) Marshal() ([]byte, []UnixFD, error) {
	return m.marshal(binary.LittleEndian)
}

func (m *Message) marshal(order byteOrder) ([]byte, []UnixFD, error) {
	if m.Serial == 0 {
		return nil, nil, invalidf("message serial is zero")
	}
	switch m.Type {
	case TypeMethodCall, TypeMethodReturn, TypeError, TypeSignal:
	default:
		return nil, nil, invalidf("message type %d", m.Type)
	}
	if err := m.validate(); err != nil {
		return nil, nil, err
	}
	body := encoder{order: order}
	sig, err := body.values(m.Signature, m.Body)
	if err != nil {
		return nil, nil, err
	}

	h := encoder{buf: make([]byte, 0, 128), order: order}
	mark := byte('l')
	if order == binary.BigEndian {
		mark = 'B'
	}
	h.buf = append(h.buf, mark, byte(m.Type), byte(m.Flags), 1)
	h.u32(uint32(len(body.buf)))
	h.u32(m.Serial)
	h.u32(0) // the header fields' length, filled in below
	start := len(h.buf)
	field := func(code byte, sig string) {
		h.pad(8)
		h.buf = append(h.buf, code)
		h.sig(sig)
	}
	if m.Path != "" {
		field(fieldPath, "o")
		h.str(string(m.Path))
	}
	if m.Interface != "" {
		field(fieldInterface, "s")
		h.str(m.Interface)
	}
	if m.Member != "" {
		field(fieldMember, "s")
		h.str(m.Member)
	}
	if m.ErrorName != "" {
		field(fieldErrorName, "s")
		h.str(m.ErrorName)
	}
	if m.ReplySerial != 0 {
		field(fieldReplySerial, "u")
		h.u32(m.ReplySerial)
	}
	if m.Destination != "" {
		field(fieldDestination, "s")
		h.str(m.Destination)
	}
	if m.Sender != "" {
		field(fieldSender, "s")
		h.str(m.Sender)
	}
	if sig != "" {
		field(fieldSignature, "g")
		h.sig(string(sig))
	}
	if len(body.fds) > 0 {
		field(fieldUnixFDs, "u")
		h.u32(uint32(len(body.fds)))
	}
	order.PutUint32(h.buf[12:], uint32(len(h.buf)-start))
	h.pad(8)
	if len(h.buf)+len(body.buf) > MaxMessageSize {
		return nil, nil, invalidf("message of %d bytes is larger than %d", len(h.buf)+len(body.buf), MaxMessageSize)
	}
	return append(h.buf, body.buf...), body.fds, nil
}

// UnmarshalMessage decodes one whole message. fds must be exactly the
// descriptors the message declares; UnmarshalMessage neither keeps nor
// closes the ones its body does not refer to.
func UnmarshalMessage(data []byte, fds []UnixFD) (*Message, error) {
	total, err := frameLength(data, MaxMessageSize)
	if err != nil {
		return nil, err
	}
	if total != len(data) {
		return nil, invalidf("message is %d bytes but declares %d", len(data), total)
	}
	m, d, n, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	if n != len(fds) {
		return nil, invalidf("message declares %d descriptors but %d came with it", n, len(fds))
	}
	if err := m.decodeBody(d, fds); err != nil {
		return nil, err
	}
	return m, nil
}

// frameLength reads the fixed first 16 bytes of a message and returns the
// length of the whole message, refusing anything over max.
func frameLength(hdr []byte, max int) (int, error) {
	if len(hdr) < 16 {
		return 0, invalidf("message header is truncated")
	}
	order, err := orderOf(hdr[0])
	if err != nil {
		return 0, err
	}
	if hdr[3] != 1 {
		return 0, invalidf("protocol version %d", hdr[3])
	}
	body := uint64(order.Uint32(hdr[4:8]))
	fields := uint64(order.Uint32(hdr[12:16]))
	if fields > MaxArraySize {
		return 0, invalidf("header fields of %d bytes", fields)
	}
	total := 16 + (fields+7)&^7 + body
	if total > uint64(max) {
		return 0, invalidf("message of %d bytes is larger than %d", total, max)
	}
	return int(total), nil
}

func orderOf(b byte) (binary.ByteOrder, error) {
	switch b {
	case 'l':
		return binary.LittleEndian, nil
	case 'B':
		return binary.BigEndian, nil
	}
	return nil, invalidf("byte order mark %q", b)
}

// parseHeader decodes the header of a whole, framed message. It returns the
// message without its body, a decoder positioned at the body, and the number
// of descriptors the message declares.
func parseHeader(data []byte) (*Message, *decoder, int, error) {
	order, err := orderOf(data[0])
	if err != nil {
		return nil, nil, 0, err
	}
	m := &Message{
		Type:   MessageType(data[1]),
		Flags:  Flags(data[2]),
		Serial: order.Uint32(data[8:12]),
	}
	if m.Serial == 0 {
		return nil, nil, 0, invalidf("message serial is zero")
	}
	bodyLen := order.Uint32(data[4:8])
	d := &decoder{buf: data, pos: 12, order: order}
	n, err := d.u32()
	if err != nil {
		return nil, nil, 0, err
	}
	if err := d.align(8); err != nil {
		return nil, nil, 0, err
	}
	if uint64(n) > uint64(len(data)-d.pos) {
		return nil, nil, 0, invalidf("header fields run past the end")
	}
	d.buf = data[:d.pos+int(n)]
	var seen [len(fieldTypes)]bool
	nfds := 0
	for d.pos < len(d.buf) {
		if err := d.align(8); err != nil {
			return nil, nil, 0, err
		}
		code, err := d.u8()
		if err != nil {
			return nil, nil, 0, err
		}
		s, err := d.sig()
		if err != nil {
			return nil, nil, 0, err
		}
		t, err := parseSingle(s)
		if err != nil {
			return nil, nil, 0, err
		}
		v, err := d.value(t, 3)
		if err != nil {
			return nil, nil, 0, err
		}
		if code == 0 {
			return nil, nil, 0, invalidf("header field code 0")
		}
		if int(code) >= len(fieldTypes) {
			continue // unknown fields are ignored
		}
		if seen[code] {
			return nil, nil, 0, invalidf("header field %d appears twice", code)
		}
		seen[code] = true
		if s != fieldTypes[code] {
			return nil, nil, 0, invalidf("header field %d has type %q, not %q", code, s, fieldTypes[code])
		}
		switch code {
		case fieldPath:
			m.Path = v.(ObjectPath)
		case fieldInterface:
			m.Interface = v.(string)
		case fieldMember:
			m.Member = v.(string)
		case fieldErrorName:
			m.ErrorName = v.(string)
		case fieldReplySerial:
			m.ReplySerial = v.(uint32)
		case fieldDestination:
			m.Destination = v.(string)
		case fieldSender:
			m.Sender = v.(string)
		case fieldSignature:
			m.Signature = v.(Signature)
		case fieldUnixFDs:
			if v.(uint32) > MaxUnixFDs {
				return nil, nil, 0, invalidf("message declares %d descriptors", v.(uint32))
			}
			nfds = int(v.(uint32))
		}
	}
	if seen[fieldReplySerial] && m.ReplySerial == 0 {
		return nil, nil, 0, invalidf("reply serial is zero")
	}
	if err := m.validate(); err != nil {
		return nil, nil, 0, err
	}
	d.buf = data
	if err := d.align(8); err != nil {
		return nil, nil, 0, err
	}
	if uint64(len(data)-d.pos) != uint64(bodyLen) {
		return nil, nil, 0, invalidf("body is %d bytes but declared %d", len(data)-d.pos, bodyLen)
	}
	return m, d, nfds, nil
}

// decodeBody decodes the body that d is positioned at, with the descriptors
// that came with the message.
func (m *Message) decodeBody(d *decoder, fds []UnixFD) error {
	types, err := parseSignature(string(m.Signature))
	if err != nil {
		return err
	}
	d.setFDs(fds)
	body, err := d.body(types)
	if err != nil {
		return err
	}
	m.Body = body
	return nil
}
