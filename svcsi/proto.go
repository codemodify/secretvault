package svcsi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The provider protocol's messages, as the Secrets Store CSI driver
// defines them (sigs.k8s.io/secrets-store-csi-driver,
// provider/v1alpha1/service.proto), encoded and decoded by hand in
// protobuf's wire format. Only what these messages use is here: varints
// (wire type 0) and length-delimited fields (wire type 2); fields of
// other types are skipped, as protobuf requires of unknown fields.
//
//	message VersionRequest  { string version = 1; }
//	message VersionResponse { string version = 1; string runtime_name = 2; string runtime_version = 3; }
//	message MountRequest    { string attributes = 1; string secrets = 2; string target_path = 3;
//	                          string permission = 4; repeated ObjectVersion current_object_version = 5; }
//	message MountResponse   { repeated ObjectVersion object_version = 1; Error error = 2; repeated File files = 3; }
//	message File            { string path = 1; int32 mode = 2; bytes contents = 3; }
//	message ObjectVersion   { string id = 1; string version = 2; }
//	message Error           { string code = 1; }

// VersionRequest asks the provider its version.
type VersionRequest struct {
	Version string // the driver's protocol version, "v1alpha1"
}

// VersionResponse answers it.
type VersionResponse struct {
	Version        string
	RuntimeName    string
	RuntimeVersion string
}

// MountRequest asks for a volume's files.
type MountRequest struct {
	Attributes           string // JSON: the SecretProviderClass's parameters, and the pod's
	Secrets              string // JSON: the nodePublishSecretRef's data
	TargetPath           string
	Permission           string // JSON: the files' mode, as a decimal number
	CurrentObjectVersion []ObjectVersion
}

// MountResponse gives the files, for the driver to write.
type MountResponse struct {
	ObjectVersion []ObjectVersion
	Error         *Error
	Files         []File
}

// File is one file of the volume.
type File struct {
	Path     string
	Mode     int32
	Contents []byte
}

// ObjectVersion names an object and its version, so the driver can tell
// when a secret changed.
type ObjectVersion struct {
	ID      string
	Version string
}

// Error is an error code in a MountResponse.
type Error struct {
	Code string
}

const (
	wireVarint = 0
	wire64     = 1
	wireBytes  = 2
	wire32     = 5
)

var errProto = errors.New("svcsi: a message is not valid protobuf")

// Encoding.

type encoder struct{ b []byte }

func (e *encoder) tag(field, wire int) {
	e.b = binary.AppendUvarint(e.b, uint64(field)<<3|uint64(wire))
}

func (e *encoder) bytes(field int, v []byte) {
	if len(v) == 0 {
		return // proto3 leaves defaults out
	}
	e.tag(field, wireBytes)
	e.b = binary.AppendUvarint(e.b, uint64(len(v)))
	e.b = append(e.b, v...)
}

func (e *encoder) string(field int, v string) { e.bytes(field, []byte(v)) }

func (e *encoder) message(field int, v []byte) {
	// An embedded message is written even when empty, so that it is
	// present.
	e.tag(field, wireBytes)
	e.b = binary.AppendUvarint(e.b, uint64(len(v)))
	e.b = append(e.b, v...)
}

func (e *encoder) int32(field int, v int32) {
	if v == 0 {
		return
	}
	e.tag(field, wireVarint)
	// Negative int32s are sign-extended to 64 bits, as protobuf does.
	e.b = binary.AppendUvarint(e.b, uint64(int64(v)))
}

// Marshal encodes the message.
func (m *VersionRequest) Marshal() []byte {
	var e encoder
	e.string(1, m.Version)
	return e.b
}

// Marshal encodes the message.
func (m *VersionResponse) Marshal() []byte {
	var e encoder
	e.string(1, m.Version)
	e.string(2, m.RuntimeName)
	e.string(3, m.RuntimeVersion)
	return e.b
}

// Marshal encodes the message.
func (m *MountRequest) Marshal() []byte {
	var e encoder
	e.string(1, m.Attributes)
	e.string(2, m.Secrets)
	e.string(3, m.TargetPath)
	e.string(4, m.Permission)
	for _, ov := range m.CurrentObjectVersion {
		e.message(5, ov.marshal())
	}
	return e.b
}

// Marshal encodes the message.
func (m *MountResponse) Marshal() []byte {
	var e encoder
	for _, ov := range m.ObjectVersion {
		e.message(1, ov.marshal())
	}
	if m.Error != nil {
		var ee encoder
		ee.string(1, m.Error.Code)
		e.message(2, ee.b)
	}
	for _, f := range m.Files {
		var fe encoder
		fe.string(1, f.Path)
		fe.int32(2, f.Mode)
		fe.bytes(3, f.Contents)
		e.message(3, fe.b)
	}
	return e.b
}

func (ov ObjectVersion) marshal() []byte {
	var e encoder
	e.string(1, ov.ID)
	e.string(2, ov.Version)
	return e.b
}

// Decoding.

// fields calls f for each field of a message, with its number, wire type,
// and its value: the bytes of a length-delimited field, or the varint.
func fields(b []byte, f func(field, wire int, v []byte, n uint64) error) error {
	for len(b) > 0 {
		key, k := binary.Uvarint(b)
		if k <= 0 || key>>3 == 0 || key>>3 > math.MaxInt32 {
			return errProto
		}
		b = b[k:]
		field, wire := int(key>>3), int(key&7)
		var v []byte
		var n uint64
		switch wire {
		case wireVarint:
			if n, k = binary.Uvarint(b); k <= 0 {
				return errProto
			}
			b = b[k:]
		case wireBytes:
			l, k := binary.Uvarint(b)
			if k <= 0 || l > uint64(len(b)-k) {
				return errProto
			}
			v, b = b[k:k+int(l)], b[k+int(l):]
		case wire64:
			if len(b) < 8 {
				return errProto
			}
			b = b[8:]
			continue
		case wire32:
			if len(b) < 4 {
				return errProto
			}
			b = b[4:]
			continue
		default: // groups, long deprecated, and nothing else is defined
			return errProto
		}
		if err := f(field, wire, v, n); err != nil {
			return err
		}
	}
	return nil
}

// want checks a known field's wire type.
func want(field, wire, expected int) error {
	if wire != expected {
		return fmt.Errorf("%w: field %d has wire type %d", errProto, field, wire)
	}
	return nil
}

// Unmarshal decodes the message.
func (m *VersionRequest) Unmarshal(b []byte) error {
	*m = VersionRequest{}
	return fields(b, func(field, wire int, v []byte, _ uint64) error {
		if field == 1 {
			if err := want(field, wire, wireBytes); err != nil {
				return err
			}
			m.Version = string(v)
		}
		return nil
	})
}

// Unmarshal decodes the message.
func (m *VersionResponse) Unmarshal(b []byte) error {
	*m = VersionResponse{}
	return fields(b, func(field, wire int, v []byte, _ uint64) error {
		dst := map[int]*string{1: &m.Version, 2: &m.RuntimeName, 3: &m.RuntimeVersion}[field]
		if dst == nil {
			return nil
		}
		if err := want(field, wire, wireBytes); err != nil {
			return err
		}
		*dst = string(v)
		return nil
	})
}

// Unmarshal decodes the message.
func (m *MountRequest) Unmarshal(b []byte) error {
	*m = MountRequest{}
	return fields(b, func(field, wire int, v []byte, _ uint64) error {
		if field < 1 || field > 5 {
			return nil
		}
		if err := want(field, wire, wireBytes); err != nil {
			return err
		}
		switch field {
		case 1:
			m.Attributes = string(v)
		case 2:
			m.Secrets = string(v)
		case 3:
			m.TargetPath = string(v)
		case 4:
			m.Permission = string(v)
		case 5:
			var ov ObjectVersion
			if err := ov.unmarshal(v); err != nil {
				return err
			}
			m.CurrentObjectVersion = append(m.CurrentObjectVersion, ov)
		}
		return nil
	})
}

// Unmarshal decodes the message.
func (m *MountResponse) Unmarshal(b []byte) error {
	*m = MountResponse{}
	return fields(b, func(field, wire int, v []byte, _ uint64) error {
		if field < 1 || field > 3 {
			return nil
		}
		if err := want(field, wire, wireBytes); err != nil {
			return err
		}
		switch field {
		case 1:
			var ov ObjectVersion
			if err := ov.unmarshal(v); err != nil {
				return err
			}
			m.ObjectVersion = append(m.ObjectVersion, ov)
		case 2:
			m.Error = &Error{}
			return fields(v, func(field, wire int, v []byte, _ uint64) error {
				if field == 1 {
					if err := want(field, wire, wireBytes); err != nil {
						return err
					}
					m.Error.Code = string(v)
				}
				return nil
			})
		case 3:
			var f File
			err := fields(v, func(field, wire int, v []byte, n uint64) error {
				switch field {
				case 1:
					if err := want(field, wire, wireBytes); err != nil {
						return err
					}
					f.Path = string(v)
				case 2:
					if err := want(field, wire, wireVarint); err != nil {
						return err
					}
					f.Mode = int32(n) // int32 is truncated from 64 bits
				case 3:
					if err := want(field, wire, wireBytes); err != nil {
						return err
					}
					f.Contents = append([]byte(nil), v...)
				}
				return nil
			})
			if err != nil {
				return err
			}
			m.Files = append(m.Files, f)
		}
		return nil
	})
}

func (ov *ObjectVersion) unmarshal(b []byte) error {
	return fields(b, func(field, wire int, v []byte, _ uint64) error {
		if field != 1 && field != 2 {
			return nil
		}
		if err := want(field, wire, wireBytes); err != nil {
			return err
		}
		if field == 1 {
			ov.ID = string(v)
		} else {
			ov.Version = string(v)
		}
		return nil
	})
}
