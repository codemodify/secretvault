package svformat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"

	"github.com/codemodify/secretvault/svcrypto"
)

// A revision file is one immutable version of one object:
//
//	revision = prefix || body
//	prefix   = "SVR1" || suite(1) || 0x00 || header_len(2, BE) || header
//	header   = TLV {
//	    0x01 vault ID (16)
//	    0x02 object ID (16)
//	    0x03 epoch (4, BE)             which vault key wrapped the object key
//	    0x04 time (8, BE)              hybrid-logical clock, Unix nanoseconds
//	    0x05 parents (32 each)         sorted revision IDs; absent for the first
//	    0x06 wrapped object key        Seal(wrap key, object key, dek_aad)
//	    0x81 device ID (16)            optional: which device wrote it
//	    0x82 signature                 optional: that device's (signature.go)
//	}
//	body     = Seal(object key, padded payload, aad = prefix)
//	dek_aad  = "secretvault sv1 dek" || vault ID || object ID || epoch(4)
//
// The whole prefix is the body's associated data, so no header field can be
// changed or moved to another body. The object key's own associated data
// names the vault, object and epoch, so a wrapped key cannot be moved to
// another object. A revision's ID is the SHA-256 of the whole file.

const revisionMagic = "SVR1"

const (
	tagVault     = 0x01
	tagObject    = 0x02
	tagEpoch     = 0x03
	tagTime      = 0x04
	tagParents   = 0x05
	tagWrapped   = 0x06
	tagDevice    = 0x81
	tagSignature = 0x82
)

// ErrRevision is a revision file that is malformed or of an unsupported
// version. ErrOpen from svcrypto is one that is well formed but does not
// authenticate.
var ErrRevision = errors.New("svformat: malformed revision")

// RevisionHeader is everything in a revision that is readable without keys.
type RevisionHeader struct {
	Suite   svcrypto.Suite
	Vault   ID
	Object  ID
	Epoch   uint32
	Time    int64
	Parents []RevID
	Device  ID // zero when not recorded

	// Signature is the writing device's signature, nil when the revision
	// is not signed. Sealing ignores it: SealSignedRevision makes one.
	Signature *RevisionSignature

	wrapped []byte
}

// SealRevision writes a revision: payload sealed under the object key dek,
// dek wrapped under wrapKey. Parents are sorted into canonical order.
func SealRevision(h RevisionHeader, wrapKey, dek, payload []byte) ([]byte, error) {
	return sealRevision(h, wrapKey, dek, payload, nil)
}

// sealRevision seals a revision, signed with key unless it is nil.
func sealRevision(h RevisionHeader, wrapKey, dek, payload []byte, key ed25519.PrivateKey) ([]byte, error) {
	if !h.Suite.Valid() || h.Epoch == 0 || h.Time < 0 || h.Vault.IsZero() || h.Object.IsZero() {
		return nil, fmt.Errorf("%w: incomplete header", ErrRevision)
	}
	parents := slices.Clone(h.Parents)
	slices.SortFunc(parents, func(a, b RevID) int { return bytes.Compare(a[:], b[:]) })
	parents = slices.Compact(parents)

	wrapped, err := h.Suite.Seal(wrapKey, dek, dekAAD(h.Vault, h.Object, h.Epoch))
	if err != nil {
		return nil, err
	}
	var t tlvBuilder
	t.add(tagVault, h.Vault[:])
	t.add(tagObject, h.Object[:])
	t.u32(tagEpoch, h.Epoch)
	t.u64(tagTime, uint64(h.Time))
	if len(parents) > 0 {
		var p []byte
		for _, r := range parents {
			p = append(p, r[:]...)
		}
		t.add(tagParents, p)
	}
	t.add(tagWrapped, wrapped)
	if !h.Device.IsZero() {
		t.add(tagDevice, h.Device[:])
	}
	hdr, err := t.encode()
	if err != nil {
		return nil, err
	}
	if key != nil {
		fields, err := sign(h.Suite, t.fields, h.Vault, dek, payload, key)
		if err != nil {
			return nil, err
		}
		if hdr, err = EncodeTLV(fields); err != nil {
			return nil, err
		}
	}
	if len(hdr) > 0xFFFF {
		return nil, fmt.Errorf("%w: header is %d bytes", ErrRevision, len(hdr))
	}
	prefix := append([]byte(revisionMagic), byte(h.Suite), 0)
	prefix = binary.BigEndian.AppendUint16(prefix, uint16(len(hdr)))
	prefix = append(prefix, hdr...)

	padded := pad(payload)
	defer clear(padded)
	body, err := h.Suite.Seal(dek, padded, prefix)
	if err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
}

// ParseRevision reads a revision's header without any key. Nothing in it is
// authenticated until OpenRevision succeeds.
func ParseRevision(file []byte) (RevisionHeader, error) {
	h, _, _, err := parseRevision(file)
	return h, err
}

// OpenRevision authenticates and decrypts a revision. It returns the header,
// the payload and the object key; the caller zeroes the key when done.
func OpenRevision(file []byte, wrapKey []byte) (h RevisionHeader, payload, dek []byte, err error) {
	h, prefix, body, err := parseRevision(file)
	if err != nil {
		return h, nil, nil, err
	}
	dek, err = h.Suite.Open(wrapKey, h.wrapped, dekAAD(h.Vault, h.Object, h.Epoch))
	if err != nil {
		return h, nil, nil, err
	}
	padded, err := h.Suite.Open(dek, body, prefix)
	if err != nil {
		clear(dek)
		return h, nil, nil, err
	}
	payload, err = unpad(padded)
	if err != nil {
		clear(dek)
		return h, nil, nil, err
	}
	return h, payload, dek, nil
}

func parseRevision(file []byte) (h RevisionHeader, prefix, body []byte, err error) {
	bad := func(why string) (RevisionHeader, []byte, []byte, error) {
		return RevisionHeader{}, nil, nil, fmt.Errorf("%w: %s", ErrRevision, why)
	}
	if len(file) < 8 || string(file[:4]) != revisionMagic {
		return bad("not a secretvault v1 revision")
	}
	h.Suite = svcrypto.Suite(file[4])
	if !h.Suite.Valid() {
		return bad(fmt.Sprintf("unknown suite %d", file[4]))
	}
	if file[5] != 0 {
		return bad("reserved byte is set")
	}
	n := int(binary.BigEndian.Uint16(file[6:8]))
	if len(file) < 8+n {
		return bad("header runs past the end")
	}
	prefix, body = file[:8+n:8+n], file[8+n:]
	fields, err := DecodeTLV(file[8 : 8+n])
	if err != nil {
		return RevisionHeader{}, nil, nil, err
	}
	seen := map[uint8]bool{}
	for _, f := range fields {
		seen[f.Tag] = true
		switch f.Tag {
		case tagVault, tagObject, tagDevice:
			if len(f.Value) != 16 {
				return bad(fmt.Sprintf("tag 0x%02x is %d bytes", f.Tag, len(f.Value)))
			}
			switch f.Tag {
			case tagVault:
				copy(h.Vault[:], f.Value)
			case tagObject:
				copy(h.Object[:], f.Value)
			default:
				copy(h.Device[:], f.Value)
			}
		case tagEpoch:
			if len(f.Value) != 4 {
				return bad("epoch is not 4 bytes")
			}
			h.Epoch = binary.BigEndian.Uint32(f.Value)
		case tagTime:
			if len(f.Value) != 8 {
				return bad("time is not 8 bytes")
			}
			t := binary.BigEndian.Uint64(f.Value)
			if t > 1<<63-1 {
				return bad("time out of range")
			}
			h.Time = int64(t)
		case tagParents:
			if len(f.Value) == 0 || len(f.Value)%32 != 0 {
				return bad("parents are not whole revision IDs")
			}
			for i := 0; i < len(f.Value); i += 32 {
				var r RevID
				copy(r[:], f.Value[i:])
				if len(h.Parents) > 0 && bytes.Compare(h.Parents[len(h.Parents)-1][:], r[:]) >= 0 {
					return bad("parents are not sorted and unique")
				}
				h.Parents = append(h.Parents, r)
			}
		case tagWrapped:
			h.wrapped = f.Value
		case tagSignature:
			sig, err := parseSignature(f.Value)
			if err != nil {
				return RevisionHeader{}, nil, nil, err
			}
			h.Signature = sig
		default:
			if Critical(f.Tag) {
				return bad(fmt.Sprintf("unknown critical tag 0x%02x", f.Tag))
			}
		}
	}
	for _, need := range []uint8{tagVault, tagObject, tagEpoch, tagTime, tagWrapped} {
		if !seen[need] {
			return bad(fmt.Sprintf("missing tag 0x%02x", need))
		}
	}
	if h.Epoch == 0 {
		return bad("epoch 0")
	}
	if h.Signature != nil && h.Device.IsZero() {
		return bad("a signed revision names no device")
	}
	return h, prefix, body, nil
}

func dekAAD(vault, object ID, epoch uint32) []byte {
	aad := []byte("secretvault sv1 dek")
	aad = append(aad, vault[:]...)
	aad = append(aad, object[:]...)
	return binary.BigEndian.AppendUint32(aad, epoch)
}

// pad frames a payload as length(4, BE) || payload || zeros, to a size from
// the Padmé scheme (at least 256 bytes), so a revision's size says little
// about its contents: at most O(log log n) bits of the length leak.
func pad(payload []byte) []byte {
	n := padme(max(4+len(payload), 256))
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

func unpad(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("%w: payload frame too short", ErrRevision)
	}
	n := int(binary.BigEndian.Uint32(padded))
	if n > len(padded)-4 {
		return nil, fmt.Errorf("%w: payload length past the frame", ErrRevision)
	}
	for _, b := range padded[4+n:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: non-zero padding", ErrRevision)
		}
	}
	return padded[4 : 4+n], nil
}

// padme rounds n up so that only the top ~log2(log2(n)) bits are free
// (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
// Communication with PURBs", 2019).
func padme(n int) int {
	if n < 2 {
		return n
	}
	e := bits.Len(uint(n)) - 1     // floor(log2 n)
	s := bits.Len(uint(e))         // floor(log2 e) + 1
	mask := (1 << max(e-s, 0)) - 1 // low bits that must be zero
	return (n + mask) &^ mask
}
