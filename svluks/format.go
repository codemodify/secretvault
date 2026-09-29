package svluks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
)

// What Format writes, as cryptsetup does by default.
const (
	// DataOffset is where the data starts: after two 16 KiB header copies
	// and the 16 MiB - 32 KiB keyslot area.
	DataOffset = 16 << 20

	keyslotsSize = DataOffset - 2*defHdrSize

	// VolumeKeySize is the volume key: 512 bits, for AES-256 in XTS.
	VolumeKeySize = 64

	// digestIterations is the digest's PBKDF2 count: cryptsetup's minimum.
	// The digest is over a 512-bit random key, which no amount of
	// iterations makes any harder to guess; each keyslot's own KDF is what
	// slows down guessing a passphrase.
	digestIterations = 1000
)

// Options shape a new header.
type Options struct {
	// SectorSize is the data's encryption sector size: 512 or 4096 bytes
	// (4096 when 0, as cryptsetup chooses for image files).
	SectorSize int

	// Label and Subsystem go in the binary header, up to 47 bytes each.
	Label, Subsystem string

	// KDF is the first keyslot's (DefaultKDF when its Type is "").
	KDF KDF

	// UUID is the image's UUID ("" for a random one).
	UUID string
}

// Format writes a new LUKS2 header onto dev: a fresh random volume key,
// one aes-xts-plain64 data segment from DataOffset to the end of the
// device (whose size must be DataOffset plus whole sectors), and keyslot 0
// opening with passphrase. Nothing after DataOffset is touched, and the
// metadata area is zeroed first where it is not already. It returns the
// header and the volume key, which the caller destroys.
func Format(dev Device, passphrase []byte, o Options) (*Header, *Key, error) {
	if o.SectorSize == 0 {
		o.SectorSize = 4096
	}
	if o.SectorSize != 512 && o.SectorSize != 4096 {
		return nil, nil, fmt.Errorf("svluks: sector size %d (512 or 4096)", o.SectorSize)
	}
	for _, f := range []struct{ name, v string }{{"label", o.Label}, {"subsystem", o.Subsystem}} {
		if len(f.v) >= labelLen {
			return nil, nil, fmt.Errorf("svluks: the %s is %d bytes, more than %d", f.name, len(f.v), labelLen-1)
		}
		for _, r := range f.v {
			if unicode.IsControl(r) {
				return nil, nil, fmt.Errorf("svluks: the %s holds a control character", f.name)
			}
		}
	}
	if o.UUID == "" {
		o.UUID = newUUID()
	}
	if !uuidPattern.MatchString(o.UUID) {
		return nil, nil, fmt.Errorf("svluks: %q is not a UUID", o.UUID)
	}
	size, err := sizeOf(dev)
	if err != nil {
		return nil, nil, err
	}
	if size < DataOffset+int64(o.SectorSize) {
		return nil, nil, fmt.Errorf("svluks: the image is %d bytes; it needs at least %d for the header and one sector", size, DataOffset+o.SectorSize)
	}
	if (size-DataOffset)%int64(o.SectorSize) != 0 {
		return nil, nil, fmt.Errorf("svluks: the image's size, %d bytes, is not the header and whole %d-byte sectors", size, o.SectorSize)
	}

	vk := make([]byte, VolumeKeySize)
	rand.Read(vk)
	key := keyFrom(vk)
	salt := make([]byte, 32)
	rand.Read(salt)
	sum := pbkdf2(sha256.New, key.Bytes(), salt, digestIterations, sha256.Size)

	seg, _ := encodeJSON(segmentJSON{Type: "crypt", Offset: DataOffset, Size: "dynamic", IVTweak: 0,
		Encryption: cipherXTS, SectorSize: uint32(o.SectorSize)})
	dig, _ := encodeJSON(digestJSON{Type: "pbkdf2", Keyslots: []string{}, Segments: []string{"0"},
		Hash: "sha256", Iterations: digestIterations, Salt: salt, Digest: sum})
	cfg, _ := encodeJSON(configJSON{JSONSize: defHdrSize - binSize, KeyslotsSize: keyslotsSize})
	h := &Header{
		bin: binHeader{hdrSize: defHdrSize, label: o.Label, csumAlg: "sha256", uuid: o.UUID, subsystem: o.Subsystem},
		meta: &metadata{
			keyslots: map[int]*keyslot{},
			tokens:   map[int]json.RawMessage{},
			segments: map[int]*segment{0: {Type: "crypt", Offset: DataOffset, Encryption: cipherXTS, SectorSize: o.SectorSize, raw: seg}},
			digests: map[int]*digest{0: {Type: "pbkdf2", Segments: []int{0}, Hash: "sha256", Iterations: digestIterations,
				Salt: salt, Digest: sum, raw: dig}},
			config:   cfg,
			extra:    map[string]json.RawMessage{},
			jsonSize: defHdrSize - binSize, keyslotsSize: keyslotsSize,
		},
	}
	for i := range h.salts {
		rand.Read(h.salts[i][:])
	}
	fail := func(err error) (*Header, *Key, error) {
		key.Destroy()
		return nil, nil, err
	}
	if err := zeroMetadata(dev); err != nil {
		return fail(err)
	}
	if err := h.write(dev); err != nil {
		return fail(err)
	}
	kdf := o.KDF
	if kdf.Type == "" {
		kdf = DefaultKDF
	}
	if _, err := h.AddKeyslot(dev, key, passphrase, kdf); err != nil {
		return fail(err)
	}
	return h, key, nil
}

// zeroMetadata clears the header and keyslot area, so no keyslot or header
// of whatever was there before survives. Parts already zero (all of a new
// sparse file) are left unwritten, so they stay unallocated.
func zeroMetadata(dev Device) error {
	const chunk = 1 << 20
	buf, zero := make([]byte, chunk), make([]byte, chunk)
	for off := int64(0); off < DataOffset; off += chunk {
		n, err := dev.ReadAt(buf, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if !allZero(buf[:n]) {
			if _, err := dev.WriteAt(zero, off); err != nil {
				return err
			}
		}
	}
	return nil
}
