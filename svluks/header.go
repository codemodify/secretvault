package svluks

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
)

// Device is where an image lives: an *os.File, or anything else that reads
// and writes at offsets. Operations that need the image's size ask it with
// Stat (as *os.File has) or Size.
type Device interface {
	io.ReaderAt
	io.WriterAt
}

// Header is a LUKS2 header, as read from an image or written to one. Its
// methods that change the header write it back at once. It is not safe for
// concurrent use.
type Header struct {
	bin   binHeader
	salts [2][saltLen]byte
	fresh [2]bool // copy i was unreadable: a rewrite repairs it with a new salt
	meta  *metadata

	// broken is why a write failed: what is on disk is then unknown, and
	// the header must be read again before it is changed.
	broken error
}

// Read reads an image's header. Both copies are read, and the newer of
// those whose checksums hold is used, so an image whose primary header was
// damaged still opens from its secondary. Only then is its metadata
// parsed: a newer copy whose metadata fails is an error, never a reason to
// fall back to an older copy, which a later write would put over what the
// newer one recorded. Nothing beyond the header copies is read.
func Read(r io.ReaderAt) (*Header, error) {
	type found struct {
		b    *binHeader
		text []byte
		err  error
	}
	var copies [2]found
	copies[0].b, copies[0].text, copies[0].err = readCopy(r, 0, magicPrimary)

	// The secondary copy is where a sound primary says; else it is looked
	// for at each offset the specification allows.
	offsets := hdrSizes
	if copies[0].err == nil {
		offsets = []uint64{copies[0].b.hdrSize}
	}
	copies[1].err = ErrNotLUKS
	for _, off := range offsets {
		b, text, err := readCopy(r, off, magicSecondary)
		if errors.Is(err, ErrNotLUKS) {
			continue
		}
		copies[1] = found{b, text, err}
		break
	}

	use := -1
	switch {
	case copies[0].err == nil && copies[1].err == nil:
		use = 0
		if copies[1].b.seqid > copies[0].b.seqid && copies[1].b.hdrSize == copies[0].b.hdrSize {
			use = 1
		}
	case copies[0].err == nil:
		use = 0
	case copies[1].err == nil:
		use = 1
	case errors.Is(copies[0].err, ErrNotLUKS) && !errors.Is(copies[1].err, ErrNotLUKS):
		return nil, copies[1].err
	default:
		return nil, copies[0].err
	}
	c := copies[use]
	m, err := parseMetadata(c.text, c.b.hdrSize)
	if err != nil {
		return nil, err
	}
	h := &Header{bin: *c.b, meta: m}
	for i := range copies {
		if copies[i].err == nil && copies[i].b.hdrSize == h.bin.hdrSize {
			h.salts[i] = copies[i].b.salt
		} else {
			h.fresh[i] = true
		}
	}
	return h, nil
}

// UUID is the image's UUID, as blkid and udev see it.
func (h *Header) UUID() string { return h.bin.uuid }

// Label is the header's label (not the filesystem's).
func (h *Header) Label() string { return h.bin.label }

// Subsystem is the header's secondary label.
func (h *Header) Subsystem() string { return h.bin.subsystem }

// Seqid counts the header's updates.
func (h *Header) Seqid() uint64 { return h.bin.seqid }

// DataOffset is where the encrypted data starts, in bytes.
func (h *Header) DataOffset() int64 {
	_, s, _ := h.meta.dataSegment()
	return int64(s.Offset)
}

// SectorSize is the data's encryption sector size in bytes.
func (h *Header) SectorSize() int {
	_, s, _ := h.meta.dataSegment()
	return s.SectorSize
}

// Cipher is the data's cipher, in dm-crypt notation (aes-xts-plain64).
func (h *Header) Cipher() string {
	_, s, _ := h.meta.dataSegment()
	return s.Encryption
}

// MetadataSize is the size of the header copies and keyslot area together:
// what BackupHeader copies.
func (h *Header) MetadataSize() int64 { return int64(h.meta.metaEnd(h.bin.hdrSize)) }

// Requirements are the features the header says a reader must have
// (config.requirements). This package has none of them, so a header that
// lists any can be read and backed up, but not unlocked or changed.
func (h *Header) Requirements() []string { return slices.Clone(h.meta.requirements) }

// Keyslot describes one keyslot.
type Keyslot struct {
	ID       int
	Type     string // "luks2"; keyslots of other types are kept but never opened
	KeySize  int    // bytes of key it holds
	KDF      KDF
	Priority int  // 0: used only when named, 1: normal, 2: tried first
	Bound    bool // it holds the data's volume key (not an unbound key)

	// DigestIterations is the PBKDF2 count of the digest a key from this
	// keyslot is checked against: work done for every key tried.
	DigestIterations uint32
}

// Keyslots lists the keyslots in order.
func (h *Header) Keyslots() []Keyslot {
	_, _, dataDigest := h.meta.dataSegment()
	var out []Keyslot
	for id, ks := range h.meta.keyslots {
		k := Keyslot{ID: id, Type: ks.Type, KeySize: ks.KeySize, Priority: ks.Priority}
		if ks.Type == "luks2" {
			k.KDF = kdfFromJSON(ks.KDF)
			k.Bound = dataDigest != nil && h.meta.digestOf(id) == dataDigest
			if d := h.meta.digestOf(id); d != nil {
				k.DigestIterations = d.Iterations
			}
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// usable refuses to unlock or change a header that lists requirements, or
// one whose last write failed.
func (h *Header) usable() error {
	if h.broken != nil {
		return fmt.Errorf("svluks: the header could not be written (%v); read it again before changing it", h.broken)
	}
	if len(h.meta.requirements) > 0 {
		return unsupported("the header requires %v, which secretvault does not implement", h.meta.requirements)
	}
	return nil
}

// write writes both header copies with the next sequence number, primary
// first: a crash between the two leaves one valid copy, which Read then
// uses. What it writes must pass the same checks Read makes. After a
// failure the Header is broken (see usable): what reached the disk is
// unknown, and a sequence number is never written twice.
func (h *Header) write(dev Device) (err error) {
	if err := h.usable(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			h.broken = err
		}
	}()
	text, err := h.meta.marshal()
	if err != nil {
		return err
	}
	if _, err := parseMetadata(text, h.bin.hdrSize); err != nil {
		return fmt.Errorf("svluks: refusing to write metadata that does not check: %w", err)
	}
	h.bin.seqid++
	for i, magic := range [][]byte{magicPrimary, magicSecondary} {
		if h.fresh[i] {
			rand.Read(h.salts[i][:])
		}
		c := h.bin
		c.hdrOffset = uint64(i) * c.hdrSize
		c.salt = h.salts[i]
		buf, err := encodeCopy(&c, magic, text)
		if err != nil {
			return err
		}
		if _, err := dev.WriteAt(buf, int64(c.hdrOffset)); err != nil {
			return err
		}
		if err := flush(dev); err != nil {
			return err
		}
		h.fresh[i] = false
	}
	return nil
}

func flush(dev any) error {
	if s, ok := dev.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// sizeOf is a device's size in bytes.
func sizeOf(dev any) (int64, error) {
	if f, ok := dev.(interface{ Stat() (os.FileInfo, error) }); ok {
		st, err := f.Stat()
		if err != nil {
			return 0, err
		}
		if st.Mode().IsRegular() {
			return st.Size(), nil
		}
	}
	if s, ok := dev.(interface{ Size() int64 }); ok {
		return s.Size(), nil
	}
	if s, ok := dev.(io.Seeker); ok {
		return s.Seek(0, io.SeekEnd)
	}
	return 0, errors.New("svluks: cannot tell the size of the device")
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// newUUID is a random (version 4) UUID.
func newUUID() string {
	var u [16]byte
	rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
