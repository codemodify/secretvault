package svluks

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"

	"golang.org/x/crypto/xts"

	"github.com/codemodify/secretvault/svcrypto"
)

// ErrLastKeyslot is removing the only keyslot that still opens the data.
var ErrLastKeyslot = errors.New("svluks: that is the last keyslot that opens the data; removing it would lose the data for good")

// Key is a volume key, held in locked memory. Destroy wipes it.
type Key struct{ s *svcrypto.Secret }

// NewKey copies b into a new Key.
func NewKey(b []byte) *Key {
	s := svcrypto.NewSecret(len(b))
	copy(s.Bytes(), b)
	return &Key{s: s}
}

// keyFrom moves b into a new Key, zeroing b.
func keyFrom(b []byte) *Key { return &Key{s: svcrypto.SecretFrom(b)} }

// Bytes is the key itself, valid until Destroy.
func (k *Key) Bytes() []byte { return k.s.Bytes() }

// Destroy wipes the key. It is safe to call more than once.
func (k *Key) Destroy() {
	if k != nil {
		k.s.Destroy()
	}
}

// Keyslot data sizes this package writes: a 512-bit key for the
// keyslot area's aes-xts-plain64, and a 32-byte KDF salt, as cryptsetup.
const (
	areaKeySize = 64
	kdfSaltSize = 32
)

// newXTS is the cipher for a dm-crypt specification. Only aes-xts-plain64
// is implemented, with AES-128, -192 or -256 (a 256-, 384- or 512-bit key).
func newXTS(spec string, key []byte) (*xts.Cipher, error) {
	if spec != cipherXTS {
		return nil, unsupported("cipher %q (secretvault implements aes-xts-plain64)", spec)
	}
	switch len(key) {
	case 32, 48, 64:
	default:
		return nil, unsupported("aes-xts-plain64 with a %d-bit key", 8*len(key))
	}
	return xts.NewCipher(aes.NewCipher, key)
}

// cryptSectors encrypts or decrypts buf in place, sectorSize bytes at a
// time. plain64 IVs count 512-byte sectors whatever the sector size (as
// LUKS2 does; dm-crypt's iv_large_sectors is for plain mode only), so the
// first sector's IV is iv and each next one's is sectorSize/512 more.
func cryptSectors(c *xts.Cipher, buf []byte, sectorSize int, iv uint64, encrypt bool) {
	step := uint64(sectorSize / sectorBytes)
	for off := 0; off < len(buf); off += sectorSize {
		s := buf[off : off+sectorSize]
		if encrypt {
			c.Encrypt(s, s, iv)
		} else {
			c.Decrypt(s, s, iv)
		}
		iv += step
	}
}

// matches checks a candidate key against the digest.
func (d *digest) matches(key []byte) bool {
	h, err := hashNamed(d.Hash)
	if err != nil {
		return false
	}
	got := pbkdf2(h, key, d.Salt, int(d.Iterations), len(d.Digest))
	defer clear(got)
	return subtle.ConstantTimeCompare(got, d.Digest) == 1
}

// Unlock finds a keyslot the passphrase opens and returns the key it holds
// and its number. Keyslots are tried as cryptsetup tries them: those of
// high priority first, then normal ones; priority 0 keyslots open only
// through UnlockSlot. Only keyslots holding the data's volume key are
// tried.
func (h *Header) Unlock(dev io.ReaderAt, passphrase []byte) (*Key, int, error) {
	if err := h.usable(); err != nil {
		return nil, -1, err
	}
	var order []Keyslot
	for _, k := range h.Keyslots() {
		if k.Type == "luks2" && k.Bound && k.Priority > 0 {
			order = append(order, k)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].Priority > order[j].Priority })
	var unsupportedErr error
	for _, k := range order {
		key, err := h.openSlot(dev, k.ID, passphrase)
		switch {
		case err == nil:
			return key, k.ID, nil
		case errors.Is(err, ErrWrongKey):
		case errors.Is(err, ErrUnsupported):
			unsupportedErr = err
		default:
			return nil, -1, err
		}
	}
	if unsupportedErr != nil {
		return nil, -1, fmt.Errorf("%w (and some keyslots could not be tried: %v)", ErrWrongKey, unsupportedErr)
	}
	return nil, -1, ErrWrongKey
}

// UnlockSlot opens one keyslot.
func (h *Header) UnlockSlot(dev io.ReaderAt, id int, passphrase []byte) (*Key, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	return h.openSlot(dev, id, passphrase)
}

func (h *Header) openSlot(dev io.ReaderAt, id int, passphrase []byte) (*Key, error) {
	ks, ok := h.meta.keyslots[id]
	if !ok {
		return nil, fmt.Errorf("svluks: there is no keyslot %d", id)
	}
	if ks.Type != "luks2" {
		return nil, unsupported("keyslot %d is of type %q", id, ks.Type)
	}
	d := h.meta.digestOf(id)
	if d == nil {
		return nil, headerErr("keyslot %d has no digest", id)
	}
	afHash, err := hashNamed(ks.AF.Hash)
	if err != nil {
		return nil, fmt.Errorf("keyslot %d: %w", id, err)
	}
	if ks.Area.Encryption != cipherXTS {
		return nil, unsupported("keyslot %d is encrypted with %q", id, ks.Area.Encryption)
	}
	kek, err := kdfFromJSON(ks.KDF).derive(passphrase, ks.KDF.Salt, int(ks.Area.KeySize))
	if err != nil {
		return nil, fmt.Errorf("keyslot %d: %w", id, err)
	}
	c, err := newXTS(ks.Area.Encryption, kek)
	clear(kek)
	if err != nil {
		return nil, fmt.Errorf("keyslot %d: %w", id, err)
	}
	material := make([]byte, afSize(ks.KeySize))
	defer clear(material)
	if _, err := dev.ReadAt(material, int64(ks.Area.Offset)); err != nil {
		return nil, fmt.Errorf("svluks: reading keyslot %d: %w", id, err)
	}
	cryptSectors(c, material, sectorBytes, 0, false)
	key := afMerge(material, ks.KeySize, afHash)
	if !d.matches(key) {
		clear(key)
		return nil, ErrWrongKey
	}
	return keyFrom(key), nil
}

// CheckKey reports whether key is the data's volume key.
func (h *Header) CheckKey(key *Key) bool {
	_, _, d := h.meta.dataSegment()
	return d != nil && d.matches(key.Bytes())
}

// AddKeyslot adds a keyslot that opens with passphrase and holds key,
// which must be the data's volume key. It returns the new keyslot's
// number.
func (h *Header) AddKeyslot(dev Device, key *Key, passphrase []byte, kdf KDF) (int, error) {
	if err := h.usable(); err != nil {
		return -1, err
	}
	_, _, d := h.meta.dataSegment()
	if d == nil {
		return -1, headerErr("the data segment has no digest")
	}
	if !d.matches(key.Bytes()) {
		return -1, errors.New("svluks: that is not this image's volume key")
	}
	id := -1
	for i := range maxObjects {
		if _, taken := h.meta.keyslots[i]; !taken {
			id = i
			break
		}
	}
	if id < 0 {
		return -1, fmt.Errorf("svluks: all %d keyslots are in use", maxObjects)
	}
	ks, err := h.newKeyslot(dev, key.Bytes(), passphrase, kdf, nil)
	if err != nil {
		return -1, err
	}
	oldDigest := d.raw
	raw, err := setMember(d.raw, "keyslots", idStrings(append(slices.Clone(d.Keyslots), id)))
	if err != nil {
		return -1, err
	}
	h.meta.keyslots[id] = ks
	d.Keyslots, d.raw = append(d.Keyslots, id), raw
	if err := h.write(dev); err != nil {
		delete(h.meta.keyslots, id)
		d.Keyslots, d.raw = d.Keyslots[:len(d.Keyslots)-1], oldDigest
		return -1, err
	}
	return id, nil
}

// ChangeKeyslot gives keyslot id a new passphrase (and KDF), keeping its
// number and priority, as cryptsetup luksChangeKey does: the new keyslot
// is written to free space, the header then points at it, and the old
// area is overwritten last. key must be the volume key the keyslot holds.
func (h *Header) ChangeKeyslot(dev Device, id int, key *Key, passphrase []byte, kdf KDF) error {
	if err := h.usable(); err != nil {
		return err
	}
	old, ok := h.meta.keyslots[id]
	if !ok || old.Type != "luks2" {
		return fmt.Errorf("svluks: there is no keyslot %d", id)
	}
	if d := h.meta.digestOf(id); d == nil || !d.matches(key.Bytes()) {
		return fmt.Errorf("svluks: keyslot %d does not hold that key", id)
	}
	var priority *uint32
	if old.Priority != 1 {
		p := uint32(old.Priority)
		priority = &p
	}
	ks, err := h.newKeyslot(dev, key.Bytes(), passphrase, kdf, priority)
	if err != nil {
		return err
	}
	h.meta.keyslots[id] = ks
	if err := h.write(dev); err != nil {
		h.meta.keyslots[id] = old
		return err
	}
	return wipeArea(dev, uint64(old.Area.Offset), uint64(old.Area.Size))
}

// RemoveKeyslot destroys a keyslot. Its area is overwritten first, as the
// specification asks; then it leaves the metadata, and the digest and
// tokens that named it. The last keyslot that opens the data is refused
// (ErrLastKeyslot).
func (h *Header) RemoveKeyslot(dev Device, id int) error {
	if err := h.usable(); err != nil {
		return err
	}
	ks, ok := h.meta.keyslots[id]
	if !ok {
		return fmt.Errorf("svluks: there is no keyslot %d", id)
	}
	bound := 0
	for _, k := range h.Keyslots() {
		if k.Bound {
			bound++
		}
	}
	d := h.meta.digestOf(id)
	_, _, dataDigest := h.meta.dataSegment()
	if d != nil && d == dataDigest && bound <= 1 {
		return ErrLastKeyslot
	}
	if err := wipeArea(dev, uint64(ks.Area.Offset), uint64(ks.Area.Size)); err != nil {
		return err
	}
	delete(h.meta.keyslots, id)
	for _, dg := range h.meta.digests {
		if i := slices.Index(dg.Keyslots, id); i >= 0 {
			dg.Keyslots = slices.Delete(dg.Keyslots, i, i+1)
			raw, err := setMember(dg.raw, "keyslots", idStrings(dg.Keyslots))
			if err != nil {
				return err
			}
			dg.raw = raw
		}
	}
	for tid, raw := range h.meta.tokens {
		var t struct {
			Keyslots []string `json:"keyslots"`
		}
		if err := strict(raw, &t, "token"); err != nil {
			return err
		}
		if i := slices.Index(t.Keyslots, fmt.Sprint(id)); i >= 0 {
			nraw, err := setMember(raw, "keyslots", slices.Delete(t.Keyslots, i, i+1))
			if err != nil {
				return err
			}
			h.meta.tokens[tid] = nraw
		}
	}
	return h.write(dev)
}

// newKeyslot writes a luks2 keyslot's area (key split by the AF splitter,
// encrypted under a key derived from the passphrase) into free space, and
// returns its metadata.
func (h *Header) newKeyslot(dev Device, key, passphrase []byte, kdf KDF, priority *uint32) (*keyslot, error) {
	if kdf.Type == "" {
		kdf = DefaultKDF
	}
	if err := kdf.check(true); err != nil {
		return nil, err
	}
	size := (afSize(len(key)) + areaAlign - 1) / areaAlign * areaAlign
	off, err := h.allocate(size)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, kdfSaltSize)
	rand.Read(salt)
	kek, err := kdf.derive(passphrase, salt, areaKeySize)
	if err != nil {
		return nil, err
	}
	c, err := newXTS(cipherXTS, kek)
	clear(kek)
	if err != nil {
		return nil, err
	}
	material := afSplit(key, sha256.New, func(b []byte) { rand.Read(b) })
	defer clear(material)
	cryptSectors(c, material, sectorBytes, 0, true)
	if _, err := dev.WriteAt(material, int64(off)); err != nil {
		return nil, err
	}
	if err := flush(dev); err != nil {
		return nil, err
	}
	j := keyslotJSON{
		Type: "luks2", KeySize: uint32(len(key)),
		AF:       &afJSON{Type: "luks1", Stripes: afStripes, Hash: "sha256"},
		Area:     &areaJSON{Type: "raw", Offset: u64(off), Size: u64(size), Encryption: cipherXTS, KeySize: areaKeySize},
		KDF:      ptr(kdf.toJSON(salt)),
		Priority: priority,
	}
	raw, err := encodeJSON(j)
	if err != nil {
		return nil, err
	}
	ks := &keyslot{Type: j.Type, KeySize: len(key), AF: *j.AF, Area: *j.Area, KDF: *j.KDF, Priority: 1, raw: raw}
	if priority != nil {
		ks.Priority = int(*priority)
	}
	return ks, nil
}

func ptr[T any](v T) *T { return &v }

// allocate finds size bytes of the keyslot area that no keyslot uses,
// aligned to 4 KiB.
func (h *Header) allocate(size uint64) (uint64, error) {
	type span struct{ off, end uint64 }
	var used []span
	for _, ks := range h.meta.keyslots {
		used = append(used, span{uint64(ks.Area.Offset), uint64(ks.Area.Offset + ks.Area.Size)})
	}
	sort.Slice(used, func(i, j int) bool { return used[i].off < used[j].off })
	pos, end := 2*h.bin.hdrSize, h.meta.metaEnd(h.bin.hdrSize)
	for _, u := range used {
		if u.off >= pos+size {
			break
		}
		if u.end > pos {
			pos = (u.end + areaAlign - 1) / areaAlign * areaAlign
		}
	}
	if pos+size > end {
		return 0, errors.New("svluks: the keyslot area is full")
	}
	return pos, nil
}

// wipeArea overwrites a keyslot area with random bytes.
func wipeArea(dev Device, off, size uint64) error {
	buf := make([]byte, min(size, 1<<20))
	for done := uint64(0); done < size; {
		n := min(uint64(len(buf)), size-done)
		rand.Read(buf[:n])
		if _, err := dev.WriteAt(buf[:n], int64(off+done)); err != nil {
			return err
		}
		done += n
	}
	return flush(dev)
}
