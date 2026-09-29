// Package svcontainer is secretvault's encrypted containers: LUKS2 image
// files (svluks) with the OS's own filesystem inside, whose keys live in
// vault items. On Linux they are mounted as UDisks2 mounts USB drives: the
// image is attached as a loop device, the kernel's dm-crypt decrypts it,
// and the filesystem is mounted under /run/media, all without root
// (svudisks). On Windows and macOS the images are read and written in
// userspace (svluks.Volume) and the mount layer comes later.
//
// A container's key is 256 random bits written as 64 hex digits: the
// passphrase of the image's first keyslot. A second keyslot can open with
// a passphrase a person chose, so the image also opens with plain
// cryptsetup, or any LUKS2 tool, without secretvault.
package svcontainer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svluks"
)

// KeySize is the length of a container key: 32 random bytes as hex.
const KeySize = 64

// MinSize is the smallest image: the 16 MiB LUKS2 header and 16 MiB of
// data, about the least any of the filesystems will format.
const MinSize = 32 << 20

// Filesystems a container can be made with, the default first.
var Filesystems = []string{"ext4", "exfat", "vfat", "btrfs"}

// PassphraseKDF is the key derivation of passphrase keyslots (tests lower
// it).
var PassphraseKDF = svluks.DefaultKDF

// NewKey returns a fresh container key.
func NewKey() []byte {
	var raw [32]byte
	rand.Read(raw[:])
	key := make([]byte, KeySize)
	hex.Encode(key, raw[:])
	clear(raw[:])
	return key
}

// CheckKey reports whether key looks like a container key.
func CheckKey(key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("a container key is %d hex digits, not %d bytes", KeySize, len(key))
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("a container key is lowercase hex digits")
		}
	}
	return nil
}

// CreateOptions shape a new image.
type CreateOptions struct {
	// Size is the whole image in bytes, header included; it is rounded up
	// to a whole MiB.
	Size int64

	// SectorSize is the encryption sector size, 512 or 4096 (when 0).
	SectorSize int

	// Label goes in the LUKS2 header (the filesystem gets its own).
	Label string

	// Passphrase, when not empty, opens a second keyslot.
	Passphrase []byte
}

// Image says what CreateImage made.
type Image struct {
	Path           string
	UUID           string
	KeySlot        int
	PassphraseSlot int // -1 when there is none
}

// CreateImage writes a new image at path, which must not exist: a sparse
// file of o.Size bytes with a LUKS2 header whose keyslot 0 opens with key
// and, when o.Passphrase is given, keyslot 1 with that. On failure nothing
// is left behind.
func CreateImage(path string, key []byte, o CreateOptions) (img Image, err error) {
	if err := CheckKey(key); err != nil {
		return img, err
	}
	size := (o.Size + 1<<20 - 1) &^ (1<<20 - 1)
	if size < MinSize {
		return img, fmt.Errorf("a container must be at least %d MiB", MinSize>>20)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return img, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	if err := f.Truncate(size); err != nil {
		return img, err
	}
	h, vk, err := svluks.Format(f, key, svluks.Options{SectorSize: o.SectorSize, Label: o.Label, KDF: svluks.KeyKDF, Subsystem: "secretvault"})
	if err != nil {
		return img, err
	}
	defer vk.Destroy()
	img = Image{Path: path, UUID: h.UUID(), KeySlot: 0, PassphraseSlot: -1}
	if len(o.Passphrase) > 0 {
		if img.PassphraseSlot, err = h.AddKeyslot(f, vk, o.Passphrase, PassphraseKDF); err != nil {
			return img, err
		}
	}
	return img, f.Sync()
}

// openImage opens an image file, refusing anything but a regular file: a
// FIFO named as an image would keep whoever opens it waiting for ever, and
// a device is not a container.
func openImage(path string, write bool) (*os.File, error) {
	flag := os.O_RDONLY
	if write {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file, so not a container", path)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Inspect reads an image's header.
func Inspect(path string) (*svluks.Header, error) {
	f, err := openImage(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readHeader(f, path)
}

func readHeader(f *os.File, path string) (*svluks.Header, error) {
	h, err := svluks.Read(f)
	if errors.Is(err, svluks.ErrNotLUKS) {
		return nil, fmt.Errorf("%s is not a container (it has no LUKS header)", path)
	}
	return h, err
}

// maxKeyIterations bounds the keyslots a container key is tried on. The
// key only ever goes in a PBKDF2 keyslot at svluks.KeyKDF's cost; trying
// it on others would let a planted image make the daemon run Argon2 over
// gigabytes.
const maxKeyIterations = 100_000

// unlockKey opens the header with a container key, trying only keyslots
// that could hold one.
func unlockKey(f *os.File, h *svluks.Header, path string, key []byte) (*svluks.Key, int, error) {
	for _, k := range h.Keyslots() {
		if !k.Bound || k.KDF.Type != svluks.KDFPBKDF2 || k.KDF.Iterations > maxKeyIterations {
			continue
		}
		vk, err := h.UnlockSlot(f, k.ID, key)
		if err == nil {
			return vk, k.ID, nil
		}
		if !errors.Is(err, svluks.ErrWrongKey) && !errors.Is(err, svluks.ErrUnsupported) {
			return nil, -1, err
		}
	}
	return nil, -1, fmt.Errorf("the key does not open %s", path)
}

// Check opens the image's header with a container key and returns the
// keyslot it opens. It also refuses an image whose data is not
// aes-xts-plain64: a header planted with cipher_null would have the kernel
// store the container's files in the clear.
func Check(path string, key []byte) (int, error) {
	f, err := openImage(path, false)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	h, err := readHeader(f, path)
	if err != nil {
		return -1, err
	}
	if c := h.Cipher(); c != "aes-xts-plain64" {
		return -1, fmt.Errorf("%s encrypts its data with %q; secretvault opens only aes-xts-plain64 containers", path, c)
	}
	vk, slot, err := unlockKey(f, h, path, key)
	if err != nil {
		return -1, err
	}
	vk.Destroy()
	return slot, nil
}

// CheckPassphrase returns the keyslot a passphrase opens, trying every
// keyslot at whatever cost it records (bounded by svluks). It is for
// images one trusts to be what they say.
func CheckPassphrase(path string, pass []byte) (int, error) {
	f, err := openImage(path, false)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	h, err := readHeader(f, path)
	if err != nil {
		return -1, err
	}
	vk, slot, err := h.Unlock(f, pass)
	if err != nil {
		return -1, fmt.Errorf("the passphrase does not open %s", path)
	}
	vk.Destroy()
	return slot, nil
}

// SetPassphrase gives the image a keyslot that opens with pass, unlocking
// it with key. With replace >= 0 that keyslot is changed instead (keeping
// its number); replacing the keyslot the key itself opens is refused.
// It returns the passphrase's keyslot.
func SetPassphrase(path string, key, pass []byte, replace int) (int, error) {
	return withKey(path, key, func(f *os.File, h *svluks.Header, vk *svluks.Key, keySlot int) (int, error) {
		if replace < 0 || !slices.ContainsFunc(h.Keyslots(), func(k svluks.Keyslot) bool { return k.ID == replace }) {
			return h.AddKeyslot(f, vk, pass, PassphraseKDF)
		}
		if replace == keySlot {
			return -1, errors.New("that keyslot is the one the vault's key opens")
		}
		return replace, h.ChangeKeyslot(f, replace, vk, pass, PassphraseKDF)
	})
}

// RemoveKeyslot removes one of the image's keyslots, unlocking it with
// key; the keyslot key opens is refused.
func RemoveKeyslot(path string, key []byte, slot int) error {
	_, err := withKey(path, key, func(f *os.File, h *svluks.Header, _ *svluks.Key, keySlot int) (int, error) {
		if slot == keySlot {
			return -1, errors.New("that keyslot is the one the vault's key opens")
		}
		return slot, h.RemoveKeyslot(f, slot)
	})
	return err
}

func withKey(path string, key []byte, do func(*os.File, *svluks.Header, *svluks.Key, int) (int, error)) (int, error) {
	f, err := openImage(path, true)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	h, err := readHeader(f, path)
	if err != nil {
		return -1, err
	}
	vk, slot, err := unlockKey(f, h, path, key)
	if err != nil {
		return -1, err
	}
	defer vk.Destroy()
	n, err := do(f, h, vk, slot)
	if err != nil {
		return -1, err
	}
	return n, f.Sync()
}

// BackupHeader copies the image's header and keyslots to out, a new file
// (mode 0600, never over an existing one). Anyone with the backup and a
// passphrase that opened the image then can open it later, even after
// that keyslot is removed: keep it as safe as the passphrase.
func BackupHeader(path, out string) (err error) {
	f, err := openImage(path, false)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(out)
		}
	}()
	if _, err := svluks.BackupHeader(f, w); err != nil {
		return err
	}
	return w.Sync()
}

// CheckFormat checks a filesystem type and label before anything is made.
func CheckFormat(fstype, label string) error {
	max := map[string]int{"ext4": 16, "exfat": 15, "vfat": 11, "btrfs": 255}[fstype]
	if max == 0 {
		return fmt.Errorf("filesystem %q is not one of %v", fstype, Filesystems)
	}
	if !utf8.ValidString(label) || len(label) > max {
		return fmt.Errorf("a %s label is at most %d bytes", fstype, max)
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f || fstype == "vfat" && r > 0x7e {
			return fmt.Errorf("%q is not a %s label", label, fstype)
		}
	}
	return nil
}
