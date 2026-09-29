package svluks

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/xts"
)

// Volume is an image's decrypted data: its data segment, read and written
// through aes-xts-plain64 a sector at a time, exactly as dm-crypt does, so
// what one writes the other reads. It is what a mount layer serves where
// the kernel cannot decrypt LUKS2 itself.
//
// XTS hides the data; it does not authenticate it. Someone who can change
// the image can garble a 16-byte block of plaintext without being noticed,
// as with every LUKS2 image without dm-integrity.
//
// A Volume is safe for concurrent use. Writes that cover only part of a
// sector read, change and rewrite the whole sector, one at a time.
type Volume struct {
	dev        Device
	c          *xts.Cipher
	offset     int64
	size       int64
	sectorSize int
	ivTweak    uint64
	wmu        sync.Mutex
}

// chunkSize bounds the memory a single ReadAt or WriteAt uses.
const chunkSize = 1 << 20

// Volume opens the data with its volume key. The key is copied into the
// cipher's key schedule, which is ordinary Go memory: destroy key when
// done, and drop the Volume.
func (h *Header) Volume(dev Device, key *Key) (*Volume, error) {
	if err := h.usable(); err != nil {
		return nil, err
	}
	_, s, d := h.meta.dataSegment()
	if d == nil || !d.matches(key.Bytes()) {
		return nil, errors.New("svluks: that is not this image's volume key")
	}
	c, err := newXTS(s.Encryption, key.Bytes())
	if err != nil {
		return nil, err
	}
	devSize, err := sizeOf(dev)
	if err != nil {
		return nil, err
	}
	v := &Volume{dev: dev, c: c, offset: int64(s.Offset), sectorSize: s.SectorSize, ivTweak: s.IVTweak}
	switch {
	case devSize < v.offset:
		return nil, fmt.Errorf("svluks: the image is %d bytes, but its data starts at %d", devSize, v.offset)
	case s.Size == 0: // "dynamic": the rest of the device, in whole sectors
		v.size = (devSize - v.offset) / int64(v.sectorSize) * int64(v.sectorSize)
	case devSize-v.offset < int64(s.Size):
		return nil, fmt.Errorf("svluks: the image is %d bytes, too short for its %d bytes of data", devSize, s.Size)
	default:
		v.size = int64(s.Size)
	}
	return v, nil
}

// Size is the data's size in bytes.
func (v *Volume) Size() int64 { return v.size }

// SectorSize is the encryption sector size in bytes.
func (v *Volume) SectorSize() int { return v.sectorSize }

// Close drops the cipher; the Volume cannot be used after.
func (v *Volume) Close() error {
	v.wmu.Lock()
	v.c = nil
	v.wmu.Unlock()
	return nil
}

// iv is the plain64 IV of the sector at pos bytes into the data.
func (v *Volume) iv(pos int64) uint64 { return v.ivTweak + uint64(pos)/sectorBytes }

// ReadAt reads decrypted data.
func (v *Volume) ReadAt(p []byte, off int64) (int, error) {
	c := v.c
	if c == nil {
		return 0, errors.New("svluks: the volume is closed")
	}
	if off < 0 {
		return 0, errors.New("svluks: negative offset")
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := min(int64(len(p)), v.size-off)
	ss := int64(v.sectorSize)
	buf := make([]byte, min(chunkSize, (want+2*ss)/ss*ss))
	done := int64(0)
	for done < want {
		pos := off + done
		start := pos / ss * ss
		n := min(int64(len(buf)), (pos+want-done+ss-1)/ss*ss-start)
		chunk := buf[:n]
		if _, err := v.dev.ReadAt(chunk, v.offset+start); err != nil && !errors.Is(err, io.EOF) {
			return int(done), err
		}
		cryptSectors(c, chunk, v.sectorSize, v.iv(start), false)
		done += int64(copy(p[done:want], chunk[pos-start:]))
	}
	clear(buf)
	if want < int64(len(p)) {
		return int(want), io.EOF
	}
	return int(want), nil
}

// WriteAt encrypts and writes data. Writing past the end of the data is
// an error.
func (v *Volume) WriteAt(p []byte, off int64) (int, error) {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	c := v.c
	if c == nil {
		return 0, errors.New("svluks: the volume is closed")
	}
	if off < 0 {
		return 0, errors.New("svluks: negative offset")
	}
	want := int64(len(p))
	if off > v.size || want > v.size-off {
		want = max(0, v.size-off)
	}
	ss := int64(v.sectorSize)
	buf := make([]byte, min(chunkSize, (want+2*ss)/ss*ss))
	defer clear(buf)
	done := int64(0)
	for done < want {
		pos := off + done
		start := pos / ss * ss
		end := min(start+int64(len(buf)), (off+want+ss-1)/ss*ss)
		chunk := buf[:end-start]
		// A sector written only in part is read and decrypted first.
		if pos > start {
			if err := v.readSector(c, chunk[:ss], start); err != nil {
				return int(done), err
			}
		}
		if last := end - ss; off+want < end && (last > start || pos == start) {
			if err := v.readSector(c, chunk[last-start:], last); err != nil {
				return int(done), err
			}
		}
		n := int64(copy(chunk[pos-start:], p[done:want]))
		cryptSectors(c, chunk, v.sectorSize, v.iv(start), true)
		if _, err := v.dev.WriteAt(chunk, v.offset+start); err != nil {
			return int(done), err
		}
		done += n
	}
	if want < int64(len(p)) {
		return int(want), fmt.Errorf("svluks: write past the end of the %d-byte volume", v.size)
	}
	return int(want), nil
}

// readSector reads and decrypts the sector at pos into dst.
func (v *Volume) readSector(c *xts.Cipher, dst []byte, pos int64) error {
	dst = dst[:v.sectorSize]
	if _, err := v.dev.ReadAt(dst, v.offset+pos); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	cryptSectors(c, dst, v.sectorSize, v.iv(pos), false)
	return nil
}
