package svluks

import (
	"errors"
	"fmt"
	"io"
)

// A header backup is what `cryptsetup luksHeaderBackup` writes: the image's
// first MetadataSize bytes, both header copies and the keyslot area, as they
// are on disk. It is itself a LUKS2 header (cryptsetup can open it as a
// detached header), and it opens with every passphrase the image opened
// with when it was taken, so it is as secret as the image's keyslots.

// BackupHeader copies dev's header and keyslot area to w, after checking
// that they read as a sound header.
func BackupHeader(dev io.ReaderAt, w io.Writer) (int64, error) {
	h, err := Read(dev)
	if err != nil {
		return 0, err
	}
	return io.Copy(w, io.NewSectionReader(dev, 0, h.MetadataSize()))
}

// RestoreHeader writes a header backup back over dev's header and keyslot
// area. The backup must read as a sound header, and describe data that
// starts where dev's does and that fits dev. If dev still has a readable
// header, the backup must be of the same image (the same UUID): restoring
// another image's header would make this one's data unreadable.
func RestoreHeader(dev Device, backup io.ReaderAt) error {
	hb, err := Read(backup)
	if err != nil {
		return fmt.Errorf("the backup: %w", err)
	}
	n := hb.MetadataSize()
	buf := make([]byte, n)
	if _, err := backup.ReadAt(buf, 0); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("svluks: the backup is cut short: it has less than the %d bytes its header describes", n)
		}
		return err
	}
	size, err := sizeOf(dev)
	if err != nil {
		return err
	}
	if size < hb.DataOffset()+int64(hb.SectorSize()) {
		return fmt.Errorf("svluks: the image is %d bytes, too small for that header's data at %d", size, hb.DataOffset())
	}
	if cur, err := Read(dev); err == nil {
		switch {
		case cur.UUID() != hb.UUID():
			return fmt.Errorf("svluks: the backup is of another image (UUID %s); this one is %s", hb.UUID(), cur.UUID())
		case cur.DataOffset() != hb.DataOffset() || cur.SectorSize() != hb.SectorSize():
			return errors.New("svluks: the backup puts the data somewhere else than this image's header does")
		}
	}
	if _, err := dev.WriteAt(buf, 0); err != nil {
		return err
	}
	return flush(dev)
}
