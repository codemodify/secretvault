package svext

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Native messaging (https://developer.mozilla.org/docs/Mozilla/Add-ons/
// WebExtensions/Native_messaging): the browser starts the host and talks
// to it over its stdin and stdout, each message a 4-byte length in the
// machine's own byte order, then that many bytes of UTF-8 JSON.

// MaxFrame is the largest message either side accepts. Browsers refuse a
// larger one from a host.
const MaxFrame = 1 << 20

// ErrFrameTooLarge is a message over MaxFrame. The stream cannot be read
// past it, so the host stops.
var ErrFrameTooLarge = errors.New("svext: a message larger than 1 MiB")

// ReadFrame reads one message. At a clean end between messages it returns
// io.EOF; a message cut short is io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.NativeEndian.Uint32(head[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w (%d bytes)", ErrFrameTooLarge, n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return msg, nil
}

// WriteFrame writes one message, in a single Write.
func WriteFrame(w io.Writer, msg []byte) error {
	if len(msg) > MaxFrame {
		return fmt.Errorf("%w (%d bytes)", ErrFrameTooLarge, len(msg))
	}
	buf := make([]byte, 4+len(msg))
	binary.NativeEndian.PutUint32(buf, uint32(len(msg)))
	copy(buf[4:], msg)
	_, err := w.Write(buf)
	return err
}
