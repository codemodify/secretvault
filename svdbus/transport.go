package svdbus

import (
	"bytes"
	"errors"
	"time"
)

// transport is a connected byte stream that can carry descriptors.
type transport interface {
	// read reads into b and returns any descriptors that arrived with the
	// bytes read.
	read(b []byte) (n int, fds []UnixFD, err error)

	// write writes all of b, with fds attached to its first byte.
	write(b []byte, fds []UnixFD) error

	// canPassFDs reports whether the transport can carry descriptors.
	canPassFDs() bool

	setDeadline(t time.Time) error
	close() error
}

// maxQueuedFDs bounds the descriptors received ahead of the message that
// declares them.
const maxQueuedFDs = 4 * MaxUnixFDs

// msgReader frames messages (and, before them, authentication lines) out of
// a transport's stream, and keeps the descriptors that arrive with the bytes
// until the message that declares them is complete.
type msgReader struct {
	tr   transport
	max  int      // largest message accepted
	buf  []byte   // buf[r:w] is read but not yet consumed
	r, w int      //
	fds  []UnixFD // received, not yet claimed by a message
}

func newMsgReader(tr transport, max int) *msgReader {
	return &msgReader{tr: tr, max: max, buf: make([]byte, 4096)}
}

// fill reads until at least n bytes are buffered. The buffer grows with the
// data actually received, not with the length a header claims.
func (r *msgReader) fill(n int) error {
	for r.w-r.r < n {
		if r.r > 0 && len(r.buf)-r.r < n {
			r.w = copy(r.buf, r.buf[r.r:r.w])
			r.r = 0
		}
		if r.w == len(r.buf) {
			size := min(max(2*len(r.buf), 4096), r.r+n)
			grown := make([]byte, size)
			copy(grown, r.buf[:r.w])
			r.buf = grown
		}
		k, fds, err := r.tr.read(r.buf[r.w:])
		r.fds = append(r.fds, fds...)
		r.w += k
		if len(r.fds) > maxQueuedFDs {
			return invalidf("peer sent %d descriptors ahead of their messages", len(r.fds))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// readLine reads one authentication line, without its CR LF.
func (r *msgReader) readLine() (string, error) {
	const maxLine = 16384
	for {
		for i := r.r; i+1 < r.w; i++ {
			if r.buf[i] == '\r' && r.buf[i+1] == '\n' {
				line := string(r.buf[r.r:i])
				r.r = i + 2
				return line, nil
			}
		}
		if r.w-r.r > maxLine {
			return "", errors.New("svdbus: authentication line too long")
		}
		if err := r.fill(r.w - r.r + 1); err != nil {
			return "", err
		}
	}
}

// next reads the next message. An error means the stream can no longer be
// trusted and the connection must close. A message whose body is malformed
// is returned with bodyErr set, and its descriptors already closed.
func (r *msgReader) next() (*Message, error) {
	if r.r == r.w {
		r.r, r.w = 0, 0
		if len(r.buf) > 1<<16 {
			r.buf = make([]byte, 4096) // let a large message's buffer go
		}
	}
	if err := r.fill(16); err != nil {
		return nil, err
	}
	total, err := frameLength(r.buf[r.r:r.r+16], r.max)
	if err != nil {
		return nil, err
	}
	if err := r.fill(total); err != nil {
		return nil, err
	}
	data := r.buf[r.r : r.r+total]
	r.r += total
	m, d, n, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	if n > len(r.fds) {
		return nil, invalidf("message declares %d descriptors but %d came", n, len(r.fds))
	}
	fds := make([]UnixFD, n)
	copy(fds, r.fds)
	r.fds = r.fds[:copy(r.fds, r.fds[n:])]
	m.fds = fds

	if err := m.decodeBody(d, fds); err != nil {
		m.Body = nil
		m.bodyErr = err
		m.CloseFDs()
		return m, nil
	}
	for i, used := range d.used {
		if !used {
			closeFD(fds[i])
			fds[i] = -1
		}
	}
	if m.Type == TypeSignal && len(m.FDs()) > 0 {
		// Bodies start 8-aligned, so the body alone decodes the same.
		fields := int(d.order.Uint32(data[12:16]))
		m.raw = bytes.Clone(data[16+(fields+7)&^7:])
		m.order = d.order
	}
	return m, nil
}

// closeQueued closes descriptors no message claimed.
func (r *msgReader) closeQueued() {
	for _, fd := range r.fds {
		closeFD(fd)
	}
	r.fds = nil
}
