package svage

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// The payload: a 16-byte nonce, then the plaintext in 64 KiB chunks, each
// sealed with ChaCha20-Poly1305 under
//
//	payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")
//
// with the AEAD nonce an 11-byte big-endian chunk counter and a last-chunk
// flag byte (1 on the final chunk, 0 before it). This is age's STREAM, the
// same construction svcrypto uses for vault attachments with a different
// key derivation. The final chunk may be shorter than 64 KiB, and is empty
// only when the whole payload is.

// ChunkSize is the plaintext size of every payload chunk but the last.
const ChunkSize = 64 * 1024

const (
	nonceSize    = 16
	tagSize      = chacha20poly1305.Overhead
	encChunkSize = ChunkSize + tagSize
)

// ErrPayload is a payload that is truncated, reordered, altered or
// followed by trailing data. Plaintext already returned before it came
// from chunks that were each authentic, but the file as a whole is not.
var ErrPayload = errors.New("svage: the payload is damaged or has been tampered with")

func payloadErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPayload}, args...)...)
}

func payloadAEAD(fileKey, nonce []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, fileKey, nonce, "payload", chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return chacha20poly1305.New(key)
}

func chunkNonce(counter uint64, last bool) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 1
	}
	return n[:]
}

// streamWriter seals what is written to it. A full chunk is held back
// until the next byte arrives, so the final chunk is full when the
// plaintext ends on a chunk boundary, never an empty one after it.
type streamWriter struct {
	aead    cipher.AEAD
	w       io.Writer
	buf     []byte
	counter uint64
	err     error
}

func newStreamWriter(aead cipher.AEAD, w io.Writer) *streamWriter {
	return &streamWriter{aead: aead, w: w, buf: make([]byte, 0, encChunkSize)}
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	if sw.err != nil {
		return 0, sw.err
	}
	n := 0
	for len(p) > 0 {
		if len(sw.buf) == ChunkSize {
			if err := sw.flush(false); err != nil {
				return n, err
			}
		}
		take := min(len(p), ChunkSize-len(sw.buf))
		sw.buf = append(sw.buf, p[:take]...)
		p, n = p[take:], n+take
	}
	return n, nil
}

// Close seals the final chunk. It does not close the underlying writer.
func (sw *streamWriter) Close() error {
	if sw.err != nil {
		return sw.err
	}
	err := sw.flush(true)
	clear(sw.buf[:cap(sw.buf)])
	if err == nil {
		sw.err = errors.New("svage: write after Close")
	}
	return err
}

// flush seals the buffered chunk. The 11-byte counter cannot wrap: a
// uint64 runs out first, at 2^64 chunks.
func (sw *streamWriter) flush(last bool) error {
	out := sw.aead.Seal(sw.buf[:0], chunkNonce(sw.counter, last), sw.buf, nil)
	sw.counter++
	sw.buf = sw.buf[:0]
	if _, err := sw.w.Write(out); err != nil {
		sw.err = err
		return err
	}
	return nil
}

// streamReader opens a payload chunk by chunk, returning each chunk's
// plaintext only once it is authenticated. It reads exactly what age
// reads and fails where age fails, so that the plaintext released before
// an error is the same (the test vectors check this).
type streamReader struct {
	aead    cipher.AEAD
	r       io.Reader
	buf     []byte // one sealed chunk
	plain   []byte // its plaintext
	out     []byte // authenticated plaintext not yet returned
	counter uint64
	err     error // returned once out is drained
}

func newStreamReader(aead cipher.AEAD, r io.Reader) *streamReader {
	return &streamReader{aead: aead, r: r, buf: make([]byte, encChunkSize), plain: make([]byte, 0, ChunkSize)}
}

func (sr *streamReader) Read(p []byte) (int, error) {
	if len(sr.out) > 0 {
		n := copy(p, sr.out)
		sr.out = sr.out[n:]
		return n, nil
	}
	if sr.err != nil {
		return 0, sr.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	last, err := sr.next()
	if err != nil {
		sr.err = err
		return 0, err
	}
	if last {
		var one [1]byte
		switch _, err := io.ReadFull(sr.r, one[:]); {
		case err == nil:
			sr.err = payloadErrorf("trailing data after the final chunk")
		case errors.Is(err, io.EOF):
			sr.err = io.EOF
		default:
			sr.err = err
		}
	}
	if len(sr.out) == 0 {
		return 0, sr.err // an empty payload
	}
	n := copy(p, sr.out)
	sr.out = sr.out[n:]
	return n, nil
}

// next opens the next chunk into sr.out and reports whether it was the
// final one.
func (sr *streamReader) next() (last bool, err error) {
	in := sr.buf
	n, err := io.ReadFull(sr.r, in)
	switch {
	case err == io.EOF: // ReadFull's own sentinels, never wrapped ones
		return false, payloadErrorf("the file ends without a final chunk")
	case err == io.ErrUnexpectedEOF:
		if sr.counter > 0 && n == tagSize {
			return false, payloadErrorf("the final chunk is empty")
		}
		in, last = in[:n], true
	case err != nil:
		return false, err
	}
	// Not opened in place: a failed Open clobbers its output, and a full
	// chunk may need a second try.
	out, err := sr.aead.Open(sr.plain[:0], chunkNonce(sr.counter, last), in, nil)
	if err != nil && !last {
		// A full chunk at the end of the payload is the final one.
		last = true
		out, err = sr.aead.Open(sr.plain[:0], chunkNonce(sr.counter, true), in, nil)
	}
	if err != nil {
		return false, payloadErrorf("chunk %d does not authenticate", sr.counter)
	}
	sr.counter++
	sr.out = out
	return last, nil
}

// chunkCount is how many chunks a payload of size bytes (after the nonce)
// has, or an error when no valid payload has that size.
func chunkCount(size int64) (int64, error) {
	if size < tagSize || size > math.MaxInt64-encChunkSize {
		return 0, payloadErrorf("impossible payload size %d", size)
	}
	chunks := (size + encChunkSize - 1) / encChunkSize
	plain := size - chunks*tagSize
	want := (plain + ChunkSize - 1) / ChunkSize
	if plain == 0 {
		want = 1
	}
	if want != chunks {
		return 0, payloadErrorf("impossible payload size %d", size)
	}
	return chunks, nil
}

// readerAt decrypts a payload at random offsets. It authenticates the
// final chunk up front, which fixes the plaintext size, and caches the
// chunk it opened last.
type readerAt struct {
	aead   cipher.AEAD
	src    io.ReaderAt // the payload after the nonce
	size   int64       // plaintext size
	chunks int64

	mu        sync.Mutex
	cacheIdx  int64
	cacheData []byte
}

func newReaderAt(aead cipher.AEAD, src io.ReaderAt, encSize int64) (*readerAt, error) {
	chunks, err := chunkCount(encSize)
	if err != nil {
		return nil, err
	}
	r := &readerAt{aead: aead, src: src, chunks: chunks, size: encSize - chunks*tagSize, cacheIdx: -1}
	if _, err := r.chunk(chunks - 1); err != nil {
		return nil, err
	}
	return r, nil
}

// chunk returns chunk i's plaintext, opening it if it is not cached.
func (r *readerAt) chunk(i int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cacheIdx == i {
		return r.cacheData, nil
	}
	off := i * encChunkSize
	n := min(encChunkSize, r.size+r.chunks*tagSize-off)
	buf := make([]byte, n)
	if got, err := r.src.ReadAt(buf, off); got != len(buf) {
		if err == nil || errors.Is(err, io.EOF) {
			err = payloadErrorf("the file is shorter than it was")
		}
		return nil, err
	}
	out, err := r.aead.Open(buf[:0], chunkNonce(uint64(i), i == r.chunks-1), buf, nil)
	if err != nil {
		return nil, payloadErrorf("chunk %d does not authenticate", i)
	}
	r.cacheIdx, r.cacheData = i, out
	return out, nil
}

func (r *readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > r.size {
		return 0, fmt.Errorf("svage: offset %d out of range [0, %d]", off, r.size)
	}
	n := 0
	for len(p) > 0 && off < r.size {
		i := off / ChunkSize
		data, err := r.chunk(i)
		if err != nil {
			return n, err
		}
		c := copy(p, data[off-i*ChunkSize:])
		p, off, n = p[c:], off+int64(c), n+c
	}
	if off == r.size {
		return n, io.EOF
	}
	return n, nil
}
